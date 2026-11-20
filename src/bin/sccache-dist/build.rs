// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::command_helpers::CommandExt;
use anyhow::{Context, Error, Result, anyhow, bail};
use fs_err as fs;
use libmount::Overlay;
use nix::errno::Errno;
use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
use nix::sys::stat::{Mode, mkdirat};
use sccache::compression::ZstdFrame;
use sccache::compression::deflate::unpack_gzip;
use sccache::dist::{
    BuildResult, BuilderIncoming, CompileCommand, InputsReader, OutputRequest, ProcessOutput,
    TcCache, Toolchain,
};
use sccache::lru_disk_cache::Error as LruError;
use std::collections::{HashMap, hash_map};
use std::io;
use std::iter;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use version_compare::Version;

/// Host-side filesystem operations on a build's temporary root must obey
/// the same root boundary as the compiler running under bubblewrap. In
/// particular, normal host paths would otherwise follow absolute symlinks in
/// uploaded inputs outside the build directory.
struct RootedBuildFs {
    root: std::fs::File,
}

impl RootedBuildFs {
    fn new(root: &Path) -> io::Result<Self> {
        Ok(Self {
            root: std::fs::File::open(root)?,
        })
    }

    fn open_dir(&self, path: &Path) -> io::Result<std::os::fd::OwnedFd> {
        // RESOLVE_IN_ROOT interprets absolute paths and absolute symlinks
        // relative to the build root. NO_MAGICLINKS also forbids procfs-like
        // special links that are not ordinary filesystem symlinks.
        let how = OpenHow::new()
            .flags(OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        openat2(&self.root, path, how).map_err(Into::into)
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        // For missing segments, obtain a safely resolved parent directory fd
        // and mkdirat *only* the single new component. A normal host mkdir
        // against a multi-component path could follow a symlink outside root.
        let mut prefix = PathBuf::new();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => prefix.push(".."),
                Component::Normal(name) => {
                    let parent = prefix.clone();
                    prefix.push(name);
                    match self.open_dir(&prefix) {
                        Ok(_) => {}
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            let parent = if parent.as_os_str().is_empty() {
                                Path::new(".")
                            } else {
                                parent.as_path()
                            };
                            let parent_fd = self.open_dir(parent)?;
                            match mkdirat(&parent_fd, name, Mode::from_bits_truncate(0o755)) {
                                Ok(()) | Err(Errno::EEXIST) => {}
                                Err(error) => return Err(error.into()),
                            }
                            // Verify the created/existing entry is a directory
                            // and resolves inside root, even under contention.
                            drop(self.open_dir(&prefix)?);
                        }
                        Err(error) => return Err(error),
                    }
                }
                Component::Prefix(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unsupported build path prefix",
                    ));
                }
            }
        }
        Ok(())
    }

    fn open_output(&self, path: &Path) -> io::Result<std::fs::File> {
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_MAGICLINKS);
        let fd = openat2(&self.root, path, how)?;
        let file = std::fs::File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compiler output is not a regular file",
            ));
        }
        Ok(file)
    }
}

#[derive(Debug)]
struct OverlaySpec {
    build_dir: PathBuf,
    toolchain_dir: PathBuf,
    // Keep the extracted toolchain alive through the complete build and its
    // filesystem cleanup. The map owns the other reference to this lease.
    _active_lease: Arc<()>,
}

#[derive(Debug, Clone)]
struct DeflatedToolchain {
    path: PathBuf,
    build_count: u64,
    active_lease: Arc<()>,
}

pub struct OverlayBuilder {
    bubblewrap: PathBuf,
    dir: PathBuf,
    toolchain_dir_map: Mutex<HashMap<Toolchain, DeflatedToolchain>>,
}

impl OverlayBuilder {
    pub fn new(bubblewrap: PathBuf, dir: PathBuf) -> Result<Self> {
        info!("Creating overlay builder");

        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() {
            // Not root, or a setuid binary - haven't put enough thought into supporting this, bail
            bail!("not running as root")
        }

        let out = Command::new(&bubblewrap)
            .arg("--version")
            .check_stdout_trim()
            .context("Failed to execute bwrap for version check")?;
        if let Some(s) = out.split_whitespace().nth(1) {
            match (Version::from("0.3.0"), Version::from(s)) {
                (Some(min), Some(seen)) => {
                    if seen < min {
                        bail!(
                            "bubblewrap 0.3.0 or later is required, got {:?} for {:?}",
                            out,
                            bubblewrap
                        );
                    }
                }
                (_, _) => {
                    bail!(
                        "Unexpected version format running {:?}: got {:?}, expected \"bubblewrap x.x.x\"",
                        bubblewrap,
                        out
                    );
                }
            }
        } else {
            bail!(
                "Unexpected version format running {:?}: got {:?}, expected \"bubblewrap x.x.x\"",
                bubblewrap,
                out
            );
        }

        // TODO: pidfile
        let ret = Self {
            bubblewrap,
            dir,
            toolchain_dir_map: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        fs::create_dir(&ret.dir).context("Failed to create base directory for builder")?;
        fs::create_dir(ret.dir.join("builds"))
            .context("Failed to create builder builds directory")?;
        fs::create_dir(ret.dir.join("toolchains"))
            .context("Failed to create builder toolchains directory")?;
        Ok(ret)
    }

    fn cleanup(&self) -> Result<()> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir).context("Failed to clean up builder directory")?
        }
        Ok(())
    }

    /// Reclaim extracted toolchains whose archives have been evicted, but
    /// never while a running build still references their lower directory.
    /// The caller holds the directory-map mutex, preventing new build leases
    /// from being acquired during the check and filesystem deletion.
    fn prune_unused_toolchain_dirs(
        &self,
        dir_map: &mut HashMap<Toolchain, DeflatedToolchain>,
        tccache: &Mutex<TcCache>,
    ) {
        // Inspect the actual cache membership rather than comparing collection
        // sizes: eviction order need not match directory creation order.
        // Release the cache lock before potentially slow directory deletion.
        let candidates: Vec<_> = {
            let cache = tccache.lock().unwrap();
            dir_map
                .iter()
                .filter(|(tc, entry)| {
                    Arc::strong_count(&entry.active_lease) == 1 && !cache.contains_toolchain(tc)
                })
                .map(|(tc, entry)| (tc.clone(), entry.path.clone()))
                .collect()
        };
        for (tc, path) in candidates {
            match fs::remove_dir_all(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    warn!(
                        "Failed to prune inactive toolchain directory {}: {error:#}",
                        path.display()
                    );
                    continue;
                }
            }
            debug!("Pruned inactive uncompressed toolchain {}", tc.archive_id);
            dir_map.remove(&tc);
        }
    }

    fn prepare_overlay_dirs(
        &self,
        tc: &Toolchain,
        tccache: &Mutex<TcCache>,
    ) -> Result<OverlaySpec> {
        let DeflatedToolchain {
            path: toolchain_dir,
            build_count: id,
            active_lease,
        } = {
            let mut toolchain_dir_map = self.toolchain_dir_map.lock().unwrap();
            // Create the toolchain dir (if necessary) while we have an exclusive lock
            let toolchain_dir = self.dir.join("toolchains").join(&tc.archive_id);
            if toolchain_dir_map.contains_key(tc) && toolchain_dir.exists() {
                // TODO: use if let when sccache can use NLL
                let entry = toolchain_dir_map.get_mut(tc).ok_or_else(|| {
                    anyhow!("toolchain disappeared from directory map while locked")
                })?;
                entry.build_count += 1;
                entry.clone()
            } else {
                // Once the archive file has been opened, extraction must not
                // hold the global LRU mutex. The open descriptor remains valid
                // even if another cache operation evicts the directory entry.
                let toolchain_rdr = {
                    let mut cache = tccache.lock().unwrap();
                    match cache.get(tc) {
                        Ok(rdr) => rdr,
                        Err(LruError::FileNotInCache) => {
                            bail!("expected toolchain {}, but not available", tc.archive_id)
                        }
                        Err(e) => {
                            return Err(
                                Error::from(e).context("failed to get toolchain from cache")
                            );
                        }
                    }
                };

                // Do not leave an empty extraction directory behind when the
                // toolchain is missing: the next request must be able to retry.
                trace!("Creating toolchain directory for {}", tc.archive_id);
                fs::create_dir(&toolchain_dir)?;
                if let Err(error) = unpack_gzip(toolchain_rdr, &toolchain_dir) {
                    warn!("Failed to unpack toolchain: {error:?}");
                    if let Err(cleanup_error) = fs::remove_dir_all(&toolchain_dir) {
                        warn!(
                            "Failed to remove incomplete toolchain directory {}: {cleanup_error:#}",
                            toolchain_dir.display()
                        );
                    }
                    if let Err(cache_error) = tccache.lock().unwrap().remove(tc) {
                        warn!(
                            "Failed to remove corrupt toolchain {} from cache: {cache_error:#}",
                            tc.archive_id
                        );
                    }
                    return Err(Error::from(error).context("Failed to unpack toolchain"));
                }

                let entry = DeflatedToolchain {
                    path: toolchain_dir,
                    build_count: 1,
                    active_lease: Arc::new(()),
                };

                toolchain_dir_map.insert(tc.clone(), entry.clone());
                self.prune_unused_toolchain_dirs(&mut toolchain_dir_map, tccache);
                entry
            }
        };

        trace!("Creating build directory for {}-{}", tc.archive_id, id);
        let build_dir = self
            .dir
            .join("builds")
            .join(format!("{}-{}", tc.archive_id, id));
        fs::create_dir(&build_dir)?;
        Ok(OverlaySpec {
            build_dir,
            toolchain_dir,
            _active_lease: active_lease,
        })
    }

    fn perform_build(
        bubblewrap: &Path,
        compile_command: CompileCommand,
        inputs_rdr: InputsReader,
        outputs: OutputRequest,
        overlay: &OverlaySpec,
    ) -> Result<BuildResult> {
        let OutputRequest {
            paths: output_paths,
            compression_level,
        } = outputs;
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable, compile_command.arguments
        );

        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // Now mounted filesystems will be automatically unmounted when this thread dies
                    // (and tmpfs filesystems will be completely destroyed)
                    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
                        .context("Failed to enter a new Linux namespace")?;
                    // Make sure that all future mount changes are private to this namespace
                    // TODO: shouldn't need to add these annotations
                    let source: Option<&str> = None;
                    let fstype: Option<&str> = None;
                    let data: Option<&str> = None;
                    // Turn / into a 'slave', so it receives mounts from real root, but doesn't propagate back
                    nix::mount::mount(
                        source,
                        "/",
                        fstype,
                        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
                        data,
                    )
                    .context("Failed to turn / into a slave")?;

                    let work_dir = overlay.build_dir.join("work");
                    let upper_dir = overlay.build_dir.join("upper");
                    let target_dir = overlay.build_dir.join("target");
                    fs::create_dir(&work_dir).context("Failed to create overlay work directory")?;
                    fs::create_dir(&upper_dir)
                        .context("Failed to create overlay upper directory")?;
                    fs::create_dir(&target_dir)
                        .context("Failed to create overlay target directory")?;

                    let () = Overlay::writable(
                        iter::once(overlay.toolchain_dir.as_path()),
                        upper_dir,
                        work_dir,
                        &target_dir,
                        // This error is unfortunately not Send+Sync
                    )
                    .mount()
                    .map_err(|e| anyhow!("Failed to mount overlay FS: {}", e.to_string()))?;

                    trace!("copying in inputs");
                    // Note that we don't unpack directly into the upperdir since there overlayfs has some
                    // special marker files that we don't want to create by accident (or malicious intent)
                    inputs_rdr
                        .unpack(&target_dir)
                        .context("Failed to unpack inputs to overlay")?;

                    let CompileCommand {
                        executable,
                        arguments,
                        env_vars,
                        cwd,
                    } = compile_command;
                    let cwd = Path::new(&cwd);

                    let build_fs = RootedBuildFs::new(&target_dir)
                        .context("Failed to open overlay build root")?;
                    trace!("creating output directories");
                    build_fs
                        .create_dir_all(cwd)
                        .context("Failed to create cwd")?;
                    for path in output_paths.iter() {
                        // If it doesn't have a parent, nothing needs creating
                        let output_parent = if let Some(p) = Path::new(path).parent() {
                            p
                        } else {
                            continue;
                        };
                        build_fs
                            .create_dir_all(&cwd.join(output_parent))
                            .context("Failed to create an output directory")?;
                    }

                    trace!("performing compile");
                    // Bubblewrap notes:
                    // - We're running as uid 0 (to do the mounts above), and so bubblewrap is run as uid 0
                    // - There's special handling in bubblewrap to compare uid and euid - of interest to us,
                    //   if uid == euid == 0, bubblewrap preserves capabilities (not good!) so we explicitly
                    //   drop all capabilities
                    // - By entering a new user namespace means any set of capabilities do not apply to any
                    //   other user namespace, i.e. you lose privileges. This is not strictly necessary because
                    //   we're dropping caps anyway so it's irrelevant which namespace we're in, but it doesn't
                    //   hurt.
                    // - --unshare-all is not ideal as it happily continues if it fails to unshare either
                    //   the user or cgroups namespace, so we list everything explicitly
                    // - The order of bind vs proc + dev is important - the new root must be put in place
                    //   first, otherwise proc and dev get hidden
                    let mut cmd = Command::new(bubblewrap);
                    cmd.arg("--die-with-parent")
                        .args(["--cap-drop", "ALL"])
                        .args([
                            "--unshare-user",
                            "--unshare-cgroup",
                            "--unshare-ipc",
                            "--unshare-pid",
                            "--unshare-net",
                            "--unshare-uts",
                        ])
                        .arg("--bind")
                        .arg(&target_dir)
                        .arg("/")
                        .args(["--proc", "/proc"])
                        .args(["--dev", "/dev"])
                        .arg("--chdir")
                        .arg(cwd);

                    for (k, v) in env_vars {
                        if k.contains('=') {
                            warn!("Skipping environment variable: {:?}", k);
                            continue;
                        }
                        cmd.arg("--setenv").arg(k).arg(v);
                    }
                    cmd.arg("--");
                    cmd.arg(executable);
                    cmd.args(arguments);
                    let compile_output = cmd
                        .output()
                        .context("Failed to retrieve output from compile")?;
                    trace!("compile_output: {:?}", compile_output);

                    let mut outputs = vec![];
                    trace!("retrieving {:?}", output_paths);
                    for path in output_paths {
                        // Follow output symlinks with the same root semantics
                        // as bubblewrap, never against the host filesystem.
                        match build_fs.open_output(&cwd.join(&path)) {
                            Ok(file) => {
                                let output = ZstdFrame::try_from_reader(file, compression_level)
                                    .context("Failed to read output file")?;
                                outputs.push((path, output))
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::NotFound {
                                    debug!("Missing output path {:?}", path)
                                } else {
                                    return Err(
                                        Error::from(e).context("Failed to open output file")
                                    );
                                }
                            }
                        }
                    }
                    let compile_output = ProcessOutput::try_from(compile_output)
                        .context("Failed to convert compilation exit status")?;
                    Ok(BuildResult {
                        output: compile_output,
                        outputs,
                    })
                    // Bizarrely there's no way to actually get any information from a thread::Result::Err
                })
                .join()
                .unwrap_or_else(|_e| Err(anyhow!("Build thread exited unsuccessfully")))
        })
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_overlay(&self, _tc: &Toolchain, overlay: OverlaySpec, tccache: &Mutex<TcCache>) {
        // Deleting the temporary build directory may fail, but the compile
        // result should still be returned to the client.
        if let Err(e) = fs::remove_dir_all(&overlay.build_dir) {
            error!(
                "Failed to remove build directory {}: {}",
                overlay.build_dir.display(),
                e
            );
        }
        // The compile and mount namespace have finished. Release the lease
        // before pruning so this toolchain can be collected if its archive is
        // no longer cached and no other builds are using it.
        drop(overlay);
        let mut dir_map = self.toolchain_dir_map.lock().unwrap();
        self.prune_unused_toolchain_dirs(&mut dir_map, tccache);
    }
}

impl BuilderIncoming for OverlayBuilder {
    fn run_build(
        &self,
        tc: Toolchain,
        command: CompileCommand,
        outputs: OutputRequest,
        inputs_rdr: InputsReader,
        tccache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        debug!("Preparing overlay");
        let overlay = self
            .prepare_overlay_dirs(&tc, tccache)
            .context("failed to prepare overlay dirs")?;
        debug!("Performing build in {:?}", overlay);
        let res = Self::perform_build(&self.bubblewrap, command, inputs_rdr, outputs, &overlay);
        debug!("Finishing with overlay");
        self.finish_overlay(&tc, overlay, tccache);
        debug!("Returning result");
        res.context("Compilation execution failed")
    }
}

const BASE_DOCKER_IMAGE: &str = "aidanhs/busybox";
// Make sure sh doesn't exec the final command, since we need it to do
// init duties (reaping zombies). Also, because we kill -9 -1, that kills
// the sleep (it's not a builtin) so it needs to be a loop.
const DOCKER_SHELL_INIT: &str = "while true; do /busybox sleep 365d && /busybox true; done";

// Check the diff and clean up the FS
fn docker_diff(cid: &str) -> Result<String> {
    Command::new("docker")
        .args(["diff", cid])
        .check_stdout_trim()
        .context("Failed to Docker diff container")
}

// Force remove the container
fn docker_rm(cid: &str) -> Result<()> {
    Command::new("docker")
        .args(["rm", "-f", cid])
        .check_run()
        .context("Failed to force delete container")
}

/// Return the IDs of sccache-owned Docker resources from an ID/name listing.
///
/// Both Docker container and image listings provide exactly two
/// whitespace-separated columns; reject malformed output rather than silently
/// ignoring an unexpected Docker response.
fn builder_resource_ids(listing: &str) -> Result<Vec<&str>> {
    let mut ids = Vec::new();
    for (index, line) in listing.lines().enumerate() {
        let mut columns = line.split_ascii_whitespace();
        let (Some(id), Some(name), None) = (columns.next(), columns.next(), columns.next()) else {
            bail!(
                "Malformed Docker resource listing at line {}: {line:?}",
                index + 1
            );
        };
        if name.starts_with("sccache-builder-") {
            ids.push(id);
        }
    }
    Ok(ids)
}

pub struct DockerBuilder {
    image_map: Mutex<HashMap<Toolchain, String>>,
    container_lists: Mutex<HashMap<Toolchain, Vec<String>>>,
}

impl DockerBuilder {
    // TODO: this should accept a unique string, e.g. inode of the tccache directory
    // having locked a pidfile, or at minimum should loudly detect other running
    // instances - pidfile in /tmp
    pub fn new() -> Result<Self> {
        info!("Creating docker builder");

        let ret = Self {
            image_map: Mutex::new(HashMap::new()),
            container_lists: Mutex::new(HashMap::new()),
        };
        ret.cleanup()?;
        Ok(ret)
    }

    // TODO: this should really reclaim, and should check in the image map and container lists, so
    // that when things are removed from there it becomes a form of GC
    fn cleanup(&self) -> Result<()> {
        info!("Performing initial Docker cleanup");

        let containers = Command::new("docker")
            .args(["ps", "-a", "--format", "{{.ID}} {{.Image}}"])
            .check_stdout_trim()
            .context("Unable to list all Docker containers")?;
        let containers_to_rm =
            builder_resource_ids(&containers).context("Malformed Docker container listing")?;
        if !containers_to_rm.is_empty() {
            Command::new("docker")
                .args(["rm", "-f"])
                .args(containers_to_rm)
                .check_run()
                .context("Failed to start command to remove old containers")?;
        }

        let images = Command::new("docker")
            .args(["images", "--format", "{{.ID}} {{.Repository}}"])
            .check_stdout_trim()
            .context("Failed to list all docker images")?;
        let images_to_rm =
            builder_resource_ids(&images).context("Malformed Docker image listing")?;
        if !images_to_rm.is_empty() {
            Command::new("docker")
                .args(["rmi"])
                .args(images_to_rm)
                .check_run()
                .context("Failed to remove image")?;
        }
        info!("Completed initial Docker cleanup");
        Ok(())
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Docker image along
    // the way)
    fn get_container(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let container = {
            let mut map = self.container_lists.lock().unwrap();
            map.entry(tc.clone()).or_default().pop()
        };
        match container {
            Some(cid) => Ok(cid),
            None => {
                // TODO: can improve parallelism (of creating multiple images at a time) by using another
                // (more fine-grained) mutex around the entry value and checking if its empty a second time
                let image = {
                    let mut map = self.image_map.lock().unwrap();
                    match map.entry(tc.clone()) {
                        hash_map::Entry::Occupied(e) => e.get().clone(),
                        hash_map::Entry::Vacant(e) => {
                            info!("Creating Docker image for {:?} (may block requests)", tc);
                            let image = Self::make_image(tc, tccache)?;
                            e.insert(image.clone());
                            image
                        }
                    }
                };
                Self::start_container(&image)
            }
        }
    }

    fn clean_container(&self, cid: &str) -> Result<()> {
        // Clean up any running processes
        Command::new("docker")
            .args(["exec", cid, "/busybox", "kill", "-9", "-1"])
            .check_run()
            .context("Failed to run kill on all processes in container")?;

        let diff = docker_diff(cid)?;
        if !diff.is_empty() {
            let mut lastpath = None;
            for line in diff.split('\n') {
                let mut iter = line.splitn(2, ' ');
                let changetype = iter
                    .next()
                    .context("Malformed container diff - no change type")?;
                let changepath = iter
                    .next()
                    .context("Malformed container diff - no change path")?;
                if iter.next().is_some() {
                    bail!("Malformed container diff - third field on row")
                }
                // TODO: If files are created in this dir, it gets marked as modified.
                // A similar thing applies to /root or /build etc
                if changepath == "/tmp" {
                    continue;
                }
                if changetype != "A" {
                    bail!(
                        "Path {} had a non-A changetype of {}",
                        changepath,
                        changetype
                    );
                }
                // Docker diff paths are in alphabetical order and we do `rm -rf`, so we might be able to skip
                // calling Docker more than necessary (since it's slow)
                if let Some(lastpath) = lastpath {
                    if Path::new(changepath).starts_with(lastpath) {
                        continue;
                    }
                }
                lastpath = Some(changepath);
                if let Err(e) = Command::new("docker")
                    .args(["exec", cid, "/busybox", "rm", "-rf", changepath])
                    .check_run()
                {
                    // We do a final check anyway, so just continue
                    warn!("Failed to remove added path in a container: {}", e)
                }
            }

            let newdiff = docker_diff(cid)?;
            // See note about changepath == "/tmp" above
            if !newdiff.is_empty() && newdiff != "C /tmp" {
                bail!(
                    "Attempted to delete files, but container still has a diff: {:?}",
                    newdiff
                );
            }
        }

        Ok(())
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_container(&self, tc: &Toolchain, cid: String) {
        // TODO: collect images

        if let Err(e) = self.clean_container(&cid) {
            info!("Failed to clean container {}: {}", cid, e);
            if let Err(e) = docker_rm(&cid) {
                warn!(
                    "Failed to remove container {} after failed clean: {}",
                    cid, e
                );
            }
            return;
        }

        // Good as new, add it back to the container list
        if let Some(entry) = self.container_lists.lock().unwrap().get_mut(tc) {
            debug!("Reclaimed container {}", cid);
            entry.push(cid)
        } else {
            warn!(
                "Was ready to reclaim container {} but toolchain went missing",
                cid
            );
            if let Err(e) = docker_rm(&cid) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
    }

    fn make_image(tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        // The open archive remains readable after we release the LRU lock.
        // Docker operations must not block other toolchain-cache users.
        let mut toolchain_rdr = {
            let mut cache = tccache.lock().unwrap();
            match cache.get(tc) {
                Ok(rdr) => rdr,
                Err(LruError::FileNotInCache) => bail!(
                    "Expected to find toolchain {}, but not available",
                    tc.archive_id
                ),
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("Failed to use toolchain {}", tc.archive_id));
                }
            }
        };

        let cid = Command::new("docker")
            .args(["create", BASE_DOCKER_IMAGE, "/busybox", "true"])
            .check_stdout_trim()
            .context("Failed to create docker container")?;

        // Once a temporary container exists, remove it even when copying or
        // committing the image fails. Keep the original failure as the result.
        let imagename = format!("sccache-builder-{}", &tc.archive_id);
        let image_result = (|| -> Result<()> {
            trace!("Copying in toolchain");
            Command::new("docker")
                .args(["cp", "-", &format!("{}:/", cid)])
                .check_piped(&mut |stdin| {
                    io::copy(&mut toolchain_rdr, stdin)?;
                    Ok(())
                })
                .context("Failed to copy toolchain tar into container")?;
            drop(toolchain_rdr);

            Command::new("docker")
                .args(["commit", &cid, &imagename])
                .check_run()
                .context("Failed to commit container after build")
        })();
        let cleanup_result = docker_rm(&cid);
        match (image_result, cleanup_result) {
            (Ok(()), Ok(())) => Ok(imagename),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => {
                Err(error.context("Failed to remove temporary build container"))
            }
            (Err(error), Err(cleanup_error)) => {
                warn!(
                    "Failed to remove temporary container {} after image creation failed: {cleanup_error:#}",
                    cid
                );
                Err(error)
            }
        }
    }

    fn start_container(image: &str) -> Result<String> {
        Command::new("docker")
            .args([
                "run",
                "-d",
                image,
                "/busybox",
                "sh",
                "-c",
                DOCKER_SHELL_INIT,
            ])
            .check_stdout_trim()
            .context("Failed to run container")
    }

    fn perform_build(
        compile_command: CompileCommand,
        inputs_rdr: InputsReader,
        outputs: OutputRequest,
        cid: &str,
    ) -> Result<BuildResult> {
        let OutputRequest {
            paths: output_paths,
            compression_level,
        } = outputs;
        trace!("Compile environment: {:?}", compile_command.env_vars);
        trace!(
            "Compile command: {:?} {:?}",
            compile_command.executable, compile_command.arguments
        );

        trace!("copying in inputs");
        let mut inputs_rdr = inputs_rdr.into_decoded()?;
        Command::new("docker")
            .args(["cp", "-", &format!("{}:/", cid)])
            .check_piped(&mut |stdin| {
                io::copy(&mut inputs_rdr, stdin)?;
                Ok(())
            })
            .context("Failed to copy inputs tar into container")?;
        drop(inputs_rdr);

        let CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        if output_paths.is_empty() {
            bail!("Docker build requires at least one output path");
        }
        let mut cmd = Command::new("docker");
        cmd.args(["exec", cid, "/busybox", "mkdir", "-p"]).arg(cwd);
        for path in output_paths.iter() {
            // If it doesn't have a parent, nothing needs creating
            let output_parent = if let Some(p) = Path::new(path).parent() {
                p
            } else {
                continue;
            };
            cmd.arg(cwd.join(output_parent));
        }
        cmd.check_run()
            .context("Failed to create directories required for compile in container")?;

        trace!("performing compile");
        // TODO: likely shouldn't perform the compile as root in the container
        let mut cmd = Command::new("docker");
        cmd.arg("exec");
        for (k, v) in env_vars {
            if k.contains('=') {
                warn!("Skipping environment variable: {:?}", k);
                continue;
            }
            let mut env = k;
            env.push('=');
            env.push_str(&v);
            cmd.arg("-e").arg(env);
        }
        let shell_cmd = "cd \"$1\" && shift && exec \"$@\"";
        cmd.args([cid, "/busybox", "sh", "-c", shell_cmd]);
        cmd.arg(&executable);
        cmd.arg(cwd);
        cmd.arg(executable);
        cmd.args(arguments);
        let compile_output = cmd.output().context("Failed to start executing compile")?;
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let abspath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("docker")
                .args(["exec", cid, "/busybox", "cat"])
                .arg(abspath)
                .output()
                .context("Failed to start command to retrieve output file")?;
            if output.status.success() {
                let output = ZstdFrame::try_from_reader(&*output.stdout, compression_level)
                    .context("failed to compress build output")?;
                outputs.push((path, output))
            } else {
                debug!("Missing output path {:?}", path)
            }
        }

        let compile_output = ProcessOutput::try_from(compile_output)
            .context("Failed to convert compilation exit status")?;
        Ok(BuildResult {
            output: compile_output,
            outputs,
        })
    }
}

impl BuilderIncoming for DockerBuilder {
    // From Server
    fn run_build(
        &self,
        tc: Toolchain,
        command: CompileCommand,
        outputs: OutputRequest,
        inputs_rdr: InputsReader,
        tccache: &Mutex<TcCache>,
    ) -> Result<BuildResult> {
        debug!("Finding container");
        let cid = self
            .get_container(&tc, tccache)
            .context("Failed to get a container for build")?;
        debug!("Performing build with container {}", cid);
        let result = Self::perform_build(command, inputs_rdr, outputs, &cid)
            .context("Failed to perform build");
        debug!("Finishing with container {}", cid);
        self.finish_container(&tc, cid);
        debug!("Returning result");
        result
    }
}

#[cfg(test)]
mod overlay_lifecycle_tests {
    use super::*;

    fn fixture_toolchain(marker: char) -> Toolchain {
        Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from(marker.to_string().repeat(64)).unwrap(),
        }
    }

    #[test]
    fn output_paths_follow_symlinks_only_within_build_root() -> Result<()> {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir()?;
        let root = tempdir.path().join("root");
        fs::create_dir(&root)?;
        fs::create_dir(root.join("inside"))?;
        symlink("/inside", root.join("alias"))?;

        let build_fs = RootedBuildFs::new(&root)?;
        build_fs.create_dir_all(Path::new("/alias/../alias/outputs"))?;
        assert!(
            root.join("inside/outputs").is_dir(),
            "absolute symlinks must resolve inside the build root"
        );
        fs::write(root.join("inside/outputs/object.o"), b"valid output")?;
        let mut result = Vec::new();
        use std::io::Read as _;
        build_fs
            .open_output(Path::new("/alias/outputs/object.o"))?
            .read_to_end(&mut result)?;
        assert_eq!(result, b"valid output");

        let host_secret = tempdir.path().join("outside-root");
        fs::write(&host_secret, b"host secret")?;
        symlink(&host_secret, root.join("host-link"))?;
        assert!(
            build_fs.open_output(Path::new("/host-link")).is_err(),
            "absolute symlinks must not expose host files"
        );
        let host_directory = tempdir.path().join("host-directory");
        fs::create_dir(&host_directory)?;
        symlink(&host_directory, root.join("host-dir-link"))?;
        assert!(
            build_fs
                .create_dir_all(Path::new("/host-dir-link/unwanted"))
                .is_err(),
            "absolute symlinks must not create directories on the host"
        );
        assert!(!host_directory.join("unwanted").exists());

        // .. is interpreted as it would be inside the compiler's chroot.
        build_fs.create_dir_all(Path::new("/../../relative-to-root"))?;
        assert!(root.join("relative-to-root").is_dir());
        assert!(!tempdir.path().join("relative-to-root").exists());
        Ok(())
    }

    #[test]
    fn missing_toolchain_does_not_leave_extraction_directory() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        fs::create_dir(tempdir.path().join("toolchains"))?;
        fs::create_dir(tempdir.path().join("builds"))?;

        let builder = OverlayBuilder {
            bubblewrap: PathBuf::from("unused-bubblewrap"),
            dir: tempdir.path().to_path_buf(),
            toolchain_dir_map: Mutex::new(HashMap::new()),
        };
        let tc = fixture_toolchain('d');
        let cache = Mutex::new(TcCache::new(&tempdir.path().join("tc-cache"), 1024 * 1024)?);
        let error = builder
            .prepare_overlay_dirs(&tc, &cache)
            .expect_err("missing toolchain must fail");
        assert!(
            error
                .to_string()
                .contains(&format!("expected toolchain {}", tc.archive_id)),
            "unexpected error: {error:#}"
        );
        assert!(
            !tempdir
                .path()
                .join("toolchains")
                .join(&tc.archive_id)
                .exists(),
            "missing archive must not poison subsequent extraction attempts"
        );
        Ok(())
    }
    #[test]
    fn active_extracted_toolchain_is_pruned_only_after_last_build_finishes() -> Result<()> {
        use std::io::Write as _;

        let tempdir = tempfile::tempdir()?;
        let toolchains_dir = tempdir.path().join("toolchains");
        fs::create_dir(&toolchains_dir)?;
        let builder = OverlayBuilder {
            bubblewrap: PathBuf::from("unused-bubblewrap"),
            dir: tempdir.path().to_path_buf(),
            toolchain_dir_map: Mutex::new(HashMap::new()),
        };
        let active_tc = fixture_toolchain('a');
        let idle_tc = fixture_toolchain('b');
        let archive = b"cached toolchain bytes";
        let cached_tc = Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from(sccache::util::Digest::reader_sync(
                &archive[..],
            )?)?,
        };
        let active_path = toolchains_dir.join(&active_tc.archive_id);
        let idle_path = toolchains_dir.join(&idle_tc.archive_id);
        let cached_path = toolchains_dir.join(&cached_tc.archive_id);
        fs::create_dir(&active_path)?;
        fs::create_dir(&idle_path)?;
        fs::create_dir(&cached_path)?;

        let lease = Arc::new(());
        let in_flight: Vec<_> = (0..2)
            .map(|_| OverlaySpec {
                build_dir: tempdir.path().join("unused-build"),
                toolchain_dir: active_path.clone(),
                _active_lease: Arc::clone(&lease),
            })
            .collect();
        let mut tc_cache = TcCache::new(&tempdir.path().join("tc-cache"), 1024 * 1024)?;
        tc_cache.insert_with(&cached_tc, |mut file| file.write_all(archive))?;
        let cache = Mutex::new(tc_cache);
        let mut dir_map = builder.toolchain_dir_map.lock().unwrap();
        dir_map.insert(
            active_tc.clone(),
            DeflatedToolchain {
                path: active_path.clone(),
                build_count: 2,
                active_lease: lease,
            },
        );
        dir_map.insert(
            idle_tc.clone(),
            DeflatedToolchain {
                path: idle_path.clone(),
                build_count: 1,
                active_lease: Arc::new(()),
            },
        );

        dir_map.insert(
            cached_tc.clone(),
            DeflatedToolchain {
                path: cached_path.clone(),
                build_count: 1,
                active_lease: Arc::new(()),
            },
        );

        builder.prune_unused_toolchain_dirs(&mut dir_map, &cache);
        assert!(
            cached_path.exists(),
            "cached toolchain must not be evicted by unrelated cache churn"
        );
        assert!(dir_map.contains_key(&cached_tc));
        assert!(
            active_path.exists(),
            "active toolchain must survive pruning"
        );
        assert!(!idle_path.exists(), "idle toolchain should be reclaimed");
        assert!(dir_map.contains_key(&active_tc));
        assert!(!dir_map.contains_key(&idle_tc));

        let mut active_builds = in_flight.into_iter();
        drop(active_builds.next());
        builder.prune_unused_toolchain_dirs(&mut dir_map, &cache);
        assert!(
            active_path.exists(),
            "another ongoing build must keep the toolchain alive"
        );

        drop(active_builds.next());
        builder.prune_unused_toolchain_dirs(&mut dir_map, &cache);
        assert!(!active_path.exists(), "last build release allows pruning");
        assert!(
            cached_path.exists(),
            "cached toolchain must remain available"
        );
        assert_eq!(dir_map.len(), 1);
        assert!(dir_map.contains_key(&cached_tc));
        Ok(())
    }
}

#[cfg(test)]
mod docker_listing_tests {
    use super::*;

    #[test]
    fn missing_toolchain_is_checked_before_creating_docker_container() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = Mutex::new(TcCache::new(&dir.path().join("toolchains"), 1024 * 1024)?);
        let tc = Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from("d".repeat(64)).unwrap(),
        };
        let error = DockerBuilder::make_image(&tc, &cache).expect_err("missing archive");
        assert!(
            error.to_string().contains("Expected to find toolchain"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn selects_only_owned_container_and_image_ids() -> Result<()> {
        let containers = "a1 some-other-image\nb2 sccache-builder-123:latest\nc3 sha256:abc";
        assert_eq!(builder_resource_ids(containers)?, vec!["b2"]);

        let images = "sha256:one sccache-builder-xyz\nsha256:two other-image\nsha256:three sccache-builder-abc";
        assert_eq!(
            builder_resource_ids(images)?,
            vec!["sha256:one", "sha256:three"]
        );
        assert!(builder_resource_ids("")?.is_empty());
        Ok(())
    }

    #[test]
    fn rejects_malformed_resource_listings() {
        for listing in [
            "missing-name",
            "id name extra",
            "id  ",
            "  ",
            "id name\nno-name",
        ] {
            assert!(
                builder_resource_ids(listing).is_err(),
                "incorrectly accepted malformed listing {listing:?}"
            );
        }
    }
}
