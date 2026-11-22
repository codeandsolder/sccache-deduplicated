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

use super::command_helpers::{CommandExt, run_with_environment};
use anyhow::{Context, Error, Result, bail};
use sccache::compression::ZstdFrame;
use sccache::compression::deflate::unpack_gzip;
use sccache::dist::{
    BuildResult, BuilderIncoming, CompileCommand, InputsReader, OutputRequest, ProcessOutput,
    TcCache, Toolchain,
};
use sccache::lru_disk_cache::Error as LruError;
use std::collections::{HashMap, hash_map};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use uuid::Uuid;

// Force remove the container
fn pot_rm(cid: &str, pot_cmd: &Path) -> Result<()> {
    Command::new(pot_cmd)
        .args(&["destroy", "-F", "-p", cid])
        .check_run()
        .context("Failed to force delete container")
}

#[derive(Clone)]
pub struct PotBuilder {
    pot_fs_root: PathBuf,
    clone_from: String,
    pot_cmd: PathBuf,
    pot_clone_args: Vec<String>,
    image_map: Arc<Mutex<HashMap<Toolchain, String>>>,
    container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
    cleanup_thread_count: Arc<AtomicUsize>,
    max_cleanup_thread_count: usize,
}

impl PotBuilder {
    // TODO: this should accept a unique string, e.g. inode of the tccache directory
    // having locked a pidfile, or at minimum should loudly detect other running
    // instances - pidfile in /tmp
    pub fn new(
        pot_fs_root: PathBuf,
        clone_from: String,
        pot_cmd: PathBuf,
        pot_clone_args: Vec<String>,
    ) -> Result<Self> {
        info!("Creating pot builder");

        let ret = Self {
            pot_fs_root,
            clone_from,
            pot_cmd,
            pot_clone_args,
            image_map: Arc::new(Mutex::new(HashMap::new())),
            container_lists: Arc::new(Mutex::new(HashMap::new())),
            cleanup_thread_count: Arc::new(AtomicUsize::new(0)),
            max_cleanup_thread_count: sccache::util::num_cpus() * 3,
        };
        ret.cleanup()?;
        Ok(ret)
    }

    // This removes all leftover pots from previous runs
    fn cleanup(&self) -> Result<()> {
        info!("Performing initial pot cleanup");
        let mut to_remove = Command::new(&self.pot_cmd)
            .args(&["ls", "-q"])
            .check_stdout_trim()
            .context("Failed to force delete container")?
            .split('\n')
            .filter(|a| a.starts_with("sccache-builder-") || a.starts_with("sccache-image-"))
            .map(|s| s.to_string())
            .collect::<Vec<String>>();
        to_remove.sort();
        for cid in to_remove {
            trace!("Removing pot {}", cid);
            if let Err(e) = pot_rm(&cid, &self.pot_cmd) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
        info!("Completed initial pot cleanup");
        Ok(())
    }

    // If we have a spare running container, claim it and remove it from the available list,
    // otherwise try and create a new container (possibly creating the Pot image along
    // the way)
    fn get_container(&self, tc: &Toolchain, tccache: &Mutex<TcCache>) -> Result<String> {
        let container = {
            let mut map = self.container_lists.lock().unwrap();
            map.entry(tc.clone()).or_insert_with(Vec::new).pop()
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
                            info!("Creating pot image for {:?} (may block requests)", tc);
                            let image = Self::make_image(
                                tc,
                                tccache,
                                &self.pot_fs_root,
                                &self.clone_from,
                                &self.pot_cmd,
                                &self.pot_clone_args,
                            )?;
                            e.insert(image.clone());
                            image
                        }
                    }
                };
                Self::start_container(&image, &self.pot_cmd, &self.pot_clone_args)
            }
        }
    }

    fn clean_container(cid: &str, pot_cmd: &Path) -> Result<()> {
        Command::new(pot_cmd)
            .args(&["stop", "-p", cid])
            .check_run()
            .context("Failed to stop container")?;

        Command::new(pot_cmd)
            .args(&["revert", "-p", cid])
            .check_run()
            .context("Failed to revert container")?;

        Command::new(pot_cmd)
            .args(&["start", "-p", cid])
            .check_run()
            .context("Failed to (re)start container")?;
        Ok(())
    }

    // Failing during cleanup is pretty unexpected, but we can still return the successful compile
    // TODO: if too many of these fail, we should mark this builder as faulty
    fn finish_container(
        container_lists: Arc<Mutex<HashMap<Toolchain, Vec<String>>>>,
        tc: Toolchain,
        cid: String,
        pot_cmd: &Path,
    ) {
        if let Err(e) = Self::clean_container(&cid, pot_cmd) {
            info!("Failed to clean container {}: {}", cid, e);
            if let Err(e) = pot_rm(&cid, pot_cmd) {
                warn!(
                    "Failed to remove container {} after failed clean: {}",
                    cid, e
                );
            }
            return;
        }

        // Good as new, add it back to the container list
        if let Some(entry) = container_lists.lock().unwrap().get_mut(&tc) {
            debug!("Reclaimed container {}", cid);
            entry.push(cid)
        } else {
            warn!(
                "Was ready to reclaim container {} but toolchain went missing",
                cid
            );
            if let Err(e) = pot_rm(&cid, pot_cmd) {
                warn!("Failed to remove container {}: {}", cid, e);
            }
        }
    }

    fn make_image(
        tc: &Toolchain,
        tccache: &Mutex<TcCache>,
        pot_fs_root: &Path,
        clone_from: &str,
        pot_cmd: &Path,
        pot_clone_args: &[String],
    ) -> Result<String> {
        // Hold the LRU mutex only long enough to open the archive. Extraction
        // may be slow, and the open descriptor remains valid after eviction.
        let toolchain_rdr = {
            let mut cache = tccache.lock().unwrap();
            match cache.get(tc) {
                Ok(rdr) => rdr,
                Err(LruError::FileNotInCache) => {
                    bail!("expected toolchain {}, but not available", tc.archive_id)
                }
                Err(e) => return Err(Error::from(e).context("failed to get toolchain from cache")),
            }
        };

        let imagename = format!("sccache-image-{}", &tc.archive_id);
        trace!("Creating toolchain image: {}", imagename);
        let mut clone_args: Vec<&str> = ["clone", "-p", &imagename, "-P", clone_from].to_vec();
        clone_args.extend(pot_clone_args.iter().map(String::as_str));
        Command::new(pot_cmd)
            .args(clone_args)
            .check_run()
            .context("Failed to create pot container")?;

        // A cloned image must be destroyed if either extraction or snapshot
        // fails, otherwise subsequent image creation can collide with it.
        let image_result = (|| -> Result<()> {
            trace!("Copying in toolchain");
            if let Err(error) = unpack_gzip(
                toolchain_rdr,
                &pot_fs_root.join("jails").join(&imagename).join("m"),
            ) {
                warn!("Failed to unpack toolchain: {error:?}");
                if let Err(cache_error) = tccache.lock().unwrap().remove(tc) {
                    warn!(
                        "Failed to remove corrupt toolchain {} from cache: {cache_error:#}",
                        tc.archive_id
                    );
                }
                return Err(Error::from(error).context("Failed to unpack toolchain"));
            }

            Command::new(pot_cmd)
                .args(["snapshot", "-p", &imagename])
                .check_run()
                .context("Failed to snapshot container after build")
        })();
        if let Err(error) = image_result {
            if let Err(cleanup_error) = pot_rm(&imagename, pot_cmd) {
                warn!(
                    "Failed to remove pot image {} after creation failed: {cleanup_error:#}",
                    imagename
                );
            }
            return Err(error);
        }
        Ok(imagename)
    }

    fn start_container(image: &str, pot_cmd: &Path, pot_clone_args: &[String]) -> Result<String> {
        let cid = format!("sccache-builder-{}", Uuid::new_v4());
        let mut clone_args: Vec<&str> = ["clone", "-p", &cid, "-P", image].to_vec();
        clone_args.extend(pot_clone_args.iter().map(String::as_str));
        Command::new(pot_cmd)
            .args(&clone_args)
            .check_run()
            .context("Failed to create pot container")?;

        let start_result = (|| -> Result<()> {
            Command::new(pot_cmd)
                .args(["snapshot", "-p", &cid])
                .check_run()
                .context("Failed to snapshot pot container")?;
            Command::new(pot_cmd)
                .args(["start", "-p", &cid])
                .check_run()
                .context("Failed to start container")
        })();
        if let Err(error) = start_result {
            if let Err(cleanup_error) = pot_rm(&cid, pot_cmd) {
                warn!(
                    "Failed to remove pot container {} after startup failed: {cleanup_error:#}",
                    cid
                );
            }
            return Err(error);
        }
        Ok(cid)
    }

    fn perform_build(
        compile_command: CompileCommand,
        inputs_rdr: InputsReader,
        outputs: OutputRequest,
        cid: &str,
        pot_fs_root: &Path,
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
        // not elegant
        inputs_rdr
            .unpack(&pot_fs_root.join("jails").join(cid).join("m"))
            .context("Failed to unpack inputs to pot")?;

        let CompileCommand {
            executable,
            arguments,
            env_vars,
            cwd,
        } = compile_command;
        let cwd = Path::new(&cwd);

        trace!("creating output directories");
        if output_paths.is_empty() {
            bail!("Pot build requires at least one output path");
        }
        let mut cmd = Command::new("jexec");
        cmd.args(&[cid, "mkdir", "-p"]).arg(cwd);
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
        let mut cmd = Command::new("jexec");
        // Set cwd first, then clear the shell's environment as well as
        // the jail's inherited environment before executing the compiler.
        cmd.arg(cid);
        let shell_cmd = "cd \"$1\" && shift && exec /usr/bin/env -i -- \"$@\"";
        cmd.args(["/bin/sh", "-c", shell_cmd]);
        cmd.arg(&executable);
        cmd.arg(cwd);
        let compile_output = run_with_environment(&mut cmd, env_vars, executable, arguments)?;
        trace!("compile_output: {:?}", compile_output);

        let mut outputs = vec![];
        trace!("retrieving {:?}", output_paths);
        for path in output_paths {
            let abspath = cwd.join(&path); // Resolve in case it's relative since we copy it from the root level
            // TODO: this isn't great, but cp gives it out as a tar
            let output = Command::new("jexec")
                .args(&[cid, "cat"])
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

impl BuilderIncoming for PotBuilder {
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
        let result = Self::perform_build(command, inputs_rdr, outputs, &cid, &self.pot_fs_root)
            .context("Failed to perform build");
        debug!("Finishing with container {}", cid);
        let cloned = self.clone();
        loop {
            let active = cloned.cleanup_thread_count.load(Ordering::Relaxed);
            if active < self.max_cleanup_thread_count
                && cloned
                    .cleanup_thread_count
                    .compare_exchange_weak(active, active + 1, Ordering::AcqRel, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            thread::yield_now();
        }
        thread::spawn(move || {
            Self::finish_container(cloned.container_lists, tc, cid, &cloned.pot_cmd);
            cloned.cleanup_thread_count.fetch_sub(1, Ordering::Release);
        });
        debug!("Returning result");
        result
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn missing_toolchain_is_rejected_before_cloning_pot() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cache = Mutex::new(TcCache::new(&dir.path().join("toolchains"), 1024 * 1024)?);
        let tc = Toolchain {
            archive_id: sccache::dist::ArchiveId::try_from("d".repeat(64))?,
        };
        let error = PotBuilder::make_image(
            &tc,
            &cache,
            dir.path(),
            "base",
            Path::new("/missing-pot-command"),
            &[],
        )
        .expect_err("missing archive must not launch pot");
        assert!(
            error
                .to_string()
                .contains(&format!("expected toolchain {}", tc.archive_id))
        );
        Ok(())
    }

    #[test]
    fn cleanup_uses_configured_pot_command() -> Result<()> {
        PotBuilder::clean_container("test-container", Path::new("/usr/bin/true"))
    }
}
