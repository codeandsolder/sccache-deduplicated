use crate::dist::{ArchiveId, Toolchain};
use crate::lru_disk_cache::Result as LruResult;
use crate::lru_disk_cache::{LruDiskCache, ReadSeek};
use anyhow::{Result, anyhow};
use fs_err as fs;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(feature = "dist-client")]
pub use self::client::ClientToolchains;
use crate::util::Digest;
use std::io::Read;

#[cfg(feature = "dist-client")]
mod client {
    use crate::config;
    use crate::dist::pkg::ToolchainPackager;
    use crate::dist::{ArchiveId, CustomToolchainOverride, Toolchain};
    use crate::lru_disk_cache::Error as LruError;
    use anyhow::{Context, Error, Result, anyhow, bail};
    use fs_err as fs;
    use std::collections::{HashMap, HashSet};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use super::{TcCache, path_key};

    #[derive(Clone, Debug)]
    struct CustomToolchain {
        archive: PathBuf,
        compiler_executable: String,
        cargo_executable: Option<String>,
        identity: Option<Toolchain>,
        hash_lock: Arc<Mutex<()>>,
    }

    impl CustomToolchain {
        fn to_override(&self) -> CustomToolchainOverride {
            CustomToolchainOverride {
                compiler_executable: self.compiler_executable.clone(),
                archive: self.archive.clone(),
                cargo_executable: self.cargo_executable.clone(),
            }
        }
    }

    // Both indexes must be updated under one lock: returning a resolved toolchain
    // without registering its archive makes get_toolchain() miss that toolchain.
    struct CustomToolchainRegistry {
        configured: HashMap<PathBuf, CustomToolchain>,
        archives: HashMap<Toolchain, PathBuf>,
    }

    impl CustomToolchainRegistry {
        fn register(
            &mut self,
            compiler_path: &Path,
            candidate: Toolchain,
        ) -> Result<(Toolchain, CustomToolchainOverride)> {
            let custom = self
                .configured
                .get_mut(compiler_path)
                .ok_or_else(|| anyhow!("configured toolchain disappeared during registration"))?;
            // Another caller may have completed hashing and registered the path.
            let tc = custom.identity.get_or_insert(candidate).clone();
            let override_ = custom.to_override();
            let previous = self.archives.insert(tc.clone(), override_.archive.clone());
            if let Some(previous) = previous
                && previous != override_.archive
            {
                warn!(
                    "Detected interchangeable toolchain archives at {} and {}",
                    previous.display(),
                    override_.archive.display()
                );
            }
            Ok((tc, override_))
        }
    }

    pub struct ClientToolchains {
        cache_dir: PathBuf,
        cache: Mutex<TcCache>,
        toolchain_creation: Mutex<()>,
        custom_toolchains: Mutex<CustomToolchainRegistry>,
        // Toolchains configured to not be distributed
        disabled_toolchains: HashSet<PathBuf>,
        // Local machine mapping from 'weak' hashes to strong toolchain hashes
        // - Weak hashes are what sccache uses to determine if a compiler has changed
        //   on the local machine - they're fast and 'good enough' (assuming we trust
        //   the local machine), but not safe if other users can update the cache.
        // - Strong hashes (or 'archive ids') are the hash of the complete compiler contents that
        //   will be sent over the wire for use in distributed compilation - it is assumed
        //   that if two of them match, the contents of a compiler archive cannot
        //   have been tampered with
        weak_map: Mutex<HashMap<String, String>>,
    }

    impl ClientToolchains {
        pub fn new(
            cache_dir: &Path,
            cache_size: u64,
            toolchain_configs: &[config::DistToolchainConfig],
        ) -> Result<Self> {
            let cache_dir = cache_dir.to_owned();
            fs::create_dir_all(&cache_dir).context(format!(
                "failed to create top level toolchain cache dir: {}",
                cache_dir.display()
            ))?;

            let toolchain_creation_dir = cache_dir.join("toolchain_tmp");
            if toolchain_creation_dir.exists() {
                fs::remove_dir_all(&toolchain_creation_dir).context(format!(
                    "failed to clean up temporary toolchain creation directory: {}",
                    toolchain_creation_dir.display()
                ))?;
            }
            fs::create_dir(&toolchain_creation_dir).context(format!(
                "failed to create temporary toolchain creation directory: {}",
                toolchain_creation_dir.display()
            ))?;

            let weak_map_path = cache_dir.join("weak_map.json");
            if !weak_map_path.exists() {
                fs::File::create(&weak_map_path)
                    .and_then(|mut f| f.write_all(b"{}"))
                    .context(format!(
                        "failed to create new toolchain weak map file: {}",
                        weak_map_path.display()
                    ))?;
            }
            let weak_map = fs::File::open(&weak_map_path)
                .map_err(Error::from)
                .and_then(|f| serde_json::from_reader(f).map_err(Error::from))
                .context(format!(
                    "failed to load toolchain weak map: {}",
                    weak_map_path.display()
                ))?;

            let tc_cache_dir = cache_dir.join("tc");
            let cache = TcCache::new(&tc_cache_dir, cache_size)
                .map(Mutex::new)
                .context("failed to initialise a toolchain cache")?;

            // Load in toolchain configuration
            let mut custom_toolchain_paths = HashMap::new();
            let mut disabled_toolchains = HashSet::new();
            for ct in toolchain_configs {
                match ct {
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable,
                        archive,
                        archive_compiler_executable,
                        archive_cargo_executable,
                    } => {
                        debug!(
                            "Registering custom toolchain for {}",
                            compiler_executable.display()
                        );
                        let custom_tc = CustomToolchain {
                            archive: archive.clone(),
                            compiler_executable: archive_compiler_executable.clone(),
                            cargo_executable: archive_cargo_executable.clone(),
                            identity: None,
                            hash_lock: Arc::new(Mutex::new(())),
                        };
                        if custom_toolchain_paths
                            .insert(compiler_executable.clone(), custom_tc)
                            .is_some()
                        {
                            bail!("Multiple toolchains for {}", compiler_executable.display())
                        }
                        if disabled_toolchains.contains(compiler_executable) {
                            bail!(
                                "Override for toolchain {} conflicts with it being disabled",
                                compiler_executable.display()
                            )
                        }
                    }
                    config::DistToolchainConfig::NoDist {
                        compiler_executable,
                    } => {
                        debug!("Disabling toolchain {}", compiler_executable.display());
                        if !disabled_toolchains.insert(compiler_executable.clone()) {
                            bail!(
                                "Disabled toolchain {} multiple times",
                                compiler_executable.display()
                            )
                        }
                        if custom_toolchain_paths.contains_key(compiler_executable) {
                            bail!(
                                "Override for toolchain {} conflicts with it being disabled",
                                compiler_executable.display()
                            )
                        }
                    }
                }
            }
            Ok(Self {
                cache_dir,
                cache,
                toolchain_creation: Mutex::new(()),
                custom_toolchains: Mutex::new(CustomToolchainRegistry {
                    configured: custom_toolchain_paths,
                    archives: HashMap::new(),
                }),
                disabled_toolchains,
                // TODO: shouldn't clear on restart, but also should have some
                // form of pruning
                weak_map: Mutex::new(weak_map),
            })
        }

        // Get the bytes of a toolchain tar
        // TODO: by this point the toolchain should be known to exist
        pub fn get_toolchain(&self, tc: &Toolchain) -> Result<Option<fs::File>> {
            // TODO: be more relaxed about path casing and slashes on Windows
            let custom_tc_archive = self
                .custom_toolchains
                .lock()
                .map_err(|_| anyhow::anyhow!("custom toolchain registry mutex poisoned"))?
                .archives
                .get(tc)
                .cloned();
            let file = if let Some(custom_tc_archive) = custom_tc_archive {
                fs::File::open(&custom_tc_archive).with_context(|| {
                    format!(
                        "could not open file for toolchain {}",
                        custom_tc_archive.display()
                    )
                })?
            } else {
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|_| anyhow::anyhow!("toolchain cache mutex poisoned"))?;
                match cache.get_file(tc) {
                    Ok(file) => file,
                    Err(LruError::FileNotInCache) => return Ok(None),
                    Err(e) => return Err(e).context("error while retrieving toolchain from cache"),
                }
            };
            Ok(Some(file))
        }
        // If the toolchain doesn't already exist, create it and insert into the cache
        pub fn put_toolchain(
            &self,
            compiler_path: &Path,
            weak_key: &str,
            toolchain_packager: Box<dyn ToolchainPackager>,
        ) -> Result<(Toolchain, Option<CustomToolchainOverride>)> {
            if self.disabled_toolchains.contains(compiler_path) {
                bail!(
                    "Toolchain distribution for {} is disabled",
                    compiler_path.display()
                )
            }
            if let Some((tc, toolchain_override)) = self.get_custom_toolchain(compiler_path)? {
                debug!("Using custom toolchain for {}", compiler_path.display());
                return Ok((tc, Some(toolchain_override)));
            }
            // Include package-specific dependencies in the weak cache identity.
            // A GCC executable can stay byte-identical while its assembler,
            // linker or other helper is rebuilt in place.
            let weak_key = toolchain_packager.cache_key_extension()?.map_or_else(
                || weak_key.to_owned(),
                |extra| format!("{weak_key}:{extra}"),
            );
            self.get_or_create(&weak_key, |file| toolchain_packager.write_pkg(file))
                .map(|toolchain| (toolchain, None))
        }

        fn check_namespace_policy(&self, compiler_path: &Path) -> Result<()> {
            if self.disabled_toolchains.contains(compiler_path) {
                bail!(
                    "Toolchain distribution for {} is disabled",
                    compiler_path.display()
                );
            }
            // A host path override does not identify a compiler in a different
            // namespace. Only the namespace caller may resolve its own override.
            Ok(())
        }

        pub(crate) fn lookup_namespace_toolchain(
            &self,
            compiler_path: &Path,
            key: &str,
        ) -> Result<(Option<Toolchain>, u64)> {
            self.check_namespace_policy(compiler_path)?;
            let tc = self.lookup_toolchain(&format!("namespace:{key}"))?;
            let max_size = self
                .cache
                .lock()
                .map_err(|_| anyhow!("toolchain cache mutex poisoned"))?
                .inner
                .capacity();
            Ok((tc, max_size))
        }

        pub(crate) fn import_namespace_toolchain(
            &self,
            compiler_path: &Path,
            key: &str,
            mut package: std::fs::File,
        ) -> Result<Toolchain> {
            self.check_namespace_policy(compiler_path)?;
            self.get_or_create(&format!("namespace:{key}"), move |mut file| {
                std::io::copy(&mut package, &mut file)?;
                Ok(())
            })
        }

        fn lookup_toolchain(&self, weak_key: &str) -> Result<Option<Toolchain>> {
            let Some(archive_id) = self.weak_to_strong(weak_key)? else {
                return Ok(None);
            };
            let tc = Toolchain { archive_id };
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| anyhow!("toolchain cache mutex poisoned"))?;
            match cache.get_file(&tc) {
                Ok(_) => Ok(Some(tc)),
                Err(LruError::FileNotInCache) => Ok(None),
                Err(LruError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok(None)
                }
                Err(error) => Err(error).context("error while validating cached toolchain"),
            }
        }

        fn get_or_create(
            &self,
            weak_key: &str,
            create: impl FnOnce(fs::File) -> Result<()>,
        ) -> Result<Toolchain> {
            // A warm package does not depend on an unrelated cold package
            // finishing compression. Repeat the lookup after acquiring the
            // creation lock to retain single-flight behavior on a miss.
            if let Some(tc) = self.lookup_toolchain(weak_key)? {
                return Ok(tc);
            }
            // Only permit one toolchain creation at a time, without holding the
            // LRU cache mutex across potentially slow packaging I/O.
            let _creation_guard = self
                .toolchain_creation
                .lock()
                .map_err(|_| anyhow!("toolchain creation mutex poisoned"))?;
            if let Some(tc) = self.lookup_toolchain(weak_key)? {
                debug!("Using cached toolchain {weak_key} -> {}", tc.archive_id);
                return Ok(tc);
            }
            debug!("Weak key {weak_key} requires toolchain packaging");
            let tmpfile = tempfile::NamedTempFile::new_in(self.cache_dir.join("toolchain_tmp"))?;
            create(fs_err::File::from_parts(tmpfile.reopen()?, tmpfile.path()))
                .context("Could not package toolchain")?;
            let tc = {
                let mut cache = self
                    .cache
                    .lock()
                    .map_err(|_| anyhow!("toolchain cache mutex poisoned"))?;
                cache.insert_file(tmpfile.path())?
            };
            self.record_weak(weak_key.to_owned(), tc.archive_id.to_string())?;
            Ok(tc)
        }

        pub(crate) fn get_custom_toolchain(
            &self,
            compiler_path: &Path,
        ) -> Result<Option<(Toolchain, CustomToolchainOverride)>> {
            let (archive, hash_lock) = {
                let registry = self
                    .custom_toolchains
                    .lock()
                    .map_err(|_| anyhow!("custom toolchain registry mutex poisoned"))?;
                let Some(custom) = registry.configured.get(compiler_path) else {
                    return Ok(None);
                };
                if let Some(tc) = &custom.identity {
                    return Ok(Some((tc.clone(), custom.to_override())));
                }
                let values = (custom.archive.clone(), Arc::clone(&custom.hash_lock));
                drop(registry);
                values
            };
            // Only one caller hashes an uninitialized archive. Other toolchains
            // and archive lookups remain independent of this slow I/O.
            let hash_guard = hash_lock
                .lock()
                .map_err(|_| anyhow!("custom toolchain hash mutex poisoned"))?;
            {
                let registry = self
                    .custom_toolchains
                    .lock()
                    .map_err(|_| anyhow!("custom toolchain registry mutex poisoned"))?;
                let Some(custom) = registry.configured.get(compiler_path) else {
                    return Err(anyhow!("configured toolchain disappeared during hashing"));
                };
                if let Some(tc) = &custom.identity {
                    return Ok(Some((tc.clone(), custom.to_override())));
                }
                drop(registry);
            }
            let candidate = Toolchain {
                archive_id: path_key(&archive)?,
            };
            let mut registry = self
                .custom_toolchains
                .lock()
                .map_err(|_| anyhow!("custom toolchain registry mutex poisoned"))?;
            let result = registry.register(compiler_path, candidate).map(Some);
            drop(registry);
            drop(hash_guard);
            result
        }

        fn weak_to_strong(&self, weak_key: &str) -> Result<Option<ArchiveId>> {
            let result = {
                let weak_map = self
                    .weak_map
                    .lock()
                    .map_err(|_| anyhow::anyhow!("toolchain weak-map mutex poisoned"))?;
                weak_map.get(weak_key).cloned()
            };
            Ok(result.and_then(|value| match ArchiveId::try_from(value) {
                Ok(id) => Some(id),
                Err(error) => {
                    warn!("Ignoring malformed weak toolchain mapping for {weak_key}: {error}");
                    None
                }
            }))
        }
        fn record_weak(&self, weak_key: String, key: String) -> Result<()> {
            let mut weak_map = self
                .weak_map
                .lock()
                .map_err(|_| anyhow::anyhow!("toolchain weak-map mutex poisoned"))?;
            // Keep serialization and persistence under the same lock so concurrent
            // updates cannot publish an older snapshot over a newer one.
            let mut updated = weak_map.clone();
            updated.insert(weak_key, key);
            let serialized = serde_json::to_vec(&updated).map_err(Error::from)?;
            let weak_map_path = self.cache_dir.join("weak_map.json");
            let mut temporary = tempfile::NamedTempFile::new_in(&self.cache_dir)
                .context("failed to create temporary toolchain weak map")?;
            temporary
                .write_all(&serialized)
                .context("failed to write temporary toolchain weak map")?;
            temporary
                .persist(&weak_map_path)
                .map_err(|error| error.error)
                .context("failed to publish toolchain weak map")?;
            *weak_map = updated;
            drop(weak_map);
            Ok(())
        }
    }

    #[cfg(test)]
    mod test {
        use crate::config;
        use crate::test::utils::create_file;
        use anyhow::{Result, anyhow};
        use std::io::Write;

        use super::{ClientToolchains, CustomToolchainOverride};

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        struct StaticToolchainPackager;

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        impl crate::dist::pkg::ToolchainPackager for StaticToolchainPackager {
            fn write_pkg(self: Box<Self>, mut f: super::fs::File) -> crate::errors::Result<()> {
                f.write_all(b"toolchain_contents")?;
                Ok(())
            }
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        struct DependencyVersionedPackage(&'static str);

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        impl crate::dist::pkg::ToolchainPackager for DependencyVersionedPackage {
            fn cache_key_extension(&self) -> Result<Option<String>> {
                Ok(Some(self.0.to_owned()))
            }

            fn write_pkg(self: Box<Self>, mut f: super::fs::File) -> crate::errors::Result<()> {
                f.write_all(self.0.as_bytes())?;
                Ok(())
            }
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[test]
        fn toolchain_repackages_when_external_helper_changes() -> Result<()> {
            let temp = tempfile::tempdir()?;
            let client = ClientToolchains::new(temp.path(), 1024 * 1024, &[])?;
            let path = std::path::Path::new("/compiler/whose-binary-did-not-change");
            let (first, _) = client.put_toolchain(
                path,
                "same-compiler-executable-digest",
                Box::new(DependencyVersionedPackage("binutils-v1")),
            )?;
            let (second, _) = client.put_toolchain(
                path,
                "same-compiler-executable-digest",
                Box::new(DependencyVersionedPackage("binutils-v2")),
            )?;
            assert_ne!(first.archive_id, second.archive_id);
            assert!(client.get_toolchain(&first)?.is_some());
            assert!(client.get_toolchain(&second)?.is_some());
            Ok(())
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        fn cached_toolchain() -> Result<(
            tempfile::TempDir,
            std::path::PathBuf,
            ClientToolchains,
            crate::dist::Toolchain,
        )> {
            let td = tempfile::Builder::new().prefix("sccache").tempdir()?;
            let cache_dir = td.path().join("cache");
            let client = ClientToolchains::new(&cache_dir, 1024 * 1024, &[])?;
            let (toolchain, _) = client.put_toolchain(
                "/my/compiler".as_ref(),
                "weak_key",
                Box::new(StaticToolchainPackager),
            )?;
            assert!(client.get_toolchain(&toolchain)?.is_some());
            Ok((td, cache_dir, client, toolchain))
        }

        struct PanicToolchainPackager;
        impl PanicToolchainPackager {
            fn boxed() -> Box<Self> {
                Box::new(Self)
            }
        }
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        impl crate::dist::pkg::ToolchainPackager for PanicToolchainPackager {
            fn write_pkg(self: Box<Self>, _f: super::fs::File) -> crate::errors::Result<()> {
                Err(anyhow!("unexpected toolchain packager invocation"))
            }
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[test]
        fn stale_weak_mapping_repackages_missing_archive() -> Result<()> {
            let (_td, cache_dir, first, toolchain) = cached_toolchain()?;
            drop(first);

            std::fs::remove_dir_all(cache_dir.join("tc"))?;

            let second = ClientToolchains::new(&cache_dir, 1024 * 1024, &[])?;
            let (repacked, _) = second.put_toolchain(
                "/my/compiler".as_ref(),
                "weak_key",
                Box::new(StaticToolchainPackager),
            )?;

            assert_eq!(repacked, toolchain);
            assert!(second.get_toolchain(&repacked)?.is_some());
            Ok(())
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[test]
        fn cached_toolchain_lookup_does_not_wait_for_unrelated_packaging() -> Result<()> {
            let (_td, _cache_dir, client, toolchain) = cached_toolchain()?;
            let client = std::sync::Arc::new(client);
            let creation = client.toolchain_creation.lock().unwrap();
            let worker = std::sync::Arc::clone(&client);
            let (tx, rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                tx.send(worker.put_toolchain(
                    "/my/compiler".as_ref(),
                    "weak_key",
                    PanicToolchainPackager::boxed(),
                ))
            });
            let result = rx.recv_timeout(std::time::Duration::from_secs(5));
            drop(creation);
            thread.join().expect("lookup thread panicked")?;
            assert_eq!(result??.0, toolchain);
            Ok(())
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[test]
        fn malformed_weak_mapping_repackages_and_repairs_disk_index() -> Result<()> {
            let (_td, cache_dir, first, toolchain) = cached_toolchain()?;
            drop(first);

            std::fs::write(
                cache_dir.join("weak_map.json"),
                br#"{"weak_key":"../malformed"}"#,
            )?;
            let recovered = ClientToolchains::new(&cache_dir, 1024 * 1024, &[])?;
            let (repacked, _) = recovered.put_toolchain(
                "/my/compiler".as_ref(),
                "weak_key",
                Box::new(StaticToolchainPackager),
            )?;
            assert_eq!(repacked, toolchain);
            assert_eq!(
                recovered.weak_to_strong("weak_key")?,
                Some(toolchain.archive_id.clone())
            );
            let persisted: serde_json::Value =
                serde_json::from_slice(&std::fs::read(cache_dir.join("weak_map.json"))?)?;
            assert_eq!(persisted["weak_key"], toolchain.archive_id.to_string());
            Ok(())
        }

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        #[test]
        fn missing_archive_file_repackages_without_restart() -> Result<()> {
            let (_td, cache_dir, client, toolchain) = cached_toolchain()?;

            let archive_path = cache_dir
                .join("tc")
                .join(&toolchain.archive_id[0..1])
                .join(&toolchain.archive_id[1..2])
                .join(&toolchain.archive_id);
            std::fs::remove_file(archive_path)?;

            let (repacked, _) = client.put_toolchain(
                "/my/compiler".as_ref(),
                "weak_key",
                Box::new(StaticToolchainPackager),
            )?;
            assert_eq!(repacked, toolchain);
            assert!(client.get_toolchain(&repacked)?.is_some());
            Ok(())
        }

        #[test]
        fn custom_toolchain_registration_is_atomic_across_both_indexes() -> Result<()> {
            let directory = tempfile::tempdir()?;
            let archive = create_file(directory.path(), "custom.tar", |mut file| {
                file.write_all(b"custom archive")
            })?;
            let client = std::sync::Arc::new(ClientToolchains::new(
                &directory.path().join("cache"),
                1024 * 1024,
                &[config::DistToolchainConfig::PathOverride {
                    compiler_executable: "/my/compiler".into(),
                    archive,
                    archive_compiler_executable: "/my/compiler".into(),
                    archive_cargo_executable: None,
                }],
            )?);

            let workers: Vec<_> = (0..16)
                .map(|_| {
                    let client = std::sync::Arc::clone(&client);
                    std::thread::spawn(move || -> Result<crate::dist::Toolchain> {
                        let (tc, _) = client
                            .get_custom_toolchain("/my/compiler".as_ref())?
                            .ok_or_else(|| anyhow!("configured toolchain was not found"))?;
                        assert!(client.get_toolchain(&tc)?.is_some());
                        Ok(tc)
                    })
                })
                .collect();
            let mut expected = None;
            for worker in workers {
                let tc = worker.join().expect("worker panicked")?;
                if let Some(expected) = &expected {
                    assert_eq!(expected, &tc);
                } else {
                    expected = Some(tc);
                }
            }
            Ok(())
        }

        #[test]
        fn custom_toolchain_failed_hash_can_be_retried() -> Result<()> {
            let directory = tempfile::tempdir()?;
            let archive = directory.path().join("custom.tar");
            let client = ClientToolchains::new(
                &directory.path().join("cache"),
                1024 * 1024,
                &[config::DistToolchainConfig::PathOverride {
                    compiler_executable: "/my/compiler".into(),
                    archive: archive.clone(),
                    archive_compiler_executable: "/my/compiler".into(),
                    archive_cargo_executable: None,
                }],
            )?;
            assert!(
                client
                    .get_custom_toolchain("/my/compiler".as_ref())
                    .is_err()
            );
            std::fs::write(&archive, b"restored archive")?;
            let (tc, _) = client
                .get_custom_toolchain("/my/compiler".as_ref())?
                .ok_or_else(|| anyhow!("configured toolchain was not found"))?;
            assert!(client.get_toolchain(&tc)?.is_some());
            Ok(())
        }

        #[test]
        fn weak_map_failed_publish_does_not_mutate_memory() -> Result<()> {
            let directory = tempfile::tempdir()?;
            let client = ClientToolchains::new(directory.path(), 1024 * 1024, &[])?;
            let index = directory.path().join("weak_map.json");
            std::fs::remove_file(&index)?;
            std::fs::create_dir(&index)?;
            assert!(client.record_weak("weak".into(), "strong".into()).is_err());
            assert!(client.weak_map.lock().unwrap().get("weak").is_none());
            Ok(())
        }

        #[test]
        fn concurrent_weak_map_updates_are_all_persisted() -> Result<()> {
            let directory = tempfile::tempdir()?;
            let client =
                std::sync::Arc::new(ClientToolchains::new(directory.path(), 1024 * 1024, &[])?);
            let threads: Vec<_> = (0..8)
                .map(|index| {
                    let client = std::sync::Arc::clone(&client);
                    std::thread::spawn(move || {
                        client.record_weak(format!("weak-{index}"), format!("strong-{index}"))
                    })
                })
                .collect();
            for thread in threads {
                thread.join().expect("worker panicked")?;
            }
            let persisted: std::collections::HashMap<String, String> =
                serde_json::from_slice(&std::fs::read(directory.path().join("weak_map.json"))?)?;
            for index in 0..8 {
                assert_eq!(
                    persisted.get(&format!("weak-{index}")),
                    Some(&format!("strong-{index}"))
                );
            }
            Ok(())
        }

        #[test]
        fn test_client_toolchains_custom() -> Result<()> {
            let td = tempfile::Builder::new().prefix("sccache").tempdir()?;

            let ct1 = create_file(td.path(), "ct1", |mut f| f.write_all(b"toolchain_contents"))?;

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[config::DistToolchainConfig::PathOverride {
                    compiler_executable: "/my/compiler".into(),
                    archive: ct1.clone(),
                    archive_compiler_executable: "/my/compiler/in_archive".into(),
                    archive_cargo_executable: Some("/my/cargo/in_archive".into()),
                }],
            )?;

            let (_tc, newpath) = client_toolchains.put_toolchain(
                "/my/compiler".as_ref(),
                "weak_key",
                PanicToolchainPackager::boxed(),
            )?;
            assert_eq!(
                newpath.ok_or_else(|| anyhow!("missing custom toolchain path"))?,
                CustomToolchainOverride {
                    compiler_executable: "/my/compiler/in_archive".to_owned(),
                    archive: ct1,
                    cargo_executable: Some("/my/cargo/in_archive".to_owned()),
                }
            );
            Ok(())
        }

        #[test]
        fn test_client_toolchains_custom_multiuse_archive() -> Result<()> {
            let td = tempfile::Builder::new().prefix("sccache").tempdir()?;

            let ct1 = create_file(td.path(), "ct1", |mut f| f.write_all(b"toolchain_contents"))?;

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler".into(),
                        archive: ct1.clone(),
                        archive_compiler_executable: "/my/compiler/in_archive".into(),
                        archive_cargo_executable: None,
                    },
                    // Uses the same archive, but a maps a different external compiler to a different archive compiler
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler2".into(),
                        archive: ct1.clone(),
                        archive_compiler_executable: "/my/compiler2/in_archive".into(),
                        archive_cargo_executable: None,
                    },
                    // Uses the same archive, but a maps a different external compiler to the same archive compiler as the first
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler3".into(),
                        archive: ct1.clone(),
                        archive_compiler_executable: "/my/compiler/in_archive".into(),
                        archive_cargo_executable: None,
                    },
                ],
            )?;

            let (_tc, newpath) = client_toolchains.put_toolchain(
                "/my/compiler".as_ref(),
                "weak_key",
                PanicToolchainPackager::boxed(),
            )?;
            assert_eq!(
                newpath.ok_or_else(|| anyhow!("missing custom toolchain path"))?,
                CustomToolchainOverride {
                    compiler_executable: "/my/compiler/in_archive".to_owned(),
                    archive: ct1.clone(),
                    cargo_executable: None,
                }
            );
            let (_tc, newpath) = client_toolchains.put_toolchain(
                "/my/compiler2".as_ref(),
                "weak_key2",
                PanicToolchainPackager::boxed(),
            )?;
            assert_eq!(
                newpath.ok_or_else(|| anyhow!("missing custom toolchain path"))?,
                CustomToolchainOverride {
                    compiler_executable: "/my/compiler2/in_archive".to_owned(),
                    archive: ct1.clone(),
                    cargo_executable: None,
                }
            );
            let (_tc, newpath) = client_toolchains.put_toolchain(
                "/my/compiler3".as_ref(),
                "weak_key2",
                PanicToolchainPackager::boxed(),
            )?;
            assert_eq!(
                newpath.ok_or_else(|| anyhow!("missing custom toolchain path"))?,
                CustomToolchainOverride {
                    compiler_executable: "/my/compiler/in_archive".to_owned(),
                    archive: ct1,
                    cargo_executable: None,
                }
            );
            Ok(())
        }

        #[test]
        fn test_client_toolchains_nodist() -> Result<()> {
            let td = tempfile::Builder::new().prefix("sccache").tempdir()?;

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[config::DistToolchainConfig::NoDist {
                    compiler_executable: "/my/compiler".into(),
                }],
            )?;

            assert!(
                client_toolchains
                    .put_toolchain(
                        "/my/compiler".as_ref(),
                        "weak_key",
                        PanicToolchainPackager::boxed()
                    )
                    .is_err()
            );
            Ok(())
        }

        #[test]
        fn test_client_toolchains_custom_nodist_conflict() -> Result<()> {
            let td = tempfile::Builder::new().prefix("sccache").tempdir()?;

            let ct1 = create_file(td.path(), "ct1", |mut f| f.write_all(b"toolchain_contents"))?;

            let client_toolchains = ClientToolchains::new(
                &td.path().join("cache"),
                1024,
                &[
                    config::DistToolchainConfig::PathOverride {
                        compiler_executable: "/my/compiler".into(),
                        archive: ct1,
                        archive_compiler_executable: "/my/compiler".into(),
                        archive_cargo_executable: None,
                    },
                    config::DistToolchainConfig::NoDist {
                        compiler_executable: "/my/compiler".into(),
                    },
                ],
            );
            assert!(client_toolchains.is_err());
            Ok(())
        }
    }
}

pub struct TcCache {
    inner: LruDiskCache,
}

/// A received, hash-verified archive that can be installed without holding
/// the cache mutex across network I/O or archive hashing.
pub struct StagedToolchainArchive {
    toolchain: Toolchain,
    file: tempfile::NamedTempFile,
}

impl StagedToolchainArchive {
    /// Clone an immutable snapshot of an archive from another local cache,
    /// without sharing writable names or LRU state. Verify the cloned bytes,
    /// rather than trusting a filename or a mutable source file.
    /// A missing/unsupported/corrupt source is a normal cache miss.
    ///
    /// # Errors
    /// Returns an error for invalid paths, unsupported clones, oversized
    /// archives, I/O failures, or digest mismatches.
    #[cfg(all(target_os = "linux", feature = "dist-server"))]
    pub fn clone_verified(
        directory: &Path,
        source_root: &Path,
        toolchain: Toolchain,
        max_size: u64,
    ) -> Result<Self> {
        use nix::fcntl::{OFlag, OpenHow, ResolveFlag, openat2};
        use std::os::fd::AsRawFd;

        if !source_root.is_absolute() {
            return Err(anyhow!("local toolchain source must be an absolute path"));
        }
        // Reject symlinks in all components, including user-owned source
        // directories. NONBLOCK avoids waiting on a malicious FIFO.
        let root = std::fs::File::open("/")?;
        let path = source_root.join(make_lru_key_path(&toolchain.archive_id));
        let how = OpenHow::new()
            .flags(OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .resolve(ResolveFlag::RESOLVE_IN_ROOT | ResolveFlag::RESOLVE_NO_SYMLINKS);
        let source = std::fs::File::from(openat2(&root, &path, how)?);
        let meta = source.metadata()?;
        if !meta.is_file() || meta.len() > max_size {
            return Err(anyhow!(
                "local archive is not a regular file within cache capacity"
            ));
        }
        let file = tempfile::Builder::new()
            .prefix(".sccachetmp")
            .tempfile_in(directory)?;
        // SAFETY: FICLONE takes a valid writable destination file descriptor
        // and the live readable source file descriptor by value. It snapshots
        // the file's data into independent copy-on-write extents.
        if unsafe {
            libc::ioctl(
                file.as_file().as_raw_fd(),
                libc::FICLONE,
                source.as_raw_fd(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if file.as_file().metadata()?.len() > max_size {
            return Err(anyhow!("cloned archive exceeds cache capacity"));
        }
        if file_key(file.reopen()?)? != toolchain.archive_id.as_str() {
            return Err(anyhow!("local cloned archive digest mismatch"));
        }
        Ok(Self { toolchain, file })
    }

    /// Receive and validate an archive in the cache filesystem.
    ///
    /// The temporary file is removed on any failure, and remains invisible
    /// to the LRU index until installation.
    ///
    /// # Errors
    ///
    /// Returns an error for failed, oversized, or corrupted transfers.
    pub fn receive<R: Read>(
        directory: &Path,
        toolchain: Toolchain,
        reader: R,
        max_size: u64,
    ) -> Result<Self> {
        let mut file = tempfile::Builder::new()
            .prefix(".sccachetmp")
            .tempfile_in(directory)?;
        let written = io::copy(
            &mut reader.take(max_size.saturating_add(1)),
            file.as_file_mut(),
        )?;
        if written > max_size {
            return Err(anyhow!("toolchain archive exceeds cache capacity"));
        }
        if file_key(file.reopen()?)? != toolchain.archive_id.as_str() {
            return Err(anyhow!("toolchain archive digest mismatch"));
        }
        Ok(Self { toolchain, file })
    }
}

impl TcCache {
    /// Create a toolchain cache rooted at `cache_dir`.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying disk cache cannot be initialized.
    pub fn new(cache_dir: &Path, cache_size: u64) -> Result<Self> {
        trace!("Using TcCache({}, {cache_size})", cache_dir.display());
        Ok(Self {
            inner: LruDiskCache::new(cache_dir, cache_size)?,
        })
    }

    #[must_use = "the result determines whether a toolchain upload or reuse is needed"]
    pub fn contains_toolchain(&self, tc: &Toolchain) -> bool {
        self.inner.contains_key(make_lru_key_path(&tc.archive_id))
    }

    /// Commit a verified archive, or discard it if another concurrent upload
    /// installed the same toolchain first.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache cannot install the archive.
    pub fn insert_staged(&mut self, staged: StagedToolchainArchive) -> Result<()> {
        let StagedToolchainArchive { toolchain, file } = staged;
        match self.get_file(&toolchain) {
            Ok(_) => {}
            Err(crate::lru_disk_cache::Error::FileNotInCache) => {
                self.inner
                    .insert_file(make_lru_key_path(&toolchain.archive_id), file.path())?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    /// Open a cached toolchain archive as a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive is missing or cannot be opened.
    pub fn get_file(&mut self, tc: &Toolchain) -> LruResult<fs::File> {
        self.inner.get_file(make_lru_key_path(&tc.archive_id))
    }

    /// Open a cached toolchain archive as a readable, seekable stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive is missing or cannot be opened.
    pub fn get(&mut self, tc: &Toolchain) -> LruResult<Box<dyn ReadSeek>> {
        self.inner.get(make_lru_key_path(&tc.archive_id))
    }

    #[must_use = "the entry count is returned without modifying the cache"]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use = "the result describes whether the cache contains any entries"]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove a toolchain archive from the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache entry cannot be removed.
    pub fn remove(&mut self, tc: &Toolchain) -> LruResult<()> {
        self.inner.remove(make_lru_key_path(&tc.archive_id))
    }

    #[cfg(feature = "dist-client")]
    fn insert_file(&mut self, path: &Path) -> Result<Toolchain> {
        let archive_id = path_key(path)?;
        self.inner
            .insert_file(make_lru_key_path(&archive_id), path)?;
        Ok(Toolchain { archive_id })
    }
}

#[cfg(feature = "dist-client")]
fn path_key(path: &Path) -> Result<ArchiveId> {
    Ok(ArchiveId::try_from(file_key(fs::File::open(path)?)?)?)
}

fn file_key<R: Read>(rdr: R) -> Result<String> {
    Digest::reader_sync(rdr)
}
/// Make a path to the cache entry with key `key`.
fn make_lru_key_path(key: &ArchiveId) -> PathBuf {
    Path::new(&key[0..1]).join(&key[1..2]).join(key.as_str())
}

#[cfg(test)]
mod cache_validation_tests {
    use super::*;

    #[cfg(all(target_os = "linux", feature = "dist-server"))]
    #[test]
    fn cloned_archive_is_verified_and_independent_of_mutable_source() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let root = tempdir.path().canonicalize()?;
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&destination)?;
        let payload = vec![42_u8; 128 * 1024];
        let tc = Toolchain {
            archive_id: ArchiveId::try_from(Digest::reader_sync(payload.as_slice())?)?,
        };
        let source_file = source.join(make_lru_key_path(&tc.archive_id));
        fs::create_dir_all(source_file.parent().unwrap())?;
        fs::write(&source_file, &payload)?;

        // Oversize and symlink inputs must be rejected before cloning.
        assert!(
            StagedToolchainArchive::clone_verified(&destination, &source, tc.clone(), 1,).is_err()
        );
        let symlink = root.join("symlink-source");
        std::os::unix::fs::symlink(&source, &symlink)?;
        assert!(StagedToolchainArchive::clone_verified(
            &destination, &symlink, tc.clone(), 1024 * 1024,
        ).is_err());
        let staged = match StagedToolchainArchive::clone_verified(
            &destination,
            &source,
            tc.clone(),
            1024 * 1024,
        ) {
            Ok(staged) => staged,
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::raw_os_error)
                    .is_some_and(|code| {
                        matches!(
                            code,
                            libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL | libc::ENOTTY
                        )
                    }) =>
            {
                // Not all CI filesystems support FICLONE. Rejection paths
                // above still execute; the live ZFS validation must clone.
                eprintln!("filesystem does not support reflinks: {error:#}");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        // A writer in the other LRU namespace cannot mutate our cloned bytes.
        fs::write(&source_file, vec![0_u8; payload.len()])?;
        assert!(
            StagedToolchainArchive::clone_verified(&destination, &source, tc.clone(), 1024 * 1024,)
                .is_err()
        );
        let mut cache = TcCache::new(&root.join("cache"), 1024 * 1024)?;
        cache.insert_staged(staged)?;
        let mut actual = Vec::new();
        cache.get(&tc)?.read_to_end(&mut actual)?;
        assert_eq!(actual, payload);
        fs::remove_file(&source_file)?;
        assert!(cache.contains_toolchain(&tc));
        Ok(())
    }

    #[test]
    fn staged_archive_replaces_missing_cached_file_without_trusting_stale_index() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let bytes = b"toolchain from verified upload";
        let toolchain = Toolchain {
            archive_id: ArchiveId::try_from(Digest::reader_sync(bytes.as_slice())?)?,
        };
        let mut cache = TcCache::new(temp.path(), 1024)?;
        let staged = StagedToolchainArchive::receive(
            temp.path(),
            toolchain.clone(),
            bytes.as_slice(),
            1024,
        )?;
        cache.insert_staged(staged)?;
        let key = make_lru_key_path(&toolchain.archive_id);
        fs::remove_file(temp.path().join(&key))?;
        assert!(cache.contains_toolchain(&toolchain));

        let retry = StagedToolchainArchive::receive(
            temp.path(),
            toolchain.clone(),
            bytes.as_slice(),
            1024,
        )?;
        cache.insert_staged(retry)?;
        let mut actual = Vec::new();
        cache.get(&toolchain)?.read_to_end(&mut actual)?;
        assert_eq!(actual, bytes);
        assert_eq!(cache.len(), 1);

        #[cfg(unix)]
        {
            fs::remove_file(temp.path().join(&key))?;
            std::os::unix::fs::symlink(
                key.file_name()
                    .ok_or_else(|| anyhow!("cache path has no filename"))?,
                temp.path().join(&key),
            )?;
            let retry = StagedToolchainArchive::receive(
                temp.path(),
                toolchain.clone(),
                bytes.as_slice(),
                1024,
            )?;
            assert!(cache.insert_staged(retry).is_err());
            assert!(
                fs::symlink_metadata(temp.path().join(&key))?
                    .file_type()
                    .is_symlink()
            );
            // The cache index is retained for an actionable filesystem error.
            assert!(cache.contains_toolchain(&toolchain));
        }
        Ok(())
    }

    #[test]
    fn rejected_digest_does_not_leave_a_cached_archive() -> Result<()> {
        let tempdir = tempfile::tempdir()?;
        let expected = b"expected";
        let tc = Toolchain {
            archive_id: ArchiveId::try_from(Digest::reader_sync(expected.as_slice())?)?,
        };
        let mut cache = TcCache::new(tempdir.path(), 1024 * 1024)?;
        assert!(
            StagedToolchainArchive::receive(
                tempdir.path(),
                tc.clone(),
                b"not the expected archive".as_slice(),
                1024 * 1024,
            )
            .is_err()
        );
        assert!(!cache.contains_toolchain(&tc));
        assert!(matches!(
            cache.get(&tc),
            Err(crate::lru_disk_cache::Error::FileNotInCache)
        ));

        let staged = StagedToolchainArchive::receive(
            tempdir.path(),
            tc.clone(),
            expected.as_slice(),
            1024 * 1024,
        )?;
        cache.insert_staged(staged)?;
        assert!(
            StagedToolchainArchive::receive(
                tempdir.path(),
                tc.clone(),
                b"invalid replacement".as_slice(),
                1024 * 1024,
            )
            .is_err()
        );
        let mut persisted = Vec::new();
        cache.get(&tc)?.read_to_end(&mut persisted)?;
        assert_eq!(persisted, expected);
        Ok(())
    }
}
