//! Verify and import a real upstream package on a selected filesystem.

#[cfg(unix)]
mod unix {
    use std::{fs::File, path::PathBuf, time::Instant};

    use anyhow::{Context, Result, bail, ensure};
    use sccache_build::{
        ArchiveLength, NativeStore, PackageCompression, PackageDecoder, PackageIdentity,
        PackagePolicy, PackageSource, TreeLayer, TreeMetadata, TreePath, TreeRecipe, TreeTimestamp,
    };

    pub fn run() -> Result<()> {
        let mut args = std::env::args_os().skip(1);
        let parent = PathBuf::from(args.next().context("expected temporary directory parent")?);
        let package = PathBuf::from(args.next().context("expected package path")?);
        let hash = args.next().context("expected upstream SHA-256")?;
        let hash = hash.to_str().context("non-UTF-8 checksum")?;
        let codec = args.next().context("expected package compression")?;
        let compression = match codec.to_str() {
            Some("gzip") => PackageCompression::Gzip,
            Some("xz") => PackageCompression::Xz,
            Some("tar") => PackageCompression::Tar,
            _ => bail!("unsupported package compression"),
        };
        ensure!(args.next().is_none(), "unexpected argument");
        let input = File::open(&package)?;
        let source = PackageSource {
            identity: PackageIdentity::from_sha256_hex(hash, compression)?,
            size: input.metadata()?.len(),
        };
        let modified = TreeTimestamp {
            seconds: 1_700_000_000,
            nanoseconds: 0,
        };
        let policy = PackagePolicy {
            retain_original: false,
            directory: TreeMetadata {
                mode: 0o755,
                modified,
            },
            modified,
            max_entries: 100_000,
            max_expanded_bytes: 8 * 1024 * 1024 * 1024,
            max_tar_bytes: 9 * 1024 * 1024 * 1024,
            max_metadata_bytes: 64 * 1024 * 1024,
        };
        let scratch = tempfile::Builder::new()
            .prefix("package-probe-")
            .tempdir_in(parent)?;
        let store = NativeStore::open(&scratch.path().join("store"))?;
        let start = Instant::now();
        let imported_package = store.import_package(
            source.identity,
            ArchiveLength::Exact(source.size),
            policy,
            input,
            PackageDecoder::InProcess,
        )?;
        let id = imported_package.tree().id();
        let imported = start.elapsed();
        let stats = store.stats()?;
        let start = Instant::now();
        let lease = store
            .lookup_package(source.identity, policy)?
            .context("package mapping missing")?;
        let looked_up = start.elapsed();
        ensure!(lease.tree().id() == id, "incorrect package lookup");
        let entries = lease.tree().manifest().entries.len();
        let recipe = TreeRecipe {
            directories: policy.directory,
            layers: vec![TreeLayer {
                tree: id,
                source: None,
                destination: Some(TreePath::new(b"toolchain".to_vec())?),
            }],
        };
        let start = Instant::now();
        let composed = store.publish_recipe(&recipe)?;
        ensure!(
            store.stats()?.logical_bytes == stats.logical_bytes,
            "recipe copied file content"
        );
        let composed_time = start.elapsed();
        println!(
            "{}: {entries} entries, {} unique files, {} bytes; original {} bytes",
            package.display(),
            stats.blobs,
            stats.logical_bytes,
            source.size
        );
        println!(
            "verified import {imported:?}; indexed lookup {looked_up:?}; recipe composition {composed_time:?}"
        );
        #[cfg(target_os = "linux")]
        {
            let lease = store
                .lookup_tree(composed)?
                .context("composed tree missing")?;
            let start = Instant::now();
            let materialized = lease.materialize(scratch.path())?;
            println!(
                "materialized in {:?}: {:?}",
                start.elapsed(),
                materialized.stats()
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = composed;
        Ok(())
    }
}

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    unix::run()
}

#[cfg(not(unix))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("package probe requires a Unix native store")
}
