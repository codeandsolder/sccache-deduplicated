//! Smoke probe for the native store on a caller-selected filesystem.
//! Run with a directory for temporary files and a representative input file.

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::BTreeMap,
        fs::{self, File},
        io::{self, Write},
        path::PathBuf,
        time::Instant,
    };

    use anyhow::{Context, Result, ensure};
    use sccache_build::{
        ActionFingerprint, Artifact, ContentId, NativeStore, ResultManifest, TreeEntry,
        TreeManifest, TreeMetadata, TreePath, TreeTimestamp,
    };

    pub fn run() -> Result<()> {
        let mut args = std::env::args_os().skip(1);
        let parent = PathBuf::from(args.next().context("expected temporary directory parent")?);
        let source = PathBuf::from(args.next().context("expected representative file")?);
        ensure!(args.next().is_none(), "unexpected additional arguments");
        let directory = tempfile::Builder::new()
            .prefix("native-store-probe-")
            .tempdir_in(parent)?;
        let start = Instant::now();
        let store = NativeStore::open(&directory.path().join("store"))?;
        let staged = store.stage(File::open(&source)?)?;
        let blob = staged.reference();
        let metadata = TreeMetadata {
            mode: 0o755,
            modified: TreeTimestamp {
                seconds: 1_700_000_000,
                nanoseconds: 1234,
            },
        };
        let manifest = TreeManifest {
            root: metadata,
            entries: BTreeMap::from([
                (
                    TreePath::new(b"first".to_vec())?,
                    TreeEntry::File { blob, metadata },
                ),
                (
                    TreePath::new(b"second".to_vec())?,
                    TreeEntry::File {
                        blob,
                        metadata: TreeMetadata {
                            mode: 0o644,
                            ..metadata
                        },
                    },
                ),
            ]),
        };
        let id = store.publish_tree(&manifest, vec![staged])?;
        let fingerprint = ActionFingerprint {
            schema: "probe".into(),
            components: BTreeMap::from([("input".into(), blob.id)]),
        };
        let output = ResultManifest {
            outputs: BTreeMap::from([(
                "output".into(),
                Artifact::File {
                    blob,
                    mode: Some(0o644),
                },
            )]),
            stdout: None,
            stderr: None,
        };
        store.publish(&fingerprint, &output, vec![])?;
        let indexed = start.elapsed();
        let stats = store.stats()?;
        ensure!(
            stats.blobs == 1 && stats.logical_bytes == blob.size,
            "deduplication failed"
        );
        let lease = store.lookup_tree(id)?.context("published tree missing")?;
        let clone_start = Instant::now();
        let view = lease.materialize(directory.path())?;
        let clone_elapsed = clone_start.elapsed();
        for file in ["first", "second"] {
            let mut input = File::open(view.root().join(file))?;
            let mut hash = blake3::Hasher::new();
            io::copy(&mut input, &mut hash)?;
            ensure!(
                ContentId(*hash.finalize().as_bytes()) == blob.id,
                "incorrect materialization"
            );
        }
        // Modify one clone, proving that its data is independent of the CAS
        // and independently materialized files.
        let mut dest = File::options()
            .write(true)
            .open(view.root().join("first"))?;
        dest.write_all(b"modified")?;
        let mut hash = blake3::Hasher::new();
        io::copy(&mut lease.open_blob(blob.id)?, &mut hash)?;
        ensure!(
            ContentId(*hash.finalize().as_bytes()) == blob.id,
            "materialization mutated CAS"
        );
        ensure!(
            fs::metadata(view.root().join("second"))?.len() == blob.size,
            "incorrect second file"
        );

        println!("unique source bytes: {}", blob.size);
        println!(
            "CAS keys: {} actions, {} trees, {} blobs",
            stats.actions, stats.trees, stats.blobs
        );
        println!("first publication: {indexed:?}");
        println!("materialization: {clone_elapsed:?}, {:?}", view.stats());
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("the block clone probe requires Linux")
}
