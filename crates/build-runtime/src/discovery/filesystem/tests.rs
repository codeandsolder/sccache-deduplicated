use super::*;
use crate::discovery::DiscoveryLimits;
use std::os::unix::fs::{MetadataExt, symlink};

fn path(bytes: &[u8]) -> Result<BuildPath> {
    BuildPath::new(bytes.to_vec())
}

fn origin(root: &Path) -> Result<DiscoveryOrigin> {
    let mut origin = DiscoveryOrigin::new(DiscoveryLimits {
        max_queries: 128,
        max_dirents: 128,
        max_content_bytes: 4096,
    })?;
    origin.add_root(path(b"/inputs")?, root)?;
    Ok(origin)
}

struct NoOrigin;

impl DiscoveryTransport for NoOrigin {
    fn query(&mut self, _: &DiscoveryQuery) -> Result<DiscoveryReply> {
        anyhow::bail!("replay attempted an origin query")
    }

    fn seal(&mut self, _: &DiscoveryTranscript) -> Result<()> {
        anyhow::bail!("replay attempted to seal a live origin")
    }

    fn open_blob(&mut self, _: BlobRef) -> Result<Box<dyn Read + Send>> {
        anyhow::bail!("resident CAS content was fetched again")
    }
}

#[test]
#[ignore = "requires host FUSE mount support"]
fn live_and_replay_mounts_preserve_aliases_and_hash_only_read_files() -> Result<()> {
    let input = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let store = NativeStore::open(&scratch.path().join("store"))?;
    fs::write(input.path().join("selected"), b"chosen bytes")?;
    fs::hard_link(input.path().join("selected"), input.path().join("alias"))?;
    symlink("selected", input.path().join("link"))?;
    fs::write(input.path().join("metadata-only"), b"never read")?;
    fs::write(input.path().join("unrelated"), b"unrelated bytes")?;

    let live = DiscoverySession::new(store.clone(), origin(input.path())?, None)?;
    let mounted = live.mount(path(b"/inputs")?, scratch.path())?;
    let root = mounted.root();
    let names = fs::read_dir(root)?
        .map(|e| Ok(e?.file_name()))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(names.len(), 5);
    assert_eq!(
        fs::metadata(root.join("alias"))?.ino(),
        fs::metadata(root.join("selected"))?.ino()
    );
    assert_eq!(fs::metadata(root.join("alias"))?.nlink(), 2);
    assert_eq!(fs::read(root.join("alias"))?, b"chosen bytes");
    assert_eq!(fs::read_link(root.join("link"))?, Path::new("selected"));
    assert_eq!(fs::metadata(root.join("metadata-only"))?.len(), 10);
    drop(fs::File::open(root.join("metadata-only"))?);
    assert_eq!(
        fs::metadata(root.join("missing")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    mounted.unmount()?;
    let discovered = live.finish()?;
    let bundle = discovered.publish(&store)?;
    assert_eq!(
        DiscoveryBundle::load(&bundle, 1024 * 1024)?,
        *discovered.bundle()
    );
    assert!(DiscoveryBundle::load(&bundle, 1).is_err());
    let transcript = discovered.transcript();
    let content = transcript
        .observations()
        .iter()
        .filter_map(|(query, reply)| {
            if let DiscoveryReply::File { blob, .. } = reply {
                Some((query, blob))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(content.len(), 1);
    let mut bytes = Vec::new();
    discovered
        .open_blob(*content[0].1)?
        .read_to_end(&mut bytes)?;
    assert_eq!(bytes, b"chosen bytes");

    fs::write(input.path().join("unrelated"), b"new unrelated contents")?;
    let refreshed = origin(input.path())?
        .refresh(transcript)?
        .context("unrelated content invalidated transcript")?;
    assert_eq!(refreshed.seal()?.fingerprint()?, transcript.fingerprint()?);

    let replay = DiscoverySession::new(store.clone(), NoOrigin, Some(discovered.bundle().clone()))?;
    let mounted = replay.mount(path(b"/inputs")?, scratch.path())?;
    let root = mounted.root();
    assert_eq!(fs::read_dir(root)?.count(), 5);
    assert_eq!(
        fs::metadata(root.join("selected"))?.ino(),
        fs::metadata(root.join("alias"))?.ino()
    );
    assert_eq!(fs::read(root.join("selected"))?, b"chosen bytes");
    assert_eq!(fs::read_link(root.join("link"))?, Path::new("selected"));
    assert_eq!(fs::metadata(root.join("metadata-only"))?.len(), 10);
    drop(fs::File::open(root.join("metadata-only"))?);
    assert_eq!(
        fs::metadata(root.join("missing")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    mounted.unmount()?;
    assert_eq!(
        replay.finish()?.transcript().fingerprint()?,
        transcript.fingerprint()?
    );

    let invalid = DiscoverySession::new(store, NoOrigin, Some(discovered.bundle().clone()))?;
    let mounted = invalid.mount(path(b"/inputs")?, scratch.path())?;
    assert_eq!(
        fs::metadata(mounted.root().join("unobserved"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EIO)
    );
    mounted.unmount()?;
    assert!(invalid.finish().is_err());
    Ok(())
}

#[test]
fn worker_namespace_defers_content_until_first_read_and_verifies_bytes() -> Result<()> {
    let input = tempfile::tempdir()?;
    let scratch = tempfile::tempdir()?;
    let store = NativeStore::open(&scratch.path().join("store"))?;
    fs::write(input.path().join("file"), b"contents")?;
    let session = DiscoverySession::new(store, origin(input.path())?, None)?;
    let filesystem = DiscoveryFs::new(Arc::clone(&session.0), path(b"/inputs")?)?;
    let inode = filesystem
        .call(|ns, state| Ok(ns.lookup(state, INodeNo::ROOT, OsStr::new("file"))?.ino))
        .map_err(|e| anyhow::anyhow!("lookup: {e:?}"))?;
    let handle = filesystem
        .call(|ns, _| ns.open(inode, OpenFlags(libc::O_RDONLY), false))
        .map_err(|e| anyhow::anyhow!("open: {e:?}"))?;
    {
        let state = session.0.lock().unwrap();
        assert!(state.content.is_empty());
    }
    let bytes = filesystem
        .call(|ns, state| ns.read(state, &filesystem.scope, inode, handle, 2, 4))
        .map_err(|e| anyhow::anyhow!("read: {e:?}"))?;
    assert_eq!(bytes, b"nten");
    drop(filesystem);
    let inputs = session.finish()?;
    assert_eq!(inputs.content.len(), 1);
    assert_eq!(inputs.transcript().observations().len(), 3);
    Ok(())
}
