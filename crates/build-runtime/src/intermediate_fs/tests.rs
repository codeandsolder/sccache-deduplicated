use super::*;
use std::{
    io::Write,
    sync::atomic::{AtomicUsize, Ordering},
};

struct Content {
    session: Ticket,
    fetches: AtomicUsize,
}
const GOOD: &[u8] = b"compiled artifact";
const OTHER: &[u8] = b"other artifact";
const BAD: &[u8] = b"unavailable artifact";
impl IntermediateContent for Content {
    fn authorize(&self, reference: IntermediateReference) -> Result<()> {
        ensure!(reference.session == self.session, "wrong test session");
        ensure!(
            [GOOD, OTHER, BAD]
                .iter()
                .any(|bytes| reference.blob == blob(bytes)),
            "unknown test content"
        );
        Ok(())
    }
    fn fetch(&self, reference: IntermediateReference, destination: &mut File) -> Result<()> {
        self.authorize(reference)?;
        self.fetches.fetch_add(1, Ordering::SeqCst);
        if reference.blob == blob(BAD) {
            anyhow::bail!("lost test lease");
        }
        let bytes = if reference.blob == blob(GOOD) {
            GOOD
        } else {
            OTHER
        };
        destination.write_all(bytes)?;
        Ok(())
    }
}
fn blob(bytes: &[u8]) -> BlobRef {
    BlobRef {
        id: ContentId::of(bytes),
        size: bytes.len() as u64,
    }
}
fn publish(path: &Path, session: Ticket, bytes: &[u8]) -> Result<()> {
    let file = File::create_new(path)?;
    attach_intermediate(
        &file,
        IntermediateReference {
            session,
            blob: blob(bytes),
        },
    )
}

#[test]
#[ignore = "requires a real /dev/fuse mount and fusermount3"]
fn mounted_intermediates_preserve_inode_semantics_and_fetch_only_on_demand() -> Result<()> {
    let scratch = tempfile::tempdir()?;
    let mount = scratch.path().join("mount");
    let backing = scratch.path().join("backing");
    let spool = scratch.path().join("spool");
    for path in [&mount, &backing, &spool] {
        fs::create_dir(path)?;
    }
    let session = Ticket([7; 32]);
    let content = Arc::new(Content {
        session,
        fetches: AtomicUsize::new(0),
    });
    let filesystem = mount_intermediates(
        &mount,
        &backing,
        &spool,
        session,
        Arc::clone(&content) as Arc<dyn IntermediateContent>,
    )?;
    assert_eq!(intermediate_session(&mount)?, Some(session));
    let a = mount.join("a");
    let b = mount.join("b");
    let c = mount.join("c");
    publish(&a, session, GOOD)?;
    publish(&b, session, GOOD)?;
    publish(&c, session, OTHER)?;
    let alias = mount.join("alias");
    fs::hard_link(&a, &alias)?;
    let subdir = mount.join("subdir");
    fs::create_dir(&subdir)?;
    let moved = subdir.join("moved");
    fs::rename(&a, &moved)?;
    let symlink = mount.join("symlink");
    std::os::unix::fs::symlink("subdir/moved", &symlink)?;
    fs::set_permissions(&moved, fs::Permissions::from_mode(0o640))?;
    let stamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567);
    File::open(&moved)?.set_times(fs::FileTimes::new().set_modified(stamp))?;
    assert_eq!(fs::metadata(&alias)?.modified()?, stamp);
    assert_eq!(fs::metadata(&alias)?.mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(&alias)?.ino(), fs::metadata(&moved)?.ino());
    assert_eq!(fs::metadata(&moved)?.nlink(), 2);
    assert_eq!(fs::metadata(&b)?.len(), GOOD.len() as u64);
    assert_eq!(
        intermediate_reference(&File::open(&alias)?)?
            .context("missing reference")?
            .blob,
        blob(GOOD)
    );
    assert_eq!(content.fetches.load(Ordering::SeqCst), 0);
    std::thread::scope(|scope| -> Result<()> {
        let left = scope.spawn(|| fs::read(&symlink));
        let right = scope.spawn(|| fs::read(&b));
        assert_eq!(
            left.join()
                .map_err(|_| anyhow::anyhow!("reader panicked"))??,
            GOOD
        );
        assert_eq!(
            right
                .join()
                .map_err(|_| anyhow::anyhow!("reader panicked"))??,
            GOOD
        );
        Ok(())
    })?;
    assert_eq!(content.fetches.load(Ordering::SeqCst), 1);
    let mut writable = fs::OpenOptions::new().append(true).open(&alias)?;
    writable.write_all(b"!")?;
    drop(writable);
    assert_eq!(intermediate_reference(&File::open(&moved)?)?, None);
    assert_eq!(fs::read(&moved)?, [GOOD, b"!"].concat());
    assert_eq!(fs::read(&b)?, GOOD);
    File::create(&c)?.write_all(b"replacement")?;
    assert_eq!(fs::read(&c)?, b"replacement");
    assert_eq!(content.fetches.load(Ordering::SeqCst), 1);
    let bad = mount.join("bad");
    publish(&bad, session, BAD)?;
    assert!(fs::read(&bad).is_err());
    assert!(intermediate_reference(&File::open(&bad)?)?.is_some());
    let open = File::open(&b)?;
    fs::remove_file(&b)?;
    let mut contents = Vec::new();
    (&open).read_to_end(&mut contents)?;
    assert_eq!(contents, GOOD);
    drop(open);
    drop(filesystem);
    assert_eq!(fs::read_dir(&mount)?.count(), 0);
    Ok(())
}
