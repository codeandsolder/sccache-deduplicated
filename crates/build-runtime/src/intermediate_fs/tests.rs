use super::*;
use std::{
    io::Write,
    os::fd::AsRawFd,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Content {
    session: Ticket,
    fetches: AtomicUsize,
    unavailable: AtomicBool,
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
        if self.unavailable.load(Ordering::SeqCst) || reference.blob == blob(BAD) {
            destination.write_all(b"partial")?;
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

fn read_mapping(file: &File, len: usize) -> Result<Vec<u8>> {
    // SAFETY: the file is opened for reading, len is its verified size,
    // and the mapping is only read before being unmapped.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    if address == libc::MAP_FAILED {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: mmap succeeded for this entire readable range.
    let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>(), len) }.to_vec();
    // SAFETY: this is the exact live mapping returned above.
    if unsafe { libc::munmap(address, len) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(bytes)
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
        unavailable: AtomicBool::new(false),
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
    let dangling = mount.join("dangling");
    let dangling_alias = mount.join("dangling-alias");
    std::os::unix::fs::symlink("absent-target", &dangling)?;
    fs::hard_link(&dangling, &dangling_alias)?;
    assert_eq!(fs::read_link(&dangling_alias)?, Path::new("absent-target"));
    assert_eq!(
        fs::symlink_metadata(&dangling)?.ino(),
        fs::symlink_metadata(&dangling_alias)?.ino()
    );
    assert_eq!(fs::symlink_metadata(&dangling_alias)?.nlink(), 2);

    fs::set_permissions(&moved, fs::Permissions::from_mode(0o640))?;
    let stamp = SystemTime::UNIX_EPOCH + Duration::from_secs(1_234_567);
    assert_eq!(fs::metadata(&alias)?.mode() & 0o777, 0o640);
    assert_eq!(fs::metadata(&alias)?.ino(), fs::metadata(&moved)?.ino());
    assert_eq!(fs::metadata(&moved)?.nlink(), 2);
    assert_eq!(fs::metadata(&b)?.len(), GOOD.len() as u64);
    assert_eq!(
        intermediate_reference(&crate::open_input_descriptor(&alias, false)?)?
            .context("missing reference")?
            .blob,
        blob(GOOD)
    );
    let mut mapped = crate::MappedTree::new(crate::TreeMetadata {
        mode: 0o755,
        modified: crate::TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        },
    });
    mapped.add_file(
        crate::TreePath::new(b"artifact".to_vec())?,
        moved.clone(),
        crate::MappedMetadata::Preserve,
    )?;
    let prepared = mapped.prepare_with_references(&|file, _| {
        let reference = intermediate_reference(file)?.context("missing mapped reference")?;
        Ok(Some((
            reference.blob,
            crate::ReferenceBlobProvider::new(|_| anyhow::bail!("unexpected content read")),
        )))
    })?;
    assert_eq!(
        prepared.manifest().blobs()?.get(&blob(GOOD).id),
        Some(&blob(GOOD).size)
    );
    assert_eq!(content.fetches.load(Ordering::SeqCst), 0);

    let data = File::open(&moved)?;
    assert_eq!(content.fetches.load(Ordering::SeqCst), 1);
    data.set_times(fs::FileTimes::new().set_modified(stamp))?;
    assert_eq!(fs::metadata(&alias)?.modified()?, stamp);
    // Loss of the remote lease after open must not turn a later page fault
    // into SIGBUS. Other aliases of the same content share the local spool.
    content.unavailable.store(true, Ordering::SeqCst);
    assert_eq!(read_mapping(&data, GOOD.len())?, GOOD);
    drop(data);
    assert!(File::open(&c).is_err());
    assert_eq!(content.fetches.load(Ordering::SeqCst), 2);
    assert!(intermediate_reference(&crate::open_input_descriptor(&c, false)?)?.is_some());
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
    assert_eq!(content.fetches.load(Ordering::SeqCst), 2);
    content.unavailable.store(false, Ordering::SeqCst);
    // A partial failed fetch is not reusable. A later successful open
    // verifies and supplies the entire artifact.
    assert_eq!(fs::read(&c)?, OTHER);
    assert_eq!(content.fetches.load(Ordering::SeqCst), 3);
    let mut writable = fs::OpenOptions::new().append(true).open(&alias)?;
    writable.write_all(b"!")?;
    drop(writable);
    assert_eq!(intermediate_reference(&File::open(&moved)?)?, None);
    assert_eq!(fs::read(&moved)?, [GOOD, b"!"].concat());
    assert_eq!(fs::read(&b)?, GOOD);
    File::create(&c)?.write_all(b"replacement")?;
    assert_eq!(fs::read(&c)?, b"replacement");
    assert_eq!(content.fetches.load(Ordering::SeqCst), 3);
    let bad = mount.join("bad");
    publish(&bad, session, BAD)?;
    assert!(File::open(&bad).is_err());
    assert!(intermediate_reference(&crate::open_input_descriptor(&bad, false)?)?.is_some());
    // Truncating a leased artifact does not read unavailable old content.
    File::create(&bad)?.write_all(b"replacement")?;
    assert_eq!(fs::read(&bad)?, b"replacement");
    assert_eq!(content.fetches.load(Ordering::SeqCst), 4);
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
