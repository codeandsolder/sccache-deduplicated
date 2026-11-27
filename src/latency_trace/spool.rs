//! Single-owner persistent FIFO. Only the exporter threads touch disk.
//! A record is immutable after publication and survives daemon restarts.
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const HEADER: usize = 40;
pub(super) const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const TEMP_PREFIX: &str = ".trace-pending-";

pub(super) struct Record {
    pub sequence: u64,
    pub count: u64,
    pub body: Vec<u8>,
}

pub(super) struct Spool {
    directory: PathBuf,
    _owner: File,
    records: BTreeMap<u64, u64>,
    bytes: u64,
    capacity: u64,
    next: u64,
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        // Windows does not support opening a directory through File::open.
        // The payload itself is flushed before publication on all platforms.
        let _ = path;
        Ok(())
    }
}

fn sequence(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".otlp")?;
    if stem.len() == 20 && stem.bytes().all(|byte| byte.is_ascii_digit()) {
        stem.parse().ok()
    } else {
        None
    }
}

impl Spool {
    pub(super) fn open(directory: &Path, capacity: u64) -> Result<Self> {
        ensure!(
            directory.is_absolute(),
            "trace spool directory must be absolute"
        );
        ensure!(
            capacity >= 1024 * 1024,
            "trace spool budget must be at least 1 MiB"
        );
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder.recursive(true).create(directory)?;
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "trace spool must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            ensure!(
                fs::metadata(directory)?
                    .permissions()
                    .mode()
                    .trailing_zeros()
                    >= 6,
                "trace spool directory must be private (0700)"
            );
        }
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("spool.lock"))?;
        owner.try_lock().map_err(|error| {
            anyhow::anyhow!("trace spool already owned or cannot be locked: {error}")
        })?;
        let mut records = BTreeMap::new();
        let mut bytes = 0_u64;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("non-UTF8 trace spool entry")?;
            if name == "spool.lock" {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "nonregular trace spool entry: {name}"
            );
            if name.starts_with(TEMP_PREFIX) {
                fs::remove_file(entry.path())?;
                continue;
            }
            let sequence =
                sequence(name).with_context(|| format!("unrecognized trace spool entry {name}"))?;
            let length = entry.metadata()?.len();
            bytes = bytes
                .checked_add(length)
                .context("trace spool size overflow")?;
            records.insert(sequence, length);
        }
        let next = records.last_key_value().map_or(Ok(0), |(&last, _)| {
            last.checked_add(1)
                .context("trace spool sequence exhausted")
        })?;
        Ok(Self {
            directory: directory.to_owned(),
            _owner: owner,
            records,
            bytes,
            capacity,
            next,
        })
    }

    fn path(&self, sequence: u64) -> PathBuf {
        self.directory.join(format!("{sequence:020}.otlp"))
    }

    /// Retain the already-published FIFO when the budget is exhausted.
    /// No pending record is evicted while delivery may be using it.
    pub(super) fn push(&mut self, count: u64, body: &[u8]) -> Result<bool> {
        let length = u64::try_from(body.len().saturating_add(HEADER))?;
        if body.is_empty()
            || body.len() > MAX_BODY
            || count == 0
            || self.records.len() >= MAX_RECORDS
            || self.bytes.saturating_add(length) > self.capacity
        {
            return Ok(false);
        }
        let seq = self.next;
        let next = seq
            .checked_add(1)
            .context("trace spool sequence exhausted")?;
        let mut file = tempfile::Builder::new()
            .prefix(TEMP_PREFIX)
            .tempfile_in(&self.directory)?;
        let count = count.to_le_bytes();
        let mut hash = blake3::Hasher::new();
        hash.update(&count);
        hash.update(body);
        file.write_all(&count)?;
        file.write_all(hash.finalize().as_bytes())?;
        file.write_all(body)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(self.path(seq))?;
        self.records.insert(seq, length);
        self.bytes += length;
        self.next = next;
        // The published record remains in the queue even if the filesystem
        // rejects the directory sync; do not miscount it as discarded.
        if let Err(error) = sync_directory(&self.directory) {
            log::warn!("trace spool directory sync failed; record retained: {error}");
        }
        Ok(true)
    }

    /// Return the oldest record or discard an invalid payload. I/O failures
    /// are retried by the delivery loop rather than mistaken for corruption.
    pub(super) fn front(&mut self) -> Result<Option<Record>> {
        while let Some((&seq, &length)) = self.records.first_key_value() {
            if let Some(record) = self.read(seq, length)? {
                return Ok(Some(record));
            }
            log::error!("discarding corrupt trace spool record {seq}");
            self.ack(seq)?;
        }
        Ok(None)
    }

    fn read(&self, seq: u64, length: u64) -> Result<Option<Record>> {
        if length <= HEADER as u64 || length > (HEADER + MAX_BODY) as u64 {
            return Ok(None);
        }
        let mut bytes = Vec::new();
        File::open(self.path(seq))?
            .take(length + 1)
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len())? != length {
            return Ok(None);
        }
        let count = u64::from_le_bytes(bytes[..8].try_into()?);
        let mut hash = blake3::Hasher::new();
        hash.update(&bytes[..8]);
        hash.update(&bytes[HEADER..]);
        if count == 0 || hash.finalize().as_bytes() != &bytes[8..HEADER] {
            return Ok(None);
        }
        Ok(Some(Record {
            sequence: seq,
            count,
            body: bytes.split_off(HEADER),
        }))
    }

    pub(super) fn ack(&mut self, sequence: u64) -> Result<()> {
        let length = *self
            .records
            .get(&sequence)
            .context("unknown trace spool record")?;
        fs::remove_file(self.path(sequence))?;
        self.records.remove(&sequence);
        self.bytes -= length;
        sync_directory(&self.directory)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_survives_restart_and_rejects_overflow() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("spool");
        let capacity = 1024 * 1024;
        let body = vec![3; 600_000];
        {
            let mut spool = Spool::open(&path, capacity)?;
            assert!(Spool::open(&path, capacity).is_err());
            assert!(spool.push(17, &body)?);
            assert!(!spool.push(18, &body)?);
            assert!(spool.push(19, b"second")?);
        }
        let mut spool = Spool::open(&path, capacity)?;
        let first = spool.front()?.context("missing persisted first record")?;
        assert_eq!(first.count, 17);
        assert_eq!(first.body, body);
        spool.ack(first.sequence)?;
        assert!(spool.push(20, b"third")?);
        for (count, body) in [(19, b"second".as_slice()), (20, b"third".as_slice())] {
            let record = spool.front()?.context("missing persisted record")?;
            assert_eq!(record.count, count);
            assert_eq!(record.body, body);
            spool.ack(record.sequence)?;
        }
        assert!(spool.front()?.is_none());
        assert_eq!(spool.bytes, 0);
        Ok(())
    }

    #[test]
    fn incomplete_publication_and_corruption_do_not_block_later_records() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("spool");
        {
            let mut spool = Spool::open(&path, 1024 * 1024)?;
            assert!(spool.push(1, b"corrupted")?);
            assert!(spool.push(2, b"intact")?);
        }
        fs::write(path.join(".trace-pending-crash"), b"partial")?;
        fs::write(path.join("00000000000000000000.otlp"), [0; 49])?;
        let mut spool = Spool::open(&path, 1024 * 1024)?;
        let record = spool.front()?.context("later valid record lost")?;
        assert_eq!(record.count, 2);
        assert_eq!(record.body, b"intact");
        assert!(!path.join(".trace-pending-crash").exists());
        spool.ack(record.sequence)?;
        assert_eq!(spool.bytes, 0);
        Ok(())
    }
}
