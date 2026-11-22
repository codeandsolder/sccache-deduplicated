use super::TreeLease;
use crate::{BlobRef, MaterializationStats, MaterializedTree, materialize_tree};
use anyhow::{Context, Result, ensure};
use rustix::io::Errno;
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

impl TreeLease {
    /// Materialize a validated tree using block clones where available, then
    /// streamed copies. Never share mutable CAS inodes with the consumer.
    /// # Errors
    /// Returns an error for invalid data or failed filesystem operations.
    pub fn materialize(&self, parent: &Path) -> Result<MaterializedTree> {
        let mut stats = MaterializationStats::default();
        let mut tree = materialize_tree(&self.manifest, parent, |blob, path| {
            self.materialize_file(blob, path, &mut stats)
        })?;
        tree.stats = stats;
        Ok(tree)
    }

    fn materialize_file(
        &self,
        blob: BlobRef,
        path: &Path,
        stats: &mut MaterializationStats,
    ) -> Result<()> {
        let mut source = File::open(self.inner.blob_path(blob.id))?;
        let mut destination = OpenOptions::new().write(true).create_new(true).open(path)?;
        match rustix::fs::ioctl_ficlone(&destination, &source) {
            Ok(()) => {
                stats.cloned_files = stats
                    .cloned_files
                    .checked_add(1)
                    .context("clone count overflow")?;
            }
            Err(Errno::OPNOTSUPP | Errno::XDEV | Errno::INVAL | Errno::NOTTY | Errno::NOSYS) => {
                // The destination belongs exclusively to us, including if
                // an unsupported clone attempt modified part of its size.
                destination.set_len(0)?;
                let copied = io::copy(&mut source, &mut destination)?;
                ensure!(copied == blob.size, "incomplete tree file copy");
                stats.copied_files = stats
                    .copied_files
                    .checked_add(1)
                    .context("copy count overflow")?;
                stats.copied_bytes = stats
                    .copied_bytes
                    .checked_add(copied)
                    .context("copied size overflow")?;
            }
            Err(error) => return Err(error).context("clone native content into build tree"),
        }
        ensure!(
            destination.metadata()?.len() == blob.size,
            "tree file length mismatch"
        );
        Ok(())
    }
}
