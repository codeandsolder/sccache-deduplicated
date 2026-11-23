//! Plan compressed transfers from the existing reverse content index.
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use bincode::Options;
use redb::ReadableDatabase;

use super::{PackageArchiveLease, PackageRecord};
use crate::store::{BLOB_PACKAGES, PACKAGES, encoding};
use crate::{BlobRef, ContentId, NativeStore, PackageArchive, PackageTransferCost};

struct Candidate {
    archive: PackageArchive,
    covers: BTreeSet<ContentId>,
}

impl NativeStore {
    /// Select retained original archives that reduce the remaining raw
    /// transfer. Coverage is counted only once, even across overlapping
    /// packages; each selected original remains pinned until delivery ends.
    ///
    /// # Errors
    /// Returns an error for inconsistent index metadata or unavailable content.
    pub fn plan_package_downloads(
        &self,
        missing: &[BlobRef],
        maximum: usize,
        max_archive_bytes: u64,
        cost: PackageTransferCost,
    ) -> Result<Vec<PackageArchiveLease>> {
        cost.validate()?;
        let mut remaining: BTreeMap<_, _> =
            missing.iter().map(|blob| (blob.id, blob.size)).collect();
        ensure!(
            remaining.len() == missing.len(),
            "duplicate requested package content"
        );
        let mut candidates = BTreeMap::<ContentId, Candidate>::new();
        {
            let read = self.inner.db.begin_read()?;
            let reverse = read.open_multimap_table(BLOB_PACKAGES)?;
            let packages = read.open_table(PACKAGES)?;
            let mut oversized = BTreeSet::new();
            for blob in missing {
                for key in reverse.get(&blob.id.0)? {
                    let key = ContentId(*key?.value());
                    if let Some(candidate) = candidates.get_mut(&key) {
                        candidate.covers.insert(blob.id);
                        continue;
                    }
                    if oversized.contains(&key) {
                        continue;
                    }
                    let record = packages.get(&key.0)?.context("missing indexed package")?;
                    let record: PackageRecord = encoding().deserialize(record.value())?;
                    let archive = record
                        .archive()
                        .context("missing indexed original archive")?;
                    if archive.blob.size <= max_archive_bytes {
                        candidates.insert(
                            key,
                            Candidate {
                                archive,
                                covers: BTreeSet::from([blob.id]),
                            },
                        );
                    } else {
                        oversized.insert(key);
                    }
                }
            }
        }
        let mut selected = Vec::new();
        while selected.len() < maximum {
            let best = candidates
                .iter()
                .filter_map(|(key, candidate)| {
                    let (raw, files) = candidate
                        .covers
                        .iter()
                        .filter_map(|id| remaining.get(id))
                        .fold((0_u128, 0_usize), |(bytes, count), size| {
                            (bytes + u128::from(*size), count + 1)
                        });
                    cost.predicted_savings_nanoseconds(raw, files, candidate.archive)
                        .map(|saving| (saving, *key))
                })
                .max();
            let Some((_, key)) = best else { break };
            let candidate = candidates
                .remove(&key)
                .context("selected package disappeared")?;
            // Candidate enumeration uses a read snapshot, not the store's
            // global mutation lock. Revalidate and pin each chosen package
            // atomically with eviction before exposing its archive.
            let mutation = self.inner.lock_mutations()?;
            let current = {
                let read = self.inner.db.begin_read()?;
                let packages = read.open_table(PACKAGES)?;
                packages
                    .get(&key.0)?
                    .map(|entry| encoding().deserialize::<PackageRecord>(entry.value()))
                    .transpose()?
            };
            if current.and_then(|record| record.archive()) != Some(candidate.archive) {
                continue;
            }
            let tree = self
                .lookup_tree(candidate.archive.tree)?
                .context("indexed package tree missing")?;
            self.inner
                .check_blob(candidate.archive.blob.id, candidate.archive.blob.size)?;
            drop(mutation);
            for id in candidate.covers {
                remaining.remove(&id);
            }
            selected.push(PackageArchiveLease {
                archive: candidate.archive,
                tree,
            });
        }
        Ok(selected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ArchiveLength, PackageCompression, PackageDecoder, PackageIdentity, PackagePolicy,
    };
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};

    fn slow_link() -> PackageTransferCost {
        PackageTransferCost {
            download_bytes_per_second: 1 << 20,
            startup_nanoseconds: 0,
            ..PackageTransferCost::default()
        }
    }

    fn fixture() -> Result<(Vec<u8>, BlobRef)> {
        let contents = b"original payload".repeat(8192);
        let blob = BlobRef {
            id: ContentId::of(&contents),
            size: u64::try_from(contents.len())?,
        };
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(blob.size);
        header.set_cksum();
        tar.append_data(&mut header, "release/payload", &contents[..])?;
        Ok((tar.into_inner()?, blob))
    }

    fn gzip(bytes: &[u8], compression: flate2::Compression) -> Result<Vec<u8>> {
        let mut writer = flate2::write::GzEncoder::new(Vec::new(), compression);
        writer.write_all(bytes)?;
        Ok(writer.finish()?)
    }

    fn source(bytes: &[u8], compression: PackageCompression) -> Result<crate::PackageSource> {
        Ok(crate::PackageSource {
            identity: PackageIdentity {
                sha256: Sha256::digest(bytes).into(),
                compression,
            },
            size: u64::try_from(bytes.len())?,
        })
    }

    #[test]
    fn original_archive_digest_reused_from_encoded_output_keeps_source_bytes() -> Result<()> {
        use crate::{TreeEntry, TreeManifest, TreeMetadata, TreePath};
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let (tar, expanded) = fixture()?;
        let original = gzip(&tar, flate2::Compression::fast())?;
        let policy = PackagePolicy {
            retain_original: true,
            ..PackagePolicy::normalized_archive(100, 1 << 20, 1 << 20, 1 << 20)?
        };
        let staged = store.stage(original.as_slice())?;
        let reference = staged.reference();
        let tree = TreeManifest {
            root: policy.directory,
            entries: std::collections::BTreeMap::from([
                (
                    TreePath::new(b"generated".to_vec())?,
                    TreeEntry::Directory(policy.directory),
                ),
                (
                    TreePath::new(b"generated/input.crate".to_vec())?,
                    TreeEntry::File {
                        blob: reference,
                        metadata: TreeMetadata {
                            mode: 0o644,
                            modified: policy.modified,
                        },
                    },
                ),
            ]),
        };
        let id = store.publish_tree(&tree, vec![staged])?;
        let lease = store.lookup_tree(id)?.context("missing staged tree")?;
        assert!(
            crate::BlobReader::open(
                lease.open_file(reference.id)?,
                crate::BlobEncoding::ZstdChunks
            )?
            .is_encoded()
        );
        let source = source(&original, PackageCompression::Gzip)?;
        let package = store.import_package(
            source.identity,
            ArchiveLength::Exact(source.size),
            policy,
            original.as_slice(),
            PackageDecoder::InProcess,
        )?;
        assert_eq!(package.source(), source);
        let offers = store.plan_package_downloads(&[expanded], 8, u64::MAX, slow_link())?;
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].archive().blob, reference);
        let mut restored = Vec::new();
        offers[0].open_file()?.read_to_end(&mut restored)?;
        assert_eq!(restored, original);
        Ok(())
    }

    #[test]
    fn original_transport_prefers_smallest_cover_and_is_reference_accounted() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let (tar, blob) = fixture()?;
        let fast = gzip(&tar, flate2::Compression::fast())?;
        let small = gzip(&tar, flate2::Compression::best())?;
        assert!(small.len() < fast.len());
        let mut policy = PackagePolicy::normalized_archive(100, 1 << 20, 1 << 20, 1 << 20)?;
        policy.retain_original = true;
        let mut tree = None;
        for (bytes, codec) in [
            (&fast, PackageCompression::Gzip),
            (&small, PackageCompression::Gzip),
            (&tar, PackageCompression::Tar),
        ] {
            let source = source(bytes, codec)?;
            let package = store.import_package(
                source.identity,
                ArchiveLength::Exact(source.size),
                policy,
                &bytes[..],
                PackageDecoder::InProcess,
            )?;
            let id = package.tree().id();
            if let Some(previous) = tree {
                assert_eq!(previous, id);
            }
            tree = Some(id);
        }
        let id = tree.context("missing package")?;
        assert_eq!(store.stats()?.trees, 1);
        assert_eq!(store.stats()?.blobs, 4);
        let logical = blob.size + u64::try_from(fast.len() + small.len() + tar.len())?;
        assert_eq!(store.stats()?.logical_bytes, logical);
        assert!(
            store
                .plan_package_downloads(&[blob], 8, 1, slow_link())?
                .is_empty()
        );
        assert!(
            store
                .plan_package_downloads(&[blob, blob], 8, u64::MAX, slow_link())
                .is_err()
        );

        let selected = store.plan_package_downloads(&[blob], 8, u64::MAX, slow_link())?;
        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0].archive().source,
            source(&small, PackageCompression::Gzip)?
        );
        let mut original = Vec::new();
        selected[0].open_file()?.read_to_end(&mut original)?;
        assert_eq!(original, small);
        assert_eq!(store.evict_tree(id)?, crate::Eviction::Pinned);

        drop(store);
        // The archive delivery pin also holds the store owner alive.
        drop(selected);
        let store = NativeStore::open(directory.path())?;
        let selected = store.plan_package_downloads(&[blob], 8, u64::MAX, slow_link())?;
        assert_eq!(selected.len(), 1);
        drop(selected);
        assert_eq!(
            store.evict_tree(id)?,
            crate::Eviction::Removed {
                unreferenced_logical_bytes: logical
            }
        );
        assert!(
            store
                .plan_package_downloads(&[blob], 8, u64::MAX, slow_link())?
                .is_empty()
        );
        assert_eq!(store.stats()?.pending_gc_blobs, 4);
        store.collect_garbage(8)?;
        assert_eq!(store.stats()?.pending_gc_blobs, 0);
        Ok(())
    }

    #[test]
    fn retained_archive_can_be_added_without_changing_package_tree() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(directory.path())?;
        let (tar, blob) = fixture()?;
        let bytes = gzip(&tar, flate2::Compression::best())?;
        let source = source(&bytes, PackageCompression::Gzip)?;
        let mut policy = PackagePolicy::normalized_archive(100, 1 << 20, 1 << 20, 1 << 20)?;
        let first = store.import_package(
            source.identity,
            ArchiveLength::Exact(source.size),
            policy,
            &bytes[..],
            PackageDecoder::InProcess,
        )?;
        assert!(
            store
                .plan_package_downloads(&[blob], 8, u64::MAX, slow_link())?
                .is_empty()
        );
        policy.retain_original = true;
        let second = store.import_package(
            source.identity,
            ArchiveLength::Exact(source.size),
            policy,
            &bytes[..],
            PackageDecoder::InProcess,
        )?;
        assert_eq!(first.tree().id(), second.tree().id());
        assert_eq!(store.stats()?.blobs, 2);
        let offer = store.plan_package_downloads(&[blob], 8, u64::MAX, slow_link())?;
        assert_eq!(offer.len(), 1);
        policy.retain_original = false;
        let third = store.import_package(
            source.identity,
            ArchiveLength::Exact(source.size),
            policy,
            &bytes[..],
            PackageDecoder::InProcess,
        )?;
        assert_eq!(second.tree().id(), third.tree().id());
        assert_eq!(store.stats()?.blobs, 2);
        assert_eq!(
            store
                .plan_package_downloads(&[blob], 8, u64::MAX, slow_link())?
                .len(),
            1
        );
        Ok(())
    }
}
