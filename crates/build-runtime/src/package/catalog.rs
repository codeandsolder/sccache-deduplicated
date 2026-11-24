//! Advisory original-package coverage. Catalog entries contain verified
//! metadata, not leases or a promise that an original remains resident.

use super::{PackageArchive, PackageTransferCost};
use crate::ContentId;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub(crate) archive: PackageArchive,
    pub(crate) covers: BTreeSet<ContentId>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageCatalog {
    pub(crate) candidates: BTreeMap<ContentId, Candidate>,
    pub(crate) tree_groups: Vec<Vec<ContentId>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PackageDeliveryLimits {
    pub max_archive_bytes: u64,
    pub max_expanded_bytes: u64,
    pub max_entries: u64,
    pub parallelism: u32,
}

impl PackageDeliveryLimits {
    #[must_use = "invalid reconstruction capabilities must not drive placement"]
    pub const fn valid(self) -> bool {
        self.max_archive_bytes > 0
            && self.max_expanded_bytes > 0
            && self.max_entries > 0
            && self.parallelism > 0
            && self.parallelism <= 32
    }

    const fn accepts(self, archive: PackageArchive) -> bool {
        archive.blob.size <= self.max_archive_bytes
            && archive.expanded_bytes <= self.max_expanded_bytes
            && archive.entry_count <= self.max_entries
    }
}

struct Selection<'a> {
    catalog: &'a PackageCatalog,
    limits: PackageDeliveryLimits,
    cost: PackageTransferCost,
    unseen: BTreeMap<ContentId, u64>,
    excluded: BTreeSet<ContentId>,
    selected: Vec<PackageArchive>,
}

impl Selection<'_> {
    fn tree(&mut self, mut tree: BTreeMap<ContentId, u64>, missing: &mut BTreeMap<ContentId, u64>) {
        for _ in 0..8 {
            let Some(key) = self
                .catalog
                .best(&tree, &self.excluded, self.cost, |archive| {
                    self.limits.accepts(archive)
                })
            else {
                break;
            };
            let Some(candidate) = self.catalog.candidates.get(&key) else {
                break;
            };
            self.excluded.insert(key);
            for id in &candidate.covers {
                tree.remove(id);
                if self.unseen.remove(id).is_some() {
                    missing.remove(id);
                }
            }
            self.selected.push(candidate.archive);
        }
    }
}

impl PackageCatalog {
    /// Retain only package-covered identities in the real input-tree order.
    /// Excessively large advisory catalogs fall back to ordinary raw estimates.
    pub fn restrict_to_trees<'a>(
        &mut self,
        trees: impl IntoIterator<Item = &'a BTreeMap<ContentId, u64>>,
    ) {
        if self.candidates.is_empty() {
            return;
        }
        let covered: BTreeSet<_> = self
            .candidates
            .values()
            .flat_map(|candidate| candidate.covers.iter().copied())
            .collect();
        let mut total = 0_usize;
        for tree in trees {
            let group: Vec<_> = tree
                .keys()
                .filter(|id| covered.contains(id))
                .copied()
                .collect();
            total = total.saturating_add(group.len());
            if total > 262_144 {
                *self = Self::default();
                return;
            }
            if !group.is_empty() {
                self.tree_groups.push(group);
            }
        }
    }

    #[must_use = "empty catalogs require only raw transfer prediction"]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Pick the best positive saving from the current uncovered set.
    /// Identical selection logic is used by the real archive delivery path.
    pub(crate) fn best(
        &self,
        remaining: &BTreeMap<ContentId, u64>,
        excluded: &BTreeSet<ContentId>,
        cost: PackageTransferCost,
        accepts: impl Fn(PackageArchive) -> bool,
    ) -> Option<ContentId> {
        self.candidates
            .iter()
            .filter_map(|(key, candidate)| {
                if excluded.contains(key) || !accepts(candidate.archive) {
                    return None;
                }
                let (bytes, files) = candidate
                    .covers
                    .iter()
                    .filter_map(|id| remaining.get(id))
                    .fold((0_u128, 0_usize), |(bytes, count), size| {
                        (bytes + u128::from(*size), count + 1)
                    });
                cost.predicted_savings_nanoseconds(bytes, files, candidate.archive)
                    .map(|saving| (saving, *key))
            })
            .max()
            .map(|(_, key)| key)
    }

    /// Remove only the actual newly covered digest identities, without
    /// treating package expansion bytes as additional requested files.
    #[must_use = "remaining exact blobs are still required after archive delivery"]
    pub fn select(
        &self,
        missing: &mut BTreeMap<ContentId, u64>,
        limits: PackageDeliveryLimits,
        cost: PackageTransferCost,
    ) -> Vec<PackageArchive> {
        if !limits.valid() || self.is_empty() {
            return Vec::new();
        }
        let unseen = self
            .candidates
            .values()
            .flat_map(|candidate| candidate.covers.iter())
            .filter_map(|id| missing.get(id).map(|&size| (*id, size)))
            .collect();
        let mut selection = Selection {
            catalog: self,
            limits,
            cost,
            unseen,
            excluded: BTreeSet::new(),
            selected: Vec::new(),
        };
        if self.tree_groups.is_empty() {
            selection.tree(selection.unseen.clone(), missing);
        } else {
            for group in &self.tree_groups {
                let tree = group
                    .iter()
                    .filter_map(|id| selection.unseen.get(id).map(|&size| (*id, size)))
                    .collect();
                selection.tree(tree, missing);
                // Raw content delivered for an earlier tree cannot be saved
                // retroactively by an original chosen for a later tree.
                for id in group {
                    selection.unseen.remove(id);
                }
            }
        }
        selection.selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BlobRef, PackageCompression, PackageIdentity, PackageSource, TreeId};

    fn archive(label: &[u8], size: u64, expanded_bytes: u64) -> PackageArchive {
        PackageArchive {
            source: PackageSource {
                identity: PackageIdentity {
                    sha256: [1; 32],
                    compression: PackageCompression::Zstd,
                },
                size,
            },
            tree: TreeId([1; 32]),
            blob: BlobRef {
                id: ContentId::of(label),
                size,
            },
            expanded_bytes,
            entry_count: 2,
        }
    }

    #[test]
    fn package_catalog_reduces_overlapping_coverage_and_respects_decoder_limits() {
        let a = ContentId::of(b"a");
        let b = ContentId::of(b"b");
        let c = ContentId::of(b"c");
        let left = archive(b"left", 10_000, 2_000_000);
        let right = archive(b"right", 20_000, 2_000_000);
        let oversize = archive(b"oversize", 1, 100_000_000);
        let catalog = PackageCatalog {
            candidates: BTreeMap::from([
                (
                    left.blob.id,
                    Candidate {
                        archive: left,
                        covers: BTreeSet::from([a, b]),
                    },
                ),
                (
                    right.blob.id,
                    Candidate {
                        archive: right,
                        covers: BTreeSet::from([b, c]),
                    },
                ),
                (
                    oversize.blob.id,
                    Candidate {
                        archive: oversize,
                        covers: BTreeSet::from([a, b, c]),
                    },
                ),
            ]),
            tree_groups: Vec::new(),
        };
        let limits = PackageDeliveryLimits {
            max_archive_bytes: 100_000,
            max_expanded_bytes: 3_000_000,
            max_entries: 10,
            parallelism: 2,
        };
        let cost = PackageTransferCost {
            download_bytes_per_second: 100_000,
            archive_download_bytes_per_second: 100_000,
            ..Default::default()
        };
        let mut missing = BTreeMap::from([(a, 1_000_000), (b, 1_000_000), (c, 1_000_000)]);
        assert_eq!(
            catalog.select(&mut missing, limits, cost),
            vec![left, right]
        );
        assert!(missing.is_empty());
        let mut missing = BTreeMap::from([(a, 1_000_000), (b, 1_000_000), (c, 10)]);
        assert_eq!(catalog.select(&mut missing, limits, cost), vec![left]);
        assert_eq!(missing, BTreeMap::from([(c, 10)]));
    }

    #[test]
    fn package_catalog_does_not_retroactively_cover_an_earlier_raw_tree() {
        let a = ContentId::of(b"a");
        let b = ContentId::of(b"b");
        let original = archive(b"archive", 200_000, 2_000_000);
        let mut catalog = PackageCatalog {
            candidates: BTreeMap::from([(
                original.blob.id,
                Candidate {
                    archive: original,
                    covers: BTreeSet::from([a, b]),
                },
            )]),
            ..Default::default()
        };
        let first = BTreeMap::from([(a, 100)]);
        let second = BTreeMap::from([(b, 1_000_000)]);
        catalog.restrict_to_trees([&first, &second]);
        let limits = PackageDeliveryLimits {
            max_archive_bytes: 1_000_000,
            max_expanded_bytes: 3_000_000,
            max_entries: 10,
            parallelism: 1,
        };
        let cost = PackageTransferCost {
            download_bytes_per_second: 100_000,
            archive_download_bytes_per_second: 100_000,
            ..Default::default()
        };
        let mut missing = BTreeMap::from([(a, 100), (b, 1_000_000)]);
        assert_eq!(catalog.select(&mut missing, limits, cost), vec![original]);
        assert_eq!(missing, first);
    }
}
