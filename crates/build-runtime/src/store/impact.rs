//! Mutable test-impact heads over immutable CAS trees. A head is not a
//! permanent pin: ordinary cache eviction removes the corresponding index
//! entry atomically with the tree. Clients must treat absence as a miss.
use super::{NativeStore, TreeLease, WriteTransaction};
use crate::wire::ImpactUpdate;
use crate::{
    BlobRef, ContentId, TreeEntry, TreeId, TreeManifest, TreeMetadata, TreePath, TreeTimestamp,
};
use anyhow::{Context, Result, ensure};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use std::collections::BTreeMap;

const HEADS: TableDefinition<'static, &[u8; 32], &[u8; 32]> =
    TableDefinition::new("impact_heads_v1");
const REVERSE: TableDefinition<'static, &[u8; 32], &[u8; 32]> =
    TableDefinition::new("impact_head_trees_v1");

pub(super) fn initialize(write: &WriteTransaction) -> Result<()> {
    write.open_table(HEADS)?;
    write.open_table(REVERSE)?;
    Ok(())
}

fn record_path(scope: ContentId) -> Result<TreePath> {
    TreePath::new(format!("impact-{}", blake3::Hash::from_bytes(scope.0).to_hex()).into_bytes())
}

impl NativeStore {
    /// Canonical immutable baseline record tree. Scope names the project and
    /// configuration; embedding it in the path makes reverse ownership unique.
    pub fn impact_manifest(scope: ContentId, blob: BlobRef) -> Result<TreeManifest> {
        let modified = TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        Ok(TreeManifest {
            root: TreeMetadata {
                mode: 0o755,
                modified,
            },
            entries: BTreeMap::from([(
                record_path(scope)?,
                TreeEntry::File {
                    blob,
                    metadata: TreeMetadata {
                        mode: 0o444,
                        modified,
                    },
                },
            )]),
        })
    }

    /// Resolve a head and pin its immutable record in one index snapshot.
    pub fn lookup_impact_head(&self, scope: ContentId) -> Result<Option<(TreeLease, BlobRef)>> {
        let pins = self.inner.lock_pins()?;
        let read = self.inner.db.begin_read()?;
        let Some(id) = read
            .open_table(HEADS)?
            .get(&scope.0)?
            .map(|value| TreeId(*value.value()))
        else {
            return Ok(None);
        };
        let Some(lease) = self.lookup_tree_in(id, &read, pins)? else {
            return Ok(None);
        };
        let blob = validate_record(scope, &lease)?;
        Ok(Some((lease, blob)))
    }

    /// Install a complete record only if the observed head still matches.
    /// The caller retains the replacement tree throughout publication.
    /// Concurrent incremental collectors cannot silently overwrite one another.
    pub fn compare_exchange_impact_head(
        &self,
        scope: ContentId,
        expected: Option<TreeId>,
        replacement: &TreeLease,
    ) -> Result<ImpactUpdate> {
        ensure!(
            replacement.belongs_to(self) && replacement.is_indexed(),
            "impact head requires a pinned tree in the same store"
        );
        validate_record(scope, replacement)?;
        let id = replacement.id();
        let _mutation = self.inner.lock_mutations()?;
        let write = self.inner.db.begin_write()?;
        {
            let mut heads = write.open_table(HEADS)?;
            let mut reverse = write.open_table(REVERSE)?;
            let actual = heads.get(&scope.0)?.map(|value| TreeId(*value.value()));
            if actual != expected {
                return Ok(ImpactUpdate::Conflict(actual));
            }
            if actual == Some(id) {
                return Ok(ImpactUpdate::Published(id));
            }
            if let Some(old) = actual {
                let owner = reverse
                    .remove(&old.0)?
                    .context("missing impact reverse index")?;
                ensure!(
                    owner.value() == &scope.0,
                    "inconsistent impact reverse index"
                );
            }
            ensure!(
                reverse.get(&id.0)?.is_none(),
                "replacement tree already owns an impact head"
            );
            reverse.insert(&id.0, &scope.0)?;
            heads.insert(&scope.0, &id.0)?;
        }
        write.commit()?;
        Ok(ImpactUpdate::Published(id))
    }
}

fn validate_record(scope: ContentId, lease: &TreeLease) -> Result<BlobRef> {
    let path = record_path(scope)?;
    let Some(TreeEntry::File { blob, .. }) = lease.manifest().entries.get(&path) else {
        anyhow::bail!("impact record belongs to another scope or is malformed");
    };
    ensure!(
        lease.manifest() == &NativeStore::impact_manifest(scope, *blob)?,
        "noncanonical impact record"
    );
    Ok(*blob)
}

pub(super) fn remove_tree(write: &WriteTransaction, id: TreeId) -> Result<()> {
    let mut reverse = write.open_table(REVERSE)?;
    let Some(owner) = reverse.remove(&id.0)? else {
        return Ok(());
    };
    let mut heads = write.open_table(HEADS)?;
    let head = heads
        .remove(owner.value())?
        .context("missing impact head")?;
    ensure!(head.value() == &id.0, "inconsistent impact head");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Eviction;
    use std::io::Read;

    #[test]
    fn impact_head_conflicts_pins_eviction_and_reopen() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let scope = ContentId::of(b"project/profile/target");
        let other_scope = ContentId::of(b"another project");
        let first_id;
        let second_id;
        {
            let store = NativeStore::open(dir.path())?;
            assert!(store.lookup_impact_head(scope)?.is_none());
            let first = store.stage(&b"first baseline"[..])?;
            let first_manifest = NativeStore::impact_manifest(scope, first.reference())?;
            let first = store.publish_tree_pinned(&first_manifest, vec![first])?;
            first_id = first.id();
            assert_eq!(
                store.compare_exchange_impact_head(scope, None, &first)?,
                ImpactUpdate::Published(first_id)
            );
            assert!(
                store
                    .compare_exchange_impact_head(other_scope, None, &first)
                    .is_err()
            );
            let (read, blob) = store
                .lookup_impact_head(scope)?
                .context("missing published head")?;
            let mut bytes = Vec::new();
            read.open_blob(blob.id)?.read_to_end(&mut bytes)?;
            assert_eq!(bytes, b"first baseline");
            let second = store.stage(&b"second baseline"[..])?;
            let second_manifest = NativeStore::impact_manifest(scope, second.reference())?;
            let second = store.publish_tree_pinned(&second_manifest, vec![second])?;
            second_id = second.id();
            assert_eq!(
                store.compare_exchange_impact_head(scope, None, &second)?,
                ImpactUpdate::Conflict(Some(first_id))
            );
            assert_eq!(
                store.compare_exchange_impact_head(scope, Some(first_id), &second)?,
                ImpactUpdate::Published(second_id)
            );
            drop(first);
            assert_eq!(store.evict_tree(first_id)?, Eviction::Pinned);
            drop(read);
            assert!(matches!(
                store.evict_tree(first_id)?,
                Eviction::Removed { .. }
            ));
            assert_eq!(
                store
                    .lookup_impact_head(scope)?
                    .context("lost replacement head")?
                    .0
                    .id(),
                second_id
            );
        }
        let store = NativeStore::open(dir.path())?;
        assert_eq!(
            store
                .lookup_impact_head(scope)?
                .context("head not durable")?
                .0
                .id(),
            second_id
        );
        assert!(matches!(
            store.evict_tree(second_id)?,
            Eviction::Removed { .. }
        ));
        assert!(store.lookup_impact_head(scope)?.is_none());
        Ok(())
    }
}
