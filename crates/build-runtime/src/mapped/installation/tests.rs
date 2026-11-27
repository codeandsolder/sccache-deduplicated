use super::*;
use crate::{
    ContentId, MappedMetadata, MappedTree, SourceDigestCache, TreeEntry, TreeId, TreeManifest,
    TreeMetadata, TreePath, TreeTimestamp,
};
use std::fs;

#[test]
fn mutable_installation_is_reverified_and_rejects_mutation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("install");
    fs::create_dir(&root)?;
    let tool = root.join("tool");
    fs::write(&tool, b"original")?;
    fs::write(root.join("modified"), b"modified")?;
    let metadata = TreeMetadata {
        mode: 0o755,
        modified: TreeTimestamp {
            seconds: 0,
            nanoseconds: 0,
        },
    };
    let blob = BlobRef {
        id: ContentId::of(b"original"),
        size: 8,
    };
    let manifest = InstallationManifest {
        source: crate::PackageSource {
            identity: crate::PackageIdentity {
                sha256: [1; 32],
                compression: crate::PackageCompression::Tar,
            },
            size: 0,
        },
        package: TreeId([2; 32]),
        components: BTreeMap::from([(
            "test".into(),
            TreeManifest {
                root: metadata,
                entries: ["tool", "modified", "missing"]
                    .into_iter()
                    .map(|name| {
                        Ok((
                            TreePath::new(name.as_bytes().to_vec())?,
                            TreeEntry::File { blob, metadata },
                        ))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?,
            },
        )]),
    };
    let mut encoded = Vec::new();
    manifest.write(&mut encoded)?;
    let decoded = InstallationManifest::read(encoded.as_slice())?;
    let (fresh_catalog, fresh_report) =
        InstallationCatalog::attest(&root, std::slice::from_ref(&decoded), None)?;
    assert_eq!(fresh_report.verified_files, 1);
    assert_eq!(fresh_catalog.files.len(), 1);
    let (catalog, report) =
        InstallationCatalog::attest(&root, std::slice::from_ref(&decoded), None)?;
    assert_eq!(report.verified_files, 1);
    assert_eq!(report.verified_bytes, 8);
    assert_eq!(report.differing_files, 1);
    assert_eq!(report.missing_files, 1);
    let catalog_path = temp.path().join("catalog");
    catalog.write(File::create(&catalog_path)?)?;
    let (_, warm) =
        InstallationCatalog::attest(&root, std::slice::from_ref(&decoded), Some(&catalog_path))?;
    assert_eq!(warm.verified_files, 1);
    assert_eq!(warm.reused_files, 0);
    assert_eq!(warm.reused_bytes, 0);
    let mut cache = SourceDigestCache::default();
    cache.load_catalog(&catalog_path)?;
    let capture = |cache: Option<&SourceDigestCache>| -> Result<TreeId> {
        let mut mapping = MappedTree::new(metadata);
        mapping.add_file(
            TreePath::new(b"tool".to_vec())?,
            tool.clone(),
            MappedMetadata::Normalize(metadata.modified),
        )?;
        Ok(match cache {
            Some(cache) => mapping.prepare_with_cache(cache)?,
            None => mapping.prepare()?,
        }
        .id())
    };
    let original = capture(None)?;
    assert_eq!(capture(Some(&cache))?, original);
    assert_eq!(cache.catalog_hits(), (0, 0));
    let (file, stat) = open_source(&tool)?;
    assert_eq!(cache.digest(&tool, &file, &stat)?, blob);
    fs::write(&tool, b"changed!")?;
    assert_ne!(capture(Some(&cache))?, original);
    let (_, changed) = InstallationCatalog::attest(&root, &[decoded], Some(&catalog_path))?;
    assert_eq!(changed.reused_files, 0);
    assert_eq!(changed.differing_files, 2);
    assert_eq!(cache.catalog_hits(), (0, 0));
    Ok(())
}
