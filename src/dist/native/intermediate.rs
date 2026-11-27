//! Session filesystem IPC. Only local tokens and exact content identities
//! cross the existing daemon connection.
use crate::{
    build_runtime::{
        Artifact, ReferenceBlobProvider, ResultManifest,
        intermediate_fs::{
            IntermediateContent, IntermediateReference, attach_intermediate, intermediate_session,
        },
        materialize_tree,
        wire::Ticket,
    },
    client::{ServerConnection, connect_to_server},
    protocol::{TransferReply, TransferRequest},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
};

fn connection() -> Result<ServerConnection> {
    connect_to_server(&crate::commands::get_addr())
        .context("connect to managed intermediate daemon")
}

pub struct Content {
    session: Ticket,
    // These identities came directly from the daemon after it pinned the
    // package tree. No per-file authorization roundtrip is required to attach
    // a member of that same tree to the launcher's private filesystem.
    packages: Mutex<BTreeMap<crate::build_runtime::ContentId, u64>>,
}

impl Content {
    fn register_package(&self, package: &crate::build_runtime::RetainedPackage) -> Result<()> {
        let blobs = package.manifest.blobs()?;
        let mut packages = self
            .packages
            .lock()
            .map_err(|_| anyhow::anyhow!("package authorization map poisoned"))?;
        for (id, size) in blobs {
            ensure!(
                packages.get(&id).is_none_or(|old| *old == size),
                "conflicting package content length"
            );
            packages.insert(id, size);
        }
        Ok(())
    }
}

impl IntermediateContent for Content {
    fn authorize(&self, reference: IntermediateReference) -> Result<()> {
        ensure!(
            reference.session == self.session,
            "foreign intermediate session"
        );
        if self
            .packages
            .lock()
            .map_err(|_| anyhow::anyhow!("package authorization map poisoned"))?
            .get(&reference.blob.id)
            == Some(&reference.blob.size)
        {
            return Ok(());
        }
        ensure!(
            matches!(
                connection()?.transfer(TransferRequest::IntermediateAuthorize {
                    session: reference.session,
                    blob: reference.blob,
                })?,
                TransferReply::Ack
            ),
            "unexpected reference authorization reply"
        );
        Ok(())
    }

    fn fetch(&self, reference: IntermediateReference, destination: &mut File) -> Result<()> {
        fetch_retained(reference, destination)
    }
}

fn fetch_retained(reference: IntermediateReference, destination: &mut File) -> Result<()> {
    let mut connection = connection()?;
    let TransferReply::ReadStarted(Some(mut remaining)) =
        connection.transfer(TransferRequest::IntermediateRead {
            session: reference.session,
            blob: reference.blob,
        })?
    else {
        anyhow::bail!("unexpected retained content response");
    };
    ensure!(
        remaining == reference.blob.size,
        "retained content length mismatch"
    );
    while remaining > 0 {
        let TransferReply::Chunk(chunk) =
            connection.transfer(TransferRequest::IntermediateChunk)?
        else {
            anyhow::bail!("unexpected retained chunk response");
        };
        ensure!(
            !chunk.is_empty() && chunk.len() as u64 <= remaining,
            "invalid retained chunk size"
        );
        destination.write_all(&chunk)?;
        remaining -= chunk.len() as u64;
    }
    Ok(())
}

/// Materialize registry sources as immutable leased CAS references, not a
/// decompressed duplicate of the original archive. Only metadata and files
/// actually read by the caller have to traverse the network.
pub fn package(
    content: &Content,
    identity: crate::build_runtime::PackageIdentity,
    upstream: &str,
    path: &str,
    offline: bool,
    destination: &std::path::Path,
    stem: &str,
) -> Result<bool> {
    let session = content.session;
    let mut connection = connection()?;
    let TransferReply::ReadStarted(length) =
        connection.transfer(TransferRequest::IntermediatePackage {
            session,
            identity,
            upstream: upstream.into(),
            path: path.into(),
            offline,
        })?
    else {
        anyhow::bail!("unexpected package tree reply");
    };
    let Some(mut remaining) = length else {
        return Ok(false);
    };
    // Stream potentially large metadata through the existing chunk protocol.
    let mut file = tempfile::tempfile()?;
    while remaining > 0 {
        let TransferReply::Chunk(chunk) =
            connection.transfer(TransferRequest::IntermediateChunk)?
        else {
            anyhow::bail!("unexpected package tree chunk reply");
        };
        ensure!(
            !chunk.is_empty() && chunk.len() as u64 <= remaining,
            "invalid package tree chunk size"
        );
        file.write_all(&chunk)?;
        remaining -= chunk.len() as u64;
    }
    file.rewind()?;
    let package: crate::build_runtime::RetainedPackage = bincode::deserialize_from(&mut file)?;
    ensure!(
        file.stream_position()? == file.metadata()?.len(),
        "trailing package tree metadata"
    );
    package.validate(identity)?;
    validate_registry_tree(&package.manifest, stem)?;
    content.register_package(&package)?;
    let parent = destination
        .parent()
        .context("missing package destination parent")?;
    std::fs::create_dir_all(parent)?;
    let tree = materialize_tree(&package.manifest, parent, |blob, path| {
        let file = File::create_new(path)?;
        attach_intermediate(&file, IntermediateReference { session, blob })
    })?;
    tree.publish(destination)?;
    Ok(true)
}

fn validate_registry_tree(manifest: &crate::build_runtime::TreeManifest, stem: &str) -> Result<()> {
    use crate::build_runtime::TreeEntry;
    let prefix = format!("{stem}/");
    for (path, entry) in &manifest.entries {
        ensure!(
            path.as_bytes() == stem.as_bytes() || path.as_bytes().starts_with(prefix.as_bytes()),
            "archive entry outside package root"
        );
        ensure!(
            matches!(entry, TreeEntry::Directory(_) | TreeEntry::File { .. }),
            "unsupported registry archive entry"
        );
    }
    ensure!(
        matches!(
            manifest.entries.get(stem.as_bytes()),
            Some(TreeEntry::Directory(_))
        ),
        "registry package has no root"
    );
    let manifest_path = format!("{stem}/Cargo.toml");
    ensure!(
        matches!(
            manifest.entries.get(manifest_path.as_bytes()),
            Some(TreeEntry::File { .. })
        ),
        "registry package has no manifest"
    );
    Ok(())
}

pub fn open() -> Result<(Ticket, ServerConnection)> {
    let mut conn = connection()?;
    let TransferReply::IntermediateOpened(token) =
        conn.transfer(TransferRequest::IntermediateOpen)?
    else {
        anyhow::bail!("unexpected intermediate session response");
    };
    Ok((token, conn))
}

pub fn source(reference: IntermediateReference) -> ReferenceBlobProvider {
    ReferenceBlobProvider::new(move |blob| {
        ensure!(
            reference.blob == blob,
            "different requested retained content"
        );
        let mut file = tempfile::tempfile()?;
        fetch_retained(reference, &mut file)?;
        file.seek(SeekFrom::Start(0))?;
        Ok(Box::new(file))
    })
}

/// Partition selected outputs by the actual destination filesystem, never
/// by filename, extension, compiler type, or environment variable.
pub(super) struct Destinations {
    pub eager: BTreeMap<String, PathBuf>,
    lazy: BTreeMap<String, (PathBuf, Ticket)>,
}
impl Destinations {
    pub(super) fn new(destinations: BTreeMap<String, PathBuf>) -> Result<Self> {
        let mut result = Self {
            eager: BTreeMap::new(),
            lazy: BTreeMap::new(),
        };
        for (name, path) in destinations {
            let parent = path.parent().context("intermediate output has no parent")?;
            if let Some(session) = intermediate_session(parent)? {
                result.lazy.insert(name, (path, session));
            } else {
                result.eager.insert(name, path);
            }
        }
        Ok(result)
    }
    pub(super) fn sessions(&self) -> BTreeSet<Ticket> {
        self.lazy.values().map(|(_, session)| *session).collect()
    }
    pub(super) fn stage(
        &self,
        manifest: &ResultManifest,
    ) -> Result<super::client::StagedIntermediates> {
        let mut staged = super::client::StagedIntermediates::default();
        for (name, (path, session)) in &self.lazy {
            let Some(artifact) = manifest.outputs.get(name) else {
                continue;
            };
            let parent = path.parent().context("intermediate output has no parent")?;
            log::debug!("publishing leased intermediate {}", path.display());
            match artifact {
                Artifact::File { blob, mode } => {
                    let file = tempfile::NamedTempFile::new_in(parent)?;
                    attach_intermediate(
                        file.as_file(),
                        IntermediateReference {
                            session: *session,
                            blob: *blob,
                        },
                    )?;
                    if let Some(mode) = mode {
                        use std::os::unix::fs::PermissionsExt;
                        file.as_file()
                            .set_permissions(std::fs::Permissions::from_mode(*mode))?;
                    }
                    staged.file(file, path.clone());
                }
                Artifact::Tree(tree) | Artifact::GeneratedTree(tree) => {
                    let tree = materialize_tree(tree, parent, |blob, path| {
                        let file = File::create_new(path)?;
                        attach_intermediate(
                            &file,
                            IntermediateReference {
                                session: *session,
                                blob,
                            },
                        )
                    })?;
                    staged.tree(tree, path.clone());
                }
            }
        }
        Ok(staged)
    }
}

pub fn content(session: Ticket) -> Arc<Content> {
    Arc::new(Content {
        session,
        packages: Mutex::default(),
    })
}
