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
    sync::Arc,
};

fn connection() -> Result<ServerConnection> {
    connect_to_server(&crate::commands::get_addr())
        .context("connect to managed intermediate daemon")
}

pub struct Content;

impl IntermediateContent for Content {
    fn authorize(&self, reference: IntermediateReference) -> Result<()> {
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
}

pub fn package(
    session: Ticket,
    identity: crate::build_runtime::PackageIdentity,
    upstream: &str,
    path: &str,
    offline: bool,
    destination: &mut File,
) -> Result<bool> {
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
        anyhow::bail!("unexpected package delivery reply");
    };
    let Some(mut remaining) = length else {
        return Ok(false);
    };
    while remaining > 0 {
        let TransferReply::Chunk(chunk) =
            connection.transfer(TransferRequest::IntermediateChunk)?
        else {
            anyhow::bail!("unexpected package chunk reply");
        };
        ensure!(
            !chunk.is_empty() && chunk.len() as u64 <= remaining,
            "invalid package chunk size"
        );
        destination.write_all(&chunk)?;
        remaining -= chunk.len() as u64;
    }
    Ok(true)
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
        Content.fetch(reference, &mut file)?;
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

pub fn content() -> Arc<dyn IntermediateContent> {
    Arc::new(Content)
}
