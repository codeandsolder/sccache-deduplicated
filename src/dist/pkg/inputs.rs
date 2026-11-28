//! One compiler input plan for archive emission and native CAS capture.
//! Dependency discovery and path topology do not depend on the transport.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::{self, Seek},
    path::{Path, PathBuf},
};

use fs_err as fs;

use super::{InputArchivePaths, make_tar_header};
use crate::{
    dist::PathTransformer,
    errors::{Result, anyhow},
};

#[derive(PartialEq, Eq)]
struct InputFile {
    source: PathBuf,
    generated: Option<Vec<u8>>,
    codegen_only: bool,
}

pub struct CompilerInputs {
    paths: InputArchivePaths,
    files: BTreeMap<String, InputFile>,
}

impl CompilerInputs {
    pub fn new(transformer: PathTransformer) -> Self {
        Self {
            paths: InputArchivePaths::new(transformer),
            files: BTreeMap::new(),
        }
    }

    pub fn directory(&mut self, path: &Path) -> Result<String> {
        self.paths.directory(path)
    }

    pub fn file(&mut self, path: &Path, generated: Option<Vec<u8>>) -> Result<()> {
        self.file_with_role(path, generated, false)
    }

    /// The frontend discovered this file through codegen-only dependency
    /// discovery. Any independent declaration as a link input overrides
    /// this role, even when two spellings resolve to the same file.
    pub fn codegen_file(&mut self, path: &Path) -> Result<()> {
        self.file_with_role(path, None, true)
    }

    fn file_with_role(
        &mut self,
        path: &Path,
        generated: Option<Vec<u8>>,
        codegen_only: bool,
    ) -> Result<()> {
        let (source, destination) = self.paths.file(path)?;
        let input = InputFile {
            source,
            generated,
            codegen_only,
        };
        match self.files.entry(destination) {
            Entry::Vacant(entry) => {
                entry.insert(input);
            }
            Entry::Occupied(mut entry) => {
                if entry.get().source != input.source || entry.get().generated != input.generated {
                    return Err(anyhow!(
                        "conflicting compiler input paths at {}",
                        entry.key()
                    ));
                }
                entry.get_mut().codegen_only &= codegen_only;
            }
        }
        Ok(())
    }

    pub fn write_archive(
        self,
        writer: &mut dyn io::Write,
        mut transform: impl FnMut(&Path, &mut fs::File) -> Result<Option<Vec<u8>>>,
    ) -> Result<()> {
        let mut archive = tar::Builder::new(writer);
        for (destination, input) in self.files {
            let mut header = make_tar_header(&input.source, &destination)?;
            if let Some(bytes) = input.generated {
                header.set_size(u64::try_from(bytes.len())?);
                header.set_cksum();
                archive.append(&header, bytes.as_slice())?;
                continue;
            }
            let mut file = fs::File::open(&input.source)?;
            if let Some(bytes) = transform(&input.source, &mut file)? {
                header.set_size(u64::try_from(bytes.len())?);
                header.set_cksum();
                archive.append(&header, bytes.as_slice())?;
            } else {
                file.rewind()?;
                header.set_size(file.metadata()?.len());
                header.set_cksum();
                archive.append(&header, file)?;
            }
        }
        self.paths.append_support_entries(&mut archive)?;
        archive.into_inner()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn into_native_mapping(
        self,
        normalize_timestamp: impl Fn(&Path) -> bool,
    ) -> Result<crate::build_runtime::MappedTree> {
        Ok(self.into_native_input_plan(normalize_timestamp)?.mapping)
    }

    #[cfg(target_os = "linux")]
    pub fn into_native_input_plan(
        self,
        normalize_timestamp: impl Fn(&Path) -> bool,
    ) -> Result<super::NativeInputPlan> {
        use crate::build_runtime::{
            MappedMetadata, MappedTree, TreeMetadata, TreePath, TreeTimestamp,
        };
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

        let directories = super::native_directory_metadata()?;
        let mut mapping = MappedTree::new(directories);
        let mut codegen_only = std::collections::BTreeSet::new();
        let relative = |path: &Path| -> Result<TreePath> {
            TreePath::new(path.strip_prefix("/")?.as_os_str().as_bytes().to_vec())
        };
        for (destination, input) in self.files {
            let logical = Path::new(&destination);
            let normalize = normalize_timestamp(logical);
            let path = relative(logical)?;
            if input.codegen_only {
                codegen_only.insert(path.clone());
            }
            let source = input.source.canonicalize()?;
            if let Some(bytes) = input.generated {
                let metadata = fs::metadata(&source)?;
                mapping.add_bytes(
                    path,
                    bytes,
                    TreeMetadata {
                        mode: metadata.mode() & 0o7777,
                        modified: if normalize {
                            directories.modified
                        } else {
                            TreeTimestamp {
                                seconds: metadata.mtime(),
                                nanoseconds: u32::try_from(metadata.mtime_nsec())?,
                            }
                        },
                    },
                )?;
            } else {
                let policy = if normalize {
                    MappedMetadata::NormalizeTimestamp(directories.modified)
                } else {
                    MappedMetadata::Preserve
                };
                mapping.add_file(path, source, policy)?;
            }
        }
        for directory in self.paths.directories.keys() {
            mapping.add_directory(relative(Path::new(directory))?)?;
        }
        if let Some(physical) = self.paths.physical {
            for directory in physical.directories {
                mapping.add_directory(relative(&directory)?)?;
            }
            for (path, target) in physical.links {
                mapping.add_symlink(
                    relative(&path)?,
                    target.as_os_str().as_bytes().to_vec(),
                    directories.modified,
                )?;
            }
        }
        Ok(super::NativeInputPlan {
            mapping,
            codegen_only,
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::build_runtime::TreePath;

    #[test]
    fn independently_declared_input_overrides_codegen_only_role() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        fs::write(root.join("source.rs"), b"source")?;
        fs::write(root.join("shared"), b"shared")?;
        fs::create_dir(root.join("sub"))?;
        let mut transformer = PathTransformer::new();
        transformer.add_root_mapping(root.clone(), "/workspace");
        let mut inputs = CompilerInputs::new(transformer);
        inputs.codegen_file(&root.join("source.rs"))?;
        inputs.codegen_file(&root.join("sub/../shared"))?;
        inputs.file(&root.join("shared"), None)?;
        inputs.codegen_file(&root.join("shared"))?;
        let plan = inputs.into_native_input_plan(|_| false)?;
        assert_eq!(
            plan.codegen_only,
            [TreePath::new(b"workspace/source.rs".to_vec())?]
                .into_iter()
                .collect()
        );
        let prepared = plan.mapping.prepare()?;
        assert!(
            prepared
                .manifest()
                .entries
                .contains_key(&TreePath::new(b"workspace/shared".to_vec())?)
        );
        Ok(())
    }
}
