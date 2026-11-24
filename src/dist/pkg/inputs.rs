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
        let (source, destination) = self.paths.file(path)?;
        let input = InputFile { source, generated };
        match self.files.entry(destination) {
            Entry::Vacant(entry) => {
                entry.insert(input);
            }
            Entry::Occupied(entry) => {
                if entry.get() != &input {
                    return Err(anyhow!(
                        "conflicting compiler input paths at {}",
                        entry.key()
                    ));
                }
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
    pub fn into_native_mapping(self) -> Result<crate::build_runtime::MappedTree> {
        use crate::build_runtime::{
            MappedMetadata, MappedTree, TreeMetadata, TreePath, TreeTimestamp,
        };
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

        let directories = super::native_directory_metadata()?;
        let mut mapping = MappedTree::new(directories);
        let relative = |path: &Path| -> Result<TreePath> {
            TreePath::new(path.strip_prefix("/")?.as_os_str().as_bytes().to_vec())
        };
        for (destination, input) in self.files {
            let path = relative(Path::new(&destination))?;
            let source = input.source.canonicalize()?;
            if let Some(bytes) = input.generated {
                let metadata = fs::metadata(&source)?;
                mapping.add_bytes(
                    path,
                    bytes,
                    TreeMetadata {
                        mode: metadata.mode() & 0o7777,
                        modified: TreeTimestamp {
                            seconds: metadata.mtime(),
                            nanoseconds: u32::try_from(metadata.mtime_nsec())?,
                        },
                    },
                )?;
            } else {
                mapping.add_file(path, source, MappedMetadata::Preserve)?;
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
        Ok(mapping)
    }
}
