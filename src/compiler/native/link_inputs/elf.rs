//! Read only the ELF identity and dynamic tags relevant to link-time search.
//! No target code or library is executed during dependency discovery.
use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::Read,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Path, PathBuf},
};

use anyhow::{Result, ensure};
use object::{ReadRef, read::ReadCache};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Identity {
    class: u8,
    endian: u8,
    machine: u16,
}

impl Identity {
    fn header(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 || !bytes.starts_with(b"\x7fELF") {
            return None;
        }
        let machine = [bytes[18], bytes[19]];
        Some(Self {
            class: bytes[4],
            endian: bytes[5],
            machine: match bytes[5] {
                1 => u16::from_le_bytes(machine),
                2 => u16::from_be_bytes(machine),
                _ => return None,
            },
        })
    }

    pub(super) fn read(path: &Path) -> Result<Option<Self>> {
        Self::read_inner(path, &mut BTreeSet::new())
    }

    fn read_inner(path: &Path, active: &mut BTreeSet<PathBuf>) -> Result<Option<Self>> {
        ensure!(active.insert(path.to_owned()), "recursive thin archive");
        let mut file = File::open(path)?;
        let mut prefix = Vec::new();
        (&mut file).take(64).read_to_end(&mut prefix)?;
        if let Some(identity) = Self::header(&prefix) {
            active.remove(path);
            return Ok(Some(identity));
        }
        if !prefix.starts_with(b"!<arch>\n") && !prefix.starts_with(b"!<thin>\n") {
            active.remove(path);
            return Ok(None);
        }
        let cache = ReadCache::new(file);
        let archive = object::read::archive::ArchiveFile::parse(&cache)?;
        let mut found = None;
        for member in archive.members() {
            let member = member?;
            let identity = if member.is_thin() {
                let target = path
                    .parent()
                    .unwrap_or(Path::new("/"))
                    .join(OsStr::from_bytes(member.name()));
                Self::read_inner(&target, active)?
            } else {
                let (offset, size) = member.file_range();
                if size < 20 {
                    continue;
                }
                Self::header(
                    cache
                        .read_bytes_at(offset, size.min(64))
                        .map_err(|()| anyhow::anyhow!("invalid archive member range"))?,
                )
            };
            if identity.is_some() {
                found = identity;
                break;
            }
        }
        active.remove(path);
        Ok(found)
    }

    pub(super) const fn lib_directory(self) -> &'static str {
        if self.class == 2 { "lib64" } else { "lib" }
    }
}

#[derive(Default)]
pub(super) struct DynamicInfo {
    pub soname: Option<OsString>,
    pub needed: Vec<OsString>,
    pub rpath: Vec<PathBuf>,
    pub runpath: Option<Vec<PathBuf>>,
    pub identity: Option<Identity>,
}

fn paths(bytes: &[u8]) -> Vec<PathBuf> {
    bytes
        .split(|byte| *byte == b':')
        .map(|value| PathBuf::from(OsStr::from_bytes(value)))
        .collect()
}

impl DynamicInfo {
    pub(super) fn read(path: &Path) -> Result<Option<Self>> {
        let file = File::open(path)?;
        let cache = ReadCache::new(file);
        let Ok(header) = cache.read_bytes_at(0, 20) else {
            return Ok(None);
        };
        let Some(identity) = Identity::header(header) else {
            return Ok(None);
        };
        // Relocatable inputs need only their ELF header, not symbol tables.
        let kind = if identity.endian == 1 {
            u16::from_le_bytes([header[16], header[17]])
        } else {
            u16::from_be_bytes([header[16], header[17]])
        };
        if kind != object::elf::ET_DYN.0 {
            return Ok(None);
        }
        let mut result = Self {
            identity: Some(identity),
            ..Self::default()
        };
        macro_rules! read_table {
            ($file:expr) => {{
                let file = $file;
                let table = file
                    .elf_section_table()
                    .dynamic_table(file.endian(), file.data())?;
                for entry in &table {
                    match entry.tag {
                        object::elf::DT_NEEDED => result
                            .needed
                            .push(OsString::from_vec(table.string(entry)?.to_vec())),
                        object::elf::DT_SONAME => {
                            result.soname = Some(OsString::from_vec(table.string(entry)?.to_vec()))
                        }
                        object::elf::DT_RPATH => result.rpath = paths(table.string(entry)?),
                        object::elf::DT_RUNPATH => {
                            result.runpath = Some(paths(table.string(entry)?))
                        }
                        _ => {}
                    }
                }
            }};
        }
        match object::File::parse(&cache)? {
            object::File::Elf32(file) => read_table!(file),
            object::File::Elf64(file) => read_table!(file),
            _ => anyhow::bail!("unexpected ELF format"),
        }
        Ok(Some(result))
    }

    pub(super) fn has_libc(&self) -> bool {
        self.needed
            .iter()
            .any(|name| name.as_bytes().starts_with(b"libc.so"))
    }
}
