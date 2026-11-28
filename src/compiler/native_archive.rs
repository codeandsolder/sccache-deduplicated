//! Selected native archive inputs and deterministic worker serialization.
//! All uses share the same member and index semantics; only the bytes actually
//! consumed by the compiler determine the identity.
use crate::errors::{Context, Result};
use crate::util::{Digest, debug_display, fmt_duration_as_secs, hash_input_batch};
use fs_err as fs;
use object::read::archive::ArchiveFile;
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use std::{
    borrow::Cow,
    ffi::OsStr,
    io::Write,
    path::{Path, PathBuf},
    str, time,
};

/// A selected thin member is both a semantic input and a worker input. The
/// literal archive name matters because rustc preserves it when bundling.
#[derive(Debug)]
pub(crate) struct ThinArchiveMember {
    pub name: PathBuf,
    pub path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct ArchiveIdentity {
    pub digest: String,
    pub external_members: Vec<ThinArchiveMember>,
    /// If present, these exact canonical bytes replace the original in the worker.
    pub generated: Option<Vec<u8>>,
}

/// Archive identity depends on how the compiler consumes the selected file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ArchiveUse {
    /// Rebuild an archive from ordered loose object members.
    Members,
    /// Embed the original archive bytes in an rlib wrapper object.
    Packed,
    /// Pass an archive directly to the linker, preserving its symbol index.
    Link,
}

/// Hash only the representation consumed by each selected archive request.
/// Thin archive members needed by the compiler are also returned for packaging.
pub(crate) async fn hash_all_archives(
    files: &[(PathBuf, ArchiveUse)],
    pool: &tokio::runtime::Handle,
    macho_target: Option<object::Architecture>,
    normalize_serialization: bool,
    source_files: &[PathBuf],
) -> Result<Vec<ArchiveIdentity>> {
    let start = time::Instant::now();
    let count = files.len();
    let observed = if normalize_serialization
        && files.iter().any(|(_, usage)| *usage != ArchiveUse::Members)
    {
        source_files
            .iter()
            .filter_map(|path| path.canonicalize().ok())
            .collect::<std::collections::HashSet<_>>()
    } else {
        std::collections::HashSet::new()
    };
    let hashes = hash_input_batch(files, pool, move |(path, usage)| {
        let normalize = normalize_serialization
            && *usage != ArchiveUse::Members
            && !observed.contains(&path.canonicalize()?);
        hash_archive(path, macho_target, *usage, normalize)
    })
    .await?;
    trace!(
        "Hashed {count} archives in {}",
        fmt_duration_as_secs(&start.elapsed())
    );
    Ok(hashes)
}

fn hash_archive(
    path: &Path,
    macho_target: Option<object::Architecture>,
    usage: ArchiveUse,
    normalize_serialization: bool,
) -> Result<ArchiveIdentity> {
    // Use owned memory: another process may truncate or rewrite the archive.
    let mut archive = fs::read(path)
        .with_context(|| format!("Failed to read archive: {}", debug_display(path)))?;
    if usage != ArchiveUse::Members {
        // rustc writes the full archive into .bundled_lib and the basename
        // into rmeta-link. Normalize the bytes actually delivered to rustc,
        // never just pretend two distinct wrapper objects are identical.
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .context("packed archive name is not UTF-8")?;
        let changed = if normalize_serialization {
            if let Some(canonical) = canonical_gnu_archive(path, &archive)? {
                let changed = canonical != archive;
                archive = canonical;
                changed
            } else {
                normalize_archive_headers(&mut archive)
            }
        } else {
            false
        };
        let mut digest = Digest::new();
        digest.delimiter(match usage {
            ArchiveUse::Packed => b"packed-native-archive-v2",
            ArchiveUse::Link => b"linked-native-archive-v2",
            ArchiveUse::Members => unreachable!(),
        });
        digest.update(&(name.len() as u128).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update(blake3::hash(&archive).as_bytes());
        let mut external_members = Vec::new();
        if usage == ArchiveUse::Link && archive.starts_with(&object::archive::THIN_MAGIC) {
            let members = hash_archive_members(path, &archive, macho_target)?;
            digest.update(members.digest.as_bytes());
            external_members = members.external_members;
        }
        return Ok(ArchiveIdentity {
            digest: digest.finish(),
            external_members,
            generated: changed.then_some(archive),
        });
    }
    hash_archive_members(path, &archive, macho_target)
}

/// Canonicalize only header fields that describe archive creation rather than
/// the member contents or symbol lookup. Preserve the format, layout, member
/// names, offsets and symbol tables exactly. The normalization is transactional:
/// unrecognized or malformed layouts are left byte-for-byte unchanged.
fn normalize_archive_headers(data: &mut [u8]) -> bool {
    let Some(headers) = archive_header_ranges(data) else {
        return false;
    };
    let mut changed = false;
    for (offset, special) in headers {
        let header = &mut data[offset..offset + 60];
        for (start, end, value) in [
            (16, 28, b"0".as_slice()),
            (28, 34, b"0"),
            (34, 40, b"0"),
            (40, 48, if special { b"0" } else { b"644" }),
        ] {
            let field = &mut header[start..end];
            if !field.starts_with(value) || field[value.len()..].iter().any(|byte| *byte != b' ') {
                field.fill(b' ');
                field[..value.len()].copy_from_slice(value);
                changed = true;
            }
        }
    }
    changed
}

fn archive_header_ranges(data: &[u8]) -> Option<Vec<(usize, bool)>> {
    // FAT containers preserve their original slices and offsets. Normalize
    // each recognized contained archive independently, without rebuilding it.
    if let Ok(fat) = MachOFatFile32::parse(data) {
        return fat_header_ranges(data, fat.arches());
    }
    if let Ok(fat) = MachOFatFile64::parse(data) {
        return fat_header_ranges(data, fat.arches());
    }
    let archive = ArchiveFile::parse(data).ok()?;
    if !data.starts_with(&object::archive::MAGIC) && !data.starts_with(&object::archive::THIN_MAGIC)
    {
        // AIX and z/OS have different header encodings; preserve the exact
        // serialized input rather than rewriting fields with Unix rules.
        return None;
    }
    let mut headers = Vec::new();
    let mut offset = 8usize;
    while offset < data.len() {
        let header = data.get(offset..offset.checked_add(60)?)?;
        if header[58..60] != object::archive::TERMINATOR {
            return None;
        }
        let name = str::from_utf8(&header[..16]).ok()?.trim_end_matches(' ');
        let special = matches!(
            name,
            "/" | "//"
                | "/SYM64/"
                | "__.SYMDEF"
                | "__.SYMDEF SORTED"
                | "__.SYMDEF_64"
                | "__.SYMDEF_64 SORTED"
                | "/<ECSYMBOLS>/"
        );
        let size = str::from_utf8(&header[48..58])
            .ok()?
            .trim()
            .parse::<usize>()
            .ok()?;
        // A BSD extended member name is part of the stored data. Thin
        // archives use GNU names and omit ordinary member bodies entirely.
        let stored = if archive.is_thin() && !special {
            0
        } else {
            size
        };
        if archive.is_thin() && name.starts_with("#1/") {
            return None;
        }
        headers.push((offset, special));
        offset = offset
            .checked_add(60)?
            .checked_add(stored)?
            .checked_add(stored % 2)?;
    }
    (offset == data.len()).then_some(headers)
}

fn fat_header_ranges<A: FatArch>(data: &[u8], arches: &[A]) -> Option<Vec<(usize, bool)>> {
    let base = data.as_ptr().addr();
    let mut ranges = Vec::new();
    let mut headers = Vec::new();
    for arch in arches {
        let slice = arch.data(data).ok()?;
        let start = slice.as_ptr().addr().checked_sub(base)?;
        let end = start.checked_add(slice.len())?;
        // Reject slices overlapping the FAT header or each other. In
        // particular a malformed self-referential slice must not recurse.
        if start < 8usize.checked_add(arches.len().checked_mul(std::mem::size_of::<A>())?)?
            || slice.len() >= data.len()
        {
            return None;
        }
        if ranges
            .iter()
            .any(|&(first, last)| start < last && first < end)
        {
            return None;
        }
        ranges.push((start, end));
        headers.extend(
            archive_header_ranges(slice)?
                .into_iter()
                .map(|(offset, special)| (start + offset, special)),
        );
    }
    Some(headers)
}

fn hash_archive_members(
    path: &Path,
    archive: &[u8],
    macho_target: Option<object::Architecture>,
) -> Result<ArchiveIdentity> {
    if let Ok(fat) = MachOFatFile32::parse(archive) {
        return hash_fat_archive(path, archive, fat.arches(), macho_target);
    }
    if let Ok(fat) = MachOFatFile64::parse(archive) {
        return hash_fat_archive(path, archive, fat.arches(), macho_target);
    }
    hash_regular_archive(path, archive)
}

fn hash_fat_archive<A: FatArch>(
    path: &Path,
    data: &[u8],
    arches: &[A],
    target: Option<object::Architecture>,
) -> Result<ArchiveIdentity> {
    // rustc's macOS archive builder chooses the first matching architecture
    // (not the CPU subtype), then treats its slice as an ordinary archive.
    if let Some(selected) =
        target.and_then(|target| arches.iter().find(|arch| arch.architecture() == target))
    {
        return hash_regular_archive(path, selected.data(data)?);
    }
    // Unknown/non-macOS consumers cannot be equated to an arbitrary slice.
    // Keep architecture association and slice boundaries explicit.
    let mut digest = Digest::new();
    digest.delimiter(b"fat-archive-v2");
    let mut external_members = Vec::new();
    for arch in arches {
        digest.update(&arch.cputype().0.to_le_bytes());
        digest.update(&arch.cpusubtype().0.to_le_bytes());
        let slice = hash_regular_archive(path, arch.data(data)?)?;
        digest.update(slice.digest.as_bytes());
        external_members.extend(slice.external_members);
    }
    Ok(ArchiveIdentity {
        digest: digest.finish(),
        external_members,
        generated: None,
    })
}

fn hash_regular_archive(path: &Path, data: &[u8]) -> Result<ArchiveIdentity> {
    let archive = ArchiveFile::parse(data)?;
    let mut digest = Digest::new();
    digest.delimiter(b"archive-members-v2");
    let mut external_members = Vec::new();
    for entry in archive.members() {
        let entry = entry?;
        let name = entry.name();
        digest.update(&(name.len() as u128).to_le_bytes());
        digest.update(name);
        let content = if entry.is_thin() {
            // rustc uses the member's UTF-8 name verbatim and resolves it
            // relative to the selected archive's parent, including ../.
            let name = PathBuf::from(str::from_utf8(name)?);
            let member_path = path.parent().context("archive has no parent")?.join(&name);
            let file = fs::File::open(&member_path).with_context(|| {
                format!(
                    "Failed to open thin archive member {}",
                    debug_display(&member_path)
                )
            })?;
            let mut member_hash = blake3::Hasher::new();
            member_hash.update_reader(file)?;
            external_members.push(ThinArchiveMember {
                name,
                path: member_path,
            });
            member_hash.finalize()
        } else {
            blake3::hash(entry.data(data)?)
        };
        digest.update(content.as_bytes());
    }
    Ok(ArchiveIdentity {
        digest: digest.finish(),
        external_members,
        generated: None,
    })
}

/// GNU archives have a complete symbol-to-member index. Represent each
/// symbol by its member ordinal, then serialize a deterministic archive with
/// fresh offsets. This also makes packed thin archives self-contained.
fn canonical_gnu_archive(path: &Path, data: &[u8]) -> Result<Option<Vec<u8>>> {
    use object::read::archive::ArchiveKind;
    let Ok(archive) = ArchiveFile::parse(data) else {
        return Ok(None);
    };
    if !archive.is_thin() && !matches!(archive.kind(), ArchiveKind::Gnu | ArchiveKind::Gnu64) {
        return Ok(None);
    }
    let mut members = Vec::new();
    let mut ordinals = std::collections::HashMap::new();
    let base = data.as_ptr().addr();
    for (ordinal, member) in archive.members().enumerate() {
        let member = member?;
        let header = member
            .header()
            .context("GNU archive member has no standard header")?;
        let offset = std::ptr::from_ref(header)
            .addr()
            .checked_sub(base)
            .context("archive header outside data")?;
        ordinals.insert(u64::try_from(offset)?, ordinal);
        let name = member.name();
        let content = if member.is_thin() {
            Cow::Owned(fs::read(
                path.parent()
                    .context("archive has no parent")?
                    .join(str::from_utf8(name)?),
            )?)
        } else {
            Cow::Borrowed(member.data(data)?)
        };
        members.push((name, content));
    }
    let symbols = archive
        .symbols()?
        .map(|symbols| {
            symbols
                .map(|symbol| {
                    let symbol = symbol?;
                    let ordinal = *ordinals
                        .get(&symbol.offset().0)
                        .context("archive symbol references missing member")?;
                    Ok((symbol.name(), ordinal))
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    Ok(Some(write_gnu_archive(&members, symbols.as_deref())?))
}

/// Canonical GNU serialization preserves member and symbol order, supports
/// arbitrary GNU extended member names, and chooses the smallest valid
/// index word width. Index offsets are recomputed, not hashed as inputs.
type GnuMember<'a> = (&'a [u8], Cow<'a, [u8]>);

fn write_gnu_archive(
    members: &[GnuMember<'_>],
    symbols: Option<&[(&[u8], usize)]>,
) -> Result<Vec<u8>> {
    let (headers, names) = gnu_member_headers(members)?;
    let symbol_name_bytes = symbols.map_or(0, |symbols| {
        symbols.iter().map(|(name, _)| name.len() + 1).sum()
    });
    let offsets_for = |word: usize| -> Result<Vec<usize>> {
        let mut offset = 8usize;
        if let Some(symbols) = symbols {
            offset = offset
                .checked_add(gnu_record_size(
                    word.checked_mul(symbols.len() + 1)
                        .context("archive index too large")?
                        .checked_add(symbol_name_bytes)
                        .context("archive index too large")?,
                )?)
                .context("archive too large")?;
        }
        if symbols.is_none() || !names.is_empty() {
            offset = offset
                .checked_add(gnu_record_size(names.len())?)
                .context("archive too large")?;
        }
        let mut offsets = Vec::with_capacity(members.len());
        for (_, bytes) in members {
            offsets.push(offset);
            offset = offset
                .checked_add(gnu_record_size(bytes.len())?)
                .context("archive too large")?;
        }
        Ok(offsets)
    };
    let mut word = 4usize;
    let mut offsets = offsets_for(word)?;
    if offsets.iter().any(|offset| u32::try_from(*offset).is_err())
        || symbols.is_some_and(|symbols| u32::try_from(symbols.len()).is_err())
    {
        word = 8;
        offsets = offsets_for(word)?;
    }
    let mut output = object::archive::MAGIC.to_vec();
    if let Some(symbols) = symbols {
        let mut index = Vec::new();
        let append_word = |index: &mut Vec<u8>, value: usize| -> Result<()> {
            if word == 4 {
                index.extend_from_slice(&u32::try_from(value)?.to_be_bytes());
            } else {
                index.extend_from_slice(&u64::try_from(value)?.to_be_bytes());
            }
            Ok(())
        };
        append_word(&mut index, symbols.len())?;
        for (_, ordinal) in symbols {
            append_word(&mut index, offsets[*ordinal])?;
        }
        for (name, _) in symbols {
            index.extend_from_slice(name);
            index.push(0);
        }
        append_gnu_record(
            &mut output,
            if word == 4 { b"/" } else { b"/SYM64/" },
            &index,
            true,
        )?;
    }
    if symbols.is_none() || !names.is_empty() {
        append_gnu_record(&mut output, b"//", &names, true)?;
    }
    for ((_, bytes), header) in members.iter().zip(headers) {
        append_gnu_record(&mut output, &header, bytes, false)?;
    }
    Ok(output)
}

fn gnu_member_headers(members: &[GnuMember<'_>]) -> Result<(Vec<Vec<u8>>, Vec<u8>)> {
    let mut names = Vec::new();
    let mut name_offsets = std::collections::HashMap::new();
    let mut headers = Vec::new();
    for (name, _) in members {
        if !name.is_empty()
            && name.len() < 16
            && !name.contains(&b'/')
            && !name.contains(&b'\n')
            && !name.starts_with(b"#1/")
        {
            let mut short = name.to_vec();
            short.push(b'/');
            headers.push(short);
        } else {
            anyhow::ensure!(
                !name.windows(2).any(|pair| pair == b"/\n"),
                "unrepresentable GNU archive member name"
            );
            let offset = *name_offsets.entry(*name).or_insert_with(|| {
                let offset = names.len();
                names.extend_from_slice(name);
                names.extend_from_slice(b"/\n");
                offset
            });
            headers.push(format!("/{offset}").into_bytes());
        }
    }
    Ok((headers, names))
}

fn gnu_record_size(size: usize) -> Result<usize> {
    60usize
        .checked_add(size)
        .and_then(|size| size.checked_add(size % 2))
        .context("archive member too large")
}

fn append_gnu_record(output: &mut Vec<u8>, name: &[u8], bytes: &[u8], special: bool) -> Result<()> {
    anyhow::ensure!(
        name.len() <= 16 && u64::try_from(bytes.len())? <= 9_999_999_999u64,
        "archive member exceeds GNU header limits"
    );
    output.extend_from_slice(name);
    output.extend(std::iter::repeat_n(b' ', 16 - name.len()));
    write!(
        output,
        "{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        0,
        0,
        0,
        if special { "0" } else { "644" },
        bytes.len()
    )?;
    output.extend_from_slice(bytes);
    if bytes.len() % 2 != 0 {
        output.push(b'\n');
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive_bytes(name: &[u8], data: &[u8], mtime: u64) -> anyhow::Result<Vec<u8>> {
        let mut builder = ar::Builder::new(Vec::new());
        let mut header = ar::Header::new(name.to_vec(), u64::try_from(data.len())?);
        header.set_mtime(mtime);
        builder.append(&header, data)?;
        Ok(builder.into_inner()?)
    }

    #[test]
    fn archive_identity_frames_members_and_ignores_timestamps() -> anyhow::Result<()> {
        let path = Path::new("/lib.a");
        let digest = |name: &[u8], data: &[u8], time| -> anyhow::Result<String> {
            Ok(super::hash_regular_archive(path, &archive_bytes(name, data, time)?)?.digest)
        };
        assert_eq!(digest(b"a", b"bc", 1)?, digest(b"a", b"bc", 2)?);
        assert_ne!(digest(b"a", b"bc", 1)?, digest(b"ab", b"c", 1)?);
        Ok(())
    }

    #[test]
    fn canonical_archive_preserves_symbol_targets_and_member_order() -> Result<()> {
        let members: [GnuMember<'_>; 3] = [
            (b"a-very-long-object-name.o", Cow::Borrowed(b"first")),
            (b"a-very-long-object-name.o", Cow::Borrowed(b"second")),
            (b"other.o", Cow::Borrowed(b"third")),
        ];
        let symbols: &[(&[u8], usize)] = &[(b"same", 0), (b"same", 1), (b"other", 2)];
        let bytes = write_gnu_archive(&members, Some(symbols))?;
        let archive = ArchiveFile::parse(bytes.as_slice())?;
        let index = archive.symbols()?.context("missing symbol index")?;
        for (symbol, (expected_name, ordinal)) in index.zip(symbols) {
            let symbol = symbol?;
            assert_eq!(symbol.name(), *expected_name);
            let member = archive.member(symbol.offset())?;
            assert_eq!(member.name(), members[*ordinal].0);
            assert_eq!(member.data(bytes.as_slice())?, members[*ordinal].1.as_ref());
        }
        let mut modified = bytes.clone();
        for (offset, _) in archive_header_ranges(&bytes).context("invalid headers")? {
            modified[offset + 16..offset + 28].copy_from_slice(b"123456      ");
        }
        let path = Path::new("/lib.a");
        assert_eq!(canonical_gnu_archive(path, &modified)?, Some(bytes.clone()));
        assert_eq!(canonical_gnu_archive(path, &bytes)?, Some(bytes.clone()));
        assert_ne!(
            write_gnu_archive(&members, Some(&[(b"same", 1), (b"same", 0), (b"other", 2)]))?,
            bytes
        );
        Ok(())
    }

    #[test]
    fn packed_archives_normalize_only_unobserved_serialization() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("libprobe.a");
        let first = archive_bytes(b"probe.o", b"object", 100)?;
        let second = archive_bytes(b"probe.o", b"object", 200)?;
        fs::write(&path, first)?;
        let normalized = hash_archive(&path, None, ArchiveUse::Packed, true)?;
        let observed = hash_archive(&path, None, ArchiveUse::Packed, false)?;
        fs::write(&path, second)?;
        let normalized_again = hash_archive(&path, None, ArchiveUse::Packed, true)?;
        assert_eq!(normalized.digest, normalized_again.digest);
        assert_eq!(normalized.generated, normalized_again.generated);
        assert_ne!(
            observed.digest,
            hash_archive(&path, None, ArchiveUse::Packed, false)?.digest
        );
        Ok(())
    }

    #[test]
    fn fat_archive_identity_selects_the_compiler_architecture() -> anyhow::Result<()> {
        use object::macho::{CPU_TYPE_ARM64, CPU_TYPE_X86_64, FAT_MAGIC};
        let fat = |arm: &[u8]| -> anyhow::Result<Vec<u8>> {
            let x86 = archive_bytes(b"x86.o", b"x86 bytes", 0)?;
            let arm = archive_bytes(b"arm.o", arm, 0)?;
            let mut output = Vec::new();
            output.extend(FAT_MAGIC.to_be_bytes());
            output.extend(2u32.to_be_bytes());
            let mut offset = 48u32;
            for (cpu, bytes) in [(CPU_TYPE_X86_64.0, &x86), (CPU_TYPE_ARM64.0, &arm)] {
                let size = u32::try_from(bytes.len())?;
                for field in [cpu, 0, offset, size, 0] {
                    output.extend(field.to_be_bytes());
                }
                offset += size;
            }
            output.extend(x86);
            output.extend(arm);
            Ok(output)
        };
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("fat.a");
        std::fs::write(&path, fat(b"old arm")?)?;
        let x86 = super::hash_archive(
            &path,
            Some(object::Architecture::X86_64),
            super::ArchiveUse::Members,
            false,
        )?
        .digest;
        let arm = super::hash_archive(
            &path,
            Some(object::Architecture::Aarch64),
            super::ArchiveUse::Members,
            false,
        )?
        .digest;
        let all = super::hash_archive(&path, None, super::ArchiveUse::Members, false)?.digest;
        std::fs::write(&path, fat(b"new arm")?)?;
        assert_eq!(
            x86,
            super::hash_archive(
                &path,
                Some(object::Architecture::X86_64),
                super::ArchiveUse::Members,
                false
            )?
            .digest
        );
        assert_ne!(
            arm,
            super::hash_archive(
                &path,
                Some(object::Architecture::Aarch64),
                super::ArchiveUse::Members,
                false
            )?
            .digest
        );
        assert_ne!(
            all,
            super::hash_archive(&path, None, super::ArchiveUse::Members, false)?.digest
        );
        Ok(())
    }

    #[test]
    fn thin_archive_identity_reads_external_member_bytes() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let archive_path = temp.path().join("thin.a");
        let member = temp.path().join("member.o");
        // A GNU thin archive stores a member header but no inline member body.
        let mut thin = b"!<thin>\n".to_vec();
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            "member.o/", 0, 0, 0, "644", 3
        );
        thin.extend(header.as_bytes());
        std::fs::write(&archive_path, &thin)?;
        std::fs::write(&member, b"old")?;
        let first = super::hash_archive(&archive_path, None, super::ArchiveUse::Members, false)?;
        assert_eq!(first.external_members.len(), 1);
        assert_eq!(first.external_members[0].path, member);
        assert_eq!(
            first.digest,
            super::hash_regular_archive(&archive_path, &archive_bytes(b"member.o", b"old", 0)?,)?
                .digest
        );
        let packed = hash_archive(&archive_path, None, ArchiveUse::Packed, true)?;
        let bytes = packed
            .generated
            .context("thin archive must be materialized")?;
        let archive = ArchiveFile::parse(bytes.as_slice())?;
        assert!(!archive.is_thin());
        assert_eq!(
            archive
                .members()
                .next()
                .context("missing member")??
                .data(bytes.as_slice())?,
            b"old"
        );
        std::fs::write(&member, b"new")?;
        assert_ne!(
            packed.digest,
            hash_archive(&archive_path, None, ArchiveUse::Packed, true)?.digest
        );
        let second = super::hash_archive(&archive_path, None, super::ArchiveUse::Members, false)?;
        assert_ne!(first.digest, second.digest);
        assert_eq!(std::fs::read(&archive_path)?, thin);
        std::fs::remove_file(member)?;
        assert!(
            super::hash_archive(&archive_path, None, super::ArchiveUse::Members, false).is_err()
        );
        Ok(())
    }
}
