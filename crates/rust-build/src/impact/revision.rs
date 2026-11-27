//! Content-verified repository snapshots for revision-relative coverage.
//! Git's index stat cache is deliberately not consulted for freshness.
//! The HEAD tree supplies expected blob identities and path modes; current
//! file bytes and symlink spellings are independently hashed.
use anyhow::{Context, Result, ensure};
use sccache_build::ContentId;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEvidence {
    pub path: String,
    pub mode: u32,
    pub content: Option<ContentId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionSnapshot {
    /// None for an unborn repository. Dirty trees are not eligible for
    /// anchoring coverage ranges to this commit.
    pub head: Option<String>,
    pub tree: ContentId,
    pub clean: bool,
    pub files: Vec<FileEvidence>,
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .with_context(|| format!("git {} in {}", args.join(" "), root.display()))?;
    ensure!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

fn os_path(bytes: Vec<u8>) -> Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(OsString::from(String::from_utf8(bytes)?)))
    }
}

pub fn git_root(cwd: &Path) -> Result<PathBuf> {
    let mut raw = git(
        cwd,
        &["rev-parse", "--path-format=absolute", "--show-toplevel"],
    )?;
    ensure!(raw.pop() == Some(b'\n'), "unterminated Git root");
    let path = os_path(raw)?;
    ensure!(path.is_absolute(), "Git root is not absolute");
    Ok(path.canonicalize()?)
}

fn name(bytes: &[u8]) -> Result<String> {
    // Coverage filenames and JSON reports use UTF-8. Refuse rather than
    // silently dropping a repository file which might be an input.
    let name = std::str::from_utf8(bytes)?;
    let path = Path::new(name);
    ensure!(
        !name.is_empty() && path.components().all(|c| matches!(c, Component::Normal(_))),
        "invalid Git path"
    );
    Ok(name.to_owned())
}

#[derive(Clone, Copy)]
enum ObjectFormat {
    Sha1,
    Sha256,
}

enum ObjectHasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}
impl ObjectHasher {
    fn new(format: ObjectFormat, size: u64) -> Self {
        let header = format!("blob {size}\0");
        match format {
            ObjectFormat::Sha1 => {
                let mut h = sha1::Sha1::new();
                h.update(header);
                Self::Sha1(h)
            }
            ObjectFormat::Sha256 => {
                let mut h = sha2::Sha256::new();
                h.update(header);
                Self::Sha256(h)
            }
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }
    fn finish(self) -> String {
        fn hex(bytes: &[u8]) -> String {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut result = String::with_capacity(bytes.len() * 2);
            for &byte in bytes {
                result.push(char::from(DIGITS[usize::from(byte >> 4)]));
                result.push(char::from(DIGITS[usize::from(byte & 15)]));
            }
            result
        }
        match self {
            Self::Sha1(h) => hex(&h.finalize()),
            Self::Sha256(h) => hex(&h.finalize()),
        }
    }
}

struct Hashes {
    git: ObjectHasher,
    content: blake3::Hasher,
    size: u64,
}
impl Write for Hashes {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.git.update(buf);
        self.content.update(buf);
        self.size = self
            .size
            .checked_add(buf.len() as u64)
            .ok_or_else(|| std::io::Error::other("source size overflow"))?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn blob(format: ObjectFormat, size: u64, mut reader: impl Read) -> Result<(ContentId, String)> {
    let mut hashes = Hashes {
        git: ObjectHasher::new(format, size),
        content: blake3::Hasher::new(),
        size: 0,
    };
    std::io::copy(&mut reader, &mut hashes)?;
    ensure!(hashes.size == size, "source size changed while hashing");
    Ok((
        ContentId(*hashes.content.finalize().as_bytes()),
        hashes.git.finish(),
    ))
}

fn current(
    root: &Path,
    path: &str,
    format: ObjectFormat,
    depth: usize,
) -> Result<(FileEvidence, Option<String>, bool)> {
    let full = root.join(path);
    let meta = match fs::symlink_metadata(&full) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                FileEvidence {
                    path: path.into(),
                    mode: 0,
                    content: None,
                },
                None,
                false,
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let (mode, content, oid, valid) = if meta.is_symlink() {
        let link = fs::read_link(&full)?;
        let bytes = link.as_os_str().as_encoded_bytes();
        let (content, oid) = blob(format, bytes.len() as u64, bytes)?;
        (0o120000, content, Some(oid), true)
    } else if meta.is_file() {
        #[cfg(unix)]
        let executable = {
            use std::os::unix::fs::PermissionsExt as _;
            meta.permissions().mode() & 0o111 != 0
        };
        #[cfg(not(unix))]
        let executable = false;
        let file = fs::File::open(&full)?;
        let (content, oid) = blob(format, file.metadata()?.len(), file)?;
        (
            if executable { 0o100755 } else { 0o100644 },
            content,
            Some(oid),
            true,
        )
    } else if meta.is_dir() {
        // Gitlinks carry a commit, not a blob. Include the submodule's own
        // working-tree content, not merely its recorded checkout revision.
        ensure!(depth < 64, "nested Git repository limit exceeded");
        let nested = git_root(&full)?;
        ensure!(
            nested == full.canonicalize()?,
            "Git directory entry is not a nested repository"
        );
        let nested = capture(&nested, depth + 1)?;
        (0o160000, nested.tree, nested.head, nested.clean)
    } else {
        anyhow::bail!("unsupported repository entry {}", full.display())
    };
    Ok((
        FileEvidence {
            path: path.into(),
            mode,
            content: Some(content),
        },
        oid,
        valid,
    ))
}

fn capture(root: &Path, depth: usize) -> Result<RevisionSnapshot> {
    let format =
        match std::str::from_utf8(&git(root, &["rev-parse", "--show-object-format"])?)?.trim() {
            "sha1" => ObjectFormat::Sha1,
            "sha256" => ObjectFormat::Sha256,
            _ => anyhow::bail!("unsupported Git object format"),
        };
    // --verify with a missing HEAD is valid for an unborn branch. A broken
    // object database must not be interpreted as a clean empty repository.
    let head = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;
    let head = if head.status.success() {
        Some(String::from_utf8(head.stdout)?.trim().to_owned())
    } else {
        ensure!(
            Command::new("git")
                .current_dir(root)
                .args(["symbolic-ref", "-q", "HEAD"])
                .status()?
                .success(),
            "cannot resolve Git HEAD"
        );
        None
    };
    let mut expected = BTreeMap::<String, (u32, String)>::new();
    if let Some(head) = &head {
        for entry in git(root, &["ls-tree", "-r", "-z", "--full-tree", head])?
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
        {
            let tab = entry
                .iter()
                .position(|b| *b == b'\t')
                .context("invalid ls-tree entry")?;
            let mut fields = std::str::from_utf8(&entry[..tab])?.split_whitespace();
            let mode = u32::from_str_radix(fields.next().context("missing Git mode")?, 8)?;
            let kind = fields.next().context("missing Git object type")?;
            let oid = fields.next().context("missing Git object ID")?.to_owned();
            ensure!(
                fields.next().is_none() && matches!(kind, "blob" | "commit"),
                "invalid Git tree entry"
            );
            ensure!(
                expected
                    .insert(name(&entry[tab + 1..])?, (mode, oid))
                    .is_none(),
                "duplicate Git tree path"
            );
        }
    }
    let raw = git(
        root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    let mut paths = expected.keys().cloned().collect::<BTreeSet<_>>();
    for entry in raw.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        // Untracked nested repositories are reported with a trailing slash.
        let entry = entry.strip_suffix(b"/").unwrap_or(entry);
        paths.insert(name(entry)?);
    }
    let mut clean = head.is_some();
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let (file, oid, valid) = current(root, &path, format, depth)?;
        clean &= valid
            && expected
                .get(&path)
                .is_some_and(|(mode, hash)| *mode == file.mode && oid.as_ref() == Some(hash));
        files.push(file);
    }
    // A snapshot identity includes all observed names, modes and actual bytes.
    // Git's commit hash is an anchor, not a substitute for checking those bytes.
    let tree = ContentId::of(&serde_json::to_vec(&files)?);
    Ok(RevisionSnapshot {
        head,
        tree,
        clean,
        files,
    })
}

impl RevisionSnapshot {
    pub fn capture(root: &Path) -> Result<Self> {
        ensure!(
            root == git_root(root)?,
            "snapshot must start at the Git root"
        );
        capture(root, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_head_content_and_untracked_files_are_verified() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().canonicalize()?;
        git(&root, &["init", "-q"])?;
        git(&root, &["config", "user.name", "test"])?;
        git(&root, &["config", "user.email", "test@example.invalid"])?;
        fs::write(root.join("source.rs"), b"aaaa")?;
        git(&root, &["add", "source.rs"])?;
        git(&root, &["commit", "-qm", "baseline"])?;
        let before = RevisionSnapshot::capture(&root)?;
        assert!(before.clean);
        let source = root.join("source.rs");
        let modified = fs::metadata(&source)?.modified()?;
        fs::write(&source, b"bbbb")?;
        fs::File::open(&source)?.set_modified(modified)?;
        // Even explicitly telling Git to trust the index cannot fool capture.
        git(&root, &["update-index", "--assume-unchanged", "source.rs"])?;
        let after = RevisionSnapshot::capture(&root)?;
        assert!(!after.clean);
        assert_ne!(before.tree, after.tree);
        fs::write(&source, b"aaaa")?;
        assert_eq!(before, RevisionSnapshot::capture(&root)?);
        fs::write(root.join("new.txt"), b"fixture")?;
        let added = RevisionSnapshot::capture(&root)?;
        assert!(!added.clean);
        assert_eq!(added.files.len(), 2);
        Ok(())
    }
}
