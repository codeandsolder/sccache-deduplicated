//! Freshness is a property of content, never filesystem times. A directory
//! digest frames each relative name, type, permissions and content digest.
use anyhow::{Context, Result, ensure};
use sccache_build::ContentId;
use std::{
    fs,
    io::{self},
    path::Path,
};

pub fn content_file(path: &Path) -> Result<ContentId> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "not a regular file: {}",
        path.display()
    );
    let mut hasher = blake3::Hasher::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(ContentId(*hasher.finalize().as_bytes()))
}

fn frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

pub fn content_tree(root: &Path) -> Result<ContentId> {
    fn walk(path: &Path, root: &Path, hash: &mut blake3::Hasher) -> Result<()> {
        let meta = fs::symlink_metadata(path)?;
        frame(
            hash,
            path.strip_prefix(root)?.as_os_str().as_encoded_bytes(),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            hash.update(&(meta.permissions().mode() & 0o7777).to_le_bytes());
        }
        if meta.is_symlink() {
            hash.update(b"L");
            frame(hash, fs::read_link(path)?.as_os_str().as_encoded_bytes());
        } else if meta.is_file() {
            hash.update(b"F");
            hash.update(&content_file(path)?.0);
        } else if meta.is_dir() {
            hash.update(b"D");
            let mut entries = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
            entries.sort_by_key(fs::DirEntry::file_name);
            for entry in entries {
                walk(&entry.path(), root, hash)?;
            }
        } else {
            anyhow::bail!("unsupported source entry {}", path.display());
        }
        Ok(())
    }
    let mut hash = blake3::Hasher::new_derive_key("sccache rust-build content tree v1");
    walk(root, root, &mut hash)?;
    Ok(ContentId(*hash.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn same_length_same_timestamp_replacement_changes_identity() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("input");
        fs::write(&path, "abc")?;
        let original = fs::metadata(&path)?.modified()?;
        let before = content_tree(dir.path())?;
        fs::write(&path, "xyz")?;
        fs::File::open(&path)?.set_times(fs::FileTimes::new().set_modified(original))?;
        assert_ne!(before, content_tree(dir.path())?);
        fs::write(&path, "abc")?;
        assert_eq!(before, content_tree(dir.path())?);
        Ok(())
    }
}
