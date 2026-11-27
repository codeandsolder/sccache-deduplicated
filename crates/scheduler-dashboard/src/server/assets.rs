//! Verified, immutable in-memory generation. A directory replacement after
//! startup cannot switch the assets served by a running scheduler.
use anyhow::{Context, Result, ensure};
use axum::{
    body::Bytes,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

const MANIFEST: &str = "SHA256SUMS";
const WASM: &str = "sccache-dashboard_bg.wasm";
const REQUIRED: &[&str] = &["sccache-dashboard.js", WASM, "sccache-dashboard.css"];
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 1024;

#[derive(Clone, Default)]
pub(super) struct Assets(Arc<BTreeMap<String, Bytes>>);

fn collect(root: &Path, path: &Path, files: &mut BTreeMap<String, PathBuf>) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect(root, &path, files)?;
        } else {
            ensure!(
                kind.is_file(),
                "nonregular dashboard asset: {}",
                path.display()
            );
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 dashboard asset")?;
            ensure!(
                !name.chars().any(|c| c.is_control() || c == '\\'),
                "invalid dashboard asset name"
            );
            ensure!(files.len() < MAX_FILES, "too many dashboard assets");
            files.insert(name.to_owned(), path);
        }
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    ensure!(
        u64::try_from(bytes.len())? <= limit,
        "dashboard asset budget exceeded"
    );
    Ok(bytes)
}

impl Assets {
    pub(super) fn load(directory: &Path) -> Result<Self> {
        Self::load_generation(directory, crate::GENERATION)
    }

    fn load_generation(directory: &Path, expected: &str) -> Result<Self> {
        let root = directory.canonicalize()?;
        let mut files = BTreeMap::new();
        collect(&root, &root, &mut files)?;
        let manifest = files
            .remove(MANIFEST)
            .context("missing dashboard SHA256SUMS")?;
        let manifest = String::from_utf8(read_limited(&manifest, 256 * 1024)?)?;
        let mut verified = BTreeMap::new();
        let mut remaining = MAX_BYTES;
        for line in manifest.lines() {
            let (hash, name) = line
                .split_once("  ./")
                .context("invalid dashboard manifest entry")?;
            let path = files
                .remove(name)
                .with_context(|| format!("unexpected or duplicate dashboard asset: {name}"))?;
            let bytes = read_limited(&path, remaining)?;
            remaining -= u64::try_from(bytes.len())?;
            ensure!(
                hash == sha256(&bytes),
                "dashboard asset checksum mismatch: {name}"
            );
            verified.insert(name.to_owned(), Bytes::from(bytes));
        }
        ensure!(files.is_empty(), "unlisted dashboard assets");
        for name in REQUIRED {
            ensure!(
                verified.get(*name).is_some_and(|bytes| !bytes.is_empty()),
                "missing dashboard asset: {name}"
            );
        }
        let wasm = &verified[WASM];
        ensure!(
            wasm.starts_with(b"\0asm\x01\0\0\0")
                && wasm
                    .windows(expected.len())
                    .any(|bytes| bytes == expected.as_bytes()),
            "dashboard WASM generation does not match scheduler"
        );
        Ok(Self(Arc::new(verified)))
    }

    pub(super) fn response(&self, name: &str) -> Response {
        let Some(bytes) = self.0.get(name) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let content_type = match Path::new(name).extension().and_then(|ext| ext.to_str()) {
            Some("js" | "mjs") => "text/javascript; charset=utf-8",
            Some("wasm") => "application/wasm",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            _ => "application/octet-stream",
        };
        ([(header::CONTENT_TYPE, content_type)], bytes.clone()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(directory: &Path, marker: &str) -> Result<()> {
        let wasm = [b"\0asm\x01\0\0\0".as_slice(), marker.as_bytes()].concat();
        for (name, bytes) in [
            (REQUIRED[0], b"js".as_slice()),
            (WASM, wasm.as_slice()),
            (REQUIRED[2], b"css".as_slice()),
        ] {
            fs::write(directory.join(name), bytes)?;
        }
        manifest(directory)
    }

    fn manifest(directory: &Path) -> Result<()> {
        use std::fmt::Write as _;
        let mut result = String::new();
        for name in REQUIRED {
            writeln!(
                result,
                "{}  ./{name}",
                sha256(&fs::read(directory.join(name))?)
            )?;
        }
        fs::write(directory.join(MANIFEST), result)?;
        Ok(())
    }

    #[test]
    fn generation_and_complete_checksums_are_required() -> Result<()> {
        let directory = tempfile::tempdir()?;
        fixture(directory.path(), "old generation")?;
        assert!(Assets::load(directory.path()).is_err());
        fixture(directory.path(), crate::GENERATION)?;
        let assets = Assets::load(directory.path())?;
        fs::write(directory.path().join(REQUIRED[0]), b"corrupt")?;
        assert!(Assets::load(directory.path()).is_err());
        assert_eq!(assets.0[REQUIRED[0]], Bytes::from_static(b"js"));
        fixture(directory.path(), crate::GENERATION)?;
        fs::write(directory.path().join("unlisted.js"), b"extra")?;
        assert!(Assets::load(directory.path()).is_err());
        Ok(())
    }
}
