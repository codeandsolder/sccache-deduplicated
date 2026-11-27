//! A content identity shared by Cargo's build script and the package verifier.
use sha2::{Digest, Sha256};
use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
};

const INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "src",
    "crates/build-runtime/Cargo.toml",
    "crates/build-runtime/src",
    "crates/cluster-identity/Cargo.toml",
    "crates/cluster-identity/src",
    "crates/peer-identity/Cargo.toml",
    "crates/peer-identity/src",
    "crates/scheduler-dashboard/Cargo.toml",
    "crates/scheduler-dashboard/build.rs",
    "crates/scheduler-dashboard/src",
    "scripts/build-scheduler-dashboard.sh",
    "scripts/publish-dashboard-assets.sh",
    "contrib/codeandsolder/release-protocol.env",
];

fn collect(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    let kind = fs::symlink_metadata(path)?.file_type();
    if kind.is_dir() {
        for entry in fs::read_dir(path)? {
            collect(&entry?.path(), files)?;
        }
    } else if kind.is_file() {
        files.push(path.to_owned());
    } else {
        return Err(io::Error::other(format!(
            "non-regular build input: {}",
            path.display()
        )));
    }
    Ok(())
}

fn inputs(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in INPUTS {
        collect(&root.join(input), &mut files)?;
    }
    files.sort_unstable();
    Ok(files)
}

pub fn generation(root: &Path) -> io::Result<String> {
    let mut digest = Sha256::new();
    for file in inputs(root)? {
        let relative = file.strip_prefix(root).map_err(io::Error::other)?;
        let name = relative
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 build input"))?
            .replace('\\', "/");
        let bytes = fs::read(file)?;
        // Length framing prevents ambiguities between file names and contents.
        digest.update(
            u64::try_from(name.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        );
        digest.update(name.as_bytes());
        digest.update(
            u64::try_from(bytes.len())
                .map_err(io::Error::other)?
                .to_le_bytes(),
        );
        digest.update(bytes);
    }
    let mut result = String::from("sccache-dashboard-generation-v1:");
    for byte in digest.finalize() {
        write!(result, "{byte:02x}").map_err(io::Error::other)?;
    }
    Ok(result)
}
