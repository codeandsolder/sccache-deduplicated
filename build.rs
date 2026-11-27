//! Embed the source revision without depending on deployment environment.
//! Git archives carry the commit through export-subst; live checkouts resolve
//! HEAD and track its ref even when only the commit metadata changes.

#[path = "crates/scheduler-dashboard/src/fingerprint.rs"]
mod fingerprint;

use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).ok())
        .flatten()
        .map(|value| value.trim().to_owned())
}

fn valid_revision(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn watch(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
}

fn git_path(root: &Path, name: &str, watch_parent: bool) {
    if let Some(path) = git(
        root,
        &["rev-parse", "--path-format=absolute", "--git-path", name],
    ) {
        let path = PathBuf::from(path);
        if path.exists() {
            watch(&path);
        } else if watch_parent
            && let Some(parent) = path.ancestors().skip(1).find(|parent| parent.exists())
        {
            // A new loose ref can replace a packed ref.
            watch(parent);
        }
    }
}

fn revision(root: &Path) -> io::Result<String> {
    let archive_path = root.join("source-revision");
    watch(&archive_path);
    // Git archive expands the placeholder. A checkout retains it literally.
    let archive = fs::read_to_string(&archive_path)?;
    if valid_revision(archive.trim()) {
        return Ok(archive.trim().to_owned());
    }
    let Some(top) = git(root, &["rev-parse", "--show-toplevel"]) else {
        return Ok("unknown".into());
    };
    if Path::new(&top).canonicalize()? != root {
        return Ok("unknown".into());
    }
    for name in ["HEAD", "index", "packed-refs"] {
        git_path(root, name, false);
    }
    if let Some(reference) = git(root, &["symbolic-ref", "-q", "HEAD"]) {
        git_path(root, &reference, true);
    }
    let Some(sha) = git(root, &["rev-parse", "--verify", "HEAD"]).filter(|sha| valid_revision(sha))
    else {
        return Ok("unknown".into());
    };
    let mut args = vec![
        "--no-optional-locks",
        "status",
        "--porcelain",
        "--untracked-files=normal",
        "--",
        "source-revision",
    ];
    args.extend_from_slice(fingerprint::INPUTS);
    let dirty = git(root, &args).is_none_or(|status| !status.is_empty());
    if dirty {
        let digest = fingerprint::generation(root)?;
        let digest = digest
            .rsplit_once(':')
            .ok_or_else(|| io::Error::other("invalid source fingerprint"))?
            .1;
        Ok(format!("{sha}-dirty-{digest}"))
    } else {
        Ok(sha)
    }
}

fn main() -> io::Result<()> {
    let root = std::env::current_dir()?.canonicalize()?;
    for path in fingerprint::INPUTS {
        watch(&root.join(path));
    }
    let output = PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| io::Error::other("missing Cargo output directory"))?,
    );
    let revision = revision(&root)?;
    fs::write(output.join("source-revision"), &revision)?;
    fs::write(
        output.join("build-version"),
        format!("{} ({revision})", env!("CARGO_PKG_VERSION")),
    )
}
