//! Original system package discovery from pacman's installed ownership and
//! repository metadata. The real compiler input bytes still determine action
//! identity; repository metadata is only an optional transport optimization.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::File,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{Context, Result, bail, ensure};
use sccache::{
    build_runtime::{PackageCompression, PackageIdentity, PackageSource},
    dist::native::{NativeCacheClient, PackageLocator, map_packages},
};
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Provisioned {
    name: String,
    version: String,
    source: PackageSource,
    tree: sccache::build_runtime::TreeId,
    reused: bool,
    transfer: &'static str,
}

#[derive(Debug, Serialize)]
pub(super) struct SyncReport {
    selected_files: usize,
    owned_packages: usize,
    provisioned: Vec<Provisioned>,
    skipped: BTreeMap<String, String>,
}

#[derive(Debug)]
struct Candidate {
    name: String,
    version: String,
    locator: PackageLocator,
    filename: String,
}

fn pacman(args: &[&OsStr]) -> Result<Output> {
    Command::new("/usr/bin/pacman")
        .args(args)
        .output()
        .context("query pacman package database")
}

fn output_success(args: &[&OsStr]) -> Result<String> {
    let output = pacman(args)?;
    ensure!(
        output.status.success(),
        "pacman query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn installed_versions(names: &BTreeSet<String>) -> Result<BTreeMap<String, String>> {
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut args = vec![OsStr::new("-Q"), OsStr::new("--")];
    args.extend(names.iter().map(OsStr::new));
    let output = output_success(&args)?;
    let mut versions = BTreeMap::new();
    for line in output.lines() {
        let (name, version) = line
            .split_once(' ')
            .context("pacman installed package has no version")?;
        ensure!(
            names.contains(name)
                && versions
                    .insert(name.to_owned(), version.to_owned())
                    .is_none(),
            "unexpected or duplicated installed package"
        );
    }
    ensure!(
        versions.len() == names.len(),
        "incomplete pacman installed package inventory"
    );
    Ok(versions)
}

fn owners(paths: &[PathBuf]) -> Result<(BTreeSet<String>, BTreeMap<String, String>)> {
    ensure!(!paths.is_empty(), "no installed paths selected");
    let mut args = vec![OsStr::new("-Qqo"), OsStr::new("--")];
    args.extend(paths.iter().map(|path| path.as_os_str()));
    let output = pacman(&args)?;
    let mut skipped = BTreeMap::new();
    let owned = if output.status.success() {
        String::from_utf8(output.stdout)?
    } else {
        // Distinguish unowned paths from a broken package database. Normally
        // one batch query covers hundreds of files; only failed batches need
        // individual ownership queries.
        let mut result = String::new();
        for path in paths {
            let query = pacman(&[OsStr::new("-Qqo"), OsStr::new("--"), path.as_os_str()])?;
            if query.status.success() {
                result.push_str(&String::from_utf8(query.stdout)?);
            } else {
                skipped.insert(
                    path.display().to_string(),
                    String::from_utf8_lossy(&query.stderr).trim().to_owned(),
                );
            }
        }
        result
    };
    let names = owned
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    Ok((names, skipped))
}

fn parse_repository_record(line: &str) -> Result<Candidate> {
    let fields: Vec<_> = line.split('|').collect();
    ensure!(fields.len() == 6, "unexpected pacman repository format");
    let [name, version, architecture, digest, repo, url] = fields[..] else {
        unreachable!("field count validated");
    };
    let parsed = reqwest::Url::parse(url).context("invalid repository package URL")?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https" | "file")
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "unsupported repository package URL"
    );
    let segment = parsed
        .path_segments()
        .and_then(|segments| segments.last())
        .context("repository package URL missing filename")?;
    let filename = percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .context("non-UTF-8 package archive name")?
        .into_owned();
    // Pacman package filenames omit an optional epoch in the installed
    // version, but retain the pkgver-pkgrel and architecture exactly.
    let archive_version = version.rsplit_once(':').map_or(version, |(_, value)| value);
    let expected_prefix = format!("{name}-{archive_version}-{architecture}.pkg.tar");
    ensure!(
        filename
            .strip_prefix(&expected_prefix)
            .is_some_and(|suffix| matches!(suffix, ".zst" | ".xz" | ".gz" | ""))
            && !name.is_empty()
            && !version.is_empty(),
        "repository metadata package does not match its URL"
    );
    let compression = if filename.ends_with(".pkg.tar.zst") {
        PackageCompression::Zstd
    } else if filename.ends_with(".pkg.tar.xz") {
        PackageCompression::Xz
    } else if filename.ends_with(".pkg.tar.gz") {
        PackageCompression::Gzip
    } else if filename.ends_with(".pkg.tar") {
        PackageCompression::Tar
    } else {
        bail!("unsupported original package extension");
    };
    let identity = PackageIdentity::from_sha256_hex(digest, compression)?;
    let locator = PackageLocator {
        identity,
        expected_size: None,
        upstream: repo.to_owned(),
        path: filename.clone(),
    };
    locator.validate()?;
    Ok(Candidate {
        name: name.to_owned(),
        version: version.to_owned(),
        locator,
        filename,
    })
}

fn candidates(
    versions: &BTreeMap<String, String>,
) -> Result<(Vec<Candidate>, BTreeMap<String, String>)> {
    let mut args = vec![
        OsStr::new("-Sp"),
        OsStr::new("--print-format"),
        OsStr::new("%n|%v|%a|%h|%r|%l"),
        OsStr::new("--"),
    ];
    args.extend(versions.keys().map(OsStr::new));
    let output = pacman(&args)?;
    let mut found = BTreeMap::new();
    let mut skipped = BTreeMap::new();
    // Pacman may return a partial successful listing when an installed
    // package is no longer in a configured sync repository. Never invent
    // a release checksum from a local filename.
    for line in String::from_utf8(output.stdout)?.lines() {
        let candidate = parse_repository_record(line)?;
        ensure!(
            versions.contains_key(&candidate.name),
            "unexpected pacman repository package"
        );
        let name = candidate.name.clone();
        let installed = &versions[&name];
        if candidate.version == *installed {
            ensure!(
                found.insert(name, candidate).is_none(),
                "ambiguous repository candidate"
            );
        } else {
            skipped.insert(
                name,
                format!(
                    "installed version {installed} differs from repository {}",
                    candidate.version
                ),
            );
        }
    }
    for name in versions.keys() {
        if !found.contains_key(name) {
            skipped.entry(name.clone()).or_insert_with(|| {
                format!("no matching installed release in synchronized pacman repositories: {name}")
            });
        }
    }
    if !output.status.success() && found.is_empty() && skipped.is_empty() {
        bail!(
            "pacman repository query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok((found.into_values().collect(), skipped))
}

fn provision_one(
    client: &NativeCacheClient,
    candidate: &Candidate,
    cache_dir: &Path,
) -> Result<Provisioned> {
    let locator = &candidate.locator;
    let (receipt, reused, transfer) =
        if let Some(receipt) = client.lookup_package(locator.identity)? {
            (receipt, true, "existing")
        } else {
            let archive = cache_dir.join(&candidate.filename);
            match File::open(&archive) {
                Ok(file) => {
                    let size = file.metadata()?.len();
                    let source = PackageSource {
                        identity: locator.identity,
                        size,
                    };
                    let receipt = client.import_package(source, file)?;
                    (receipt, false, "local-original")
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let acquired = client.acquire_package(locator)?;
                    (acquired.package, acquired.reused, "named-upstream")
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("open cached package {}", archive.display()));
                }
            }
        };
    ensure!(
        receipt.source.identity == locator.identity,
        "incorrect release provenance"
    );
    Ok(Provisioned {
        name: candidate.name.clone(),
        version: candidate.version.clone(),
        source: receipt.source,
        tree: receipt.tree,
        reused,
        transfer,
    })
}

/// Resolve selected installed paths to their owning packages, compare the
/// installed versions with trusted sync metadata and provision verified
/// originals. Partial ownership and obsolete repository versions are reported,
/// never substituted with guessed archive identities.
/// # Errors
/// Returns an error when the manager or cache service fails to provision an
/// eligible package. Non-owned and unavailable versions are reported.
pub(super) fn sync_packages(
    client: &NativeCacheClient,
    paths: &[PathBuf],
    cache_dir: &Path,
    jobs: NonZeroUsize,
) -> Result<SyncReport> {
    ensure!(
        cache_dir.is_absolute(),
        "pacman cache directory must be absolute"
    );
    let (names, mut skipped) = owners(paths)?;
    let versions = installed_versions(&names)?;
    let (packages, unavailable) = candidates(&versions)?;
    skipped.extend(unavailable);
    let mut provisioned = map_packages(&packages, jobs, |candidate| {
        provision_one(client, candidate, cache_dir)
    })?;
    provisioned.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(SyncReport {
        selected_files: paths.len(),
        owned_packages: names.len(),
        provisioned,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacman_release_parsing_rejects_ambiguous_or_untrusted_entries() -> Result<()> {
        let candidate = parse_repository_record(
            "gcc|16.2.1+r23+gd564253eb6c8-3|x86_64_v3|2057ff30fcabdf6a01093e5967d1a70c13554352eaf4d5b198d0feb3f50bf861|cachyos-v3|file:///var/cache/pacman/pkg/gcc-16.2.1+r23+gd564253eb6c8-3-x86_64_v3.pkg.tar.zst",
        )?;
        assert_eq!(candidate.name, "gcc");
        assert_eq!(candidate.locator.upstream, "cachyos-v3");
        assert_eq!(
            candidate.locator.identity.compression,
            PackageCompression::Zstd
        );
        for invalid in [
            "gcc|1|x86_64|bad|core|https://host/gcc-1-x86_64.pkg.tar.zst",
            "gcc|1|x86_64|2057ff30fcabdf6a01093e5967d1a70c13554352eaf4d5b198d0feb3f50bf861|core|https://host/gcc-2-x86_64.pkg.tar.zst",
            "gcc|1|x86_64|2057ff30fcabdf6a01093e5967d1a70c13554352eaf4d5b198d0feb3f50bf861|../bad|https://host/gcc-1-x86_64.pkg.tar.zst",
            "gcc|1|x86_64|2057ff30fcabdf6a01093e5967d1a70c13554352eaf4d5b198d0feb3f50bf861|core|https://host/gcc-1-x86_64.pkg.tar.bad",
        ] {
            assert!(parse_repository_record(invalid).is_err());
        }
        let epoch = parse_repository_record(
            "gcc|1:16.2.1+r23+gd564253eb6c8-3|x86_64_v3|2057ff30fcabdf6a01093e5967d1a70c13554352eaf4d5b198d0feb3f50bf861|cachyos-v3|https://mirror.example/gcc-16.2.1+r23+gd564253eb6c8-3-x86_64_v3.pkg.tar.zst",
        )?;
        assert_eq!(epoch.version, "1:16.2.1+r23+gd564253eb6c8-3");
        let escaped = parse_repository_record(
            "gcc|16.2.1+r23+gd564253eb6c8-3|x86_64_v3|2057ff30fcabdf6a01093e5967d1a70c13554352eaf4d5b198d0feb3f50bf861|cachyos-v3|https://mirror.example/gcc-16.2.1%2Br23%2Bgd564253eb6c8-3-x86_64_v3.pkg.tar.zst",
        )?;
        assert_eq!(escaped.filename, candidate.filename);
        Ok(())
    }
}
