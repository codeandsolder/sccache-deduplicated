//! Export an explicit destination CPU profile as compiler-specific flags.
//!
//! The profile is transport/configuration data. It must never be injected into
//! compilation cache keys: each cache key is owned by the individual compiler
//! invocation and its effective arguments.

use anyhow::{Context, Result, ensure};
use archspec::cpu::Microarchitecture;
use archspec::schema::{Compiler, CompilerSet, MicroarchitecturesSchema};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

const SCHEMA_VERSION: u32 = 1;

/// Normalize target triple architecture spelling into Archspec family names.
fn triple_cpu_family(triple: &str) -> &str {
    let arch = triple.split('-').next().unwrap_or_default();
    match arch {
        "powerpc" => "ppc",
        "powerpc64" => "ppc64",
        "powerpc64le" => "ppc64le",
        "powerpcle" => "ppcle",
        arch if arch.starts_with("arm") || arch.starts_with("thumb") => "arm",
        arch if arch.starts_with("riscv64") => "riscv64",
        arch if arch.starts_with('i') && arch.len() == 4 && arch.ends_with("86") => "x86",
        _ => arch,
    }
}

/// Target triple selects endianness. POWER CPU models in Archspec's ppc64
/// family also support ppc64le ABI targets.
fn matches_cpu_family(triple: &str, cpu_family: &str) -> bool {
    let target_family = triple_cpu_family(triple);
    target_family == cpu_family || (target_family == "ppc64le" && cpu_family == "ppc64")
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileOrigin {
    Detected,
    NamedModel,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DestinationProfile {
    pub schema_version: u32,
    pub origin: ProfileOrigin,
    pub target_triple: String,
    pub microarchitecture: String,
    pub vendor: String,
    pub features: Vec<String>,
}

impl DestinationProfile {
    /// Detect current CPU for the provided target triple.
    ///
    /// # Errors
    /// CPU detection fails or the target architecture is incompatible.
    pub fn capture(target_triple: &str) -> Result<Self> {
        let detected =
            archspec::cpu::host().map_err(|_| anyhow::anyhow!("cannot detect destination CPU"))?;
        Self::from_microarchitecture(target_triple, &detected, ProfileOrigin::Detected)
    }

    /// Define a destination CPU model independently of the build host.
    ///
    /// # Errors
    /// The CPU is unknown or the target architecture is incompatible.
    pub fn named(target_triple: &str, name: &str) -> Result<Self> {
        let cpu = Microarchitecture::known_targets()
            .get(name)
            .with_context(|| format!("unknown archspec CPU model {name}"))?;
        Self::from_microarchitecture(target_triple, cpu, ProfileOrigin::NamedModel)
    }

    fn from_microarchitecture(
        target_triple: &str,
        detected: &Microarchitecture,
        origin: ProfileOrigin,
    ) -> Result<Self> {
        ensure!(
            target_triple.split('-').count() >= 3,
            "expected a complete target triple, got {target_triple}"
        );
        let target_arch = triple_cpu_family(target_triple);
        ensure!(
            matches_cpu_family(target_triple, detected.family().name()),
            "target triple architecture {target_arch} differs from detected CPU family {}",
            detected.family().name()
        );
        let mut features: Vec<_> = detected.all_features().into_iter().collect();
        features.sort();
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            origin,
            target_triple: target_triple.to_owned(),
            microarchitecture: detected.name().to_owned(),
            vendor: detected.vendor().to_owned(),
            features,
        })
    }

    /// Resolve a requested CPU against a destination profile.
    ///
    /// # Errors
    /// The CPU is unknown, requires unavailable features or the profile is inconsistent.
    pub fn resolve(&self, requested: Option<&str>) -> Result<&'static Microarchitecture> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported CPU profile schema version {}",
            self.schema_version
        );
        ensure!(!self.target_triple.is_empty(), "missing target triple");
        let known = Microarchitecture::known_targets();
        let native = known.get(&self.microarchitecture).with_context(|| {
            format!(
                "archspec does not know captured CPU {}",
                self.microarchitecture
            )
        })?;
        ensure!(
            self.vendor == native.vendor(),
            "CPU vendor in profile differs from architecture database"
        );
        ensure!(
            matches_cpu_family(&self.target_triple, native.family().name()),
            "target triple architecture does not match captured CPU family"
        );
        let snapshot: std::collections::HashSet<_> = self.features.iter().cloned().collect();
        ensure!(
            snapshot.len() == self.features.len(),
            "duplicate CPU features in profile"
        );
        ensure!(
            snapshot.is_superset(&native.all_features()),
            "archspec's current model requires CPU features missing from the captured profile"
        );
        let selected = known
            .get(requested.unwrap_or(&self.microarchitecture))
            .with_context(|| {
                format!(
                    "unknown requested CPU architecture {}",
                    requested.unwrap_or(&self.microarchitecture)
                )
            })?;
        ensure!(
            selected.family().name() == native.family().name(),
            "requested CPU and captured CPU have different architecture families"
        );
        ensure!(
            snapshot.is_superset(&selected.all_features()),
            "requested CPU requires features absent from the captured destination"
        );
        ensure!(
            selected.vendor() == "generic" || selected.vendor() == native.vendor(),
            "requested CPU belongs to a different vendor"
        );
        Ok(selected)
    }

    /// Read an exported JSON destination CPU profile.
    ///
    /// # Errors
    /// The profile file cannot be read or decoded.
    pub fn read(path: &Path) -> Result<Self> {
        let input =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        serde_json::from_slice(&input).context("invalid CPU profile JSON")
    }

    /// Write the exported JSON destination CPU profile.
    ///
    /// # Errors
    /// The profile cannot be serialized or written.
    pub fn write(&self, path: &Path) -> Result<()> {
        let serialized = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, serialized).with_context(|| format!("cannot write {}", path.display()))
    }
}

fn numeric_components(value: &str) -> Result<Vec<u64>> {
    ensure!(!value.is_empty(), "empty compiler version");
    value
        .split('.')
        .map(|part| {
            ensure!(
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()),
                "invalid compiler version {value}"
            );
            part.parse::<u64>().context("compiler version overflow")
        })
        .collect()
}

fn numeric_cmp(left: &[u64], right: &[u64]) -> std::cmp::Ordering {
    left.iter()
        .copied()
        .chain(std::iter::repeat(0))
        .zip(right.iter().copied().chain(std::iter::repeat(0)))
        .take(left.len().max(right.len()))
        .find_map(|(l, r)| (l != r).then_some(l.cmp(&r)))
        .unwrap_or(std::cmp::Ordering::Equal)
}

fn version_in_range(version: &[u64], interval: &str) -> Result<bool> {
    let (minimum, maximum) = interval
        .split_once(':')
        .with_context(|| format!("invalid archspec compiler version interval {interval}"))?;
    let after_minimum = minimum.is_empty()
        || numeric_cmp(version, &numeric_components(minimum)?) != std::cmp::Ordering::Less;
    let before_maximum = maximum.is_empty()
        || numeric_cmp(version, &numeric_components(maximum)?) != std::cmp::Ordering::Greater;
    Ok(after_minimum && before_maximum)
}

fn compiler_entries(set: &CompilerSet) -> Vec<&Compiler> {
    match set {
        CompilerSet::Single(entry) => vec![entry],
        CompilerSet::Several(entries) => entries.iter().collect(),
    }
}

/// Resolve Archspec flags for a specific compiler family and version.
///
/// Never substitute another CPU model when the requested target is unsupported.
///
/// # Errors
/// The compiler version or the CPU/compiler mapping is unsupported.
pub fn c_compiler_flags(
    cpu: &Microarchitecture,
    compiler: &str,
    version: &str,
) -> Result<Vec<String>> {
    let numeric_version = numeric_components(version)?;
    let database = MicroarchitecturesSchema::schema();
    let family = database
        .microarchitectures
        .get(cpu.family().name())
        .with_context(|| format!("no archspec family definition for {}", cpu.family().name()))?;
    ensure!(
        family
            .compilers
            .as_ref()
            .is_some_and(|m| m.contains_key(compiler)),
        "archspec has no optimization mapping for {compiler} on {}",
        cpu.family().name()
    );
    let entry = database
        .microarchitectures
        .get(cpu.name())
        .and_then(|m| m.compilers.as_ref())
        .and_then(|m| m.get(compiler))
        .with_context(|| {
            format!(
                "{compiler} has no mapping for requested CPU {} (no implicit downgrade)",
                cpu.name()
            )
        })?;
    let mut selected = None;
    for mapping in compiler_entries(entry) {
        if version_in_range(&numeric_version, &mapping.versions)? {
            selected = Some(mapping);
            break;
        }
    }
    let flag_template = selected
        .with_context(|| format!("{compiler} {version} cannot compile for {}", cpu.name()))?;
    let cpu_name = flag_template.name.as_deref().unwrap_or_else(|| cpu.name());
    let expanded = flag_template.flags.replace("{name}", cpu_name);
    ensure!(
        !expanded.contains('{'),
        "unsupported archspec compiler flag placeholder {expanded}"
    );
    shlex::split(&expanded).with_context(|| format!("invalid compiler flag quoting: {expanded}"))
}

fn tool_output(compiler: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(compiler)
        .args(args)
        .output()
        .with_context(|| format!("unable to run {}", compiler.display()))?;
    ensure!(
        output.status.success(),
        "{} {:?} failed: {}",
        compiler.display(),
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("compiler emitted non-UTF8 output")
}

fn compiler_version(compiler: &Path, family: &str) -> Result<String> {
    let output = if family == "gcc" {
        tool_output(compiler, &["-dumpfullversion"])?
            .trim()
            .to_owned()
    } else {
        let output = tool_output(compiler, &["--version"])?;
        output
            .split_whitespace()
            .skip_while(|part| *part != "version")
            .nth(1)
            .with_context(|| format!("unable to extract {family} compiler version"))?
            .to_owned()
    };
    let numeric = output.trim_end_matches(|ch: char| !ch.is_ascii_digit());
    numeric_components(numeric)?;
    Ok(numeric.to_owned())
}

/// Select explicit C compiler flags from a real compiler binary.
///
/// # Errors
/// The compiler cannot be probed or is incompatible with the destination.
pub fn selected_c_flags(
    profile: &DestinationProfile,
    target_cpu: Option<&str>,
    family: &str,
    compiler: &Path,
) -> Result<Vec<String>> {
    ensure!(
        ["gcc", "clang"].contains(&family),
        "unsupported compiler family {family}"
    );
    let cpu = profile.resolve(target_cpu)?;
    let version = compiler_version(compiler, family)?;
    c_compiler_flags(cpu, family, &version)
}

/// Generate an explicit Rust CPU target for a compiler binary.
///
/// # Errors
/// Rustc cannot be probed or does not support the destination CPU.
pub fn rustc_flags(
    profile: &DestinationProfile,
    target_cpu: Option<&str>,
    compiler: &Path,
) -> Result<Vec<String>> {
    let cpu = profile.resolve(target_cpu)?;
    let supported = tool_output(
        compiler,
        &["--print", "target-cpus", "--target", &profile.target_triple],
    )?;
    let supported: std::collections::HashSet<&str> = supported
        .lines()
        .filter(|line| line.starts_with("    "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    let mut alternatives = vec![cpu.name().to_owned(), cpu.name().replace('_', "-")];
    if let Some(compilers) = MicroarchitecturesSchema::schema()
        .microarchitectures
        .get(cpu.name())
        .and_then(|arch| arch.compilers.as_ref())
    {
        for family in ["clang", "gcc"] {
            if let Some(versions) = compilers.get(family) {
                let mut entries = compiler_entries(versions)
                    .into_iter()
                    .map(|entry| {
                        let (minimum, _) = entry
                            .versions
                            .split_once(':')
                            .context("invalid archspec version interval")?;
                        let lower_bound = if minimum.is_empty() {
                            vec![]
                        } else {
                            numeric_components(minimum)?
                        };
                        Ok((lower_bound, entry))
                    })
                    .collect::<Result<Vec<_>>>()?;
                entries.sort_by(|a, b| numeric_cmp(&b.0, &a.0));
                if let Some((_, latest)) = entries.first()
                    && let Some(name) = latest.name.as_ref()
                {
                    alternatives.push(name.clone());
                }
            }
        }
    }
    if let Some(rest) = cpu.name().strip_prefix("x86_64_v") {
        alternatives.push(format!("x86-64-v{rest}"));
    }
    let selected = alternatives.into_iter().find(|name| supported.contains(name.as_str()))
        .with_context(|| format!("rustc {} does not recognize Archspec CPU {} for target {}; use a compiler that supports the destination CPU", compiler.display(), cpu.name(), profile.target_triple))?;
    Ok(vec!["-C".to_owned(), format!("target-cpu={selected}")])
}

#[derive(Serialize)]
struct CargoTarget {
    rustflags: Vec<String>,
}
#[derive(Serialize)]
struct CargoConfig {
    target: BTreeMap<String, CargoTarget>,
}

/// Generate Cargo target-specific rustc configuration only.
///
/// # Errors
/// The CPU is unsupported or configuration serialization fails.
pub fn cargo_toml(
    profile: &DestinationProfile,
    target_cpu: Option<&str>,
    compiler: &Path,
) -> Result<String> {
    let rustflags = rustc_flags(profile, target_cpu, compiler)?;
    let mut targets = BTreeMap::new();
    targets.insert(profile.target_triple.clone(), CargoTarget { rustflags });
    Ok(toml::to_string_pretty(&CargoConfig { target: targets })?)
}

fn cmake_quote(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(';', "\\;")
}

#[must_use = "The CMake configuration must be used by the native build"]
pub fn cmake_toolchain(flags: &[String]) -> String {
    let flags = cmake_quote(&flags.join(" "));
    format!("set(CMAKE_C_FLAGS_INIT \"{flags}\")\nset(CMAKE_CXX_FLAGS_INIT \"{flags}\")\n")
}

fn meson_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

#[must_use = "The Meson configuration must be passed to the native build"]
pub fn meson_options(flags: &[String]) -> String {
    let flags = flags
        .iter()
        .map(|f| meson_quote(f))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[built-in options]\nc_args = [{flags}]\ncpp_args = [{flags}]\n")
}

pub fn show_flags(flags: &[String]) -> String {
    let mut result = String::new();
    for (index, flag) in flags.iter().enumerate() {
        if index != 0 {
            result.push(' ');
        }
        let _ = write!(
            &mut result,
            "{}",
            shlex::try_quote(flag).map_or_else(|_| flag.clone(), std::borrow::Cow::into_owned)
        );
    }
    result.push('\n');
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_profile(name: &str) -> Result<DestinationProfile> {
        DestinationProfile::named("x86_64-unknown-linux-gnu", name)
    }

    #[test]
    fn compiler_version_ranges_compare_numeric_components() -> Result<()> {
        assert!(version_in_range(
            &numeric_components("16.2.1")?,
            "4.1:16.3"
        )?);
        assert!(!version_in_range(&numeric_components("16.2.1")?, ":16.1")?);
        assert!(version_in_range(&numeric_components("16.2.1")?, "16.2:")?);
        assert!(version_in_range(&numeric_components("16")?, "16.0:16.0.0")?);
        assert!(numeric_components("16.two").is_err());
        Ok(())
    }

    #[test]
    fn gcc_and_clang_select_independent_flags() -> Result<()> {
        let profile = mock_profile("x86_64_v3")?;
        let cpu = profile.resolve(None)?;
        let gcc = c_compiler_flags(cpu, "gcc", "16.2.1")?;
        let clang = c_compiler_flags(cpu, "clang", "23.1.5")?;
        assert!(gcc.iter().any(|f| f == "-march=x86-64-v3"));
        assert!(clang.iter().any(|f| f == "-march=x86-64-v3"));
        assert!(c_compiler_flags(cpu, "gcc", "not-a-version").is_err());
        Ok(())
    }

    #[test]
    fn rust_flags_do_not_depend_on_gcc_flag_mappings() -> Result<()> {
        let profile = mock_profile("x86_64_v3")?;
        let cpu = profile.resolve(None)?;
        let cargo_before = cargo_toml(&profile, None, Path::new("rustc"))?;
        let gcc_old = c_compiler_flags(cpu, "gcc", "10.2.0")?;
        let gcc_new = c_compiler_flags(cpu, "gcc", "16.2.1")?;
        assert_ne!(gcc_old, gcc_new);
        assert_eq!(
            cargo_toml(&profile, None, Path::new("rustc"))?,
            cargo_before
        );
        assert!(!cargo_before.contains("-march="));
        Ok(())
    }

    #[test]
    fn reject_target_incompatible_with_captured_destination() -> Result<()> {
        let profile = mock_profile("x86_64_v2")?;
        assert!(profile.resolve(Some("x86_64_v4")).is_err());
        assert!(profile.resolve(Some("neoverse_n2")).is_err());
        Ok(())
    }

    #[test]
    fn cargo_flags_do_not_include_c_compiler_options() -> Result<()> {
        let profile = mock_profile("x86_64_v3")?;
        let doc = cargo_toml(&profile, None, Path::new("rustc"))?;
        assert!(doc.contains("target-cpu=x86-64-v3"));
        assert!(!doc.contains("-march="));
        assert!(!doc.contains("gcc"));
        Ok(())
    }

    #[test]
    fn named_profiles_can_target_a_cpu_absent_from_build_host() -> Result<()> {
        let profile = mock_profile("x86_64_v4")?;
        let flags = rustc_flags(&profile, None, Path::new("rustc"))?;
        assert_eq!(flags, ["-C", "target-cpu=x86-64-v4"]);
        assert_eq!(profile.origin, ProfileOrigin::NamedModel);
        assert!(
            mock_profile("x86_64_v3")?
                .resolve(Some("x86_64_v4"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn malformed_target_triples_are_rejected() {
        assert!(DestinationProfile::named("aarch64-unknown-linux-gnu", "zen2").is_err());
        assert!(DestinationProfile::named("x86_64", "zen2").is_err());
        assert!(DestinationProfile::named("x86_64-unknown-linux-gnu", "not-a-cpu").is_err());
    }

    #[test]
    fn architecture_triples_cover_archspec_cpu_families() -> Result<()> {
        for (triple, cpu) in [
            ("aarch64-unknown-linux-gnu", "neoverse_n2"),
            ("powerpc64le-unknown-linux-gnu", "power9"),
            ("riscv64gc-unknown-linux-gnu", "riscv64"),
            ("i686-unknown-linux-gnu", "x86"),
        ] {
            let profile = DestinationProfile::named(triple, cpu)?;
            assert_eq!(profile.resolve(None)?.name(), cpu);
        }
        Ok(())
    }

    #[test]
    fn cmake_and_meson_only_serialize_c_compiler_flags() {
        let flags = vec!["-march=znver2".to_owned(), "-mtune=znver2".to_owned()];
        let cmake = cmake_toolchain(&flags);
        let meson = meson_options(&flags);
        assert!(cmake.contains("CMAKE_CXX_FLAGS_INIT"));
        assert!(meson.contains("cpp_args"));
        assert!(!cmake.contains("rustflags"));
        assert!(!meson.contains("rustflags"));
    }
}
