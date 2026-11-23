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
use std::path::Path;
use std::process::{Command, Stdio};
use target_lexicon::Triple;

#[cfg(target_os = "linux")]
mod linux_capabilities;

const SCHEMA_VERSION: u32 = 2;

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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileOrigin {
    NamedModel,
    /// Host model and feature set were obtained from Archspec's platform
    /// detector; processor topology was not independently established.
    ArchspecHost,
    /// Linux capability intersection over all listed processors. A present
    /// hypervisor flag is a hint only, not a definitive virtualization test.
    LinuxCpuInfo {
        logical_processors: usize,
        heterogeneous: bool,
        hypervisor_flag_seen: bool,
    },
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
        let profile =
            Self::from_microarchitecture(target_triple, &detected, ProfileOrigin::ArchspecHost)?;
        #[cfg(target_os = "linux")]
        {
            let contents = std::fs::read_to_string("/proc/cpuinfo")
                .context("cannot read Linux processor capabilities from /proc/cpuinfo")?;
            linux_capabilities::enforce_common_cpu_features(profile, &contents)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(profile)
        }
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
    let path = compiler.display();
    let stderr = String::from_utf8_lossy(&output.stderr);
    ensure!(output.status.success(), "{path} {args:?} failed: {stderr}");
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

fn compiler_target_matches(requested: &str, reported: &str) -> Result<bool> {
    let requested: Triple = requested
        .parse()
        .with_context(|| format!("unrecognized destination target triple {requested}"))?;
    let reported: Triple = reported
        .parse()
        .with_context(|| format!("unrecognized GCC target triple {reported}"))?;
    // Toolchain vendors are not part of the target ISA/ABI: both
    // x86_64-pc-linux-gnu and x86_64-unknown-linux-gnu target the same ABI.
    Ok(requested.architecture == reported.architecture
        && requested.operating_system == reported.operating_system
        && requested.environment == reported.environment
        && requested.binary_format == reported.binary_format)
}

fn validate_c_target_flags(compiler: &Path, flags: &[String]) -> Result<()> {
    // Parse a translation unit with the selected compiler but perform no
    // code generation. GCC and Clang both validate -march/-mcpu with
    // -fsyntax-only, so no local compilation artifact is created.
    // This catches CPU models unsupported by the installed compiler.
    let output = Command::new(compiler)
        .args(flags)
        .args(["-fsyntax-only", "-x", "c", "-"])
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("cannot probe C compiler {}", compiler.display()))?;
    let path = compiler.display();
    let stderr = String::from_utf8_lossy(&output.stderr);
    ensure!(
        output.status.success(),
        "C compiler {path} rejected target flags {flags:?}: {stderr}"
    );
    Ok(())
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
    let mut flags = c_compiler_flags(cpu, family, &version)?;
    if family == "gcc" {
        let machine = tool_output(compiler, &["-dumpmachine"])?;
        let machine = machine.trim();
        ensure!(
            compiler_target_matches(&profile.target_triple, machine)?,
            "GCC {} targets {machine}, not {}; choose a cross-GCC toolchain for the destination instead of exporting unusable flags",
            compiler.display(),
            profile.target_triple
        );
    } else {
        // Clang is natively cross-target. Make the destination explicit in
        // the actual invocation as well as in the target-profile document.
        // Both the target and optimization flags are now normal clang
        // arguments, hashed by the existing C compiler-specific cache key.
        flags.insert(0, format!("--target={}", profile.target_triple));
    }
    validate_c_target_flags(compiler, &flags)?;
    Ok(flags)
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
    if cpu.name() == "aarch64" {
        alternatives.push("generic".to_owned());
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

/// Serialize C compiler arguments for a cc-rs build script to read at runtime.
///
/// The native flag data is not Rust source, so changing GCC flags does not
/// change the host-executed build script's Rust compilation identity.
///
/// # Errors
/// Fails if serializing the compiler arguments as JSON fails.
pub fn cc_rs_flags_json(flags: &[String]) -> Result<String> {
    Ok(serde_json::to_string_pretty(flags)?)
}

pub fn show_flags(flags: &[String]) -> String {
    let mut result = String::new();
    for (index, flag) in flags.iter().enumerate() {
        if index != 0 {
            result.push(' ');
        }
        // Plain compiler options should remain easy to paste into a shell
        // command, while values requiring quoting must round-trip faithfully.
        let shell_safe = flag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'_' | b'=' | b'.' | b'/' | b':' | b'+' | b',' | b'@'
                )
        });
        if shell_safe {
            result.push_str(flag);
        } else {
            result.push_str(
                &shlex::try_quote(flag).map_or_else(|_| flag.clone(), std::borrow::Cow::into_owned),
            );
        }
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
    fn cc_rs_generated_flags_are_data_not_rust_source() -> Result<()> {
        let flags = vec![
            "-march=x86-64-v4".to_owned(),
            "-DNAME=two words".to_owned(),
            r#"-DQUOTED=hello\"world"#.to_owned(),
        ];
        let output = cc_rs_flags_json(&flags)?;
        assert_eq!(serde_json::from_str::<Vec<String>>(&output)?, flags);
        assert!(!output.contains("build.flag"));
        assert!(!output.contains("rustflags"));
        assert!(!output.contains("cargo:rustc"));
        Ok(())
    }

    #[test]
    fn shell_flag_output_remains_readable_and_round_trippable() -> Result<()> {
        let ordinary = vec![
            "--target=aarch64-unknown-linux-gnu".to_owned(),
            "-mcpu=neoverse-n2".to_owned(),
        ];
        assert_eq!(
            show_flags(&ordinary),
            "--target=aarch64-unknown-linux-gnu -mcpu=neoverse-n2\n"
        );
        let quoted = vec!["-DNAME=two words".to_owned(), "-DQUOTE=can't".to_owned()];
        let encoded = show_flags(&quoted);
        assert_eq!(
            shlex::split(&encoded).context("shell flag serialization produced invalid tokens")?,
            quoted
        );
        Ok(())
    }

    #[test]
    fn profile_schema_records_provenance_and_rejects_old_versions() -> Result<()> {
        let profile = mock_profile("x86_64_v3")?;
        let json = serde_json::to_string(&profile)?;
        assert!(json.contains(r#""schema_version":2"#));
        assert!(json.contains(r#""kind":"named_model""#));
        let decoded: DestinationProfile = serde_json::from_str(&json)?;
        assert_eq!(decoded, profile);
        let mut incompatible = decoded;
        incompatible.schema_version = 1;
        assert!(incompatible.resolve(None).is_err());
        Ok(())
    }

    #[test]
    fn c_target_machine_accepts_vendor_aliases_but_not_abi_or_architecture_changes() -> Result<()> {
        assert!(compiler_target_matches(
            "x86_64-unknown-linux-gnu",
            "x86_64-pc-linux-gnu"
        )?);
        assert!(!compiler_target_matches(
            "x86_64-unknown-linux-musl",
            "x86_64-pc-linux-gnu"
        )?);
        assert!(!compiler_target_matches(
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-linux-gnu"
        )?);
        assert!(!compiler_target_matches(
            "x86_64-pc-windows-gnu",
            "x86_64-pc-linux-gnu"
        )?);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn toolchain_probe_checks_actual_backend_support() {
        assert!(
            validate_c_target_flags(
                Path::new("gcc"),
                &["-march=cpu-definitely-not-present-in-any-gcc".to_owned()]
            )
            .is_err()
        );
        assert!(
            validate_c_target_flags(
                Path::new("clang"),
                &[
                    "--target=aarch64-unknown-linux-gnu".to_owned(),
                    "-mcpu=this-does-not-exist".to_owned()
                ]
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn toolchain_probe_rejects_native_gcc_for_foreign_cpu() -> Result<()> {
        let profile = DestinationProfile::named("aarch64-unknown-linux-gnu", "neoverse_n2")?;
        let result = selected_c_flags(&profile, None, "gcc", Path::new("gcc"));
        assert!(result.is_err());
        let error = result
            .err()
            .context("native GCC unexpectedly accepted cross target")?;
        assert!(error.to_string().contains("cross-GCC toolchain"));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clang_cross_target_is_part_of_compiler_arguments() -> Result<()> {
        let profile = DestinationProfile::named("aarch64-unknown-linux-gnu", "neoverse_n2")?;
        let flags = selected_c_flags(&profile, None, "clang", Path::new("clang"))?;
        assert_eq!(
            flags.first().map(String::as_str),
            Some("--target=aarch64-unknown-linux-gnu")
        );
        assert!(flags.iter().any(|flag| flag == "-mcpu=neoverse-n2"));
        Ok(())
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
    fn unrelated_profile_metadata_does_not_affect_effective_rustc_flags() -> Result<()> {
        let original = mock_profile("x86_64_v3")?;
        let expected = cargo_toml(&original, None, Path::new("rustc"))?;
        let mut modified = original.clone();
        modified.features.push("kernel_bookkeeping_bit".to_owned());
        modified.origin = ProfileOrigin::ArchspecHost;
        assert_ne!(original, modified);
        assert_eq!(expected, cargo_toml(&modified, None, Path::new("rustc"))?);
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
