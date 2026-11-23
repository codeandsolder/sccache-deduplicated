//! Detect the effective Linux ISA shared by all processors.
//!
//! Archspec's Linux host detector reads only the first processor record.
//! An executable may run on any online core, so a destination profile must not
//! use ISA features missing from another CPU. Kernel flags represent OS-usable
//! instructions, including XSAVE/XCR0 requirements for vector extensions.

use super::DestinationProfile;
use anyhow::{Context, Result, ensure};
use archspec::cpu::Microarchitecture;
use archspec::schema::MicroarchitecturesSchema;
use std::collections::{HashMap, HashSet};

fn cpu_records(contents: &str) -> Vec<HashMap<&str, &str>> {
    let mut records = Vec::new();
    let mut record = HashMap::new();
    for line in contents.lines() {
        if line.trim().is_empty() {
            if !record.is_empty() {
                records.push(std::mem::take(&mut record));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            record.insert(key.trim(), value.trim());
        }
    }
    if !record.is_empty() {
        records.push(record);
    }
    records
}

fn core_signature(record: &HashMap<&str, &str>, family: &str) -> Option<String> {
    let keys = match family {
        "x86_64" | "x86" => &["vendor_id", "cpu family", "model", "model name"][..],
        "aarch64" => &["CPU implementer", "CPU part"][..],
        "ppc64" | "ppc64le" => &["cpu", "revision"][..],
        "riscv64" => &["isa", "uarch"][..],
        _ => return None,
    };
    let fields = keys
        .iter()
        .map(|key| record.get(key).copied().filter(|value| !value.is_empty()))
        .collect::<Option<Vec<_>>>()?;
    Some(fields.join("/"))
}

fn common_features(records: &[HashMap<&str, &str>], key: &str) -> Result<HashSet<String>> {
    let mut common = None;
    for (processor, record) in records.iter().enumerate() {
        // Every visible core must report its usable ISA or we fail closed.
        let features = record
            .get(key)
            .with_context(|| format!("processor entry {processor} has no '{key}' feature list"))?;
        ensure!(
            !features.is_empty(),
            "processor entry {processor} has empty '{key}' features"
        );
        let features: HashSet<String> = features
            .split_ascii_whitespace()
            .map(str::to_owned)
            .collect();
        common = Some(match common {
            Some(previous) => features.intersection(&previous).cloned().collect(),
            None => features,
        });
    }
    common.context("Linux cpuinfo contains no processor entries")
}

fn best_common_generic_cpu(
    family: &str,
    features: &HashSet<String>,
) -> Result<&'static Microarchitecture> {
    // ARM architectural revision markers such as armv9.0a can carry no
    // explicit feature list in Archspec. A subset test alone cannot establish
    // their minimum ISA level, so heterogeneous ARM defaults to ARMv8-A.
    if family == "aarch64" {
        return Microarchitecture::known_targets()
            .get("aarch64")
            .map(std::sync::Arc::as_ref)
            .context("Archspec has no generic AArch64 model");
    }
    let cpu = Microarchitecture::known_targets()
        .values()
        .filter(|cpu| {
            cpu.vendor() == "generic"
                && cpu.family().name() == family
                && cpu.all_features().is_subset(features)
        })
        .max_by(|a, b| {
            a.all_features()
                .len()
                .cmp(&b.all_features().len())
                .then_with(|| a.generation().cmp(&b.generation()))
                .then_with(|| a.name().cmp(b.name()))
        })
        .context("no generic CPU model supports the destination's shared Linux ISA")?;
    Ok(cpu)
}

pub fn enforce_common_cpu_features(
    mut profile: DestinationProfile,
    contents: &str,
) -> Result<DestinationProfile> {
    let family = Microarchitecture::known_targets()
        .get(&profile.microarchitecture)
        .context("Archspec detected CPU disappeared from architecture database")?
        .family()
        .name();
    let records = cpu_records(contents);
    ensure!(!records.is_empty(), "Linux cpuinfo contains no processors");
    let feature_key = match family {
        "x86_64" | "x86" => "flags",
        "aarch64" => "Features",
        // For Linux families without a normalized per-core ISA feature list,
        // verify processor identity rather than treating CPU0 as the entire
        // destination. Mixed or unidentifiable cores require an explicit
        // compatible model supplied by the caller.
        _ => {
            if records.len() > 1 {
                let first = core_signature(&records[0], family);
                ensure!(
                    first.is_some()
                        && records
                            .iter()
                            .all(|rec| core_signature(rec, family) == first),
                    "cannot infer a common {family} ISA from heterogeneous or unidentified Linux CPUs; specify an explicit compatible model"
                );
            }
            return Ok(profile);
        }
    };
    let mut features = common_features(&records, feature_key)?;
    ensure!(
        !features.is_empty(),
        "no ISA features shared by all listed processors"
    );
    // Use Archspec's alias rules rather than inventing another mapping.
    for (name, alias) in &MicroarchitecturesSchema::schema().feature_aliases {
        let is_supported = alias
            .any_of
            .as_ref()
            .is_some_and(|names| names.iter().any(|name| features.contains(name)))
            || alias
                .families
                .as_ref()
                .is_some_and(|families| families.iter().any(|name| name == family));
        if is_supported {
            features.insert(name.to_owned());
        }
    }

    let signatures: Vec<_> = records
        .iter()
        .map(|record| core_signature(record, family))
        .collect();
    let homogeneous = signatures
        .first()
        .is_some_and(|first| first.is_some() && signatures.iter().all(|value| value == first));

    let detected = Microarchitecture::known_targets()
        .get(&profile.microarchitecture)
        .context("Archspec detected CPU disappeared from architecture database")?;
    let selected = if homogeneous && detected.all_features().is_subset(&features) {
        detected.as_ref()
    } else {
        best_common_generic_cpu(family, &features)?
    };
    ensure!(
        selected.all_features().is_subset(&features),
        "chosen CPU requires features absent from another Linux processor"
    );
    selected.name().clone_into(&mut profile.microarchitecture);
    selected.vendor().clone_into(&mut profile.vendor);
    profile.features = features.into_iter().collect();
    profile.features.sort();
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpuinfo(cores: &[(&str, &str)]) -> String {
        cores
            .iter()
            .enumerate()
            .map(|(id, (name, flags))| {
                format!(
                    "processor : {id}\nvendor_id : GenuineIntel\ncpu family : 6\nmodel : 151\nmodel name : {name}\nflags : {flags}\n"
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn flags(model: &str) -> Result<String> {
        let cpu = Microarchitecture::known_targets()
            .get(model)
            .with_context(|| format!("unknown test model {model}"))?;
        let mut flags: Vec<_> = cpu.all_features().into_iter().collect();
        flags.sort();
        Ok(flags.join(" "))
    }

    #[test]
    fn interleaved_cores_cannot_enable_first_core_only_avx512() -> Result<()> {
        let v4 = flags("x86_64_v4")?;
        let v3 = flags("x86_64_v3")?;
        let source = cpuinfo(&[("fast core", &v4), ("slow core", &v3)]);
        let profile = DestinationProfile::named("x86_64-unknown-linux-gnu", "x86_64_v4")?;
        let actual = enforce_common_cpu_features(profile, &source)?;
        assert_eq!(actual.microarchitecture, "x86_64_v3");
        assert!(
            !actual
                .features
                .iter()
                .any(|value| value.starts_with("avx512"))
        );
        assert!(actual.resolve(Some("x86_64_v4")).is_err());
        assert!(actual.resolve(Some("x86_64_v2")).is_ok());
        Ok(())
    }

    #[test]
    fn uniform_model_preserves_specific_cpu_tuning() -> Result<()> {
        let flags = flags("x86_64_v4")?;
        let source = cpuinfo(&[("same model", &flags), ("same model", &flags)]);
        let profile = DestinationProfile::named("x86_64-unknown-linux-gnu", "x86_64_v4")?;
        let actual = enforce_common_cpu_features(profile, &source)?;
        assert_eq!(actual.microarchitecture, "x86_64_v4");
        Ok(())
    }

    #[test]
    fn masked_virtual_machine_features_require_baseline() -> Result<()> {
        let source = cpuinfo(&[("virtual", &flags("x86_64_v2")?)]);
        let profile = DestinationProfile::named("x86_64-unknown-linux-gnu", "x86_64_v4")?;
        let actual = enforce_common_cpu_features(profile, &source)?;
        assert_eq!(actual.microarchitecture, "x86_64_v2");
        assert!(actual.resolve(Some("x86_64_v3")).is_err());
        Ok(())
    }

    #[test]
    fn missing_processor_capabilities_fail_closed() -> Result<()> {
        let profile = DestinationProfile::named("x86_64-unknown-linux-gnu", "x86_64_v4")?;
        assert!(enforce_common_cpu_features(profile.clone(), "").is_err());
        assert!(
            enforce_common_cpu_features(profile, "processor : 0\nmodel name : unsafe\n").is_err()
        );
        Ok(())
    }

    #[test]
    fn heterogeneous_power_cores_are_not_assumed_to_match_cpu_zero() -> Result<()> {
        let original = DestinationProfile::named("powerpc64le-unknown-linux-gnu", "power9")?;
        let input = "processor : 0\ncpu : POWER9\nrevision : 2.0\n\nprocessor : 1\ncpu : POWER8\nrevision : 1.0";
        assert!(enforce_common_cpu_features(original, input).is_err());
        Ok(())
    }

    #[test]
    fn uniform_power_cores_preserve_archspec_cpu_model() -> Result<()> {
        let original = DestinationProfile::named("powerpc64le-unknown-linux-gnu", "power9")?;
        let input = "processor : 0\ncpu : POWER9\nrevision : 2.0\n\nprocessor : 1\ncpu : POWER9\nrevision : 2.0";
        let actual = enforce_common_cpu_features(original, input)?;
        assert_eq!(actual.microarchitecture, "power9");
        Ok(())
    }

    #[test]
    fn consistent_arm_cores_preserve_specific_target() -> Result<()> {
        let flags = flags("neoverse_n2")?;
        let source = [
            format!("processor : 0\nCPU implementer : 0x41\nCPU part : 0xd49\nFeatures : {flags}"),
            format!("processor : 1\nCPU implementer : 0x41\nCPU part : 0xd49\nFeatures : {flags}"),
        ]
        .join("\n\n");
        let profile = DestinationProfile::named("aarch64-unknown-linux-gnu", "neoverse_n2")?;
        let actual = enforce_common_cpu_features(profile, &source)?;
        assert_eq!(actual.microarchitecture, "neoverse_n2");
        assert_eq!(
            crate::rustc_flags(&actual, None, std::path::Path::new("rustc"))?,
            ["-C", "target-cpu=neoverse-n2"]
        );
        Ok(())
    }

    #[test]
    fn riscv_heterogeneous_isa_must_not_trust_first_processor() -> Result<()> {
        let profile = DestinationProfile::named("riscv64gc-unknown-linux-gnu", "riscv64")?;
        let source = "processor : 0\nisa : rv64imafdc\nuarch : sifive,u74-mc\n\nprocessor : 1\nisa : rv64imafdcv\nuarch : sifive,u74-mc";
        assert!(enforce_common_cpu_features(profile, source).is_err());
        Ok(())
    }

    #[test]
    fn heterogeneous_arm_cores_require_architecture_wide_baseline() -> Result<()> {
        let flags = flags("neoverse_n2")?;
        let source = [
            format!("processor : 0\nCPU implementer : 0x41\nCPU part : 0xd49\nFeatures : {flags}"),
            format!("processor : 1\nCPU implementer : 0x41\nCPU part : 0xd05\nFeatures : {flags}"),
        ]
        .join("\n\n");
        let profile = DestinationProfile::named("aarch64-unknown-linux-gnu", "neoverse_n2")?;
        let actual = enforce_common_cpu_features(profile, &source)?;
        assert_eq!(actual.microarchitecture, "aarch64");
        assert!(actual.features.contains(&"neon".to_owned()));
        assert_eq!(
            crate::rustc_flags(&actual, None, std::path::Path::new("rustc"))?,
            ["-C", "target-cpu=generic"]
        );
        Ok(())
    }

    #[test]
    fn every_processor_must_report_usable_features() -> Result<()> {
        let source = format!(
            "{}\nprocessor : 1\nvendor_id : GenuineIntel\nmodel name : missing features\n",
            cpuinfo(&[("first", &flags("x86_64_v4")?)])
        );
        let profile = DestinationProfile::named("x86_64-unknown-linux-gnu", "x86_64_v4")?;
        assert!(enforce_common_cpu_features(profile, &source).is_err());
        Ok(())
    }
}
