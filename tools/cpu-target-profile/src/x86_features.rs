//! Common Linux x86 ISA name translation for Rust, GCC and Clang.
//!
//! Linux capability names, GCC `-m*` switches and LLVM target-feature names
//! are not identical. An ISA snapshot is useful for code generation only when
//! those differences are resolved before invoking each compiler.

use super::{DestinationProfile, ProfileOrigin};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeSet, HashSet};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// (GCC -m switch, LLVM target-feature, Linux aliases indicating availability).
/// All the CPU-dependent x86-64 GCC switches known at this compiler generation
/// have a mapping. Unrecognized CPU-dependent switches are rejected for saved
/// Linux capability snapshots rather than silently enabling unverified ISA.
const ISA: &[(&str, &str, &[&str])] = &[
    ("abm", "lzcnt", &["abm", "lzcnt"]),
    ("adx", "adx", &["adx"]),
    ("aes", "aes", &["aes"]),
    ("amx-bf16", "amx-bf16", &["amx_bf16"]),
    ("amx-int8", "amx-int8", &["amx_int8"]),
    ("amx-tile", "amx-tile", &["amx_tile"]),
    ("avx", "avx", &["avx"]),
    ("avx2", "avx2", &["avx2"]),
    ("avx512bf16", "avx512bf16", &["avx512_bf16"]),
    ("avx512bitalg", "avx512bitalg", &["avx512_bitalg"]),
    ("avx512bw", "avx512bw", &["avx512bw"]),
    ("avx512cd", "avx512cd", &["avx512cd"]),
    ("avx512dq", "avx512dq", &["avx512dq"]),
    ("avx512f", "avx512f", &["avx512f"]),
    ("avx512fp16", "avx512fp16", &["avx512_fp16"]),
    ("avx512ifma", "avx512ifma", &["avx512_ifma"]),
    ("avx512vbmi", "avx512vbmi", &["avx512_vbmi"]),
    ("avx512vbmi2", "avx512vbmi2", &["avx512_vbmi2"]),
    ("avx512vl", "avx512vl", &["avx512vl"]),
    ("avx512vnni", "avx512vnni", &["avx512_vnni"]),
    (
        "avx512vp2intersect",
        "avx512vp2intersect",
        &["avx512_vp2intersect"],
    ),
    ("avx512vpopcntdq", "avx512vpopcntdq", &["avx512_vpopcntdq"]),
    ("avxvnni", "avxvnni", &["avx_vnni"]),
    ("bmi", "bmi1", &["bmi1", "bmi"]),
    ("bmi2", "bmi2", &["bmi2"]),
    ("cldemote", "cldemote", &["cldemote"]),
    ("clflushopt", "clflushopt", &["clflushopt"]),
    ("clwb", "clwb", &["clwb"]),
    ("clzero", "clzero", &["clzero"]),
    ("crc32", "sse4.2", &["sse4_2"]),
    ("cx16", "cmpxchg16b", &["cx16"]),
    ("enqcmd", "enqcmd", &["enqcmd"]),
    ("f16c", "f16c", &["f16c"]),
    ("fma", "fma", &["fma"]),
    ("fsgsbase", "fsgsbase", &["fsgsbase"]),
    ("gfni", "gfni", &["gfni"]),
    ("hle", "hle", &["hle"]),
    ("lzcnt", "lzcnt", &["abm", "lzcnt"]),
    ("movbe", "movbe", &["movbe"]),
    ("movdir64b", "movdir64b", &["movdir64b"]),
    ("movdiri", "movdiri", &["movdiri"]),
    ("mwait", "mwait", &["monitor"]),
    ("mwaitx", "mwaitx", &["mwaitx"]),
    ("pclmul", "pclmulqdq", &["pclmulqdq", "pclmul"]),
    ("pconfig", "pconfig", &["pconfig"]),
    ("pku", "pku", &["ospke"]),
    ("popcnt", "popcnt", &["popcnt"]),
    ("prefetchi", "prefetchi", &["prefetchi"]),
    ("prfchw", "prfchw", &["3dnowprefetch", "prfchw"]),
    ("ptwrite", "ptwrite", &["ptwrite"]),
    ("rdpid", "rdpid", &["rdpid"]),
    ("rdrnd", "rdrand", &["rdrand"]),
    ("rdseed", "rdseed", &["rdseed"]),
    ("sahf", "sahf", &["lahf_lm"]),
    ("serialize", "serialize", &["serialize"]),
    ("sgx", "sgx", &["sgx"]),
    ("sha", "sha", &["sha_ni", "sha"]),
    ("sse3", "sse3", &["pni", "sse3"]),
    ("sse4", "sse4.1", &["sse4_1"]),
    ("sse4.1", "sse4.1", &["sse4_1"]),
    ("sse4.2", "sse4.2", &["sse4_2"]),
    ("sse4a", "sse4a", &["sse4a"]),
    ("ssse3", "ssse3", &["ssse3"]),
    ("tsxldtrk", "tsxldtrk", &["tsxldtrk"]),
    ("uintr", "uintr", &["uintr"]),
    ("vaes", "vaes", &["vaes"]),
    ("vpclmulqdq", "vpclmulqdq", &["vpclmulqdq"]),
    ("waitpkg", "waitpkg", &["waitpkg"]),
    ("wbnoinvd", "wbnoinvd", &["wbnoinvd"]),
    ("xsave", "xsave", &["xsave"]),
    ("xsavec", "xsavec", &["xsavec"]),
    ("xsaveopt", "xsaveopt", &["xsaveopt"]),
    ("xsaves", "xsaves", &["xsaves"]),
];

pub fn is_captured_x86(profile: &DestinationProfile) -> bool {
    matches!(profile.origin, ProfileOrigin::LinuxCpuInfo { .. })
        && matches!(profile.target_triple.split('-').next(), Some("x86_64"))
}

pub fn llvm_available(profile: &DestinationProfile, llvm: &str) -> bool {
    // GCC, Clang and Rust spell several identical x86 capabilities differently.
    // Normalize the LLVM names in addition to the GCC-oriented mapping below.
    let driver_aliases: &[&str] = match llvm {
        "bmi" => &["bmi1", "bmi"],
        "crc32" => &["sse4_2"],
        "pclmul" => &["pclmulqdq", "pclmul"],
        "rdrnd" => &["rdrand"],
        "x87" => &["fpu"],
        _ => &[],
    };
    if driver_aliases
        .iter()
        .any(|alias| profile.features.iter().any(|raw| raw == alias))
    {
        return true;
    }
    let mut recognized = !driver_aliases.is_empty();
    for (_, feature, names) in ISA {
        if *feature == llvm {
            recognized = true;
            if names
                .iter()
                .any(|alias| profile.features.iter().any(|raw| raw == alias))
            {
                return true;
            }
        }
    }
    !recognized
        && profile
            .features
            .iter()
            .any(|raw| raw == llvm || raw == &llvm.replace(['.', '-'], "_"))
}

fn gcc_enabled(compiler: &Path, flags: &[String]) -> Result<HashSet<String>> {
    let output = Command::new(compiler)
        .args(flags)
        .args(["-Q", "-O2", "--help=target"])
        .output()
        .with_context(|| {
            format!(
                "cannot inspect GCC ISA switches using {}",
                compiler.display()
            )
        })?;
    ensure!(
        output.status.success(),
        "GCC refused target feature inspection: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let opt = parts.next()?.strip_prefix("-m")?;
            (parts.next()? == "[enabled]").then(|| opt.to_owned())
        })
        .collect())
}

pub fn gcc_mask_flags(
    profile: &DestinationProfile,
    compiler: &Path,
    selected: &[String],
) -> Result<Vec<String>> {
    let enabled = gcc_enabled(compiler, selected)?;
    let baseline = gcc_enabled(compiler, &["-march=x86-64".to_owned()])?;
    let mapped: HashSet<_> = ISA.iter().map(|(gcc, _, _)| *gcc).collect();
    let unmapped: BTreeSet<_> = enabled
        .difference(&baseline)
        .filter(|flag| !mapped.contains(flag.as_str()))
        .collect();
    ensure!(
        unmapped.is_empty(),
        "GCC's CPU activates unmapped ISA switches {unmapped:?}; cannot preserve a captured masked CPU safely"
    );
    Ok(ISA
        .iter()
        .filter(|(gcc, _, _)| enabled.contains(*gcc))
        .filter(|(_, llvm, _)| !llvm_available(profile, llvm))
        .map(|(gcc, _, _)| format!("-mno-{gcc}"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

/// Query Clang's *actual* enabled LLVM target features for the named CPU.
/// Driver `-###` only reports a CPU name for ordinary `-march`, losing the
/// feature expansion. Emitting a tiny IR-only function exposes that final
/// feature list without creating or running machine code, and works for an
/// offline destination CPU that is absent from the requesting machine.
pub fn clang_mask_flags(
    profile: &DestinationProfile,
    compiler: &Path,
    selected: &[String],
) -> Result<Vec<String>> {
    let mut child = Command::new(compiler)
        .args(selected)
        .args(["-x", "c", "-", "-S", "-emit-llvm", "-o", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "cannot inspect Clang target features using {}",
                compiler.display()
            )
        })?;
    let mut stdin = child
        .stdin
        .take()
        .context("cannot feed Clang CPU target probe")?;
    stdin.write_all(b"int sccache_target_probe(void) { return 0; }\n")?;
    drop(stdin);
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "Clang refused target-feature probe: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ir = String::from_utf8(output.stdout).context("Clang emitted non-UTF8 target IR")?;
    let serialized = ir
        .lines()
        .find_map(|line| {
            line.split_once("\"target-features\"=\"")?
                .1
                .split_once('"')
                .map(|(features, _)| features)
        })
        .context("Clang target IR did not expose CPU feature attributes")?;
    let missing: BTreeSet<_> = serialized
        .split(',')
        .filter_map(|feature| feature.strip_prefix('+'))
        .filter(|feature| !llvm_available(profile, feature))
        .collect();
    Ok(missing
        .into_iter()
        .flat_map(|feature| {
            [
                "-Xclang".to_owned(),
                "-target-feature".to_owned(),
                "-Xclang".to_owned(),
                format!("-{feature}"),
            ]
        })
        .collect())
}
