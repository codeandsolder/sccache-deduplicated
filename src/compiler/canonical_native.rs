//! Path identity for native Cargo build-script compilations.
//!
//! A Cargo intermediate tree is temporary, but the compiler can expose its
//! absolute paths through macros and debug information. Normalize the actual
//! compilation with the compiler's prefix-map option, not just the cache key.
//! Dependency generation still uses the physical filesystem.

use super::Language;
use super::c::{CCompilerKind, ParsedArguments, inline_assembly_matches};
use super::canonical_paths::{env_value, target_root_from_out_dir_path};
use crate::util::Digest;
use std::borrow::Cow;
use std::ffi::OsString;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrefixMap {
    physical: String,
    canonical: &'static str,
}

#[derive(Debug)]
pub(super) struct NativeCargoPaths {
    // GCC and Clang resolve overlapping maps in favor of the most specific
    // prefix when the longer maps are supplied last.
    maps: Vec<PrefixMap>,
    preserve_preprocessed_identity: bool,
}

impl NativeCargoPaths {
    pub(super) fn discover(
        env: &[(OsString, OsString)],
        kind: CCompilerKind,
        version: Option<&str>,
        args: &ParsedArguments,
    ) -> Option<Self> {
        if !cfg!(target_os = "linux")
            || !supports_file_prefix_map(kind, version)
            || args.profile_generate
            || args.language.is_c_like_header()
            || !env.iter().any(|(key, val)| {
                (key == "SCCACHE_EXPERIMENTAL_CANONICAL_RUST" && val == "1")
                    || (key == "SCCACHE_CANONICAL_TARGET_ROOT" && !val.is_empty())
            })
        {
            return None;
        }

        // User-supplied remaps define the desired path semantics. Do not
        // silently override them with our opt-in Cargo default.
        let mut arguments = args
            .common_args
            .iter()
            .chain(&args.preprocessor_args)
            .chain(&args.unhashed_args);
        if arguments.any(|arg| {
            let arg = arg.as_encoded_bytes();
            (arg.starts_with(b"-f") && memchr::memmem::find(arg, b"prefix-map").is_some())
                || arg.starts_with(b"-Wa,--debug-prefix-map")
                || arg.starts_with(b"--debug-prefix-map")
                || arg.starts_with(b"-fdebug-compilation-dir")
                || arg.starts_with(b"-fcoverage-compilation-dir")
        }) {
            return None;
        }

        let out = env_value(env, "OUT_DIR")?;
        if !out.is_absolute() || !out.is_dir() {
            return None;
        }
        let mut paths = Self {
            maps: Vec::new(),
            // Clang's integrated assembler can embed a checksum of the
            // temporary preprocessed assembly file (including its original
            // line markers) in DWARF 5. Remapping that filename alone does not
            // normalize the checksum. Keep the real stream identity whenever
            // debug output can observe it, without disabling caching.
            preserve_preprocessed_identity: kind == CCompilerKind::Clang
                && args.language == Language::AssemblerToPreprocess
                && args.common_args.iter().chain(&args.arch_args).any(|arg| {
                    let bytes = arg.as_encoded_bytes();
                    bytes.split(|&b| b == b',').any(|part| {
                        (part.starts_with(b"-g") && part != b"-gcc-toolchain")
                            || part.starts_with(b"--gdwarf")
                            || part.starts_with(b"-debug-info-kind=")
                    })
                }),
        };
        // Per-package OUT_DIR is the most specific stable identity, including
        // generated sources copied there by a build script. It deliberately
        // does not contain Cargo's package/build fingerprint directory.
        paths.add(&out, "/__sccache/cargo/out");
        if paths.maps.is_empty() {
            return None;
        }
        let target = env_value(env, "TARGET");
        if let Some(intermediate) =
            target_root_from_out_dir_path(&out, target.as_deref().map(Path::as_os_str))
        {
            paths.add(&intermediate, "/__sccache/cargo/intermediate");
        }
        if let Some(target) = env_value(env, "SCCACHE_CANONICAL_TARGET_ROOT")
            .or_else(|| env_value(env, "CARGO_TARGET_DIR"))
        {
            paths.add(&target, "/__sccache/cargo/target");
        }
        if let Some(manifest) = env_value(env, "CARGO_MANIFEST_DIR") {
            paths.add(&manifest, "/__sccache/cargo/package");
        }
        if let Some(registry) = env_value(env, "EPHEMERAL_CARGO_REGISTRY_SRC") {
            paths.add(&registry, "/__sccache/cargo/registry");
        }
        if let Some(home) = env_value(env, "CARGO_HOME") {
            paths.add(&home.join("registry/src"), "/__sccache/cargo/registry");
        }
        paths.maps.sort_by_key(|map| map.physical.len());
        Some(paths)
    }

    fn add(&mut self, path: &Path, canonical: &'static str) {
        if !path.is_absolute() || path == Path::new("/") {
            return;
        }
        let real = path.canonicalize().ok();
        for alias in std::iter::once(path).chain(real.as_deref()) {
            let Some(physical) = alias.to_str() else {
                continue;
            };
            // These characters have special meaning in the compiler option or
            // the escaped filename syntax of its preprocessor output.
            if physical
                .bytes()
                .any(|b| matches!(b, b'=' | b'"' | b'\\' | b'\n' | b'\r'))
                || self.maps.iter().any(|map| map.physical == physical)
            {
                continue;
            }
            self.maps.push(PrefixMap {
                physical: physical.to_owned(),
                canonical,
            });
        }
    }

    pub(super) fn compiler_options(&self) -> impl Iterator<Item = OsString> + '_ {
        self.maps
            .iter()
            .map(|map| format!("-ffile-prefix-map={}={}", map.physical, map.canonical).into())
    }

    fn map_bytes<'a>(&self, path: &'a [u8]) -> Cow<'a, [u8]> {
        // Prefix-map options are string-prefix substitutions, not arbitrary
        // search-and-replace. Mirror the compiler's last-match precedence.
        for map in self.maps.iter().rev() {
            if let Some(suffix) = path.strip_prefix(map.physical.as_bytes()) {
                let mut mapped = map.canonical.as_bytes().to_vec();
                mapped.extend_from_slice(suffix);
                return Cow::Owned(mapped);
            }
        }
        Cow::Borrowed(path)
    }

    pub(super) fn preprocessed_key_bytes<'a>(&self, bytes: &'a [u8]) -> Cow<'a, [u8]> {
        if self.preserve_preprocessed_identity {
            return Cow::Borrowed(bytes);
        }
        let mut lexer = LineContext::Code;
        let mut continued = false;
        let mut result = None::<Vec<u8>>;
        let mut offset = 0;
        for line in bytes.split_inclusive(|&byte| byte == b'\n') {
            let marker = if lexer == LineContext::Code && !continued {
                linemarker_filename(line)
            } else {
                None
            };
            if let Some((start, end)) = marker {
                let mapped = self.map_bytes(&line[start..end]);
                if let Cow::Owned(mapped) = mapped {
                    let output = result.get_or_insert_with(|| {
                        let mut output = Vec::with_capacity(bytes.len());
                        output.extend_from_slice(&bytes[..offset]);
                        output
                    });
                    output.extend_from_slice(&line[..start]);
                    output.extend_from_slice(&mapped);
                    output.extend_from_slice(&line[end..]);
                } else if let Some(output) = result.as_mut() {
                    output.extend_from_slice(line);
                }
            } else {
                lexer.scan(line);
                if let Some(output) = result.as_mut() {
                    output.extend_from_slice(line);
                }
            }
            continued = line.strip_suffix(b"\n").unwrap_or(line).ends_with(b"\\");
            offset += line.len();
        }
        result.map_or(Cow::Borrowed(bytes), Cow::Owned)
    }

    pub(super) fn context_digest(
        &self,
        args: &ParsedArguments,
        cwd: &Path,
        preprocessed: &[u8],
    ) -> String {
        let mut digest = Digest::new();
        digest.update(b"sccache-cargo-native-paths-v1\0");
        let input = cwd.join(&args.input);
        self.hash_path(&mut digest, cwd);
        self.hash_path(&mut digest, &input);
        // Split DWARF and similar compiler outputs can refer to one another.
        // Preserve their relative identity while dropping the transient root.
        let mut outputs: Vec<_> = args.outputs.iter().collect();
        outputs.sort_unstable_by_key(|(name, _)| *name);
        for (name, output) in outputs {
            if *name != "d" {
                digest.update(name.as_bytes());
                digest.update(b"\0");
                self.hash_path(&mut digest, &cwd.join(&output.path));
            }
        }

        // Arbitrary strings, assembler .file directives, and explicit
        // compiler options can observe a physical prefix too. When one is
        // still present after normalizing genuine linemarkers, retain the
        // mapping's physical identity; never mistake a literal for a filename.
        // Explicit assembler file directives may also encode a path with
        // escapes, and command-line recording can record the map flags.
        let physical_options_observable = match args.language {
            Language::Assembler | Language::AssemblerToPreprocess => {
                assembler_may_observe_map(preprocessed)
            }
            _ => inline_assembly_matches(preprocessed, assembler_may_observe_map),
        } || args.common_args.iter().any(|arg| {
            let bytes = arg.as_encoded_bytes();
            bytes.starts_with(b"-frecord-gcc-switches")
                || bytes.starts_with(b"-grecord-command-line")
                || bytes.starts_with(b"-frecord-command-line")
        });
        for map in &self.maps {
            if physical_options_observable
                || memchr::memmem::find(preprocessed, map.physical.as_bytes()).is_some()
                || args.common_args.iter().any(|arg| {
                    memchr::memmem::find(arg.as_encoded_bytes(), map.physical.as_bytes()).is_some()
                })
            {
                digest.update(map.physical.as_bytes());
                digest.update(b"\0");
                digest.update(map.canonical.as_bytes());
                digest.update(b"\0");
            }
        }
        digest.finish()
    }

    fn hash_path(&self, digest: &mut Digest, path: &Path) {
        // Use the lexical spelling the driver receives, not realpath:
        // symlinks and relative spellings can affect the debug filename.
        digest.update(&self.map_bytes(path.as_os_str().as_encoded_bytes()));
        digest.update(b"\0");
    }
}

fn assembler_may_observe_map(bytes: &[u8]) -> bool {
    // A .file directive is not necessarily derived from the current input
    // filename (it can have its own absolute/escaped name). An opaque asm
    // template that constructs bytes using numeric escapes may also synthesize
    // such a directive or path. Preserve the map identity in either case.
    memchr::memmem::find_iter(bytes, b".file").any(|pos| {
        bytes
            .get(pos + b".file".len())
            .is_none_or(|byte| byte.is_ascii_whitespace() || matches!(byte, b'\\' | b'"'))
    }) || bytes
        .windows(2)
        .any(|pair| pair[0] == b'\\' && matches!(pair[1], b'0'..=b'7' | b'x' | b'u' | b'U'))
}

fn supports_file_prefix_map(kind: CCompilerKind, version: Option<&str>) -> bool {
    let Some(major) = version.and_then(|version| {
        version
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .split(|c: char| !c.is_ascii_digit())
            .next()?
            .parse::<u32>()
            .ok()
    }) else {
        return false;
    };
    match kind {
        CCompilerKind::Gcc => major >= 8,
        CCompilerKind::Clang => major >= 10,
        _ => false,
    }
}

// A genuine GNU linemarker is a directive, not a textual occurrence of
// a filename. In particular a C++ raw string may contain a complete line
// which looks exactly like one.
fn linemarker_filename(line: &[u8]) -> Option<(usize, usize)> {
    let mut at = usize::from(line.first() == Some(&b'#'));
    if at == 0 {
        return None;
    }
    while line.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    if line.get(at..)?.starts_with(b"line ") {
        at += b"line ".len();
    }
    let number = at;
    while line.get(at).is_some_and(u8::is_ascii_digit) {
        at += 1;
    }
    if number == at || !line.get(at).is_some_and(u8::is_ascii_whitespace) {
        return None;
    }
    while line.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    if line.get(at) != Some(&b'"') {
        return None;
    }
    at += 1;
    let start = at;
    while let Some(&byte) = line.get(at) {
        match byte {
            b'"' => return Some((start, at)),
            b'\\' => at += 2,
            b'\n' => return None,
            _ => at += 1,
        }
    }
    None
}

#[derive(Debug, PartialEq, Eq)]
enum LineContext {
    Code,
    BlockComment,
    Quoted(u8),
    RawString(Vec<u8>),
}

impl LineContext {
    fn scan(&mut self, line: &[u8]) {
        let mut at = 0;
        while at < line.len() {
            let tail = &line[at..];
            match self {
                Self::BlockComment => {
                    let Some(end) = memchr::memmem::find(tail, b"*/") else {
                        return;
                    };
                    at += end + 2;
                    *self = Self::Code;
                }
                Self::RawString(end_marker) => {
                    let Some(end) = memchr::memmem::find(tail, end_marker) else {
                        return;
                    };
                    at += end + end_marker.len();
                    *self = Self::Code;
                }
                Self::Quoted(quote) => match tail[0] {
                    b'\\' => at += 2,
                    byte if byte == *quote => {
                        at += 1;
                        *self = Self::Code;
                    }
                    _ => at += 1,
                },
                Self::Code if tail.starts_with(b"//") => return,
                Self::Code if tail.starts_with(b"/*") => {
                    at += 2;
                    *self = Self::BlockComment;
                }
                Self::Code if raw_string_prefix(tail).is_some() => {
                    if let Some((prefix, delimiter)) = raw_string_prefix(tail).and_then(|prefix| {
                        raw_string_delimiter(&tail[prefix..]).map(|delimiter| (prefix, delimiter))
                    }) {
                        at += prefix + delimiter.len() + 1;
                        *self = Self::RawString([b")".as_slice(), delimiter, b"\""].concat());
                    } else {
                        at += 1;
                    }
                }
                Self::Code if tail[0].is_ascii_alphabetic() || tail[0] == b'_' => {
                    at += tail
                        .iter()
                        .take_while(|&&byte| byte.is_ascii_alphanumeric() || byte == b'_')
                        .count();
                }
                Self::Code if tail[0].is_ascii_digit() => {
                    // A preprocessing number may contain C++ digit separators.
                    at += tail
                        .iter()
                        .take_while(|&&byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'\'')
                        })
                        .count();
                }
                Self::Code if matches!(tail[0], b'"' | b'\'') => {
                    *self = Self::Quoted(tail[0]);
                    at += 1;
                }
                Self::Code => at += 1,
            }
        }
    }
}

fn raw_string_prefix(bytes: &[u8]) -> Option<usize> {
    [b"R\"".as_slice(), b"u8R\"", b"uR\"", b"UR\"", b"LR\""]
        .into_iter()
        .find(|prefix| bytes.starts_with(prefix))
        .map(<[u8]>::len)
}

fn raw_string_delimiter(bytes: &[u8]) -> Option<&[u8]> {
    let end = bytes.iter().take(17).position(|&byte| byte == b'(')?;
    let delimiter = &bytes[..end];
    delimiter
        .iter()
        .all(|&byte| !byte.is_ascii_whitespace() && !matches!(byte, b')' | b'\\'))
        .then_some(delimiter)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::compiler::CompilerArguments;
    use crate::compiler::c::CCompilerImpl;
    use crate::compiler::gcc::Gcc;
    use std::fs;

    #[test]
    fn markers_are_not_source_literals_or_comments() {
        let paths = NativeCargoPaths {
            preserve_preprocessed_identity: false,
            maps: vec![PrefixMap {
                physical: "/tmp/physical".into(),
                canonical: "/stable",
            }],
        };
        let input = br##"# 1 "/tmp/physical/source.cc"
const char *literal = "/tmp/physical/source.cc";
const char *raw = R"delim(
# 1 "/tmp/physical/raw.cc"
)delim";
/*
# 1 "/tmp/physical/comment.cc"
*/
# 6 "/tmp/physical/next.h" 1
int n = 1'000;
const char *other = u8R"(
"
# 1 "/tmp/physical/other.cc"
)";
# 9 "/tmp/physical/source.cc" 2
"##;
        let expected = br##"# 1 "/stable/source.cc"
const char *literal = "/tmp/physical/source.cc";
const char *raw = R"delim(
# 1 "/tmp/physical/raw.cc"
)delim";
/*
# 1 "/tmp/physical/comment.cc"
*/
# 6 "/stable/next.h" 1
int n = 1'000;
const char *other = u8R"(
"
# 1 "/tmp/physical/other.cc"
)";
# 9 "/stable/source.cc" 2
"##;
        assert_eq!(paths.preprocessed_key_bytes(input).as_ref(), expected);
    }

    #[test]
    fn cargo_output_mapping_does_not_depend_on_package_build_hash() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let compiler = Gcc {
            gplusplus: true,
            version: Some("16.2.1".into()),
            assembler_digest: None,
        };
        let mut identities = Vec::new();
        for (session, package) in [("first", "package-abc"), ("second", "package-def")] {
            let root = tmp.path().join(session);
            let out_dir = root.join("debug/build").join(package).join("out");
            let cwd = out_dir.join("build");
            fs::create_dir_all(&cwd)?;
            fs::write(root.join("CACHEDIR.TAG"), b"")?;
            let source = out_dir.join("src/file.cc");
            let input = source.as_os_str().to_owned();
            let arguments = vec!["-c".into(), input, "-o".into(), "file.o".into()];
            let env = vec![
                ("OUT_DIR".into(), out_dir.into_os_string()),
                (
                    "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                    tmp.path().join("target").into_os_string(),
                ),
            ];
            let CompilerArguments::Ok(args) = compiler.parse_arguments(&arguments, &cwd, &env)
            else {
                anyhow::bail!("failed to parse ordinary C++ arguments");
            };
            assert_eq!(args.language, Language::Cxx);
            let paths = NativeCargoPaths::discover(
                &env,
                CCompilerKind::Gcc,
                compiler.version().as_deref(),
                &args,
            )
            .expect("Cargo context is sufficient");
            let marker = format!("# 1 \"{}\"\n", source.display());
            let content = paths.preprocessed_key_bytes(marker.as_bytes());
            assert_eq!(
                content.as_ref(),
                b"# 1 \"/__sccache/cargo/out/src/file.cc\"\n"
            );
            identities.push(paths.context_digest(&args, &cwd, &content));
        }
        assert_eq!(identities[0], identities[1]);
        Ok(())
    }
}
