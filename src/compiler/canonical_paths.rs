use crate::dist;
use std::collections::HashSet;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RootMapping {
    aliases: Vec<PathBuf>,
    canonical: PathBuf,
}

impl RootMapping {
    fn new(physical: &Path, canonical: &str) -> Self {
        let mut aliases = vec![physical.to_path_buf()];
        if let Ok(real) = physical.canonicalize()
            && real != physical
        {
            aliases.push(real);
        }
        Self {
            aliases,
            canonical: PathBuf::from(canonical),
        }
    }

    fn to_canonical(&self, path: &Path) -> Option<PathBuf> {
        self.aliases.iter().find_map(|physical| {
            path.strip_prefix(physical)
                .ok()
                .map(|suffix| self.canonical.join(suffix))
        })
    }

    #[cfg(test)]
    fn to_physical(&self, path: &Path) -> Option<PathBuf> {
        path.strip_prefix(&self.canonical)
            .ok()
            .map(|suffix| self.aliases[0].join(suffix))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalRustPaths {
    roots: Vec<RootMapping>,
    pub(crate) build_root: PathBuf,
    pub(crate) target_root: PathBuf,
    pub(crate) intermediate_root: Option<PathBuf>,
    pub(crate) cargo_home: Option<PathBuf>,
    pub(crate) rust_root: PathBuf,
    clippy_config_dir: Option<PathBuf>,
}

pub(super) fn env_value(env: &[(OsString, OsString)], name: &str) -> Option<PathBuf> {
    env.iter()
        .rev()
        .find(|(k, _)| k == name)
        .map(|(_, v)| PathBuf::from(v))
}

fn enabled(env: &[(OsString, OsString)]) -> bool {
    env.iter()
        .rev()
        .find(|(k, _)| k == "SCCACHE_EXPERIMENTAL_CANONICAL_RUST")
        .is_some_and(|(_, v)| v == "1")
}

fn topmost_cargo_root(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .filter(|ancestor| ancestor.join("Cargo.toml").is_file())
        .last()
        .map(Path::to_owned)
}

fn has_cargo_root_marker(path: &Path) -> bool {
    path.join("CACHEDIR.TAG").is_file() || path.join(".rustc_info.json").is_file()
}

fn cargo_target_directory_name(target: &OsStr) -> Option<&OsStr> {
    let path = Path::new(target);
    if path.extension().is_some_and(|ext| ext == "json") {
        path.file_stem()
    } else {
        path.file_name()
    }
}

fn marked_cargo_root(path: &Path, target: Option<&OsStr>) -> Option<PathBuf> {
    let nearest = path.ancestors().find(|path| has_cargo_root_marker(path))?;
    // Cargo marks both the shared build root and its target-specific immediate
    // child. A cross-target invocation can consume host proc macros and target
    // metadata simultaneously. Promote only a directory whose name matches the
    // actual compiler target, not an arbitrary nested marked cache directory.
    if let Some(target_name) = target.and_then(cargo_target_directory_name)
        && nearest.file_name() == Some(target_name)
        && let Some(parent) = nearest.parent().filter(|path| has_cargo_root_marker(path))
    {
        return Some(parent.to_owned());
    }
    Some(nearest.to_owned())
}

pub(super) fn target_root_from_out_dir_path(
    out_dir: &Path,
    target: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(root) = marked_cargo_root(out_dir, target) {
        return Some(root);
    }

    // Before Cargo writes its root marker, OUT_DIR still identifies the
    // profile via build/<package-hash>/out or build/<package>/<hash>/out.
    if out_dir.file_name()? != "out" {
        return None;
    }
    let unit = out_dir.parent()?;
    let parent = unit.parent()?;
    // Cargo's new layout separates the hexadecimal unit fingerprint from the
    // package name. This also handles a package or a profile named "build".
    let separate_fingerprint = unit
        .file_name()?
        .as_encoded_bytes()
        .iter()
        .all(u8::is_ascii_hexdigit);
    let build = if separate_fingerprint {
        parent.parent()?
    } else {
        parent
    };
    (build.file_name()? == "build")
        .then(|| build.parent().map(Path::to_owned))
        .flatten()
}

fn target_root_from_out_dir(
    env: &[(OsString, OsString)],
    target: Option<&OsStr>,
) -> Option<PathBuf> {
    target_root_from_out_dir_path(&env_value(env, "OUT_DIR")?, target)
}

fn target_root_from_output_dir(output_dir: &Path, target: Option<&OsStr>) -> Option<PathBuf> {
    // --out-dir is not restricted to Cargo's OUT_DIR shape: it can be
    // deps/, examples/, a cross-target directory, or the build-script tree.
    // Require a Cargo root marker instead of guessing from path components.
    marked_cargo_root(output_dir, target)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RustEnvironmentPath {
    Ordinary,
    Temporary,
    Home,
    ClippyConfig,
    CargoBuildDir,
    Cargo,
    Rustc,
    Rustdoc,
    Other,
}

impl RustEnvironmentPath {
    pub(super) fn classify(name: &OsStr) -> Self {
        match name.to_str() {
            Some("TMPDIR" | "TMP" | "TEMP" | "TEMPDIR") => Self::Temporary,
            Some("HOME") => Self::Home,
            Some("CLIPPY_CONF_DIR") => Self::ClippyConfig,
            Some("CARGO") => Self::Cargo,
            Some("CARGO_BUILD_BUILD_DIR") => Self::CargoBuildDir,
            Some("RUSTC") => Self::Rustc,
            Some("RUSTDOC") => Self::Rustdoc,
            Some(
                "CARGO_HOME"
                | "CARGO_INSTALL_ROOT"
                | "CARGO_MANIFEST_DIR"
                | "CARGO_MANIFEST_PATH"
                | "CARGO_TARGET_DIR"
                | "CARGO_TARGET_TMPDIR"
                | "OUT_DIR"
                | "PWD",
            ) => Self::Ordinary,
            Some(name) if name.starts_with("CARGO_BIN_EXE_") => Self::Ordinary,
            _ => Self::Other,
        }
    }

    // Diagnostic disclosure is intentionally narrower than canonicalization.
    pub(super) const fn disclose_in_shadow(self) -> bool {
        matches!(
            self,
            Self::Ordinary | Self::Temporary | Self::Cargo | Self::Rustc | Self::Rustdoc
        )
    }
}

fn embedded_path_match_is_token(text: &str, start: usize, end: usize) -> bool {
    let prefix = &text[..start];
    let token_start = prefix
        .rfind(|c: char| {
            matches!(
                c,
                '=' | ','
                    | ';'
                    | ':'
                    | ' '
                    | '\t'
                    | '\n'
                    | '\r'
                    | '"'
                    | '\''
                    | '('
                    | '['
                    | '{'
                    | '@'
            )
        })
        .map_or(0, |index| index + 1);
    let token_prefix = &prefix[token_start..];
    let before_ok = !token_prefix.contains('/') && !token_prefix.contains('\\');

    let after_ok = end == text.len()
        || text[end..].chars().next().is_some_and(|c| {
            matches!(
                c,
                '/' | '\\'
                    | '='
                    | ','
                    | ';'
                    | ':'
                    | ' '
                    | '\t'
                    | '\n'
                    | '\r'
                    | '"'
                    | '\''
                    | ')'
                    | ']'
                    | '}'
            )
        });

    before_ok && after_ok
}

fn replace_embedded_path(text: &str, physical: &str, canonical: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut copied_until = 0;

    for (start, _) in text.match_indices(physical) {
        if start < copied_until {
            continue;
        }
        let end = start + physical.len();
        if embedded_path_match_is_token(text, start, end) {
            output.push_str(&text[copied_until..start]);
            output.push_str(canonical);
            copied_until = end;
        }
    }

    output.push_str(&text[copied_until..]);
    output
}

/// Resolve an operand against the invocation's physical cwd before applying
/// an independent sandbox root mapping. Never erase a symlink traversal.
pub(super) fn physical_operand(cwd: &Path, operand: &Path) -> Option<PathBuf> {
    let absolute = cwd.join(operand);
    let mut result = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                if result.is_symlink() || !result.is_dir() {
                    return None;
                }
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other),
        }
    }
    Some(result)
}

impl CanonicalRustPaths {
    #[cfg(test)]
    pub(crate) fn from_env(
        env: &[(OsString, OsString)],
        cwd: &Path,
        rust_root: &Path,
    ) -> Option<Self> {
        Self::from_env_with_output_dir(env, cwd, rust_root, None, None)
    }

    pub(crate) fn from_env_with_output_dir(
        env: &[(OsString, OsString)],
        cwd: &Path,
        rust_root: &Path,
        output_dir: Option<&Path>,
        target: Option<&OsStr>,
    ) -> Option<Self> {
        if !enabled(env) {
            return None;
        }

        let build_root = env_value(env, "SCCACHE_CANONICAL_BUILD_ROOT")
            .or_else(|| topmost_cargo_root(cwd))
            .or_else(|| {
                env_value(env, "CARGO_MANIFEST_DIR")
                    .and_then(|manifest_dir| topmost_cargo_root(&manifest_dir))
            })?;

        let environment_target = env_value(env, "TARGET");
        let target = target.or_else(|| environment_target.as_deref().map(Path::as_os_str));
        let actual_build_root = target_root_from_out_dir(env, target)
            .or_else(|| output_dir.and_then(|path| target_root_from_output_dir(path, target)));
        let target_root = env_value(env, "SCCACHE_CANONICAL_TARGET_ROOT")
            .or_else(|| env_value(env, "CARGO_TARGET_DIR"))
            .or_else(|| actual_build_root.clone())
            .unwrap_or_else(|| build_root.join("target"));
        // Cargo can keep final deliverables under target_directory while its
        // compiler outputs and generated OUT_DIR inputs live in a separate
        // per-invocation build-dir. Mapping only target_directory makes those
        // compiler inputs unstable or rejects them outright.
        let intermediate_root = actual_build_root
            .filter(|root| root != &target_root && !root.starts_with(&target_root));
        let cargo_home = env_value(env, "SCCACHE_CANONICAL_CARGO_HOME")
            .or_else(|| env_value(env, "CARGO_HOME"))
            .or_else(|| env_value(env, "HOME").map(|home| home.join(".cargo")));

        let mut roots = vec![RootMapping::new(&target_root, "/target")];
        if let Some(root) = intermediate_root.as_ref() {
            roots.push(RootMapping::new(root, "/intermediate"));
        }
        roots.push(RootMapping::new(&build_root, "/build"));
        if let Some(ref cargo_home) = cargo_home {
            roots.push(RootMapping::new(cargo_home, "/cargo"));

            // cargo-ephemeral can materialize registry sources outside
            // CARGO_HOME while keeping the persistent registry archives in
            // CARGO_HOME. Treat that process-scoped source tree as the same
            // canonical /cargo/registry/src namespace so cache keys remain
            // stable and the bubblewrap compiler sandbox can see the cwd.
            if let Some(ephemeral_registry_src) = env_value(env, "EPHEMERAL_CARGO_REGISTRY_SRC") {
                let persistent_registry_src = cargo_home.join("registry/src");
                let physical_ephemeral = ephemeral_registry_src
                    .canonicalize()
                    .unwrap_or_else(|_| ephemeral_registry_src.clone());
                let physical_persistent = persistent_registry_src
                    .canonicalize()
                    .unwrap_or(persistent_registry_src);

                if physical_ephemeral != physical_persistent {
                    roots.push(RootMapping::new(
                        &ephemeral_registry_src,
                        "/cargo/registry/src",
                    ));
                }
            }
        }
        roots.push(RootMapping::new(rust_root, "/rust"));

        // Strict Clippy may be configured by a separate policy checkout, not
        // located under the crate's /build root. Make it visible to both the
        // local canonical sandbox and the distributed worker at a stable path.
        let clippy_config_dir = env_value(env, "CLIPPY_CONF_DIR").map(|path| {
            let absolute = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            absolute.canonicalize().unwrap_or(absolute)
        });
        if let Some(config_dir) = clippy_config_dir.as_ref()
            && config_dir.is_dir()
            && !roots.iter().any(|root| {
                root.to_canonical(config_dir).is_some()
                    || config_dir
                        .canonicalize()
                        .is_ok_and(|real| root.to_canonical(&real).is_some())
            })
        {
            roots.push(RootMapping::new(config_dir, "/clippy-config"));
        }

        Some(Self {
            roots,
            build_root,
            target_root,
            intermediate_root,
            cargo_home,
            rust_root: rust_root.to_owned(),
            clippy_config_dir,
        })
    }

    pub(crate) fn to_canonical(&self, path: &Path) -> PathBuf {
        self.roots
            .iter()
            .find_map(|root| root.to_canonical(path))
            .unwrap_or_else(|| path.to_owned())
    }

    #[cfg(test)]
    pub(crate) fn to_physical(&self, path: &Path) -> PathBuf {
        self.roots
            .iter()
            .find_map(|root| root.to_physical(path))
            .unwrap_or_else(|| path.to_owned())
    }

    pub(crate) fn os_to_canonical(&self, value: &OsStr) -> OsString {
        let path = Path::new(value);
        if path.is_absolute() {
            self.to_canonical(path).into_os_string()
        } else {
            value.to_owned()
        }
    }

    pub(crate) fn normalize_os_value(&self, value: &OsStr) -> OsString {
        let Some(mut text) = value.to_str().map(str::to_owned) else {
            return self.os_to_canonical(value);
        };

        let mut replacements = self
            .roots
            .iter()
            .flat_map(|root| {
                root.aliases.iter().filter_map(move |alias| {
                    alias.to_str().map(|alias| {
                        (
                            alias.to_owned(),
                            root.canonical.to_string_lossy().into_owned(),
                        )
                    })
                })
            })
            .collect::<Vec<_>>();
        replacements.sort_by_key(|(physical, _)| std::cmp::Reverse(physical.len()));

        for (physical, canonical) in replacements {
            text = replace_embedded_path(&text, &physical, &canonical);
        }
        text.into()
    }

    pub(crate) fn canonical_cwd(&self, cwd: &Path) -> PathBuf {
        self.to_canonical(cwd)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn canonical_executable(&self, executable: &Path) -> PathBuf {
        self.to_canonical(executable)
    }

    pub(crate) fn root_is_known(&self, path: &Path) -> bool {
        let candidate = path.canonicalize().unwrap_or_else(|_| path.to_owned());
        self.roots.iter().any(|root| {
            root.aliases
                .iter()
                .any(|alias| candidate.starts_with(alias))
        })
    }

    pub(crate) fn env_to_canonical(
        &self,
        env: &[(OsString, OsString)],
    ) -> Vec<(OsString, OsString)> {
        self.env_to_canonical_preserving(env, &HashSet::new())
    }

    /// Canonicalize the compiler environment while preserving values that rustc
    /// reported as explicit environment dependencies. Values consumed through
    /// `env!`/`option_env!` are observable program data, so rewriting them before
    /// compilation changes the resulting program rather than merely its cache key.
    pub(crate) fn env_to_canonical_preserving(
        &self,
        env: &[(OsString, OsString)],
        preserve: &HashSet<OsString>,
    ) -> Vec<(OsString, OsString)> {
        env.iter()
            .filter(|(k, _)| {
                k != "SCCACHE_EXPERIMENTAL_CANONICAL_RUST"
                    && !k.to_string_lossy().starts_with("SCCACHE_CANONICAL_")
            })
            .map(|(k, v)| {
                let value = if preserve.contains(k) {
                    v.clone()
                } else {
                    self.env_value_to_canonical(k, v)
                };
                (k.clone(), value)
            })
            .collect()
    }

    pub(crate) fn env_value_to_canonical(&self, name: &OsStr, value: &OsStr) -> OsString {
        match RustEnvironmentPath::classify(name) {
            RustEnvironmentPath::Temporary => OsString::from("/tmp"),
            RustEnvironmentPath::Home => OsString::from("/tmp/home"),
            RustEnvironmentPath::ClippyConfig => self.clippy_config_dir.as_ref().map_or_else(
                || self.normalize_os_value(value),
                |dir| self.to_canonical(dir).into_os_string(),
            ),
            RustEnvironmentPath::CargoBuildDir => {
                // Cargo expands the standard workspace hash template before
                // invoking rustc, but leaves the original template in its
                // inherited environment. Map only a template that actually
                // produced this invocation's discovered output root. The
                // physical per-invocation lease must not enter the action key.
                let root = self.intermediate_root.as_ref().unwrap_or(&self.target_root);
                let template = Path::new(value);
                if template.file_name() == Some(OsStr::new("{workspace-path-hash}"))
                    && let Some(parent) = template.parent()
                    && let Ok(suffix) = root.strip_prefix(parent)
                {
                    let components = suffix.components().collect::<Vec<_>>();
                    if components.len() == 2
                        && components.iter().all(|component| {
                            let bytes = component.as_os_str().as_encoded_bytes();
                            !bytes.is_empty() && bytes.iter().all(u8::is_ascii_hexdigit)
                        })
                    {
                        return self.to_canonical(root).into_os_string();
                    }
                }
                self.os_to_canonical(value)
            }
            RustEnvironmentPath::Cargo => {
                // Cargo may invoke procedural macros that call Cargo again. A
                // site wrapper may not exist on the worker; use packaged Cargo.
                if self.rust_root.join("bin/cargo.real").is_file() {
                    OsString::from("/rust/bin/cargo.real")
                } else {
                    OsString::from("/rust/bin/cargo")
                }
            }
            RustEnvironmentPath::Rustc => OsString::from("/rust/bin/rustc"),
            RustEnvironmentPath::Rustdoc => OsString::from("/rust/bin/rustdoc"),
            RustEnvironmentPath::Ordinary => self.os_to_canonical(value),
            RustEnvironmentPath::Other => self.normalize_os_value(value),
        }
    }

    pub(crate) fn add_to_transformer(&self, transformer: &mut dist::PathTransformer) {
        for root in &self.roots {
            transformer
                .add_root_mapping(root.aliases[0].clone(), &root.canonical.to_string_lossy());
            for alias in root.aliases.iter().skip(1) {
                transformer.add_root_mapping(alias.clone(), &root.canonical.to_string_lossy());
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bwrap_arguments(
        &self,
        executable: &Path,
        arguments: &[OsString],
        cwd: &Path,
    ) -> Vec<OsString> {
        let mut out = self.bwrap_mount_arguments();
        out.extend([
            OsString::from("--chdir"),
            self.canonical_cwd(cwd).into_os_string(),
            OsString::from("--"),
            self.canonical_executable(executable).into_os_string(),
        ]);
        out.extend(arguments.iter().map(|arg| self.normalize_os_value(arg)));
        out
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn bwrap_mount_arguments(&self) -> Vec<OsString> {
        let mut out = Vec::<OsString>::new();

        macro_rules! push {
            ($value:expr) => {
                out.push(OsString::from($value))
            };
        }

        push!("--die-with-parent");
        push!("--tmpfs");
        push!("/");
        push!("--proc");
        push!("/proc");
        push!("--dev-bind");
        push!("/dev");
        push!("/dev");

        for system in ["/usr", "/usr/local", "/etc", "/bin", "/lib", "/lib64"] {
            if Path::new(system).exists() {
                push!("--ro-bind");
                push!(system);
                push!(system);
            }
        }

        for (physical, virtual_path) in self.mappings() {
            if physical.exists() {
                if matches!(virtual_path.to_str(), Some("/target" | "/intermediate")) {
                    push!("--bind");
                } else {
                    push!("--ro-bind");
                }
                out.push(physical.as_os_str().to_owned());
            } else {
                push!("--dir");
            }
            out.push(virtual_path.as_os_str().to_owned());
        }

        // Set up the sandbox temporary filesystem before mounting declared
        // physical aliases below. Cargo target roots commonly live under /tmp;
        // mounting an alias first and then replacing /tmp with a tmpfs would
        // hide it from rustc while preserved OUT_DIR values still point at it.
        push!("--tmpfs");
        push!("/tmp");
        push!("--dir");
        push!("/tmp/home");

        // Build scripts can generate Rust source containing absolute paths from
        // their physical OUT_DIR/CARGO_MANIFEST_DIR. The rustc invocation is
        // canonicalized to /target and /build, but include_bytes!/include_str!
        // in that generated source still resolves the literal physical path.
        //
        // Keep only the declared roots available at their physical aliases as
        // compatibility mounts. Compiler arguments/environment remain
        // canonical, and any literal physical path embedded in an input file
        // remains part of that file's cache-key material.
        let canonical_mounts = self
            .roots
            .iter()
            .map(|root| root.canonical.as_path())
            .collect::<Vec<_>>();
        let mut physical_aliases = Vec::new();
        for root in &self.roots {
            let writable = matches!(root.canonical.to_str(), Some("/target" | "/intermediate"));
            for alias in &root.aliases {
                if !alias.exists() || canonical_mounts.contains(&alias.as_path()) {
                    continue;
                }
                physical_aliases.push((alias.as_path(), writable));
            }
        }
        physical_aliases
            .sort_by_key(|(alias, writable)| (alias.components().count(), u8::from(*writable)));

        for (alias, writable) in physical_aliases {
            if writable {
                push!("--bind");
            } else {
                push!("--ro-bind");
            }
            out.push(alias.as_os_str().to_owned());
            out.push(alias.as_os_str().to_owned());
        }

        out
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn mappings(&self) -> impl Iterator<Item = (&Path, &Path)> {
        self.roots
            .iter()
            .map(|root| (root.aliases[0].as_path(), root.canonical.as_path()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn rust_environment_classification_preserves_disclosure_policy() {
        use super::RustEnvironmentPath as Kind;
        use std::ffi::OsStr;
        for (name, expected, disclose) in [
            ("CARGO_BIN_EXE_example", Kind::Ordinary, true),
            ("CARGO_MANIFEST_PATH", Kind::Ordinary, true),
            ("TMPDIR", Kind::Temporary, true),
            ("TEMPDIR", Kind::Temporary, true),
            ("HOME", Kind::Home, false),
            ("CLIPPY_CONF_DIR", Kind::ClippyConfig, false),
            ("CARGO", Kind::Cargo, true),
            ("CARGO_BUILD_BUILD_DIR", Kind::CargoBuildDir, false),
            ("RUSTC", Kind::Rustc, true),
            ("RUSTDOC", Kind::Rustdoc, true),
            ("CARGO_REGISTRIES_PRIVATE_TOKEN", Kind::Other, false),
        ] {
            let kind = Kind::classify(OsStr::new(name));
            assert_eq!(kind, expected, "{name}");
            assert_eq!(kind.disclose_in_shadow(), disclose, "{name}");
        }
    }

    #[test]
    fn maps_roots_with_target_precedence() {
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
            (
                "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                "/work/a/target".into(),
            ),
            (
                "SCCACHE_CANONICAL_CARGO_HOME".into(),
                "/home/u/.cargo".into(),
            ),
        ];
        let roots =
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/opt/rust"))
                .unwrap();
        assert_eq!(
            roots.to_canonical(Path::new("/work/a/src/lib.rs")),
            PathBuf::from("/build/src/lib.rs")
        );
        assert_eq!(
            roots.to_canonical(Path::new("/work/a/target/release/deps/x.rlib")),
            PathBuf::from("/target/release/deps/x.rlib")
        );
        assert_eq!(
            roots.to_canonical(Path::new("/home/u/.cargo/registry/src/x/lib.rs")),
            PathBuf::from("/cargo/registry/src/x/lib.rs")
        );
        assert_eq!(
            roots.to_canonical(Path::new("/opt/rust/lib/rustlib/x")),
            PathBuf::from("/rust/lib/rustlib/x")
        );
        assert_eq!(
            roots.to_physical(Path::new("/build/src/lib.rs")),
            PathBuf::from("/work/a/src/lib.rs")
        );
    }

    #[test]
    fn infers_shared_target_root_from_out_dir_for_registry_dependency() {
        let temp = tempfile::tempdir().unwrap();
        let registry_crate = temp.path().join("cargo/registry/src/index/serde_core");
        let target = temp.path().join("workspace-target");
        let out_dir = target.join("debug/build/serde_core-hash/out");
        std::fs::create_dir_all(&registry_crate).unwrap();
        std::fs::create_dir_all(&out_dir).unwrap();
        std::fs::write(
            registry_crate.join("Cargo.toml"),
            "[package]\nname='serde_core'\nversion='1.0.0'\n",
        )
        .unwrap();
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n",
        )
        .unwrap();
        let generated = out_dir.join("private.rs");
        std::fs::write(&generated, "pub const PRIVATE: () = ();\n").unwrap();

        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("OUT_DIR".into(), out_dir.into_os_string()),
        ];
        let roots =
            CanonicalRustPaths::from_env(&env, &registry_crate, Path::new("/rust")).unwrap();

        assert_eq!(roots.target_root, target);
        assert!(roots.root_is_known(&generated));
        assert_eq!(
            roots.to_canonical(&generated),
            PathBuf::from("/target/debug/build/serde_core-hash/out/private.rs")
        );
    }

    #[test]
    fn discovers_registry_dependency_target_without_out_dir_or_target_env()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let registry = temp.path().join("cargo/registry/src/index/hashbrown");
        let target = temp.path().join("workspace/target");
        let output = target.join("debug/deps");
        std::fs::create_dir_all(&registry)?;
        std::fs::create_dir_all(&output)?;
        std::fs::write(
            registry.join("Cargo.toml"),
            "[package]\nname='hashbrown'\nversion='0.1.0'\n",
        )?;
        std::fs::write(
            target.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55",
        )?;
        let dependency = output.join("liballocator_api2-abcdef.rmeta");
        std::fs::write(&dependency, b"metadata")?;
        let env = vec![("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into())];

        let roots = CanonicalRustPaths::from_env_with_output_dir(
            &env,
            &registry,
            Path::new("/rust"),
            Some(&output),
            None,
        )
        .expect("compiler output must identify the shared target");
        assert_eq!(roots.target_root, target);
        assert!(roots.root_is_known(&dependency));
        assert_eq!(
            roots.to_canonical(&dependency),
            Path::new("/target/debug/deps/liballocator_api2-abcdef.rmeta")
        );
        Ok(())
    }

    #[test]
    fn canonicalizes_separate_persistent_and_ephemeral_cargo_output_roots() {
        let temp = tempfile::tempdir().unwrap();
        let registry_crate = temp.path().join("registry/crate");
        let persistent_target = temp.path().join("workspace/target");
        std::fs::create_dir_all(&registry_crate).unwrap();
        std::fs::create_dir_all(&persistent_target).unwrap();
        std::fs::write(
            registry_crate.join("Cargo.toml"),
            "[package]\nname='crate'\nversion='0.1.0'\n",
        )
        .unwrap();

        let mut normalized = Vec::new();
        for temporary_name in [
            "cargo-ephemeral-build-first",
            "cargo-ephemeral-build-second",
        ] {
            let lease = temp.path().join(temporary_name);
            let intermediate = lease.join("12/3456789abcdeff");
            let out_dir = intermediate.join("debug/build/some-crate-hash/out");
            let dep = intermediate.join("debug/deps/libsome_crate-hash.rmeta");
            let compiler_output = intermediate.join("debug/deps");
            std::fs::create_dir_all(&out_dir).unwrap();
            std::fs::create_dir_all(&compiler_output).unwrap();
            std::fs::write(
                intermediate.join("CACHEDIR.TAG"),
                "Signature: 8a477f597d28d172789f06886806bc55",
            )
            .unwrap();
            let env = vec![
                ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
                (
                    "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                    persistent_target.clone().into_os_string(),
                ),
                (
                    "SCCACHE_CANONICAL_TARGET_ROOT_ORIGIN".into(),
                    "codeandsolder-cargo-wrapper".into(),
                ),
                ("OUT_DIR".into(), out_dir.clone().into_os_string()),
                (
                    "CARGO_BUILD_BUILD_DIR".into(),
                    lease.join("{workspace-path-hash}").into_os_string(),
                ),
            ];
            let roots = CanonicalRustPaths::from_env_with_output_dir(
                &env,
                &registry_crate,
                Path::new("/rust"),
                Some(&compiler_output),
                None,
            )
            .unwrap();
            assert_eq!(roots.target_root, persistent_target);
            let key = OsStr::new("CARGO_BUILD_BUILD_DIR");
            let physical = lease.join("{workspace-path-hash}");
            assert_eq!(
                roots.env_value_to_canonical(key, physical.as_os_str()),
                "/intermediate"
            );
            let preserved =
                roots.env_to_canonical_preserving(&env, &HashSet::from([key.to_owned()]));
            assert_eq!(
                env_value(&preserved, "CARGO_BUILD_BUILD_DIR"),
                Some(physical)
            );

            assert_eq!(
                roots.intermediate_root.as_deref(),
                Some(intermediate.as_path())
            );
            assert_eq!(
                roots.to_canonical(&compiler_output),
                Path::new("/intermediate/debug/deps")
            );
            assert_eq!(
                roots.to_canonical(&dep),
                Path::new("/intermediate/debug/deps/libsome_crate-hash.rmeta")
            );
            assert_eq!(
                roots.to_canonical(&out_dir),
                Path::new("/intermediate/debug/build/some-crate-hash/out")
            );
            assert!(roots.root_is_known(&dep));
            assert!(roots.root_is_known(&out_dir));
            assert_eq!(
                roots.to_canonical(&persistent_target.join("release/final.rlib")),
                Path::new("/target/release/final.rlib"),
            );
            let canonical_out_dir =
                roots.env_value_to_canonical(OsStr::new("OUT_DIR"), out_dir.as_os_str());
            normalized.push(canonical_out_dir.clone());
            assert_eq!(
                canonical_out_dir,
                OsStr::new("/intermediate/debug/build/some-crate-hash/out")
            );

            #[cfg(target_os = "linux")]
            {
                let args =
                    roots.bwrap_arguments(Path::new("/rust/bin/rustc"), &[], &registry_crate);
                assert!(args.windows(3).any(|three| {
                    three[0] == "--bind"
                        && three[1] == intermediate.as_os_str()
                        && three[2] == "/intermediate"
                }));
                assert!(args.windows(3).any(|three| {
                    three[0] == "--bind"
                        && three[1] == persistent_target.as_os_str()
                        && three[2] == "/target"
                }));
            }
        }
        assert_eq!(normalized[0], normalized[1]);
    }

    #[test]
    fn cross_target_build_root_includes_host_proc_macros() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace");
        let persistent = source.join("target");
        std::fs::create_dir_all(&persistent).unwrap();
        std::fs::write(source.join("Cargo.toml"), "[workspace]\n").unwrap();
        let tag = "Signature: 8a477f597d28d172789f06886806bc55\n";
        std::fs::write(temp.path().join("CACHEDIR.TAG"), tag).unwrap();
        for session in ["session-a", "session-b"] {
            let shared = temp.path().join(session).join("workspace-hash");
            let target = shared.join("x86_64-unknown-uefi");
            let generated = target.join("release/build/consumer/0a25ece00a9f4300/out");
            let output = target.join("release/build/consumer/1c1e9eb0228676a4/out");
            let host_proc_macro = shared.join(
                "release/build/uefi-macros/7a8cc8f45c370789/out/libuefi_macros-7a8cc8f45c370789.so",
            );
            for path in [
                generated.as_path(),
                output.as_path(),
                host_proc_macro.parent().unwrap(),
            ] {
                std::fs::create_dir_all(path).unwrap();
            }
            std::fs::write(shared.join("CACHEDIR.TAG"), tag).unwrap();
            std::fs::write(target.join("CACHEDIR.TAG"), tag).unwrap();
            let base_env = vec![
                ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
                (
                    "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                    persistent.clone().into_os_string(),
                ),
            ];
            let mut with_out_dir = base_env.clone();
            with_out_dir.push(("OUT_DIR".into(), generated.into_os_string()));
            for env in [&base_env, &with_out_dir] {
                let roots = CanonicalRustPaths::from_env_with_output_dir(
                    env,
                    &source,
                    Path::new("/rust"),
                    Some(&output),
                    Some(OsStr::new("x86_64-unknown-uefi")),
                )
                .unwrap();
                assert_eq!(roots.intermediate_root.as_deref(), Some(shared.as_path()));
                assert!(roots.root_is_known(&host_proc_macro));
                assert_eq!(
                    roots.to_canonical(&host_proc_macro),
                    Path::new(
                        "/intermediate/release/build/uefi-macros/7a8cc8f45c370789/out/libuefi_macros-7a8cc8f45c370789.so"
                    )
                );
                assert_eq!(
                    roots.to_canonical(&output),
                    Path::new(
                        "/intermediate/x86_64-unknown-uefi/release/build/consumer/1c1e9eb0228676a4/out"
                    )
                );
            }
            // An unrelated nested marked cache must not be promoted.
            for hint in [None, Some(OsStr::new("other-target"))] {
                assert_eq!(marked_cargo_root(&output, hint), Some(target.clone()));
            }
            assert_eq!(
                marked_cargo_root(&output, Some(OsStr::new("/specs/x86_64-unknown-uefi.json"))),
                Some(shared)
            );
        }
    }

    #[test]
    fn markerless_cargo_build_unit_layouts_infer_profile_root() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("shared/debug");
        for suffix in ["build/pkg-abc/out", "build/pkg/abc/out"] {
            assert_eq!(
                target_root_from_out_dir_path(&profile.join(suffix), None),
                Some(profile.clone())
            );
        }
        assert_eq!(
            target_root_from_out_dir_path(&profile.join("build/pkg/abc/not-out"), None),
            None
        );
    }

    #[test]
    fn infers_ephemeral_build_dir_from_rustc_output_without_out_dir_env() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("workspace");
        let persistent_target = source.join("target");
        let intermediate = temp.path().join("cargo-ephemeral-build-RANDOM/hash");
        let output_dir = intermediate.join("wasm32-unknown-unknown/debug/deps");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&persistent_target).unwrap();
        std::fs::create_dir_all(&output_dir).unwrap();
        std::fs::write(source.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(
            intermediate.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55",
        )
        .unwrap();
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                persistent_target.into_os_string(),
            ),
        ];
        let roots = CanonicalRustPaths::from_env_with_output_dir(
            &env,
            &source,
            Path::new("/rust"),
            Some(&output_dir),
            Some(OsStr::new("wasm32-unknown-unknown")),
        )
        .unwrap();
        assert_eq!(
            roots.intermediate_root.as_deref(),
            Some(intermediate.as_path())
        );
        assert_eq!(
            roots.to_canonical(&output_dir),
            Path::new("/intermediate/wasm32-unknown-unknown/debug/deps")
        );
    }

    #[test]
    fn rustc_uses_ephemeral_output_root_without_out_dir_env() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let persistent = source.join("target");
        let intermediate = temp.path().join("cargo-ephemeral-build-FALLBACK/hash");
        let output_dir = intermediate.join("debug/deps");
        std::fs::create_dir_all(&output_dir).unwrap();
        std::fs::create_dir_all(&persistent).unwrap();
        std::fs::write(source.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(
            intermediate.join("CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55",
        )
        .unwrap();
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                persistent.into_os_string(),
            ),
        ];
        let roots = CanonicalRustPaths::from_env_with_output_dir(
            &env,
            &source,
            Path::new("/rust"),
            Some(&output_dir),
            None,
        )
        .unwrap();
        assert_eq!(
            roots.to_canonical(&output_dir),
            Path::new("/intermediate/debug/deps")
        );
    }

    #[test]
    fn maps_ephemeral_registry_source_into_cargo_namespace() {
        let temp = tempfile::tempdir().unwrap();
        let build = temp.path().join("build");
        let target = temp.path().join("target");
        let cargo_home = temp.path().join("cargo");
        let persistent_registry = cargo_home.join("registry/src");
        let ephemeral_registry = temp.path().join("ephemeral-registry");

        std::fs::create_dir_all(&build).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&persistent_registry).unwrap();
        std::fs::create_dir_all(ephemeral_registry.join("index/pkg")).unwrap();
        std::fs::write(
            build.join("Cargo.toml"),
            "[workspace]
",
        )
        .unwrap();

        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                build.clone().into_os_string(),
            ),
            ("CARGO_TARGET_DIR".into(), target.into_os_string()),
            ("CARGO_HOME".into(), cargo_home.into_os_string()),
            (
                "EPHEMERAL_CARGO_REGISTRY_SRC".into(),
                ephemeral_registry.clone().into_os_string(),
            ),
        ];

        let roots = CanonicalRustPaths::from_env(&env, &build, Path::new("/rust")).unwrap();
        let source = ephemeral_registry.join("index/pkg/src/lib.rs");
        assert_eq!(
            roots.to_canonical(&source),
            PathBuf::from("/cargo/registry/src/index/pkg/src/lib.rs")
        );
        assert!(roots.root_is_known(&source));

        #[cfg(target_os = "linux")]
        {
            let args = roots.bwrap_arguments(
                Path::new("/rust/bin/rustc"),
                &[source.into_os_string()],
                &ephemeral_registry.join("index/pkg"),
            );
            assert!(args.windows(2).any(|pair| {
                pair[0] == ephemeral_registry.as_os_str()
                    && pair[1] == OsStr::new("/cargo/registry/src")
            }));
            assert!(args.windows(2).any(|pair| {
                pair[0] == OsStr::new("--chdir")
                    && pair[1] == OsStr::new("/cargo/registry/src/index/pkg")
            }));
            assert!(
                args.iter()
                    .any(|arg| arg == OsStr::new("/cargo/registry/src/index/pkg/src/lib.rs"))
            );
        }
    }

    #[test]
    fn normalizes_embedded_root_strings() {
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
            ("SCCACHE_CANONICAL_TARGET_ROOT".into(), "/cache/a".into()),
        ];
        let roots =
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/opt/rust"))
                .unwrap();
        assert_eq!(
            roots.normalize_os_value(OsStr::new("prefix=/work/a/src/lib.rs")),
            OsString::from("prefix=/build/src/lib.rs")
        );
        assert_eq!(
            roots.normalize_os_value(OsStr::new("x=/cache/a/debug;y=/work/a")),
            OsString::from("x=/target/debug;y=/build")
        );
    }

    #[test]
    fn embedded_path_rewrite_respects_token_boundaries() {
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
        ];
        let roots =
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/rust")).unwrap();

        assert_eq!(
            roots.normalize_os_value(OsStr::new("-I/work/a/include")),
            OsString::from("-I/build/include")
        );
        assert_eq!(
            roots.normalize_os_value(OsStr::new("-Wl,-rpath,/work/a/lib")),
            OsString::from("-Wl,-rpath,/build/lib")
        );
        assert_eq!(
            roots.normalize_os_value(OsStr::new("/tmp/work/a/src/lib.rs")),
            OsString::from("/tmp/work/a/src/lib.rs")
        );
        assert_eq!(
            roots.normalize_os_value(OsStr::new("/work/ab/src/lib.rs")),
            OsString::from("/work/ab/src/lib.rs")
        );
        assert_eq!(
            roots.normalize_os_value(OsStr::new("prefix=/work/a;other=/work/a/src")),
            OsString::from("prefix=/build;other=/build/src")
        );
    }

    #[test]
    fn defaults_cargo_home_from_home() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.0.0'\n",
        )
        .unwrap();
        let home = temp.path().join("home");
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("HOME".into(), home.clone().into_os_string()),
        ];
        let roots = CanonicalRustPaths::from_env(&env, temp.path(), Path::new("/rust")).unwrap();
        assert_eq!(roots.cargo_home, Some(home.join(".cargo")));
    }

    #[cfg(unix)]
    #[test]
    fn resolved_root_check_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let build = temp.path().join("build");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(build.join("inside")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(build.join("Cargo.toml"), "[workspace]\n").unwrap();
        std::fs::write(build.join("inside/ok.rs"), "pub fn ok() {}\n").unwrap();
        std::fs::write(outside.join("escape.rs"), "pub fn escape() {}\n").unwrap();

        symlink(build.join("inside"), build.join("inside-link")).unwrap();
        symlink(&outside, build.join("escape-link")).unwrap();

        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                build.clone().into_os_string(),
            ),
        ];
        let roots = CanonicalRustPaths::from_env(&env, &build, Path::new("/rust")).unwrap();

        assert!(roots.root_is_known(&build.join("inside-link/ok.rs")));
        assert!(!roots.root_is_known(&build.join("escape-link/escape.rs")));
    }

    #[test]
    fn preserves_explicit_environment_dependencies() {
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
            ("CARGO_MANIFEST_DIR".into(), "/work/a/crate".into()),
            ("CARGO_TARGET_DIR".into(), "/work/a/target".into()),
        ];
        let roots =
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/rust")).unwrap();
        let preserve = HashSet::from([OsString::from("CARGO_MANIFEST_DIR")]);
        let canonical = roots.env_to_canonical_preserving(&env, &preserve);

        assert_eq!(
            env_value(&canonical, "CARGO_MANIFEST_DIR"),
            Some(PathBuf::from("/work/a/crate"))
        );
        assert_eq!(
            env_value(&canonical, "CARGO_TARGET_DIR"),
            Some(PathBuf::from("/target"))
        );
    }

    #[test]
    fn canonicalizes_cargo_to_packaged_real_binary() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let rust_root = temp.path().join("rust");
        std::fs::create_dir_all(rust_root.join("bin"))?;
        std::fs::write(rust_root.join("bin/cargo.real"), b"cargo")?;

        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
        ];
        let roots = CanonicalRustPaths::from_env(&env, Path::new("/work/a"), &rust_root)
            .ok_or_else(|| anyhow::anyhow!("canonical Rust paths unexpectedly disabled"))?;

        assert_eq!(
            roots.env_value_to_canonical(
                OsStr::new("CARGO"),
                OsStr::new("/usr/local/libexec/sentinelx-bin/cargo"),
            ),
            OsString::from("/rust/bin/cargo.real")
        );
        Ok(())
    }

    #[test]
    fn canonicalizes_cargo_to_standard_packaged_binary() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let rust_root = temp.path().join("rust");
        std::fs::create_dir_all(rust_root.join("bin"))?;
        std::fs::write(rust_root.join("bin/cargo"), b"cargo")?;

        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
        ];
        let roots = CanonicalRustPaths::from_env(&env, Path::new("/work/a"), &rust_root)
            .ok_or_else(|| anyhow::anyhow!("canonical Rust paths unexpectedly disabled"))?;

        assert_eq!(
            roots.env_value_to_canonical(
                OsStr::new("CARGO"),
                OsStr::new("/home/user/.cargo/bin/cargo"),
            ),
            OsString::from("/rust/bin/cargo")
        );
        Ok(())
    }

    #[test]
    fn external_clippy_configuration_is_mounted_and_canonicalized() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let build = temp.path().join("build");
        let policy = temp.path().join("external-policy");
        let rust_root = temp.path().join("rust");
        for dir in [&build, &policy, &rust_root] {
            std::fs::create_dir_all(dir)?;
        }
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                build.clone().into_os_string(),
            ),
            ("CLIPPY_CONF_DIR".into(), policy.clone().into_os_string()),
        ];
        let roots = CanonicalRustPaths::from_env(&env, &build, &rust_root)
            .ok_or_else(|| anyhow::anyhow!("canonical paths disabled"))?;
        assert!(roots.root_is_known(&policy.join("clippy.toml")));
        assert_eq!(
            roots.env_value_to_canonical(OsStr::new("CLIPPY_CONF_DIR"), policy.as_os_str()),
            OsString::from("/clippy-config/")
        );
        let args = roots.bwrap_arguments(
            Path::new("/rust/bin/clippy-driver"),
            &[OsString::from("--version")],
            &build,
        );
        assert!(args.windows(3).any(|a| {
            a[0] == "--ro-bind" && a[1] == policy.as_os_str() && a[2] == "/clippy-config"
        }));
        Ok(())
    }

    #[test]
    fn relative_external_clippy_configuration_resolves_from_compiler_cwd() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let build = temp.path().join("build");
        let policy = temp.path().join("policy");
        std::fs::create_dir_all(&build)?;
        std::fs::create_dir_all(&policy)?;
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                build.clone().into_os_string(),
            ),
            ("CLIPPY_CONF_DIR".into(), OsString::from("../policy")),
        ];
        let roots = CanonicalRustPaths::from_env(&env, &build, Path::new("/rust"))
            .ok_or_else(|| anyhow::anyhow!("canonical paths disabled"))?;
        assert_eq!(
            roots.env_value_to_canonical(OsStr::new("CLIPPY_CONF_DIR"), OsStr::new("../policy")),
            OsString::from("/clippy-config/")
        );
        Ok(())
    }

    #[test]
    fn canonicalizes_common_temp_environment_variables() {
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            ("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into()),
        ];
        let roots =
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/rust")).unwrap();
        for name in ["TMPDIR", "TMP", "TEMP", "TEMPDIR"] {
            assert_eq!(
                roots.env_value_to_canonical(OsStr::new(name), OsStr::new("/host/tmp")),
                OsString::from("/tmp")
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bwrap_uses_empty_dir_for_missing_target_root() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname='x'\nversion='0.0.0'\n",
        )
        .unwrap();
        let missing_target = temp.path().join("missing-target");
        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "CARGO_TARGET_DIR".into(),
                missing_target.clone().into_os_string(),
            ),
        ];
        let roots = CanonicalRustPaths::from_env(&env, temp.path(), Path::new("/rust")).unwrap();
        let args = roots.bwrap_arguments(
            Path::new("/rust/bin/rustc"),
            &[OsString::from("-vV")],
            temp.path(),
        );

        let pairs = args.windows(2).collect::<Vec<_>>();
        assert!(
            pairs
                .iter()
                .any(|pair| pair[0] == "--dir" && pair[1] == "/target"),
            "{args:?}"
        );
        assert!(!args.iter().any(|arg| arg == missing_target.as_os_str()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bwrap_keeps_declared_physical_roots_as_compatibility_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let build = temp.path().join("build");
        let target = temp.path().join("target");
        let cargo_home = temp.path().join("cargo-home");
        let rust_root = temp.path().join("rust");
        std::fs::create_dir_all(&build).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&cargo_home).unwrap();
        std::fs::create_dir_all(&rust_root).unwrap();
        std::fs::write(
            build.join("Cargo.toml"),
            "[workspace]
",
        )
        .unwrap();

        let env = vec![
            ("SCCACHE_EXPERIMENTAL_CANONICAL_RUST".into(), "1".into()),
            (
                "SCCACHE_CANONICAL_BUILD_ROOT".into(),
                build.clone().into_os_string(),
            ),
            (
                "SCCACHE_CANONICAL_TARGET_ROOT".into(),
                target.clone().into_os_string(),
            ),
            (
                "SCCACHE_CANONICAL_CARGO_HOME".into(),
                cargo_home.clone().into_os_string(),
            ),
        ];
        let roots = CanonicalRustPaths::from_env(&env, &build, &rust_root).unwrap();
        let args = roots.bwrap_arguments(
            &rust_root.join("bin/rustc"),
            &[OsString::from("-vV")],
            &build,
        );

        let has_mount = |kind: &str, path: &Path| {
            args.windows(3).any(|triple| {
                triple[0] == kind && triple[1] == path.as_os_str() && triple[2] == path.as_os_str()
            })
        };

        assert!(has_mount("--bind", &target));
        assert!(has_mount("--ro-bind", &build));
        assert!(has_mount("--ro-bind", &cargo_home));
        assert!(has_mount("--ro-bind", &rust_root));

        let tmpfs_index = args
            .windows(2)
            .position(|pair| pair[0] == "--tmpfs" && pair[1] == "/tmp")
            .unwrap();
        let target_alias_index = args
            .windows(3)
            .position(|triple| {
                triple[0] == "--bind"
                    && triple[1] == target.as_os_str()
                    && triple[2] == target.as_os_str()
            })
            .unwrap();
        assert!(
            tmpfs_index < target_alias_index,
            "physical target alias under /tmp must be mounted after the sandbox tmpfs: {args:?}"
        );
    }

    #[test]
    fn disabled_without_opt_in() {
        let env = vec![("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into())];
        assert!(
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/rust")).is_none()
        );
    }
}
