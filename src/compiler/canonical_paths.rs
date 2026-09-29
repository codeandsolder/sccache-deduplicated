use crate::dist;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
struct RootMapping {
    aliases: Vec<PathBuf>,
    canonical: PathBuf,
}

impl RootMapping {
    fn new(physical: PathBuf, canonical: &str) -> Self {
        let mut aliases = vec![physical.clone()];
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
pub(crate) struct CanonicalRustPaths {
    roots: Vec<RootMapping>,
    pub(crate) build_root: PathBuf,
    pub(crate) target_root: PathBuf,
    pub(crate) cargo_home: Option<PathBuf>,
    pub(crate) rust_root: PathBuf,
}

fn env_value(env: &[(OsString, OsString)], name: &str) -> Option<PathBuf> {
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

fn path_env(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(
            "CARGO"
                | "CARGO_HOME"
                | "CARGO_INSTALL_ROOT"
                | "CARGO_MANIFEST_DIR"
                | "CARGO_MANIFEST_PATH"
                | "CARGO_TARGET_DIR"
                | "CARGO_TARGET_TMPDIR"
                | "OUT_DIR"
                | "PWD"
                | "RUSTC"
                | "RUSTDOC"
        )
    ) || name
        .to_str()
        .is_some_and(|name| name.starts_with("CARGO_BIN_EXE_"))
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

impl CanonicalRustPaths {
    #[cfg(target_os = "linux")]
    pub(crate) fn from_rustc_executable(
        env: &[(OsString, OsString)],
        cwd: &Path,
        executable: &Path,
    ) -> Option<Self> {
        let rust_root = executable.parent()?.parent()?;
        Self::from_env(env, cwd, rust_root)
    }

    pub(crate) fn from_env(
        env: &[(OsString, OsString)],
        cwd: &Path,
        rust_root: &Path,
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

        let target_root = env_value(env, "SCCACHE_CANONICAL_TARGET_ROOT")
            .or_else(|| env_value(env, "CARGO_TARGET_DIR"))
            .unwrap_or_else(|| build_root.join("target"));
        let cargo_home = env_value(env, "SCCACHE_CANONICAL_CARGO_HOME")
            .or_else(|| env_value(env, "CARGO_HOME"))
            .or_else(|| env_value(env, "HOME").map(|home| home.join(".cargo")));

        let mut roots = vec![
            RootMapping::new(target_root.clone(), "/target"),
            RootMapping::new(build_root.clone(), "/build"),
        ];
        if let Some(ref cargo_home) = cargo_home {
            roots.push(RootMapping::new(cargo_home.clone(), "/cargo"));

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
                        ephemeral_registry_src,
                        "/cargo/registry/src",
                    ));
                }
            }
        }
        roots.push(RootMapping::new(rust_root.to_owned(), "/rust"));

        Some(Self {
            roots,
            build_root,
            target_root,
            cargo_home,
            rust_root: rust_root.to_owned(),
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
        env.iter()
            .filter(|(k, _)| {
                k != "SCCACHE_EXPERIMENTAL_CANONICAL_RUST"
                    && !k.to_string_lossy().starts_with("SCCACHE_CANONICAL_")
            })
            .map(|(k, v)| {
                let value = if matches!(k.to_str(), Some("TMPDIR" | "TMP" | "TEMP" | "TEMPDIR")) {
                    OsString::from("/tmp")
                } else if k == "HOME" {
                    OsString::from("/tmp/home")
                } else if k == "RUSTC" {
                    OsString::from("/rust/bin/rustc")
                } else if k == "RUSTDOC" {
                    OsString::from("/rust/bin/rustdoc")
                } else if path_env(k) {
                    self.os_to_canonical(v)
                } else {
                    self.normalize_os_value(v)
                };
                (k.clone(), value)
            })
            .collect()
    }

    pub(crate) fn env_value_to_canonical(&self, name: &OsStr, value: &OsStr) -> OsString {
        if matches!(name.to_str(), Some("TMPDIR" | "TMP" | "TEMP" | "TEMPDIR")) {
            OsString::from("/tmp")
        } else if name == "HOME" {
            OsString::from("/tmp/home")
        } else if name == "RUSTC" {
            OsString::from("/rust/bin/rustc")
        } else if name == "RUSTDOC" {
            OsString::from("/rust/bin/rustdoc")
        } else if path_env(name) {
            self.os_to_canonical(value)
        } else {
            self.normalize_os_value(value)
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
                if virtual_path == Path::new("/target") {
                    push!("--bind");
                } else {
                    push!("--ro-bind");
                }
                out.push(physical.as_os_str().to_owned());
                out.push(virtual_path.as_os_str().to_owned());
            } else {
                push!("--dir");
                out.push(virtual_path.as_os_str().to_owned());
            }
        }

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
            let writable = root.canonical == Path::new("/target");
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

        push!("--tmpfs");
        push!("/tmp");
        push!("--dir");
        push!("/tmp/home");
        push!("--chdir");
        out.push(self.canonical_cwd(cwd).into_os_string());
        push!("--");
        out.push(self.canonical_executable(executable).into_os_string());
        out.extend(arguments.iter().map(|arg| self.normalize_os_value(arg)));
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
            ("CARGO_TARGET_DIR".into(), target.clone().into_os_string()),
            ("CARGO_HOME".into(), cargo_home.clone().into_os_string()),
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
                &[source.clone().into_os_string()],
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
    }

    #[test]
    fn disabled_without_opt_in() {
        let env = vec![("SCCACHE_CANONICAL_BUILD_ROOT".into(), "/work/a".into())];
        assert!(
            CanonicalRustPaths::from_env(&env, Path::new("/work/a"), Path::new("/rust")).is_none()
        );
    }
}
