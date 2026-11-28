// Copyright 2016 Mozilla Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(target_os = "windows")]
use crate::util::normalize_win_path;
use directories::ProjectDirs;
use fs::File;
use fs_err as fs;
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
use serde::ser::Serializer;
use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, Deserializer},
};
use std::collections::HashMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::str::FromStr;
use std::sync::Mutex;
use typed_path::Utf8TypedPathBuf;

use crate::errors::{Context, Result, anyhow, bail};

static CACHED_CONFIG: Mutex<Option<(PathBuf, CachedFileConfig)>> = Mutex::new(None);

const ORGANIZATION: &str = "Mozilla";
const APP_NAME: &str = "sccache";
#[cfg(test)]
const TEN_GIGS: u64 = 10 * 1024 * 1024 * 1024;

pub const INSECURE_DIST_CLIENT_TOKEN: &str = "dangerously_insecure_client";

#[must_use = "check the result to distinguish a valid byte count from invalid input"]
pub fn parse_size(val: &str) -> Option<u64> {
    let multiplier = match val.chars().last().map(|v| v.to_ascii_uppercase()) {
        Some('K') => 1024,
        Some('M') => 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('T') => 1024 * 1024 * 1024 * 1024,
        _ => 1,
    };
    let val = if multiplier > 1 && !val.is_empty() {
        val.split_at(val.len() - 1).0
    } else {
        val
    };
    u64::from_str(val).ok()?.checked_mul(multiplier)
}

#[cfg(any(feature = "dist-client", feature = "dist-server"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HTTPUrl(url::Url);
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl Serialize for HTTPUrl {
    fn serialize<S>(&self, serializer: S) -> StdResult<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl<'a> Deserialize<'a> for HTTPUrl {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        use serde::de::Error;
        let helper: String = Deserialize::deserialize(deserializer)?;
        let url = parse_http_url(&helper).map_err(D::Error::custom)?;
        Ok(Self(url))
    }
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
fn parse_http_url(url: &str) -> Result<url::Url> {
    use std::net::SocketAddr;
    let url = url.parse::<SocketAddr>().map_or_else(
        |_| url::Url::parse(url),
        |sa| {
            warn!("Url {url} has no scheme, assuming http");
            url::Url::parse(&format!("http://{sa}"))
        },
    )?;
    if url.scheme() != "http" && url.scheme() != "https" {
        bail!("url not http or https")
    }
    // TODO: relative url handling just hasn't been implemented and tested
    if url.path() != "/" {
        bail!("url has a relative path (currently unsupported)")
    }
    Ok(url)
}
#[cfg(any(feature = "dist-client", feature = "dist-server"))]
impl HTTPUrl {
    #[must_use = "the returned wrapper contains the supplied HTTP URL"]
    pub const fn from_url(u: url::Url) -> Self {
        Self(u)
    }
    #[must_use = "the HTTP URL is returned without modifying the wrapper"]
    pub fn to_url(&self) -> url::Url {
        self.0.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum DistAuth {
    #[serde(rename = "token")]
    Token { token: String },
    #[serde(rename = "oauth2_code_grant_pkce")]
    Oauth2CodeGrantPKCE {
        client_id: String,
        auth_url: String,
        token_url: String,
    },
    #[serde(rename = "oauth2_implicit")]
    Oauth2Implicit { client_id: String, auth_url: String },
}

// Convert a type = "mozilla" immediately into an actual oauth configuration
// https://github.com/serde-rs/serde/issues/595 could help if implemented
impl<'a> Deserialize<'a> for DistAuth {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        #[serde(tag = "type")]
        pub enum Helper {
            #[serde(rename = "token")]
            Token { token: String },
            #[serde(rename = "oauth2_code_grant_pkce")]
            Oauth2CodeGrantPKCE {
                client_id: String,
                auth_url: String,
                token_url: String,
            },
            #[serde(rename = "oauth2_implicit")]
            Oauth2Implicit { client_id: String, auth_url: String },
        }

        let helper: Helper = Deserialize::deserialize(deserializer)?;

        Ok(match helper {
            Helper::Token { token } => Self::Token { token },
            Helper::Oauth2CodeGrantPKCE {
                client_id,
                auth_url,
                token_url,
            } => Self::Oauth2CodeGrantPKCE {
                client_id,
                auth_url,
                token_url,
            },
            Helper::Oauth2Implicit {
                client_id,
                auth_url,
            } => Self::Oauth2Implicit {
                client_id,
                auth_url,
            },
        })
    }
}

impl Default for DistAuth {
    fn default() -> Self {
        Self::Token {
            token: INSECURE_DIST_CLIENT_TOKEN.to_owned(),
        }
    }
}

/// Explicit scheduler-owned cache and execution policy for a native client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeClientConfig {
    #[cfg(any(feature = "dist-client", feature = "dist-server"))]
    pub endpoint: HTTPUrl,
    #[cfg(not(any(feature = "dist-client", feature = "dist-server")))]
    pub endpoint: String,
    pub platform_contract: String,
    pub request_timeout_secs: u64,
    pub build_timeout_secs: u64,
    pub renewal_interval_secs: u64,
    pub max_metadata_bytes: u64,
    pub max_result_bytes: u64,
}

impl NativeClientConfig {
    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            cfg!(all(
                feature = "dist-client",
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )),
            "native compiler mode requires a Linux distributed client"
        );
        anyhow::ensure!(
            !self.platform_contract.is_empty()
                && self.request_timeout_secs > 0
                && self.build_timeout_secs > 0
                && self.renewal_interval_secs > 0
                && self.max_metadata_bytes > 0
                && self.max_metadata_bytes < u64::MAX
                && self.max_result_bytes > 0
                && self.max_result_bytes < u64::MAX,
            "invalid native compiler client limits or platform contract"
        );
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct DistConfig {
    pub auth: DistAuth,
    pub cluster: Option<sccache_peer_identity::PeerConfig>,
    #[cfg(any(feature = "dist-client", feature = "dist-server"))]
    pub scheduler_url: Option<HTTPUrl>,
    #[cfg(not(any(feature = "dist-client", feature = "dist-server")))]
    pub scheduler_url: Option<String>,
    pub native: Option<NativeClientConfig>,
    pub native_installation_catalogs: Vec<PathBuf>,
}

impl Default for DistConfig {
    fn default() -> Self {
        Self {
            auth: DistAuth::default(),
            cluster: None,
            scheduler_url: Option::default(),
            native: None,
            native_installation_catalogs: Vec::new(),
        }
    }
}

/// An administrator-attested, argument-transparent compiler launcher.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerAlias {
    pub compiler: PathBuf,
    pub blake3: String,
}

/// Exact path mappings, never inferred from the contents of arbitrary scripts.
/// The expected digest prevents a modified launcher from being silently bypassed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompilerAliases(pub HashMap<PathBuf, CompilerAlias>);

impl CompilerAliases {
    fn validate(&self) -> Result<()> {
        for (launcher, alias) in &self.0 {
            if !launcher.is_absolute() || !alias.compiler.is_absolute() {
                bail!(
                    "Compiler alias paths must be absolute: {}",
                    launcher.display()
                );
            }
            if self.0.contains_key(&alias.compiler) {
                bail!(
                    "Compiler alias must name a real compiler, not another alias: {}",
                    launcher.display()
                );
            }
            blake3::Hash::from_hex(&alias.blake3).with_context(|| {
                format!("Invalid compiler alias digest for {}", launcher.display())
            })?;
        }
        Ok(())
    }

    /// Find a configured launcher, including alternate symlink spellings.
    ///
    /// Preserve the requested path of ordinary executables: multicall
    /// compilers can select their language or mode from argv[0].
    fn launcher(&self, executable: &Path) -> Result<Option<&CompilerAlias>> {
        if let Some(alias) = self.0.get(executable) {
            return Ok(Some(alias));
        }
        if self.0.is_empty() {
            return Ok(None);
        }
        let Ok(canonical) = executable.canonicalize() else {
            return Ok(None);
        };
        let mut matched = self.0.get(&canonical);
        for (path, alias) in &self.0 {
            if path != &canonical && path.canonicalize().ok().as_ref() == Some(&canonical) {
                if matched.is_some_and(|existing| existing != alias) {
                    bail!("Conflicting compiler aliases for {}", executable.display());
                }
                matched = Some(alias);
            }
        }
        Ok(matched)
    }

    /// Resolve a trusted launcher before compiler detection and key generation.
    /// A changed launcher is a configuration error, not an alias match.
    pub(crate) fn resolve(&self, executable: PathBuf) -> Result<PathBuf> {
        let Some(alias) = self.launcher(&executable)? else {
            return Ok(executable);
        };
        let contents = fs::read(&executable)?;
        let expected = blake3::Hash::from_hex(&alias.blake3)?;
        if blake3::hash(&contents) != expected {
            bail!(
                "Compiler alias digest mismatch for {}; update the alias configuration or remove it",
                executable.display()
            );
        }
        // Reject indirect launcher chains too, even if a configured real
        // compiler path was subsequently replaced by a symlink.
        if self.launcher(&alias.compiler)?.is_some() {
            bail!(
                "Compiler alias must name a real compiler, not another alias: {}",
                executable.display()
            );
        }
        debug!(
            "Resolved transparent compiler alias {} to {}",
            executable.display(),
            alias.compiler.display()
        );
        Ok(alias.compiler.clone())
    }
}

#[cfg(test)]
#[test]
fn compiler_alias_configuration_and_identity() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let launcher = temp.path().join("launcher");
    let compiler = temp.path().join("compiler");
    let script = b"#!/bin/sh\nexec compiler \"$@\"\n";
    fs::write(&launcher, script)?;
    let aliases = CompilerAliases(HashMap::from([(
        launcher.clone(),
        CompilerAlias {
            compiler: compiler.clone(),
            blake3: blake3::hash(script).to_hex().to_string(),
        },
    )]));
    let serialized = toml::to_string(&FileConfig {
        compiler_aliases: aliases.clone(),
        ..Default::default()
    })?;
    let file: FileConfig = toml::from_str(&serialized)?;
    assert_eq!(file.compiler_aliases, aliases);
    file.compiler_aliases.validate()?;
    assert_eq!(file.compiler_aliases.resolve(launcher.clone())?, compiler);
    let unrelated = temp.path().join("unrelated");
    assert_eq!(file.compiler_aliases.resolve(unrelated.clone())?, unrelated);
    fs::write(&launcher, b"#!/bin/sh\nexit 0\n")?;
    assert!(file.compiler_aliases.resolve(launcher).is_err());
    Ok(())
}

#[cfg(all(test, unix))]
#[test]
fn compiler_alias_symlink_identity_and_indirect_chains() -> Result<()> {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let wrapper = root.join("wrapper");
    let public = root.join("cc");
    let nested = root.join("host-cc");
    let compiler = root.join("real-cc");
    let compiler_link = root.join("real-c++");
    let script = b"#!/bin/sh\nexec compiler \"$@\"\n";
    fs::write(&wrapper, script)?;
    fs::write(&compiler, b"real compiler")?;
    symlink("wrapper", &public)?;
    symlink("cc", &nested)?;
    symlink("real-cc", &compiler_link)?;
    let mut aliases = CompilerAliases(HashMap::from([(
        wrapper.clone(),
        CompilerAlias {
            compiler: compiler_link.clone(),
            blake3: blake3::hash(script).to_hex().to_string(),
        },
    )]));
    assert_eq!(aliases.resolve(nested.clone())?, compiler_link);
    // Do not change argv[0] of unrelated symlinked compilers.
    assert_eq!(aliases.resolve(compiler_link.clone())?, compiler_link);
    fs::write(&wrapper, b"modified")?;
    assert!(aliases.resolve(public.clone()).is_err());
    fs::write(&wrapper, script)?;
    fs::remove_file(&compiler_link)?;
    symlink("cc", &compiler_link)?;
    assert!(aliases.resolve(nested.clone()).is_err());
    fs::remove_file(&compiler_link)?;
    symlink("real-cc", &compiler_link)?;
    aliases.0.insert(
        public,
        CompilerAlias {
            compiler,
            blake3: blake3::hash(script).to_hex().to_string(),
        },
    );
    assert!(aliases.resolve(nested).is_err());
    Ok(())
}

#[cfg(test)]
#[test]
fn compiler_alias_rejects_relative_paths_and_alias_chains() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    let mut aliases = CompilerAliases(HashMap::from([(
        first.clone(),
        CompilerAlias {
            compiler: PathBuf::from("relative"),
            blake3: blake3::hash(b"").to_hex().to_string(),
        },
    )]));
    assert!(aliases.validate().is_err());
    aliases.0.get_mut(&first).context("first alias")?.compiler = second.clone();
    aliases.0.insert(
        second,
        CompilerAlias {
            compiler: first,
            blake3: blake3::hash(b"").to_hex().to_string(),
        },
    );
    assert!(aliases.validate().is_err());
    Ok(())
}

/// Authorized host UIDs for a root-owned shared compiler service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedDaemonConfig {
    pub socket_gid: u32,
    pub allowed_uids: std::collections::BTreeSet<u32>,
    /// Maximum outstanding private executions, including remote I/O waits.
    /// When absent, allow three executors per physical compiler permit.
    #[serde(default)]
    pub max_executors: Option<std::num::NonZeroUsize>,
}

// TODO: fields only pub for tests
#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub dist: DistConfig,
    pub server_startup_timeout_ms: Option<u64>,
    /// Base directories to strip from paths for cache key computation.
    pub basedirs: Vec<String>,
    pub client_side_mode: bool,
    pub shared_daemon: Option<SharedDaemonConfig>,
    pub compiler_aliases: CompilerAliases,
    pub compile_limits: crate::server::activity::CompileLimits,
    pub traces: Option<crate::latency_trace::TraceConfig>,
}

/// Read and parse a configuration file.
///
/// Only a missing file is treated as absent.
///
/// # Errors
///
/// Returns an error for unreadable files or invalid configuration.
pub fn try_read_config_file<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    debug!(
        "Attempting to read config file at {}",
        crate::util::debug_display(path)
    );
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("Cannot open config file {}", path.display()));
        }
    };

    let mut string = String::new();
    file.read_to_string(&mut string)
        .with_context(|| format!("Cannot read config file {}", path.display()))?;

    let res = if path.extension().is_some_and(|e| e == "json") {
        serde_json::from_str(&string)
            .with_context(|| format!("Failed to load json config file from {}", path.display()))?
    } else {
        toml::from_str(&string)
            .with_context(|| format!("Failed to load toml config file from {}", path.display()))?
    };

    Ok(Some(res))
}

#[derive(Debug, Clone, Default)]
struct Environment {
    vars: HashMap<String, OsString>,
}

impl Environment {
    fn capture() -> Self {
        Self {
            vars: env::vars_os()
                .filter_map(|(name, value)| name.into_string().ok().map(|name| (name, value)))
                .collect(),
        }
    }

    fn var_os(&self, name: &str) -> Option<&OsStr> {
        self.vars.get(name).map(OsString::as_os_str)
    }

    #[cfg(test)]
    fn set(&mut self, name: &str, value: impl AsRef<OsStr>) {
        self.vars
            .insert(name.to_owned(), value.as_ref().to_os_string());
    }

    #[cfg(test)]
    fn remove(&mut self, name: &str) {
        self.vars.remove(name);
    }
}

#[derive(Debug, Default)]
pub struct EnvConfig {
    basedirs: Option<Vec<String>>,
    client_side_mode: Option<bool>,
}

fn string_from_env_var(environment: &Environment, env_var_name: &str) -> Option<String> {
    environment
        .var_os(env_var_name)
        .and_then(OsStr::to_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn bool_from_env_var(environment: &Environment, env_var_name: &str) -> Result<Option<bool>> {
    string_from_env_var(environment, env_var_name)
        .map(|value| match value.to_lowercase().as_str() {
            "true" | "on" | "1" => Ok(true),
            "false" | "off" | "0" => Ok(false),
            _ => bail!("{env_var_name} must be 'true', 'on', '1', 'false', 'off' or '0'."),
        })
        .transpose()
}

fn config_from_environment(environment: &Environment) -> Result<EnvConfig> {
    for name in environment.vars.keys() {
        let retired = [
            "SCCACHE_S3_",
            "SCCACHE_GCS_",
            "SCCACHE_AZURE_",
            "SCCACHE_REDIS_",
            "SCCACHE_MEMCACHED_",
            "SCCACHE_GHA_",
            "SCCACHE_WEBDAV_",
            "SCCACHE_OSS_",
            "SCCACHE_COS_",
            "SCCACHE_MULTILEVEL_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
            || matches!(
                name.as_str(),
                "SCCACHE_BUCKET"
                    | "SCCACHE_REGION"
                    | "SCCACHE_ENDPOINT"
                    | "SCCACHE_DIR"
                    | "SCCACHE_CACHE_SIZE"
                    | "SCCACHE_SKIP_CACHE_CHECK"
                    | "SCCACHE_DIRECT"
                    | "SCCACHE_LOCAL_RW_MODE"
                    | "SCCACHE_REDIS"
                    | "SCCACHE_MEMCACHED"
            );
        if retired {
            bail!("retired cache setting {name}; use the native scheduler CAS");
        }
    }
    // ======= Base directory =======
    // Support multiple paths separated by ';' on Windows and ':' on other platforms
    // to match PATH behavior.
    #[cfg(target_os = "windows")]
    let split_symbol = ';';
    #[cfg(not(target_os = "windows"))]
    let split_symbol = ':';
    let basedirs = environment.var_os("SCCACHE_BASEDIRS").map(|s| {
        s.to_string_lossy()
            .split(split_symbol)
            .filter(|s| !s.is_empty())
            .map(std::borrow::ToOwned::to_owned)
            .collect()
    });

    let client_side_mode = bool_from_env_var(environment, "SCCACHE_CLIENT_SIDE")?;

    Ok(EnvConfig {
        basedirs,
        client_side_mode,
    })
}

// The directories crate changed the location of `config_dir` on macos in version 3,
// so we also check the config in `preference_dir` (new in that version), which
// corresponds to the old location, for compatibility with older setups.
fn config_file(env_var: &str, leaf: &str) -> Result<PathBuf> {
    let environment = Environment::capture();
    config_file_with_environment(&environment, env_var, leaf)
}

fn config_file_with_environment(
    environment: &Environment,
    env_var: &str,
    leaf: &str,
) -> Result<PathBuf> {
    if let Some(env_value) = environment.var_os(env_var) {
        return Ok(env_value.into());
    }
    let dirs = ProjectDirs::from("", ORGANIZATION, APP_NAME)
        .context("unable to determine the user configuration directory")?;
    // If the new location exists, use that.
    let path = dirs.config_dir().join(leaf);
    if path.exists() {
        return Ok(path);
    }
    // If the old location exists, use that.
    let path = dirs.preference_dir().join(leaf);
    if path.exists() {
        return Ok(path);
    }
    // Otherwise, use the new location.
    Ok(dirs.config_dir().join(leaf))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub dist: DistConfig,
    pub server_startup_timeout: Option<std::time::Duration>,
    /// Base directory (or directories) to strip from paths for cache key computation.
    /// Similar to ccache's `CCACHE_BASEDIR`.
    pub basedirs: Vec<Vec<u8>>,
    pub client_side_mode: bool,
    pub shared_daemon: Option<SharedDaemonConfig>,
    pub compiler_aliases: CompilerAliases,
    pub compile_limits: crate::server::activity::CompileLimits,
    pub traces: Option<crate::latency_trace::TraceConfig>,
}

impl Config {
    /// Load the effective sccache configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid environment values or config-file contents,
    /// an unresolvable config path, or an invalid base-directory configuration.
    pub fn load() -> Result<Self> {
        let environment = Environment::capture();
        Self::load_from_environment(&environment)
    }

    fn load_from_environment(environment: &Environment) -> Result<Self> {
        let env_conf = config_from_environment(environment)?;

        let file_conf_path = config_file_with_environment(environment, "SCCACHE_CONF", "config")?;
        let file_conf =
            match try_read_config_file(&file_conf_path).context("Failed to load config file")? {
                Some(config) => config,
                None if environment.var_os("SCCACHE_CONF").is_some() => bail!(
                    "Configured sccache file does not exist: {}",
                    file_conf_path.display()
                ),
                None => FileConfig::default(),
            };

        Self::from_env_and_file_configs(env_conf, file_conf)
    }

    fn from_env_and_file_configs(env_conf: EnvConfig, file_conf: FileConfig) -> Result<Self> {
        let FileConfig {
            dist,
            server_startup_timeout_ms,
            basedirs: file_basedirs,
            client_side_mode: file_client_side_mode,
            shared_daemon,
            compiler_aliases,
            compile_limits,
            traces,
        } = file_conf;
        compile_limits.validate()?;
        compiler_aliases.validate()?;

        let server_startup_timeout =
            server_startup_timeout_ms.map(std::time::Duration::from_millis);

        let EnvConfig {
            basedirs: env_basedirs,
            client_side_mode: env_client_side_mode,
        } = env_conf;

        // Environment variable takes precedence over file config if it is set
        let basedirs_raw = env_basedirs.unwrap_or(file_basedirs);

        // Validate that all basedirs are absolute paths
        // basedirs_raw is Vec<PathBuf>
        let mut basedirs = Vec::with_capacity(basedirs_raw.len());
        for d in basedirs_raw {
            let p = Utf8TypedPathBuf::from(d);
            if !p.is_absolute() {
                bail!("Basedir path must be absolute: {p:?}");
            }
            // Normalize basedir:
            // remove double separators, cur_dirs, parent_dirs, trailing slashes
            let p_norm = p.normalize();
            let mut bytes = p_norm.to_string().into_bytes();

            // Always add a trailing `/` to basedirs to ensure we only match complete path
            // components
            bytes.push(b'/');

            // normalize windows paths: use slashes and lowercase
            let normalized = {
                #[cfg(target_os = "windows")]
                {
                    normalize_win_path(&bytes)
                }

                #[cfg(not(target_os = "windows"))]
                {
                    bytes
                }
            };
            // push only if not already present
            if !basedirs.contains(&normalized) {
                basedirs.push(normalized);
            }
        }

        if !basedirs.is_empty() && log::log_enabled!(log::Level::Debug) {
            let basedirs_str: Vec<String> = basedirs
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect();
            debug!("Using basedirs for path normalization: {basedirs_str:?}");
        }

        // Logging must never change the filesystem namespace used to compile.
        let client_side_mode = env_client_side_mode.unwrap_or(file_client_side_mode);
        if shared_daemon.is_some() {
            anyhow::ensure!(cfg!(target_os = "linux"), "shared daemon is Linux-only");
            anyhow::ensure!(
                !client_side_mode,
                "shared daemon cannot use caller-owned compilation"
            );
        }
        if let Some(native) = &dist.native {
            native.validate()?;
            anyhow::ensure!(
                dist.scheduler_url.is_some(),
                "native compiler mode requires the scheduler status URL"
            );
        }

        Ok(Self {
            dist,
            server_startup_timeout,
            basedirs,
            client_side_mode,
            shared_daemon,
            compiler_aliases,
            compile_limits,
            traces,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CachedDistConfig {
    pub auth_tokens: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct CachedFileConfig {
    pub dist: CachedDistConfig,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CachedConfig {
    file_conf_path: PathBuf,
}

impl CachedConfig {
    /// Load the persistent cached configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lock is poisoned, the cached-config path
    /// cannot be resolved, or the cached file cannot be created, read, or parsed.
    pub fn load() -> Result<Self> {
        let mut cached = CACHED_CONFIG
            .lock()
            .map_err(|_| anyhow!("cached config lock is poisoned"))?;

        if cached.is_none() {
            let file_conf_path = config_file("SCCACHE_CACHED_CONF", "cached-config")?;
            let cfg = Self::load_file_config(&file_conf_path)
                .context("Unable to initialise cached config")?;
            *cached = Some((file_conf_path, cfg));
        }

        let file_conf_path = cached
            .as_ref()
            .map(|(path, _)| path.clone())
            .context("cached config was not initialised")?;
        drop(cached);
        Ok(Self { file_conf_path })
    }

    /// Discard the in-process cached configuration and reload it.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lock is poisoned or loading the replacement
    /// cached configuration fails.
    pub fn reload() -> Result<Self> {
        {
            let mut cached = CACHED_CONFIG
                .lock()
                .map_err(|_| anyhow!("cached config lock is poisoned"))?;
            *cached = None;
        }
        Self::load()
    }

    /// Run `f` against a stable snapshot of the cached configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lock is poisoned, the cache is uninitialized,
    /// or this handle was invalidated by a reload.
    pub fn with<F: FnOnce(&CachedFileConfig) -> T, T>(&self, f: F) -> Result<T> {
        let config = {
            let cached = CACHED_CONFIG
                .lock()
                .map_err(|_| anyhow!("cached config lock is poisoned"))?;
            let (path, config) = cached
                .as_ref()
                .context("cached config was not initialised")?;
            if path != &self.file_conf_path {
                bail!("cached config handle is stale after reload");
            }
            let config = config.clone();
            drop(cached);
            config
        };
        Ok(f(&config))
    }

    /// Mutate and persist the cached configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache lock is poisoned, the cache is uninitialized,
    /// this handle was invalidated by a reload, or persisting the update fails.
    pub fn with_mut<F: FnOnce(&mut CachedFileConfig)>(&self, f: F) -> Result<()> {
        let mut cached = CACHED_CONFIG
            .lock()
            .map_err(|_| anyhow!("cached config lock is poisoned"))?;
        let (path, config) = cached
            .as_mut()
            .context("cached config was not initialised")?;
        if path != &self.file_conf_path {
            bail!("cached config handle is stale after reload");
        }

        let mut new_config = config.clone();
        f(&mut new_config);
        Self::save_file_config(path, &new_config)?;
        *config = new_config;
        drop(cached);
        Ok(())
    }

    fn load_file_config(file_conf_path: &Path) -> Result<CachedFileConfig> {
        if !file_conf_path.exists() {
            let file_conf_dir = file_conf_path
                .parent()
                .context("cached config path has no parent directory")?;
            if !file_conf_dir.is_dir() {
                fs::create_dir_all(file_conf_dir)
                    .context("Failed to create dir to hold cached config")?;
            }
            Self::save_file_config(file_conf_path, &CachedFileConfig::default()).with_context(
                || {
                    format!(
                        "Unable to create cached config file at {}",
                        file_conf_path.display()
                    )
                },
            )?;
        }
        try_read_config_file(file_conf_path)
            .context("Failed to load cached config file")?
            .with_context(|| format!("Failed to load from {}", file_conf_path.display()))
    }

    fn save_file_config(file_conf_path: &Path, config: &CachedFileConfig) -> Result<()> {
        let serialized =
            toml::to_string(config).context("failed to serialize cached configuration")?;
        let mut file = File::create(file_conf_path).context("Could not open config for writing")?;
        file.write_all(serialized.as_bytes())
            .context("failed to write cached configuration")
    }
}

#[cfg(feature = "dist-server")]
pub mod scheduler {
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    use crate::errors::{Context, Result, bail};

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ClientAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "token")]
        Token { token: String },
        #[serde(rename = "jwt_validate")]
        JwtValidate {
            audience: String,
            issuer: String,
            jwks_url: String,
        },
        #[serde(rename = "proxy_token")]
        ProxyToken {
            url: String,
            cache_secs: Option<u64>,
        },
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum ServerAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "jwt_hs256")]
        JwtHS256 { secret_key: String },
        #[serde(rename = "token")]
        Token { token: String },
    }

    #[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct JobSlackConfig {
        pub static_jobs: usize,
        pub percent: f64,
    }

    impl Default for JobSlackConfig {
        fn default() -> Self {
            Self {
                static_jobs: 1,
                percent: 12.5,
            }
        }
    }

    impl JobSlackConfig {
        /// # Errors
        /// Rejects a negative or nonfinite proportional slack setting.
        pub fn validate(self) -> Result<()> {
            if !self.percent.is_finite() || self.percent < 0.0 {
                bail!("scheduler job_slack.percent must be finite and non-negative");
            }
            Ok(())
        }

        #[must_use = "the computed admission capacity limits worker reservations"]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "validated nonnegative capacity is intentionally rounded to whole job slots using saturating float-to-integer casts"
        )]
        #[expect(
            clippy::cast_sign_loss,
            reason = "CPU capacity and proportional slack have been validated as nonnegative"
        )]
        pub fn max_jobs(self, cpu_capacity: f64) -> usize {
            if !cpu_capacity.is_finite() || cpu_capacity < 0.0 {
                return 0;
            }
            let proportional = (cpu_capacity * self.percent / 100.0).floor() as usize;
            (cpu_capacity.ceil() as usize)
                .max(1)
                .saturating_add(self.static_jobs)
                .saturating_add(proportional)
        }
    }

    /// Owner-configured repository prefix for original package archives.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PackageUpstream {
        pub origin: url::Url,
        pub timeout_secs: u64,
    }

    /// Dedicated native cache listener and its explicit resource limits.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NativeCacheConfig {
        pub public_addr: SocketAddr,
        pub bind_address: Option<SocketAddr>,
        pub directory: PathBuf,
        pub space: crate::build_runtime::SpacePolicy,
        pub idle_timeout_secs: u64,
        pub max_sessions: usize,
        pub max_result_bytes: u64,
        pub max_result_blobs: usize,
        pub max_tree_bytes: u64,
        pub max_tree_blobs: usize,
        pub max_concurrent_uploads: usize,
        pub max_total_uploads: usize,
        pub http_threads: usize,
        pub max_metadata_bytes: usize,
        pub package_import: Option<crate::build_runtime::PackageImportLimits>,
        #[serde(default)]
        pub package_upstreams: std::collections::BTreeMap<String, PackageUpstream>,
    }

    impl NativeCacheConfig {
        /// Validate configuration before binding the listener.
        ///
        /// # Errors
        /// Returns an error for a relative path or unusable resource bounds.
        pub fn session_limits(&self) -> Result<crate::build_runtime::SessionLimits> {
            if !self.directory.is_absolute() {
                bail!("native cache directory must be absolute");
            }
            if self.http_threads <= self.max_total_uploads || self.max_metadata_bytes == 0 {
                bail!(
                    "native cache requires spare HTTP threads for control traffic and a nonzero metadata limit"
                );
            }
            let limits = crate::build_runtime::SessionLimits {
                idle_timeout: std::time::Duration::from_secs(self.idle_timeout_secs),
                max_sessions: self.max_sessions,
                max_result_bytes: self.max_result_bytes,
                max_result_blobs: self.max_result_blobs,
                max_tree_bytes: self.max_tree_bytes,
                max_tree_blobs: self.max_tree_blobs,
                max_concurrent_uploads: self.max_concurrent_uploads,
                max_total_uploads: self.max_total_uploads,
                max_manifest_cache_bytes: self.max_metadata_bytes,
                peer_discovery_timeout: std::time::Duration::from_millis(25)
                    .min(std::time::Duration::from_secs(self.idle_timeout_secs)),
            };
            limits.validate()?;
            self.space.validate()?;
            if let Some(package_import) = self.package_import {
                package_import.validate()?;
                if package_import.max_concurrent_imports > self.max_total_uploads {
                    bail!("native package concurrency exceeds total upload capacity");
                }
            }
            for (name, upstream) in &self.package_upstreams {
                crate::dist::native::validate_upstream_name(name)?;
                crate::dist::native::validate_upstream_base(&upstream.origin)?;
                if self.package_import.is_none() || upstream.timeout_secs == 0 {
                    bail!("original package upstream needs import limits and a nonzero timeout");
                }
            }
            Ok(limits)
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct DashboardConfig {
        pub bind_address: SocketAddr,
        pub assets: PathBuf,
        pub metrics_url: Option<String>,
        pub metrics_ingress_host: Option<String>,
        pub traces_url: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub cluster_directory: PathBuf,
        pub dashboard: Option<DashboardConfig>,
        pub public_addr: SocketAddr,
        pub client_auth: ClientAuth,
        pub server_auth: ServerAuth,
        #[serde(default)]
        pub maintenance_drain_file: Option<PathBuf>,
        pub job_slack: JobSlackConfig,
        pub native_cache: Option<NativeCacheConfig>,
        /// Native worker sharing this scheduler's store and process.
        pub local_worker: Option<Box<super::server::Config>>,
        pub traces: Option<crate::latency_trace::TraceConfig>,
    }

    /// Load and validate scheduler configuration.
    ///
    /// # Errors
    /// Returns an error for unreadable, malformed or incompatible configuration.
    pub fn from_path(conf_path: &Path) -> Result<Option<Config>> {
        let config: Option<Config> = super::try_read_config_file(conf_path)
            .context("Failed to load scheduler config file")?;
        if let Some(config) = &config {
            config.job_slack.validate()?;
            if let Some(worker) = &config.local_worker {
                let native = config
                    .native_cache
                    .as_ref()
                    .context("local_worker requires native_cache")?;
                worker.validate_native_store(true)?;
                if !cfg!(target_os = "linux")
                    || worker.builder != super::server::BuilderType::Native
                    || worker.cluster.directory == config.cluster_directory
                    || worker.public_addr == config.public_addr
                    || worker.public_addr == native.public_addr
                    || sccache_cluster_identity::endpoint(&worker.scheduler_url.to_url())?
                        != config.public_addr
                    || sccache_cluster_identity::endpoint(
                        &worker
                            .native_worker
                            .as_ref()
                            .context("local_worker requires native_worker")?
                            .cache_url
                            .to_url(),
                    )? != native.public_addr
                {
                    bail!(
                        "local_worker must be a native Linux worker with a separate identity and listener targeting this scheduler and cache"
                    );
                }
            }
            if let Some(dashboard) = &config.dashboard {
                if !cfg!(feature = "scheduler-dashboard") {
                    bail!("dashboard requires the scheduler-dashboard build feature");
                }
                if !dashboard.bind_address.ip().is_loopback() || !dashboard.assets.is_absolute() {
                    bail!("dashboard requires a loopback bind address and absolute assets path");
                }
                if dashboard.bind_address == config.public_addr
                    || config
                        .native_cache
                        .as_ref()
                        .is_some_and(|native| native.public_addr == dashboard.bind_address)
                {
                    bail!("dashboard requires a separate listener address");
                }
            }
            if let Some(native) = &config.native_cache {
                native.session_limits()?;
                if native.public_addr == config.public_addr {
                    bail!("native cache listener must have a separate address");
                }
            }
        }
        Ok(config)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn scheduler_requires_explicit_valid_admission_policy() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("scheduler.toml");
            let base = r#"
public_addr = "127.0.0.1:10600"
cluster_directory = "/tmp/test-cluster"
[client_auth]
type = "DANGEROUSLY_INSECURE"
[server_auth]
type = "DANGEROUSLY_INSECURE"
"#;
            for (policy, valid) in [
                ("", false),
                ("[job_slack]\nstatic_jobs = 0\n", false),
                ("[job_slack]\nstatic_jobs = 0\npercent = -1.0\n", false),
                ("[job_slack]\nstatic_jobs = 0\npercent = nan\n", false),
                ("[job_slack]\nstatic_jobs = 0\npercent = inf\n", false),
                ("[job_slack]\nstatic_jobs = 0\npercent = 200.0\n", true),
            ] {
                std::fs::write(&path, format!("{base}\n{policy}")).unwrap();
                let loaded = from_path(&path);
                assert_eq!(loaded.is_ok(), valid, "{policy}");
                if valid {
                    assert_eq!(loaded.unwrap().unwrap().job_slack.max_jobs(12.0), 36);
                }
            }
        }
    }
}

#[cfg(feature = "dist-server")]
pub mod server {
    use super::HTTPUrl;
    use serde::{Deserialize, Serialize};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    use crate::errors::{Context, Result, bail};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum BuilderType {
        #[serde(rename = "native")]
        Native,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum SchedulerAuth {
        #[serde(rename = "DANGEROUSLY_INSECURE")]
        Insecure,
        #[serde(rename = "jwt_token")]
        JwtToken { token: String },
        #[serde(rename = "token")]
        Token { token: String },
    }

    const fn default_artifact_grace_secs() -> u64 {
        300
    }

    /// Explicit native worker execution and store configuration.
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct NativeWorkerConfig {
        pub cache_url: HTTPUrl,
        pub directory: Option<PathBuf>,
        pub space: Option<crate::build_runtime::SpacePolicy>,
        pub scratch: PathBuf,
        pub bubblewrap: PathBuf,
        pub platform_contract: String,
        pub renewal_interval_secs: u64,
        pub request_timeout_secs: u64,
        pub execution_timeout_secs: u64,
        pub max_result_bytes: u64,
        pub max_metadata_bytes: u64,
        #[serde(default = "default_artifact_grace_secs")]
        pub artifact_grace_secs: u64,
        pub artifact_grace_bytes: Option<u64>,
        pub max_inflight_jobs: Option<std::num::NonZeroUsize>,
        pub package_import: Option<crate::build_runtime::PackageImportLimits>,
        #[serde(default)]
        pub package_transfer: crate::build_runtime::PackageTransferCost,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Config {
        pub cluster: sccache_peer_identity::PeerConfig,
        pub builder: BuilderType,
        pub public_addr: SocketAddr,
        pub bind_address: Option<SocketAddr>,
        pub scheduler_url: HTTPUrl,
        pub scheduler_auth: SchedulerAuth,
        pub native_worker: Option<NativeWorkerConfig>,
        pub traces: Option<crate::latency_trace::TraceConfig>,
    }

    impl Config {
        pub(super) fn validate_native_store(&self, shared: bool) -> Result<()> {
            if let Some(native) = &self.native_worker {
                match (&native.directory, native.space, shared) {
                    (None, None, true) => (),
                    (Some(directory), Some(space), false) if directory.is_absolute() => {
                        space.validate()?;
                    }
                    _ => bail!(
                        "standalone native workers require directory and space; local workers inherit both from the scheduler"
                    ),
                }
            } else {
                bail!("worker requires native_worker");
            }
            Ok(())
        }
    }

    /// Load worker configuration.
    ///
    /// # Errors
    /// Returns an error for unreadable or malformed configuration.
    pub fn from_path(conf_path: &Path) -> Result<Option<Config>> {
        let config: Option<Config> =
            super::try_read_config_file(conf_path).context("Failed to load server config file")?;
        if let Some(config) = &config {
            config.validate_native_store(false)?;
        }
        Ok(config)
    }
}

#[test]
fn test_parse_size() {
    assert_eq!(None, parse_size(""));
    assert_eq!(None, parse_size("bogus value"));
    assert_eq!(Some(100), parse_size("100"));
    assert_eq!(Some(2048), parse_size("2K"));
    assert_eq!(Some(2048), parse_size("2k"));
    assert_eq!(Some(10 * 1024 * 1024), parse_size("10M"));
    assert_eq!(Some(TEN_GIGS), parse_size("10G"));
    assert_eq!(Some(1024 * TEN_GIGS), parse_size("10T"));
    assert_eq!(None, parse_size("18446744073709551615T"));
    assert_eq!(Some(u64::MAX), parse_size("18446744073709551615"));
    assert_eq!(None, parse_size("18446744073709551615K"));
    assert_eq!(None, parse_size("16777216T"));
}

#[test]
fn test_string_from_env_var() {
    let mut environment = Environment::default();
    let var_name = "TEST_SCCACHE_VAR";
    for value in [None, Some(""), Some("foo")] {
        match value {
            None => {
                environment.remove(var_name);
            }
            Some(value) => {
                environment.set(var_name, value);
            }
        }
        let result = string_from_env_var(&environment, var_name);
        {
            environment.remove(var_name);
        }

        let expected = match value {
            None | Some("") => None,
            Some(value) => Some(value.to_string()),
        };

        assert_eq!(result, expected);
    }
}

#[test]
fn config_basedirs_overrides() -> Result<()> {
    let (env_path, file_path, env_expected, file_expected) = if cfg!(windows) {
        (
            "C:/env/basedir",
            "C:/file/basedir",
            "c:/env/basedir/",
            "c:/file/basedir/",
        )
    } else {
        (
            "/env/basedir",
            "/file/basedir",
            "/env/basedir/",
            "/file/basedir/",
        )
    };
    for (env_dirs, file_dirs, expected) in [
        (
            Some(vec![env_path.to_owned()]),
            vec![file_path.to_owned()],
            vec![env_expected],
        ),
        (None, vec![file_path.to_owned()], vec![file_expected]),
        (Some(vec![]), vec![file_path.to_owned()], vec![]),
        (Some(vec![]), vec![], vec![]),
        (None, vec![], vec![]),
    ] {
        let env_conf = EnvConfig {
            basedirs: env_dirs,
            ..Default::default()
        };
        let file_conf = FileConfig {
            basedirs: file_dirs,
            ..Default::default()
        };
        let config = Config::from_env_and_file_configs(env_conf, file_conf)?;
        assert_eq!(
            config.basedirs,
            expected
                .into_iter()
                .map(|path| path.as_bytes().to_vec())
                .collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_deserialize_basedirs() {
    // Test array of paths
    let toml = r#"
        basedirs = ["/home/user/project", "/home/user/workspace"]

        [dist]
    "#;

    let config: FileConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        config.basedirs,
        vec![
            "/home/user/project".to_string(),
            "/home/user/workspace".to_string()
        ]
    );
}

#[test]
fn test_deserialize_basedirs_missing() {
    // Test no basedirs specified (should default to empty vec)
    let toml = r#"
        [dist]
    "#;

    let config: FileConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.basedirs, [] as [std::string::String; 0]);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_single() {
    let mut environment = Environment::default();
    {
        environment.set("SCCACHE_BASEDIRS", "/home/user/project");
    }
    let config = config_from_environment(&environment).unwrap();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec!["/home/user/project".to_string()]
    );
}

#[test]
#[cfg(target_os = "windows")]
fn test_env_basedirs_single() {
    let mut environment = Environment::default();
    {
        environment.set("SCCACHE_BASEDIRS", "C:/home/user/project");
    }
    let config = config_from_environment(&environment).unwrap();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec!["C:/home/user/project".to_string()]
    );
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_multiple() {
    let mut environment = Environment::default();
    {
        environment.set(
            "SCCACHE_BASEDIRS",
            "/home/user/project:/home/user/workspace",
        );
    }
    let config = config_from_environment(&environment).unwrap();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "/home/user/project".to_string(),
            "/home/user/workspace".to_string()
        ]
    );
}

#[test]
#[cfg(target_os = "windows")]
fn test_env_basedirs_multiple() {
    let mut environment = Environment::default();
    {
        environment.set(
            "SCCACHE_BASEDIRS",
            "C:/home/user/project;C:/home/user/workspace",
        );
    }
    let config = config_from_environment(&environment).unwrap();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "C:/home/user/project".to_string(),
            "C:/home/user/workspace".to_string()
        ]
    );
}

#[test]
fn test_env_basedirs_with_spaces() -> Result<()> {
    let mut environment = Environment::default();
    let (value, first, second) = if cfg!(windows) {
        (
            " C:/home/user/project ; C:/home/user/workspace ",
            " C:/home/user/project ",
            " C:/home/user/workspace ",
        )
    } else {
        (
            " /home/user/project : /home/user/workspace ",
            " /home/user/project ",
            " /home/user/workspace ",
        )
    };
    environment.set("SCCACHE_BASEDIRS", value);
    let env_conf = config_from_environment(&environment)?;
    assert_eq!(
        env_conf.basedirs.as_deref(),
        Some(&[first.to_owned(), second.to_owned()][..])
    );
    // Leading and trailing spaces are preserved; these are not absolute paths.
    assert!(Config::from_env_and_file_configs(env_conf, FileConfig::default()).is_err());
    Ok(())
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_env_basedirs_empty_entries() {
    let mut environment = Environment::default();
    // Test that empty entries are filtered out
    {
        environment.set(
            "SCCACHE_BASEDIRS",
            "/home/user/project::/home/user/workspace",
        );
    }
    let config = config_from_environment(&environment).unwrap();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "/home/user/project".to_string(),
            "/home/user/workspace".to_string()
        ]
    );
}

#[test]
#[cfg(target_os = "windows")]
fn test_env_basedirs_empty_entries() {
    let mut environment = Environment::default();
    // Test that empty entries are filtered out
    {
        environment.set(
            "SCCACHE_BASEDIRS",
            "c:/home/user/project;;c:/home/user/workspace",
        );
    }
    let config = config_from_environment(&environment).unwrap();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    assert_eq!(
        config.basedirs.expect("SCCACHE_BASEDIRS is set"),
        vec![
            "c:/home/user/project".to_string(),
            "c:/home/user/workspace".to_string()
        ]
    );
}

#[test]
fn test_env_basedirs_not_set() {
    let mut environment = Environment::default();
    {
        environment.remove("SCCACHE_BASEDIRS");
    }
    let config = config_from_environment(&environment).unwrap();
    assert!(config.basedirs.is_none());
}

#[test]
fn rejects_retired_client_archive_configuration() {
    for field in [
        "cache_dir = \"/tmp/archive\"",
        "toolchain_cache_size = 100",
        "rewrite_includes_only = true",
        "toolchains = []",
        "[[dist.toolchains]]\ntype = \"no_dist\"\ncompiler_executable = \"/usr/bin/gcc\"",
    ] {
        assert!(
            toml::from_str::<FileConfig>(&format!("[dist]\n{field}")).is_err(),
            "{field}"
        );
    }
}

#[test]
fn rejects_retired_cache_configuration() {
    for name in [
        "disk",
        "s3",
        "redis",
        "gcs",
        "azure",
        "gha",
        "memcached",
        "webdav",
        "oss",
        "cos",
        "multilevel",
    ] {
        assert!(toml::from_str::<FileConfig>(&format!("[cache.{name}]")).is_err());
    }
    let mut environment = Environment::default();
    environment.set("SCCACHE_BUCKET", "retired");
    assert!(config_from_environment(&environment).is_err());
}

#[test]
fn full_toml_parse() {
    const CONFIG_STR: &str = r#"
server_startup_timeout_ms = 10000

[dist]
# where to find the scheduler
scheduler_url = "http://1.2.3.4:10600"

[dist.auth]
type = "token"
token = "secrettoken"


"#;

    let file_config: FileConfig = toml::from_str(CONFIG_STR).expect("Is valid toml.");
    assert_eq!(
        file_config,
        FileConfig {
            dist: DistConfig {
                cluster: None,
                auth: DistAuth::Token {
                    token: "secrettoken".to_owned()
                },
                #[cfg(any(feature = "dist-client", feature = "dist-server"))]
                scheduler_url: Some(
                    parse_http_url("http://1.2.3.4:10600")
                        .map(|url| { HTTPUrl::from_url(url) })
                        .expect("Scheduler url must be valid url str")
                ),
                #[cfg(not(any(feature = "dist-client", feature = "dist-server")))]
                scheduler_url: Some("http://1.2.3.4:10600".to_owned()),
                native: None,
                native_installation_catalogs: Vec::new(),
            },
            server_startup_timeout_ms: Some(10000),
            basedirs: vec![],
            client_side_mode: false,
            shared_daemon: None,
            compiler_aliases: Default::default(),
            compile_limits: Default::default(),
            traces: None,
        }
    );
}

#[test]
#[cfg(feature = "dist-server")]
fn server_toml_parse() {
    const CONFIG: &str = r#"
public_addr = "192.168.1.1:10501"
bind_address = "0.0.0.0:10501"
scheduler_url = "https://192.168.1.1"
[builder]
type = "native"
[cluster]
directory = "/tmp/worker-identity"
ca_certificate = "/tmp/ca.pem"
scheduler_id = "0101010101010101010101010101010101010101010101010101010101010101"
[scheduler_auth]
type = "jwt_token"
token = "test-token"
[native_worker]
cache_url = "https://192.168.1.1:10502"
directory = "/tmp/worker-store"
scratch = "/tmp/worker-scratch"
bubblewrap = "/usr/bin/bwrap"
platform_contract = "test-linux"
renewal_interval_secs = 15
request_timeout_secs = 120
execution_timeout_secs = 600
max_result_bytes = 1073741824
max_metadata_bytes = 67108864
[native_worker.space]
min_available_bytes = 536870912
target_available_bytes = 2147483648
max_resident_bytes = 4294967296
target_resident_bytes = 3221225472
max_evictions_per_pass = 32
gc_batch = 1024
"#;
    let config: server::Config = toml::from_str(CONFIG).unwrap();
    assert_eq!(config.builder, server::BuilderType::Native);
    assert_eq!(config.public_addr, "192.168.1.1:10501".parse().unwrap());
    assert_eq!(
        config.native_worker.as_ref().unwrap().platform_contract,
        "test-linux"
    );
    config.validate_native_store(false).unwrap();
    for retired in ["overlay", "docker", "pot"] {
        assert!(
            toml::from_str::<server::Config>(
                &CONFIG.replace("type = \"native\"", &format!("type = \"{retired}\""))
            )
            .is_err()
        );
    }
    for field in [
        "cache_dir = \"/tmp/archive\"\n",
        "toolchain_cache_size = 100\n",
        "toolchain_archive_sources = []\n",
    ] {
        assert!(toml::from_str::<server::Config>(&format!("{field}{CONFIG}")).is_err());
    }
    let missing: server::Config =
        toml::from_str(CONFIG.split("[native_worker]").next().unwrap()).unwrap();
    assert!(missing.validate_native_store(false).is_err());
}

#[test]
fn rejects_zero_compile_deadlines() -> Result<()> {
    for name in ["phase_timeout_secs", "execution_timeout_secs"] {
        let file: FileConfig = toml::from_str(&format!("[compile_limits]\n{name} = 0\n"))?;
        assert!(Config::from_env_and_file_configs(EnvConfig::default(), file).is_err());
    }
    let file: FileConfig = toml::from_str(
        "[compile_limits]\nphase_timeout_secs = 42\nexecution_timeout_secs = 3600\n",
    )?;
    let config = Config::from_env_and_file_configs(EnvConfig::default(), file)?;
    assert_eq!(config.compile_limits.phase_timeout_secs, 42);
    assert_eq!(config.compile_limits.execution_timeout_secs, 3600);
    Ok(())
}

// Integration tests: Config normalization + strip_basedirs usage

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_config_normalizes_and_strips() {
    // Test that Config normalizes basedirs and strip_basedirs uses them correctly
    use crate::util::strip_basedirs;
    use std::borrow::Cow;

    let env_conf = EnvConfig::default();

    let file_conf = FileConfig {
        basedirs: vec!["/home/user/project".to_string()],
        ..Default::default()
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Verify config normalized the basedir with trailing slash
    assert_eq!(config.basedirs, vec![b"/home/user/project/"]);

    // Test that strip_basedirs uses the normalized basedir
    let input = b"# 1 \"/home/user/project/src/main.c\"\nint main() { return 0; }";
    let output = strip_basedirs(input, &config.basedirs);

    // Should strip the basedir
    let expected = b"# 1 \"src/main.c\"\nint main() { return 0; }";
    assert_eq!(&*output, expected);
    assert!(matches!(output, Cow::Owned(_)));
}

#[test]
fn test_integration_normalized_paths() -> Result<()> {
    use crate::util::strip_basedirs;
    let cases: &[(&str, &[u8], &[u8], &[u8])] = if cfg!(windows) {
        &[
            (
                r"C:\Users\Test\Project",
                b"c:/users/test/project/",
                br#"# 1 "C:\Users\Test\Project\src\main.c""#,
                br#"# 1 "src\main.c""#,
            ),
            (
                r"C:\Users\test\project",
                b"c:/users/test/project/",
                br#"# 1 "C:/Users\test\project\src/main.c""#,
                br#"# 1 "src/main.c""#,
            ),
        ]
    } else {
        &[
            (
                "/home//user///project/",
                b"/home/user/project/",
                br#"# 1 "/home/user/project/src/main.c""#,
                br#"# 1 "src/main.c""#,
            ),
            (
                "/home/user/./project/../project",
                b"/home/user/project/",
                br#"# 1 "/home/user/project/src/main.c""#,
                br#"# 1 "src/main.c""#,
            ),
        ]
    };
    for &(path, normalized, input, expected) in cases {
        let file = FileConfig {
            basedirs: vec![path.to_owned()],
            ..Default::default()
        };
        let config = Config::from_env_and_file_configs(EnvConfig::default(), file)?;
        assert_eq!(config.basedirs, vec![normalized]);
        assert_eq!(&*strip_basedirs(input, &config.basedirs), expected);
    }
    Ok(())
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_cow_borrowed_when_no_match() {
    // Test that strip_basedirs returns Cow::Borrowed when no stripping occurs
    use crate::util::strip_basedirs;
    use std::borrow::Cow;

    let env_conf = EnvConfig::default();

    let file_conf = FileConfig {
        basedirs: vec!["/home/user/project".to_string()],
        ..Default::default()
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Input doesn't contain the basedir
    let input = b"# 1 \"/other/path/main.c\"\nint main() { return 0; }";
    let output = strip_basedirs(input, &config.basedirs);

    // Should return borrowed reference (no allocation)
    assert!(matches!(output, Cow::Borrowed(_)));
    assert_eq!(&*output, input);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_cow_borrowed_when_empty_basedirs() {
    // Test that strip_basedirs returns Cow::Borrowed when basedirs is empty
    use crate::util::strip_basedirs;
    use std::borrow::Cow;

    let env_conf = EnvConfig::default();

    let file_conf = FileConfig::default();

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();
    assert_eq!(config.basedirs, [] as [std::vec::Vec<u8>; 0]);

    let input = b"# 1 \"/home/user/project/src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);

    // Should return borrowed reference when basedirs is empty
    assert!(matches!(output, Cow::Borrowed(_)));
    assert_eq!(&*output, input);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_multiple_basedirs_longest_match() {
    // Test that strip_basedirs prefers longest match with normalized basedirs
    use crate::util::strip_basedirs;

    let env_conf = EnvConfig::default();

    let file_conf = FileConfig {
        basedirs: vec!["/home/user".to_string(), "/home/user/project".to_string()],
        ..Default::default()
    };

    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    // Both should be normalized with trailing slashes
    assert_eq!(config.basedirs.len(), 2);
    assert_eq!(config.basedirs[0], b"/home/user/");
    assert_eq!(config.basedirs[1], b"/home/user/project/");

    // Input matches both, but longest should win
    let input = b"# 1 \"/home/user/project/src/main.c\"";
    let output = strip_basedirs(input, &config.basedirs);

    // Should match the longest basedir (/home/user/project/)
    let expected = b"# 1 \"src/main.c\"";
    assert_eq!(&*output, expected);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn test_integration_env_variable_to_strip() {
    let mut environment = Environment::default();
    // Test full flow: SCCACHE_BASEDIRS env var -> Config -> strip_basedirs
    use crate::util::strip_basedirs;

    {
        environment.set("SCCACHE_BASEDIRS", "/home/user/project:/tmp/build");
    }

    let env_conf = config_from_environment(&environment).unwrap();
    let file_conf = FileConfig::default();
    let config = Config::from_env_and_file_configs(env_conf, file_conf).unwrap();

    {
        environment.remove("SCCACHE_BASEDIRS");
    }

    // Should have two normalized basedirs
    assert_eq!(config.basedirs.len(), 2);
    assert_eq!(config.basedirs[0], b"/home/user/project/");
    assert_eq!(config.basedirs[1], b"/tmp/build/");

    // Test stripping with both
    let input1 = b"# 1 \"/home/user/project/src/main.c\"";
    let output1 = strip_basedirs(input1, &config.basedirs);
    assert_eq!(&*output1, b"# 1 \"src/main.c\"");

    let input2 = b"# 1 \"/tmp/build/obj/file.o\"";
    let output2 = strip_basedirs(input2, &config.basedirs);
    assert_eq!(&*output2, b"# 1 \"obj/file.o\"");
}

#[test]
#[cfg(all(
    feature = "dist-client",
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn native_compiler_config_is_validated() -> Result<()> {
    let input = r#"
[dist]
scheduler_url = "http://127.0.0.1:10500"

[dist.native]
endpoint = "http://127.0.0.1:10502"
platform_contract = "test-platform"
request_timeout_secs = 120
build_timeout_secs = 600
renewal_interval_secs = 15
max_metadata_bytes = 67108864
max_result_bytes = 1073741824
"#;
    let make = |text: &str| -> Result<Config> {
        Config::from_env_and_file_configs(EnvConfig::default(), toml::from_str(text)?)
    };
    assert_eq!(
        make(input)?
            .dist
            .native
            .context("native configuration missing")?
            .platform_contract,
        "test-platform"
    );
    assert!(
        make(&input.replace("renewal_interval_secs = 15", "renewal_interval_secs = 0")).is_err()
    );
    assert!(make(&input.replace("scheduler_url = \"http://127.0.0.1:10500\"", "")).is_err());
    assert!(make(&format!("client_side_mode = true\n{input}"))?.client_side_mode);
    Ok(())
}
