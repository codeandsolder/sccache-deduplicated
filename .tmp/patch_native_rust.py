from pathlib import Path
p=Path('/srv/scratch/sccache-native-resolution/src/compiler/rust.rs')
s=p.read_text()

s=s.replace('use std::collections::{HashMap, HashSet};','use std::collections::{BTreeSet, HashMap, HashSet};',1)

# Add resolution fields to structs.
s=s.replace(
'''    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
}

/// A struct on which to hang a `CompilerHasher` impl.''',
'''    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// Host-native CPU resolution for this compiler.
    native_cpu_resolution: Option<NativeCpuResolution>,
}

/// A struct on which to hang a `CompilerHasher` impl.''',1)
s=s.replace(
'''    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// Parsed arguments from the rustc invocation
    parsed_args: ParsedArguments,
}''',
'''    /// A shared, caching reader for rlib dependencies
    #[cfg(feature = "dist-client")]
    rlib_dep_reader: Option<Arc<RlibDepReader>>,
    /// Host-native CPU resolution for this compiler.
    native_cpu_resolution: Option<NativeCpuResolution>,
    /// Parsed arguments from the rustc invocation
    parsed_args: ParsedArguments,
}''',1)

# Helpers before ParsedArguments.
needle='''#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArguments {'''
helpers=r'''#[derive(Debug, Clone)]
struct NativeCpuResolution {
    fingerprint: String,
    cpu: Option<String>,
    explicit_cpu_matches_native_features: bool,
}

fn native_codegen_requests(arguments: &[Argument<ArgData>]) -> (bool, bool) {
    let mut target_cpu = false;
    let mut tune_cpu = false;
    for argument in arguments {
        if let Some(CodeGen(ArgCodegen { opt, value: Some(value) })) = argument.get_data()
            && value == "native"
        {
            match opt.as_str() {
                "target-cpu" => target_cpu = true,
                "tune-cpu" => tune_cpu = true,
                _ => {}
            }
        }
    }
    (target_cpu, tune_cpu)
}

fn parse_native_cpu_name(target_cpus: &str) -> Option<String> {
    target_cpus.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("native") {
            return None;
        }
        let (_, tail) = line.split_once("(currently ")?;
        Some(tail.trim_end_matches([')', '.']).to_owned())
    })
}

fn cfg_target_features(cfg: &str) -> BTreeSet<String> {
    cfg.lines()
        .filter_map(|line| {
            line.strip_prefix("target_feature=\"")
                .and_then(|feature| feature.strip_suffix('"'))
                .map(str::to_owned)
        })
        .collect()
}

async fn rustc_print<T>(
    creator: &T,
    executable: &Path,
    print: &str,
    codegen: Option<&str>,
    env_vars: &[(OsString, OsString)],
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let mut cmd = creator.clone().new_command_sync(executable);
    cmd.arg("--print")
        .arg(print)
        .env_clear()
        .envs(env_vars.to_vec());
    if let Some(codegen) = codegen {
        cmd.arg("-C").arg(codegen);
    }
    let output = run_input_output(cmd, None).await?;
    String::from_utf8(output.stdout).context("Error parsing rustc --print output")
}

async fn resolve_host_native_cpu<T>(
    creator: &T,
    executable: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<NativeCpuResolution>
where
    T: CommandCreatorSync,
{
    let target_cpus = rustc_print(creator, executable, "target-cpus", None, env_vars).await?;
    let cpu = parse_native_cpu_name(&target_cpus);
    let native_cfg = rustc_print(
        creator,
        executable,
        "cfg",
        Some("target-cpu=native"),
        env_vars,
    )
    .await?;
    let explicit_cpu_matches_native_features = if let Some(cpu) = cpu.as_deref() {
        let explicit_cfg = rustc_print(
            creator,
            executable,
            "cfg",
            Some(&format!("target-cpu={cpu}")),
            env_vars,
        )
        .await?;
        cfg_target_features(&native_cfg) == cfg_target_features(&explicit_cfg)
    } else {
        false
    };

    let mut digest = Digest::new();
    digest.update(b"sccache-rust-native-cpu-v1\0");
    digest.update(target_cpus.as_bytes());
    digest.update(native_cfg.as_bytes());
    Ok(NativeCpuResolution {
        fingerprint: digest.finish(),
        cpu,
        explicit_cpu_matches_native_features,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedArguments {'''
if needle not in s: raise SystemExit('helpers needle missing')
s=s.replace(needle,helpers,1)

# Resolve once in Rust::new before sysroot probe.
needle='''        // it's fine to use the `executable` directly no matter if proxied or not
        let mut cmd = creator.new_command_sync(&executable);'''
repl='''        let native_cpu_resolution = match resolve_host_native_cpu(&creator, &executable, env_vars).await {
            Ok(resolution) => Some(resolution),
            Err(error) => {
                debug!("Failed to resolve rustc native CPU: {error:#}");
                None
            }
        };

        // it's fine to use the `executable` directly no matter if proxied or not
        let mut cmd = creator.new_command_sync(&executable);'''
if needle not in s: raise SystemExit('new probe needle missing')
s=s.replace(needle,repl,1)

# Both Rust initializers.
s=s.replace('''                dist_archive,
                rlib_dep_reader,
            })''','''                dist_archive,
                rlib_dep_reader,
                native_cpu_resolution,
            })''',1)
s=s.replace('''                compiler_shlibs_digests: digests,
                dist_archive,
            })''','''                compiler_shlibs_digests: digests,
                dist_archive,
                native_cpu_resolution,
            })''',1)

# Parse: fail native uncached if discovery failed, otherwise pass resolution.
needle='''        match parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => CompilerArguments::Ok(Box::new(RustHasher {'''
repl='''        match parse_arguments(arguments, cwd) {
            CompilerArguments::Ok(args) => {
                let (target_cpu_native, tune_cpu_native) = native_codegen_requests(&args.arguments);
                if (target_cpu_native || tune_cpu_native) && self.native_cpu_resolution.is_none() {
                    return CompilerArguments::CannotCache("native CPU resolution unavailable", None);
                }
                CompilerArguments::Ok(Box::new(RustHasher {'''
if needle not in s: raise SystemExit('parse start missing')
s=s.replace(needle,repl,1)
needle='''                #[cfg(feature = "dist-client")]
                rlib_dep_reader: self.rlib_dep_reader.clone(),
                parsed_args: args,
            })),'''
repl='''                #[cfg(feature = "dist-client")]
                rlib_dep_reader: self.rlib_dep_reader.clone(),
                native_cpu_resolution: self.native_cpu_resolution.clone(),
                parsed_args: args,
            }))
            },'''
if needle not in s: raise SystemExit('parse end missing')
s=s.replace(needle,repl,1)

# Hash host resolution iff request uses native.
needle='''        let weak_toolchain_key = rust_dist_toolchain_weak_key(&m, &self.sysroot);
        // 3. The full commandline (self.arguments)'''
repl='''        let weak_toolchain_key = rust_dist_toolchain_weak_key(&m, &self.sysroot);
        let (target_cpu_native, tune_cpu_native) = native_codegen_requests(&self.parsed_args.arguments);
        if target_cpu_native || tune_cpu_native {
            if let Some(resolution) = &self.native_cpu_resolution {
                m.update(resolution.fingerprint.as_bytes());
            }
        }
        // 3. The full commandline (self.arguments)'''
if needle not in s: raise SystemExit('hash needle missing')
s=s.replace(needle,repl,1)

# Add field to RustCompilation.
needle='''    /// The environment variables
    env_vars: Vec<(OsString, OsString)>,
}'''
repl='''    /// The environment variables
    env_vars: Vec<(OsString, OsString)>,
    /// Host-native CPU resolution used for safe distributed rewriting.
    native_cpu_resolution: Option<NativeCpuResolution>,
}'''
if needle not in s: raise SystemExit('compilation field missing')
s=s.replace(needle,repl,1)

# Pass field into compilation.
needle='''                #[cfg(feature = "dist-client")]
                rlib_dep_reader: self.rlib_dep_reader.clone(),
            }),'''
repl='''                #[cfg(feature = "dist-client")]
                rlib_dep_reader: self.rlib_dep_reader.clone(),
                native_cpu_resolution: self.native_cpu_resolution.clone(),
            }),'''
if needle not in s: raise SystemExit('compilation init missing')
s=s.replace(needle,repl,1)

# Destructure.
needle='''            ref env_vars,
            ref host,
            ref sysroot,
            ..
        } = *self;'''
repl='''            ref env_vars,
            ref host,
            ref sysroot,
            ref native_cpu_resolution,
            ..
        } = *self;'''
if needle not in s: raise SystemExit('destructure missing')
s=s.replace(needle,repl,1)

# Dist guard + rewrite.
needle='''            let mut dist_arguments = vec![];
            let mut saw_target = false;

            // flat_map would be nice but the lifetimes don't work out
            for argument in arguments.iter() {
                let path_transformer_fn = &mut |p: &Path| path_transformer.as_dist(p);'''
repl='''            let mut dist_arguments = vec![];
            let mut saw_target = false;
            let (target_cpu_native, tune_cpu_native) = native_codegen_requests(arguments);
            let has_explicit_target = arguments
                .iter()
                .any(|argument| matches!(argument.get_data(), Some(Target(_))));
            if target_cpu_native || tune_cpu_native {
                let resolution = native_cpu_resolution.as_ref()?;
                if has_explicit_target
                    || resolution.cpu.is_none()
                    || (target_cpu_native && !resolution.explicit_cpu_matches_native_features)
                {
                    return None;
                }
            }

            // flat_map would be nice but the lifetimes don't work out
            for argument in arguments.iter() {
                let path_transformer_fn = &mut |p: &Path| path_transformer.as_dist(p);
                if let Some(CodeGen(ArgCodegen { opt, value: Some(value) })) = argument.get_data()
                    && value == "native"
                    && matches!(opt.as_str(), "target-cpu" | "tune-cpu")
                {
                    let cpu = native_cpu_resolution.as_ref()?.cpu.as_ref()?;
                    dist_arguments.push(argument.flag_str()?.to_owned());
                    dist_arguments.push(format!("{opt}={cpu}"));
                    continue;
                }'''
if needle not in s: raise SystemExit('dist loop missing')
s=s.replace(needle,repl,1)

# Test RustHasher direct initializers.
needle='''            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            parsed_args: ParsedArguments {'''
repl='''            #[cfg(feature = "dist-client")]
            rlib_dep_reader: None,
            native_cpu_resolution: None,
            parsed_args: ParsedArguments {'''
if needle not in s: raise SystemExit('test init missing')
s=s.replace(needle,repl)

# Pure tests.
needle='''    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_generate_hash_key(preprocessor_cache_mode: bool) {'''
tests='''    #[test]
    fn test_parse_native_cpu_name() {
        let cpus = "native - Select the CPU of the current host (currently znver2).\\n";
        assert_eq!(parse_native_cpu_name(cpus).as_deref(), Some("znver2"));
    }

    #[test]
    fn test_cfg_target_features() {
        let cfg = "target_feature=\\\"sse2\\\"\\ntarget_feature=\\\"avx2\\\"\\n";
        assert_eq!(
            cfg_target_features(cfg),
            BTreeSet::from(["avx2".to_owned(), "sse2".to_owned()])
        );
    }

    #[test_case(true ; "with preprocessor cache")]
    #[test_case(false ; "without preprocessor cache")]
    fn test_generate_hash_key(preprocessor_cache_mode: bool) {'''
if needle not in s: raise SystemExit('tests needle missing')
s=s.replace(needle,tests,1)

p.write_text(s)
