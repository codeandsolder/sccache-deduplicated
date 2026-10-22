from pathlib import Path

p = Path('/srv/scratch/sccache-native-main/src/compiler/rust.rs')
s = p.read_text()

def replace(old: str, new: str, count: int = 1) -> None:
    global s
    if s.count(old) < count:
        raise SystemExit(f'missing anchor: {old[:80]!r}')
    s = s.replace(old, new, count)

replace(
'''static NATIVE_PROFILE_CACHE: LazyLock<std::sync::Mutex<HashMap<(PathBuf, String), String>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

static WARNED_DIST_NATIVE_PORTABLE: AtomicBool = AtomicBool::new(false);
''',
'''static NATIVE_PROFILE_CACHE: LazyLock<std::sync::Mutex<HashMap<(PathBuf, String), String>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

static EXPLICIT_CPU_PROFILE_CACHE: LazyLock<
    std::sync::Mutex<HashMap<(PathBuf, String, String), String>>,
> = LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));
''')

replace(
'''fn compilation_target(arguments: &[Argument<ArgData>], host: &str) -> String {''',
'''fn native_tune_requested(arguments: &[Argument<ArgData>]) -> bool {
    arguments.iter().any(|arg| {
        matches!(
            arg.get_data(),
            Some(CodeGen(ArgCodegen {
                opt,
                value: Some(value)
            })) if opt == "tune-cpu" && value == "native"
        )
    })
}

fn compilation_target(arguments: &[Argument<ArgData>], host: &str) -> String {''')

replace(
'''    let profile = probe_native_profile(creator, executable, env_vars).await?;
    let mut cache = NATIVE_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(cache.entry(key).or_insert_with(|| profile.clone()).clone())
}

async fn probe_native_profile<T>(
    mut creator: T,
    executable: &Path,
    env_vars: &[(OsString, OsString)],
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let temp_dir = tempfile::Builder::new()
        .prefix("sccache-native")
        .tempdir()
        .context("Failed to create native-profile temp dir")?;
    let mut cmd = creator.new_command_sync(executable);
    cmd.args(&[
        "-",
        "--crate-name",
        "sccache_native_probe",
        "--crate-type",
        "lib",
        "--emit=llvm-ir=-",
        "-C",
        "target-cpu=native",
    ])
    .env_clear()
    .envs(env_vars.to_vec())
    .current_dir(temp_dir.path());

    let source =
        b"pub fn sccache_native_probe(x:u64)->u64{x.wrapping_mul(17).rotate_left(9)}\\n".to_vec();
    let output = run_input_output(cmd, Some(source)).await?;
    let llvm_ir = String::from_utf8(output.stdout).context("native probe LLVM IR was not UTF-8")?;
    parse_native_profile(&llvm_ir)
}
''',
'''    let profile = probe_cpu_profile(creator, executable, env_vars, "native").await?;
    let mut cache = NATIVE_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(cache.entry(key).or_insert_with(|| profile.clone()).clone())
}

async fn cached_explicit_cpu_profile<T>(
    creator: T,
    executable: &Path,
    rustc_verbose_version: &str,
    env_vars: &[(OsString, OsString)],
    cpu: &str,
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let key = (
        executable.to_owned(),
        rustc_verbose_version.to_owned(),
        cpu.to_owned(),
    );
    if let Some(profile) = EXPLICIT_CPU_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&key)
        .cloned()
    {
        return Ok(profile);
    }

    let profile = probe_cpu_profile(creator, executable, env_vars, cpu).await?;
    let mut cache = EXPLICIT_CPU_PROFILE_CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(cache.entry(key).or_insert_with(|| profile.clone()).clone())
}

fn native_profile_cpu(profile: &str) -> Option<&str> {
    let (cpu, _) = profile.split_once('|')?;
    (!cpu.is_empty()).then_some(cpu)
}

async fn probe_cpu_profile<T>(
    mut creator: T,
    executable: &Path,
    env_vars: &[(OsString, OsString)],
    cpu: &str,
) -> Result<String>
where
    T: CommandCreatorSync,
{
    let temp_dir = tempfile::Builder::new()
        .prefix("sccache-native")
        .tempdir()
        .context("Failed to create native-profile temp dir")?;
    let mut cmd = creator.new_command_sync(executable);
    cmd.args(&[
        "-",
        "--crate-name",
        "sccache_native_probe",
        "--crate-type",
        "lib",
        "--emit=llvm-ir=-",
        "-C",
    ])
    .arg(format!("target-cpu={cpu}"))
    .env_clear()
    .envs(env_vars.to_vec())
    .current_dir(temp_dir.path());

    let source =
        b"pub fn sccache_native_probe(x:u64)->u64{x.wrapping_mul(17).rotate_left(9)}\\n".to_vec();
    let output = run_input_output(cmd, Some(source)).await?;
    let llvm_ir = String::from_utf8(output.stdout).context("native probe LLVM IR was not UTF-8")?;
    parse_native_profile(&llvm_ir)
}
''')

replace(
'''        let mut effective_arguments = self.parsed_args.arguments.clone();
        let native_requested = native_target_requested(&effective_arguments);
        let target = compilation_target(&effective_arguments, &self.host);
        let mut allow_dist = true;
        let mut effective_cache_control = cache_control;
        let mut resolved_native_profile = None;
        if native_requested && may_dist {
            if target.starts_with("x86_64-") {
                rewrite_native_target_cpu(&mut effective_arguments, "x86-64-v2");
                resolved_native_profile = Some("x86-64-v2".to_owned());
                if !WARNED_DIST_NATIVE_PORTABLE.swap(true, Ordering::Relaxed) {
                    warn!(
                        "distributed Rust compile requested -C target-cpu=native; using x86-64-v2 for deterministic heterogeneous-worker codegen (performance may be reduced)"
                    );
                }
            } else {
                allow_dist = false;
                warn!(
                    "distributed Rust compile requested -C target-cpu=native for {target}; compiling locally because no portable native policy is defined for this target"
                );
            }
        }

        if native_requested && (!may_dist || !allow_dist) {
            let profile = if let Some(profile) = self.native_profile.as_ref() {
                profile.clone()
            } else {
                match cached_native_profile(
                    (*creator).clone(),
                    &self.executable,
                    &self.version,
                    &env_vars,
                )
                .await
                {
                    Ok(profile) => profile,
                    Err(error) => {
                        warn!(
                            "Failed to resolve rustc native CPU profile; bypassing cache: {error:#}"
                        );
                        effective_cache_control = CacheControl::ForceNoCache;
                        format!("unresolved:{}", self.host)
                    }
                }
            };
            resolved_native_profile = Some(profile);
        }
''',
'''        let mut effective_arguments = self.parsed_args.arguments.clone();
        let native_target = native_target_requested(&effective_arguments);
        let native_tune = native_tune_requested(&effective_arguments);
        let native_requested = native_target || native_tune;
        let target = compilation_target(&effective_arguments, &self.host);
        let mut allow_dist = true;
        let mut effective_cache_control = cache_control;
        let mut resolved_native_profile = None;
        let mut native_rewritten_to_explicit = false;

        if native_requested {
            let profile = if let Some(profile) = self.native_profile.as_ref() {
                profile.clone()
            } else {
                match cached_native_profile(
                    (*creator).clone(),
                    &self.executable,
                    &self.version,
                    &env_vars,
                )
                .await
                {
                    Ok(profile) => profile,
                    Err(error) => {
                        warn!(
                            "Failed to resolve rustc native CPU profile; bypassing cache and distributed compilation: {error:#}"
                        );
                        effective_cache_control = CacheControl::ForceNoCache;
                        allow_dist = false;
                        format!("unresolved:{}", self.host)
                    }
                }
            };
            resolved_native_profile = Some(profile);
        }

        if native_requested && may_dist && allow_dist {
            if native_tune {
                allow_dist = false;
                warn!(
                    "distributed Rust compile requested -C tune-cpu=native; compiling locally because native tuning is not yet resolved for workers"
                );
            } else if target != self.host {
                allow_dist = false;
                warn!(
                    "distributed Rust compile requested -C target-cpu=native for {target}; compiling locally because native resolution is only proven for host target {}",
                    self.host
                );
            } else if let Some(profile) = resolved_native_profile.as_ref()
                && let Some(cpu) = native_profile_cpu(profile)
            {
                match cached_explicit_cpu_profile(
                    (*creator).clone(),
                    &self.executable,
                    &self.version,
                    &env_vars,
                    cpu,
                )
                .await
                {
                    Ok(explicit_profile) if explicit_profile == *profile => {
                        rewrite_native_target_cpu(&mut effective_arguments, cpu);
                        native_rewritten_to_explicit = true;
                    }
                    Ok(explicit_profile) => {
                        allow_dist = false;
                        warn!(
                            "rustc native CPU profile {profile:?} does not match explicit {cpu} profile {explicit_profile:?}; compiling locally"
                        );
                    }
                    Err(error) => {
                        allow_dist = false;
                        warn!(
                            "Failed to verify explicit rustc CPU profile for {cpu}; compiling native request locally: {error:#}"
                        );
                    }
                }
            } else {
                allow_dist = false;
                warn!(
                    "rustc native CPU profile did not contain an explicit CPU name; compiling locally"
                );
            }
        }
''')

replace(
'''        if native_requested && (!may_dist || !target.starts_with("x86_64-")) {
            if let Some(profile) = resolved_native_profile.as_ref() {
                profile.hash(&mut HashToDigest { digest: &mut m });
            } else {
                effective_cache_control = CacheControl::ForceNoCache;
            }
        }
''',
'''        if native_requested && !native_rewritten_to_explicit {
            if let Some(profile) = resolved_native_profile.as_ref() {
                profile.hash(&mut HashToDigest { digest: &mut m });
            } else {
                effective_cache_control = CacheControl::ForceNoCache;
            }
        }
''')

replace('fn test_dist_native_normalizes_to_x86_64_v2() -> Result<()> {',
        'fn test_dist_native_resolves_to_equivalent_explicit_cpu() -> Result<()> {')
replace(
'''            if profile.is_none() {
                next_command(&creator, Err(anyhow!("native profile probe failed")));
            }
            mock_dep_info(&creator, &["foo.rs"]);
''',
'''            if profile.is_none() {
                next_command(&creator, Err(anyhow!("native profile probe failed")));
            } else if may_dist {
                let (cpu, features) = profile.unwrap().split_once('|').unwrap();
                let ir = format!(
                    "attributes #0 = {{ \\\"target-cpu\\\"=\\\"{cpu}\\\" \\\"target-features\\\"=\\\"{features}\\\" }}\\n"
                );
                next_command(&creator, Ok(MockChild::new(exit_status(0), ir, "")));
            }
            mock_dep_info(&creator, &["foo.rs"]);
''')
replace('assert_eq!(dist_znver2.key, dist_znver5.key);',
        'assert_ne!(dist_znver2.key, dist_znver5.key);')
replace('assert!(local_args.iter().any(|arg| arg == "target-cpu=x86-64-v2"));',
        'assert!(local_args.iter().any(|arg| arg == "target-cpu=znver2"));')
replace('assert!(dist_args.iter().any(|arg| arg == "target-cpu=x86-64-v2"));',
        'assert!(dist_args.iter().any(|arg| arg == "target-cpu=znver2"));')

p.write_text(s)
