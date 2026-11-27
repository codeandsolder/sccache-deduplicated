//! Native instrumented test execution. Per-test processes and LLVM tools
//! share the existing managed compiler session's local admission. Coverage
//! is exported as evidence, not silently installed as a skipping baseline.
use crate::{
    build_plan::{self, process_command},
    build_runtime::{
        ContentId, PlanAction, PlanNode,
        intermediate_fs::{IntermediateContent, intermediate_reference},
    },
    commands::{CompileInvocation, CompileSession},
    dist::native::intermediate::Content,
};
use anyhow::{Context, Result, ensure};
use sccache_rust_build::{
    PlannedExecutable, PlannedHarness, Planner, Toolchain, Workspace, content_file,
    impact::{
        CoverageMode,
        coverage::{
            BinaryFunctionMap, ExecutableIndex, ExecutableMap, HitRange, build_function_map_with,
            executed_functions,
        },
        harness::{DiscoveredTest, HarnessOptions, inventory, verify_single_success},
        revision::{RevisionSnapshot, committed_changes, git_root},
        selection::{Baseline, TestId, select},
        sources::CoverageSources,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{self, Read, Seek, Write},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use tempfile::{NamedTempFile, TempDir};

pub(crate) struct Options<'a> {
    pub report: &'a Path,
    pub impact_project: Option<&'a str>,
    pub impact_shadow: bool,
    pub aggregate: Option<&'a Path>,
    pub mode: CoverageMode,
    pub tools_dir: Option<&'a Path>,
    pub jobs: NonZeroUsize,
    pub trailing: &'a [OsString],
    pub verbose: bool,
}

#[derive(Debug, Serialize)]
struct ToolIdentity {
    version: String,
    content: ContentId,
}

struct LlvmTools {
    profdata: PathBuf,
    cov: PathBuf,
    profdata_identity: ToolIdentity,
    cov_identity: ToolIdentity,
}

fn llvm_version(text: &str) -> Option<&str> {
    text.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("LLVM version: ")
            .or_else(|| line.strip_prefix("LLVM version "))
            .and_then(|v| v.split_whitespace().next())
    })
}

fn version_series(version: &str) -> Option<(&str, &str)> {
    let mut parts = version.split('.');
    Some((parts.next()?, parts.next()?))
}

fn command_output(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{}: {}",
        command.get_program().to_string_lossy(),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

impl LlvmTools {
    fn discover(toolchain: &Toolchain, cwd: &Path, explicit: Option<&Path>) -> Result<Self> {
        let expected =
            llvm_version(&toolchain.version).context("rustc did not report LLVM version")?;
        let root = command_output(
            Command::new(&toolchain.rustc)
                .current_dir(cwd)
                .arg("--print=sysroot"),
        )?;
        let bundled = Path::new(root.trim_end())
            .join("lib/rustlib")
            .join(&toolchain.host.triple)
            .join("bin");
        let find = |name: &str| -> Result<(PathBuf, ToolIdentity)> {
            let filename = format!("{name}{}", std::env::consts::EXE_SUFFIX);
            let path=if let Some(dir)=explicit {
                cwd.join(dir).join(&filename)
            } else if bundled.join(&filename).is_file() {
                bundled.join(&filename)
            } else {
                which::which(&filename).with_context(||format!("install llvm-tools for the selected Rust toolchain or specify --llvm-tools-dir ({name})"))?
            }.canonicalize()?;
            let version = command_output(Command::new(&path).arg("--version"))?;
            let version = llvm_version(&version)
                .context("LLVM tool did not report a version")?
                .to_owned();
            ensure!(
                version_series(&version) == version_series(expected),
                "{} uses LLVM {version}, rustc uses LLVM {expected}; select matching LLVM tools",
                path.display()
            );
            let identity = ToolIdentity {
                version,
                content: content_file(&path)?,
            };
            Ok((path, identity))
        };
        let (profdata, profdata_identity) = find("llvm-profdata")?;
        let (cov, cov_identity) = find("llvm-cov")?;
        Ok(Self {
            profdata,
            cov,
            profdata_identity,
            cov_identity,
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            content_file(&self.profdata)? == self.profdata_identity.content
                && content_file(&self.cov)? == self.cov_identity.content,
            "LLVM tools changed during collection"
        );
        Ok(())
    }
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn capture(
    session: &CompileSession<'_>,
    scratch: &Path,
    command: &mut Command,
) -> Result<Captured> {
    let mut stdout = tempfile::tempfile_in(scratch)?;
    let mut stderr = tempfile::tempfile_in(scratch)?;
    command
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?);
    let status = session.execute_process(command)?;
    stdout.rewind()?;
    stderr.rewind()?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.read_to_end(&mut out)?;
    stderr.read_to_end(&mut err)?;
    Ok(Captured {
        status,
        stdout: out,
        stderr: err,
    })
}

fn successful(output: Captured, label: &str) -> Result<Vec<u8>> {
    ensure!(
        output.status.success(),
        "{label}: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}

/// LLVM continuous mode is a runtime capability, not just a filename flag.
/// Verify a managed, instrumented executable leaves usable counters after
/// SIGKILL before trusting this mode for a collection.
fn verify_continuous(
    session: &CompileSession<'_>,
    toolchain: &Toolchain,
    scratch: &Path,
    tools: &LlvmTools,
) -> Result<()> {
    ensure!(
        toolchain.host.triple == toolchain.target.triple,
        "continuous coverage requires a native target"
    );
    let probe = tempfile::tempdir_in(scratch)?;
    let source = probe.path().join("probe.rs");
    let binary = probe.path().join("coverage-probe");
    let marker = probe.path().join("ready");
    fs::write(
        &source,
        r#"
#[inline(never)]
fn continuous_probe_hit() -> u32 { std::hint::black_box(42) }
fn main() {
    assert_eq!(continuous_probe_hit(), 42);
    std::fs::write(std::env::args_os().nth(1).unwrap(), b"ready").unwrap();
    loop { std::thread::park(); }
}
"#,
    )?;
    let mut args: Vec<OsString> = vec![
        "--crate-name".into(),
        "coverage_probe".into(),
        "--crate-type=bin".into(),
        "--edition=2024".into(),
        "--emit=link".into(),
    ];
    args.extend(CoverageMode::Continuous.flags().iter().map(OsString::from));
    args.extend([
        source.as_os_str().to_owned(),
        "-o".into(),
        binary.as_os_str().to_owned(),
    ]);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let status = session.execute(
        CompileInvocation {
            exe: &toolchain.rustc,
            cmdline: args,
            cwd: probe.path(),
            env_vars: std::env::vars_os().collect(),
        },
        &mut stdout,
        &mut stderr,
    )?;
    ensure!(
        status == 0,
        "continuous coverage probe compilation: {}",
        String::from_utf8_lossy(&stderr)
    );
    let mut command = Command::new(&binary);
    command
        .arg(&marker)
        .env(
            "LLVM_PROFILE_FILE",
            probe.path().join(CoverageMode::Continuous.profile_name()),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    session.with_local_process(&mut command, |command| {
        let mut child = command.spawn()?;
        let ready = (|| -> Result<()> {
            let start = Instant::now();
            while !marker.is_file() {
                ensure!(
                    child.try_wait()?.is_none(),
                    "continuous coverage probe exited prematurely"
                );
                ensure!(
                    start.elapsed() < Duration::from_secs(10),
                    "continuous coverage probe timed out"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        })();
        let killed = child.kill();
        let reaped = child.wait();
        ready?;
        killed?;
        reaped?;
        Ok(())
    })?;
    let profile = merge_text(session, scratch, tools, &raw_profiles(probe.path())?)?;
    let text = fs::read_to_string(profile.path())?;
    ensure!(
        executed_functions(&text)?
            .iter()
            .any(|name| name.contains("continuous_probe_hit")),
        "LLVM continuous coverage did not preserve executed counters after process termination"
    );
    Ok(())
}

fn raw_profiles(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "profraw") {
            ensure!(
                entry.file_type()?.is_file(),
                "unexpected raw profile file type"
            );
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn merge_text(
    session: &CompileSession<'_>,
    scratch: &Path,
    tools: &LlvmTools,
    profiles: &[PathBuf],
) -> Result<NamedTempFile> {
    ensure!(!profiles.is_empty(), "no LLVM profile generated");
    let output = NamedTempFile::new_in(scratch)?;
    let mut command = Command::new(&tools.profdata);
    command
        .args(["merge", "--sparse", "--text", "--failure-mode=any"])
        .args(profiles)
        .arg("-o")
        .arg(output.path())
        .stdin(Stdio::null());
    successful(
        capture(session, scratch, &mut command)?,
        "llvm-profdata merge",
    )?;
    Ok(output)
}

fn content_identity(content: &Content, path: &Path) -> Result<ContentId> {
    let file = File::open(path)?;
    if let Some(reference) = intermediate_reference(&file)? {
        content.authorize(reference)?;
        Ok(reference.blob.id)
    } else {
        // Mutable final binaries are verified by bytes, never by stat time.
        let mut file = file;
        let mut hash = blake3::Hasher::new();
        io::copy(&mut file, &mut hash)?;
        Ok(ContentId(*hash.finalize().as_bytes()))
    }
}

#[derive(Debug, Serialize)]
struct TestReport {
    name: String,
    passed: bool,
    duration_ns: u64,
    coverage: Option<BTreeSet<HitRange>>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SuiteReport {
    unit: String,
    label: String,
    executable: Option<ContentId>,
    ignored: Vec<String>,
    tests: Vec<TestReport>,
    whole_harness: bool,
    passed: bool,
    coverage_error: Option<String>,
    collection_failed: bool,
}

struct TestResult {
    report: TestReport,
    profile: Option<NamedTempFile>,
}

struct PreparedHarness {
    plan: PlannedHarness,
    options: HarnessOptions,
    map: Arc<BinaryFunctionMap>,
    executables: ExecutableIndex,
    sentinel: Option<HitRange>,
}

struct Job {
    harness: Arc<PreparedHarness>,
    test: DiscoveredTest,
    result: mpsc::Sender<Result<TestResult>>,
}

type MapSlot = Arc<Mutex<Option<Arc<BinaryFunctionMap>>>>;

struct Collector<'a> {
    session: &'a CompileSession<'a>,
    content: &'a Content,
    sources: &'a CoverageSources,
    git_root: PathBuf,
    scratch: PathBuf,
    tools: LlvmTools,
    mode: CoverageMode,
    empty_profile: PathBuf,
    maps: Mutex<BTreeMap<ContentId, MapSlot>>,
    suites: Mutex<Vec<SuiteReport>>,
    profiles: Mutex<Vec<NamedTempFile>>,
    aggregate: bool,
}

fn locked<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| anyhow::anyhow!("coverage state poisoned"))
}

impl Collector<'_> {
    fn map(&self, executable: &PlannedExecutable) -> Result<Arc<BinaryFunctionMap>> {
        let id = content_identity(self.content, &executable.path)?;
        let slot = Arc::clone(locked(&self.maps)?.entry(id).or_default());
        let mut slot = locked(&slot)?;
        if let Some(map) = slot.as_ref() {
            return Ok(Arc::clone(map));
        }
        let mut command = Command::new(&self.tools.cov);
        command
            .arg("export")
            .arg(&executable.path)
            .arg("--instr-profile")
            .arg(&self.empty_profile)
            .arg("--skip-expansions")
            .stdin(Stdio::null());
        let stdout = successful(
            capture(self.session, &self.scratch, &mut command)?,
            "llvm-cov export",
        )?;
        let functions = build_function_map_with(std::str::from_utf8(&stdout)?, |path| {
            self.sources.key(path, &self.git_root)
        })?;
        ensure!(
            content_identity(self.content, &executable.path)? == id,
            "executable changed during LLVM export"
        );
        let map = Arc::new(BinaryFunctionMap {
            binary: id,
            functions,
        });
        *slot = Some(Arc::clone(&map));
        Ok(map)
    }

    fn prepare(
        &self,
        plan: PlannedHarness,
        options: HarnessOptions,
    ) -> Result<(Arc<PreparedHarness>, Vec<DiscoveredTest>)> {
        let listing_dir = tempfile::tempdir_in(&self.scratch)?;
        let mut list = process_command(&plan.command, false);
        list.args(options.listing()).env(
            "LLVM_PROFILE_FILE",
            listing_dir.path().join(self.mode.profile_name()),
        );
        let stdout = successful(
            capture(self.session, &self.scratch, &mut list)?,
            "libtest discovery",
        )?;
        let tests = inventory(&stdout)?;
        let map = self.map(&plan.binary)?;
        let mut executables = Vec::new();
        for executable in &plan.subprocesses {
            executables.push(ExecutableMap {
                path: executable.path.clone(),
                map: self.map(executable)?,
                sentinels: self
                    .sources
                    .sentinel(&executable.source, &self.git_root)?
                    .into_iter()
                    .collect(),
            });
        }
        let executables = ExecutableIndex::with_identity(&executables, |path| {
            content_identity(self.content, path)
        })?;
        let sentinel = self.sources.sentinel(&plan.binary.source, &self.git_root)?;
        Ok((
            Arc::new(PreparedHarness {
                plan,
                options,
                map,
                executables,
                sentinel,
            }),
            tests,
        ))
    }

    fn execute_test(&self, harness: &PreparedHarness, test: &DiscoveredTest) -> Result<TestResult> {
        let dir = tempfile::tempdir_in(&self.scratch)?;
        let mut command = process_command(&harness.plan.command, false);
        command.args(harness.options.exact(&test.name)).env(
            "LLVM_PROFILE_FILE",
            dir.path().join(self.mode.profile_name()),
        );
        let started = Instant::now();
        let output = capture(self.session, &self.scratch, &mut command)?;
        let duration_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let passed = output.status.success();
        let mut report = TestReport {
            name: test.name.clone(),
            passed,
            duration_ns,
            coverage: None,
            error: None,
        };
        if !passed {
            report.error = Some(format!("test process exited with {}", output.status));
            let mut err = io::stderr().lock();
            writeln!(err, "test {} failed", test.name)?;
            err.write_all(&output.stdout)?;
            err.write_all(&output.stderr)?;
            return Ok(TestResult {
                report,
                profile: None,
            });
        }
        if let Err(error) = verify_single_success(&output.stdout, &test.name) {
            report.passed = false;
            report.error = Some(format!("{error:#}"));
            return Ok(TestResult {
                report,
                profile: None,
            });
        }
        // Display successful output only when libtest emitted it; failure
        // output above is never discarded.
        for line in output.stdout.split(|b| *b == b'\n') {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line)
                && let Some(text) = value.get("stdout").and_then(serde_json::Value::as_str)
            {
                eprint!("{text}");
            }
        }
        let extracted = (|| -> Result<_> {
            let raw = raw_profiles(dir.path())?;
            let profile = merge_text(self.session, &self.scratch, &self.tools, &raw)?;
            let text = fs::read_to_string(profile.path())?;
            let functions = executed_functions(&text)?;
            let mut ranges =
                harness
                    .executables
                    .ranges(&functions, &harness.map.functions, raw.len())?;
            ranges.extend(harness.sentinel.iter().cloned());
            Ok((ranges, profile))
        })();
        let profile = match extracted {
            Ok((ranges, profile)) => {
                report.coverage = Some(ranges);
                self.aggregate.then_some(profile)
            }
            Err(error) => {
                report.error = Some(format!("{error:#}"));
                None
            }
        };
        Ok(TestResult { report, profile })
    }

    fn whole(
        &self,
        node: &PlanNode,
        unit: String,
        mut reason: String,
        mut collection_failed: bool,
    ) -> Result<SuiteReport> {
        let PlanAction::Process { command, .. } = &node.action else {
            anyhow::bail!("test execution was not a process");
        };
        let dir = tempfile::tempdir_in(&self.scratch)?;
        let mut command = process_command(command, false);
        command.env(
            "LLVM_PROFILE_FILE",
            dir.path().join(self.mode.profile_name()),
        );
        let output = capture(self.session, &self.scratch, &mut command)?;
        io::stdout().lock().write_all(&output.stdout)?;
        io::stderr().lock().write_all(&output.stderr)?;
        if self.aggregate {
            let raw = raw_profiles(dir.path())?;
            if !raw.is_empty() {
                match merge_text(self.session, &self.scratch, &self.tools, &raw) {
                    Ok(profile) => locked(&self.profiles)?.push(profile),
                    Err(error) => {
                        collection_failed = true;
                        reason.push_str(&format!("; aggregate profile unavailable: {error:#}"));
                    }
                }
            }
        }
        Ok(SuiteReport {
            unit,
            label: node.label.clone(),
            executable: None,
            ignored: vec![],
            tests: vec![],
            whole_harness: true,
            passed: output.status.success(),
            coverage_error: Some(reason),
            collection_failed,
        })
    }

    fn suite(
        &self,
        node: &PlanNode,
        harness: Option<PlannedHarness>,
        trailing: &[OsString],
        sender: &mpsc::SyncSender<Job>,
    ) -> Result<()> {
        let (harness, tests) = if let Some(plan) = harness {
            let unit = plan.unit.clone();
            if let Some(options) = HarnessOptions::from_arguments(trailing) {
                match self.prepare(plan, options) {
                    Ok(value) => value,
                    Err(error) => {
                        let result = self.whole(
                            node,
                            unit,
                            format!("per-test collection unavailable: {error:#}"),
                            true,
                        )?;
                        locked(&self.suites)?.push(result);
                        return Ok(());
                    }
                }
            } else {
                let result = self.whole(
                    node,
                    unit,
                    "harness options require whole-process execution".into(),
                    false,
                )?;
                locked(&self.suites)?.push(result);
                return Ok(());
            }
        } else {
            let result = self.whole(
                node,
                node.label.clone(),
                "custom harness or doctest: full execution".into(),
                false,
            )?;
            locked(&self.suites)?.push(result);
            return Ok(());
        };
        let (reply, receiver) = mpsc::channel();
        let mut ignored = Vec::new();
        let mut expected = 0;
        for test in tests {
            if !harness.options.executes(&test) {
                ignored.push(test.name);
                continue;
            }
            sender
                .send(Job {
                    harness: Arc::clone(&harness),
                    test,
                    result: reply.clone(),
                })
                .map_err(|_| anyhow::anyhow!("coverage worker pool stopped"))?;
            expected += 1;
        }
        drop(reply);
        let mut reports = Vec::with_capacity(expected);
        for result in receiver {
            let result = result?;
            if let Some(profile) = result.profile {
                locked(&self.profiles)?.push(profile);
            }
            reports.push(result.report);
        }
        ensure!(
            reports.len() == expected,
            "coverage worker lost a test result"
        );
        reports.sort_by(|a, b| a.name.cmp(&b.name));
        let validation = harness
            .map
            .validate(content_identity(self.content, &harness.plan.binary.path)?)
            .and_then(|()| {
                harness
                    .executables
                    .validate(|path| content_identity(self.content, path))
            });
        let coverage_error = validation.err().map(|error| format!("{error:#}"));
        if coverage_error.is_some() {
            for report in &mut reports {
                report.coverage = None;
            }
        }
        let passed = reports.iter().all(|report| report.passed);
        eprintln!(
            "{}: {} tests, {} ignored, {} with coverage",
            node.label,
            reports.len(),
            ignored.len(),
            reports.iter().filter(|r| r.coverage.is_some()).count()
        );
        let collection_failed =
            coverage_error.is_some() || reports.iter().any(|test| test.coverage.is_none());
        locked(&self.suites)?.push(SuiteReport {
            unit: harness.plan.unit.clone(),
            label: node.label.clone(),
            executable: Some(harness.map.binary),
            ignored,
            tests: reports,
            whole_harness: false,
            passed,
            collection_failed,
            coverage_error,
        });
        Ok(())
    }
}

// These records are advisory. A successful coverage run is not yet a
// complete runtime input contract, so no client may skip tests from this
// schema. Keep the distinction explicit in persisted evidence.
#[derive(Serialize, Deserialize)]
struct ImpactRecord {
    schema: u32,
    advisory: bool,
    scope: ContentId,
    revision: String,
    tree: ContentId,
    baselines: Vec<(TestId, Baseline)>,
}

struct ImpactContext {
    slot: ContentId,
    scope: ContentId,
    previous: Option<(crate::build_runtime::wire::ImpactHead, ImpactRecord)>,
    lookup_error: Option<String>,
    shadow: bool,
}

#[derive(Serialize)]
struct ImpactReport {
    scope: ContentId,
    previous: Option<crate::build_runtime::TreeId>,
    lookup_error: Option<String>,
    publication: Option<crate::build_runtime::wire::ImpactUpdate>,
    publication_error: Option<String>,
    comparison: Option<ShadowComparison>,
}

#[derive(Serialize)]
struct ShadowComparison {
    total: usize,
    predicted: usize,
    missed_failures: Vec<TestId>,
    reasons: Vec<(
        TestId,
        BTreeSet<sccache_rust_build::impact::selection::Reason>,
    )>,
}

impl ImpactContext {
    fn new(
        content: &Content,
        planner: &Planner<'_>,
        toolchain: &Toolchain,
        tools: &LlvmTools,
        git_root: &Path,
        project: &str,
        shadow: bool,
    ) -> Result<Self> {
        ensure!(
            !project.trim().is_empty(),
            "impact project must be nonempty"
        );
        let slot = planner.impact_slot(project, git_root)?;
        let rustc = content_file(&toolchain.rustc)?;
        let rustdoc = toolchain.rustdoc.as_deref().map(content_file).transpose()?;
        let scope = ContentId::of(&serde_json::to_vec(&(
            "advisory-impact-v1",
            planner.impact_configuration()?,
            rustc,
            rustdoc,
            tools.profdata_identity.content,
            tools.cov_identity.content,
        ))?);
        let previous = content.lookup_impact_head(slot).and_then(|value| {
            let Some((head, file)) = value else {
                return Ok(None);
            };
            let record: ImpactRecord = serde_json::from_reader(file)?;
            ensure!(
                record.schema == 1 && record.advisory,
                "unknown impact evidence schema"
            );
            Ok(Some((head, record)))
        });
        let (previous, lookup_error) = match previous {
            Ok(previous) => (previous, None),
            Err(error) => (None, Some(format!("{error:#}"))),
        };
        Ok(Self {
            slot,
            scope,
            previous,
            lookup_error,
            shadow,
        })
    }

    fn finish(
        self,
        collector: &Collector<'_>,
        before: &RevisionSnapshot,
        stable: bool,
        passed: bool,
        incomplete: bool,
        suites: &[SuiteReport],
    ) -> Result<ImpactReport> {
        let previous = self.previous.as_ref().map(|(head, _)| head.tree);
        let mut report = ImpactReport {
            scope: self.scope,
            previous,
            lookup_error: self.lookup_error,
            publication: None,
            publication_error: None,
            comparison: None,
        };
        if self.shadow {
            let inventory = suites
                .iter()
                .flat_map(|suite| {
                    suite.tests.iter().map(|test| {
                        (
                            TestId {
                                unit: suite.unit.clone(),
                                name: test.name.clone(),
                            },
                            self.scope,
                        )
                    })
                })
                .collect::<BTreeMap<_, _>>();
            let baselines = self
                .previous
                .as_ref()
                .map(|(_, record)| record.baselines.iter().cloned().collect::<BTreeMap<_, _>>())
                .unwrap_or_default();
            let mut changes = BTreeMap::new();
            if before.clean
                && stable
                && let Some(head) = &before.head
            {
                let revisions = baselines
                    .values()
                    .map(|baseline| baseline.revision.clone())
                    .collect::<BTreeSet<_>>();
                for revision in revisions {
                    let known = baselines
                        .values()
                        .filter(|baseline| baseline.revision == revision)
                        .flat_map(|baseline| baseline.ranges.iter().map(|range| range.file.clone()))
                        .collect();
                    // Missing commits, malformed diffs and unverified inputs
                    // never produce an empty successful change set.
                    if let Ok(change) =
                        committed_changes(&collector.git_root, &revision, head, &known)
                    {
                        changes.insert(revision, change);
                    }
                }
            }
            let selected = select(&inventory, &baselines, &changes)?;
            let missed_failures = suites
                .iter()
                .flat_map(|suite| {
                    suite
                        .tests
                        .iter()
                        .filter(|test| !test.passed)
                        .map(|test| TestId {
                            unit: suite.unit.clone(),
                            name: test.name.clone(),
                        })
                })
                .filter(|test| !selected.contains_key(test))
                .collect();
            report.comparison = Some(ShadowComparison {
                total: inventory.len(),
                predicted: selected.len(),
                missed_failures,
                reasons: selected.into_iter().collect(),
            });
        }
        // Untracked whole-harness runs remain full-run actions. Only complete
        // per-test coverage is recorded, never a partial failed collection.
        if passed
            && stable
            && before.clean
            && !incomplete
            && report.lookup_error.is_none()
            && let Some(revision) = before.head.as_ref()
        {
            let mut baselines = Vec::new();
            for suite in suites {
                if let Some(executable) = suite.executable {
                    for test in &suite.tests {
                        if let Some(ranges) = &test.coverage {
                            baselines.push((
                                TestId {
                                    unit: suite.unit.clone(),
                                    name: test.name.clone(),
                                },
                                Baseline {
                                    scope: self.scope,
                                    revision: revision.clone(),
                                    executable,
                                    ranges: ranges.clone(),
                                },
                            ));
                        }
                    }
                }
            }
            baselines.sort_by(|a, b| a.0.cmp(&b.0));
            if !baselines.is_empty() {
                let record = ImpactRecord {
                    schema: 1,
                    advisory: true,
                    scope: self.scope,
                    revision: revision.clone(),
                    tree: before.tree,
                    baselines,
                };
                let mut file = tempfile::tempfile_in(&collector.scratch)?;
                serde_json::to_writer(&mut file, &record)?;
                match collector
                    .content
                    .publish_impact_head(self.slot, previous, file)
                {
                    Ok(update) => report.publication = Some(update),
                    Err(error) => report.publication_error = Some(format!("{error:#}")),
                }
            }
        }
        Ok(report)
    }
}

#[derive(Serialize)]
struct Report<'a> {
    schema: u32,
    mode: CoverageMode,
    rustc_version: &'a str,
    llvm_cov: &'a ToolIdentity,
    llvm_profdata: &'a ToolIdentity,
    repository: RevisionSnapshot,
    stable_source_snapshot: bool,
    suites: Vec<SuiteReport>,
    aggregate_published: bool,
    aggregate_error: Option<String>,
    impact: Option<ImpactReport>,
}

fn atomic_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = NamedTempFile::new_in(parent)?;
    serde_json::to_writer(file.as_file_mut(), value)?;
    file.as_file_mut().write_all(b"\n")?;
    file.persist(path)?;
    Ok(())
}

fn publish_aggregate(collector: &Collector<'_>, destination: &Path) -> Result<bool> {
    let profiles = locked(&collector.profiles)?;
    if profiles.is_empty() {
        return Ok(false);
    }
    let mut list = NamedTempFile::new_in(&collector.scratch)?;
    for profile in profiles.iter() {
        let path = profile.path().to_str().context("non-UTF8 profile path")?;
        ensure!(!path.contains(['\n', '\r']), "invalid profile list path");
        writeln!(list, "{path}")?;
    }
    list.flush()?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let output = NamedTempFile::new_in(parent)?;
    let mut command = Command::new(&collector.tools.profdata);
    command
        .args(["merge", "--sparse", "--failure-mode=any", "--input-files"])
        .arg(list.path())
        .arg("-o")
        .arg(output.path())
        .stdin(Stdio::null());
    successful(
        capture(collector.session, &collector.scratch, &mut command)?,
        "aggregate LLVM profile",
    )?;
    output.persist(destination)?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn execute(
    session: &CompileSession<'_>,
    content: &Content,
    planner: &Planner<'_>,
    toolchain: &Toolchain,
    workspace: &Workspace,
    lease_root: &Path,
    max_in_flight: NonZeroUsize,
    options: Options<'_>,
) -> Result<i32> {
    let git_root = git_root(&workspace.root)?;
    let before = RevisionSnapshot::capture(&git_root)?;
    let tools = LlvmTools::discover(toolchain, &workspace.root, options.tools_dir)?;
    let scratch: TempDir = tempfile::Builder::new()
        .prefix("test-coverage-")
        .tempdir_in(lease_root)?;
    if options.mode == CoverageMode::Continuous {
        verify_continuous(session, toolchain, scratch.path(), &tools)?;
    }
    let empty_text = scratch.path().join("empty.proftext");
    let empty_profile = scratch.path().join("empty.profdata");
    fs::write(&empty_text, b"")?;
    let mut command = Command::new(&tools.profdata);
    command
        .arg("merge")
        .arg(&empty_text)
        .arg("-o")
        .arg(&empty_profile)
        .stdin(Stdio::null());
    successful(
        capture(session, scratch.path(), &mut command)?,
        "empty LLVM profile",
    )?;
    let impact = options
        .impact_project
        .map(|project| {
            ImpactContext::new(
                content,
                planner,
                toolchain,
                &tools,
                &git_root,
                project,
                options.impact_shadow,
            )
        })
        .transpose()?;
    let collector = Collector {
        session,
        content,
        sources: planner
            .coverage_sources()
            .context("coverage planner has no source map")?,
        git_root,
        scratch: scratch.path().to_path_buf(),
        tools,
        mode: options.mode,
        empty_profile,
        maps: Mutex::default(),
        suites: Mutex::default(),
        profiles: Mutex::default(),
        aggregate: options.aggregate.is_some(),
    };
    let graph = planner.graph()?;
    let (sender, receiver) = mpsc::sync_channel::<Job>(options.jobs.get().saturating_mul(2));
    let receiver = Mutex::new(receiver);
    thread::scope(|scope| -> Result<()> {
        for _ in 0..options.jobs.get() {
            let receiver = &receiver;
            let collector = &collector;
            scope.spawn(move || {
                loop {
                    let job = match locked(receiver)
                        .and_then(|receiver| receiver.recv().context("coverage queue closed"))
                    {
                        Ok(job) => job,
                        Err(_) => break,
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        collector.execute_test(&job.harness, &job.test)
                    }))
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("coverage test worker panicked")));
                    let _ = job.result.send(result);
                }
            });
        }
        let result = build_plan::dispatch(graph, max_in_flight, |index| {
            let node = planner
                .prepare(index)
                .with_context(|| format!("prepare build node {index}"))?;
            if options.verbose {
                eprintln!("{}", node.label);
            }
            if planner.is_test_execution(index) {
                let harness = planner.test_harness(index, &node)?;
                collector.suite(&node, harness, options.trailing, &sender)?;
            } else {
                build_plan::execute_node(session, &node, &node.action)
                    .with_context(|| node.label.clone())?;
            }
            planner.complete(index)
        });
        drop(sender);
        result
    })?;
    collector.tools.validate()?;
    let stable = before == RevisionSnapshot::capture(&collector.git_root)?;
    let mut suites = std::mem::take(&mut *locked(&collector.suites)?);
    suites.sort_by(|a, b| (&a.unit, &a.label).cmp(&(&b.unit, &b.label)));
    let passed = suites.iter().all(|suite| suite.passed);
    let collected = suites
        .iter()
        .flat_map(|suite| &suite.tests)
        .filter(|test| test.coverage.is_some())
        .count();
    let incomplete = suites.iter().any(|suite| suite.collection_failed);
    let mut aggregate_error = None;
    let aggregate_published = if passed && stable && !incomplete {
        match options
            .aggregate
            .map(|path| publish_aggregate(&collector, path))
            .transpose()
        {
            Ok(published) => published.unwrap_or(false),
            Err(error) => {
                aggregate_error = Some(format!("{error:#}"));
                false
            }
        }
    } else {
        false
    };
    let impact = impact
        .map(|impact| impact.finish(&collector, &before, stable, passed, incomplete, &suites))
        .transpose()?;
    let report = Report {
        schema: 1,
        mode: options.mode,
        rustc_version: &toolchain.version,
        llvm_cov: &collector.tools.cov_identity,
        llvm_profdata: &collector.tools.profdata_identity,
        repository: before,
        stable_source_snapshot: stable,
        suites,
        aggregate_published,
        aggregate_error,
        impact,
    };
    atomic_json(options.report, &report)?;
    eprintln!(
        "native coverage: {collected} tests with mapped coverage; report {}",
        options.report.display()
    );
    if !stable {
        eprintln!("source contents changed during coverage collection");
    }
    Ok(i32::from(
        !passed || !stable || incomplete || (options.aggregate.is_some() && !aggregate_published),
    ))
}
