//! Direct libtest discovery and exact-name execution. No Nextest process or
//! Cargo metadata roundtrip is needed. The caller preserves the actual runner
//! prefix, working directory and environment from the native test action.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeSet, ffi::OsString, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredTest {
    pub name: String,
    pub source: PathBuf,
    pub ignored: bool,
}

#[derive(Debug, Clone)]
pub struct HarnessOptions {
    listing: Vec<OsString>,
    runtime: Vec<OsString>,
    include_ignored: bool,
}

/// Unsupported process-wide options (e.g. benchmarks, no-capture, logfile
/// or shuffle) retain their original semantics via a full harness run.
/// They must never silently turn into a filtered per-test execution.
impl HarnessOptions {
    pub fn from_arguments(args: &[OsString]) -> Option<Self> {
        let mut listing = Vec::new();
        let mut runtime = Vec::new();
        let mut include_ignored = false;
        let mut options = true;
        let mut input = args.iter();
        while let Some(arg) = input.next() {
            let text = arg.to_str()?;
            if !options || !text.starts_with('-') || text == "-" {
                listing.push(arg.clone());
                continue;
            }
            if text == "--" {
                options = false;
                listing.push(arg.clone());
                continue;
            }
            match text {
                "--ignored" | "--include-ignored" => {
                    include_ignored = true;
                    listing.push(arg.clone());
                }
                "--exact" | "--exclude-should-panic" | "--test" => listing.push(arg.clone()),
                "--skip" => {
                    listing.push(arg.clone());
                    listing.push(input.next()?.clone());
                }
                "--force-run-in-process" | "--report-time" | "--ensure-time" | "--show-output" => {
                    runtime.push(arg.clone());
                }
                "-Z" => {
                    if input.next()?.to_str()? != "unstable-options" {
                        return None;
                    }
                }
                "-Zunstable-options" => {}
                _ if text.starts_with("--skip=") => listing.push(arg.clone()),
                _ => return None,
            }
        }
        let mut discovery = vec![
            "-Z".into(),
            "unstable-options".into(),
            "--list".into(),
            "--format=json".into(),
            "--color=never".into(),
        ];
        discovery.extend(listing);
        Some(Self {
            listing: discovery,
            runtime,
            include_ignored,
        })
    }

    pub fn listing(&self) -> &[OsString] {
        &self.listing
    }

    /// Ignored-only and include-ignored discovery already constrain the
    /// inventory. Preserve that policy even if libtest reports ignore=true.
    pub fn executes(&self, test: &DiscoveredTest) -> bool {
        !test.ignored || self.include_ignored
    }

    /// The inventory already applied substring filters and skip rules.
    /// Exact invocation must NOT repeat those filters (libtest combines
    /// positional filters by OR, which would execute extra tests).
    pub fn exact(&self, name: &str) -> Vec<OsString> {
        let mut args = vec![
            "-Z".into(),
            "unstable-options".into(),
            "--format=json".into(),
            "--color=never".into(),
            "--exact".into(),
            "--test-threads=1".into(),
        ];
        if self.include_ignored {
            args.push("--include-ignored".into());
        }
        args.extend(self.runtime.iter().cloned());
        args.extend([OsString::from("--"), OsString::from(name)]);
        args
    }
}

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "type")]
    kind: String,
    event: String,
    #[serde(default)]
    name: String,
    ignore: Option<bool>,
    source_path: Option<PathBuf>,
    tests: Option<usize>,
    benchmarks: Option<usize>,
    total: Option<usize>,
    ignored: Option<usize>,
    test_count: Option<usize>,
    passed: Option<usize>,
    failed: Option<usize>,
    measured: Option<usize>,
}

/// Parse a complete libtest JSON discovery stream. Reject duplicate names,
/// malformed/partial discovery, and benchmark inventories which need a
/// different execution adapter. An empty inventory is valid only when the
/// final suite event attests that it is empty.
pub fn inventory(stdout: &[u8]) -> Result<Vec<DiscoveredTest>> {
    let mut started = false;
    let mut completed = false;
    let mut tests = Vec::new();
    let mut names = BTreeSet::new();
    let mut ignored = 0;
    for line in std::str::from_utf8(stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let event: Event = serde_json::from_str(line).context("invalid libtest discovery event")?;
        ensure!(!completed, "trailing discovery event");
        match (event.kind.as_str(), event.event.as_str()) {
            ("suite", "discovery") => {
                ensure!(!started, "duplicate discovery start");
                started = true;
            }
            ("test", "discovered") => {
                ensure!(
                    started && !event.name.is_empty() && names.insert(event.name.clone()),
                    "invalid or duplicate test name"
                );
                let is_ignored = event.ignore.context("test discovery lacks ignore state")?;
                ignored += usize::from(is_ignored);
                tests.push(DiscoveredTest {
                    name: event.name,
                    source: event
                        .source_path
                        .context("test discovery lacks source path")?,
                    ignored: is_ignored,
                });
            }
            ("benchmark", "discovered") => {
                anyhow::bail!("benchmark inventory requires whole-harness execution")
            }
            ("suite", "completed") => {
                ensure!(
                    started
                        && event.tests == Some(tests.len())
                        && event.benchmarks == Some(0)
                        && event.total == Some(tests.len())
                        && event.ignored == Some(ignored),
                    "incomplete libtest discovery"
                );
                completed = true;
            }
            _ => anyhow::bail!("unexpected libtest discovery event"),
        }
    }
    ensure!(completed, "libtest discovery did not complete");
    tests.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(tests)
}

/// A successful process exit does not prove that a requested test ran:
/// zero-match exact filters and ignored tests also return zero. Require a
/// matching successful terminal event and exact suite counts.
pub fn verify_single_success(stdout: &[u8], name: &str) -> Result<()> {
    let mut suite = false;
    let mut started = false;
    let mut passed = false;
    let mut complete = false;
    for line in std::str::from_utf8(stdout)?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let event: Event = serde_json::from_str(line).context("invalid libtest execution event")?;
        ensure!(!complete, "trailing test event");
        match (event.kind.as_str(), event.event.as_str()) {
            ("suite", "started") => {
                ensure!(
                    !suite && event.test_count == Some(1),
                    "exact invocation did not select one test"
                );
                suite = true;
            }
            ("test", "started") => {
                ensure!(
                    suite && !started && event.name == name,
                    "unexpected test start"
                );
                started = true;
            }
            ("test", "timeout") => ensure!(
                started && !passed && event.name == name,
                "unexpected test timeout event"
            ),
            ("test", "ok") => {
                ensure!(
                    started && !passed && event.name == name,
                    "unexpected test result"
                );
                passed = true;
            }
            ("suite", "ok") => {
                ensure!(
                    passed
                        && event.passed == Some(1)
                        && event.failed == Some(0)
                        && event.ignored == Some(0)
                        && event.measured == Some(0),
                    "invalid exact test summary"
                );
                complete = true;
            }
            _ => anyhow::bail!("unexpected exact test event"),
        }
    }
    ensure!(complete, "exact test did not complete successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_inventory_and_exact_filters_are_independent() -> Result<()> {
        let options = HarnessOptions::from_arguments(&[
            "prefix".into(),
            "--skip".into(),
            "skipme".into(),
            "--include-ignored".into(),
            "--exact".into(),
            "--show-output".into(),
        ])
        .context("supported filter flags")?;
        assert!(options.listing().contains(&"prefix".into()));
        let run = options.exact("prefix::name");
        assert!(!run.contains(&"prefix".into()));
        assert!(!run.contains(&"skipme".into()));
        assert!(run.contains(&"--include-ignored".into()));
        assert!(run.contains(&"--show-output".into()));
        assert!(HarnessOptions::from_arguments(&["--bench".into()]).is_none());
        assert!(HarnessOptions::from_arguments(&["--test-threads=2".into()]).is_none());
        let inventory = inventory(
            br#"{"type":"suite","event":"discovery"}
{"type":"test","event":"discovered","name":"b","ignore":true,"source_path":"src/lib.rs"}
{"type":"test","event":"discovered","name":"a","ignore":false,"source_path":"src/lib.rs"}
{"type":"suite","event":"completed","tests":2,"benchmarks":0,"total":2,"ignored":1}"#,
        )?;
        assert_eq!(
            inventory
                .iter()
                .map(|test| test.name.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert!(inventory[1].ignored);
        assert!(options.executes(&inventory[1]));
        assert!(
            !HarnessOptions::from_arguments(&[])
                .unwrap()
                .executes(&inventory[1])
        );
        Ok(())
    }

    #[test]
    fn zero_test_success_does_not_authorize_coverage() {
        let correct = br#"{"type":"suite","event":"started","test_count":1}
{"type":"test","event":"started","name":"selected"}
{"type":"test","event":"ok","name":"selected"}
{"type":"suite","event":"ok","passed":1,"failed":0,"ignored":0,"measured":0}"#;
        assert!(verify_single_success(correct, "selected").is_ok());
        assert!(verify_single_success(correct, "other").is_err());
        assert!(
            verify_single_success(
                br#"{"type":"suite","event":"started","test_count":0}
{"type":"suite","event":"ok","passed":0,"failed":0,"ignored":0,"measured":0}"#,
                "selected"
            )
            .is_err()
        );
        assert!(inventory(br#"{"type":"suite","event":"discovery"}"#).is_err());
    }

    #[test]
    fn real_libtest_discovery_matches_current_harness() -> Result<()> {
        let options = HarnessOptions::from_arguments(&[
            "impact::harness::tests::zero_test_success_does_not_authorize_coverage".into(),
            "--exact".into(),
        ])
        .context("test options")?;
        let binary = std::env::current_exe()?;
        let output = std::process::Command::new(&binary)
            .args(options.listing())
            .output()?;
        ensure!(
            output.status.success(),
            "libtest list failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let tests = inventory(&output.stdout)?;
        assert_eq!(tests.len(), 1);
        assert!(!tests[0].ignored);
        let output = std::process::Command::new(binary)
            .args(options.exact(&tests[0].name))
            .output()?;
        ensure!(
            output.status.success(),
            "libtest exact failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        verify_single_success(&output.stdout, &tests[0].name)
    }
}
