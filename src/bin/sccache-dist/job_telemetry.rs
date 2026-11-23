// Per-compilation lifecycle and resource telemetry, keyed by the scheduler's
// immutable job ID. This is deliberately local to the worker: it does not
// change the distributed wire format.
use sccache::dist::{CompileCommand, JobId};
use std::hash::{Hash, Hasher};
use std::io;
use std::process::{Command, Output, Stdio};
use std::time::Instant;

pub(super) fn identity(command: &CompileCommand) -> (Option<&str>, u64) {
    let crate_name = command
        .arguments
        .iter()
        .enumerate()
        .find_map(|(index, arg)| {
            if arg == "--crate-name" {
                command.arguments.get(index + 1).map(String::as_str)
            } else {
                arg.strip_prefix("--crate-name=")
            }
        });
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    command.executable.hash(&mut hasher);
    command.arguments.hash(&mut hasher);
    command.env_vars.hash(&mut hasher);
    command.cwd.hash(&mut hasher);
    (crate_name, hasher.finish())
}

/// Execute a compilation, logging the *actual* OS process tree while it lives.
/// All events carry the scheduler job ID, so even a sudden worker OOM leaves
/// durable PID-to-job mappings in the worker's journal.
pub(super) fn run(job_id: JobId, command: &mut Command) -> io::Result<Output> {
    run_with_scope(job_id, command, true)
}

/// A container compiler is not a descendant of the Docker/jexec CLI process.
/// Log the launcher PID and exit, but do not falsely label its memory usage
/// as the compiler's.
pub(super) fn run_external_container(job_id: JobId, command: &mut Command) -> io::Result<Output> {
    run_with_scope(job_id, command, false)
}

fn run_with_scope(
    job_id: JobId,
    command: &mut Command,
    monitor_descendants: bool,
) -> io::Result<Output> {
    // Match Command::output(): stdin must not inherit the worker's stdin.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let wrapper_pid = child.id();
    info!("dist_job_spawn job_id={job_id} wrapper_pid={wrapper_pid}");
    let started = Instant::now();

    #[cfg(target_os = "linux")]
    let monitor = monitor_descendants.then(|| {
        let (sender, receiver) = std::sync::mpsc::channel();
        let monitor =
            std::thread::spawn(move || monitor_process_tree(job_id, wrapper_pid, &receiver));
        (sender, monitor)
    });
    #[cfg(not(target_os = "linux"))]
    let _ = monitor_descendants;

    let output = child.wait_with_output();

    #[cfg(target_os = "linux")]
    if let Some((sender, monitor)) = monitor {
        let _ = sender.send(());
        let peaks = monitor.join();
        if peaks.is_err() {
            error!(
                "dist_job_monitor_failed job_id={job_id} wrapper_pid={wrapper_pid} error=monitor_thread_panicked"
            );
        }
        match (&output, peaks) {
            (Ok(result), Ok(peaks)) => info!(
                "dist_job_process_exit job_id={job_id} wrapper_pid={wrapper_pid} termination={} elapsed_ms={} sampled_peak_rss_bytes={} sampled_peak_swap_bytes={} sampled_peak_combined_bytes={} observed_processes={}",
                termination(&result.status),
                started.elapsed().as_millis(),
                peaks.rss,
                peaks.swap,
                peaks.combined,
                peaks.processes_seen,
            ),
            (Ok(result), Err(_)) => info!(
                "dist_job_process_exit job_id={job_id} wrapper_pid={wrapper_pid} termination={} elapsed_ms={} resource_metrics=unavailable",
                termination(&result.status),
                started.elapsed().as_millis(),
            ),
            (Err(error), Ok(peaks)) => warn!(
                "dist_job_process_wait_failed job_id={job_id} wrapper_pid={wrapper_pid} elapsed_ms={} sampled_peak_rss_bytes={} sampled_peak_swap_bytes={} error={error}",
                started.elapsed().as_millis(),
                peaks.rss,
                peaks.swap,
            ),
            (Err(error), Err(_)) => warn!(
                "dist_job_process_wait_failed job_id={job_id} wrapper_pid={wrapper_pid} elapsed_ms={} resource_metrics=unavailable error={error}",
                started.elapsed().as_millis(),
            ),
        }
    } else {
        match &output {
            Ok(result) => info!(
                "dist_job_process_exit job_id={job_id} wrapper_pid={wrapper_pid} termination={} elapsed_ms={} resource_metrics=external_container",
                termination(&result.status),
                started.elapsed().as_millis(),
            ),
            Err(error) => warn!(
                "dist_job_process_wait_failed job_id={job_id} wrapper_pid={wrapper_pid} elapsed_ms={} resource_metrics=external_container error={error}",
                started.elapsed().as_millis(),
            ),
        }
    }

    #[cfg(not(target_os = "linux"))]
    match &output {
        Ok(result) => info!(
            "dist_job_process_exit job_id={job_id} wrapper_pid={wrapper_pid} termination={} elapsed_ms={} resource_metrics=unavailable",
            termination(&result.status),
            started.elapsed().as_millis(),
        ),
        Err(error) => warn!(
            "dist_job_process_wait_failed job_id={job_id} wrapper_pid={wrapper_pid} elapsed_ms={} error={error}",
            started.elapsed().as_millis(),
        ),
    }
    output
}

fn termination(status: &std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("exit:{code}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("signal:{signal}");
        }
    }
    format!("{status:?}")
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Peaks {
    rss: u64,
    swap: u64,
    combined: u64,
    processes_seen: usize,
}

#[cfg(target_os = "linux")]
fn monitor_process_tree(
    job_id: JobId,
    root_pid: u32,
    stop: &std::sync::mpsc::Receiver<()>,
) -> Peaks {
    use std::collections::HashSet;
    use std::fs;
    use std::sync::mpsc::RecvTimeoutError;
    use std::time::Duration;

    let mut peaks = Peaks::default();
    let mut seen = HashSet::new();
    let mut next_report = 256 * 1024 * 1024u64;
    loop {
        let mut stack = vec![root_pid];
        let mut visited = HashSet::new();
        let (mut rss, mut swap) = (0u64, 0u64);
        while let Some(pid) = stack.pop() {
            if !visited.insert(pid) {
                continue;
            }
            if let Ok(children) = fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")) {
                stack.extend(
                    children
                        .split_ascii_whitespace()
                        .filter_map(|s| s.parse::<u32>().ok()),
                );
            }
            let status = fs::read_to_string(format!("/proc/{pid}/status"));
            if let Ok(status) = status {
                let (resident, swapped) = parse_status_memory(&status);
                rss = rss.saturating_add(resident);
                swap = swap.saturating_add(swapped);
                if seen.insert(pid) {
                    let name = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                    info!(
                        "dist_job_process job_id={job_id} pid={pid} name={:?}",
                        name.trim()
                    );
                }
            }
        }
        let combined = rss.saturating_add(swap);
        peaks.rss = peaks.rss.max(rss);
        peaks.swap = peaks.swap.max(swap);
        peaks.combined = peaks.combined.max(combined);
        if combined >= next_report {
            // Exponential milestones retain evidence if the worker is killed
            // before it can emit its normal process-exit event.
            if combined >= 8 * 1024 * 1024 * 1024 {
                warn!(
                    "dist_job_memory job_id={job_id} sampled_rss_bytes={rss} sampled_swap_bytes={swap} sampled_combined_bytes={combined}"
                );
            } else {
                info!(
                    "dist_job_memory job_id={job_id} sampled_rss_bytes={rss} sampled_swap_bytes={swap} sampled_combined_bytes={combined}"
                );
            }
            while next_report <= combined {
                next_report = next_report.saturating_mul(2);
                if next_report == u64::MAX {
                    break;
                }
            }
        }
        match stop.recv_timeout(Duration::from_millis(100)) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    peaks.processes_seen = seen.len();
    peaks
}

#[cfg(target_os = "linux")]
fn parse_status_memory(status: &str) -> (u64, u64) {
    let mut rss = 0;
    let mut swap = 0;
    for line in status.lines() {
        if let Some(kib) = line.strip_prefix("VmRSS:") {
            rss = parse_kib(kib);
        } else if let Some(kib) = line.strip_prefix("VmSwap:") {
            swap = parse_kib(kib);
        }
    }
    (rss, swap)
}

#[cfg(target_os = "linux")]
fn parse_kib(value: &str) -> u64 {
    value
        .split_ascii_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccache::dist::CompileCommand;

    #[test]
    fn identifies_both_rustc_crate_name_forms() {
        for arguments in [
            vec!["--crate-name".into(), "ngspice_rs".into()],
            vec!["--crate-name=ngspice_rs".into()],
        ] {
            let command = CompileCommand {
                executable: "rustc".into(),
                arguments,
                env_vars: vec![],
                cwd: "/".into(),
            };
            assert_eq!(identity(&command).0, Some("ngspice_rs"));
        }
    }

    #[test]
    fn command_fingerprint_includes_relevant_inputs() {
        let mut command = CompileCommand {
            executable: "rustc".into(),
            arguments: vec!["--crate-name".into(), "ngspice_rs".into()],
            env_vars: vec![],
            cwd: "/".into(),
        };
        let first = identity(&command).1;
        command.cwd = "/src".into();
        assert_ne!(first, identity(&command).1);
        command.cwd = "/".into();
        command.arguments.push("--emit=llvm-ir".into());
        assert_ne!(first, identity(&command).1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observes_child_processes_and_memory() -> io::Result<()> {
        use std::time::Duration;

        let mut child = Command::new("sh").args(["-c", "sleep 1 & wait"]).spawn()?;
        let root_pid = child.id();
        let (sender, receiver) = std::sync::mpsc::channel();
        let sampler =
            std::thread::spawn(move || monitor_process_tree(JobId(144), root_pid, &receiver));
        std::thread::sleep(Duration::from_millis(400));
        let _ = sender.send(());
        let peaks = sampler
            .join()
            .map_err(|_| io::Error::other("process-tree monitor panicked"))?;
        let status = child.wait()?;
        assert!(status.success());
        assert!(peaks.rss > 0);
        assert!(peaks.processes_seen >= 2);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_process_status_memory_in_kib() {
        let status = "Name:\trustc\nVmRSS:\t  4714936 kB\nVmSwap:\t12560000 kB\n";
        assert_eq!(parse_status_memory(status), (4_828_094_464, 12_861_440_000));
    }

    #[test]
    fn distinguishes_nonzero_exit() -> io::Result<()> {
        let status = Command::new("sh").args(["-c", "exit 7"]).status()?;
        assert_eq!(termination(&status), "exit:7");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn distinguishes_signal_termination() {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw(9);
        assert_eq!(termination(&status), "signal:9");
    }

    #[test]
    fn captures_output_and_process_exit() -> io::Result<()> {
        let mut command = Command::new("sh");
        command.args(["-c", "printf stdout; printf stderr >&2; exit 7"]);
        let output = run(JobId(123), &mut command)?;
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
        Ok(())
    }
}
