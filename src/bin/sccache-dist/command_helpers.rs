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

use crate::job_telemetry;
use anyhow::{Context, Result, bail};
use sccache::dist::JobId;
use std::process::{ChildStdin, Command, Output, Stdio};

pub trait CommandExt {
    fn check_stdout_trim(&mut self) -> Result<String>;
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()>;
    fn check_run(&mut self) -> Result<()>;
}

impl CommandExt for Command {
    fn check_stdout_trim(&mut self) -> Result<String> {
        let output = self.output().context("Failed to start command")?;
        check_output(&output)?;
        let stdout =
            String::from_utf8(output.stdout).context("Output from listing containers not UTF8")?;
        Ok(stdout.trim().to_owned())
    }
    // Should really take a FnOnce/FnBox
    fn check_piped(&mut self, pipe: &mut dyn FnMut(&mut ChildStdin) -> Result<()>) -> Result<()> {
        let mut process = self
            .stdin(Stdio::piped())
            .spawn()
            .context("Failed to start command")?;
        let mut stdin = process
            .stdin
            .take()
            .context("requested piped stdin but child did not expose it")?;
        let pipe_result = pipe(&mut stdin).context("Failed to pipe input to process");
        // The child may need EOF before it can exit. wait_with_output closes
        // Child.stdin, but we took that handle out of Child above.
        drop(stdin);
        if let Err(err) = pipe_result {
            // On a producer error, do not leave a running child or a zombie.
            if let Err(kill_err) = process.kill() {
                debug!("Failed to stop child after stdin error: {kill_err}");
            }
            if let Err(wait_err) = process.wait() {
                debug!("Failed to reap child after stdin error: {wait_err}");
            }
            return Err(err);
        }
        let output = process
            .wait_with_output()
            .context("Failed to wait for process to return")?;
        check_output(&output)
    }
    fn check_run(&mut self) -> Result<()> {
        let output = self.output().context("Failed to start command")?;
        check_output(&output)
    }
}

/// Append a compiler invocation after a container's clean-environment command.
pub fn run_with_environment(
    job_id: JobId,
    command: &mut Command,
    environment: Vec<(String, String)>,
    executable: String,
    arguments: Vec<String>,
) -> Result<Output> {
    for (mut key, value) in environment {
        if key.contains('=') {
            bail!("invalid compiler environment variable name {key:?}");
        }
        key.push('=');
        key.push_str(&value);
        command.arg(key);
    }
    command.arg(executable).args(arguments);
    job_telemetry::run_external_container(job_id, command)
        .context("Failed to start executing compile")
}

fn check_output(output: &Output) -> Result<()> {
    if !output.status.success() {
        warn!(
            "===========\n{}\n==========\n\n\n\n=========\n{}\n===============\n\n\n",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        bail!("Command failed with status {}", output.status)
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn stdout_is_trimmed() -> Result<()> {
        let output = Command::new("sh")
            .args(["-c", "printf '  ready \\n'"])
            .check_stdout_trim()?;
        assert_eq!(output, "ready");
        Ok(())
    }

    #[test]
    fn failed_command_reports_status() {
        let error = Command::new("sh")
            .args(["-c", "echo failed >&2; exit 7"])
            .check_run()
            .expect_err("nonzero status must fail");
        assert!(error.to_string().contains("status exit status: 7"));
    }

    #[test]
    fn piped_stdin_is_delivered() -> Result<()> {
        Command::new("sh")
            .args(["-c", "read value && test \"$value\" = delivered"])
            .check_piped(&mut |stdin| {
                stdin.write_all(b"delivered\n")?;
                Ok(())
            })
    }

    #[test]
    fn piped_stdin_is_closed_before_waiting() -> Result<()> {
        // Unlike read(1), cat only exits when the parent closes stdin.
        Command::new("sh")
            .args(["-c", "cat >/dev/null"])
            .check_piped(&mut |stdin| {
                stdin.write_all(b"delivered\n")?;
                Ok(())
            })
    }

    #[test]
    fn pipe_error_terminates_child() {
        let err = Command::new("sh")
            .args(["-c", "exec sleep 30"])
            .check_piped(&mut |_| Err(anyhow::anyhow!("deliberate pipe failure")))
            .expect_err("a failed producer must propagate an error");
        assert!(err.to_string().contains("Failed to pipe input to process"));
        assert!(
            err.root_cause()
                .to_string()
                .contains("deliberate pipe failure")
        );
    }
}
