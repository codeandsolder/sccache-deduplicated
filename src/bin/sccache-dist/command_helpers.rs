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

use anyhow::{Context, Result, bail};
use std::process::{ChildStdin, Command, Output, Stdio};

pub(super) trait CommandExt {
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
        pipe(&mut stdin).context("Failed to pipe input to process")?;
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
}
