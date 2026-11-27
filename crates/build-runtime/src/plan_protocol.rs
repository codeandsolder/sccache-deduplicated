//! Framed local planning protocol. The frontend keeps package/layout locks
//! and resolves runtime-dependent commands; the executor owns the frontier.

use std::io::{BufRead, Write};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{BuildPlan, PlanAction};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlannerRequest {
    Prepare { index: usize },
    Complete { index: usize },
    Finish,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlannerReply {
    Plan { plan: BuildPlan },
    Action { index: usize, action: PlanAction },
    Completed { index: usize },
    Finished,
    Error { message: String },
}

/// JSON-lines framing is shared by the client and the planner. Never log the
/// frames: the fully resolved command may contain environment values.
pub struct PlanConnection<R, W> {
    reader: R,
    writer: W,
    buffer: Vec<u8>,
}

impl<R: BufRead, W: Write> PlanConnection<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader,
            writer,
            buffer: Vec::new(),
        }
    }

    /// # Errors
    /// Returns an error on serialization or transport failure.
    pub fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        serde_json::to_writer(&mut self.writer, value)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    /// # Errors
    /// Returns an error for EOF, truncated or invalid frames.
    pub fn receive<T: DeserializeOwned>(&mut self) -> Result<T> {
        self.buffer.clear();
        let size = self.reader.read_until(b'\n', &mut self.buffer)?;
        ensure!(size != 0, "planning connection closed");
        ensure!(self.buffer.ends_with(b"\n"), "truncated planning frame");
        serde_json::from_slice(&self.buffer).context("invalid planning frame")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn framing_preserves_multiple_messages_and_detects_truncation() -> Result<()> {
        let mut bytes = Vec::new();
        let mut sender = PlanConnection::new(Cursor::new([]), &mut bytes);
        sender.send(&PlannerRequest::Prepare { index: 42 })?;
        sender.send(&PlannerRequest::Finish)?;
        let mut receiver = PlanConnection::new(Cursor::new(&bytes), Vec::new());
        assert!(matches!(
            receiver.receive()?,
            PlannerRequest::Prepare { index: 42 }
        ));
        assert!(matches!(receiver.receive()?, PlannerRequest::Finish));
        assert!(receiver.receive::<PlannerRequest>().is_err());
        let mut truncated = PlanConnection::new(Cursor::new(&bytes[..bytes.len() - 1]), Vec::new());
        let _: PlannerRequest = truncated.receive()?;
        assert!(truncated.receive::<PlannerRequest>().is_err());
        Ok(())
    }
}
