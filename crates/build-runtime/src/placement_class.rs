//! Advisory command-family identity; never part of an action cache key.
use crate::{ContentId, ExecutionSpec};

impl ExecutionSpec {
    /// Identify the command family used for service-time and delivery forecasts.
    ///
    /// # Errors
    /// Returns an error if the stable command declaration cannot be serialized.
    pub fn placement_class(&self) -> anyhow::Result<ContentId> {
        let command = &self.command;
        let args = &command.arguments;
        // Rust dependency artifact filenames and metadata hashes change
        // with source identity, not necessarily compilation workload.
        // Retain dependency names, all feature/target/codegen switches,
        // crate name, emit mode, and source/output path shape.
        let rust = args
            .iter()
            .any(|arg| arg == b"--crate-name" || arg.starts_with(b"--crate-name="));
        let mut stable = Vec::with_capacity(args.len());
        let mut i = 0;
        while let Some(arg) = args.get(i) {
            i += 1;
            if rust {
                if arg == b"--extern"
                    && let Some(value) = args.get(i)
                {
                    stable.push(arg.as_slice());
                    stable.push(value.split(|&byte| byte == b'=').next().unwrap_or(value));
                    i += 1;
                    continue;
                }
                if let Some(value) = arg.strip_prefix(b"--extern=") {
                    stable.push(b"--extern");
                    stable.push(value.split(|&byte| byte == b'=').next().unwrap_or(value));
                    continue;
                }
                if arg == b"-C" && args.get(i).is_some_and(|value| volatile_codegen(value)) {
                    i += 1;
                    continue;
                }
                if arg.strip_prefix(b"-C").is_some_and(volatile_codegen) {
                    continue;
                }
            }
            stable.push(arg.as_slice());
        }
        let mut hash = blake3::Hasher::new();
        hash.update(b"sccache-placement-command-v2\0");
        let outputs = self
            .outputs
            .iter()
            .map(|(name, output)| (name, output.kind, output.required))
            .collect::<Vec<_>>();
        bincode::serialize_into(
            &mut hash,
            &(
                self.platform,
                &command.executable,
                &command.cwd,
                stable,
                outputs,
            ),
        )?;
        Ok(ContentId(*hash.finalize().as_bytes()))
    }
}

fn volatile_codegen(arg: &[u8]) -> bool {
    arg.starts_with(b"metadata=") || arg.starts_with(b"extra-filename=")
}
