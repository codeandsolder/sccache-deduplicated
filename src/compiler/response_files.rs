//! Shared stack for compilers whose response files expand recursively.
//!
//! A recursive @file can refer back to itself. Keep a marker on the stack for
//! every active file so an active ancestor cannot indefinitely re-enter the
//! same response file. Reusing a file after its earlier expansion completed
//! remains valid, and the per-compiler tokenizer is supplied by the caller.

use fs_err as fs;
use log::debug;
use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

enum Entry {
    Argument(OsString),
    EndFile(PathBuf),
}

pub(super) struct ResponseFileExpansion {
    pending: Vec<Entry>,
    active: HashSet<PathBuf>,
}

impl ResponseFileExpansion {
    pub(super) fn new(args: &[OsString]) -> Self {
        Self {
            pending: args.iter().rev().cloned().map(Entry::Argument).collect(),
            active: HashSet::new(),
        }
    }

    pub(super) fn next_argument(&mut self) -> Option<OsString> {
        loop {
            match self.pending.pop()? {
                Entry::Argument(arg) => return Some(arg),
                Entry::EndFile(path) => {
                    self.active.remove(&path);
                }
            }
        }
    }

    /// Expand a file only when it is not already an active ancestor.
    ///
    /// On false the caller emits its original response directive unchanged,
    /// letting the compiler-specific parser mark the request uncacheable.
    pub(super) fn expand(
        &mut self,
        file: &Path,
        split: impl FnOnce(&str) -> Option<Vec<OsString>>,
    ) -> bool {
        let canonical = match fs::canonicalize(file) {
            Ok(canonical) => canonical,
            Err(error) => {
                debug!(
                    "failed to resolve response file {}: {error}",
                    file.display()
                );
                return false;
            }
        };
        if self.active.contains(&canonical) {
            debug!("cyclic response file reference at {}", file.display());
            return false;
        }
        let contents = match fs::read_to_string(file) {
            Ok(contents) => contents,
            Err(error) => {
                debug!("failed to read response file {}: {error}", file.display());
                return false;
            }
        };
        let Some(arguments) = split(&contents) else {
            return false;
        };
        self.active.insert(canonical.clone());
        self.pending.push(Entry::EndFile(canonical));
        self.pending
            .extend(arguments.into_iter().rev().map(Entry::Argument));
        true
    }
}
