//! Target selection and build mode independent of the command line.
use crate::{Target, TargetKind};
use std::ffi::OsString;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BuildMode {
    #[default]
    Build,
    Check,
    Test,
    Clippy,
    Run,
    Doc,
}

#[derive(Debug, Default, Clone)]
pub struct PlanOptions {
    pub mode: BuildMode,
    pub release: bool,
    pub profile: Option<String>,
    pub lib: bool,
    pub bin: Vec<String>,
    pub bins: bool,
    pub all_targets: bool,
    pub example: Vec<String>,
    pub examples: bool,
    pub test_targets: Vec<String>,
    pub tests: bool,
    pub bench: Vec<String>,
    pub benches: bool,
    pub no_run: bool,
    pub coverage: Option<crate::impact::CoverageMode>,
    pub doc: bool,
    pub no_doc: bool,
    pub no_deps: bool,
    pub trailing: Vec<OsString>,
}
impl PlanOptions {
    pub fn profile_name(&self) -> &str {
        self.profile.as_deref().unwrap_or(if self.release {
            "release"
        } else if self.mode == BuildMode::Test {
            "test"
        } else {
            "dev"
        })
    }

    pub fn selects(&self, target: &Target) -> bool {
        if self.lib
            || self.bins
            || !self.bin.is_empty()
            || self.examples
            || !self.example.is_empty()
            || self.tests
            || !self.test_targets.is_empty()
            || self.benches
            || !self.bench.is_empty()
        {
            return match target.kind {
                TargetKind::Library => self.lib,
                TargetKind::Binary => self.bins || self.bin.contains(&target.name),
                TargetKind::Example => self.examples || self.example.contains(&target.name),
                TargetKind::Test => self.tests || self.test_targets.contains(&target.name),
                TargetKind::Bench => self.benches || self.bench.contains(&target.name),
                TargetKind::BuildScript => false,
            };
        }
        if self.mode == BuildMode::Run {
            return target.kind == TargetKind::Binary;
        }
        if self.mode == BuildMode::Doc {
            return target.doc;
        }
        if self.mode == BuildMode::Test && self.doc {
            return target.kind == TargetKind::Library && target.doctest;
        }
        if self.all_targets {
            return target.kind != TargetKind::BuildScript;
        }
        if self.mode == BuildMode::Test {
            return target.test
                && matches!(
                    target.kind,
                    TargetKind::Library
                        | TargetKind::Binary
                        | TargetKind::Test
                        | TargetKind::Example
                );
        }
        matches!(target.kind, TargetKind::Library | TargetKind::Binary)
    }
}
