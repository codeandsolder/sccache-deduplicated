//! Native test impact analysis. LLVM coverage extraction is independent of
//! Cargo, Nextest and the storage backend. The scheduler's verified artifact
//! content IDs bind coverage to its producing executable.
pub mod coverage;

pub mod selection;

pub mod sources;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CoverageMode {
    Exit,
    Continuous,
}

impl CoverageMode {
    pub fn flags(self) -> &'static [&'static str] {
        match self {
            Self::Exit => &["-C", "instrument-coverage"],
            Self::Continuous => &[
                "-C",
                "instrument-coverage",
                "-C",
                "llvm-args=-runtime-counter-relocation",
            ],
        }
    }

    pub fn profile_name(self) -> &'static str {
        match self {
            Self::Exit => "%p-%m.profraw",
            Self::Continuous => "%p-%m%c.profraw",
        }
    }
}

pub mod harness;

pub mod revision;
