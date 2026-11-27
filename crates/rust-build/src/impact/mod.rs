//! Native test impact analysis. LLVM coverage extraction is independent of
//! Cargo, Nextest and the storage backend. The scheduler's verified artifact
//! content IDs bind coverage to its producing executable.
pub mod coverage;
