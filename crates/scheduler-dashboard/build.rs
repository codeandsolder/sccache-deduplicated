#[path = "src/fingerprint.rs"]
mod fingerprint;

fn main() -> std::io::Result<()> {
    // Cargo executes build scripts in the package root. Resolve the actual
    // checkout at execution time, not a path embedded in a cached executable.
    let root = std::env::current_dir()?.join("../..").canonicalize()?;
    // Directory watches also catch additions/removals of source files.
    for path in fingerprint::INPUTS {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    let generation = fingerprint::generation(&root)?;
    let output = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| std::io::Error::other("missing Cargo output directory"))?,
    );
    std::fs::write(output.join("dashboard-generation"), generation)
}
