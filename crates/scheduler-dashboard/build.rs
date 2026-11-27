#[path = "src/fingerprint.rs"]
mod fingerprint;

fn main() -> std::io::Result<()> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.join("../..").canonicalize()?;
    // Directory watches also catch additions/removals of source files.
    for path in [
        "src",
        "crates",
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "scripts/build-scheduler-dashboard.sh",
        "scripts/publish-dashboard-assets.sh",
        "contrib/codeandsolder/release-protocol.env",
    ] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
    let generation = fingerprint::generation(&root)?;
    let output = std::path::PathBuf::from(
        std::env::var_os("OUT_DIR")
            .ok_or_else(|| std::io::Error::other("missing Cargo output directory"))?,
    );
    std::fs::write(output.join("dashboard-generation"), generation)
}
