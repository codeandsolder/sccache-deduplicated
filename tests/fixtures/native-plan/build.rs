fn main() {
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let token = std::env::var("DEP_FIXTURE_NATIVE_TOKEN").unwrap();
    std::fs::write(output.join("generated.rs"), format!("pub const TOKEN: &str = {token:?};")).unwrap();
    println!("cargo::rustc-cfg=fixture_generated");
    println!("cargo::rustc-check-cfg=cfg(fixture_generated)");
    println!("cargo::rustc-env=FIXTURE_ENV=build-script");
}
