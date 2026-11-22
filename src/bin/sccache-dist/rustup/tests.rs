use super::*;

#[test]
fn installed_components_include_targeted_and_target_independent_build_payload() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let rustlib = temp.path().join("lib/rustlib");
    fs::create_dir_all(&rustlib)?;
    fs::write(
        rustlib.join("multirust-config.toml"),
        r#"
config_version = "1"
[[components]]
pkg = "rustc"
target = "host"
[[components]]
pkg = "rust-std"
target = "wasm32-unknown-unknown"
[[components]]
pkg = "rust-src"
target = "*"
[[components]]
pkg = "rust-docs"
target = "host"
"#,
    )?;
    fs::write(
        rustlib.join("components"),
        "rustc-host\nrust-std-wasm32-unknown-unknown\nrust-src\nrust-docs-host\n",
    )?;
    for (name, manifest) in [
        ("rustc-host", "file:bin/rustc\n"),
        (
            "rust-std-wasm32-unknown-unknown",
            "dir:lib/rustlib/wasm32-unknown-unknown\n",
        ),
        ("rust-src", "dir:lib/rustlib/src\n"),
        ("rust-docs-host", "dir:share/doc/rust/html\n"),
    ] {
        fs::write(rustlib.join(format!("manifest-{name}")), manifest)?;
    }
    let mut channel = String::from("manifest-version = \"2\"\ndate = \"2026-11-22\"\n");
    for (name, target, codec) in [
        ("rustc", "host", "xz"),
        ("rust-std", "wasm32-unknown-unknown", "xz"),
        ("rust-src", "*", "gz"),
        ("rust-docs", "host", "xz"),
    ] {
        use std::fmt::Write as _;
        let prefix = if codec == "xz" { "xz_" } else { "" };
        writeln!(
            channel,
            "[pkg.{name}.target.\"{target}\"]\navailable = true\n{prefix}url = \"https://static.rust-lang.org/dist/2026-11-22/{name}.tar.{codec}\"\n{prefix}hash = \"{}\"\n",
            "11".repeat(32)
        )?;
    }
    fs::write(rustlib.join("multirust-channel-manifest.toml"), &channel)?;
    let plan = Inventory::read(temp.path(), false)?;
    assert_eq!(plan.selected.len(), 3);
    assert_eq!(plan.skipped, BTreeSet::from(["rust-docs-host".into()]));
    assert_eq!(
        plan.selected["rust-src"].locator.identity.compression,
        PackageCompression::Gzip
    );
    assert_eq!(Inventory::read(temp.path(), true)?.selected.len(), 4);
    fs::write(rustlib.join("components"), "rustc-host\n")?;
    assert!(Inventory::read(temp.path(), false).is_err());
    Ok(())
}
