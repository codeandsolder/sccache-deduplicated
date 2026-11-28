#![cfg(unix)]

use assert_cmd::Command;
use tempfile::tempdir;

use std::{
    env::{consts::DLL_SUFFIX, var_os},
    ffi::OsString,
    fs::{self, File, create_dir, create_dir_all, remove_file, set_permissions},
    io::Write,
    os::unix::{
        fs::symlink,
        prelude::{OsStrExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

// A compiler discovered through a symlink must not execute locally just
// because native configuration is absent.
#[test]
fn test_symlinked_compiler_cannot_fallback() {
    let root = tempdir().unwrap();
    let root = root.path();
    fs::write(root.join("counter"), b"0").unwrap();
    fs::write(root.join("RUST_FILE.rs"), []).unwrap();
    for target in ["rust1", "rust2"] {
        create_mock_rustc(root.join(target));
        let rust = root.join("rust");
        symlink(root.join(target), &rust).unwrap();
        run_sccache(root, &rust.join("bin"));
        assert_eq!(fs::read(root.join("counter")).unwrap(), b"0");
        assert!(!root.join("RUST_FILE").exists());
        remove_file(&rust).unwrap();
    }
}

fn create_mock_rustc(dir: PathBuf) {
    let bin = dir.join("bin");
    create_dir_all(&bin).unwrap();

    let dll_name = format!("driver{DLL_SUFFIX}");
    let dll = dir.join(&dll_name);
    fs::write(&dll, dir.as_os_str().as_bytes()).unwrap();

    let lib = dir.join("lib");
    create_dir(&lib).unwrap();
    symlink(dll, lib.join(&dll_name)).unwrap();

    let rustc = bin.join("rustc");
    write!(
        File::create(&rustc).unwrap(),
        r#"#!/usr/bin/env sh

set -e
build=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        -vV)
            echo rustc 1.0.0
            exec echo "host: unknown"
            ;;
        +stable)
            exit 1
            ;;
        --print=sysroot)
            exec echo {}
            ;;
        --print)
            shift
            if [ "$1" = file-names ]; then
                exec echo RUST_FILE.rs
            fi
            ;;
        --emit)
            shift
            if [ "$1" = dep-info ]; then
                echo "deps.d: RUST_FILE.rs" > "$3"
                exec echo "RUST_FILE.rs:" "$3"
            fi
            ;;
        RUST_FILE.rs)
            build=1
            ;;
    esac
    shift
done

if [ "$build" -eq 1 ]; then
    echo $(($(cat counter) + 1)) > counter
    cp counter RUST_FILE
fi
"#,
        dir.display(),
    )
    .unwrap();

    let mut perm = rustc.metadata().unwrap().permissions();
    perm.set_mode(0o755);
    set_permissions(&rustc, perm).unwrap();
}

fn run_sccache(root: &Path, path: &Path) {
    let mut paths: OsString = path.into();
    paths.push(":");
    paths.push(var_os("PATH").unwrap());

    fs::write(root.join("native-missing.toml"), "").unwrap();
    Command::cargo_bin("sccache")
        .unwrap()
        .current_dir(root)
        .env("PATH", paths)
        .env("SCCACHE_CONF", root.join("native-missing.toml"))
        .env("SCCACHE_SERVER_UDS", root.join("client.sock"))
        .env_remove("SCCACHE_SERVER_PORT")
        .arg("rustc")
        .arg("RUST_FILE.rs")
        .arg("--crate-name=sccache_rustc_tests")
        .arg("--crate-type=lib")
        .arg("--emit=link")
        .arg("--out-dir")
        .arg(root)
        .assert()
        .failure();
}
