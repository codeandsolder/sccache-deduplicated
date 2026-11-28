use std::{
    ffi::OsString,
    os::unix::{ffi::OsStringExt, fs::symlink},
};

use super::*;

fn invocation(env: Vec<(OsString, OsString)>) -> Result<SandboxInvocation> {
    SandboxInvocation::new(
        "/usr/bin/env".into(),
        Vec::new(),
        Path::new("/"),
        env,
        0o022,
    )
}

#[test]
fn environment_hashing_preserves_bytes_and_empty_values() -> Result<()> {
    let invalid_utf8 = OsString::from_vec(vec![b'x', 0xff]);
    let first = invocation(vec![
        ("B".into(), invalid_utf8.clone()),
        ("A".into(), "".into()),
    ])?;
    let second = invocation(vec![("A".into(), "".into()), ("B".into(), invalid_utf8)])?;
    assert_eq!(first.input_components()?, second.input_components()?);
    assert_ne!(
        first.input_components()?,
        invocation(vec![("B".into(), "x".into())])?.input_components()?
    );
    assert_ne!(
        invocation(vec![("A".into(), "".into())])?.input_components()?,
        invocation(vec![])?.input_components()?
    );
    assert!(invocation(vec![("A".into(), "".into()), ("A".into(), "b".into())]).is_err());
    assert!(invocation(vec![("A=B".into(), "".into())]).is_err());
    assert!(invocation(vec![("A".into(), OsString::from_vec(vec![0]))]).is_err());
    Ok(())
}

#[test]
fn layout_is_independent_of_host_paths_and_mounts_are_explicit() -> Result<()> {
    let first = tempfile::tempdir()?;
    let second = tempfile::tempdir()?;
    let source = tempfile::tempdir()?;
    let mut a = SandboxPlan::new(first.path(), MountAccess::ReadOnly)?;
    let mut b = SandboxPlan::new(second.path(), MountAccess::ReadOnly)?;
    let dest = SandboxPath::new(Path::new("/deps"))?;
    a.bind(source.path(), dest.clone(), MountAccess::ReadOnly)?;
    b.bind(second.path(), dest.clone(), MountAccess::ReadOnly)?;
    assert_eq!(a.layout_fingerprint()?, b.layout_fingerprint()?);
    b.tmpfs(SandboxPath::new(Path::new("/out"))?)?;
    assert_ne!(a.layout_fingerprint()?, b.layout_fingerprint()?);
    assert!(a.bind(source.path(), dest, MountAccess::Writable).is_err());
    assert!(a.tmpfs(SandboxPath::new(Path::new("/proc/foo"))?).is_err());
    assert!(SandboxPath::new(Path::new("/abc/../def")).is_err());
    assert!(SandboxPath::new(Path::new("relative")).is_err());
    assert!(SandboxPlan::new(Path::new("/"), MountAccess::ReadOnly).is_err());

    let command = b.command(
        Path::new("/usr/bin/bwrap"),
        &invocation(vec![("X".into(), "1".into())])?,
        tempfile::tempfile()?,
    )?;
    let arguments: Vec<_> = command.get_args().collect();
    assert!(arguments.contains(&OsStr::new("--clearenv")));
    assert!(arguments.contains(&OsStr::new("--disable-userns")));
    assert!(arguments.contains(&OsStr::new("--unshare-net")));
    assert!(
        arguments
            .windows(2)
            .any(|pair| pair == [OsStr::new("--tmpfs"), OsStr::new("/out")])
    );
    Ok(())
}

#[test]
#[ignore = "requires installed Bubblewrap and enabled Linux user namespaces"]
fn executes_isolated_process_with_readonly_inputs_and_private_outputs() -> Result<()> {
    let root = tempfile::tempdir()?;
    let output = tempfile::tempdir()?;
    for path in ["usr", "proc", "dev", "workspace", "out", "tmp"] {
        fs::create_dir(root.path().join(path))?;
    }
    let mut runtime_dirs = vec![PathBuf::from("/usr")];
    for name in ["bin", "lib", "lib64"] {
        let host = Path::new("/").join(name);
        let dest = root.path().join(name);
        match fs::symlink_metadata(&host) {
            Ok(metadata) if metadata.is_symlink() => symlink(fs::read_link(&host)?, dest)?,
            Ok(metadata) if metadata.is_dir() => {
                fs::create_dir(dest)?;
                runtime_dirs.push(host);
            }
            Ok(_) => anyhow::bail!("unexpected runtime path: {}", host.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::write(root.path().join("workspace/input"), b"original")?;
    let mut plan = SandboxPlan::new(root.path(), MountAccess::ReadOnly)?;
    for dir in runtime_dirs {
        plan.bind(&dir, SandboxPath::new(&dir)?, MountAccess::ReadOnly)?;
    }
    plan.bind(
        output.path(),
        SandboxPath::new(Path::new("/out"))?,
        MountAccess::Writable,
    )?;
    plan.tmpfs(SandboxPath::new(Path::new("/tmp"))?)?;

    let invocation = SandboxInvocation::new(
        "/bin/sh".into(),
        vec!["-c".into(), "test \"$PRESENT\" = value && test \"${EMPTY+x}\" = x && test -z \"${HOST_SENTINEL+x}\" && test \"$(/usr/bin/id -u)\" = 1000 && test \"$(/usr/bin/hostname)\" = sccache-build && ! (echo bad > /workspace/input) && /usr/bin/cat /workspace/input > /out/result && echo tmp > /tmp/scratch".into()],
        Path::new("/workspace"),
        [("PRESENT".into(), "value".into()), ("EMPTY".into(), "".into())],
        0o077,
    )?;
    let mut status = tempfile::tempfile()?;
    let result = plan
        .command(
            Path::new("/usr/bin/bwrap"),
            &invocation,
            status.try_clone()?,
        )?
        .env("HOST_SENTINEL", "must-not-leak")
        .output()?;
    ensure!(
        result.status.success(),
        "sandbox command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    use std::io::Seek;
    status.rewind()?;
    verify_status(status, result.status)?;
    assert_eq!(fs::read(output.path().join("result"))?, b"original");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(output.path().join("result"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(fs::read(root.path().join("workspace/input"))?, b"original");
    assert!(!root.path().join("tmp/scratch").exists());
    Ok(())
}

#[test]
fn compiler_failure_is_distinct_from_sandbox_failure() -> Result<()> {
    use std::os::unix::process::ExitStatusExt;
    let failure = ExitStatus::from_raw(1 << 8);
    let valid = br#"{ "child-pid": 123, "mnt-namespace": 456 }
{ "exit-code": 1 }
"#;
    verify_status(valid.as_slice(), failure)?;
    for invalid in [
        b"".as_slice(),
        br#"{ "child-pid": 123 }"#,
        br#"{ "child-pid": 123 } { "exit-code": 0 }"#,
        br#"{ "exit-code": 1 }"#,
    ] {
        assert!(verify_status(invalid, failure).is_err());
    }
    Ok(())
}
