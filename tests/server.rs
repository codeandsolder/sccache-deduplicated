#[cfg(not(target_os = "macos"))]
use std::{net::TcpListener, process::Command};

#[cfg(not(target_os = "macos"))]
use serial_test::serial;

#[test]
#[serial]
// test fails intermittently on macos:
// https://github.com/mozilla/sccache/issues/234
#[cfg(not(target_os = "macos"))]
fn test_server_port_in_use() {
    const MSG: &str = "Server startup failed:";

    // Bind an arbitrary free port.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let sccache = env!("CARGO_BIN_EXE_sccache");
    let output = Command::new(sccache)
        .arg("--start-server")
        .env(
            "SCCACHE_SERVER_PORT",
            listener.local_addr().unwrap().port().to_string(),
        )
        .env_remove("SCCACHE_SERVER_UDS")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let s = String::from_utf8_lossy(&output.stderr);
    assert!(
        s.contains(MSG),
        "Output did not contain '{MSG}':\n========\n{s}\n========"
    );
}

#[test]
#[serial]
#[cfg(not(target_os = "macos"))]
fn test_compile_can_require_prestarted_server() {
    const MSG: &str = "sccache server is unavailable and SCCACHE_NO_AUTO_START_SERVER=1";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let sccache = env!("CARGO_BIN_EXE_sccache");
    let output = Command::new(sccache)
        .arg("definitely-not-a-compiler")
        .env("SCCACHE_SERVER_PORT", port.to_string())
        .env("SCCACHE_NO_AUTO_START_SERVER", "1")
        .env_remove("SCCACHE_SERVER_UDS")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(MSG),
        "Output did not contain '{MSG}':\n========\n{stderr}\n========"
    );

    let rebound = TcpListener::bind(("127.0.0.1", port));
    assert!(
        rebound.is_ok(),
        "client unexpectedly started a server on port {port}"
    );
}
