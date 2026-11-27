#[test]
fn published_binary_is_runnable() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_native-plan-fixture"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"native-plan-ok\n");
}
