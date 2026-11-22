use super::CompileCommand;

#[test]
fn compile_command_debug_redacts_arguments_and_environment_values() {
    let command = CompileCommand {
        executable: "rustc".to_owned(),
        arguments: vec!["--cfg=api_key=argument-secret".to_owned()],
        env_vars: vec![("PRIVATE_TOKEN".to_owned(), "environment-secret".to_owned())],
        cwd: "/build".to_owned(),
    };

    let debug = format!("{command:?}");

    assert!(debug.contains("rustc"));
    assert!(debug.contains("PRIVATE_TOKEN"));
    assert!(debug.contains("argument_count: 1"));
    assert!(!debug.contains("argument-secret"));
    assert!(!debug.contains("environment-secret"));
}
