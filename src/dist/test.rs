fn roundtrip_toolchain(archive_id: &str) -> bincode::Result<crate::dist::Toolchain> {
    let tc = crate::dist::Toolchain {
        archive_id: archive_id.to_owned(),
    };
    bincode::deserialize(&bincode::serialize(&tc).unwrap())
}

#[test]
fn test_toolchain_archive_id_digest_accepted() {
    let archive_id = crate::util::Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    assert_eq!(
        roundtrip_toolchain(&archive_id).unwrap().archive_id,
        archive_id
    );
    assert_eq!(
        roundtrip_toolchain(&archive_id.to_uppercase())
            .unwrap()
            .archive_id,
        archive_id
    );
}

#[test]
fn test_toolchain_archive_id_non_digest_rejected() {
    let digest = crate::util::Digest::reader_sync(&b"toolchain archive"[..]).unwrap();
    for archive_id in [
        "",
        "a",
        "/tmp/toolchain",
        "../toolchain",
        &digest[1..],
        &format!("{digest}0"),
        &format!("/{}", &digest[1..]),
    ] {
        assert!(
            roundtrip_toolchain(archive_id).is_err(),
            "accepted {archive_id:?}"
        );
    }
}

#[test]
fn test_process_output_exit_code_is_kept() {
    let output: std::process::Output =
        crate::dist::ProcessOutput::fake_output(1, b"out".to_vec(), b"err".to_vec()).into();
    assert_eq!(output.status.code(), Some(1));
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(output.status.signal(), None);
    }
}
