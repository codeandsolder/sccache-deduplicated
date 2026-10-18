use super::{InvalidToolchainArchiveId, Toolchain};
use serde::{Deserialize, Serialize};

const VALID_ARCHIVE_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyToolchain {
    archive_id: String,
}

#[test]
fn toolchain_accepts_safe_hex_archive_ids() {
    assert!(Toolchain::try_from(VALID_ARCHIVE_ID.to_owned()).is_ok());
    assert!(Toolchain::try_from("0A".to_owned()).is_ok());
}

#[test]
fn toolchain_rejects_archive_ids_that_cannot_be_safe_cache_keys() {
    for archive_id in ["", "f", "../aa", "gg", "é0", "00/11"] {
        assert!(
            Toolchain::try_from(archive_id.to_owned()).is_err(),
            "{archive_id:?} unexpectedly passed archive ID validation"
        );
    }
}

#[test]
fn toolchain_bincode_shape_remains_compatible() -> anyhow::Result<()> {
    let legacy = LegacyToolchain {
        archive_id: VALID_ARCHIVE_ID.to_owned(),
    };
    let legacy_bytes = bincode::serialize(&legacy)?;
    let toolchain: Toolchain = bincode::deserialize(&legacy_bytes)?;
    assert_eq!(toolchain.archive_id(), VALID_ARCHIVE_ID);
    let current_bytes = bincode::serialize(&toolchain)?;
    let decoded: LegacyToolchain = bincode::deserialize(&current_bytes)?;
    assert_eq!(decoded, legacy);
    Ok(())
}

#[test]
fn toolchain_deserialization_rejects_invalid_legacy_ids() -> anyhow::Result<()> {
    let legacy = LegacyToolchain {
        archive_id: "../escape".to_owned(),
    };
    let bytes = bincode::serialize(&legacy)?;
    let decoded = bincode::deserialize::<Toolchain>(&bytes);
    assert!(decoded.is_err());
    Ok(())
}

#[test]
fn invalid_archive_id_error_describes_the_invariant() {
    assert_eq!(
        InvalidToolchainArchiveId.to_string(),
        "toolchain archive ID must contain at least two ASCII hexadecimal characters"
    );
}
