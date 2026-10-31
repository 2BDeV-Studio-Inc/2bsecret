use base64::{engine::general_purpose::STANDARD as B64, Engine};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::TempDir;
use twobsecret::{
    default_device_dir, fingerprint_from_public_key, inspect_file, load_default_recipient,
    nonce_from_index, RecipientPublic,
};

// Megfelelő hosszúságú tesztbájtok, nem valódi ML-KEM-kulcs.
// Ezekben a tesztekben csak a hash és a JSON-ellenőrzés fut, kulcscsere nem.
const MLKEM_PUBLIC_KEY_LEN: usize = 1184;
const DUMMY_MLKEM_PK: &[u8] = &[0u8; MLKEM_PUBLIC_KEY_LEN];
const FINGERPRINT_HEX_LEN: usize = 32;

#[test]
fn nonce_zero_index_is_all_zeros() {
    assert_eq!(nonce_from_index(0), [0u8; 12]);
}

#[test]
fn nonce_index_1_encodes_in_lower_8_bytes() {
    let n = nonce_from_index(1);
    assert_eq!(&n[..4], &[0u8; 4], "upper 4 bytes should always be zero");
    assert_eq!(
        &n[4..],
        &[0u8, 0, 0, 0, 0, 0, 0, 1],
        "lower 8 bytes = big-endian index"
    );
}

#[test]
fn nonce_max_u64_fills_lower_8_bytes() {
    let n = nonce_from_index(u64::MAX);
    assert_eq!(&n[..4], &[0u8; 4]);
    assert_eq!(&n[4..], &[0xFF; 8]);
}

#[test]
fn nonce_always_12_bytes() {
    for idx in [0u64, 1, 255, 65536, u64::MAX / 2, u64::MAX] {
        assert_eq!(
            nonce_from_index(idx).len(),
            12,
            "nonce len should always be 12, idx={idx}"
        );
    }
}

#[test]
fn nonce_deterministic_for_same_index() {
    for idx in [0u64, 42, 999_999, u64::MAX] {
        assert_eq!(
            nonce_from_index(idx),
            nonce_from_index(idx),
            "nonce must be deterministic, idx={idx}"
        );
    }
}

#[test]
fn nonce_sequential_indices_differ() {
    for i in 0u64..20 {
        assert_ne!(
            nonce_from_index(i),
            nonce_from_index(i + 1),
            "adjacent nonces must differ"
        );
    }
}

#[test]
fn fingerprint_is_always_32_chars() {
    for pk in [&[0u8; 32][..], &[0xFF; 32], &[0x42; 32], &[0xAB; 32]] {
        assert_eq!(
            fingerprint_from_public_key(pk, DUMMY_MLKEM_PK).len(),
            FINGERPRINT_HEX_LEN,
            "Az ujjlenyomatnak 32 hex karakterből kell állnia"
        );
    }
}

#[test]
fn fingerprint_is_lowercase_hex() {
    let fp = fingerprint_from_public_key(&[0x55u8; 32], DUMMY_MLKEM_PK);
    assert!(
        fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "fingerprint should be lowercase hex, got: {fp}"
    );
}

#[test]
fn fingerprint_is_deterministic() {
    let pk = [0x11u8; 32];
    assert_eq!(
        fingerprint_from_public_key(&pk, DUMMY_MLKEM_PK),
        fingerprint_from_public_key(&pk, DUMMY_MLKEM_PK),
    );
}

#[test]
fn different_keys_produce_different_fingerprints() {
    assert_ne!(
        fingerprint_from_public_key(&[0x01u8; 32], DUMMY_MLKEM_PK),
        fingerprint_from_public_key(&[0x02u8; 32], DUMMY_MLKEM_PK),
    );
}

#[test]
fn single_byte_change_changes_fingerprint() {
    let pk_a = [0u8; 32];
    let mut pk_b = [0u8; 32];
    pk_b[0] = 0x01;
    assert_ne!(
        fingerprint_from_public_key(&pk_a, DUMMY_MLKEM_PK),
        fingerprint_from_public_key(&pk_b, DUMMY_MLKEM_PK),
    );
}

#[test]
fn fingerprint_first_vs_last_byte_differ() {
    let mut pk_a = [0u8; 32];
    let mut pk_b = [0u8; 32];
    pk_a[0] = 0xFF;
    pk_b[31] = 0xFF;
    // Both differ from all-zeros fingerprint
    let fp_zeros = fingerprint_from_public_key(&[0u8; 32], DUMMY_MLKEM_PK);
    assert_ne!(fingerprint_from_public_key(&pk_a, DUMMY_MLKEM_PK), fp_zeros);
    assert_ne!(fingerprint_from_public_key(&pk_b, DUMMY_MLKEM_PK), fp_zeros);
}

#[test]
fn fingerprint_changes_when_mlkem_half_changes() {
    // Az X25519 fél azonos, csak az ML-KEM fél változik — a fingerprintnek
    // ettől is meg kell változnia, mert a két kulcsot együtt hash-eljük.
    let x25519_pk = [0x77u8; 32];
    let fp_a = fingerprint_from_public_key(&x25519_pk, DUMMY_MLKEM_PK);
    let fp_b = fingerprint_from_public_key(&x25519_pk, &[1u8; MLKEM_PUBLIC_KEY_LEN]);
    assert_ne!(
        fp_a, fp_b,
        "changing the ML-KEM half must change the fingerprint"
    );
}

#[test]
fn default_device_dir_path_contains_expected_segments() {
    let dir = default_device_dir();
    assert_eq!(dir.file_name().unwrap(), "device_keys");
    assert_eq!(dir.parent().unwrap().file_name().unwrap(), "2BSecret");
}

#[test]
fn default_device_dir_is_reproducible() {
    assert_eq!(default_device_dir(), default_device_dir());
}

proptest! {
    #[test]
    fn prop_nonce_unique_per_distinct_index(a in any::<u64>(), b in any::<u64>()) {
        if a != b {
            prop_assert_ne!(nonce_from_index(a), nonce_from_index(b));
        }
    }

    #[test]
    fn prop_nonce_deterministic(idx in any::<u64>()) {
        prop_assert_eq!(nonce_from_index(idx), nonce_from_index(idx));
    }

    #[test]
    fn prop_nonce_upper_4_bytes_always_zero(idx in any::<u64>()) {
        let n = nonce_from_index(idx);
        prop_assert_eq!(&n[..4], &[0u8; 4], "upper 4 bytes must always be zero");
    }

    #[test]
    fn prop_nonce_lower_8_bytes_encode_index_big_endian(idx in any::<u64>()) {
        let n = nonce_from_index(idx);
        let decoded = u64::from_be_bytes(n[4..].try_into().unwrap());
        prop_assert_eq!(decoded, idx, "lower 8 bytes must be the big-endian index");
    }

    #[test]
    fn prop_fingerprint_always_32_chars(pk in prop::collection::vec(any::<u8>(), 32..=32)) {
        prop_assert_eq!(fingerprint_from_public_key(&pk, DUMMY_MLKEM_PK).len(), FINGERPRINT_HEX_LEN);
    }

    #[test]
    fn prop_fingerprint_always_lowercase_hex(pk in prop::collection::vec(any::<u8>(), 32..=32)) {
        let fp = fingerprint_from_public_key(&pk, DUMMY_MLKEM_PK);
        prop_assert!(
            fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "expected lowercase hex, got: {fp}"
        );
    }

    #[test]
    fn prop_fingerprint_deterministic(pk in prop::collection::vec(any::<u8>(), 32..=32)) {
        prop_assert_eq!(
            fingerprint_from_public_key(&pk, DUMMY_MLKEM_PK),
            fingerprint_from_public_key(&pk, DUMMY_MLKEM_PK),
        );
    }

    #[test]
    fn prop_different_keys_produce_different_fingerprints(
        pk_a in prop::collection::vec(any::<u8>(), 32..=32),
        pk_b in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        if pk_a != pk_b {
            // SHA-256 collisions are astronomically unlikely; this is a sanity check
            prop_assert_ne!(
                fingerprint_from_public_key(&pk_a, DUMMY_MLKEM_PK),
                fingerprint_from_public_key(&pk_b, DUMMY_MLKEM_PK),
                "distinct keys should produce distinct fingerprints"
            );
        }
    }
}

#[test]
fn fingerprint_matches_sha256_of_both_keys() {
    let x25519 = [0x42u8; 32];
    let mlkem = [0x73u8; MLKEM_PUBLIC_KEY_LEN];
    let mut hasher = Sha256::new();
    hasher.update(x25519);
    hasher.update(mlkem);
    let digest = hasher.finalize();
    let expected: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(fingerprint_from_public_key(&x25519, &mlkem), expected);
}

fn example_recipient() -> RecipientPublic {
    let x = [0x31u8; 32];
    RecipientPublic {
        fingerprint: fingerprint_from_public_key(&x, DUMMY_MLKEM_PK),
        public_key_b64: B64.encode(x),
        ml_kem_public_key_b64: B64.encode(DUMMY_MLKEM_PK),
    }
}

fn save_recipient(dir: &TempDir, rec: &RecipientPublic) {
    fs::write(
        dir.path().join("recipient.json"),
        serde_json::to_vec(rec).unwrap(),
    )
    .unwrap();
}

#[test]
fn recipient_roundtrip_keeps_both_public_keys() {
    let dir = TempDir::new().unwrap();
    let rec = example_recipient();
    save_recipient(&dir, &rec);
    let loaded = load_default_recipient(dir.path()).unwrap();
    assert_eq!(loaded.fingerprint, rec.fingerprint);
    assert_eq!(loaded.public_key_b64, rec.public_key_b64);
    assert_eq!(loaded.ml_kem_public_key_b64, rec.ml_kem_public_key_b64);
}

#[test]
fn recipient_legacy_fingerprint_is_normalized_to_32_chars() {
    let dir = TempDir::new().unwrap();
    let mut rec = example_recipient();
    let expected = rec.fingerprint.clone();
    rec.fingerprint.truncate(16);
    save_recipient(&dir, &rec);
    assert_eq!(
        load_default_recipient(dir.path()).unwrap().fingerprint,
        expected
    );
}

#[test]
fn recipient_forged_fingerprint_is_rejected_without_rewriting_file() {
    let dir = TempDir::new().unwrap();
    let mut rec = example_recipient();
    rec.fingerprint = "0".repeat(FINGERPRINT_HEX_LEN);
    save_recipient(&dir, &rec);
    let path = dir.path().join("recipient.json");
    let before = fs::read(&path).unwrap();
    assert!(load_default_recipient(dir.path()).is_err());
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn recipient_wrong_public_key_lengths_are_rejected() {
    let dir = TempDir::new().unwrap();
    for len in [0, 31, 33] {
        let mut rec = example_recipient();
        rec.public_key_b64 = B64.encode(vec![0u8; len]);
        save_recipient(&dir, &rec);
        assert!(
            load_default_recipient(dir.path()).is_err(),
            "X25519-hossz: {len}"
        );
    }
    for len in [0, MLKEM_PUBLIC_KEY_LEN - 1, MLKEM_PUBLIC_KEY_LEN + 1] {
        let mut rec = example_recipient();
        rec.ml_kem_public_key_b64 = B64.encode(vec![0u8; len]);
        save_recipient(&dir, &rec);
        assert!(
            load_default_recipient(dir.path()).is_err(),
            "ML-KEM-hossz: {len}"
        );
    }
}

#[test]
fn recipient_invalid_base64_is_rejected() {
    let dir = TempDir::new().unwrap();
    let mut rec = example_recipient();
    rec.public_key_b64 = "!!!nem-base64!!!".to_string();
    save_recipient(&dir, &rec);
    assert!(load_default_recipient(dir.path()).is_err());
    let mut rec = example_recipient();
    rec.ml_kem_public_key_b64 = "!!!nem-base64!!!".to_string();
    save_recipient(&dir, &rec);
    assert!(load_default_recipient(dir.path()).is_err());
}

#[test]
fn recipient_changed_key_with_stale_fingerprint_is_rejected() {
    let dir = TempDir::new().unwrap();
    let mut rec = example_recipient();
    rec.public_key_b64 = B64.encode([0x32u8; 32]);
    save_recipient(&dir, &rec);
    assert!(load_default_recipient(dir.path()).is_err());
    let mut rec = example_recipient();
    rec.ml_kem_public_key_b64 = B64.encode([0x11u8; MLKEM_PUBLIC_KEY_LEN]);
    save_recipient(&dir, &rec);
    assert!(load_default_recipient(dir.path()).is_err());
}

#[test]
fn recipient_missing_mlkem_key_is_rejected() {
    let dir = TempDir::new().unwrap();
    let mut value = serde_json::to_value(example_recipient()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("ml_kem_public_key_b64");
    fs::write(
        dir.path().join("recipient.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(load_default_recipient(dir.path()).is_err());
}

#[test]
fn recipient_missing_or_invalid_json_is_rejected() {
    let dir = TempDir::new().unwrap();
    assert!(load_default_recipient(dir.path()).is_err());
    fs::write(dir.path().join("recipient.json"), b"{hibas-json").unwrap();
    assert!(load_default_recipient(dir.path()).is_err());
}

fn inspect_fixture(version: u8, declared_len: u32, header: &[u8]) -> Vec<u8> {
    let mut raw = b"2BRECIP\0".to_vec();
    raw.push(version);
    raw.extend_from_slice(&declared_len.to_be_bytes());
    raw.extend_from_slice(header);
    raw
}

#[test]
fn inspect_reports_version_byte_without_os_key_access() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("metaadat.2brecip");
    let header = br#"{"sealed_blob_b64":"titkositott-tesztadat"}"#;
    fs::write(&path, inspect_fixture(5, header.len() as u32, header)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&inspect_file(&path).unwrap()).unwrap();
    assert_eq!(value["file_version_byte"], 5);
    assert_eq!(value["sealed_blob_b64"], "titkositott-tesztadat");
}

#[test]
fn inspect_rejects_wrong_magic_and_unknown_version() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hibas.2brecip");
    let mut wrong_magic = inspect_fixture(5, 2, b"{}");
    wrong_magic[0] ^= 1;
    fs::write(&path, wrong_magic).unwrap();
    assert!(inspect_file(&path).is_err());
    for version in [0, 6, u8::MAX] {
        fs::write(&path, inspect_fixture(version, 2, b"{}")).unwrap();
        assert!(inspect_file(&path).is_err(), "Verzio: {version}");
    }
}

#[test]
fn inspect_rejects_oversized_truncated_or_invalid_json_header() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("hibas.2brecip");
    for raw in [
        inspect_fixture(5, 1024 * 1024 + 1, b""),
        inspect_fixture(5, 10, b"{}"),
        inspect_fixture(5, 1, b"{"),
        b"2BRECIP\0".to_vec(),
    ] {
        fs::write(&path, raw).unwrap();
        assert!(inspect_file(&path).is_err());
    }
}

proptest! {
    #[test]
    fn prop_fingerprint_changes_when_mlkem_key_changes(
        x in prop::array::uniform32(any::<u8>()),
        mlkem in prop::collection::vec(any::<u8>(), MLKEM_PUBLIC_KEY_LEN..=MLKEM_PUBLIC_KEY_LEN),
        position in 0usize..MLKEM_PUBLIC_KEY_LEN,
    ) {
        let mut changed = mlkem.clone();
        changed[position] ^= 1;
        prop_assert_ne!(
            fingerprint_from_public_key(&x, &mlkem),
            fingerprint_from_public_key(&x, &changed),
        );
    }
}
