use twobsecret::{nonce_from_index, fingerprint_from_public_key, default_device_dir};
use proptest::prelude::*;

#[test]
fn nonce_zero_index_is_all_zeros() {
    assert_eq!(nonce_from_index(0), [0u8; 12]);
}

#[test]
fn nonce_index_1_encodes_in_lower_8_bytes() {
    let n = nonce_from_index(1);
    assert_eq!(&n[..4], &[0u8; 4], "upper 4 bytes should always be zero");
    assert_eq!(&n[4..], &[0u8, 0, 0, 0, 0, 0, 0, 1], "lower 8 bytes = big-endian index");
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
        assert_eq!(nonce_from_index(idx).len(), 12, "nonce len should always be 12, idx={idx}");
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
fn fingerprint_is_always_16_chars() {
    for pk in [&[0u8; 32][..], &[0xFF; 32], &[0x42; 32], &[0xAB; 32]] {
        assert_eq!(
            fingerprint_from_public_key(pk).len(),
            16,
            "fingerprint must always be 16 chars"
        );
    }
}

#[test]
fn fingerprint_is_lowercase_hex() {
    let fp = fingerprint_from_public_key(&[0x55u8; 32]);
    assert!(
        fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
        "fingerprint should be lowercase hex, got: {fp}"
    );
}

#[test]
fn fingerprint_is_deterministic() {
    let pk = [0x11u8; 32];
    assert_eq!(
        fingerprint_from_public_key(&pk),
        fingerprint_from_public_key(&pk),
    );
}

#[test]
fn different_keys_produce_different_fingerprints() {
    assert_ne!(
        fingerprint_from_public_key(&[0x01u8; 32]),
        fingerprint_from_public_key(&[0x02u8; 32]),
    );
}

#[test]
fn single_byte_change_changes_fingerprint() {
    let pk_a = [0u8; 32];
    let mut pk_b = [0u8; 32];
    pk_b[0] = 0x01;
    assert_ne!(
        fingerprint_from_public_key(&pk_a),
        fingerprint_from_public_key(&pk_b),
    );
}

#[test]
fn fingerprint_first_vs_last_byte_differ() {
    let mut pk_a = [0u8; 32];
    let mut pk_b = [0u8; 32];
    pk_a[0] = 0xFF;
    pk_b[31] = 0xFF;
    // Both differ from all-zeros fingerprint
    let fp_zeros = fingerprint_from_public_key(&[0u8; 32]);
    assert_ne!(fingerprint_from_public_key(&pk_a), fp_zeros);
    assert_ne!(fingerprint_from_public_key(&pk_b), fp_zeros);
}

#[test]
fn default_device_dir_path_contains_expected_segments() {
    let dir = default_device_dir();
    let s = dir.to_string_lossy();
    assert!(s.contains("2BSecret"), "path should contain '2BSecret', got: {s}");
    assert!(s.contains("device_keys"), "path should contain 'device_keys', got: {s}");
}

#[test]
fn default_device_dir_is_reproducible() {
    assert_eq!(default_device_dir(), default_device_dir());
}

proptest! {
    #[test]
    fn prop_nonce_unique_per_distinct_index(a in 0u64..100_000u64, b in 0u64..100_000u64) {
        if a != b {
            prop_assert_ne!(nonce_from_index(a), nonce_from_index(b));
        }
    }

    #[test]
    fn prop_nonce_deterministic(idx in 0u64..u64::MAX) {
        prop_assert_eq!(nonce_from_index(idx), nonce_from_index(idx));
    }

    #[test]
    fn prop_nonce_upper_4_bytes_always_zero(idx in 0u64..u64::MAX) {
        let n = nonce_from_index(idx);
        prop_assert_eq!(&n[..4], &[0u8; 4], "upper 4 bytes must always be zero");
    }

    #[test]
    fn prop_nonce_lower_8_bytes_encode_index_big_endian(idx in 0u64..u64::MAX) {
        let n = nonce_from_index(idx);
        let decoded = u64::from_be_bytes(n[4..].try_into().unwrap());
        prop_assert_eq!(decoded, idx, "lower 8 bytes must be the big-endian index");
    }

    #[test]
    fn prop_fingerprint_always_16_chars(pk in prop::collection::vec(any::<u8>(), 32..=32)) {
        prop_assert_eq!(fingerprint_from_public_key(&pk).len(), 16);
    }

    #[test]
    fn prop_fingerprint_always_lowercase_hex(pk in prop::collection::vec(any::<u8>(), 32..=32)) {
        let fp = fingerprint_from_public_key(&pk);
        prop_assert!(
            fp.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "expected lowercase hex, got: {fp}"
        );
    }

    #[test]
    fn prop_fingerprint_deterministic(pk in prop::collection::vec(any::<u8>(), 32..=32)) {
        prop_assert_eq!(
            fingerprint_from_public_key(&pk),
            fingerprint_from_public_key(&pk),
        );
    }

    #[test]
    fn prop_different_keys_usually_produce_different_fingerprints(
        pk_a in prop::collection::vec(any::<u8>(), 32..=32),
        pk_b in prop::collection::vec(any::<u8>(), 32..=32),
    ) {
        if pk_a != pk_b {
            // SHA-256 collisions are astronomically unlikely; this is a sanity check
            prop_assert_ne!(
                fingerprint_from_public_key(&pk_a),
                fingerprint_from_public_key(&pk_b),
                "distinct keys should produce distinct fingerprints"
            );
        }
    }
}