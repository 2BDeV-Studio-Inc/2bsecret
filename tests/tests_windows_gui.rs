#![cfg(target_os = "windows")]

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use twobsecret::{
    change_master_password, decrypt_on_this_device, encrypt_for_recipient, export_public_key,
    generate_device_identity, generate_device_identity_confirmed, inspect_file,
    load_default_recipient, load_identity, secure_delete_file, RecipientPublic,
};

const TEST_PASSWORD: &[u8] = b"correct horse battery staple 42";

#[test]
fn test_windows_identity_stores_expected_protection_parameters() {
    let dir = TempDir::new().unwrap();
    let device = dir.path().join("device_keys");
    let identity = generate_device_identity(&device, TEST_PASSWORD).unwrap();
    assert_eq!(identity.protection_mode, "dpapi");
    assert_eq!(identity.argon2_mem_kib, 65536);
    assert_eq!(identity.argon2_time_cost, 3);
    assert_eq!(identity.argon2_lanes, 4);
    assert_eq!(identity.fingerprint.len(), 32);
    assert_eq!(B64.decode(identity.argon2_salt_b64).unwrap().len(), 16);
    assert_eq!(B64.decode(identity.public_key_b64).unwrap().len(), 32);
    assert_eq!(
        B64.decode(identity.ml_kem_public_key_b64).unwrap().len(),
        1184
    );
    assert!(!B64
        .decode(identity.protected_private_key_b64)
        .unwrap()
        .is_empty());
}

#[test]
fn test_full_file_encryption_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    let _identity = generate_device_identity(&device_dir, TEST_PASSWORD)
        .expect("Nem sikerult az eszkoz kulcspar generalasa");

    let exported_path =
        export_public_key(&device_dir).expect("Nem sikerult a publikus kulcs exportalasa");

    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();

    let recipient =
        load_default_recipient(&device_dir).expect("Nem sikerult beolvasni a cimzett kulcsat");

    let plaintext_path = temp_dir.path().join("szupertitkos_adat.txt");
    let eredeti_szoveg =
        b"Ez egy titkos uzenet a jovobol, amit a 2BSecret v5-nek hibatlanul kell kezelnie!";
    fs::write(&plaintext_path, eredeti_szoveg).unwrap();

    let encrypted_path = encrypt_for_recipient(&plaintext_path, &recipient, false)
        .expect("A titkositasi folyamat hibara futott");
    assert!(encrypted_path.exists(), "A titkositott fajl nem jott letre");

    let decrypted_path = decrypt_on_this_device(&encrypted_path, &device_dir, TEST_PASSWORD)
        .expect("A visszafejtesi folyamat hibara futott");
    assert!(
        decrypted_path.exists(),
        "A visszafejtett fajl nem jott letre"
    );

    let visszafejtett_szoveg = fs::read(&decrypted_path).unwrap();
    assert_eq!(
        eredeti_szoveg,
        visszafejtett_szoveg.as_slice(),
        "A visszafejtett adat serult vagy nem egyezik!"
    );
}

#[test]
fn test_wrong_master_password_fails_decrypt() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");

    let exported_path = export_public_key(&device_dir).unwrap();
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    let recipient = load_default_recipient(&device_dir).unwrap();

    let plaintext_path = temp_dir.path().join("adat.txt");
    fs::write(&plaintext_path, b"titkos adat").unwrap();

    let encrypted_path = encrypt_for_recipient(&plaintext_path, &recipient, false).unwrap();

    // Rossz jelszoval a decrypt-nek hibaznia kell, nem csendben rossz adatot adnia.
    let result = decrypt_on_this_device(&encrypted_path, &device_dir, b"rossz jelszo");
    assert!(
        result.is_err(),
        "Rossz jelszo eseten a decrypt-nek hibat kell dobnia"
    );
}

#[test]
fn test_empty_master_password_rejected_at_generation() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    let result = generate_device_identity(&device_dir, b"");
    assert!(
        result.is_err(),
        "Ures jelszoval nem szabad identity-t generalni"
    );
}

#[test]
fn test_generate_confirmed_rejects_password_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    // Elgepelt megerosites eseten nem szabad identity-t letrehozni — ez
    // pontosan azt a helyzetet elozi meg, amikor a felhasznalo egy elgepelt
    // jelszot hisz sajatjanak, es orokre kizarja magat.
    let result = generate_device_identity_confirmed(&device_dir, TEST_PASSWORD, b"mas jelszo");
    assert!(
        result.is_err(),
        "Eltero megerosites eseten hibat kell dobnia"
    );
    assert!(
        !device_dir.join("identity.json").exists(),
        "Sikertelen megerosites eseten nem szabad identity fajlt letrehozni"
    );
}

#[test]
fn test_generate_confirmed_succeeds_when_passwords_match() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    let result = generate_device_identity_confirmed(&device_dir, TEST_PASSWORD, TEST_PASSWORD);
    assert!(
        result.is_ok(),
        "Egyezo jelszavak eseten sikeresen kell generalnia"
    );
}

#[test]
fn test_change_master_password_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");
    const NEW_PASSWORD: &[u8] = b"masik eros jelszo 99";

    let original_identity = generate_device_identity(&device_dir, TEST_PASSWORD)
        .expect("kulcspar generalas sikertelen");

    change_master_password(&device_dir, TEST_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)
        .expect("jelszo csere sikertelen");

    // A regi jelszo mar nem mukodhet decrypt-nel.
    let exported_path = export_public_key(&device_dir).unwrap();
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    let recipient = load_default_recipient(&device_dir).unwrap();

    let plaintext_path = temp_dir.path().join("adat.txt");
    fs::write(&plaintext_path, b"titkos adat a jelszocsere utan").unwrap();
    let encrypted_path = encrypt_for_recipient(&plaintext_path, &recipient, false).unwrap();

    let old_pw_result = decrypt_on_this_device(&encrypted_path, &device_dir, TEST_PASSWORD);
    assert!(
        old_pw_result.is_err(),
        "A regi jelszonak mar nem szabad mukodnie"
    );

    let new_pw_result = decrypt_on_this_device(&encrypted_path, &device_dir, NEW_PASSWORD);
    let decrypted = new_pw_result.expect("Az új jelszónak működnie kell");
    assert_eq!(
        fs::read(decrypted).unwrap(),
        b"titkos adat a jelszocsere utan"
    );

    // A fingerprint (es igy a mar kiosztott public key) nem valtozhat a
    // jelszocsere miatt — a partnereknek nem kell ujra importalniuk.
    let identity_after = load_identity(&device_dir).unwrap();
    assert_eq!(identity_after.fingerprint, original_identity.fingerprint);
    assert_eq!(
        identity_after.public_key_b64,
        original_identity.public_key_b64
    );
    assert_eq!(
        identity_after.ml_kem_public_key_b64,
        original_identity.ml_kem_public_key_b64
    );
    assert_ne!(
        identity_after.argon2_salt_b64,
        original_identity.argon2_salt_b64
    );
}

#[test]
fn test_change_master_password_rejects_wrong_old_password() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");

    let result = change_master_password(
        &device_dir,
        b"rossz regi jelszo",
        b"uj jelszo",
        b"uj jelszo",
    );
    assert!(
        result.is_err(),
        "Rossz regi jelszoval nem szabad sikerulnie a valtasnak"
    );
}

#[test]
fn test_change_master_password_rejects_new_confirmation_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");

    let result = change_master_password(&device_dir, TEST_PASSWORD, b"uj jelszo", b"mas uj jelszo");
    assert!(
        result.is_err(),
        "Eltero uj jelszo megerosites eseten hibat kell dobnia"
    );
}

#[test]
fn test_encrypt_with_secure_delete_removes_original() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");

    let exported_path = export_public_key(&device_dir).unwrap();
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    let recipient = load_default_recipient(&device_dir).unwrap();

    let plaintext_path = temp_dir.path().join("torlendo_adat.txt");
    let tartalom = b"erzekeny adat amit securely torolni kell titkositas utan";
    fs::write(&plaintext_path, tartalom).unwrap();

    let encrypted_path = encrypt_for_recipient(&plaintext_path, &recipient, true)
        .expect("titkositas secure delete-tel sikertelen");

    assert!(
        !plaintext_path.exists(),
        "Az eredeti fajlnak torlodnie kell delete_original=true eseten"
    );
    assert!(
        encrypted_path.exists(),
        "A titkositott fajlnak meg kell maradnia"
    );

    // A titkositott fajl visszafejtheto marad a torles utan is — a secure
    // delete csak az EREDETI fajlt erinti, a ciphertext-et nem.
    let decrypted_path = decrypt_on_this_device(&encrypted_path, &device_dir, TEST_PASSWORD)
        .expect("visszafejtes sikertelen a secure delete utan");
    let visszafejtett = fs::read(decrypted_path).unwrap();
    assert_eq!(
        visszafejtett, tartalom,
        "A visszafejtett tartalomnak egyeznie kell az eredetivel"
    );
}

#[test]
fn test_encrypt_without_secure_delete_keeps_original() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");

    let exported_path = export_public_key(&device_dir).unwrap();
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    let recipient = load_default_recipient(&device_dir).unwrap();

    let plaintext_path = temp_dir.path().join("megmarado_adat.txt");
    fs::write(&plaintext_path, b"ez a fajl megmarad").unwrap();

    let _encrypted_path =
        encrypt_for_recipient(&plaintext_path, &recipient, false).expect("titkositas sikertelen");

    assert!(
        plaintext_path.exists(),
        "delete_original=false eseten az eredeti fajlnak meg kell maradnia"
    );
}

#[test]
fn test_secure_delete_file_removes_source() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("titkos.txt");
    fs::write(&file_path, b"ez erzekeny tartalom, torolni kell").unwrap();

    secure_delete_file(&file_path).expect("secure_delete_file sikertelen");

    assert!(
        !file_path.exists(),
        "A fajlnak nem szabad leteznie a torles utan"
    );
}

#[test]
fn test_v5_decrypt_wrong_recipient_rejected() {
    let temp_dir = TempDir::new().unwrap();
    let device_a_dir = temp_dir.path().join("device_a_keys");
    let device_b_dir = temp_dir.path().join("device_b_keys");

    generate_device_identity(&device_a_dir, TEST_PASSWORD)
        .expect("A eszkoz kulcsgeneralas sikertelen");
    generate_device_identity(&device_b_dir, TEST_PASSWORD)
        .expect("B eszkoz kulcsgeneralas sikertelen");

    // A-n titkositunk B szamara.
    let exported_b = export_public_key(&device_b_dir).unwrap();
    let recipient_path_on_a = device_a_dir.join("recipient.json");
    fs::copy(exported_b, &recipient_path_on_a).unwrap();
    let recipient_b = load_default_recipient(&device_a_dir).unwrap();

    let plaintext_path = temp_dir.path().join("csak_b-nek.txt");
    fs::write(&plaintext_path, b"ez csak B eszkozon lehet olvashato").unwrap();

    let encrypted_path =
        encrypt_for_recipient(&plaintext_path, &recipient_b, false).expect("titkositas sikertelen");

    // A probalja megfejteni a sajat (nem B) kulcsaval — a hibrid kulcscsere
    // es a sealed header AEAD miatt ennek hatarozottan el kell buknia, nem
    // csendben rossz adatot visszaadnia.
    let result_on_a = decrypt_on_this_device(&encrypted_path, &device_a_dir, TEST_PASSWORD);
    assert!(
        result_on_a.is_err(),
        "A eszkoznek NEM szabadna megfejtenie a B-nek szant fajlt"
    );

    // B viszont — akinek szant a fajl — sikeresen megfejti.
    let result_on_b = decrypt_on_this_device(&encrypted_path, &device_b_dir, TEST_PASSWORD);
    let decrypted_on_b = result_on_b.expect("B eszköznek meg kell fejtenie a neki szánt fájlt");
    assert_eq!(
        fs::read(decrypted_on_b).unwrap(),
        b"ez csak B eszkozon lehet olvashato"
    );
}

#[test]
fn test_reordered_chunks_are_detected() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");
    let exported_path = export_public_key(&device_dir).unwrap();
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    let recipient = load_default_recipient(&device_dir).unwrap();

    // Ket teljes chunkot igenylo meret, hogy legyen mit felcserelni.
    let chunk_size = 1024 * 1024;
    let plaintext_path = temp_dir.path().join("nagy_adat.bin");
    let mut tartalom = vec![0u8; chunk_size + 777];
    for (i, b) in tartalom.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    fs::write(&plaintext_path, &tartalom).unwrap();

    let encrypted_path =
        encrypt_for_recipient(&plaintext_path, &recipient, false).expect("titkositas sikertelen");

    let raw = fs::read(&encrypted_path).unwrap();

    // Header hossz kiolvasasa: MAGIC(8) + VERSION(1) + header_len(4 BE).
    let header_len = u32::from_be_bytes(raw[9..13].try_into().unwrap()) as usize;
    let body_start = 13 + header_len;
    let body = &raw[body_start..];

    // Az elso ket chunk-rekord hatarainak megkeresese:
    // [plain_len(4)][cipher_len(4)][nonce(12)][ciphertext].
    let mut offset = 0usize;
    let mut record_bounds = Vec::new();
    for _ in 0..2 {
        let cipher_len =
            u32::from_be_bytes(body[offset + 4..offset + 8].try_into().unwrap()) as usize;
        let record_len = 4 + 4 + 12 + cipher_len;
        record_bounds.push((offset, offset + record_len));
        offset += record_len;
    }
    let (r0_start, r0_end) = record_bounds[0];
    let (r1_start, r1_end) = record_bounds[1];

    // Az elso ket chunk-rekord teljes felcserelese — a nonce-index
    // ellenorzesnek (nem csak az AEAD tag-nek) el kell kapnia ezt.
    let mut tampered_body = Vec::with_capacity(body.len());
    tampered_body.extend_from_slice(&body[r1_start..r1_end]);
    tampered_body.extend_from_slice(&body[r0_start..r0_end]);
    tampered_body.extend_from_slice(&body[offset..]);

    let mut tampered_file = Vec::with_capacity(body_start + tampered_body.len());
    tampered_file.extend_from_slice(&raw[..body_start]);
    tampered_file.extend_from_slice(&tampered_body);
    fs::write(&encrypted_path, &tampered_file).unwrap();

    let before = directory_entries(temp_dir.path());
    let err = decrypt_on_this_device(&encrypted_path, &device_dir, TEST_PASSWORD).unwrap_err();
    assert!(
        err.to_string()
            .contains("Chunk sequence tampered or reordered"),
        "{err:#}"
    );
    assert_eq!(directory_entries(temp_dir.path()), before);
}

#[test]
fn test_multi_chunk_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");

    generate_device_identity(&device_dir, TEST_PASSWORD).expect("kulcspar generalas sikertelen");
    let exported_path = export_public_key(&device_dir).unwrap();
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    let recipient = load_default_recipient(&device_dir).unwrap();

    // Harom teljes chunk + egy reszleges negyedik, hogy a tobb-chunkos utat
    // es a v5 chunk_count ellenorzest is lefedje egy tesztben.
    let chunk_size = 1024 * 1024;
    let plaintext_path = temp_dir.path().join("tobb_chunkos.bin");
    let mut tartalom = vec![0u8; chunk_size * 3 + 12_345];
    for (i, b) in tartalom.iter_mut().enumerate() {
        *b = ((i * 7 + 3) % 256) as u8;
    }
    fs::write(&plaintext_path, &tartalom).unwrap();

    let encrypted_path =
        encrypt_for_recipient(&plaintext_path, &recipient, false).expect("titkositas sikertelen");

    let decrypted_path = decrypt_on_this_device(&encrypted_path, &device_dir, TEST_PASSWORD)
        .expect("visszafejtes sikertelen");

    let visszafejtett = fs::read(&decrypted_path).unwrap();
    assert_eq!(
        tartalom, visszafejtett,
        "Tobb-chunkos fajlnak byte-pontosan vissza kell allnia"
    );
}

const CHUNK_SIZE: usize = 1024 * 1024;

struct Fixture {
    root: TempDir,
    device: PathBuf,
    recipient: RecipientPublic,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().unwrap();
        let device = root.path().join("device_keys");
        generate_device_identity(&device, TEST_PASSWORD).unwrap();
        let exported = export_public_key(&device).unwrap();
        fs::copy(exported, device.join("recipient.json")).unwrap();
        let recipient = load_default_recipient(&device).unwrap();
        Self {
            root,
            device,
            recipient,
        }
    }

    fn encrypt(&self, name: &str, data: &[u8]) -> PathBuf {
        let input = self.root.path().join(name);
        fs::write(&input, data).unwrap();
        encrypt_for_recipient(&input, &self.recipient, false).unwrap()
    }

    fn assert_decrypt_fails_without_new_files(&self, path: &Path, expected: &str) {
        let before = directory_entries(self.root.path());
        let err = decrypt_on_this_device(path, &self.device, TEST_PASSWORD).unwrap_err();
        assert!(
            err.to_string().contains(expected),
            "Nem a várt hiba: {err:#}"
        );
        assert_eq!(
            directory_entries(self.root.path()),
            before,
            "Félkész kimenet maradt"
        );
    }
}

fn directory_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    entries
}

fn read_header(raw: &[u8]) -> (Value, usize) {
    assert!(raw.len() >= 13);
    assert_eq!(&raw[..8], b"2BRECIP\0");
    assert_eq!(raw[8], 5);
    let len = u32::from_be_bytes(raw[9..13].try_into().unwrap()) as usize;
    let end = 13usize.checked_add(len).unwrap();
    assert!(end <= raw.len());
    (serde_json::from_slice(&raw[13..end]).unwrap(), end)
}

fn replace_header(raw: &[u8], header: &Value) -> Vec<u8> {
    let (_, body_start) = read_header(raw);
    let json = serde_json::to_vec(header).unwrap();
    let mut updated = raw[..9].to_vec();
    updated.extend_from_slice(&u32::try_from(json.len()).unwrap().to_be_bytes());
    updated.extend_from_slice(&json);
    updated.extend_from_slice(&raw[body_start..]);
    updated
}

fn chunk_end(raw: &[u8], start: usize) -> usize {
    assert!(start + 20 <= raw.len());
    let len = u32::from_be_bytes(raw[start + 4..start + 8].try_into().unwrap()) as usize;
    let end = start.checked_add(20).unwrap().checked_add(len).unwrap();
    assert!(end <= raw.len());
    end
}

#[test]
fn test_v5_empty_and_chunk_boundary_roundtrips() {
    let f = Fixture::new();
    for size in [
        0,
        1,
        CHUNK_SIZE - 1,
        CHUNK_SIZE,
        CHUNK_SIZE + 1,
        CHUNK_SIZE * 2,
    ] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let encrypted = f.encrypt(&format!("meret_{size}.bin"), &data);
        let raw = fs::read(&encrypted).unwrap();
        read_header(&raw);
        let decrypted = decrypt_on_this_device(&encrypted, &f.device, TEST_PASSWORD).unwrap();
        assert_eq!(fs::read(decrypted).unwrap(), data, "Méret: {size}");
    }
}

#[test]
fn test_v5_header_keeps_sensitive_metadata_out_of_plaintext_fields() {
    let f = Fixture::new();
    let encrypted = f.encrypt("titkos_nev.txt", b"metaadat-teszt");
    let raw = fs::read(&encrypted).unwrap();
    let (header, _) = read_header(&raw);
    assert_eq!(header["version"], 5);
    assert_eq!(header["chunk_size"], CHUNK_SIZE);
    assert_eq!(
        header["key_wrap"],
        "x25519+mlkem768-hybrid-hkdf-sha256-sealed"
    );
    for hidden in [
        "recipient_fingerprint",
        "original_name",
        "chunk_count",
        "wrapped_file_key_b64",
    ] {
        assert!(header.get(hidden).is_none(), "Nyílt mező: {hidden}");
    }
    for visible in [
        "ephemeral_public_key_b64",
        "ml_kem_ciphertext_b64",
        "sealed_nonce_b64",
        "sealed_blob_b64",
    ] {
        assert!(!B64
            .decode(header[visible].as_str().unwrap())
            .unwrap()
            .is_empty());
    }
    assert_eq!(
        B64.decode(header["sealed_nonce_b64"].as_str().unwrap())
            .unwrap()
            .len(),
        12
    );
    let preview: Value = serde_json::from_str(&inspect_file(&encrypted).unwrap()).unwrap();
    assert_eq!(preview["file_version_byte"], 5);
    assert!(preview.get("original_name").is_none());
}

#[test]
fn test_v5_sealed_metadata_tampering_is_rejected() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.txt", b"eredeti tartalom");
    let raw = fs::read(&encrypted).unwrap();
    let (mut header, _) = read_header(&raw);
    let mut sealed = B64
        .decode(header["sealed_blob_b64"].as_str().unwrap())
        .unwrap();
    sealed[0] ^= 1;
    header["sealed_blob_b64"] = Value::String(B64.encode(sealed));
    fs::write(&encrypted, replace_header(&raw, &header)).unwrap();
    f.assert_decrypt_fails_without_new_files(&encrypted, "tampered header or wrong recipient");
}

#[test]
fn test_v5_changed_exchange_context_is_rejected() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.txt", b"kulcscsere-teszt");
    let raw = fs::read(&encrypted).unwrap();
    for field in ["ephemeral_public_key_b64", "ml_kem_ciphertext_b64"] {
        let (mut header, _) = read_header(&raw);
        let mut bytes = B64.decode(header[field].as_str().unwrap()).unwrap();
        bytes[0] ^= 1;
        header[field] = Value::String(B64.encode(bytes));
        fs::write(&encrypted, replace_header(&raw, &header)).unwrap();
        f.assert_decrypt_fails_without_new_files(&encrypted, "tampered header or wrong recipient");
    }
}

#[test]
fn test_v5_content_tampering_removes_partial_output() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.bin", &vec![0x53; CHUNK_SIZE + 37]);
    let mut raw = fs::read(&encrypted).unwrap();
    let (_, body) = read_header(&raw);
    let second = chunk_end(&raw, body);
    raw[second + 20] ^= 1;
    fs::write(&encrypted, raw).unwrap();
    f.assert_decrypt_fails_without_new_files(&encrypted, "Chunk tamper detected");
}

#[test]
fn test_v5_removed_last_chunk_is_rejected_and_cleaned_up() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.bin", &vec![0x29; CHUNK_SIZE + 71]);
    let mut raw = fs::read(&encrypted).unwrap();
    let (_, body) = read_header(&raw);
    raw.truncate(chunk_end(&raw, body));
    fs::write(&encrypted, raw).unwrap();
    f.assert_decrypt_fails_without_new_files(&encrypted, "File truncated or corrupt");
}

#[test]
fn test_v5_duplicate_chunk_is_rejected() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.bin", b"egyetlen blokk");
    let mut raw = fs::read(&encrypted).unwrap();
    let (_, body) = read_header(&raw);
    let duplicate = raw[body..].to_vec();
    raw.extend_from_slice(&duplicate);
    fs::write(&encrypted, raw).unwrap();
    f.assert_decrypt_fails_without_new_files(&encrypted, "Chunk sequence tampered or reordered");
}

#[test]
fn test_v5_oversized_chunk_is_rejected_before_allocation() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.bin", b"meretlimit");
    let mut raw = fs::read(&encrypted).unwrap();
    let (_, body) = read_header(&raw);
    raw[body + 4..body + 8].copy_from_slice(&((CHUNK_SIZE + 33) as u32).to_be_bytes());
    fs::write(&encrypted, raw).unwrap();
    f.assert_decrypt_fails_without_new_files(&encrypted, "Chunk size exceeds limit");
}

#[test]
fn test_unsupported_file_versions_are_rejected() {
    let f = Fixture::new();
    let encrypted = f.encrypt("adat.bin", b"verzioteszt");
    let original = fs::read(&encrypted).unwrap();
    for version in [0, 1, 2, 6, u8::MAX] {
        let mut raw = original.clone();
        raw[8] = version;
        fs::write(&encrypted, raw).unwrap();
        f.assert_decrypt_fails_without_new_files(&encrypted, "Unsupported file version");
    }
}

#[test]
fn test_existing_identity_is_not_overwritten() {
    let f = Fixture::new();
    let path = f.device.join("identity.json");
    let before = fs::read(&path).unwrap();
    let err = generate_device_identity(&f.device, b"masik jelszo")
        .err()
        .unwrap();
    assert!(err.to_string().contains("already exists"), "{err:#}");
    assert_eq!(fs::read(&path).unwrap(), before);
    let encrypted = f.encrypt("megmaradt.txt", b"a regi kulcs mukodik");
    let decrypted = decrypt_on_this_device(&encrypted, &f.device, TEST_PASSWORD).unwrap();
    assert_eq!(fs::read(decrypted).unwrap(), b"a regi kulcs mukodik");
}

#[test]
fn test_password_rotation_preserves_previously_encrypted_file_and_public_export() {
    let f = Fixture::new();
    let encrypted = f.encrypt("regi_fajl.txt", b"jelszocsere elott titkositva");
    let export_before = fs::read(export_public_key(&f.device).unwrap()).unwrap();
    let id_before = load_identity(&f.device).unwrap();
    let new_password = b"uj eros mesterjelszo 2026";
    change_master_password(&f.device, TEST_PASSWORD, new_password, new_password).unwrap();
    let id_after = load_identity(&f.device).unwrap();
    assert_eq!(id_before.fingerprint, id_after.fingerprint);
    assert_eq!(id_before.public_key_b64, id_after.public_key_b64);
    assert_eq!(
        id_before.ml_kem_public_key_b64,
        id_after.ml_kem_public_key_b64
    );
    assert_ne!(id_before.argon2_salt_b64, id_after.argon2_salt_b64);
    assert_eq!(
        fs::read(export_public_key(&f.device).unwrap()).unwrap(),
        export_before
    );
    assert!(decrypt_on_this_device(&encrypted, &f.device, TEST_PASSWORD).is_err());
    let decrypted = decrypt_on_this_device(&encrypted, &f.device, new_password).unwrap();
    assert_eq!(
        fs::read(decrypted).unwrap(),
        b"jelszocsere elott titkositva"
    );
}

#[test]
fn test_rejected_password_changes_leave_identity_unchanged() {
    let f = Fixture::new();
    let path = f.device.join("identity.json");
    let before = fs::read(&path).unwrap();
    let cases: [(&[u8], &[u8], &[u8]); 4] = [
        (b"rossz regi jelszo", b"uj jelszo", b"uj jelszo"),
        (TEST_PASSWORD, b"", b""),
        (TEST_PASSWORD, TEST_PASSWORD, TEST_PASSWORD),
        (TEST_PASSWORD, b"uj jelszo", b"eltero megerosites"),
    ];
    for (old, new, confirm) in cases {
        assert!(change_master_password(&f.device, old, new, confirm).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let encrypted = f.encrypt("adat.txt", b"a kulcs nem serult");
    let decrypted = decrypt_on_this_device(&encrypted, &f.device, TEST_PASSWORD).unwrap();
    assert_eq!(fs::read(decrypted).unwrap(), b"a kulcs nem serult");
}

#[test]
fn test_existing_output_files_are_not_overwritten() {
    let f = Fixture::new();
    let input = f.root.path().join("adat.txt");
    let existing_encrypted = f.root.path().join("adat.txt.2brecip");
    let existing_plain = f.root.path().join("decrypted_adat.txt");
    fs::write(&input, b"uj tartalom").unwrap();
    fs::write(&existing_encrypted, b"meglevo titkositott fajl").unwrap();
    fs::write(&existing_plain, b"meglevo visszafejtett fajl").unwrap();
    let encrypted = encrypt_for_recipient(&input, &f.recipient, false).unwrap();
    assert_ne!(encrypted, existing_encrypted);
    assert_eq!(
        fs::read(&existing_encrypted).unwrap(),
        b"meglevo titkositott fajl"
    );
    let decrypted = decrypt_on_this_device(&encrypted, &f.device, TEST_PASSWORD).unwrap();
    assert_ne!(decrypted, existing_plain);
    assert_eq!(
        fs::read(&existing_plain).unwrap(),
        b"meglevo visszafejtett fajl"
    );
    assert_eq!(fs::read(decrypted).unwrap(), b"uj tartalom");
}

#[test]
fn test_same_input_is_encrypted_with_fresh_exchange_and_sealed_nonce() {
    let f = Fixture::new();
    let first = f.encrypt("adat.txt", b"azonos forras");
    let second = f.encrypt("adat.txt", b"azonos forras");
    assert_ne!(first, second);
    let (h1, _) = read_header(&fs::read(first).unwrap());
    let (h2, _) = read_header(&fs::read(second).unwrap());
    for field in [
        "ephemeral_public_key_b64",
        "ml_kem_ciphertext_b64",
        "sealed_nonce_b64",
        "sealed_blob_b64",
    ] {
        assert_ne!(h1[field], h2[field], "Új véletlen érték szükséges: {field}");
    }
}

#[test]
fn test_secure_delete_empty_file_and_missing_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("ures.bin");
    fs::write(&path, b"").unwrap();
    secure_delete_file(&path).unwrap();
    assert!(!path.exists());
    assert!(secure_delete_file(&path).is_err());
}
