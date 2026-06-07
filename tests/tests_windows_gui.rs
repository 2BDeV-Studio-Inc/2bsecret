#![cfg(target_os = "windows")]

use twobsecret::{
    generate_device_identity, export_public_key, load_default_recipient,
    encrypt_for_recipient, decrypt_on_this_device, App
};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_windows_gui_initial_state() {
    let app = App::default();
    assert!(app.selected_file.is_none());
}

#[test]
fn test_full_file_encryption_roundtrip() {
    // 1. Ideiglenes mappa létrehozása (a teszt végén automatikusan törlődik)
    let temp_dir = TempDir::new().unwrap();
    let device_dir = temp_dir.path().join("device_keys");
    
    // 2. Eszköz identitás generálása (DPAPI tesztelése élesben)
    let _identity = generate_device_identity(&device_dir)
        .expect("Nem sikerült az eszköz kulcspár generálása");
    
    // 3. Publikus kulcs exportálása és szimulált importálása címzettként
    let exported_path = export_public_key(&device_dir)
        .expect("Nem sikerült a publikus kulcs exportálása");
    
    let recipient_path = device_dir.join("recipient.json");
    fs::copy(exported_path, &recipient_path).unwrap();
    
    let recipient = load_default_recipient(&device_dir)
        .expect("Nem sikerült beolvasni a címzett kulcsát");

    // 4. Egy valódi tesztfájl létrehozása titkosításra
    let plaintext_path = temp_dir.path().join("szupertitkos_adat.txt");
    let eredeti_szoveg = b"Ez egy titkos uzenet a jovobol, amit a 2BSecret v3-nak hibatlanul kell kezelnie!";
    fs::write(&plaintext_path, eredeti_szoveg).unwrap();

    // 5. Titkosítás futtatása
    let encrypted_path = encrypt_for_recipient(&plaintext_path, &recipient)
        .expect("A titkosítási folyamat hibára futott");
    assert!(encrypted_path.exists(), "A titkosított fájl nem jött létre");

    // 6. Visszafejtés futtatása
    let decrypted_path = decrypt_on_this_device(&encrypted_path, &device_dir)
        .expect("A visszafejtési folyamat hibára futott");
    assert!(decrypted_path.exists(), "A visszafejtett fájl nem jött létre");

    // 7. Végső ellenőrzés: a visszafejtett bájtok megegyeznek az eredetivel?
    let visszafejtett_szoveg = fs::read(&decrypted_path).unwrap();
    assert_eq!(eredeti_szoveg, visszafejtett_szoveg.as_slice(), "A visszafejtett adat sérült vagy nem egyezik!");
}