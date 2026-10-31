use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use anyhow::{anyhow, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eframe::egui;
use hkdf::Hkdf;
use ml_kem::{
    Decapsulate, DecapsulationKey768, Encapsulate, EncapsulationKey768, Generate, KeyExport,
    MlKem768,
};
use rand::{rngs::OsRng, RngCore};
use rfd::FileDialog;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "windows")]
use windows_dpapi::{decrypt_data, encrypt_data, Scope};

// 1. fázis: aláíró kulcsok, névjegyek, meghívó, v6 (többcímzetteses, aláírt) formátum.
mod sharing;
mod sharing_ui;
pub use sharing::*;

#[cfg(not(target_os = "windows"))]
use keyring::Entry as KeyringEntry;

const MAGIC: &[u8; 8] = b"2BRECIP\0";
const VERSION: u8 = 5;
const CHUNK_SIZE: usize = 1024 * 1024;
const NONCE_LEN: usize = 12;

// ML-KEM-768 seed mérete (FIPS 203): a DecapsulationKey ebből rekonstruálható.
const ML_KEM_SEED_LEN: usize = 64;
// X25519 sk (32) + ML-KEM-768 seed (64) = a kombinált identitás-titok mérete,
// amit egyben véd az Argon2id+DPAPI/keyring kettős réteg.
const COMBINED_SK_LEN: usize = 32 + ML_KEM_SEED_LEN;
// Aláíró magok: Ed25519 seed (32) + ML-DSA-65 seed (32). A teljes (1. fázistól
// induló) identitás-titok: X25519 sk ‖ ML-KEM seed ‖ Ed25519 seed ‖ ML-DSA seed.
const SIGNING_SEEDS_LEN: usize = 64;
const FULL_SK_LEN: usize = COMBINED_SK_LEN + SIGNING_SEEDS_LEN;

#[cfg(target_os = "windows")]
const PROTECTION_DPAPI: &str = "dpapi";
#[cfg(not(target_os = "windows"))]
const PROTECTION_KEYRING: &str = "keyring-aes256gcmsiv";

// Argon2id paraméterek ÚJ identitásokhoz és jelszócseréhez: 256 MiB memória,
// 3 iteráció, 4 szál (kb. 1 másodperc egy mai asztali gépen). A memory-hard
// jelleg miatt GPU/ASIC brute-force sokkal drágább, mint egy sima
// PBKDF2/SHA256-nál. A paraméterek az identity.json-ban tárolódnak, így a
// régebbi (kisebb paraméterű) identitások változatlanul megnyílnak, és az első
// jelszócsere automatikusan az új értékekre emeli őket.
const ARGON2_MEM_KIB: u32 = 262_144;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_LANES: u32 = 4;
const ARGON2_SALT_LEN: usize = 16;

// A korábbi kiadások értékei. Azokhoz az identity.json-okhoz kellenek, amelyekben
// az Argon2 paraméterek mezői hiányoznak (a mezők bevezetése előtt készültek):
// ezeket a RÉGI értékekkel kell feloldani, nem a mindenkori aktuálisakkal.
const LEGACY_ARGON2_MEM_KIB: u32 = 65_536;
const LEGACY_ARGON2_TIME_COST: u32 = 3;
const LEGACY_ARGON2_LANES: u32 = 4;

// A fájlból betöltött paraméterek felső korlátja: egy meghamisított
// identity.json ne tudjon gigabájtos memóriafoglalással lefagyasztani.
const ARGON2_MAX_MEM_KIB: u32 = 1_048_576; // 1 GiB
const ARGON2_MAX_TIME_COST: u32 = 16;
const ARGON2_MAX_LANES: u32 = 16;

// Fingerprint: SHA-256 első 128 bitje (32 hex karakter). A korábbi 64 bites
// (16 hex) változat célzott, "közel egyező ujjlenyomat" keresésnél már túl
// kicsi biztonsági tartalék volt. A régi értéket csak kompatibilitásból
// fogadjuk el (már kiosztott kulcsok, régi v5 fájlok).
const FINGERPRINT_HEX_LEN: usize = 32;
const LEGACY_FINGERPRINT_HEX_LEN: usize = 16;
const X25519_PK_LEN: usize = 32;
const ML_KEM_768_EK_LEN: usize = 1184;

pub struct App {
    pub selected_file: Option<PathBuf>,
    pub status: String,
    pub metadata_preview: String,
    pub loaded_recipient: Option<RecipientPublic>,
    pub device_dir: PathBuf,
    // Master jelszó a private key Argon2id rétegéhez. Nem perzisztálódik
    // sehova, csak a memóriában él a munkamenet alatt, és Drop-kor zeroize-olódik.
    // Ez a mező tölti be "jelenlegi jelszó" szerepét Decrypt-nél, Generate-nél,
    // és jelszó-csere esetén a "régi jelszó" mezőt is.
    pub master_password: Zeroizing<String>,
    // Csak Generate-nél használt megerősítő mező — típushiba elleni védelem.
    pub master_password_confirm: Zeroizing<String>,
    // Jelszó-csere: az új jelszó és annak megerősítése.
    pub rotate_new_password: Zeroizing<String>,
    pub rotate_new_password_confirm: Zeroizing<String>,
    // Az identitás-mentés jelszava és annak megerősítése (a mentés exportjánál
    // ez védi a fájlt, visszaállításnál ezzel nyílik meg).
    pub backup_password: Zeroizing<String>,
    pub backup_password_confirm: Zeroizing<String>,
    // Opt-in, alapból KIKAPCSOLT flag: ha true, "Encrypt for recipient" után
    // az eredeti fájl felülíródik és törlődik. Visszafordíthatatlan, ezért
    // nem sensitive adat (nincs zeroize rá szükség), de tudatos döntést kér.
    pub securely_delete_original: bool,
    // Az utolsó felhasználói tevékenység ideje: tétlenség után a program
    // automatikusan lezárja magát (a memóriában lévő jelszavak nullázódnak).
    last_activity: std::time::Instant,
    // 1. fázis (megosztás): a névjegyek gyorsítótára, a kijelölt címzettek, a
    // megjelenített név, a saját ujjlenyomat és az ismeretlen feladó párbeszéd.
    contacts: Vec<Contact>,
    contacts_error: Option<String>,
    selected_contacts: std::collections::HashSet<String>,
    include_self: bool,
    display_name: String,
    own_fingerprint: Option<String>,
    pending_unknown: Option<UnknownSenderError>,
    safety_view: Option<String>,
}

/// Ennyi tétlenség után a program törli a memóriából az összes beírt jelszót.
const AUTO_LOCK_AFTER: std::time::Duration = std::time::Duration::from_secs(5 * 60);

impl Drop for App {
    fn drop(&mut self) {
        self.master_password.zeroize();
        self.master_password_confirm.zeroize();
        self.rotate_new_password.zeroize();
        self.rotate_new_password_confirm.zeroize();
        self.backup_password.zeroize();
        self.backup_password_confirm.zeroize();
    }
}

impl App {
    /// Van-e a memóriában bármilyen beírt jelszó?
    fn has_unlocked_secrets(&self) -> bool {
        !(self.master_password.is_empty()
            && self.master_password_confirm.is_empty()
            && self.rotate_new_password.is_empty()
            && self.rotate_new_password_confirm.is_empty()
            && self.backup_password.is_empty()
            && self.backup_password_confirm.is_empty())
    }

    /// Lezárás: az összes jelszómező nullázása és ürítése, valamint az egui
    /// belső állapotának törlése. Az utóbbi azért kell, mert az egui szövegmezői
    /// (a visszavonási előzmény miatt) a korábbi tartalmakról másolatot tarthatnak.
    fn lock(&mut self, ctx: &egui::Context, reason: &str) {
        let had_secrets = self.has_unlocked_secrets();
        for field in [
            &mut self.master_password,
            &mut self.master_password_confirm,
            &mut self.rotate_new_password,
            &mut self.rotate_new_password_confirm,
            &mut self.backup_password,
            &mut self.backup_password_confirm,
        ] {
            field.zeroize();
            field.clear();
        }
        ctx.data_mut(|data| data.clear());
        // A korábbi állapotüzenetet (pl. egy hosszú művelet eredményét) nem
        // írjuk felül, csak kiegészítjük; ha nem volt mit zárolni, nem ismételjük.
        if had_secrets {
            self.status = if self.status.is_empty() {
                reason.to_string()
            } else {
                format!("{} | {}", self.status, reason)
            };
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RecipientPublic {
    pub fingerprint: String,
    pub public_key_b64: String,
    // ML-KEM-768 encapsulation key (post-quantum hibrid réteghez).
    pub ml_kem_public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceIdentity {
    // Az Argon2id-derivált kulccsal AES-256-GCM-SIV-vel wrappelt, majd
    // OS-szinten (DPAPI/keyring) is védett kombinált secret blob:
    // X25519 sk (32 byte) ‖ ML-KEM-768 seed (64 byte) egyben.
    pub protected_private_key_b64: String,
    pub public_key_b64: String,
    // ML-KEM-768 encapsulation key — ez a publikus fele, plaintext.
    pub ml_kem_public_key_b64: String,
    pub fingerprint: String,
    #[serde(default = "default_protection_mode")]
    pub protection_mode: String,
    // Argon2id paraméterek — tárolva, hogy a jövőben a tuningolás ne törje
    // el a régi identity-ket (a régi salt/params-szal fejtjük vissza őket).
    pub argon2_salt_b64: String,
    #[serde(default = "default_argon2_mem_kib")]
    pub argon2_mem_kib: u32,
    #[serde(default = "default_argon2_time_cost")]
    pub argon2_time_cost: u32,
    #[serde(default = "default_argon2_lanes")]
    pub argon2_lanes: u32,
    // 1. fázis: hibrid aláíró kulcsok publikus fele (Ed25519 + ML-DSA-65). A
    // régebbi identitásokban hiányzik (üres), az `ensure_signing_keys` pótolja.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ed25519_public_key_b64: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ml_dsa_public_key_b64: String,
}

// FONTOS: ezek a serde-alapértékek a hiányzó mezőkre vonatkoznak, vagyis a
// paraméterek tárolása előtti identitásokra — azok a RÉGI értékekkel készültek.
fn default_argon2_mem_kib() -> u32 {
    LEGACY_ARGON2_MEM_KIB
}
fn default_argon2_time_cost() -> u32 {
    LEGACY_ARGON2_TIME_COST
}
fn default_argon2_lanes() -> u32 {
    LEGACY_ARGON2_LANES
}

fn default_protection_mode() -> String {
    #[cfg(target_os = "windows")]
    {
        PROTECTION_DPAPI.to_string()
    }
    #[cfg(not(target_os = "windows"))]
    {
        PROTECTION_KEYRING.to_string()
    }
}

#[derive(Serialize, Deserialize)]
struct Header {
    magic_b64: String,
    version: u8,
    algorithm: String,
    key_wrap: String,
    chunk_size: usize,

    // ── v3/v4 mezők (plaintext, csak régi fájlok olvasásához kellenek) ──
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrap_nonce_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wrapped_file_key_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunk_count: Option<u64>,

    // ── v5 mezők ──
    // X25519 ephemeral pubkey — v4-ben is ez volt a mező, v5-ben is kell
    // (a hibrid kulcscsere első fele), ezért marad Option (v3-ban nem volt).
    #[serde(skip_serializing_if = "Option::is_none")]
    ephemeral_public_key_b64: Option<String>,
    // ML-KEM-768 encapsulation ciphertext — csak v5-ben.
    #[serde(skip_serializing_if = "Option::is_none")]
    ml_kem_ciphertext_b64: Option<String>,
    // A lezárt (sealed) metadata blokk nonce-a és tartalma. A sealed_blob
    // AES-256-GCM-SIV-vel titkosítva tartalmazza: recipient_fingerprint,
    // original_name, chunk_count, file_key — mindezt csak a hibrid
    // kulcscsere birtokában lehet feloldani, egy megfigyelő nem látja.
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_nonce_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_blob_b64: Option<String>,
}

/// A sealed_blob_b64 mögött rejtőző, csak dekódolás után látható tartalom.
#[derive(Serialize, Deserialize)]
struct SealedMeta {
    recipient_fingerprint: String,
    original_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunk_count: Option<u64>,
    // A tényleges fájl-tartalom AES kulcsa — a régi verziókban külön
    // "wrapped_file_key" mezőben volt, v5-ben a sealed blokk része.
    file_key_b64: String,
}

struct FileCleanupGuard {
    path: PathBuf,
    success: bool,
}

impl Drop for FileCleanupGuard {
    fn drop(&mut self) {
        if !self.success && self.path.exists() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl Default for App {
    fn default() -> Self {
        let device_dir = default_device_dir();
        let status = match fs::create_dir_all(&device_dir) {
            Ok(_) => "Ready.".to_string(),
            Err(e) => format!("Init warning: could not create dir: {e}"),
        };
        let display_name = load_display_name(&device_dir);
        let mut app = Self {
            selected_file: None,
            status,
            metadata_preview: String::new(),
            loaded_recipient: load_default_recipient(&device_dir).ok(),
            device_dir,
            master_password: Zeroizing::new(String::new()),
            master_password_confirm: Zeroizing::new(String::new()),
            rotate_new_password: Zeroizing::new(String::new()),
            rotate_new_password_confirm: Zeroizing::new(String::new()),
            backup_password: Zeroizing::new(String::new()),
            backup_password_confirm: Zeroizing::new(String::new()),
            securely_delete_original: false,
            last_activity: std::time::Instant::now(),
            contacts: Vec::new(),
            contacts_error: None,
            selected_contacts: std::collections::HashSet::new(),
            include_self: true,
            display_name,
            own_fingerprint: None,
            pending_unknown: None,
            safety_view: None,
        };
        app.refresh_sharing_state();
        app
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ── Automatikus zárolás tétlenség esetén ──
        let active = ctx.input(|i| !i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO);
        if active {
            self.last_activity = std::time::Instant::now();
        } else if self.has_unlocked_secrets() && self.last_activity.elapsed() >= AUTO_LOCK_AFTER {
            self.lock(
                ctx,
                "Locked after 5 minutes of inactivity: passwords were cleared from memory.",
            );
        }
        if self.has_unlocked_secrets() {
            // Enélkül az egui eseménytelen ablaknál nem futna le az update, és a
            // zárolás nem következne be.
            ctx.request_repaint_after(std::time::Duration::from_secs(5));
        }

        let mut lock_requested = false;
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Master password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.master_password)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Confirm password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.master_password_confirm)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            ui.label("Required for key generation and decryption. Never stored — kept only in memory this session. \"Confirm password\" is only checked when generating a new keypair.");
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                if ui.button("Generate this device keypair").clicked() {
                    if self.master_password.is_empty() {
                        self.status = "Enter a master password first.".to_string();
                    } else if self.master_password.as_str() != self.master_password_confirm.as_str() {
                        self.status = "Passwords do not match — check both fields.".to_string();
                    } else if let Err(e) = check_password_strength(self.master_password.as_bytes()) {
                        self.status = format!("Weak password: {e}");
                    } else {
                        match generate_device_identity_confirmed(
                            &self.device_dir,
                            self.master_password.as_bytes(),
                            self.master_password_confirm.as_bytes(),
                        ) {
                            Ok(id) => self.status = format!("Generated device identity [{}]", id.fingerprint),
                            Err(e) => self.status = format!("Generate error: {e:#}"),
                        }
                        self.refresh_sharing_state();
                    }
                }
                if ui.button("Export my public key").clicked() {
                    match export_public_key(&self.device_dir) {
                        Ok(path) => self.status = format!("Exported public key: {}", path.display()),
                        Err(e) => self.status = format!("Export error: {e:#}"),
                    }
                }
                if ui.button("Import recipient public key").clicked() {
                    match import_recipient_public_key(&self.device_dir) {
                        Ok(rec) => {
                            self.loaded_recipient = Some(rec.clone());
                            self.status = format!("Imported recipient fingerprint: {}", rec.fingerprint);
                        }
                        Err(e) => self.status = format!("Import error: {e:#}"),
                    }
                }
            });

            ui.add_space(8.0);
            if let Some(rec) = &self.loaded_recipient {
                ui.label(format!("Current recipient fingerprint: {}", rec.fingerprint));
            } else {
                ui.label("Current recipient: none");
            }

            ui.add_space(8.0);
            if ui.button("Select file").clicked() {
                self.selected_file = FileDialog::new().pick_file();
                self.metadata_preview.clear();
                if let Some(path) = &self.selected_file {
                    self.status = format!("Selected: {}", path.display());
                }
            }

            if let Some(path) = &self.selected_file {
                ui.label(format!("Current file: {}", path.display()));
            } else {
                ui.label("Current file: none");
            }

            ui.add_space(8.0);
            ui.checkbox(
                &mut self.securely_delete_original,
                "Securely delete original file after encrypting (irreversible — overwrites and removes the source file)",
            );
            if ui.button("Encrypt for recipient").clicked() {
                match (&self.selected_file, &self.loaded_recipient) {
                    (Some(path), Some(rec)) => {
                        match encrypt_for_recipient(path, rec, self.securely_delete_original) {
                            Ok(out) => self.status = format!("Encrypted to: {}", out.display()),
                            Err(e) => self.status = format!("Encrypt error: {e:#}"),
                        }
                    }
                    (None, _) => self.status = "Select a file first.".to_string(),
                    (_, None) => self.status = "Import a recipient public key first.".to_string(),
                }
            }

            if ui.button("Decrypt on this device").clicked() {
                // v3–v5 és v6 fájlt is kezel; v6-nál ellenőrzi a feladót.
                self.decrypt_selected_file(SenderPolicy::ContactsOnly);
            }

            if ui.button("Show metadata").clicked() {
                match &self.selected_file {
                    Some(path) => match inspect_file(path) {
                        Ok(meta) => self.metadata_preview = meta,
                        Err(e) => self.metadata_preview = format!("Inspect error: {e:#}"),
                    },
                    None => self.metadata_preview = "Select a file first.".to_string(),
                }
            }

            self.sharing_ui(ui);

            ui.add_space(16.0);
            ui.separator();
            ui.label("Change master password");
            ui.label("Uses the \"Master password\" field above as your current password.");
            ui.horizontal(|ui| {
                ui.label("New password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.rotate_new_password)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Confirm new password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.rotate_new_password_confirm)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            if ui.button("Change master password").clicked() {
                if self.master_password.is_empty() {
                    self.status = "Enter your current master password above first.".to_string();
                } else if let Err(e) = check_password_strength(self.rotate_new_password.as_bytes()) {
                    self.status = format!("Weak new password: {e}");
                } else {
                    match change_master_password(
                        &self.device_dir,
                        self.master_password.as_bytes(),
                        self.rotate_new_password.as_bytes(),
                        self.rotate_new_password_confirm.as_bytes(),
                    ) {
                        Ok(()) => {
                            self.status = "Master password changed. Use the new password from now on.".to_string();
                            self.master_password.zeroize();
                            self.master_password.clear();
                            self.rotate_new_password.zeroize();
                            self.rotate_new_password.clear();
                            self.rotate_new_password_confirm.zeroize();
                            self.rotate_new_password_confirm.clear();
                        }
                        Err(e) => self.status = format!("Password change error: {e:#}"),
                    }
                }
            }

            ui.add_space(16.0);
            ui.separator();
            ui.label("Identity backup");
            ui.label(
                "Your private key is bound to this device's OS credential store, so identity.json \
                 alone cannot be restored after a reinstall. Make a password-protected backup and \
                 keep it somewhere safe. Use a backup password that differs from your master password.",
            );
            ui.horizontal(|ui| {
                ui.label("Backup password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.backup_password)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            ui.horizontal(|ui| {
                ui.label("Confirm backup password:");
                ui.add(
                    egui::TextEdit::singleline(&mut *self.backup_password_confirm)
                        .password(true)
                        .desired_width(220.0),
                );
            });
            ui.horizontal(|ui| {
                if ui.button("Export identity backup…").clicked() {
                    if self.master_password.is_empty() {
                        self.status = "Enter your current master password above first.".to_string();
                    } else if self.backup_password.as_str() != self.backup_password_confirm.as_str() {
                        self.status = "Backup passwords do not match — check both fields.".to_string();
                    } else if let Err(e) = check_password_strength(self.backup_password.as_bytes()) {
                        self.status = format!("Weak backup password: {e}");
                    } else if let Some(path) = FileDialog::new()
                        .add_filter("2BSecret identity backup", &["2bbackup"])
                        .set_file_name("2bsecret-identity.2bbackup")
                        .save_file()
                    {
                        match export_identity_backup(
                            &self.device_dir,
                            self.master_password.as_bytes(),
                            self.backup_password.as_bytes(),
                            &path,
                        ) {
                            Ok(()) => self.status = format!("Backup written and verified: {}", path.display()),
                            Err(e) => self.status = format!("Backup error: {e:#}"),
                        }
                    }
                }
                if ui.button("Restore identity from backup…").clicked() {
                    if self.backup_password.is_empty() {
                        self.status = "Enter the backup password first.".to_string();
                    } else if self.master_password.is_empty() {
                        self.status = "Enter the NEW master password at the top (and confirm it): it will protect the restored identity on this device.".to_string();
                    } else if self.master_password.as_str() != self.master_password_confirm.as_str() {
                        self.status = "Passwords do not match — check both master password fields.".to_string();
                    } else if let Err(e) = check_password_strength(self.master_password.as_bytes()) {
                        self.status = format!("Weak password: {e}");
                    } else if let Some(path) = FileDialog::new()
                        .add_filter("2BSecret identity backup", &["2bbackup"])
                        .pick_file()
                    {
                        match restore_identity_from_backup(
                            &self.device_dir,
                            &path,
                            self.backup_password.as_bytes(),
                            self.master_password.as_bytes(),
                        ) {
                            Ok(id) => self.status = format!("Identity restored [{}]", id.fingerprint),
                            Err(e) => self.status = format!("Restore error: {e:#}"),
                        }
                        self.refresh_sharing_state();
                    }
                }
            });

            ui.add_space(12.0);
            if ui.button("Lock now (clear passwords from memory)").clicked() {
                lock_requested = true;
            }
            ui.label(&self.status);
            ui.separator();
            ui.label("Metadata preview:");
            ui.monospace(&self.metadata_preview);
            });
        });

        // A zárolás a panel felépítése UTÁN fut le, hogy az egui belső
        // állapotának törlése ne érje a még épülő képkockát.
        if lock_requested {
            self.lock(ctx, "Locked: passwords were cleared from memory.");
        }
    }
}

pub fn default_device_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("2BSecret")
        .join("device_keys")
}

fn device_identity_path(device_dir: &Path) -> PathBuf {
    device_dir.join("identity.json")
}
fn default_recipient_path(device_dir: &Path) -> PathBuf {
    device_dir.join("recipient.json")
}
fn exported_public_key_path(device_dir: &Path, fingerprint: &str) -> PathBuf {
    device_dir.join(format!("recipient_{}.json", fingerprint))
}

// ───────────────────────── Atomikus fájlírás ─────────────────────────
//
// Az identity.json és a mentések írása nem történhet "helyben": egy megszakadt
// írás (áramkimaradás, összeomlás, tele lemez) félkész fájlt hagyna, és vele
// elveszne a privát kulcs. Ehelyett ideiglenes fájlba írunk, azt lemezre
// kényszerítjük (fsync), és csak utána tesszük a végleges helyére.

/// A könyvtárbejegyzés tartóssága: fájl létrehozása/átnevezése után a
/// szülőkönyvtárat is lemezre kell írni. Unixon működik; Windowson a könyvtár
/// nem nyitható meg így, ott ez szándékosan "best effort" (a hiba figyelmen
/// kívül marad).
fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            let parent = if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            };
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Csak a tulajdonos olvashatja (Unixon 0600), és csak újonnan létrehozható.
fn private_new_file_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

fn temp_sibling_path(path: &Path) -> PathBuf {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let mut name = std::ffi::OsString::from(".");
    name.push(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("file")),
    );
    name.push(format!(".{}.tmp", hex_prefix(&random, 16)));
    path.with_file_name(name)
}

fn write_temp_file(path: &Path, data: &[u8]) -> Result<PathBuf> {
    let tmp = temp_sibling_path(path);
    let result = (|| -> std::io::Result<()> {
        let mut f = private_new_file_options().open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!(
            "Cannot write temporary file next to {}: {e}",
            path.display()
        ));
    }
    Ok(tmp)
}

/// A fájlt atomikusan létrehozza vagy lecseréli: a másik olvasó vagy a
/// megszakadó program mindig vagy a régi, vagy az új teljes tartalmat látja.
fn write_file_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = write_temp_file(path, data)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("Cannot replace {}: {e}", path.display()));
    }
    sync_parent_dir(path);
    Ok(())
}

/// Atomikusan létrehozza a fájlt, de SOHA nem ír felül meglévőt. A kész
/// ideiglenes fájlt hard linkkel teszi a helyére (ez ütközésnél hibával áll
/// meg); ha a fájlrendszer nem támogatja a hard linket (pl. FAT/exFAT, egyes
/// hálózati megosztások), tartalékként `create_new`-val ír (ez már nem
/// atomikus, de a felülírás-védelmet megtartja).
fn write_file_atomic_new(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = write_temp_file(path, data)?;
    match fs::hard_link(&tmp, path) {
        Ok(()) => {
            let _ = fs::remove_file(&tmp);
            sync_parent_dir(path);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&tmp);
            Err(anyhow!(
                "{} already exists; refusing to overwrite it",
                path.display()
            ))
        }
        Err(_) => {
            let _ = fs::remove_file(&tmp);
            let mut f = private_new_file_options().open(path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    anyhow!(
                        "{} already exists; refusing to overwrite it",
                        path.display()
                    )
                } else {
                    anyhow!("Cannot create {}: {e}", path.display())
                }
            })?;
            f.write_all(data)?;
            f.sync_all()?;
            sync_parent_dir(path);
            Ok(())
        }
    }
}

// ───────────────────────── Jelszóerősség ─────────────────────────

/// A mesterjelszó (és a mentési jelszó) minimális hossza karakterben.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Becsült minimális entrópia bitben (hossz × log2(karakterkészlet)).
const MIN_PASSWORD_ENTROPY_BITS: f64 = 64.0;

// Olyan szavak, amelyek számjegyek/írásjelek hozzáfűzésével is gyakori, könnyen
// kitalálható jelszavak ("Password123456!"). Az ellenőrzés a jelszó csupa
// kisbetűs, számjegyek nélküli alakját hasonlítja össze velük.
const COMMON_PASSWORD_WORDS: &[&str] = &[
    "password",
    "passwort",
    "jelszo",
    "jelszó",
    "qwertyuiop",
    "qwertzuiop",
    "asdfghjkl",
    "zxcvbnm",
    "iloveyou",
    "letmein",
    "welcome",
    "administrator",
    "secret",
    "titkos",
    "twobsecret",
    "bsecret",
];

fn is_repeating_pattern(chars: &[char]) -> bool {
    // Pl. "abababababab" vagy "abcabcabcabc": a jelszó egy rövid minta ismétlése.
    let max_period = (chars.len() / 2).min(8);
    (1..=max_period).any(|p| (0..chars.len()).all(|i| chars[i] == chars[i % p]))
}

fn is_sequence(chars: &[char]) -> bool {
    // Pl. "abcdefghijkl", "123456789012", "mlkjihgfedcba".
    if chars.len() < 2 {
        return false;
    }
    let asc = chars.windows(2).all(|w| (w[1] as i64) - (w[0] as i64) == 1);
    let desc = chars.windows(2).all(|w| (w[0] as i64) - (w[1] as i64) == 1);
    asc || desc
}

fn estimate_entropy_bits(chars: &[char]) -> f64 {
    let mut pool = 0u32;
    if chars.iter().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if chars.iter().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if chars
        .iter()
        .any(|c| c.is_ascii() && !c.is_ascii_alphanumeric())
    {
        pool += 33; // írásjelek és szóköz
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        pool += 64; // ékezetes és egyéb nem-ASCII karakterek (pl. magyar betűk)
    }
    (chars.len() as f64) * (pool.max(2) as f64).log2()
}

/// Új jelszó (generáláskor, jelszócserekor, mentés védelméhez) ellenőrzése.
///
/// Ez egy egyszerű, függőségmentes heurisztika, nem helyettesít egy valódi
/// jelszóerősség-becslőt (pl. zxcvbn), de kiszűri a tipikusan gyenge
/// jelszavakat: túl rövid, kevés különböző karakter, ismétlődő minta,
/// számsor/ábécé-sorozat, gyakori szó, alacsony becsült entrópia.
///
/// A MEGLÉVŐ jelszavak feloldását nem érinti: régi, gyengébb jelszóval
/// létrehozott identitás továbbra is megnyílik, csak új jelszót nem lehet
/// ilyenre állítani.
pub fn check_password_strength(password: &[u8]) -> Result<()> {
    let s = std::str::from_utf8(password)
        .map_err(|_| anyhow!("The password must be valid UTF-8 text"))?;
    let chars: Vec<char> = s.chars().collect();

    if chars.len() < MIN_PASSWORD_CHARS {
        return Err(anyhow!(
            "Password is too short: use at least {MIN_PASSWORD_CHARS} characters \
             (a passphrase of several random words works best)"
        ));
    }

    let distinct = {
        let mut sorted = chars.clone();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.len()
    };
    if distinct < 6 || distinct * 4 < chars.len() {
        return Err(anyhow!(
            "Password uses too few different characters; make it less repetitive"
        ));
    }
    if is_repeating_pattern(&chars) {
        return Err(anyhow!(
            "Password is a repeated pattern; choose something less predictable"
        ));
    }
    if is_sequence(&chars) {
        return Err(anyhow!(
            "Password is a simple sequence (like 123456... or abcdef...); choose something less predictable"
        ));
    }

    let letters_only: String = s
        .chars()
        .filter(|c| c.is_alphabetic())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if COMMON_PASSWORD_WORDS.contains(&letters_only.as_str()) {
        return Err(anyhow!(
            "Password is based on a very common word; choose something less predictable"
        ));
    }

    if estimate_entropy_bits(&chars) < MIN_PASSWORD_ENTROPY_BITS {
        return Err(anyhow!(
            "Password is too easy to guess for its length: make it longer, or mix upper and \
             lower case letters, digits and symbols (several random words also work well)"
        ));
    }
    Ok(())
}

/// A fingerprint mindkét publikus kulcsot (X25519 + ML-KEM-768) együtt hash-eli,
/// hogy a kettő ne legyen szétszedhető/összekeverhető más identitás feléivel.
pub fn fingerprint_from_public_key(x25519_pk: &[u8], ml_kem_pk: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(x25519_pk);
    hasher.update(ml_kem_pk);
    let digest = hasher.finalize();
    hex_prefix(&digest, FINGERPRINT_HEX_LEN)
}

/// A korábbi, 64 bites (16 hex) fingerprint — csak kompatibilitási célra.
fn legacy_short_fingerprint(x25519_pk: &[u8], ml_kem_pk: &[u8]) -> String {
    let full = fingerprint_from_public_key(x25519_pk, ml_kem_pk);
    full[..LEGACY_FINGERPRINT_HEX_LEN].to_string()
}

/// Az eltárolt fingerprint egyezik a kulcsokból számolttal (új vagy régi hosszal)?
fn fingerprint_matches(stored: &str, x25519_pk: &[u8], ml_kem_pk: &[u8]) -> bool {
    stored == fingerprint_from_public_key(x25519_pk, ml_kem_pk)
        || stored == legacy_short_fingerprint(x25519_pk, ml_kem_pk)
}

/// Dekódolja és hossz-ellenőrzi a két publikus kulcsot, majd a KULCSOKBÓL
/// számolja ki a fingerprintet — soha nem a fájlban szereplő értékből.
fn validated_fingerprint(x25519_b64: &str, ml_kem_b64: &str) -> Result<String> {
    let x = B64
        .decode(x25519_b64)
        .map_err(|_| anyhow!("Invalid X25519 public key encoding"))?;
    if x.len() != X25519_PK_LEN {
        return Err(anyhow!("Invalid X25519 public key length"));
    }
    let m = B64
        .decode(ml_kem_b64)
        .map_err(|_| anyhow!("Invalid ML-KEM public key encoding"))?;
    if m.len() != ML_KEM_768_EK_LEN {
        return Err(anyhow!("Invalid ML-KEM public key length"));
    }
    Ok(fingerprint_from_public_key(&x, &m))
}

/// A címzett publikus adatait ellenőrzi: a megadott fingerprintnek egyeznie kell
/// a kulcsokból számolttal, különben a fájl sérült vagy meghamisították.
/// A visszaadott érték fingerprintje mindig a (friss, 128 bites) számolt érték.
fn normalize_recipient(mut rec: RecipientPublic) -> Result<RecipientPublic> {
    let computed = validated_fingerprint(&rec.public_key_b64, &rec.ml_kem_public_key_b64)?;
    let legacy = &computed[..LEGACY_FINGERPRINT_HEX_LEN];
    if rec.fingerprint != computed && rec.fingerprint != legacy {
        return Err(anyhow!(
            "Recipient fingerprint does not match the public keys in the file — \
             the file is corrupted or has been tampered with"
        ));
    }
    rec.fingerprint = computed;
    Ok(rec)
}

fn hex_prefix(bytes: &[u8], max_len: usize) -> String {
    let mut s = String::new();
    for b in bytes.iter().take(max_len / 2) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn derive_wrap_key_v3(shared_secret: &[u8], eph_public_bytes: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(eph_public_bytes), shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"2BSecret v3 file-key wrap", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// v5: a hibrid (X25519 + ML-KEM-768) kulcscseréből származó kombinált
/// shared secret-ből deriválja a sealed header blokk AES kulcsát.
/// A salt (eph_pubkey ‖ kem_ciphertext) az adott kulcscsere-példányhoz köti
/// a deriválást — más ephemeral/ciphertext párral más kulcs jönne ki.
fn derive_header_key_v5(combined_shared_secret: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), combined_shared_secret);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"2BSecret v5 sealed header key", okm.as_mut())
        .expect("HKDF expand failed");
    okm
}

fn sanitize_filename(name: &str) -> String {
    // Replace any character that could be used for path injection or
    // that is forbidden on common file systems.
    let s: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect();

    // Strip leading dots and spaces: prevents hidden files on Unix and
    // confusing names like "  .bashrc" that could masquerade as dotfiles.
    let s = s.trim_start_matches(|c: char| c == '.' || c == ' ');

    // Limit to 200 bytes without splitting a UTF-8 sequence.
    let s = if s.len() > 200 {
        let mut cut = 200;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        &s[..cut]
    } else {
        s
    };

    // Guard against empty result or pure ".." after stripping.
    if s.is_empty() || s == ".." {
        "decrypted_file.bin".to_string()
    } else {
        s.to_string()
    }
}

/// Argon2id-vel deriválja a 32 byte-os wrap kulcsot a jelszóból + salt-ból.
/// A password paramétert a hívó felelőssége zeroize-olni a hívás után.
fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    // A paraméterek az identity.json-ból jönnek: a felső korlát megvédi a
    // programot egy meghamisított (extrém memóriaigényű) fájltól.
    if mem_kib > ARGON2_MAX_MEM_KIB || time_cost > ARGON2_MAX_TIME_COST || lanes > ARGON2_MAX_LANES
    {
        return Err(anyhow!(
            "Argon2 parameters in the identity file are out of the accepted range"
        ));
    }
    let params = Params::new(mem_kib, time_cost, lanes, Some(32))
        .map_err(|e| anyhow!("Invalid Argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|e| anyhow!("Argon2id derivation failed: {e}"))?;
    Ok(out)
}

/// Belső réteg: a nyers private key-t a jelszóból derivált Argon2id kulccsal
/// AES-256-GCM-SIV-vel wrappeljük, MIELŐTT az OS-szintű (DPAPI/keyring)
/// védelem ráépülne. Ez defense-in-depth: mindkét faktor kell a feloldáshoz.
/// Kimenet: nonce(12) ‖ ciphertext. A salt külön, a DeviceIdentity-ben tárolódik.
fn wrap_with_password(
    sk: &[u8],
    password: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<Vec<u8>> {
    let master_key = derive_master_key(password, salt, mem_kib, time_cost, lanes)?;
    let cipher = Aes256GcmSiv::new_from_slice(master_key.as_ref())
        .map_err(|e| anyhow!("password-wrap cipher init: {e:?}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, sk)
        .map_err(|e| anyhow!("password-wrap encrypt: {e:?}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// A wrap_with_password inverze: jelszó + tárolt salt/params alapján visszafejti
/// a belső AES-256-GCM-SIV réteget. Rossz jelszó esetén auth-tag hibával bukik,
/// nem csendes korrupcióval.
fn unwrap_with_password(
    blob: &[u8],
    password: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() <= NONCE_LEN {
        return Err(anyhow!(
            "Password-wrapped blob too short (len={})",
            blob.len()
        ));
    }
    let master_key = derive_master_key(password, salt, mem_kib, time_cost, lanes)?;
    let cipher = Aes256GcmSiv::new_from_slice(master_key.as_ref())
        .map_err(|e| anyhow!("password-unwrap cipher init: {e:?}"))?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let pt = cipher
        .decrypt(nonce, &blob[NONCE_LEN..])
        .map_err(|_| anyhow!("Wrong master password or corrupted identity"))?;
    Ok(Zeroizing::new(pt))
}

#[cfg(target_os = "windows")]
fn protect_private_key(sk: &[u8]) -> Result<Vec<u8>> {
    encrypt_data(sk, Scope::User, None).map_err(|e| anyhow!("DPAPI protect failed: {e}"))
}

#[cfg(target_os = "windows")]
fn unprotect_private_key(identity: &DeviceIdentity) -> Result<Zeroizing<Vec<u8>>> {
    if identity.protection_mode != PROTECTION_DPAPI {
        return Err(anyhow!(
            "Key was protected with '{}'; this Windows build only supports DPAPI. \
             Regenerate the device identity on this machine.",
            identity.protection_mode
        ));
    }
    let blob = B64.decode(&identity.protected_private_key_b64)?;
    Ok(Zeroizing::new(
        decrypt_data(&blob, Scope::User, None)
            .map_err(|e| anyhow!("DPAPI unprotect failed: {e}"))?,
    ))
}

/// Betölti a keyring védelmi kulcsot. Új kulcsot CSAK akkor hoz létre, ha a
/// bejegyzés bizonyítottan nem létezik (`NoEntry`) ÉS `create_if_missing` igaz.
/// Bármilyen más hiba (zárolt keyring, átmeneti hiba, hozzáférési probléma)
/// hibaként megy tovább — különben egy átmeneti hiba felülírná a meglévő
/// kulcsot, és a hozzá tartozó identitás végleg elveszne.
#[cfg(not(target_os = "windows"))]
fn load_keyring_master_key(create_if_missing: bool) -> Result<Zeroizing<Vec<u8>>> {
    let entry = KeyringEntry::new("2bsecret", "device-protection-key")
        .map_err(|e| anyhow!("Keyring access error: {e}"))?;

    match entry.get_password() {
        Ok(mut k) => {
            let decoded = B64.decode(&k);
            k.zeroize();
            let bytes = Zeroizing::new(decoded?);
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "Corrupt keyring entry: expected 32-byte key, got {}",
                    bytes.len()
                ));
            }
            Ok(bytes)
        }
        Err(keyring::Error::NoEntry) if create_if_missing => {
            let mut raw = vec![0u8; 32];
            OsRng.fill_bytes(&mut raw);
            let mut encoded = B64.encode(&raw);
            let res = entry.set_password(&encoded);
            encoded.zeroize();
            if let Err(e) = res {
                raw.zeroize();
                return Err(anyhow!("Failed to persist protection key in keyring: {e}"));
            }
            Ok(Zeroizing::new(raw))
        }
        Err(keyring::Error::NoEntry) => Err(anyhow!(
            "Keyring protection key not found — this identity was protected on a different \
             system/user profile, or the keyring entry was deleted"
        )),
        Err(e) => Err(anyhow!(
            "Keyring unavailable ({e}); not touching the stored protection key. \
             Unlock the keyring and try again"
        )),
    }
}

#[cfg(not(target_os = "windows"))]
fn get_or_create_keyring_master_key() -> Result<Zeroizing<Vec<u8>>> {
    load_keyring_master_key(true)
}

#[cfg(not(target_os = "windows"))]
fn protect_private_key(sk: &[u8]) -> Result<Vec<u8>> {
    let master = get_or_create_keyring_master_key()?;
    let cipher =
        Aes256GcmSiv::new_from_slice(&master[..]).map_err(|e| anyhow!("Cipher init: {e:?}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, sk)
        .map_err(|e| anyhow!("Key protection encrypt: {e:?}"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(not(target_os = "windows"))]
fn unprotect_private_key(identity: &DeviceIdentity) -> Result<Zeroizing<Vec<u8>>> {
    if identity.protection_mode != PROTECTION_KEYRING {
        return Err(anyhow!(
            "Key was protected with '{}'; this build expects '{}'. \
             Regenerate the device identity on this machine.",
            identity.protection_mode,
            PROTECTION_KEYRING
        ));
    }
    let blob = B64.decode(&identity.protected_private_key_b64)?;
    if blob.len() <= NONCE_LEN {
        return Err(anyhow!("Protection blob too short (len={})", blob.len()));
    }
    // Feloldásnál soha nem hozunk létre új kulcsot — ha hiányzik, az hiba.
    let master = load_keyring_master_key(false)?;
    let cipher =
        Aes256GcmSiv::new_from_slice(&master[..]).map_err(|e| anyhow!("Cipher init: {e:?}"))?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    Ok(Zeroizing::new(
        cipher.decrypt(nonce, &blob[NONCE_LEN..]).map_err(|_| {
            anyhow!("Key unprotect failed — keyring mismatch or identity corrupted")
        })?,
    ))
}

/// Új eszköz-identitás generálása. A `password` a master jelszó, amivel a
/// private key belső Argon2id+AES rétege védve lesz, MIELŐTT az OS-szintű
/// (DPAPI/keyring) védelem ráépülne — mindkettő kell a későbbi feloldáshoz.
/// A hívó felelőssége, hogy a password bufferét zeroize-olja a hívás után
/// (pl. egy `Zeroizing<String>`-ből olvasva).
pub fn generate_device_identity(device_dir: &Path, password: &[u8]) -> Result<DeviceIdentity> {
    if password.is_empty() {
        return Err(anyhow!("Master password cannot be empty"));
    }
    // Meglévő identitást soha nem írunk felül: egy új keypair minden, a réginek
    // titkosított fájlt véglegesen visszafejthetetlenné tenne.
    if device_identity_path(device_dir).exists() {
        return Err(anyhow!(
            "A device identity already exists ({}). Generating a new one would make every \
             file encrypted for the current identity permanently unreadable. If you really \
             want a new identity, back up and move identity.json away first.",
            device_identity_path(device_dir).display()
        ));
    }
    fs::create_dir_all(device_dir)?;

    // ── X25519 keypair ──
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    seed.zeroize();
    let public = PublicKey::from(&secret);

    // ── ML-KEM-768 keypair (post-quantum) ──
    // A "getrandom" feature-rel a generate() a rendszer CSPRNG-jét használja
    // belsőleg, nincs szükség kézzel átadott rng-re.
    let mlkem_dk = DecapsulationKey768::generate();
    let mlkem_ek = mlkem_dk.encapsulation_key().clone();
    let mlkem_seed_bytes = mlkem_dk.to_bytes(); // 64 byte seed
    let mlkem_pub_bytes = mlkem_ek.to_bytes(); // 1184 byte encapsulation key

    if mlkem_seed_bytes.as_slice().len() != ML_KEM_SEED_LEN {
        return Err(anyhow!(
            "Unexpected ML-KEM seed length: {}",
            mlkem_seed_bytes.as_slice().len()
        ));
    }

    // ── Hibrid aláíró kulcsok (Ed25519 + ML-DSA-65), 1. fázis ──
    let signing_seeds = generate_signing_seeds();
    let signing_public = signing_public_from_seeds(signing_seeds.as_slice())?;

    // Teljes secret: X25519 sk (32) ‖ ML-KEM-768 seed (64) ‖ Ed25519 seed (32)
    // ‖ ML-DSA seed (32) = 160 byte. Egyben megy át az Argon2id +
    // DPAPI/keyring kettős védelmen.
    let mut combined_sk = Zeroizing::new(Vec::with_capacity(FULL_SK_LEN));
    combined_sk.extend_from_slice(&secret.to_bytes());
    combined_sk.extend_from_slice(mlkem_seed_bytes.as_slice());
    combined_sk.extend_from_slice(signing_seeds.as_slice());

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    // Réteg 1 (belső): Argon2id(password) → AES-256-GCM-SIV wrap
    let password_wrapped = wrap_with_password(
        combined_sk.as_ref(),
        password,
        &salt,
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
    )?;

    // Réteg 2 (külső): DPAPI (Windows) vagy keyring-AES (más OS)
    let protected = protect_private_key(&password_wrapped)?;

    let fingerprint = fingerprint_from_public_key(public.as_bytes(), mlkem_pub_bytes.as_slice());

    let identity = DeviceIdentity {
        protected_private_key_b64: B64.encode(&protected),
        public_key_b64: B64.encode(public.as_bytes()),
        ml_kem_public_key_b64: B64.encode(mlkem_pub_bytes.as_slice()),
        fingerprint,
        protection_mode: default_protection_mode(),
        argon2_salt_b64: B64.encode(salt),
        argon2_mem_kib: ARGON2_MEM_KIB,
        argon2_time_cost: ARGON2_TIME_COST,
        argon2_lanes: ARGON2_LANES,
        ed25519_public_key_b64: B64.encode(&signing_public.ed25519),
        ml_dsa_public_key_b64: B64.encode(&signing_public.ml_dsa),
    };
    // Kör-ellenőrzés ELŐSZÖR, még a lemezre írás előtt: a most becsomagolt
    // kulcsnak a jelszóval vissza kell jönnie ugyanúgy. Így egy hibás csomagolás
    // nem hagy a lemezen olyan identitást, amelyből nincs visszaút.
    let roundtrip = unlock_identity_secret(&identity, password)
        .context("Self-check failed: the new identity could not be unlocked again")?;
    if roundtrip.as_slice() != combined_sk.as_slice() {
        return Err(anyhow!(
            "Self-check failed: the unlocked key material does not match the generated one"
        ));
    }

    // Atomikus, felülírás-mentes írás: egy megszakadt írás nem hagy félkész
    // identity.json-t, és versenyhelyzetben sem írható felül meglévő identitás.
    let identity_bytes = Zeroizing::new(serde_json::to_vec_pretty(&identity)?);
    write_file_atomic_new(&device_identity_path(device_dir), identity_bytes.as_slice())?;
    Ok(identity)
}

/// Az identitás kombinált titkának (X25519 sk ‖ ML-KEM seed) feloldása: először
/// az OS-réteg (DPAPI/keyring), majd az Argon2id-alapú jelszó-réteg. Rossz
/// jelszó vagy sérült identitás auth-tag hibával bukik, csendes korrupció nélkül.
fn unlock_identity_secret(
    identity: &DeviceIdentity,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let password_wrapped = unprotect_private_key(identity)?;

    let salt_vec = B64
        .decode(&identity.argon2_salt_b64)
        .map_err(|_| anyhow!("Corrupt identity: invalid Argon2 salt encoding"))?;
    if salt_vec.len() != ARGON2_SALT_LEN {
        return Err(anyhow!("Corrupt identity: unexpected Argon2 salt length"));
    }
    let mut salt = [0u8; ARGON2_SALT_LEN];
    salt.copy_from_slice(&salt_vec);

    unwrap_with_password(
        password_wrapped.as_ref(),
        password,
        &salt,
        identity.argon2_mem_kib,
        identity.argon2_time_cost,
        identity.argon2_lanes,
    )
}

/// Biztonságos belépési pont a GUI számára: csak akkor generál új identitást,
/// ha a jelszó és a megerősítő mező pontosan egyezik. Egy elgépelt jelszó
/// ellenőrzés nélkül véglegesen elzárná a felhasználót a saját kulcsától —
/// ez a réteg pont ezt előzi meg.
pub fn generate_device_identity_confirmed(
    device_dir: &Path,
    password: &[u8],
    confirm_password: &[u8],
) -> Result<DeviceIdentity> {
    if password != confirm_password {
        return Err(anyhow!("Password confirmation does not match"));
    }
    generate_device_identity(device_dir, password)
}

/// A master jelszó lecserélése anélkül, hogy új identitást (és ezzel új
/// fingerprint-et) kellene generálni. A tényleges X25519/ML-KEM kulcsanyag
/// nem változik — csak a köré épülő Argon2id+DPAPI/keyring védelem
/// wrappelődik újra az új jelszóval, friss salt-tal.
///
/// Ez azt jelenti, hogy a már kiosztott public key / fingerprint továbbra is
/// érvényes marad a partnereknél — nem kell újra exportálni és megosztani.
pub fn change_master_password(
    device_dir: &Path,
    old_password: &[u8],
    new_password: &[u8],
    new_password_confirm: &[u8],
) -> Result<()> {
    if new_password.is_empty() {
        return Err(anyhow!("New master password cannot be empty"));
    }
    if new_password != new_password_confirm {
        return Err(anyhow!("New password confirmation does not match"));
    }
    if old_password == new_password {
        return Err(anyhow!(
            "New password must differ from the current password"
        ));
    }

    let identity = load_identity(device_dir)?;

    // Mindkét réteg lehántása a régi jelszóval — ha rossz a jelszó, itt bukik
    // auth-tag hibával, nem csendes korrupcióval.
    let combined_sk = unlock_identity_secret(&identity, old_password)?;

    // Friss salt + a jelenleg ajánlott Argon2 paraméterek — ha a konstansok
    // időközben frissültek, a jelszó-rotáció egyúttal a védelmet is frissíti.
    let mut new_salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut new_salt);

    let new_password_wrapped = wrap_with_password(
        combined_sk.as_ref(),
        new_password,
        &new_salt,
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
    )?;
    let new_protected = protect_private_key(&new_password_wrapped)?;

    let updated_identity = DeviceIdentity {
        protected_private_key_b64: B64.encode(&new_protected),
        public_key_b64: identity.public_key_b64,
        ml_kem_public_key_b64: identity.ml_kem_public_key_b64,
        fingerprint: identity.fingerprint,
        protection_mode: identity.protection_mode,
        argon2_salt_b64: B64.encode(new_salt),
        argon2_mem_kib: ARGON2_MEM_KIB,
        argon2_time_cost: ARGON2_TIME_COST,
        argon2_lanes: ARGON2_LANES,
        ed25519_public_key_b64: identity.ed25519_public_key_b64,
        ml_dsa_public_key_b64: identity.ml_dsa_public_key_b64,
    };

    // Ellenőrzés a lecserélés ELŐTT: az új jelszóval a kulcsnak pontosan ugyanúgy
    // kell visszajönnie. Ha bármi hibás, a régi, működő identity.json érintetlen marad.
    let verify = unlock_identity_secret(&updated_identity, new_password)
        .context("Self-check failed: the re-wrapped identity could not be unlocked")?;
    if verify.as_slice() != combined_sk.as_slice() {
        return Err(anyhow!(
            "Self-check failed: re-wrapped key material does not match; the identity was left unchanged"
        ));
    }

    // Atomikus csere: egy megszakadt jelszócsere nem hagy félkész fájlt, a régi
    // vagy az új identitás mindig teljes egészében megvan.
    let updated_bytes = Zeroizing::new(serde_json::to_vec_pretty(&updated_identity)?);
    write_file_atomic(&device_identity_path(device_dir), updated_bytes.as_slice())?;
    Ok(())
}

pub fn export_public_key(device_dir: &Path) -> Result<PathBuf> {
    let id = load_identity(device_dir)?;
    // A fingerprint a kulcsokból számolódik (nem a tárolt mezőből), így régi
    // identitásnál is a friss, 128 bites értéket exportáljuk.
    let fingerprint = validated_fingerprint(&id.public_key_b64, &id.ml_kem_public_key_b64)?;
    let public = RecipientPublic {
        fingerprint: fingerprint.clone(),
        public_key_b64: id.public_key_b64.clone(),
        ml_kem_public_key_b64: id.ml_kem_public_key_b64.clone(),
    };
    let out = exported_public_key_path(device_dir, &fingerprint);
    write_file_atomic(&out, &serde_json::to_vec_pretty(&public)?)?;
    Ok(out)
}

pub fn import_recipient_public_key(device_dir: &Path) -> Result<RecipientPublic> {
    let path = FileDialog::new()
        .add_filter("JSON", &["json"])
        .pick_file()
        .ok_or_else(|| anyhow!("No file selected"))?;
    if fs::metadata(&path)?.len() > 64 * 1024 {
        return Err(anyhow!("Public key file is too large"));
    }
    let data = fs::read(&path)?;
    // Hosszak ellenőrzése + a fingerprint újraszámolása a kulcsokból; eltérésnél hiba.
    let rec = normalize_recipient(serde_json::from_slice::<RecipientPublic>(&data)?)?;
    write_file_atomic(
        &default_recipient_path(device_dir),
        &serde_json::to_vec_pretty(&rec)?,
    )?;
    Ok(rec)
}

pub fn load_default_recipient(device_dir: &Path) -> Result<RecipientPublic> {
    let data = fs::read(default_recipient_path(device_dir))?;
    normalize_recipient(serde_json::from_slice(&data)?)
}

pub fn load_identity(device_dir: &Path) -> Result<DeviceIdentity> {
    let data =
        fs::read(device_identity_path(device_dir)).context("Generate this device keypair first")?;
    Ok(serde_json::from_slice(&data)?)
}

// ───────────────────────── Jelszavas identitás-mentés ─────────────────────────
//
// Az identitás az operációs rendszer hitelesítő-tárához kötött (DPAPI
// felhasználói profil / keyring-bejegyzés), ezért újratelepített rendszeren
// vagy másik felhasználói fiókban az identity.json önmagában használhatatlan.
// Az egyetlen "kijárat" a privát kulcs számára az eszközről ez a KIFEJEZETTEN
// kért, külön jelszóval védett mentés: Argon2id + AES-256-GCM-SIV, az OS-réteg
// nélkül, hogy bárhol visszaállítható legyen. A mentés jelszava nem kell, hogy
// megegyezzen a mesterjelszóval (érdemes különbözőnek lennie).

const BACKUP_FORMAT: &str = "2bsecret-identity-backup";
// 1-es verzió: csak X25519 + ML-KEM titok (96 byte). 2-es verzió (1. fázis):
// ezen felül Ed25519 + ML-DSA aláíró magok (160 byte). A 2-es verzióban az
// aláíró publikus kulcsok is az AAD részei. Mindkettő visszaállítható.
const BACKUP_VERSION_V1: u32 = 1;
const BACKUP_VERSION: u32 = 2;
const BACKUP_AAD_PREFIX: &[u8] = b"2BSecret identity backup v1";
const BACKUP_AAD_PREFIX_V2: &[u8] = b"2BSecret identity backup v2";
const BACKUP_MAX_BYTES: u64 = 64 * 1024;

#[derive(Serialize, Deserialize)]
struct IdentityBackup {
    format: String,
    version: u32,
    public_key_b64: String,
    ml_kem_public_key_b64: String,
    // Csak tájékoztató; visszaállításkor a kulcsokból újraszámoljuk.
    fingerprint: String,
    argon2_salt_b64: String,
    argon2_mem_kib: u32,
    argon2_time_cost: u32,
    argon2_lanes: u32,
    nonce_b64: String,
    ciphertext_b64: String,
    // Csak a 2-es verzióban (1. fázis).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    ed25519_public_key_b64: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    ml_dsa_public_key_b64: String,
}

fn backup_aad(
    public_key: &[u8],
    ml_kem_public_key: &[u8],
    salt: &[u8],
    mem_kib: u32,
    time_cost: u32,
    lanes: u32,
    signing_public: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    // A publikus kulcsok és az Argon2 paraméterek is az AAD részei: a mentés
    // "külső" részének bármilyen módosítása a visszafejtésnél hibát ad.
    let mut aad = Vec::new();
    aad.extend_from_slice(if signing_public.is_some() {
        BACKUP_AAD_PREFIX_V2
    } else {
        BACKUP_AAD_PREFIX
    });
    for part in [public_key, ml_kem_public_key, salt] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part);
    }
    aad.extend_from_slice(&mem_kib.to_be_bytes());
    aad.extend_from_slice(&time_cost.to_be_bytes());
    aad.extend_from_slice(&lanes.to_be_bytes());
    if let Some((ed, dsa)) = signing_public {
        for part in [ed, dsa] {
            aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
            aad.extend_from_slice(part);
        }
    }
    aad
}

/// A kombinált titok (X25519 sk ‖ ML-KEM seed) ellenőrzése a publikus kulcsok
/// ellen: a titokból levezetett publikus kulcsoknak pontosan egyezniük kell a
/// tároltakkal. Így sem exportnál, sem visszaállításnál nem kerül elő "valami"
/// kulcsanyag, ami nem a megadott identitáshoz tartozik.
fn check_key_material(
    combined_sk: &[u8],
    public_key_b64: &str,
    ml_kem_public_key_b64: &str,
) -> Result<()> {
    if combined_sk.len() != COMBINED_SK_LEN && combined_sk.len() != FULL_SK_LEN {
        return Err(anyhow!(
            "Unexpected identity secret length: {} (expected {} or {})",
            combined_sk.len(),
            COMBINED_SK_LEN,
            FULL_SK_LEN
        ));
    }
    let stored_x = B64
        .decode(public_key_b64)
        .map_err(|_| anyhow!("Invalid X25519 public key encoding"))?;
    let stored_m = B64
        .decode(ml_kem_public_key_b64)
        .map_err(|_| anyhow!("Invalid ML-KEM public key encoding"))?;

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&combined_sk[..32]);
    let derived_x = PublicKey::from(&StaticSecret::from(sk_arr));
    sk_arr.zeroize();
    if derived_x.as_bytes().as_slice() != stored_x.as_slice() {
        return Err(anyhow!(
            "Key material does not match the X25519 public key of this identity"
        ));
    }

    let seed = ml_kem::Seed::try_from(&combined_sk[32..COMBINED_SK_LEN])
        .map_err(|_| anyhow!("Invalid ML-KEM seed length"))?;
    let dk = DecapsulationKey768::from_seed(seed);
    let ek = dk.encapsulation_key().clone();
    let derived_m = ek.to_bytes();
    if derived_m.as_slice() != stored_m.as_slice() {
        return Err(anyhow!(
            "Key material does not match the ML-KEM public key of this identity"
        ));
    }
    Ok(())
}

fn decode_identity_backup(
    path: &Path,
    backup_password: &[u8],
) -> Result<(IdentityBackup, Zeroizing<Vec<u8>>)> {
    let size = fs::metadata(path)
        .with_context(|| format!("Cannot read backup file: {}", path.display()))?
        .len();
    if size > BACKUP_MAX_BYTES {
        return Err(anyhow!(
            "Backup file is too large to be a valid identity backup"
        ));
    }
    let data = fs::read(path)?;
    let backup: IdentityBackup = serde_json::from_slice(&data)
        .map_err(|_| anyhow!("Not a valid 2BSecret identity backup file"))?;
    if backup.format != BACKUP_FORMAT
        || (backup.version != BACKUP_VERSION_V1 && backup.version != BACKUP_VERSION)
    {
        return Err(anyhow!(
            "Unsupported backup format or version (expected {BACKUP_FORMAT} v{BACKUP_VERSION_V1} or v{BACKUP_VERSION})"
        ));
    }
    let is_v2 = backup.version == BACKUP_VERSION;
    let (signing_ed, signing_dsa) = if is_v2 {
        let ed = B64
            .decode(&backup.ed25519_public_key_b64)
            .map_err(|_| anyhow!("Corrupt backup: invalid Ed25519 public key encoding"))?;
        let dsa = B64
            .decode(&backup.ml_dsa_public_key_b64)
            .map_err(|_| anyhow!("Corrupt backup: invalid ML-DSA public key encoding"))?;
        (ed, dsa)
    } else {
        (Vec::new(), Vec::new())
    };

    let salt = B64
        .decode(&backup.argon2_salt_b64)
        .map_err(|_| anyhow!("Corrupt backup: invalid salt encoding"))?;
    if salt.len() != ARGON2_SALT_LEN {
        return Err(anyhow!("Corrupt backup: unexpected salt length"));
    }
    let nonce = B64
        .decode(&backup.nonce_b64)
        .map_err(|_| anyhow!("Corrupt backup: invalid nonce encoding"))?;
    if nonce.len() != NONCE_LEN {
        return Err(anyhow!("Corrupt backup: unexpected nonce length"));
    }
    let ciphertext = B64
        .decode(&backup.ciphertext_b64)
        .map_err(|_| anyhow!("Corrupt backup: invalid ciphertext encoding"))?;
    let public_key = B64
        .decode(&backup.public_key_b64)
        .map_err(|_| anyhow!("Corrupt backup: invalid public key encoding"))?;
    let ml_kem_public_key = B64
        .decode(&backup.ml_kem_public_key_b64)
        .map_err(|_| anyhow!("Corrupt backup: invalid ML-KEM public key encoding"))?;

    // A paraméterek korlátját a derive_master_key ellenőrzi.
    let key = derive_master_key(
        backup_password,
        &salt,
        backup.argon2_mem_kib,
        backup.argon2_time_cost,
        backup.argon2_lanes,
    )?;
    let cipher = Aes256GcmSiv::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("backup cipher init: {e:?}"))?;
    let aad = backup_aad(
        &public_key,
        &ml_kem_public_key,
        &salt,
        backup.argon2_mem_kib,
        backup.argon2_time_cost,
        backup.argon2_lanes,
        if is_v2 {
            Some((signing_ed.as_slice(), signing_dsa.as_slice()))
        } else {
            None
        },
    );
    let combined_sk = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("Wrong backup password or corrupted backup file"))?,
    );
    check_key_material(
        &combined_sk,
        &backup.public_key_b64,
        &backup.ml_kem_public_key_b64,
    )?;
    // A verzió és a titok hossza együtt döntenek: egy v1-es mentés nem hordozhat
    // aláíró magokat, egy v2-es pedig kötelezően hordozza őket.
    if is_v2 {
        if combined_sk.len() != FULL_SK_LEN {
            return Err(anyhow!(
                "Corrupt backup: v2 backup without signing key material"
            ));
        }
        check_signing_material(
            &combined_sk,
            &backup.ed25519_public_key_b64,
            &backup.ml_dsa_public_key_b64,
        )?;
    } else if combined_sk.len() != COMBINED_SK_LEN {
        return Err(anyhow!(
            "Corrupt backup: unexpected key material length for a v1 backup"
        ));
    }
    Ok((backup, combined_sk))
}

/// Jelszóval védett mentést készít az eszköz identitásáról.
///
/// `master_password`: a jelenlegi mesterjelszó (az identitás feloldásához).
/// `backup_password`: a mentést védő, ÚJ jelszó. A hívó (GUI) felelőssége a
/// jelszóerősség ellenőrzése ([`check_password_strength`]).
///
/// A mentés kiírása után visszaolvassa és visszafejti, és csak ezután tér
/// vissza sikerrel: egy olyan mentés, ami nem nyitható meg, rosszabb a semminél.
pub fn export_identity_backup(
    device_dir: &Path,
    master_password: &[u8],
    backup_password: &[u8],
    out_path: &Path,
) -> Result<()> {
    if backup_password.is_empty() {
        return Err(anyhow!("Backup password cannot be empty"));
    }
    let identity = load_identity(device_dir)?;
    let combined_sk = unlock_identity_secret(&identity, master_password)?;
    check_key_material(
        &combined_sk,
        &identity.public_key_b64,
        &identity.ml_kem_public_key_b64,
    )?;
    let fingerprint =
        validated_fingerprint(&identity.public_key_b64, &identity.ml_kem_public_key_b64)?;

    let public_key = B64.decode(&identity.public_key_b64)?;
    let ml_kem_public_key = B64.decode(&identity.ml_kem_public_key_b64)?;

    // Ha az identitás már hordoz aláíró kulcsokat (160 byte), a mentés 2-es
    // verziójú és azokat is tartalmazza; különben marad az 1-es formátum.
    let has_signing = combined_sk.len() == FULL_SK_LEN;
    let (signing_ed, signing_dsa) = if has_signing {
        check_signing_material(
            &combined_sk,
            &identity.ed25519_public_key_b64,
            &identity.ml_dsa_public_key_b64,
        )?;
        (
            B64.decode(&identity.ed25519_public_key_b64)?,
            B64.decode(&identity.ml_dsa_public_key_b64)?,
        )
    } else {
        (Vec::new(), Vec::new())
    };

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_master_key(
        backup_password,
        &salt,
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
    )?;
    let cipher = Aes256GcmSiv::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("backup cipher init: {e:?}"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let aad = backup_aad(
        &public_key,
        &ml_kem_public_key,
        &salt,
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
        if has_signing {
            Some((signing_ed.as_slice(), signing_dsa.as_slice()))
        } else {
            None
        },
    );
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: combined_sk.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("backup encrypt failed: {e:?}"))?;

    let backup = IdentityBackup {
        format: BACKUP_FORMAT.to_string(),
        version: if has_signing {
            BACKUP_VERSION
        } else {
            BACKUP_VERSION_V1
        },
        public_key_b64: identity.public_key_b64.clone(),
        ml_kem_public_key_b64: identity.ml_kem_public_key_b64.clone(),
        fingerprint,
        argon2_salt_b64: B64.encode(salt),
        argon2_mem_kib: ARGON2_MEM_KIB,
        argon2_time_cost: ARGON2_TIME_COST,
        argon2_lanes: ARGON2_LANES,
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(&ciphertext),
        ed25519_public_key_b64: if has_signing {
            identity.ed25519_public_key_b64.clone()
        } else {
            String::new()
        },
        ml_dsa_public_key_b64: if has_signing {
            identity.ml_dsa_public_key_b64.clone()
        } else {
            String::new()
        },
    };
    write_file_atomic(out_path, &serde_json::to_vec_pretty(&backup)?)?;

    // Kör-ellenőrzés: a kiírt mentésnek a jelszóval ugyanazt a kulcsot kell adnia.
    let (_, restored) = decode_identity_backup(out_path, backup_password)
        .context("Self-check failed: the written backup could not be opened again")?;
    if restored.as_slice() != combined_sk.as_slice() {
        return Err(anyhow!(
            "Self-check failed: the written backup does not match the identity"
        ));
    }
    Ok(())
}

/// Identitás visszaállítása jelszavas mentésből (pl. újratelepített rendszeren).
///
/// A mentésből kinyert kulcsanyag az ÚJ mesterjelszóval és ennek az eszköznek az
/// OS-rétegével (DPAPI/keyring) kerül védelembe. Meglévő identitást soha nem ír
/// felül. A hívó (GUI) felelőssége az új mesterjelszó erősségének ellenőrzése.
pub fn restore_identity_from_backup(
    device_dir: &Path,
    backup_path: &Path,
    backup_password: &[u8],
    new_master_password: &[u8],
) -> Result<DeviceIdentity> {
    if new_master_password.is_empty() {
        return Err(anyhow!("Master password cannot be empty"));
    }
    if device_identity_path(device_dir).exists() {
        return Err(anyhow!(
            "A device identity already exists ({}). Restoring a backup would replace it. \
             Move identity.json away first if you really want to restore.",
            device_identity_path(device_dir).display()
        ));
    }

    let (backup, combined_sk) = decode_identity_backup(backup_path, backup_password)?;
    let fingerprint = validated_fingerprint(&backup.public_key_b64, &backup.ml_kem_public_key_b64)?;
    fs::create_dir_all(device_dir)?;

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let password_wrapped = wrap_with_password(
        combined_sk.as_ref(),
        new_master_password,
        &salt,
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
    )?;
    let protected = protect_private_key(&password_wrapped)?;

    let identity = DeviceIdentity {
        protected_private_key_b64: B64.encode(&protected),
        public_key_b64: backup.public_key_b64.clone(),
        ml_kem_public_key_b64: backup.ml_kem_public_key_b64.clone(),
        fingerprint,
        protection_mode: default_protection_mode(),
        argon2_salt_b64: B64.encode(salt),
        argon2_mem_kib: ARGON2_MEM_KIB,
        argon2_time_cost: ARGON2_TIME_COST,
        argon2_lanes: ARGON2_LANES,
        ed25519_public_key_b64: backup.ed25519_public_key_b64.clone(),
        ml_dsa_public_key_b64: backup.ml_dsa_public_key_b64.clone(),
    };

    let roundtrip = unlock_identity_secret(&identity, new_master_password)
        .context("Self-check failed: the restored identity could not be unlocked")?;
    if roundtrip.as_slice() != combined_sk.as_slice() {
        return Err(anyhow!(
            "Self-check failed: the restored key material does not match the backup"
        ));
    }

    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&identity)?);
    write_file_atomic_new(&device_identity_path(device_dir), bytes.as_slice())?;
    Ok(identity)
}

fn derive_safe_output_path(input: &Path, prefix: &str, original_name: &str, ext: &str) -> PathBuf {
    // original_name is already sanitized (for decrypt) or a trusted local filename (for encrypt)
    let safe_name = Path::new(original_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file.bin");
    let mut out = input.with_file_name(format!("{}{}{}", prefix, safe_name, ext));
    let mut i = 1;
    while out.exists() {
        out = input.with_file_name(format!("{}{}_{}{}", prefix, safe_name, i, ext));
        i += 1;
    }
    out
}

/// A fájl tartalmát két körben felülírja (véletlen bájtokkal, majd nullákkal),
/// átnevezi egy véletlen névre — hogy a fájlnév se maradjon a könyvtár
/// metaadataiban —, majd törli.
///
/// FONTOS KORLÁT, amit érdemes tudni: SSD-n a wear-leveling és a
/// copy-on-write fájlrendszerek (pl. Windows ReFS) miatt a logikai felülírás
/// nem feltétlenül ugyanazokat a fizikai blokkokat éri el, mint amiken az
/// eredeti adat volt. Ez a művelet a szokásos "undelete" eszközök (fájlrendszer
/// szintű helyreállítás) ellen nyújt valódi védelmet, de nem garantálja a
/// fizikai adathordozó-szintű helyreállítás lehetetlenségét SSD-n.
/// HDD-n és egyszerűbb fájlrendszereken ez a klasszikus, hatékony módszer.
pub fn secure_delete_file(path: &Path) -> Result<()> {
    let len = fs::metadata(path)
        .with_context(|| format!("Cannot stat file for secure delete: {}", path.display()))?
        .len();

    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("Cannot open file for secure delete: {}", path.display()))?;

        let buf_len = (CHUNK_SIZE as u64).min(len.max(1)) as usize;
        let mut buf = vec![0u8; buf_len];

        // 1. kör: kriptográfiailag véletlen bájtok
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            OsRng.fill_bytes(&mut buf[..n]);
            file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;

        // 2. kör: nullák (extra biztonsági margó, NIST SP 800-88 ajánlás
        // szerint már az 1. kör is elegendő lenne modern lemezeken)
        // FIGYELEM: itt NEM szabad `buf.zeroize()`-t hívni. A `Vec<u8>`
        // zeroize-olása a tartalom nullázása UTÁN a vektort ki is üríti (a hossza
        // 0 lesz), így az alábbi ciklus `n = min(remaining, buf.len())` értéke
        // 0 maradna, `remaining` soha nem csökkenne, és a program végtelen
        // ciklusba esne. A `fill(0)` a hosszt megtartja.
        buf.fill(0);
        file.seek(SeekFrom::Start(0))?;
        let mut remaining = len;
        while remaining > 0 {
            let n = remaining.min(buf.len() as u64) as usize;
            file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        file.sync_all()?;
    } // fájl lezárva itt

    // Szándékosan NINCS átnevezés törlés előtt. Korábban volt egy lépés, ami
    // véletlen névre nevezte át a fájlt (hogy a könyvtárbejegyzés se árulkodjon
    // az eredeti névről), de ez a gyors felülírás+átnevezés+törlés szekvencia
    // pontosan az a minta, amit a viselkedés-alapú AV/EDR motorok (pl. Norton
    // SONAR / Ransomware Protection, Windows Defender Controlled Folder
    // Access) ransomware-gyanús tevékenységként azonosítanak, és emiatt
    // percekig blokkolják vagy vizsgálat alatt tartják a műveletet — ez
    // gyakorlatban rosszabb UX-et adott, mint amennyi biztonsági hasznot az
    // átnevezés hozott (a fájlnév amúgy is megmaradhat a fájlrendszer
    // naplójában / journal-jában, tehát ez a védelem eleve korlátozott volt).
    // A lényegi védelem — a TARTALOM felülírása törlés előtt — változatlanul
    // megvan a fenti két körben.
    fs::remove_file(path).with_context(|| {
        format!(
            "Failed to remove file during secure delete: {}",
            path.display()
        )
    })?;

    Ok(())
}

/// A frissen írt titkosított fájl újraolvasása és ellenőrzése: a fejléc bájtra
/// egyezik az elvárttal, a chunk-ok sorrendje és nonce-ai helyesek, mindegyik
/// chunk a fájlkulccsal visszafejthető, a darabszám, a teljes hossz és a nyílt
/// tartalom SHA-256 hash-e pedig megegyezik az eredeti beolvasáskor mértekkel.
fn verify_encrypted_output(
    path: &Path,
    content_cipher: &Aes256GcmSiv,
    expected_header_json: &[u8],
    expected_chunks: u64,
    expected_plain_len: u64,
    expected_sha256: &[u8],
) -> Result<()> {
    let mut f = File::open(path).context("Cannot reopen the encrypted file")?;

    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!("Encrypted file has a wrong magic value"));
    }
    let mut version = [0u8; 1];
    f.read_exact(&mut version)?;
    if version[0] != VERSION {
        return Err(anyhow!("Encrypted file has a wrong version byte"));
    }
    let mut header_len_buf = [0u8; 4];
    f.read_exact(&mut header_len_buf)?;
    let header_len = u32::from_be_bytes(header_len_buf) as usize;
    if header_len != expected_header_json.len() {
        return Err(anyhow!("Encrypted file has a wrong header length"));
    }
    let mut header_on_disk = vec![0u8; header_len];
    f.read_exact(&mut header_on_disk)?;
    if header_on_disk != expected_header_json {
        return Err(anyhow!(
            "Encrypted file header differs from what was written"
        ));
    }

    let mut hasher = Sha256::new();
    let mut total_plain: u64 = 0;
    let mut chunk_index: u64 = 0;
    loop {
        let mut plain_len_buf = [0u8; 4];
        match f.read_exact(&mut plain_len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let plain_len = u32::from_be_bytes(plain_len_buf) as usize;

        let mut cipher_len_buf = [0u8; 4];
        f.read_exact(&mut cipher_len_buf)?;
        let cipher_len = u32::from_be_bytes(cipher_len_buf) as usize;
        if cipher_len > CHUNK_SIZE + 32 {
            return Err(anyhow!("Encrypted file has an oversized chunk"));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        f.read_exact(&mut nonce_bytes)?;
        if nonce_bytes != nonce_from_index(chunk_index) {
            return Err(anyhow!("Encrypted file has a wrong chunk nonce"));
        }

        let mut ciphertext = vec![0u8; cipher_len];
        f.read_exact(&mut ciphertext)?;
        let mut plaintext = content_cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
            .map_err(|_| anyhow!("A chunk of the encrypted file does not decrypt"))?;
        if plaintext.len() != plain_len {
            plaintext.zeroize();
            return Err(anyhow!("Encrypted file has a chunk length mismatch"));
        }
        hasher.update(&plaintext);
        total_plain += plain_len as u64;
        plaintext.zeroize();
        ciphertext.zeroize();
        chunk_index += 1;
    }

    if chunk_index != expected_chunks {
        return Err(anyhow!(
            "Encrypted file has {} chunks, expected {}",
            chunk_index,
            expected_chunks
        ));
    }
    if total_plain != expected_plain_len {
        return Err(anyhow!("Encrypted file has a wrong total length"));
    }
    if hasher.finalize().as_slice() != expected_sha256 {
        return Err(anyhow!(
            "Encrypted file content does not match the original"
        ));
    }
    Ok(())
}

pub fn encrypt_for_recipient(
    input: &Path,
    recipient: &RecipientPublic,
    delete_original: bool,
) -> Result<PathBuf> {
    // A fájlba kerülő fingerprint mindig a kulcsokból számolt érték, nem a
    // megadott struktúra mezője.
    let recipient = normalize_recipient(recipient.clone())?;
    let recipient = &recipient;

    // ── X25519 fél ──
    let recipient_pk_b = B64.decode(&recipient.public_key_b64)?;
    if recipient_pk_b.len() != 32 {
        return Err(anyhow!("Invalid recipient public key length"));
    }
    let mut recipient_pk_arr = [0u8; 32];
    recipient_pk_arr.copy_from_slice(&recipient_pk_b);
    let recipient_pk = PublicKey::from(recipient_pk_arr);

    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let x25519_shared = eph_secret.diffie_hellman(&recipient_pk);

    // ── ML-KEM-768 fél (post-quantum) ──
    let mlkem_pub_bytes = B64
        .decode(&recipient.ml_kem_public_key_b64)
        .map_err(|_| anyhow!("Invalid ML-KEM public key encoding"))?;
    let ek_array = ml_kem::Key::<EncapsulationKey768>::try_from(mlkem_pub_bytes.as_slice())
        .map_err(|_| anyhow!("Invalid ML-KEM public key length"))?;
    let ek =
        EncapsulationKey768::new(&ek_array).map_err(|_| anyhow!("Invalid ML-KEM public key"))?;
    let (mlkem_ct, mlkem_shared) = ek.encapsulate();

    // ── Kombinált titok + kontextus-kötött HKDF derivált header kulcs ──
    let mut combined_secret = Zeroizing::new(Vec::with_capacity(64));
    combined_secret.extend_from_slice(x25519_shared.as_bytes());
    combined_secret.extend_from_slice(mlkem_shared.as_slice());

    let mut hkdf_salt = Vec::with_capacity(32 + mlkem_ct.as_slice().len());
    hkdf_salt.extend_from_slice(eph_public.as_bytes());
    hkdf_salt.extend_from_slice(mlkem_ct.as_slice());

    let header_key = derive_header_key_v5(combined_secret.as_ref(), &hkdf_salt);

    // ── Fájl-tartalom kulcs ──
    let mut file_key_raw = [0u8; 32];
    OsRng.fill_bytes(&mut file_key_raw);
    let file_key = Secret::new(file_key_raw);
    file_key_raw.zeroize();

    let original_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();

    let file_size = fs::metadata(input)?.len();
    let chunk_count: u64 = if file_size == 0 {
        0
    } else {
        (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
    };

    // ── Sealed metadata blokk: fingerprint, filename, chunk_count, file_key ──
    // mind egy megfigyelő elől rejtve, csak a hibrid kulcscsere birtokában
    // fejthető vissza.
    let sealed_meta = SealedMeta {
        recipient_fingerprint: recipient.fingerprint.clone(),
        original_name: original_name.clone(),
        chunk_count: Some(chunk_count),
        file_key_b64: B64.encode(file_key.expose_secret()),
    };
    let sealed_json = Zeroizing::new(serde_json::to_vec(&sealed_meta)?);

    let sealed_cipher = Aes256GcmSiv::new_from_slice(header_key.as_ref())
        .map_err(|e| anyhow!("sealed cipher init: {e:?}"))?;
    let mut sealed_nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut sealed_nonce_bytes);
    let sealed_nonce = Nonce::from_slice(&sealed_nonce_bytes);
    let sealed_payload = Payload {
        msg: sealed_json.as_ref(),
        aad: &hkdf_salt,
    };
    let sealed_blob = sealed_cipher
        .encrypt(sealed_nonce, sealed_payload)
        .map_err(|e| anyhow!("sealed encrypt fail: {e:?}"))?;

    let content_cipher = Aes256GcmSiv::new_from_slice(file_key.expose_secret())
        .map_err(|e| anyhow!("cipher init: {e:?}"))?;

    let header = Header {
        magic_b64: B64.encode(MAGIC),
        version: VERSION,
        algorithm: "aes-256-gcm-siv".to_string(),
        key_wrap: "x25519+mlkem768-hybrid-hkdf-sha256-sealed".to_string(),
        chunk_size: CHUNK_SIZE,
        recipient_fingerprint: None,
        wrap_nonce_b64: None,
        wrapped_file_key_b64: None,
        original_name: None,
        chunk_count: None,
        ephemeral_public_key_b64: Some(B64.encode(eph_public.as_bytes())),
        ml_kem_ciphertext_b64: Some(B64.encode(mlkem_ct.as_slice())),
        sealed_nonce_b64: Some(B64.encode(sealed_nonce_bytes)),
        sealed_blob_b64: Some(B64.encode(&sealed_blob)),
    };

    let out_path = derive_safe_output_path(input, "", &original_name, ".2brecip");
    let mut guard = FileCleanupGuard {
        path: out_path.clone(),
        success: false,
    };

    let mut fin = File::open(input)?;
    let mut fout = File::create(&out_path)?;

    let header_json = serde_json::to_vec(&header)?;

    fout.write_all(MAGIC)?;
    fout.write_all(&[VERSION])?;
    fout.write_all(&(header_json.len() as u32).to_be_bytes())?;
    fout.write_all(&header_json)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;
    // A beolvasott nyílt tartalom hash-e és hossza: a titkosított kimenet
    // utólagos ellenőrzéséhez (az eredeti törlése előtt).
    let mut plain_hasher = Sha256::new();
    let mut plain_total: u64 = 0;
    loop {
        let n = fin.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let plaintext = &buffer[..n];
        plain_hasher.update(plaintext);
        plain_total += n as u64;
        let nonce_bytes = nonce_from_index(chunk_index);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = content_cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("encrypt failed: {e:?}"))?;
        fout.write_all(&(n as u32).to_be_bytes())?;
        fout.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        fout.write_all(&nonce_bytes)?;
        fout.write_all(&ciphertext)?;
        chunk_index += 1;
    }

    buffer.zeroize();

    // A titkosított kimenet LEMEZRE kényszerítése (fsync), mielőtt bármi mást
    // csinálnánk: enélkül a kimenet még az operációs rendszer gyorsítótárában
    // lehet, és egy áramkimaradás után az eredeti már felül van írva, a
    // titkosított fájl pedig nincs a lemezen.
    fout.flush()?;
    fout.sync_all()?;
    drop(fout);
    sync_parent_dir(&out_path);

    // A bemeneti fájl olvasási handle-jét explicit lezárjuk itt, mielőtt bármi
    // más történne — a secure_delete_file ugyanazt a fájlt nyitja meg írásra,
    // átnevezi és törli. Ha `fin` még nyitva maradna eddig a pontig, Windows-on
    // ez rename/delete közben megakadhat (pl. a Defender valós idejű vizsgálata
    // pont az ilyen "még nyitott handle + gyors rename/delete" mintát ellenőrzi
    // hosszasan). A fout-ot (a kimeneti ciphertext-et) ez nem érinti, az külön
    // fájl.
    drop(fin);

    if chunk_index != chunk_count {
        return Err(anyhow!(
            "Chunk count mismatch during encryption (expected {}, wrote {}): source file may have changed",
            chunk_count, chunk_index
        ));
    }

    // Az eredeti törlése visszafordíthatatlan, ezért előtte a lemezre írt
    // titkosított fájlt ÚJRAOLVASSUK és a fájlkulccsal visszafejtjük: a fejlécnek,
    // a darabszámnak, a hossznak és a tartalom SHA-256 hash-ének pontosan
    // egyeznie kell azzal, amit az imént titkosítottunk. Bármilyen eltérésnél
    // hiba lesz, a hibás kimenet törlődik (a guard.success még false), és az
    // eredeti fájl érintetlen marad.
    if delete_original {
        let digest = plain_hasher.finalize();
        verify_encrypted_output(
            &out_path,
            &content_cipher,
            &header_json,
            chunk_count,
            plain_total,
            digest.as_slice(),
        )
        .context("Verification of the encrypted file failed; the original file was NOT deleted")?;
    }

    guard.success = true;

    // Csak akkor töröljük az eredetit, ha a titkosított kimenet ellenőrizhetően
    // teljes és visszafejthető (lásd fent). Ha a törlés maga hibázik, a
    // titkosított fájl már véglegesen megvan és helyes (a guard.success fentebb
    // már true, tehát a FileCleanupGuard nem törli vissza) — csak a hibát adjuk
    // tovább, hogy a hívó tudja: az eredeti fájl NEM lett törölve.
    if delete_original {
        secure_delete_file(input).with_context(|| {
            "Encryption succeeded, but securely deleting the original file failed"
        })?;
    }

    Ok(out_path)
}

pub fn decrypt_on_this_device(input: &Path, device_dir: &Path, password: &[u8]) -> Result<PathBuf> {
    // A v6 (többcímzetteses, aláírt) fájlokat a sharing modul fejti vissza. Itt
    // a biztonságos alapértelmezés (csak ismert névjegytől fogad el fájlt) él;
    // az ismeretlen feladó kezelését a hívó a `decrypt_v6` közvetlen hívásával
    // tudja másképp megoldani.
    if peek_file_version(input)? == 6 {
        return decrypt_v6(input, device_dir, password, SenderPolicy::ContactsOnly)
            .map(|outcome| outcome.path);
    }

    let identity = load_identity(device_dir)?;

    // Mindkét védelmi réteg lehántása: DPAPI/keyring, majd Argon2id(jelszó) a
    // tárolt salt/paraméterekkel → nyers kombinált secret.
    let combined_sk_raw = unlock_identity_secret(&identity, password)?;

    // A régi (v4-előtti, csak X25519) identity-k 32 byte-osak, az újak
    // (v5, kombinált X25519+ML-KEM) 96 byte-osak. Mindkettőt elfogadjuk,
    // hogy régi identity-vel is fejthető legyen v3/v4 fájl.
    let x25519_sk_bytes: &[u8] = match combined_sk_raw.len() {
        32 => &combined_sk_raw[..32],
        COMBINED_SK_LEN | FULL_SK_LEN => &combined_sk_raw[..32],
        other => return Err(anyhow!("Invalid identity secret length: {}", other)),
    };
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(x25519_sk_bytes);
    let secret = StaticSecret::from(sk_arr);
    sk_arr.zeroize();

    let pk_b = B64.decode(&identity.public_key_b64)?;
    if pk_b.len() != 32 {
        return Err(anyhow!("Invalid local public key length"));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_b);
    let public = PublicKey::from(pk_arr);

    let mlkem_pub_bytes = B64
        .decode(&identity.ml_kem_public_key_b64)
        .map_err(|_| anyhow!("Invalid ML-KEM public key encoding"))?;

    let mut fin = File::open(input)?;
    let mut magic = [0u8; 8];
    fin.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!("Not a supported file"));
    }

    let mut version_buf = [0u8; 1];
    fin.read_exact(&mut version_buf)?;
    let file_version = version_buf[0];
    if !(3..=5).contains(&file_version) {
        return Err(anyhow!(
            "Unsupported file version {}; only v3, v4 and v5 are supported",
            file_version
        ));
    }

    let mut header_len_buf = [0u8; 4];
    fin.read_exact(&mut header_len_buf)?;
    let h_len = u32::from_be_bytes(header_len_buf) as usize;
    if h_len > 1024 * 1024 {
        return Err(anyhow!("Header too large"));
    }

    let mut header_json = vec![0u8; h_len];
    fin.read_exact(&mut header_json)?;
    let header: Header = serde_json::from_slice(&header_json)?;

    if header.chunk_size != CHUNK_SIZE {
        return Err(anyhow!(
            "Unsupported chunk size in file (expected {}, got {})",
            CHUNK_SIZE,
            header.chunk_size
        ));
    }

    // file_key, original_name, chunk_count — verzió szerint más forrásból jönnek.
    let file_key_raw: Zeroizing<Vec<u8>>;
    let original_name: String;
    let chunk_count: Option<u64>;

    if file_version == 5 {
        // ── v5: hibrid X25519 + ML-KEM-768 kulcscsere, sealed header ──
        if combined_sk_raw.len() < COMBINED_SK_LEN {
            return Err(anyhow!(
                "This identity has no ML-KEM key material; cannot decrypt a v5 file. \
                 Regenerate the device identity to add post-quantum support."
            ));
        }
        let mlkem_seed_bytes = &combined_sk_raw[32..COMBINED_SK_LEN];

        let eph_b64 = header
            .ephemeral_public_key_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt v5 header: missing ephemeral public key"))?;
        let eph_b = B64.decode(eph_b64)?;
        if eph_b.len() != 32 {
            return Err(anyhow!("Invalid ephemeral public key length"));
        }
        let mut eph_arr = [0u8; 32];
        eph_arr.copy_from_slice(&eph_b);
        let x25519_shared = secret.diffie_hellman(&PublicKey::from(eph_arr));

        let mlkem_ct_b64 = header
            .ml_kem_ciphertext_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt v5 header: missing ML-KEM ciphertext"))?;
        let mlkem_ct_bytes = B64
            .decode(mlkem_ct_b64)
            .map_err(|_| anyhow!("Invalid ML-KEM ciphertext encoding"))?;

        let seed_array = ml_kem::Seed::try_from(mlkem_seed_bytes)
            .map_err(|_| anyhow!("Invalid ML-KEM seed length in identity"))?;
        let dk = DecapsulationKey768::from_seed(seed_array);
        let ct_array = ml_kem::Ciphertext::<MlKem768>::try_from(mlkem_ct_bytes.as_slice())
            .map_err(|_| anyhow!("Invalid ML-KEM ciphertext length"))?;
        let mlkem_shared = dk.decapsulate(&ct_array);

        let mut combined_secret = Zeroizing::new(Vec::with_capacity(64));
        combined_secret.extend_from_slice(x25519_shared.as_bytes());
        combined_secret.extend_from_slice(mlkem_shared.as_slice());

        let mut hkdf_salt = Vec::with_capacity(32 + mlkem_ct_bytes.len());
        hkdf_salt.extend_from_slice(&eph_b);
        hkdf_salt.extend_from_slice(&mlkem_ct_bytes);

        let header_key = derive_header_key_v5(combined_secret.as_ref(), &hkdf_salt);

        let sealed_nonce_b64 = header
            .sealed_nonce_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt v5 header: missing sealed nonce"))?;
        let sealed_nonce_bytes = B64.decode(sealed_nonce_b64)?;
        if sealed_nonce_bytes.len() != NONCE_LEN {
            return Err(anyhow!("Invalid sealed nonce length"));
        }
        let sealed_blob_b64 = header
            .sealed_blob_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt v5 header: missing sealed blob"))?;
        let sealed_blob = B64.decode(sealed_blob_b64)?;

        let sealed_cipher = Aes256GcmSiv::new_from_slice(header_key.as_ref())
            .map_err(|e| anyhow!("sealed cipher init failed: {e:?}"))?;
        let sealed_nonce = Nonce::from_slice(&sealed_nonce_bytes);
        let sealed_payload = Payload {
            msg: sealed_blob.as_slice(),
            aad: &hkdf_salt,
        };
        let sealed_pt = Zeroizing::new(
            sealed_cipher
                .decrypt(sealed_nonce, sealed_payload)
                .map_err(|_| anyhow!("Decryption failed: tampered header or wrong recipient"))?,
        );
        let sealed_meta: SealedMeta = serde_json::from_slice(&sealed_pt)?;

        // Új (128 bites) és régi (64 bites) fingerprintet is elfogadunk, hogy a
        // korábban titkosított v5 fájlok továbbra is megnyíljanak.
        if !fingerprint_matches(
            &sealed_meta.recipient_fingerprint,
            public.as_bytes(),
            &mlkem_pub_bytes,
        ) {
            return Err(anyhow!("Wrong recipient"));
        }

        file_key_raw = Zeroizing::new(
            B64.decode(&sealed_meta.file_key_b64)
                .map_err(|_| anyhow!("Corrupt sealed metadata: invalid file key encoding"))?,
        );
        original_name = sealed_meta.original_name;
        chunk_count = sealed_meta.chunk_count;
    } else {
        // ── v3/v4: legacy X25519-only kulcscsere, plaintext header ──
        let header_fpr = header
            .recipient_fingerprint
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt v3/v4 header: missing recipient fingerprint"))?;

        // A v3/v4 fingerprint csak az X25519 kulcsból számolódott (a régi
        // fingerprint_from_public_key egy paraméteres volt) — itt csak az
        // X25519 pubkey-t hash-eljük ugyanúgy, hogy a régi fájlok egyezzenek.
        let legacy_fpr = {
            let digest = Sha256::digest(public.as_bytes());
            hex_prefix(&digest, 16)
        };
        if &legacy_fpr != header_fpr {
            return Err(anyhow!("Wrong recipient"));
        }

        let eph_b64 = header
            .ephemeral_public_key_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt header: missing ephemeral public key"))?;
        let eph_b = B64.decode(eph_b64)?;
        if eph_b.len() != 32 {
            return Err(anyhow!("Invalid ephemeral public key length"));
        }
        let mut eph_arr = [0u8; 32];
        eph_arr.copy_from_slice(&eph_b);
        let shared = secret.diffie_hellman(&PublicKey::from(eph_arr));

        let mut wrap_key_bytes = derive_wrap_key_v3(shared.as_bytes(), eph_arr.as_ref());
        let wrap_cipher = Aes256GcmSiv::new_from_slice(&wrap_key_bytes)
            .map_err(|e| anyhow!("wrap cipher init failed: {e:?}"))?;
        wrap_key_bytes.zeroize();

        let wrap_n_b64 = header
            .wrap_nonce_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt header: missing wrap nonce"))?;
        let wrap_n_b = B64.decode(wrap_n_b64)?;
        if wrap_n_b.len() != NONCE_LEN {
            return Err(anyhow!("Invalid wrap nonce length"));
        }
        let wrap_nonce = Nonce::from_slice(&wrap_n_b);
        let wrapped_file_key_b64 = header
            .wrapped_file_key_b64
            .as_ref()
            .ok_or_else(|| anyhow!("Corrupt header: missing wrapped file key"))?;
        let wrapped_file_key = B64.decode(wrapped_file_key_b64)?;

        let orig_name = header
            .original_name
            .clone()
            .ok_or_else(|| anyhow!("Corrupt header: missing original name"))?;

        let meta_aad = if file_version == 4 {
            format!(
                "2BRECIP_v4|{}|{}|{}|{}|{}",
                header_fpr,
                eph_b64,
                orig_name,
                header.chunk_size,
                header.chunk_count.unwrap_or(0)
            )
        } else {
            match header.chunk_count {
                Some(c) => format!(
                    "2BRECIP_v3|{}|{}|{}|{}",
                    header_fpr, orig_name, header.chunk_size, c
                ),
                None => format!("2BRECIP_v3|{}|{}", header_fpr, orig_name),
            }
        };

        let payload = Payload {
            msg: wrapped_file_key.as_slice(),
            aad: meta_aad.as_bytes(),
        };

        file_key_raw = Zeroizing::new(
            wrap_cipher
                .decrypt(wrap_nonce, payload)
                .map_err(|_| anyhow!("Decryption failed: tampered header or wrong key"))?,
        );
        original_name = orig_name;
        chunk_count = header.chunk_count;
    }

    let content_cipher = Aes256GcmSiv::new_from_slice(&file_key_raw)
        .map_err(|e| anyhow!("content cipher init failed: {e:?}"))?;

    // Strict filename sanitization
    let raw_name = Path::new(&original_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("decrypted_file.bin");
    let safe_original_name = sanitize_filename(raw_name);

    let out_path = derive_safe_output_path(input, "decrypted_", &safe_original_name, "");
    let mut guard = FileCleanupGuard {
        path: out_path.clone(),
        success: false,
    };
    let mut fout = File::create(&out_path)?;

    let mut chunk_index: u64 = 0;

    loop {
        let mut plain_len_buf = [0u8; 4];
        match fin.read_exact(&mut plain_len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let expected_plain_len = u32::from_be_bytes(plain_len_buf) as usize;

        let mut cipher_len_buf = [0u8; 4];
        fin.read_exact(&mut cipher_len_buf)?;
        let cipher_len = u32::from_be_bytes(cipher_len_buf) as usize;

        if cipher_len > CHUNK_SIZE + 32 {
            return Err(anyhow!("Chunk size exceeds limit"));
        }

        let mut nonce_bytes = [0u8; NONCE_LEN];
        fin.read_exact(&mut nonce_bytes)?;

        if nonce_bytes != nonce_from_index(chunk_index) {
            return Err(anyhow!(
                "Chunk sequence tampered or reordered at index {}",
                chunk_index
            ));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = vec![0u8; cipher_len];
        fin.read_exact(&mut ciphertext)?;

        let mut plaintext = content_cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow!("Chunk tamper detected"))?;

        if plaintext.len() != expected_plain_len {
            return Err(anyhow!("Length mismatch"));
        }
        fout.write_all(&plaintext)?;

        ciphertext.zeroize();
        plaintext.zeroize();
        chunk_index += 1;
    }

    if let Some(expected_count) = chunk_count {
        if chunk_index != expected_count {
            return Err(anyhow!(
                "File truncated or corrupt: expected {} chunks, got {}",
                expected_count,
                chunk_index
            ));
        }
    }

    guard.success = true;
    Ok(out_path)
}

pub fn inspect_file(input: &Path) -> Result<String> {
    let mut fin = File::open(input)?;
    let mut magic = [0u8; 8];
    fin.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!("Not a supported .2brecip file"));
    }

    let mut version = [0u8; 1];
    fin.read_exact(&mut version)?;

    if version[0] == 0 || version[0] > 6 {
        return Err(anyhow!(
            "Unknown or unsupported file version: {}",
            version[0]
        ));
    }

    let mut header_len_buf = [0u8; 4];
    fin.read_exact(&mut header_len_buf)?;
    let header_len = u32::from_be_bytes(header_len_buf) as usize;

    if header_len > 1024 * 1024 {
        return Err(anyhow!("Header too large"));
    }

    let mut header_json = vec![0u8; header_len];
    fin.read_exact(&mut header_json)?;
    let mut value: serde_json::Value = serde_json::from_slice(&header_json)?;

    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "file_version_byte".to_string(),
            serde_json::json!(version[0]),
        );
    }

    Ok(serde_json::to_string_pretty(&value)?)
}

pub fn nonce_from_index(index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}

// ───────────────────────── 0. fázis tesztjei ─────────────────────────
//
// A kulcstárat igénylő tesztek (identitás-életciklus, mentés/visszaállítás)
// automatikusan kihagyják magukat, ha az operációs rendszer hitelesítő-tára
// nem érhető el (pl. fej nélküli Linux CI): ilyenkor kiírják, hogy kihagyva.
#[cfg(test)]
mod phase0_tests {
    use super::*;
    use std::sync::Mutex;

    // A keyring bejegyzés (felhasználónként egy) közös az összes teszt között,
    // ezért a kulcstárat használó teszteket sorosítjuk.
    pub(crate) static KEYSTORE_LOCK: Mutex<()> = Mutex::new(());

    const GOOD_PASSWORD: &[u8] = b"correct horse battery staple 42";
    const OTHER_PASSWORD: &[u8] = b"another-long passphrase, 7 words!";

    pub(crate) fn keystore_available() -> bool {
        match protect_private_key(b"availability probe") {
            Ok(_) => true,
            Err(e) => {
                eprintln!("SKIPPED (OS key store unavailable): {e:#}");
                false
            }
        }
    }

    fn own_recipient(device_dir: &Path) -> RecipientPublic {
        let id = load_identity(device_dir).unwrap();
        RecipientPublic {
            fingerprint: id.fingerprint.clone(),
            public_key_b64: id.public_key_b64.clone(),
            ml_kem_public_key_b64: id.ml_kem_public_key_b64.clone(),
        }
    }

    // ── jelszóerősség ──

    #[test]
    fn weak_passwords_are_rejected() {
        for weak in [
            "",
            "short1!A",
            "aaaaaaaaaaaaaaaa",
            "abababababababab",
            "abcabcabcabcabcabc",
            "123456789012",
            "abcdefghijklmnop",
            "qwertyuiop12",
            "Password123456",
            "483920175364",
            "abcdefghijkm",
        ] {
            assert!(
                check_password_strength(weak.as_bytes()).is_err(),
                "should reject {weak:?}"
            );
        }
    }

    #[test]
    fn reasonable_passwords_are_accepted() {
        for good in [
            "correct horse battery staple",
            "Tr0ub4dor&3-xyz!",
            "Zsíros kenyér, jó paprikás 7",
            "another-long passphrase, 7 words!",
        ] {
            assert!(
                check_password_strength(good.as_bytes()).is_ok(),
                "should accept {good:?}"
            );
        }
    }

    #[test]
    fn non_utf8_password_is_rejected_by_the_policy() {
        assert!(check_password_strength(&[0xff, 0xfe, 0xfd, 0xfc]).is_err());
    }

    // ── Argon2 paraméterek ──

    #[test]
    fn identity_without_stored_argon2_params_uses_the_legacy_values() {
        let json = r#"{
            "protected_private_key_b64": "AA==",
            "public_key_b64": "AA==",
            "ml_kem_public_key_b64": "AA==",
            "fingerprint": "x",
            "argon2_salt_b64": "AA=="
        }"#;
        let id: DeviceIdentity = serde_json::from_str(json).unwrap();
        assert_eq!(id.argon2_mem_kib, LEGACY_ARGON2_MEM_KIB);
        assert_eq!(id.argon2_time_cost, LEGACY_ARGON2_TIME_COST);
        assert_eq!(id.argon2_lanes, LEGACY_ARGON2_LANES);
        // és az új, erősebb alapérték tényleg különbözik a régitől
        assert!(ARGON2_MEM_KIB > LEGACY_ARGON2_MEM_KIB);
    }

    #[test]
    fn extreme_argon2_params_from_a_file_are_refused() {
        let salt = [0u8; ARGON2_SALT_LEN];
        assert!(derive_master_key(b"pw", &salt, ARGON2_MAX_MEM_KIB + 1, 3, 4).is_err());
        assert!(derive_master_key(b"pw", &salt, 65_536, ARGON2_MAX_TIME_COST + 1, 4).is_err());
        assert!(derive_master_key(b"pw", &salt, 65_536, 3, ARGON2_MAX_LANES + 1).is_err());
    }

    // ── atomikus írás ──

    fn leftover_temp_files(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count()
    }

    #[test]
    fn atomic_replace_overwrites_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.json");
        write_file_atomic(&path, b"first").unwrap();
        write_file_atomic(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(leftover_temp_files(dir.path()), 0);
    }

    #[test]
    fn atomic_new_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.json");
        write_file_atomic_new(&path, b"original").unwrap();
        let err = write_file_atomic_new(&path, b"intruder").unwrap_err();
        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read(&path).unwrap(), b"original");
        assert_eq!(leftover_temp_files(dir.path()), 0);
    }

    #[cfg(unix)]
    #[test]
    fn written_files_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.json");
        write_file_atomic(&path, b"x").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // ── biztonságos törlés ──

    /// Regressziós teszt: a `Vec::zeroize()` kiürítette a puffert, ezért a második
    /// (nullázó) kör végtelen ciklusba esett. A törlést külön szálon, időkorláttal
    /// futtatjuk, hogy egy esetleges visszaesés hibaként jelentkezzen, nem
    /// lefagyó tesztként.
    #[test]
    fn secure_delete_terminates_overwrites_and_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("victim.bin");
        let alias = dir.path().join("alias.bin");
        let data: Vec<u8> = (0..(CHUNK_SIZE + 4097))
            .map(|i| (i % 241) as u8 + 1)
            .collect();
        fs::write(&path, &data).unwrap();
        // Egy második hard link ugyanarra az adatra mutat: a törlés után ezen
        // keresztül látjuk, mi maradt a fájl tartalmában.
        fs::hard_link(&path, &alias).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let target = path.clone();
        std::thread::spawn(move || {
            let _ = tx.send(secure_delete_file(&target));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(result) => result.unwrap(),
            Err(_) => {
                panic!("secure_delete_file did not finish within 60 seconds (infinite loop?)")
            }
        }

        assert!(!path.exists(), "the file must be removed");
        let leftover = fs::read(&alias).unwrap();
        assert_eq!(leftover.len(), data.len(), "length must be unchanged");
        assert!(
            leftover.iter().all(|&b| b == 0),
            "the contents must have been overwritten (final pass is zeros)"
        );
    }

    #[test]
    fn secure_delete_handles_an_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        fs::write(&path, b"").unwrap();
        secure_delete_file(&path).unwrap();
        assert!(!path.exists());
    }

    // ── a titkosított kimenet ellenőrzése az eredeti törlése előtt ──

    /// Kézzel összerak egy v5 elrendezésű fájlt: fejléc + chunkok.
    fn build_container(path: &Path, header_json: &[u8], cipher: &Aes256GcmSiv, plaintext: &[u8]) {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&(header_json.len() as u32).to_be_bytes());
        out.extend_from_slice(header_json);
        for (i, chunk) in plaintext.chunks(CHUNK_SIZE).enumerate() {
            let nonce_bytes = nonce_from_index(i as u64);
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), chunk)
                .unwrap();
            out.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ct);
        }
        fs::write(path, out).unwrap();
    }

    #[test]
    fn verify_encrypted_output_accepts_good_and_rejects_damaged_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.2brecip");
        let cipher = Aes256GcmSiv::new_from_slice(&[7u8; 32]).unwrap();
        let header = br#"{"hdr":true}"#;
        let plaintext: Vec<u8> = (0..(CHUNK_SIZE * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        let sha = Sha256::digest(&plaintext);
        let chunks = 3u64;
        let len = plaintext.len() as u64;

        build_container(&path, header, &cipher, &plaintext);
        verify_encrypted_output(&path, &cipher, header, chunks, len, sha.as_slice()).unwrap();

        // rossz hash, rossz hossz, rossz darabszám
        assert!(verify_encrypted_output(&path, &cipher, header, chunks, len, &[0u8; 32]).is_err());
        assert!(
            verify_encrypted_output(&path, &cipher, header, chunks, len + 1, sha.as_slice())
                .is_err()
        );
        assert!(
            verify_encrypted_output(&path, &cipher, header, chunks + 1, len, sha.as_slice())
                .is_err()
        );
        // más fejléc
        assert!(verify_encrypted_output(
            &path,
            &cipher,
            b"{\"hdr\":false}",
            chunks,
            len,
            sha.as_slice()
        )
        .is_err());

        // egyetlen elrontott bájt a tartalomban
        let mut bytes = fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert!(
            verify_encrypted_output(&path, &cipher, header, chunks, len, sha.as_slice()).is_err()
        );

        // csonkolt fájl (az utolsó chunk hiányzik)
        build_container(&path, header, &cipher, &plaintext[..CHUNK_SIZE * 2]);
        assert!(
            verify_encrypted_output(&path, &cipher, header, chunks, len, sha.as_slice()).is_err()
        );

        // rossz kulcs
        build_container(&path, header, &cipher, &plaintext);
        let wrong = Aes256GcmSiv::new_from_slice(&[8u8; 32]).unwrap();
        assert!(
            verify_encrypted_output(&path, &wrong, header, chunks, len, sha.as_slice()).is_err()
        );
    }

    #[test]
    fn encrypt_with_secure_delete_verifies_then_removes_the_original() {
        // Csak publikus kulcsra van szükség, kulcstár nélkül is fut.
        let dir = tempfile::tempdir().unwrap();
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = StaticSecret::from(seed);
        let pk = PublicKey::from(&sk);
        let dk = DecapsulationKey768::generate();
        let ek = dk.encapsulation_key().clone().to_bytes();
        let recipient = RecipientPublic {
            fingerprint: fingerprint_from_public_key(pk.as_bytes(), ek.as_slice()),
            public_key_b64: B64.encode(pk.as_bytes()),
            ml_kem_public_key_b64: B64.encode(ek.as_slice()),
        };

        let input = dir.path().join("secret.bin");
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 77))
            .map(|i| (i % 253) as u8)
            .collect();
        fs::write(&input, &data).unwrap();

        let out = encrypt_for_recipient(&input, &recipient, true).unwrap();
        assert!(out.exists(), "encrypted file must exist");
        assert!(
            !input.exists(),
            "original must be deleted after verification"
        );
        assert_eq!(leftover_temp_files(dir.path()), 0);
    }

    // ── automatikus zárolás ──

    #[test]
    fn lock_clears_every_password_field() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::default();
        app.device_dir = dir.path().to_path_buf();
        app.status = String::new();
        app.master_password = Zeroizing::new("a".into());
        app.master_password_confirm = Zeroizing::new("b".into());
        app.rotate_new_password = Zeroizing::new("c".into());
        app.rotate_new_password_confirm = Zeroizing::new("d".into());
        app.backup_password = Zeroizing::new("e".into());
        app.backup_password_confirm = Zeroizing::new("f".into());
        assert!(app.has_unlocked_secrets());
        let ctx = egui::Context::default();
        app.status = "Decrypted to: x".to_string();
        app.lock(&ctx, "locked for test");
        assert!(!app.has_unlocked_secrets());
        // a korábbi üzenet megmarad, a zárolás okával kiegészítve
        assert_eq!(app.status, "Decrypted to: x | locked for test");
        // ismételt zárolás, ha nincs mit zárolni, nem módosítja az üzenetet
        app.lock(&ctx, "locked again");
        assert_eq!(app.status, "Decrypted to: x | locked for test");
    }

    // ── identitás-életciklus (kulcstárral) ──

    #[test]
    fn identity_lifecycle_backup_and_restore() {
        let _guard = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("device");

        // 1. generálás; második generálás megtagadva
        let id = generate_device_identity(&dev, GOOD_PASSWORD).unwrap();
        assert_eq!(id.fingerprint.len(), FINGERPRINT_HEX_LEN);
        assert_eq!(id.argon2_mem_kib, ARGON2_MEM_KIB);
        assert!(generate_device_identity(&dev, GOOD_PASSWORD).is_err());
        assert_eq!(leftover_temp_files(&dev), 0);

        // 2. titkosítás saját magunknak és visszafejtés
        let plain: Vec<u8> = (0..(CHUNK_SIZE + 4321)).map(|i| (i % 249) as u8).collect();
        let src = dir.path().join("note.txt");
        fs::write(&src, &plain).unwrap();
        let enc = encrypt_for_recipient(&src, &own_recipient(&dev), false).unwrap();
        let dec = decrypt_on_this_device(&enc, &dev, GOOD_PASSWORD).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), plain);
        fs::remove_file(&dec).unwrap();
        // rossz jelszó nem nyit
        assert!(decrypt_on_this_device(&enc, &dev, b"definitely the wrong one").is_err());

        // 3. jelszócsere: az új jelszó nyit, a régi nem; az ujjlenyomat nem változik
        change_master_password(&dev, GOOD_PASSWORD, OTHER_PASSWORD, OTHER_PASSWORD).unwrap();
        assert_eq!(load_identity(&dev).unwrap().fingerprint, id.fingerprint);
        assert_eq!(leftover_temp_files(&dev), 0);
        assert!(decrypt_on_this_device(&enc, &dev, GOOD_PASSWORD).is_err());
        let dec = decrypt_on_this_device(&enc, &dev, OTHER_PASSWORD).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), plain);
        fs::remove_file(&dec).unwrap();

        // 4. mentés készítése (a jelenlegi mesterjelszóval), saját mentési jelszóval
        let backup = dir.path().join("identity.2bbackup");
        let backup_pw: &[u8] = b"backup phrase: purple monkey dishwasher 9";
        export_identity_backup(&dev, OTHER_PASSWORD, backup_pw, &backup).unwrap();
        // rossz mesterjelszóval nem készülhet mentés
        assert!(export_identity_backup(
            &dev,
            b"not the master password",
            backup_pw,
            &dir.path().join("nope.2bbackup")
        )
        .is_err());

        // 5. visszaállítás megtagadva, amíg van identitás
        assert!(restore_identity_from_backup(&dev, &backup, backup_pw, GOOD_PASSWORD).is_err());

        // 6. elveszett identitás: a mentésből visszaállítható, új mesterjelszóval
        fs::remove_file(device_identity_path(&dev)).unwrap();
        assert!(restore_identity_from_backup(
            &dev,
            &backup,
            b"wrong backup password!!",
            GOOD_PASSWORD
        )
        .is_err());
        assert!(
            !device_identity_path(&dev).exists(),
            "failed restore must not leave an identity"
        );
        let restored =
            restore_identity_from_backup(&dev, &backup, backup_pw, GOOD_PASSWORD).unwrap();
        assert_eq!(restored.fingerprint, id.fingerprint);
        let dec = decrypt_on_this_device(&enc, &dev, GOOD_PASSWORD).unwrap();
        assert_eq!(fs::read(&dec).unwrap(), plain);
    }

    #[test]
    fn tampered_backup_is_rejected() {
        let _guard = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("device");
        generate_device_identity(&dev, GOOD_PASSWORD).unwrap();
        let backup = dir.path().join("b.2bbackup");
        let backup_pw: &[u8] = b"backup phrase: purple monkey dishwasher 9";
        export_identity_backup(&dev, GOOD_PASSWORD, backup_pw, &backup).unwrap();

        let original = fs::read_to_string(&backup).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();

        // a ciphertext, a publikus kulcs és az Argon2 paraméter módosítása is bukik
        let ct = value["ciphertext_b64"].as_str().unwrap().to_string();
        let mut raw = B64.decode(&ct).unwrap();
        raw[0] ^= 1;
        value["ciphertext_b64"] = serde_json::Value::String(B64.encode(raw));
        let tampered = dir.path().join("t1.2bbackup");
        fs::write(&tampered, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::remove_file(device_identity_path(&dev)).unwrap();
        assert!(restore_identity_from_backup(&dev, &tampered, backup_pw, GOOD_PASSWORD).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        let mut pk = B64
            .decode(value["public_key_b64"].as_str().unwrap())
            .unwrap();
        pk[0] ^= 1;
        value["public_key_b64"] = serde_json::Value::String(B64.encode(pk));
        let tampered = dir.path().join("t2.2bbackup");
        fs::write(&tampered, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(restore_identity_from_backup(&dev, &tampered, backup_pw, GOOD_PASSWORD).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        value["argon2_time_cost"] = serde_json::json!(2);
        let tampered = dir.path().join("t3.2bbackup");
        fs::write(&tampered, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(restore_identity_from_backup(&dev, &tampered, backup_pw, GOOD_PASSWORD).is_err());

        // az eredeti sértetlen mentés viszont továbbra is működik
        assert!(restore_identity_from_backup(&dev, &backup, backup_pw, GOOD_PASSWORD).is_ok());
    }

    #[test]
    fn keyring_error_never_replaces_the_protection_key() {
        // A load_keyring_master_key(false) soha nem hozhat létre új kulcsot:
        // ha a bejegyzés hiányzik, hibát kell adnia (nem újat generálnia).
        // Ezt a viselkedést a kulcstár nélküli környezetben is ellenőrizzük,
        // mert ott is hibát kell kapnunk, nem csendes új kulcsot.
        #[cfg(not(target_os = "windows"))]
        {
            let _guard = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            if keystore_available() {
                // létezik a bejegyzés → a (false) módú betöltés sikeres és 32 bájtos
                let key = load_keyring_master_key(false).unwrap();
                assert_eq!(key.len(), 32);
            } else {
                assert!(load_keyring_master_key(false).is_err());
            }
        }
    }
}
