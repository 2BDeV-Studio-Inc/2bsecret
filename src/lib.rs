use aes_gcm_siv::{aead::{Aead, KeyInit, Payload}, Aes256GcmSiv, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eframe::egui;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, fs::File, io::{Read, Write}, path::{Path, PathBuf}};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use secrecy::{Secret, ExposeSecret};
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "windows")]
use windows_dpapi::{decrypt_data, encrypt_data, Scope};

#[cfg(not(target_os = "windows"))]
use keyring::Entry as KeyringEntry;

const MAGIC: &[u8; 8] = b"2BRECIP\0";
const VERSION: u8 = 4;
const CHUNK_SIZE: usize = 1024 * 1024;
const NONCE_LEN: usize = 12;

#[cfg(target_os = "windows")]
const PROTECTION_DPAPI: &str = "dpapi";
#[cfg(not(target_os = "windows"))]
const PROTECTION_KEYRING: &str = "keyring-aes256gcmsiv";

pub struct App {
    pub selected_file: Option<PathBuf>,
    pub status: String,
    pub metadata_preview: String,
    pub loaded_recipient: Option<RecipientPublic>,
    pub device_dir: PathBuf,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RecipientPublic {
    pub fingerprint: String,
    pub public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub protected_private_key_b64: String,
    pub public_key_b64: String,
    pub fingerprint: String,
    #[serde(default = "default_protection_mode")]
    pub protection_mode: String,
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
    recipient_fingerprint: String,
    ephemeral_public_key_b64: String,
    wrap_nonce_b64: String,
    wrapped_file_key_b64: String,
    original_name: String,
    chunk_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunk_count: Option<u64>,
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
        Self {
            selected_file: None,
            status,
            metadata_preview: String::new(),
            loaded_recipient: load_default_recipient(&device_dir).ok(),
            device_dir,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Generate this device keypair").clicked() {
                    match generate_device_identity(&self.device_dir) {
                        Ok(id) => self.status = format!("Generated device identity [{}]", id.fingerprint),
                        Err(e) => self.status = format!("Generate error: {e:#}"),
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
            if ui.button("Encrypt for recipient").clicked() {
                match (&self.selected_file, &self.loaded_recipient) {
                    (Some(path), Some(rec)) => match encrypt_for_recipient(path, rec) {
                        Ok(out) => self.status = format!("Encrypted to: {}", out.display()),
                        Err(e) => self.status = format!("Encrypt error: {e:#}"),
                    },
                    (None, _) => self.status = "Select a file first.".to_string(),
                    (_, None) => self.status = "Import a recipient public key first.".to_string(),
                }
            }

            if ui.button("Decrypt on this device").clicked() {
                match &self.selected_file {
                    Some(path) => match decrypt_on_this_device(path, &self.device_dir) {
                        Ok(out) => self.status = format!("Decrypted to: {}", out.display()),
                        Err(e) => self.status = format!("Decrypt error: {e:#}"),
                    },
                    None => self.status = "Select a file first.".to_string(),
                }
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

            ui.add_space(12.0);
            ui.label(&self.status);
            ui.separator();
            ui.label("Metadata preview:");
            ui.monospace(&self.metadata_preview);
        });
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

pub fn fingerprint_from_public_key(pk: &[u8]) -> String {
    let digest = Sha256::digest(pk);
    hex_prefix(&digest, 16)
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

#[cfg(not(target_os = "windows"))]
fn get_or_create_keyring_master_key() -> Result<Zeroizing<Vec<u8>>> {
    let entry = KeyringEntry::new("2bsecret", "device-protection-key")
        .map_err(|e| anyhow!("Keyring access error: {e}"))?;

    match entry.get_password() {
        Ok(mut k) => {
            let bytes = Zeroizing::new(B64.decode(&k)?);
            k.zeroize();
            if bytes.len() != 32 {
                return Err(anyhow!(
                    "Corrupt keyring entry: expected 32-byte key, got {}",
                    bytes.len()
                ));
            }
            Ok(bytes)
        }
        Err(_) => {
            let mut raw = vec![0u8; 32];
            OsRng.fill_bytes(&mut raw);
            let mut encoded = B64.encode(&raw);
            entry
                .set_password(&encoded)
                .map_err(|e| anyhow!("Failed to persist protection key in keyring: {e}"))?;
            encoded.zeroize();
            Ok(Zeroizing::new(raw))
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn protect_private_key(sk: &[u8]) -> Result<Vec<u8>> {
    let master = get_or_create_keyring_master_key()?;
    let cipher = Aes256GcmSiv::new_from_slice(&master[..])
        .map_err(|e| anyhow!("Cipher init: {e:?}"))?;
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
            identity.protection_mode, PROTECTION_KEYRING
        ));
    }
    let blob = B64.decode(&identity.protected_private_key_b64)?;
    if blob.len() <= NONCE_LEN {
        return Err(anyhow!("Protection blob too short (len={})", blob.len()));
    }
    let master = get_or_create_keyring_master_key()?;
    let cipher = Aes256GcmSiv::new_from_slice(&master[..])
        .map_err(|e| anyhow!("Cipher init: {e:?}"))?;
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    Ok(Zeroizing::new(
        cipher
            .decrypt(nonce, &blob[NONCE_LEN..])
            .map_err(|_| anyhow!("Key unprotect failed — keyring mismatch or identity corrupted"))?,
    ))
}

pub fn generate_device_identity(device_dir: &Path) -> Result<DeviceIdentity> {
    fs::create_dir_all(device_dir)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    seed.zeroize();
    let public = PublicKey::from(&secret);

    let sk_bytes = Zeroizing::new(secret.to_bytes());
    let protected = protect_private_key(sk_bytes.as_ref())?;

    let identity = DeviceIdentity {
        protected_private_key_b64: B64.encode(&protected),
        public_key_b64: B64.encode(public.as_bytes()),
        fingerprint: fingerprint_from_public_key(public.as_bytes()),
        protection_mode: default_protection_mode(),
    };
    fs::write(
        device_identity_path(device_dir),
        serde_json::to_vec_pretty(&identity)?,
    )?;
    Ok(identity)
}

pub fn export_public_key(device_dir: &Path) -> Result<PathBuf> {
    let id = load_identity(device_dir)?;
    let public = RecipientPublic {
        fingerprint: id.fingerprint.clone(),
        public_key_b64: id.public_key_b64.clone(),
    };
    let out = exported_public_key_path(device_dir, &id.fingerprint);
    fs::write(&out, serde_json::to_vec_pretty(&public)?)?;
    Ok(out)
}

pub fn import_recipient_public_key(device_dir: &Path) -> Result<RecipientPublic> {
    let path = FileDialog::new()
        .add_filter("JSON", &["json"])
        .pick_file()
        .ok_or_else(|| anyhow!("No file selected"))?;
    let data = fs::read(&path)?;
    let rec: RecipientPublic = serde_json::from_slice(&data)?;
    fs::write(default_recipient_path(device_dir), serde_json::to_vec_pretty(&rec)?)?;
    Ok(rec)
}

pub fn load_default_recipient(device_dir: &Path) -> Result<RecipientPublic> {
    let data = fs::read(default_recipient_path(device_dir))?;
    Ok(serde_json::from_slice(&data)?)
}

pub fn load_identity(device_dir: &Path) -> Result<DeviceIdentity> {
    let data = fs::read(device_identity_path(device_dir)).context("Generate this device keypair first")?;
    Ok(serde_json::from_slice(&data)?)
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

pub fn encrypt_for_recipient(input: &Path, recipient: &RecipientPublic) -> Result<PathBuf> {
    let recipient_pk_b = B64.decode(&recipient.public_key_b64)?;
    if recipient_pk_b.len() != 32 {
        return Err(anyhow!("Invalid recipient public key length"));
    }
    let mut recipient_pk_arr = [0u8; 32];
    recipient_pk_arr.copy_from_slice(&recipient_pk_b);
    let recipient_pk = PublicKey::from(recipient_pk_arr);

    let mut file_key_raw = [0u8; 32];
    OsRng.fill_bytes(&mut file_key_raw);
    let file_key = Secret::new(file_key_raw);
    file_key_raw.zeroize();

    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_pk);

    let mut wrap_key_bytes = derive_wrap_key_v3(shared.as_bytes(), eph_public.as_bytes());
    let wrap_cipher = Aes256GcmSiv::new_from_slice(&wrap_key_bytes)
        .map_err(|e| anyhow!("wrap cipher init: {e:?}"))?;
    wrap_key_bytes.zeroize();

    let mut wrap_nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut wrap_nonce_bytes);
    let wrap_nonce = Nonce::from_slice(&wrap_nonce_bytes);

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

    let eph_pk_b64 = B64.encode(eph_public.as_bytes());
    let meta_aad = format!(
        "2BRECIP_v4|{}|{}|{}|{}|{}",
        recipient.fingerprint, eph_pk_b64, original_name, CHUNK_SIZE, chunk_count
    );

    let payload = Payload {
        msg: file_key.expose_secret(),
        aad: meta_aad.as_bytes(),
    };

    let wrapped_file_key = wrap_cipher
        .encrypt(wrap_nonce, payload)
        .map_err(|e| anyhow!("wrap fail: {e:?}"))?;

    let content_cipher = Aes256GcmSiv::new_from_slice(file_key.expose_secret())
        .map_err(|e| anyhow!("cipher init: {e:?}"))?;

    let header = Header {
        magic_b64: B64.encode(MAGIC),
        version: VERSION,
        algorithm: "aes-256-gcm-siv".to_string(),
        key_wrap: "x25519-hkdf-sha256-wrap".to_string(),
        recipient_fingerprint: recipient.fingerprint.clone(),
        ephemeral_public_key_b64: eph_pk_b64,
        wrap_nonce_b64: B64.encode(wrap_nonce_bytes),
        wrapped_file_key_b64: B64.encode(&wrapped_file_key),
        original_name: original_name.clone(),
        chunk_size: CHUNK_SIZE,
        chunk_count: Some(chunk_count),
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
    loop {
        let n = fin.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let plaintext = &buffer[..n];
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

    if chunk_index != chunk_count {
        return Err(anyhow!(
            "Chunk count mismatch during encryption (expected {}, wrote {}): source file may have changed",
            chunk_count, chunk_index
        ));
    }

    guard.success = true;
    Ok(out_path)
}

pub fn decrypt_on_this_device(input: &Path, device_dir: &Path) -> Result<PathBuf> {
    let identity = load_identity(device_dir)?;

    let sk_bytes_raw = unprotect_private_key(&identity)?;
    if sk_bytes_raw.len() != 32 {
        return Err(anyhow!("Invalid private key length"));
    }

    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(sk_bytes_raw.as_slice());
    let secret = StaticSecret::from(sk_arr);
    sk_arr.zeroize();

    let pk_b = B64.decode(&identity.public_key_b64)?;
    if pk_b.len() != 32 {
        return Err(anyhow!("Invalid local public key length"));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_b);
    let public = PublicKey::from(pk_arr);

    let mut fin = File::open(input)?;
    let mut magic = [0u8; 8];
    fin.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(anyhow!("Not a supported file"));
    }

    let mut version_buf = [0u8; 1];
    fin.read_exact(&mut version_buf)?;
    let file_version = version_buf[0];
    if file_version != 3 && file_version != 4 {
        return Err(anyhow!(
            "Unsupported file version {}; only v3 and v4 are supported",
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

    // ── Extra sanity check: ensure chunk size matches our expected value ──
    if header.chunk_size != CHUNK_SIZE {
        return Err(anyhow!(
            "Unsupported chunk size in file (expected {}, got {})",
            CHUNK_SIZE,
            header.chunk_size
        ));
    }

    let local_fpr = fingerprint_from_public_key(public.as_bytes());
    if local_fpr != header.recipient_fingerprint {
        return Err(anyhow!("Wrong recipient"));
    }

    let eph_b = B64.decode(&header.ephemeral_public_key_b64)?;
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

    let wrap_n_b = B64.decode(&header.wrap_nonce_b64)?;
    if wrap_n_b.len() != NONCE_LEN {
        return Err(anyhow!("Invalid wrap nonce length"));
    }
    let wrap_nonce = Nonce::from_slice(&wrap_n_b);
    let wrapped_file_key = B64.decode(&header.wrapped_file_key_b64)?;

    // Build AAD that matches what was used during encryption.
    let meta_aad = if file_version == 4 {
        format!(
            "2BRECIP_v4|{}|{}|{}|{}|{}",
            header.recipient_fingerprint,
            header.ephemeral_public_key_b64,
            header.original_name,
            header.chunk_size,
            header.chunk_count.unwrap_or(0)
        )
    } else {
        // Legacy v3 format (ephemeral key not in AAD)
        match header.chunk_count {
            Some(c) => format!(
                "2BRECIP_v3|{}|{}|{}|{}",
                header.recipient_fingerprint, header.original_name, header.chunk_size, c
            ),
            None => format!(
                "2BRECIP_v3|{}|{}",
                header.recipient_fingerprint, header.original_name
            ),
        }
    };

    let payload = Payload {
        msg: wrapped_file_key.as_slice(),
        aad: meta_aad.as_bytes(),
    };

    let file_key_raw = Zeroizing::new(
        wrap_cipher
            .decrypt(wrap_nonce, payload)
            .map_err(|_| anyhow!("Decryption failed: tampered header or wrong key"))?,
    );

    let content_cipher = Aes256GcmSiv::new_from_slice(&file_key_raw)
        .map_err(|e| anyhow!("content cipher init failed: {e:?}"))?;

    // Strict filename sanitization
    let raw_name = Path::new(&header.original_name)
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

    if let Some(expected_count) = header.chunk_count {
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

    if version[0] == 0 || version[0] > 4 {
        return Err(anyhow!("Unknown or unsupported file version: {}", version[0]));
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
        obj.insert("file_version_byte".to_string(), serde_json::json!(version[0]));
    }

    Ok(serde_json::to_string_pretty(&value)?)
}

pub fn nonce_from_index(index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}