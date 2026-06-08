from pathlib import Path
root = Path('/home/user/output/recipient_lock_rust_dpapi')
(root / 'src').mkdir(parents=True, exist_ok=True)

cargo = '''[package]
name = "2bsecret"
version = "0.5.0"
edition = "2021"

[dependencies]
anyhow = "1"
aes-gcm-siv = "0.11"
base64 = "0.22"
eframe = { version = "0.27", default-features = true }
egui = "0.27"
rand = "0.8"
rfd = "0.14"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
zeroize = "1"
x25519-dalek = { version = "2", features = ["static_secrets"] }
windows-dpapi = "0.2"
'''

main_rs = r'''use aes_gcm_siv::{aead::{Aead, KeyInit}, Aes256GcmSiv, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eframe::egui;
use rand::{rngs::OsRng, RngCore};
use rfd::FileDialog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, fs::File, io::{Read, Write}, path::{Path, PathBuf}};
use windows_dpapi::{decrypt_data, encrypt_data, Scope};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

const MAGIC: &[u8; 8] = b"2BRECIP\0";
const VERSION: u8 = 1;
const CHUNK_SIZE: usize = 1024 * 1024;
const NONCE_LEN: usize = 12;
const WRAP_NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];

struct App {
    selected_file: Option<PathBuf>,
    status: String,
    metadata_preview: String,
    loaded_recipient: Option<RecipientPublic>,
    device_dir: PathBuf,
}

#[derive(Serialize, Deserialize, Clone)]
struct RecipientPublic {
    fingerprint: String,
    public_key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct DeviceIdentity {
    protected_private_key_b64: String,
    public_key_b64: String,
    fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct Header {
    magic_b64: String,
    version: u8,
    algorithm: String,
    key_wrap: String,
    recipient_fingerprint: String,
    ephemeral_public_key_b64: String,
    wrapped_file_key_b64: String,
    original_name: String,
    chunk_size: usize,
}

impl Default for App {
    fn default() -> Self {
        let device_dir = default_device_dir();
        let _ = fs::create_dir_all(&device_dir);
        Self {
            selected_file: None,
            status: String::new(),
            metadata_preview: String::new(),
            loaded_recipient: load_default_recipient(&device_dir).ok(),
            device_dir,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Recipient-Locked File Encryptor (DPAPI-protected key)");
            ui.label("Encrypt on one PC, decrypt only on the selected recipient PC.");
            ui.add_space(8.0);

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

fn main() -> Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Recipient-Locked Encryptor",
        options,
        Box::new(|_cc| Box::new(App::default())),
    )
    .map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}

fn default_device_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("device_keys")
}

fn device_identity_path(device_dir: &Path) -> PathBuf { device_dir.join("identity.json") }
fn default_recipient_path(device_dir: &Path) -> PathBuf { device_dir.join("recipient.json") }
fn exported_public_key_path(device_dir: &Path, fingerprint: &str) -> PathBuf { device_dir.join(format!("recipient_{}.json", fingerprint)) }

fn fingerprint_from_public_key(pk: &[u8]) -> String {
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

fn protect_private_key(sk: &[u8]) -> Result<Vec<u8>> {
    Ok(encrypt_data(sk, Scope::User, None).map_err(|e| anyhow!("DPAPI protect failed: {e}"))?)
}

fn unprotect_private_key(blob: &[u8]) -> Result<Vec<u8>> {
    Ok(decrypt_data(blob, Scope::User, None).map_err(|e| anyhow!("DPAPI unprotect failed: {e}"))?)
}

fn generate_device_identity(device_dir: &Path) -> Result<DeviceIdentity> {
    fs::create_dir_all(device_dir)?;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);

    let protected = protect_private_key(&secret.to_bytes())?;

    let identity = DeviceIdentity {
        protected_private_key_b64: B64.encode(protected),
        public_key_b64: B64.encode(public.as_bytes()),
        fingerprint: fingerprint_from_public_key(public.as_bytes()),
    };
    fs::write(device_identity_path(device_dir), serde_json::to_vec_pretty(&identity)?)?;
    Ok(identity)
}

fn export_public_key(device_dir: &Path) -> Result<PathBuf> {
    let id = load_identity(device_dir)?;
    let public = RecipientPublic {
        fingerprint: id.fingerprint.clone(),
        public_key_b64: id.public_key_b64.clone(),
    };
    let out = exported_public_key_path(device_dir, &id.fingerprint);
    fs::write(&out, serde_json::to_vec_pretty(&public)?)?;
    Ok(out)
}

fn import_recipient_public_key(device_dir: &Path) -> Result<RecipientPublic> {
    let path = FileDialog::new().add_filter("JSON", &["json"]).pick_file().ok_or_else(|| anyhow!("No file selected"))?;
    let data = fs::read(&path)?;
    let rec: RecipientPublic = serde_json::from_slice(&data)?;
    fs::write(default_recipient_path(device_dir), serde_json::to_vec_pretty(&rec)?)?;
    Ok(rec)
}

fn load_default_recipient(device_dir: &Path) -> Result<RecipientPublic> {
    let data = fs::read(default_recipient_path(device_dir))?;
    Ok(serde_json::from_slice(&data)?)
}

fn load_identity(device_dir: &Path) -> Result<DeviceIdentity> {
    let data = fs::read(device_identity_path(device_dir)).context("Generate this device keypair first")?;
    Ok(serde_json::from_slice(&data)?)
}

fn derive_output_path_for_encrypt(input: &Path) -> PathBuf {
    let file_name = input.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    input.with_file_name(format!("{}.2brecip", file_name))
}

fn derive_output_path_for_decrypt(input: &Path, original_name: &str) -> PathBuf {
    let mut out = input.with_file_name(format!("decrypted_{}", original_name));
    if !out.exists() { return out; }
    for i in 1..1000 {
        let candidate = input.with_file_name(format!("decrypted_{}_{}", i, original_name));
        if !candidate.exists() { out = candidate; break; }
    }
    out
}

fn encrypt_for_recipient(input: &Path, recipient: &RecipientPublic) -> Result<PathBuf> {
    let recipient_pk_b = B64.decode(&recipient.public_key_b64)?;
    if recipient_pk_b.len() != 32 { return Err(anyhow!("Invalid recipient public key length")); }
    let mut recipient_pk_arr = [0u8; 32];
    recipient_pk_arr.copy_from_slice(&recipient_pk_b);
    let recipient_pk = PublicKey::from(recipient_pk_arr);

    let mut file_key = [0u8; 32];
    OsRng.fill_bytes(&mut file_key);

    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient_pk);
    let wrap_key_bytes = Sha256::digest(shared.as_bytes());
    let wrap_cipher = Aes256GcmSiv::new_from_slice(&wrap_key_bytes).map_err(|e| anyhow!("wrap cipher init failed: {e:?}"))?;
    let wrap_nonce = Nonce::from_slice(&WRAP_NONCE);
    let wrapped_file_key = wrap_cipher.encrypt(wrap_nonce, file_key.as_ref()).map_err(|e| anyhow!("file key wrap failed: {e:?}"))?;

    let content_cipher = Aes256GcmSiv::new_from_slice(&file_key).map_err(|e| anyhow!("content cipher init failed: {e:?}"))?;
    let original_name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let header = Header {
        magic_b64: B64.encode(MAGIC),
        version: VERSION,
        algorithm: "AES-256-GCM-SIV per-chunk + X25519 wrapped file key".to_string(),
        key_wrap: "X25519 ephemeral-recipient envelope".to_string(),
        recipient_fingerprint: recipient.fingerprint.clone(),
        ephemeral_public_key_b64: B64.encode(eph_public.as_bytes()),
        wrapped_file_key_b64: B64.encode(wrapped_file_key),
        original_name,
        chunk_size: CHUNK_SIZE,
    };

    let out_path = derive_output_path_for_encrypt(input);
    let mut fin = File::open(input).with_context(|| format!("Cannot open {}", input.display()))?;
    let mut fout = File::create(&out_path).with_context(|| format!("Cannot create {}", out_path.display()))?;
    let header_json = serde_json::to_vec(&header)?;
    fout.write_all(MAGIC)?;
    fout.write_all(&[VERSION])?;
    fout.write_all(&(header_json.len() as u32).to_be_bytes())?;
    fout.write_all(&header_json)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;
    loop {
        let n = fin.read(&mut buffer)?;
        if n == 0 { break; }
        let plaintext = &buffer[..n];
        let nonce_bytes = nonce_from_index(chunk_index);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = content_cipher.encrypt(nonce, plaintext).map_err(|e| anyhow!("encrypt failed at chunk {chunk_index}: {e:?}"))?;
        fout.write_all(&(n as u32).to_be_bytes())?;
        fout.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
        fout.write_all(&nonce_bytes)?;
        fout.write_all(&ciphertext)?;
        chunk_index += 1;
    }

    file_key.zeroize();
    Ok(out_path)
}

fn decrypt_on_this_device(input: &Path, device_dir: &Path) -> Result<PathBuf> {
    let identity = load_identity(device_dir)?;

    let protected = B64.decode(&identity.protected_private_key_b64)?;
    let sk_bytes = unprotect_private_key(&protected)?;
    if sk_bytes.len() != 32 { return Err(anyhow!("Invalid unprotected private key length")); }
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&sk_bytes);
    let secret = StaticSecret::from(sk_arr);

    let pk_b = B64.decode(&identity.public_key_b64)?;
    if pk_b.len() != 32 { return Err(anyhow!("Invalid local public key length")); }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_b);
    let public = PublicKey::from(pk_arr);

    let mut fin = File::open(input).with_context(|| format!("Cannot open {}", input.display()))?;
    let mut magic = [0u8; 8];
    fin.read_exact(&mut magic)?;
    if &magic != MAGIC { return Err(anyhow!("Not a supported .2brecip file")); }
    let mut version = [0u8; 1];
    fin.read_exact(&mut version)?;
    if version[0] != VERSION { return Err(anyhow!("Unsupported file version")); }
    let mut header_len = [0u8; 4];
    fin.read_exact(&mut header_len)?;
    let header_len = u32::from_be_bytes(header_len) as usize;
    let mut header_json = vec![0u8; header_len];
    fin.read_exact(&mut header_json)?;
    let header: Header = serde_json::from_slice(&header_json)?;

    let local_fpr = fingerprint_from_public_key(public.as_bytes());
    if local_fpr != header.recipient_fingerprint {
        return Err(anyhow!(
            "This file is intended for recipient fingerprint [{}], not this device [{}]",
            header.recipient_fingerprint,
            local_fpr
        ));
    }

    let eph_b = B64.decode(&header.ephemeral_public_key_b64)?;
    if eph_b.len() != 32 { return Err(anyhow!("Invalid ephemeral public key length")); }
    let mut eph_arr = [0u8; 32];
    eph_arr.copy_from_slice(&eph_b);
    let eph_public = PublicKey::from(eph_arr);
    let shared = secret.diffie_hellman(&eph_public);
    let wrap_key_bytes = Sha256::digest(shared.as_bytes());
    let wrap_cipher = Aes256GcmSiv::new_from_slice(&wrap_key_bytes).map_err(|e| anyhow!("wrap cipher init failed: {e:?}"))?;
    let wrap_nonce = Nonce::from_slice(&WRAP_NONCE);
    let wrapped_file_key = B64.decode(&header.wrapped_file_key_b64)?;
    let mut file_key = wrap_cipher.decrypt(wrap_nonce, wrapped_file_key.as_ref()).map_err(|_| anyhow!("Cannot unwrap file key; wrong recipient or corrupted file"))?;
    if file_key.len() != 32 { return Err(anyhow!("Invalid unwrapped file key length")); }

    let content_cipher = Aes256GcmSiv::new_from_slice(&file_key).map_err(|e| anyhow!("content cipher init failed: {e:?}"))?;
    let out_path = derive_output_path_for_decrypt(input, &header.original_name);
    let mut fout = File::create(&out_path)?;

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
        let mut nonce_bytes = [0u8; NONCE_LEN];
        fin.read_exact(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = vec![0u8; cipher_len];
        fin.read_exact(&mut ciphertext)?;
        let plaintext = content_cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| anyhow!("Wrong recipient key / tampered / corrupted file"))?;
        if plaintext.len() != expected_plain_len { return Err(anyhow!("Chunk length mismatch; file may be corrupted")); }
        fout.write_all(&plaintext)?;
    }

    file_key.zeroize();
    Ok(out_path)
}

fn inspect_file(input: &Path) -> Result<String> {
    let mut fin = File::open(input)?;
    let mut magic = [0u8; 8];
    fin.read_exact(&mut magic)?;
    if &magic != MAGIC { return Err(anyhow!("Not a supported .2brecip file")); }
    let mut version = [0u8; 1];
    fin.read_exact(&mut version)?;
    let mut header_len = [0u8; 4];
    fin.read_exact(&mut header_len)?;
    let header_len = u32::from_be_bytes(header_len) as usize;
    let mut header_json = vec![0u8; header_len];
    fin.read_exact(&mut header_json)?;
    let value: serde_json::Value = serde_json::from_slice(&header_json)?;
    Ok(serde_json::to_string_pretty(&value)?)
}

fn nonce_from_index(index: u64) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce[4..].copy_from_slice(&index.to_be_bytes());
    nonce
}
'''

readme = '''Recipient-Locked Encryptor with DPAPI-protected private key.
- Private key is stored encrypted with Windows DPAPI (Scope::User).
- Exported recipient public key and encrypted file headers contain only fingerprints, no hostnames.
'''

root.join('Cargo.toml').write_text(cargo, encoding='utf-8')
(root / 'src' / 'main.rs').write_text(main_rs, encoding='utf-8')
root.join('README.md').write_text(readme, encoding='utf-8')