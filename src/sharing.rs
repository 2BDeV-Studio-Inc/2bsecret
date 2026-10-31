//! 1. fázis: fájlmegosztás szerver nélkül.
//!
//! Ez a modul adja
//!   * a hibrid aláíró kulcsokat (Ed25519 + ML-DSA-65) az identitáshoz,
//!   * az önaláírt meghívófájlt (`.2binvite`) és a névjegyeket (`contacts.json`),
//!   * a 256 bites identitás-ujjlenyomatot és a 60 számjegyes biztonsági számot,
//!   * a v6 fájlformátumot: több címzett, hibrid KEM-es kulcs-slotok, a feladó
//!     hibrid aláírása a teljes fájlon, Padmé-párnázás.
//!
//! Minden titkos kulcs a meglévő, kettős (jelszó + OS) védelmű identitás-blobban
//! marad; ez a modul semmilyen titkot nem ír lemezre.

use super::*;

use ed25519_dalek::{
    Signature as EdSignature, Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use ml_dsa::{
    EncodedVerifyingKey as DsaEncodedVerifyingKey, Keypair as _, MlDsa65,
    Signature as DsaSignature, Signer as _, SigningKey as DsaSigningKey, Verifier as _,
    VerifyingKey as DsaVerifyingKey,
};
use rand::seq::SliceRandom;
use sha2::Sha512;
use std::time::{SystemTime, UNIX_EPOCH};

// ───────────────────────── Állandók ─────────────────────────

const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

const VERSION_V6: u8 = 6;
const V6_ALGORITHM: &str = "aes-256-gcm-siv";
const V6_KEY_WRAP: &str = "x25519+mlkem768-hybrid-multislot";
const V6_TRAILER_MAGIC: &[u8; 8] = b"2BSIGv6\0";
pub const MAX_RECIPIENTS: usize = 64;
const V6_MIN_PADDED_LEN: u64 = 4096;
const V6_MAX_FILE_LEN: u64 = 1 << 62;
const V6_MAX_HEADER_BYTES: usize = 1024 * 1024;
const V6_MAX_META_BYTES: usize = 64 * 1024;
const AEAD_TAG_LEN: usize = 16;

const INVITE_FORMAT: &str = "2bsecret-invite";
const INVITE_VERSION: u32 = 1;
const INVITE_MAX_BYTES: u64 = 64 * 1024;
const CONTACTS_FILE: &str = "contacts.json";
const CONTACTS_VERSION: u32 = 1;
const CONTACTS_MAX_BYTES: u64 = 8 * 1024 * 1024;
const CONTACTS_MAX_COUNT: usize = 1000;
const LABEL_MAX_CHARS: usize = 64;
const PROFILE_FILE: &str = "profile.json";

// ───────────────────────── Aláíró kulcsok ─────────────────────────

/// Az aláíró kulcsok publikus fele (nyers bájtok).
pub(crate) struct SigningPublicKeys {
    pub ed25519: Vec<u8>,
    pub ml_dsa: Vec<u8>,
}

/// Két új, véletlen aláíró mag: Ed25519 seed (32) ‖ ML-DSA-65 seed (32).
pub(crate) fn generate_signing_seeds() -> Zeroizing<[u8; SIGNING_SEEDS_LEN]> {
    let mut seeds = Zeroizing::new([0u8; SIGNING_SEEDS_LEN]);
    OsRng.fill_bytes(seeds.as_mut());
    seeds
}

fn ed_signing_key_from(seed: &[u8]) -> Result<EdSigningKey> {
    let arr: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow!("Invalid Ed25519 seed length"))?;
    let key = EdSigningKey::from_bytes(&arr);
    Ok(key)
}

fn dsa_signing_key_from(seed: &[u8]) -> Result<DsaSigningKey<MlDsa65>> {
    let seed = ml_dsa::Seed::try_from(seed).map_err(|_| anyhow!("Invalid ML-DSA seed length"))?;
    Ok(DsaSigningKey::<MlDsa65>::from_seed(&seed))
}

pub(crate) fn signing_public_from_seeds(seeds: &[u8]) -> Result<SigningPublicKeys> {
    if seeds.len() != SIGNING_SEEDS_LEN {
        return Err(anyhow!("Invalid signing seed block length"));
    }
    let ed = ed_signing_key_from(&seeds[..32])?;
    let dsa = dsa_signing_key_from(&seeds[32..])?;
    let ed_pk = ed.verifying_key().to_bytes().to_vec();
    let dsa_pk = dsa.verifying_key().encode().as_slice().to_vec();
    if ed_pk.len() != ED25519_PK_LEN || dsa_pk.len() != ML_DSA_65_PK_LEN {
        return Err(anyhow!("Unexpected signing public key length"));
    }
    Ok(SigningPublicKeys {
        ed25519: ed_pk,
        ml_dsa: dsa_pk,
    })
}

/// A teljes titokból (160 byte) levezetett aláíró publikus kulcsoknak pontosan
/// egyezniük kell a tárolt publikus kulcsokkal.
pub(crate) fn check_signing_material(
    full_sk: &[u8],
    ed25519_b64: &str,
    ml_dsa_b64: &str,
) -> Result<()> {
    if full_sk.len() != FULL_SK_LEN {
        return Err(anyhow!(
            "Identity secret has no signing key material (length {})",
            full_sk.len()
        ));
    }
    let derived = signing_public_from_seeds(&full_sk[COMBINED_SK_LEN..])?;
    let stored_ed = B64
        .decode(ed25519_b64)
        .map_err(|_| anyhow!("Invalid Ed25519 public key encoding"))?;
    let stored_dsa = B64
        .decode(ml_dsa_b64)
        .map_err(|_| anyhow!("Invalid ML-DSA public key encoding"))?;
    if derived.ed25519 != stored_ed {
        return Err(anyhow!(
            "Key material does not match the Ed25519 public key of this identity"
        ));
    }
    if derived.ml_dsa != stored_dsa {
        return Err(anyhow!(
            "Key material does not match the ML-DSA public key of this identity"
        ));
    }
    Ok(())
}

/// Hibrid aláíró: Ed25519 ÉS ML-DSA-65. Mindkét aláírás szükséges az
/// érvényességhez, így egy esetleges kvantumtámadás (Ed25519) vagy egy jövőbeli
/// rácsalapú kriptoanalitikai áttörés (ML-DSA) önmagában nem elég a hamisításhoz.
struct HybridSigner {
    ed: EdSigningKey,
    dsa: DsaSigningKey<MlDsa65>,
}

impl HybridSigner {
    fn from_seeds(seeds: &[u8]) -> Result<Self> {
        if seeds.len() != SIGNING_SEEDS_LEN {
            return Err(anyhow!("Invalid signing seed block length"));
        }
        Ok(Self {
            ed: ed_signing_key_from(&seeds[..32])?,
            dsa: dsa_signing_key_from(&seeds[32..])?,
        })
    }

    fn sign(&self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let ed_sig = self.ed.sign(msg).to_bytes().to_vec();
        // ML-DSA: determinisztikus változat (FIPS 204 megengedi), üres kontextussal;
        // a tartomány-elválasztás az aláírt üzenet prefixében van.
        let dsa_sig = self.dsa.sign(msg).encode().as_slice().to_vec();
        if ed_sig.len() != ED25519_SIG_LEN || dsa_sig.len() != ML_DSA_65_SIG_LEN {
            return Err(anyhow!("Unexpected signature length"));
        }
        Ok((ed_sig, dsa_sig))
    }
}

fn verify_hybrid(
    ed_pk: &[u8],
    dsa_pk: &[u8],
    msg: &[u8],
    ed_sig: &[u8],
    dsa_sig: &[u8],
) -> Result<()> {
    let ed_pk: [u8; 32] = ed_pk
        .try_into()
        .map_err(|_| anyhow!("Invalid Ed25519 public key length"))?;
    let ed_vk = EdVerifyingKey::from_bytes(&ed_pk)
        .map_err(|_| anyhow!("Invalid Ed25519 public key"))?;
    let ed_sig = EdSignature::from_slice(ed_sig).map_err(|_| anyhow!("Invalid Ed25519 signature"))?;
    ed_vk
        .verify_strict(msg, &ed_sig)
        .map_err(|_| anyhow!("Ed25519 signature check failed"))?;

    let enc = DsaEncodedVerifyingKey::<MlDsa65>::try_from(dsa_pk)
        .map_err(|_| anyhow!("Invalid ML-DSA public key length"))?;
    let dsa_vk = DsaVerifyingKey::<MlDsa65>::decode(&enc);
    let dsa_sig =
        DsaSignature::<MlDsa65>::try_from(dsa_sig).map_err(|_| anyhow!("Invalid ML-DSA signature"))?;
    dsa_vk
        .verify(msg, &dsa_sig)
        .map_err(|_| anyhow!("ML-DSA signature check failed"))?;
    Ok(())
}

// ───────────────────────── Publikus csomag és ujjlenyomat ─────────────────────────

fn push_lp(buf: &mut Vec<u8>, part: &[u8]) {
    buf.extend_from_slice(&(part.len() as u32).to_be_bytes());
    buf.extend_from_slice(part);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Egy identitás négy publikus kulcsa (base64).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct PublicBundle {
    pub x25519_b64: String,
    pub ml_kem_b64: String,
    pub ed25519_b64: String,
    pub ml_dsa_b64: String,
}

/// A dekódolt és érvényesített kulcsok.
struct BundleKeys {
    x25519: [u8; 32],
    ml_kem: Vec<u8>,
    ed25519: [u8; 32],
    ml_dsa: Vec<u8>,
}

impl PublicBundle {
    /// Dekódolja és ellenőrzi a kulcsokat (hossz, érvényes pont, érvényes KEM kulcs).
    fn decode(&self) -> Result<BundleKeys> {
        let x = B64
            .decode(&self.x25519_b64)
            .map_err(|_| anyhow!("Invalid X25519 public key encoding"))?;
        let x25519: [u8; 32] = x
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid X25519 public key length"))?;
        let ml_kem = B64
            .decode(&self.ml_kem_b64)
            .map_err(|_| anyhow!("Invalid ML-KEM public key encoding"))?;
        if ml_kem.len() != ML_KEM_768_EK_LEN {
            return Err(anyhow!("Invalid ML-KEM public key length"));
        }
        let ek_array = ml_kem::Key::<EncapsulationKey768>::try_from(ml_kem.as_slice())
            .map_err(|_| anyhow!("Invalid ML-KEM public key length"))?;
        EncapsulationKey768::new(&ek_array).map_err(|_| anyhow!("Invalid ML-KEM public key"))?;
        let e = B64
            .decode(&self.ed25519_b64)
            .map_err(|_| anyhow!("Invalid Ed25519 public key encoding"))?;
        let ed25519: [u8; 32] = e
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("Invalid Ed25519 public key length"))?;
        EdVerifyingKey::from_bytes(&ed25519).map_err(|_| anyhow!("Invalid Ed25519 public key"))?;
        let ml_dsa = B64
            .decode(&self.ml_dsa_b64)
            .map_err(|_| anyhow!("Invalid ML-DSA public key encoding"))?;
        if ml_dsa.len() != ML_DSA_65_PK_LEN {
            return Err(anyhow!("Invalid ML-DSA public key length"));
        }
        Ok(BundleKeys {
            x25519,
            ml_kem,
            ed25519,
            ml_dsa,
        })
    }

    /// 256 bites (64 hex karakteres) ujjlenyomat mind a négy kulcs fölött.
    /// Mindig a kulcsokból számolódik, soha nem egy tárolt mezőből.
    pub fn fingerprint(&self) -> Result<String> {
        let k = self.decode()?;
        Ok(identity_fingerprint(&k.x25519, &k.ml_kem, &k.ed25519, &k.ml_dsa))
    }
}

fn identity_fingerprint(x25519: &[u8], ml_kem: &[u8], ed25519: &[u8], ml_dsa: &[u8]) -> String {
    let mut buf = Vec::with_capacity(64 + ml_kem.len() + ml_dsa.len());
    buf.extend_from_slice(b"2BSecret identity fingerprint v1\0");
    for part in [x25519, ml_kem, ed25519, ml_dsa] {
        push_lp(&mut buf, part);
    }
    let digest = Sha256::digest(&buf);
    hex_prefix(&digest, 64)
}

/// Az ujjlenyomat négyes csoportokban, szóközzel, olvasható/diktálható alakban.
pub fn format_fingerprint(fp: &str) -> String {
    fp.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// 60 számjegyes biztonsági szám két identitásból. Mindkét fél UGYANAZT látja
/// (a két ujjlenyomat sorrendfüggetlen), ezért elég hangosan, telefonon vagy
/// személyesen összehasonlítani — ha egyezik, nincs közbeékelődő.
pub fn safety_number(fingerprint_a: &str, fingerprint_b: &str) -> String {
    let (lo, hi) = if fingerprint_a <= fingerprint_b {
        (fingerprint_a, fingerprint_b)
    } else {
        (fingerprint_b, fingerprint_a)
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(b"2BSecret safety number v1\0");
    push_lp(&mut buf, lo.as_bytes());
    push_lp(&mut buf, hi.as_bytes());
    let digest = Sha512::digest(&buf);
    let mut groups = Vec::with_capacity(12);
    for i in 0..12 {
        let mut v: u64 = 0;
        for b in &digest[i * 5..i * 5 + 5] {
            v = (v << 8) | u64::from(*b);
        }
        groups.push(format!("{:05}", v % 100_000));
    }
    groups.join(" ")
}

// ───────────────────────── Saját kulcsok betöltése ─────────────────────────

/// A saját identitás feloldott kulcsai egy művelet idejére.
struct OwnKeys {
    x_secret: StaticSecret,
    x_pub: [u8; 32],
    ml_dk: DecapsulationKey768,
    ml_ek_hash: [u8; 32],
    signer: Option<HybridSigner>,
    bundle: Option<PublicBundle>,
}

fn load_own_keys(identity: &DeviceIdentity, secret: &[u8]) -> Result<OwnKeys> {
    check_key_material(secret, &identity.public_key_b64, &identity.ml_kem_public_key_b64)?;
    let mut sk_arr = [0u8; 32];
    sk_arr.copy_from_slice(&secret[..32]);
    let x_secret = StaticSecret::from(sk_arr);
    sk_arr.zeroize();
    let x_pub = *PublicKey::from(&x_secret).as_bytes();

    let seed = ml_kem::Seed::try_from(&secret[32..COMBINED_SK_LEN])
        .map_err(|_| anyhow!("Invalid ML-KEM seed length"))?;
    let ml_dk = DecapsulationKey768::from_seed(seed);
    let ek_bytes = ml_dk.encapsulation_key().to_bytes();
    let ml_ek_hash: [u8; 32] = Sha256::digest(ek_bytes.as_slice()).into();

    let (signer, bundle) = if secret.len() == FULL_SK_LEN {
        check_signing_material(secret, &identity.ed25519_public_key_b64, &identity.ml_dsa_public_key_b64)?;
        let signer = HybridSigner::from_seeds(&secret[COMBINED_SK_LEN..])?;
        let bundle = PublicBundle {
            x25519_b64: identity.public_key_b64.clone(),
            ml_kem_b64: identity.ml_kem_public_key_b64.clone(),
            ed25519_b64: identity.ed25519_public_key_b64.clone(),
            ml_dsa_b64: identity.ml_dsa_public_key_b64.clone(),
        };
        bundle.decode()?;
        (Some(signer), Some(bundle))
    } else {
        (None, None)
    };

    Ok(OwnKeys {
        x_secret,
        x_pub,
        ml_dk,
        ml_ek_hash,
        signer,
        bundle,
    })
}

/// Feloldja az identitást, és ha még nincsenek aláíró kulcsai (a 0. fázisig vagy
/// régebben készült identitás), létrehozza őket: a titkos blob 96 → 160 byte
/// lesz, friss sóval és az aktuális Argon2 paraméterekkel újracsomagolva.
///
/// A régi identity.json a cseréig `identity.before-signing.json` néven
/// megmarad. A cseréhez a mesterjelszó kell. Az X25519/ML-KEM kulcsok NEM
/// változnak, tehát a régi (v5) fájlok és a már kiosztott publikus kulcs
/// továbbra is érvényes.
fn ensure_signing_keys_inner(
    device_dir: &Path,
    password: &[u8],
) -> Result<(DeviceIdentity, Zeroizing<Vec<u8>>)> {
    let identity = load_identity(device_dir)?;
    let secret = unlock_identity_secret(&identity, password)?;
    check_key_material(&secret, &identity.public_key_b64, &identity.ml_kem_public_key_b64)?;

    if secret.len() == FULL_SK_LEN {
        check_signing_material(&secret, &identity.ed25519_public_key_b64, &identity.ml_dsa_public_key_b64)?;
        return Ok((identity, secret));
    }
    if secret.len() != COMBINED_SK_LEN {
        return Err(anyhow!(
            "This identity predates ML-KEM support and cannot be upgraded; \
             create a new identity (back up the old one first)"
        ));
    }

    let seeds = generate_signing_seeds();
    let public = signing_public_from_seeds(seeds.as_slice())?;
    let mut new_secret = Zeroizing::new(Vec::with_capacity(FULL_SK_LEN));
    new_secret.extend_from_slice(&secret);
    new_secret.extend_from_slice(seeds.as_slice());

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let wrapped = wrap_with_password(
        new_secret.as_slice(),
        password,
        &salt,
        ARGON2_MEM_KIB,
        ARGON2_TIME_COST,
        ARGON2_LANES,
    )?;
    let protected = protect_private_key(&wrapped)?;
    let updated = DeviceIdentity {
        protected_private_key_b64: B64.encode(&protected),
        public_key_b64: identity.public_key_b64.clone(),
        ml_kem_public_key_b64: identity.ml_kem_public_key_b64.clone(),
        fingerprint: identity.fingerprint.clone(),
        protection_mode: identity.protection_mode.clone(),
        argon2_salt_b64: B64.encode(salt),
        argon2_mem_kib: ARGON2_MEM_KIB,
        argon2_time_cost: ARGON2_TIME_COST,
        argon2_lanes: ARGON2_LANES,
        ed25519_public_key_b64: B64.encode(&public.ed25519),
        ml_dsa_public_key_b64: B64.encode(&public.ml_dsa),
    };

    // Kör-ellenőrzés a lecserélés ELŐTT.
    let verify = unlock_identity_secret(&updated, password)
        .context("Self-check failed: the upgraded identity could not be unlocked")?;
    if verify.as_slice() != new_secret.as_slice() {
        return Err(anyhow!(
            "Self-check failed: upgraded key material does not match; the identity was left unchanged"
        ));
    }
    check_signing_material(&verify, &updated.ed25519_public_key_b64, &updated.ml_dsa_public_key_b64)?;

    let path = device_identity_path(device_dir);
    let backup_path = device_dir.join("identity.before-signing.json");
    if !backup_path.exists() {
        fs::copy(&path, &backup_path).with_context(|| {
            format!("Cannot keep a copy of the old identity at {}", backup_path.display())
        })?;
    }
    let bytes = Zeroizing::new(serde_json::to_vec_pretty(&updated)?);
    write_file_atomic(&path, bytes.as_slice())?;
    Ok((updated, new_secret))
}

/// Nyilvános belépési pont: biztosítja, hogy az identitásnak legyenek aláíró
/// kulcsai (lásd fent), és visszaadja a naprakész identitást.
pub fn ensure_signing_keys(device_dir: &Path, password: &[u8]) -> Result<DeviceIdentity> {
    ensure_signing_keys_inner(device_dir, password).map(|(identity, _)| identity)
}

/// A saját publikus csomag (négy kulcs). Csak akkor működik, ha az identitás
/// már rendelkezik aláíró kulcsokkal (lásd [`ensure_signing_keys`]).
pub fn own_public_bundle(device_dir: &Path) -> Result<PublicBundle> {
    let id = load_identity(device_dir)?;
    if id.ed25519_public_key_b64.is_empty() || id.ml_dsa_public_key_b64.is_empty() {
        return Err(anyhow!(
            "This identity has no signing keys yet; they are added the next time you \
             enter the master password (e.g. when creating an invite or encrypting for contacts)"
        ));
    }
    let bundle = PublicBundle {
        x25519_b64: id.public_key_b64,
        ml_kem_b64: id.ml_kem_public_key_b64,
        ed25519_b64: id.ed25519_public_key_b64,
        ml_dsa_b64: id.ml_dsa_public_key_b64,
    };
    bundle.decode()?;
    Ok(bundle)
}

/// A saját 256 bites identitás-ujjlenyomat.
pub fn own_identity_fingerprint(device_dir: &Path) -> Result<String> {
    own_public_bundle(device_dir)?.fingerprint()
}

// ───────────────────────── Megjelenített név ─────────────────────────

fn clean_label(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(LABEL_MAX_CHARS)
        .collect();
    cleaned.trim().to_string()
}

#[derive(Serialize, Deserialize, Default)]
struct Profile {
    display_name: String,
}

/// A felhasználó megjelenített neve (a meghívóba és a küldött fájlokba kerül).
pub fn load_display_name(device_dir: &Path) -> String {
    fs::read(device_dir.join(PROFILE_FILE))
        .ok()
        .and_then(|d| serde_json::from_slice::<Profile>(&d).ok())
        .map(|p| clean_label(&p.display_name))
        .unwrap_or_default()
}

pub fn save_display_name(device_dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(device_dir)?;
    let profile = Profile {
        display_name: clean_label(name),
    };
    write_file_atomic(&device_dir.join(PROFILE_FILE), &serde_json::to_vec_pretty(&profile)?)
}

// ───────────────────────── Meghívó ─────────────────────────

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    format: String,
    version: u32,
    name: String,
    bundle: PublicBundle,
    created_unix: u64,
    sig_ed25519_b64: String,
    sig_ml_dsa_b64: String,
}

/// Egy ellenőrzött meghívó tartalma.
#[derive(Clone, Debug)]
pub struct VerifiedInvite {
    pub name: String,
    pub bundle: PublicBundle,
    pub fingerprint: String,
    pub created_unix: u64,
}

fn invite_message(name: &str, bundle: &PublicBundle, created_unix: u64) -> Result<Vec<u8>> {
    let k = bundle.decode()?;
    let mut msg = Vec::new();
    msg.extend_from_slice(b"2BSecret invite v1\0");
    push_lp(&mut msg, name.as_bytes());
    for part in [k.x25519.as_slice(), k.ml_kem.as_slice(), k.ed25519.as_slice(), k.ml_dsa.as_slice()] {
        push_lp(&mut msg, part);
    }
    msg.extend_from_slice(&created_unix.to_be_bytes());
    Ok(msg)
}

/// Meghívófájlt (`.2binvite`) készít a saját publikus kulcsokból, és hibrid
/// aláírással látja el. Az aláírás azt bizonyítja, hogy a csomag birtokosa
/// tényleg rendelkezik a négy kulcs titkos felével, és a fájlt senki nem
/// módosította. A fájl publikus adat: bármilyen csatornán küldhető.
///
/// A meghívó hitelességét (hogy tényleg az illető küldte) NEM az aláírás
/// igazolja, hanem a biztonsági szám/ujjlenyomat egyeztetése egy másik
/// csatornán — lásd [`safety_number`].
pub fn export_invite(
    device_dir: &Path,
    password: &[u8],
    display_name: &str,
    out_path: &Path,
) -> Result<()> {
    let name = clean_label(display_name);
    if name.is_empty() {
        return Err(anyhow!("Please enter a display name for the invite"));
    }
    let (identity, secret) = ensure_signing_keys_inner(device_dir, password)?;
    let own = load_own_keys(&identity, &secret)?;
    let signer = own.signer.as_ref().ok_or_else(|| anyhow!("Missing signing keys"))?;
    let bundle = own.bundle.clone().ok_or_else(|| anyhow!("Missing public bundle"))?;

    let created_unix = unix_now();
    let msg = invite_message(&name, &bundle, created_unix)?;
    let (ed_sig, dsa_sig) = signer.sign(&msg)?;
    let invite = Invite {
        format: INVITE_FORMAT.to_string(),
        version: INVITE_VERSION,
        name,
        bundle,
        created_unix,
        sig_ed25519_b64: B64.encode(&ed_sig),
        sig_ml_dsa_b64: B64.encode(&dsa_sig),
    };
    write_file_atomic(out_path, &serde_json::to_vec_pretty(&invite)?)?;

    // Kör-ellenőrzés: a kiírt meghívónak érvényesnek kell lennie.
    let check = read_invite(out_path).context("Self-check failed: the written invite is invalid")?;
    if check.fingerprint != own_identity_fingerprint(device_dir)? {
        return Err(anyhow!("Self-check failed: the written invite does not match this identity"));
    }
    Ok(())
}

/// Beolvassa és teljes egészében ellenőrzi a meghívót: méretkorlát, szigorú
/// szerkezet, kulcsok érvényessége és mindkét aláírás.
pub fn read_invite(path: &Path) -> Result<VerifiedInvite> {
    let size = fs::metadata(path)
        .with_context(|| format!("Cannot read invite file: {}", path.display()))?
        .len();
    if size > INVITE_MAX_BYTES {
        return Err(anyhow!("The file is too large to be a 2BSecret invite"));
    }
    let data = fs::read(path)?;
    let invite: Invite = serde_json::from_slice(&data)
        .map_err(|_| anyhow!("Not a valid 2BSecret invite file"))?;
    if invite.format != INVITE_FORMAT || invite.version != INVITE_VERSION {
        return Err(anyhow!("Unsupported invite format or version"));
    }
    if invite.name != clean_label(&invite.name) || invite.name.is_empty() {
        return Err(anyhow!("The invite contains an invalid name"));
    }
    let msg = invite_message(&invite.name, &invite.bundle, invite.created_unix)?;
    let keys = invite.bundle.decode()?;
    let ed_sig = B64
        .decode(&invite.sig_ed25519_b64)
        .map_err(|_| anyhow!("Invalid invite signature encoding"))?;
    let dsa_sig = B64
        .decode(&invite.sig_ml_dsa_b64)
        .map_err(|_| anyhow!("Invalid invite signature encoding"))?;
    verify_hybrid(&keys.ed25519, &keys.ml_dsa, &msg, &ed_sig, &dsa_sig)
        .map_err(|_| anyhow!("The invite signature is invalid — the file is damaged or has been tampered with"))?;
    let fingerprint = invite.bundle.fingerprint()?;
    Ok(VerifiedInvite {
        name: invite.name,
        bundle: invite.bundle,
        fingerprint,
        created_unix: invite.created_unix,
    })
}

// ───────────────────────── Névjegyek ─────────────────────────

/// Egy ismert partner. A `fingerprint` az azonosító; a `verified` csak akkor
/// igaz, ha a felhasználó kifejezetten megerősítette a biztonsági számot.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub fingerprint: String,
    pub label: String,
    pub bundle: PublicBundle,
    pub verified: bool,
    pub added_unix: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactsFile {
    version: u32,
    contacts: Vec<Contact>,
}

fn contacts_path(device_dir: &Path) -> PathBuf {
    device_dir.join(CONTACTS_FILE)
}

/// Betölti a névjegyeket. Hiányzó fájl = üres lista. Bármilyen sérülés (nem
/// egyező ujjlenyomat, ismétlődés, érvénytelen kulcs) HIBA, nem csendes kihagyás:
/// egy módosított névjegylista nem juthat észrevétlenül titkosításhoz.
pub fn load_contacts(device_dir: &Path) -> Result<Vec<Contact>> {
    let path = contacts_path(device_dir);
    let size = match fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    if size > CONTACTS_MAX_BYTES {
        return Err(anyhow!("contacts.json is unreasonably large"));
    }
    let file: ContactsFile = serde_json::from_slice(&fs::read(&path)?)
        .map_err(|_| anyhow!("contacts.json is not valid"))?;
    if file.version != CONTACTS_VERSION {
        return Err(anyhow!("Unsupported contacts.json version {}", file.version));
    }
    if file.contacts.len() > CONTACTS_MAX_COUNT {
        return Err(anyhow!("Too many contacts"));
    }
    let mut seen = std::collections::HashSet::new();
    for c in &file.contacts {
        let computed = c.bundle.fingerprint()?;
        if computed != c.fingerprint {
            return Err(anyhow!(
                "contacts.json is damaged or tampered with: the stored fingerprint of '{}' \
                 does not match its keys",
                c.label
            ));
        }
        if !seen.insert(c.fingerprint.clone()) {
            return Err(anyhow!("contacts.json contains the same contact twice"));
        }
    }
    Ok(file.contacts)
}

fn save_contacts(device_dir: &Path, contacts: &[Contact]) -> Result<()> {
    fs::create_dir_all(device_dir)?;
    let file = ContactsFile {
        version: CONTACTS_VERSION,
        contacts: contacts.to_vec(),
    };
    write_file_atomic(&contacts_path(device_dir), &serde_json::to_vec_pretty(&file)?)
}

pub fn find_contact<'a>(contacts: &'a [Contact], fingerprint: &str) -> Option<&'a Contact> {
    contacts.iter().find(|c| c.fingerprint == fingerprint)
}

/// Hozzáad egy névjegyet a csomagból. Ha az ujjlenyomat már szerepel, a meglévő
/// bejegyzést adja vissza (a címke és a megerősített állapot VÁLTOZATLAN marad),
/// a második visszatérési érték pedig `false`. A saját identitás nem adható hozzá.
pub fn add_contact(
    device_dir: &Path,
    bundle: PublicBundle,
    label: &str,
) -> Result<(Contact, bool)> {
    let fingerprint = bundle.fingerprint()?;
    if let Ok(own) = own_identity_fingerprint(device_dir) {
        if own == fingerprint {
            return Err(anyhow!("This is your own identity, not a contact"));
        }
    }
    let mut contacts = load_contacts(device_dir)?;
    if let Some(existing) = find_contact(&contacts, &fingerprint) {
        return Ok((existing.clone(), false));
    }
    if contacts.len() >= CONTACTS_MAX_COUNT {
        return Err(anyhow!("Too many contacts"));
    }
    let mut label = clean_label(label);
    if label.is_empty() {
        label = format!("Contact {}", &fingerprint[..8]);
    }
    let contact = Contact {
        fingerprint,
        label,
        bundle,
        verified: false,
        added_unix: unix_now(),
    };
    contacts.push(contact.clone());
    save_contacts(device_dir, &contacts)?;
    Ok((contact, true))
}

/// Meghívó importálása: ellenőrzi, majd névjegyként menti (megerősítetlenként).
pub fn import_invite(
    device_dir: &Path,
    invite_path: &Path,
    label_override: Option<&str>,
) -> Result<(Contact, bool)> {
    let invite = read_invite(invite_path)?;
    let label = label_override
        .filter(|l| !clean_label(l).is_empty())
        .unwrap_or(&invite.name);
    add_contact(device_dir, invite.bundle, label)
}

fn update_contact<F: FnOnce(&mut Contact)>(device_dir: &Path, fingerprint: &str, f: F) -> Result<()> {
    let mut contacts = load_contacts(device_dir)?;
    let c = contacts
        .iter_mut()
        .find(|c| c.fingerprint == fingerprint)
        .ok_or_else(|| anyhow!("Unknown contact"))?;
    f(c);
    save_contacts(device_dir, &contacts)
}

/// A biztonsági szám egyeztetése után: megerősítettnek jelöli a névjegyet.
pub fn set_contact_verified(device_dir: &Path, fingerprint: &str, verified: bool) -> Result<()> {
    update_contact(device_dir, fingerprint, |c| c.verified = verified)
}

pub fn rename_contact(device_dir: &Path, fingerprint: &str, label: &str) -> Result<()> {
    let label = clean_label(label);
    if label.is_empty() {
        return Err(anyhow!("The name cannot be empty"));
    }
    update_contact(device_dir, fingerprint, |c| c.label = label)
}

pub fn remove_contact(device_dir: &Path, fingerprint: &str) -> Result<()> {
    let mut contacts = load_contacts(device_dir)?;
    let before = contacts.len();
    contacts.retain(|c| c.fingerprint != fingerprint);
    if contacts.len() == before {
        return Err(anyhow!("Unknown contact"));
    }
    save_contacts(device_dir, &contacts)
}

// ───────────────────────── v6 formátum ─────────────────────────
//
// Fájlfelépítés:
//   MAGIC(8) ‖ 0x06 ‖ fejléc-hossz u32 BE ‖ fejléc JSON ‖ chunk-rekordok ‖ záradék
//
// Fejléc: slotok (címzettenként egy hibrid X25519+ML-KEM-768 kulcslezárás),
//   kulcs-elköteleződés (key commitment), lezárt metaadat.
// Lezárt metaadat (csak a fájlkulccsal olvasható): fájlnév, hossz, a feladó
//   publikus csomagja és neve, időbélyeg.
// Chunk-rekord: plain_len u32 ‖ cipher_len u32 ‖ nonce(12) ‖ ciphertext. Az AAD
//   a fejléc SHA-256-ja ‖ chunk-index ‖ utolsó-e jelző, így a chunk-ok csak EZZEL
//   a fejléccel és EZEN a helyen érvényesek, a csonkolás pedig kiderül.
// Záradék: "2BSIGv6\0" ‖ Ed25519 aláírás(64) ‖ ML-DSA-65 aláírás(3309), a
//   fejléc-hash és a chunk-rekordok láncolt hash-e fölött.

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlotV6 {
    eph_b64: String,
    kem_ct_b64: String,
    nonce_b64: String,
    ct_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderV6 {
    magic_b64: String,
    version: u8,
    algorithm: String,
    key_wrap: String,
    chunk_size: usize,
    slots: Vec<SlotV6>,
    key_commit_b64: String,
    meta_nonce_b64: String,
    meta_sealed_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetaV6 {
    original_name: String,
    file_len: u64,
    padded_len: u64,
    chunk_count: u64,
    created_unix: u64,
    sender_name: String,
    sender: PublicBundle,
    // Kitöltés: a lezárt metaadat hossza 512 byte többszöröse, hogy a fájlnév
    // és a hosszok számjegyeinek száma ne látsszon a fejléc méretéből.
    pad: String,
}

const META_PAD_BLOCK: usize = 512;

struct V6Keys {
    content: Zeroizing<[u8; 32]>,
    meta: Zeroizing<[u8; 32]>,
    commit: [u8; 32],
}

fn v6_derive_keys(file_key: &[u8; 32]) -> V6Keys {
    let hk = Hkdf::<Sha256>::new(None, file_key);
    let mut content = Zeroizing::new([0u8; 32]);
    let mut meta = Zeroizing::new([0u8; 32]);
    let mut commit = [0u8; 32];
    hk.expand(b"2BSecret v6 content key", content.as_mut())
        .expect("HKDF expand failed");
    hk.expand(b"2BSecret v6 metadata key", meta.as_mut())
        .expect("HKDF expand failed");
    hk.expand(b"2BSecret v6 key commitment", &mut commit)
        .expect("HKDF expand failed");
    V6Keys {
        content,
        meta,
        commit,
    }
}

/// Padmé-párnázás (Nikitin és mások, 2019): a titkosított méret csak a
/// fájlméret kb. log-log bitjét árulja el, a többlet legfeljebb ~12%.
/// A minimum 4096 byte, így a kis fájlok mérete sem különböztethető meg.
pub fn padded_length(len: u64) -> u64 {
    if len < V6_MIN_PADDED_LEN {
        return V6_MIN_PADDED_LEN;
    }
    let e = u64::from(63 - len.leading_zeros()); // floor(log2 len)
    let s = u64::from(64 - e.leading_zeros()); // floor(log2 e) + 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    len.saturating_add(mask) & !mask
}

fn chunks_for(padded_len: u64) -> u64 {
    (padded_len + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
}

fn slot_salt(eph: &[u8], kem_ct: &[u8], recipient_x: &[u8], recipient_ek_hash: &[u8]) -> Vec<u8> {
    // A címzett publikus kulcsai is a levezetésbe kerülnek (kulcs-kötés).
    let mut salt = Vec::with_capacity(eph.len() + kem_ct.len() + 64);
    salt.extend_from_slice(eph);
    salt.extend_from_slice(kem_ct);
    salt.extend_from_slice(recipient_x);
    salt.extend_from_slice(recipient_ek_hash);
    salt
}

fn slot_key(x_shared: &[u8], kem_shared: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(kem_shared);
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm.as_slice());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(b"2BSecret v6 slot key", okm.as_mut())
        .expect("HKDF expand failed");
    okm
}

fn slot_aad(eph: &[u8], kem_ct: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + eph.len() + kem_ct.len());
    aad.extend_from_slice(b"2BSecret v6 slot\0");
    aad.extend_from_slice(eph);
    aad.extend_from_slice(kem_ct);
    aad
}

fn v6_seal_slot(recipient: &BundleKeys, file_key: &[u8; 32]) -> Result<SlotV6> {
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_public = PublicKey::from(&eph_secret);
    let x_shared = eph_secret.diffie_hellman(&PublicKey::from(recipient.x25519));
    if !x_shared.was_contributory() {
        return Err(anyhow!("A recipient key is invalid (low-order X25519 point)"));
    }

    let ek_array = ml_kem::Key::<EncapsulationKey768>::try_from(recipient.ml_kem.as_slice())
        .map_err(|_| anyhow!("Invalid ML-KEM public key length"))?;
    let ek = EncapsulationKey768::new(&ek_array).map_err(|_| anyhow!("Invalid ML-KEM public key"))?;
    let (kem_ct, kem_shared) = ek.encapsulate();

    let ek_hash = Sha256::digest(&recipient.ml_kem);
    let salt = slot_salt(eph_public.as_bytes(), kem_ct.as_slice(), &recipient.x25519, &ek_hash);
    let key = slot_key(x_shared.as_bytes(), kem_shared.as_slice(), &salt);

    let cipher = Aes256GcmSiv::new_from_slice(key.as_ref())
        .map_err(|e| anyhow!("slot cipher init: {e:?}"))?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let aad = slot_aad(eph_public.as_bytes(), kem_ct.as_slice());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: file_key.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|e| anyhow!("slot encrypt failed: {e:?}"))?;
    Ok(SlotV6 {
        eph_b64: B64.encode(eph_public.as_bytes()),
        kem_ct_b64: B64.encode(kem_ct.as_slice()),
        nonce_b64: B64.encode(nonce),
        ct_b64: B64.encode(&ct),
    })
}

/// Megpróbálja kinyitni a slotot a saját kulcsokkal. `None`, ha nem nekünk szól
/// (vagy sérült) — a hívó egyszerűen a következő slottal próbálkozik.
fn v6_open_slot(own: &OwnKeys, slot: &SlotV6) -> Option<Zeroizing<[u8; 32]>> {
    let eph: [u8; 32] = B64.decode(&slot.eph_b64).ok()?.as_slice().try_into().ok()?;
    let kem_ct_bytes = B64.decode(&slot.kem_ct_b64).ok()?;
    let nonce = B64.decode(&slot.nonce_b64).ok()?;
    let ct = B64.decode(&slot.ct_b64).ok()?;
    if nonce.len() != NONCE_LEN || ct.len() != 32 + AEAD_TAG_LEN {
        return None;
    }
    let x_shared = own.x_secret.diffie_hellman(&PublicKey::from(eph));
    if !x_shared.was_contributory() {
        return None;
    }
    let ct_array = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct_bytes.as_slice()).ok()?;
    let kem_shared = own.ml_dk.decapsulate(&ct_array);

    let salt = slot_salt(&eph, &kem_ct_bytes, &own.x_pub, &own.ml_ek_hash);
    let key = slot_key(x_shared.as_bytes(), kem_shared.as_slice(), &salt);
    let cipher = Aes256GcmSiv::new_from_slice(key.as_ref()).ok()?;
    let aad = slot_aad(&eph, &kem_ct_bytes);
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ct.as_slice(),
                    aad: &aad,
                },
            )
            .ok()?,
    );
    let mut file_key = Zeroizing::new([0u8; 32]);
    if pt.len() != 32 {
        return None;
    }
    file_key.copy_from_slice(&pt);
    Some(file_key)
}

fn meta_aad(commit: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(48);
    aad.extend_from_slice(b"2BSecret v6 meta\0");
    aad.extend_from_slice(commit);
    aad
}

fn chunk_aad(header_digest: &[u8; 32], index: u64, last: bool) -> [u8; 41] {
    let mut aad = [0u8; 41];
    aad[..32].copy_from_slice(header_digest);
    aad[32..40].copy_from_slice(&index.to_be_bytes());
    aad[40] = u8::from(last);
    aad
}

fn v6_signed_message(header_digest: &[u8; 32], chain_hash: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(96);
    msg.extend_from_slice(b"2BSecret v6 file signature\0");
    msg.extend_from_slice(header_digest);
    msg.extend_from_slice(chain_hash);
    msg
}

/// A fájl verziójának megnézése (magic + verzió bájt) anélkül, hogy bármi mást
/// értelmeznénk. A GUI ezzel választ a v3–v5 és a v6 visszafejtő között.
pub fn peek_file_version(path: &Path) -> Result<u8> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)
        .map_err(|_| anyhow!("Not a supported .2brecip file"))?;
    if &magic != MAGIC {
        return Err(anyhow!("Not a supported .2brecip file"));
    }
    let mut v = [0u8; 1];
    f.read_exact(&mut v)?;
    Ok(v[0])
}

// ───────────────────────── v6 titkosítás ─────────────────────────

/// Titkosít egy fájlt egy vagy több névjegynek (és opcionálisan magadnak), a
/// teljes fájlt hibrid módon aláírva a saját kulcsaiddal.
///
/// * `recipients`: a címzettek; legfeljebb [`MAX_RECIPIENTS`] összesen.
/// * `include_self`: te is kinyithatod a fájlt (ajánlott: így a saját küldött
///   fájljaidat is visszaolvashatod).
/// * `sender_name`: a fájlba (lezárva) kerülő név; üres esetén a mentett név.
///
/// Szükséges a mesterjelszó (az aláíráshoz). Ha az identitásnak még nincs
/// aláíró kulcsa, itt jön létre (lásd [`ensure_signing_keys`]).
///
/// `delete_original`: a titkosított kimenetet az eredeti törlése előtt újraolvassa,
/// teljesen visszafejti és az aláírást is ellenőrzi.
pub fn encrypt_for_contacts(
    input: &Path,
    device_dir: &Path,
    password: &[u8],
    recipients: &[Contact],
    include_self: bool,
    sender_name: &str,
    delete_original: bool,
) -> Result<PathBuf> {
    if recipients.is_empty() && !include_self {
        return Err(anyhow!("Select at least one recipient"));
    }
    let (identity, secret) = ensure_signing_keys_inner(device_dir, password)?;
    let own = load_own_keys(&identity, &secret)?;
    let signer = own.signer.as_ref().ok_or_else(|| anyhow!("Missing signing keys"))?;
    let own_bundle = own.bundle.clone().ok_or_else(|| anyhow!("Missing public bundle"))?;
    let own_fp = own_bundle.fingerprint()?;

    // Címzett-bundle-ök: az ujjlenyomatot a kulcsokból számoljuk újra, ismétlődést
    // kiszűrjük, és a saját kulcsainkat opcionálisan hozzáadjuk.
    let mut bundles: Vec<(String, PublicBundle)> = Vec::new();
    for c in recipients {
        let fp = c.bundle.fingerprint()?;
        if fp == own_fp {
            continue; // a saját kulcsot az include_self kezeli
        }
        if !bundles.iter().any(|(f, _)| *f == fp) {
            bundles.push((fp, c.bundle.clone()));
        }
    }
    if include_self {
        bundles.push((own_fp.clone(), own_bundle.clone()));
    }
    if bundles.is_empty() {
        return Err(anyhow!("Select at least one recipient"));
    }
    if bundles.len() > MAX_RECIPIENTS {
        return Err(anyhow!("Too many recipients (maximum {MAX_RECIPIENTS})"));
    }

    // ── Fájlkulcs, levezetett kulcsok ──
    let mut file_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(file_key.as_mut());
    let keys = v6_derive_keys(&file_key);

    // ── Slotok (a sorrend véletlen, hogy a saját slot helye ne áruljon el semmit) ──
    let mut slots = Vec::with_capacity(bundles.len());
    for (_, b) in &bundles {
        slots.push(v6_seal_slot(&b.decode()?, &file_key)?);
    }
    slots.shuffle(&mut OsRng);

    // ── Metaadat ──
    let original_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let file_len = fs::metadata(input)?.len();
    if file_len > V6_MAX_FILE_LEN {
        return Err(anyhow!("The file is too large"));
    }
    let padded_len = padded_length(file_len);
    let chunk_count = chunks_for(padded_len);
    let name = {
        let given = clean_label(sender_name);
        if given.is_empty() {
            clean_label(&load_display_name(device_dir))
        } else {
            given
        }
    };
    let mut meta = MetaV6 {
        original_name: original_name.clone(),
        file_len,
        padded_len,
        chunk_count,
        created_unix: unix_now(),
        sender_name: name,
        sender: own_bundle.clone(),
        pad: String::new(),
    };
    let base_len = serde_json::to_vec(&meta)?.len();
    meta.pad = "0".repeat((META_PAD_BLOCK - base_len % META_PAD_BLOCK) % META_PAD_BLOCK);
    let meta_json = Zeroizing::new(serde_json::to_vec(&meta)?);
    let meta_cipher = Aes256GcmSiv::new_from_slice(keys.meta.as_ref())
        .map_err(|e| anyhow!("meta cipher init: {e:?}"))?;
    let mut meta_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut meta_nonce);
    let meta_sealed = meta_cipher
        .encrypt(
            Nonce::from_slice(&meta_nonce),
            Payload {
                msg: meta_json.as_slice(),
                aad: &meta_aad(&keys.commit),
            },
        )
        .map_err(|e| anyhow!("meta encrypt failed: {e:?}"))?;

    let header = HeaderV6 {
        magic_b64: B64.encode(MAGIC),
        version: VERSION_V6,
        algorithm: V6_ALGORITHM.to_string(),
        key_wrap: V6_KEY_WRAP.to_string(),
        chunk_size: CHUNK_SIZE,
        slots,
        key_commit_b64: B64.encode(keys.commit),
        meta_nonce_b64: B64.encode(meta_nonce),
        meta_sealed_b64: B64.encode(&meta_sealed),
    };
    let header_json = serde_json::to_vec(&header)?;
    if header_json.len() > V6_MAX_HEADER_BYTES {
        return Err(anyhow!("The header would be too large"));
    }
    let header_digest: [u8; 32] = Sha256::digest(&header_json).into();

    let content_cipher = Aes256GcmSiv::new_from_slice(keys.content.as_ref())
        .map_err(|e| anyhow!("content cipher init: {e:?}"))?;

    let out_path = derive_safe_output_path(input, "", &original_name, ".2brecip");
    let mut guard = FileCleanupGuard {
        path: out_path.clone(),
        success: false,
    };
    let mut fin = File::open(input)?;
    let mut fout = File::create(&out_path)?;
    fout.write_all(MAGIC)?;
    fout.write_all(&[VERSION_V6])?;
    fout.write_all(&(header_json.len() as u32).to_be_bytes())?;
    fout.write_all(&header_json)?;

    let mut chain = Sha256::new();
    let mut plain_hasher = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0u8; CHUNK_SIZE]);
    let mut real_remaining = file_len;
    for index in 0..chunk_count {
        let offset = index * CHUNK_SIZE as u64;
        let chunk_len = (padded_len - offset).min(CHUNK_SIZE as u64) as usize;
        let real = real_remaining.min(chunk_len as u64) as usize;
        fin.read_exact(&mut buffer[..real])
            .context("The source file changed while it was being encrypted")?;
        buffer[real..chunk_len].fill(0); // Padmé-párnázás: nullák
        plain_hasher.update(&buffer[..real]);
        real_remaining -= real as u64;

        let nonce_bytes = nonce_from_index(index);
        let last = index + 1 == chunk_count;
        let ciphertext = content_cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &buffer[..chunk_len],
                    aad: &chunk_aad(&header_digest, index, last),
                },
            )
            .map_err(|e| anyhow!("encrypt failed: {e:?}"))?;
        let plain_len_be = (chunk_len as u32).to_be_bytes();
        let cipher_len_be = (ciphertext.len() as u32).to_be_bytes();
        for part in [&plain_len_be[..], &cipher_len_be[..], &nonce_bytes[..], &ciphertext[..]] {
            fout.write_all(part)?;
            chain.update(part);
        }
    }
    // A forrásfájl nem nőhetett közben.
    let mut probe = [0u8; 1];
    if fin.read(&mut probe)? != 0 {
        return Err(anyhow!("The source file changed while it was being encrypted"));
    }
    drop(fin);

    // ── Aláírás: fejléc-hash ‖ chunk-rekordok láncolt hash-e ──
    let chain_hash: [u8; 32] = chain.finalize().into();
    let (ed_sig, dsa_sig) = signer.sign(&v6_signed_message(&header_digest, &chain_hash))?;
    fout.write_all(V6_TRAILER_MAGIC)?;
    fout.write_all(&ed_sig)?;
    fout.write_all(&dsa_sig)?;
    fout.flush()?;
    fout.sync_all()?;
    drop(fout);
    sync_parent_dir(&out_path);

    if delete_original {
        // Újraolvasás: a fejlécnek bájtra egyeznie kell, minden chunk-nak
        // visszafejthetőnek, a tartalom hash-ének és az aláírásnak helyesnek.
        let digest = plain_hasher.finalize();
        verify_v6_output(&out_path, &header_json, &content_cipher, &own_bundle, &meta, digest.as_slice())
            .context("Verification of the encrypted file failed; the original file was NOT deleted")?;
    }

    guard.success = true;
    if delete_original {
        secure_delete_file(input)
            .with_context(|| "Encryption succeeded, but securely deleting the original file failed")?;
    }
    Ok(out_path)
}

fn verify_v6_output(
    path: &Path,
    expected_header_json: &[u8],
    content_cipher: &Aes256GcmSiv,
    sender: &PublicBundle,
    meta: &MetaV6,
    expected_sha256: &[u8],
) -> Result<()> {
    let mut f = File::open(path).context("Cannot reopen the encrypted file")?;
    let (header_json, _header, header_digest) = read_v6_header(&mut f)?;
    if header_json != expected_header_json {
        return Err(anyhow!("Encrypted file header differs from what was written"));
    }
    let mut hasher = Sha256::new();
    let body = process_v6_body(
        &mut f,
        &header_digest,
        meta.padded_len,
        meta.chunk_count,
        content_cipher,
        |offset, plaintext| {
            hash_real_part(&mut hasher, offset, plaintext, meta.file_len)
        },
    )?;
    if hasher.finalize().as_slice() != expected_sha256 {
        return Err(anyhow!("Encrypted file content does not match the original"));
    }
    let keys = sender.decode()?;
    verify_hybrid(
        &keys.ed25519,
        &keys.ml_dsa,
        &v6_signed_message(&header_digest, &body.chain_hash),
        &body.ed_sig,
        &body.dsa_sig,
    )
    .context("The written signature does not verify")?;
    Ok(())
}

/// A tényleges fájltartalmat (a párnázás nélkül) adja a hasher-nek; a párnázásnak
/// csupa nullának kell lennie.
fn hash_real_part(hasher: &mut Sha256, offset: u64, plaintext: &[u8], file_len: u64) -> Result<()> {
    let (real, pad) = split_real(offset, plaintext, file_len);
    hasher.update(real);
    if pad.iter().any(|b| *b != 0) {
        return Err(anyhow!("Corrupt padding"));
    }
    Ok(())
}

fn split_real(offset: u64, plaintext: &[u8], file_len: u64) -> (&[u8], &[u8]) {
    if offset >= file_len {
        return (&[], plaintext);
    }
    let real_len = (file_len - offset).min(plaintext.len() as u64) as usize;
    plaintext.split_at(real_len)
}

// ───────────────────────── v6 olvasás ─────────────────────────

fn read_v6_header(f: &mut File) -> Result<(Vec<u8>, HeaderV6, [u8; 32])> {
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)
        .map_err(|_| anyhow!("Not a supported .2brecip file"))?;
    if &magic != MAGIC {
        return Err(anyhow!("Not a supported .2brecip file"));
    }
    let mut version = [0u8; 1];
    f.read_exact(&mut version)?;
    if version[0] != VERSION_V6 {
        return Err(anyhow!("This is not a v6 file"));
    }
    let mut len_buf = [0u8; 4];
    f.read_exact(&mut len_buf)?;
    let header_len = u32::from_be_bytes(len_buf) as usize;
    if header_len == 0 || header_len > V6_MAX_HEADER_BYTES {
        return Err(anyhow!("Invalid header size"));
    }
    let mut header_json = vec![0u8; header_len];
    f.read_exact(&mut header_json)?;
    let header: HeaderV6 = serde_json::from_slice(&header_json)
        .map_err(|_| anyhow!("Corrupt v6 header"))?;
    if header.version != VERSION_V6
        || header.algorithm != V6_ALGORITHM
        || header.key_wrap != V6_KEY_WRAP
        || header.chunk_size != CHUNK_SIZE
        || B64.decode(&header.magic_b64).ok().as_deref() != Some(MAGIC.as_slice())
    {
        return Err(anyhow!("Unsupported v6 header parameters"));
    }
    if header.slots.is_empty() || header.slots.len() > MAX_RECIPIENTS {
        return Err(anyhow!("Invalid number of recipient slots"));
    }
    let digest: [u8; 32] = Sha256::digest(&header_json).into();
    Ok((header_json, header, digest))
}

struct BodyResult {
    chain_hash: [u8; 32],
    ed_sig: Vec<u8>,
    dsa_sig: Vec<u8>,
}

/// A chunk-rekordok és a záradék szigorú feldolgozása. Minden chunk hossza,
/// nonce-a és AAD-ja pontosan az elvárt; a sink a visszafejtett chunk-okat kapja
/// (eltolással). A záradék után a fájlnak véget kell érnie.
fn process_v6_body<R: Read, F: FnMut(u64, &[u8]) -> Result<()>>(
    r: &mut R,
    header_digest: &[u8; 32],
    padded_len: u64,
    chunk_count: u64,
    content_cipher: &Aes256GcmSiv,
    mut sink: F,
) -> Result<BodyResult> {
    let mut chain = Sha256::new();
    for index in 0..chunk_count {
        let offset = index * CHUNK_SIZE as u64;
        let expected_plain = (padded_len - offset).min(CHUNK_SIZE as u64) as usize;

        let mut plain_len_be = [0u8; 4];
        r.read_exact(&mut plain_len_be)
            .map_err(|_| anyhow!("File truncated: chunk {index} is missing"))?;
        let mut cipher_len_be = [0u8; 4];
        r.read_exact(&mut cipher_len_be)?;
        let plain_len = u32::from_be_bytes(plain_len_be) as usize;
        let cipher_len = u32::from_be_bytes(cipher_len_be) as usize;
        if plain_len != expected_plain || cipher_len != expected_plain + AEAD_TAG_LEN {
            return Err(anyhow!("Unexpected chunk size at index {index}"));
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        r.read_exact(&mut nonce_bytes)?;
        if nonce_bytes != nonce_from_index(index) {
            return Err(anyhow!("Chunk sequence tampered or reordered at index {index}"));
        }
        let mut ciphertext = vec![0u8; cipher_len];
        r.read_exact(&mut ciphertext)?;

        for part in [&plain_len_be[..], &cipher_len_be[..], &nonce_bytes[..], &ciphertext[..]] {
            chain.update(part);
        }
        let last = index + 1 == chunk_count;
        let mut plaintext = Zeroizing::new(
            content_cipher
                .decrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: ciphertext.as_slice(),
                        aad: &chunk_aad(header_digest, index, last),
                    },
                )
                .map_err(|_| anyhow!("Chunk {index} failed authentication (tampered or corrupt)"))?,
        );
        if plaintext.len() != expected_plain {
            return Err(anyhow!("Chunk length mismatch at index {index}"));
        }
        sink(offset, plaintext.as_slice())?;
        plaintext.zeroize();
        ciphertext.zeroize();
    }

    let mut trailer_magic = [0u8; 8];
    r.read_exact(&mut trailer_magic)
        .map_err(|_| anyhow!("File truncated: the signature trailer is missing"))?;
    if &trailer_magic != V6_TRAILER_MAGIC {
        return Err(anyhow!("Corrupt signature trailer"));
    }
    let mut ed_sig = vec![0u8; ED25519_SIG_LEN];
    r.read_exact(&mut ed_sig)?;
    let mut dsa_sig = vec![0u8; ML_DSA_65_SIG_LEN];
    r.read_exact(&mut dsa_sig)?;
    let mut extra = [0u8; 1];
    if r.read(&mut extra)? != 0 {
        return Err(anyhow!("Unexpected data after the signature trailer"));
    }
    Ok(BodyResult {
        chain_hash: chain.finalize().into(),
        ed_sig,
        dsa_sig,
    })
}

// ───────────────────────── v6 visszafejtés ─────────────────────────

/// Mit tegyen a visszafejtés, ha a feladó nincs a névjegyek között?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderPolicy {
    /// Csak ismert névjegytől fogad el fájlt (alapértelmezett, biztonságos).
    ContactsOnly,
    /// Ismeretlen feladót is elfogad — az aláírás ettől még ellenőrzött, de a
    /// feladó személye nem megerősített.
    AcceptUnknown,
}

/// Ismeretlen feladó a `ContactsOnly` szabály mellett. A GUI ebből kínálja fel
/// a "hozzáadás névjegyként" lehetőséget.
#[derive(Debug, Clone)]
pub struct UnknownSenderError {
    pub fingerprint: String,
    pub claimed_name: String,
    pub bundle: PublicBundle,
}

impl std::fmt::Display for UnknownSenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The sender is not in your contacts (claims to be '{}', fingerprint {}). \
             Add them as a contact, or choose to accept unknown senders.",
            self.claimed_name,
            format_fingerprint(&self.fingerprint)
        )
    }
}

impl std::error::Error for UnknownSenderError {}

#[derive(Clone, Debug)]
pub struct SenderInfo {
    pub fingerprint: String,
    /// A feladó által megadott név (NEM hitelesített; a névjegy címkéje számít).
    pub claimed_name: String,
    pub bundle: PublicBundle,
    pub contact_label: Option<String>,
    pub verified: bool,
}

#[derive(Debug)]
pub struct V6Outcome {
    pub path: PathBuf,
    pub original_name: String,
    pub file_len: u64,
    pub created_unix: u64,
    pub sender: SenderInfo,
}

/// v6 fájl visszafejtése és a feladó ellenőrzése.
///
/// A kimenet csak akkor kerül a végleges helyére, ha MINDEN chunk hitelesítése
/// és a feladó hibrid aláírása is helyes; hibánál az ideiglenes fájl törlődik.
/// A szabály ellenőrzése a visszafejtés előtt, a (még nem hitelesített)
/// feladó-azonosítóval történik, így ismeretlen feladónál nem készül kimenet.
pub fn decrypt_v6(
    input: &Path,
    device_dir: &Path,
    password: &[u8],
    policy: SenderPolicy,
) -> Result<V6Outcome> {
    let identity = load_identity(device_dir)?;
    let secret = unlock_identity_secret(&identity, password)?;
    let own = load_own_keys(&identity, &secret)?;

    let mut fin = File::open(input)?;
    let (_header_json, header, header_digest) = read_v6_header(&mut fin)?;

    // ── Slotok végigpróbálása ──
    let mut file_key: Option<Zeroizing<[u8; 32]>> = None;
    for slot in &header.slots {
        if let Some(k) = v6_open_slot(&own, slot) {
            file_key = Some(k);
            break;
        }
    }
    let file_key = file_key
        .ok_or_else(|| anyhow!("This file is not addressed to this identity (or it is damaged)"))?;
    let keys = v6_derive_keys(&file_key);

    // ── Kulcs-elköteleződés: minden címzett ugyanazt a kulcsot kapta ──
    let commit = B64
        .decode(&header.key_commit_b64)
        .map_err(|_| anyhow!("Corrupt v6 header"))?;
    if commit.as_slice() != keys.commit.as_slice() {
        return Err(anyhow!(
            "Key commitment mismatch: the file was not built consistently for all recipients"
        ));
    }

    // ── Lezárt metaadat ──
    let meta_nonce = B64
        .decode(&header.meta_nonce_b64)
        .map_err(|_| anyhow!("Corrupt v6 header"))?;
    let meta_sealed = B64
        .decode(&header.meta_sealed_b64)
        .map_err(|_| anyhow!("Corrupt v6 header"))?;
    if meta_nonce.len() != NONCE_LEN || meta_sealed.len() > V6_MAX_META_BYTES {
        return Err(anyhow!("Corrupt v6 header"));
    }
    let meta_cipher = Aes256GcmSiv::new_from_slice(keys.meta.as_ref())
        .map_err(|e| anyhow!("meta cipher init: {e:?}"))?;
    let meta_pt = Zeroizing::new(
        meta_cipher
            .decrypt(
                Nonce::from_slice(&meta_nonce),
                Payload {
                    msg: meta_sealed.as_slice(),
                    aad: &meta_aad(&keys.commit),
                },
            )
            .map_err(|_| anyhow!("Metadata authentication failed (tampered or corrupt)"))?,
    );
    let meta: MetaV6 =
        serde_json::from_slice(&meta_pt).map_err(|_| anyhow!("Corrupt metadata"))?;
    if meta.file_len > V6_MAX_FILE_LEN
        || meta.padded_len != padded_length(meta.file_len)
        || meta.chunk_count != chunks_for(meta.padded_len)
        || meta.sender_name != clean_label(&meta.sender_name)
        || meta.pad.len() >= META_PAD_BLOCK
        || meta.pad.bytes().any(|b| b != b'0')
    {
        return Err(anyhow!("Inconsistent metadata"));
    }
    let sender_keys = meta.sender.decode()?;
    let sender_fp = meta.sender.fingerprint()?;

    // ── Feladó-szabály (a hitelesítés előtt, hogy ismeretlennél ne készüljön kimenet) ──
    let contacts = load_contacts(device_dir)?;
    let contact = find_contact(&contacts, &sender_fp);
    if contact.is_none() && policy == SenderPolicy::ContactsOnly {
        return Err(anyhow::Error::new(UnknownSenderError {
            fingerprint: sender_fp,
            claimed_name: meta.sender_name.clone(),
            bundle: meta.sender.clone(),
        }));
    }
    let sender = SenderInfo {
        fingerprint: sender_fp,
        claimed_name: meta.sender_name.clone(),
        bundle: meta.sender.clone(),
        contact_label: contact.map(|c| c.label.clone()),
        verified: contact.map(|c| c.verified).unwrap_or(false),
    };

    // ── Kimeneti hely, ideiglenes fájl ──
    let content_cipher = Aes256GcmSiv::new_from_slice(keys.content.as_ref())
        .map_err(|e| anyhow!("content cipher init: {e:?}"))?;
    let raw_name = Path::new(&meta.original_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("decrypted_file.bin");
    let safe_name = sanitize_filename(raw_name);
    let out_path = derive_safe_output_path(input, "decrypted_", &safe_name, "");
    let temp_path = temp_sibling_path(&out_path);
    let mut temp_file = private_new_file_options()
        .open(&temp_path)
        .with_context(|| format!("Cannot create {}", temp_path.display()))?;
    let mut guard = FileCleanupGuard {
        path: temp_path.clone(),
        success: false,
    };

    let file_len = meta.file_len;
    let body = process_v6_body(
        &mut fin,
        &header_digest,
        meta.padded_len,
        meta.chunk_count,
        &content_cipher,
        |offset, plaintext| {
            let (real, pad) = split_real(offset, plaintext, file_len);
            if pad.iter().any(|b| *b != 0) {
                return Err(anyhow!("Corrupt padding"));
            }
            temp_file.write_all(real)?;
            Ok(())
        },
    )?;

    // ── A feladó hibrid aláírása ──
    verify_hybrid(
        &sender_keys.ed25519,
        &sender_keys.ml_dsa,
        &v6_signed_message(&header_digest, &body.chain_hash),
        &body.ed_sig,
        &body.dsa_sig,
    )
    .map_err(|_| anyhow!("The sender's signature is invalid — the file was modified or forged"))?;

    temp_file.flush()?;
    temp_file.sync_all()?;
    drop(temp_file);

    // Végleges hely: hard link (nem ír felül), tartalékként átnevezés.
    let final_path = if out_path.exists() {
        derive_safe_output_path(input, "decrypted_", &safe_name, "")
    } else {
        out_path
    };
    match fs::hard_link(&temp_path, &final_path) {
        Ok(()) => {
            let _ = fs::remove_file(&temp_path);
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(anyhow!("{} already exists", final_path.display()));
        }
        Err(_) => {
            fs::rename(&temp_path, &final_path)
                .with_context(|| format!("Cannot create {}", final_path.display()))?;
        }
    }
    sync_parent_dir(&final_path);
    // Az ideiglenes fájl már nincs meg (hard link + törlés, vagy átnevezés).
    guard.success = true;

    Ok(V6Outcome {
        path: final_path,
        original_name: meta.original_name,
        file_len: meta.file_len,
        created_unix: meta.created_unix,
        sender,
    })
}

// ───────────────────────── 1. fázis tesztjei ─────────────────────────
//
// A kulcstárat igénylő tesztek automatikusan kihagyják magukat, ha az
// operációs rendszer hitelesítő-tára nem érhető el (lásd phase0_tests).
#[cfg(test)]
mod phase1_tests {
    use super::*;
    use crate::phase0_tests::{keystore_available, KEYSTORE_LOCK};

    const PW: &[u8] = b"correct horse battery staple 42";

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i * 31 + i / 251) % 251) as u8).collect()
    }

    fn new_identity(root: &Path, name: &str) -> PathBuf {
        let dev = root.join(name);
        generate_device_identity(&dev, PW).unwrap();
        dev
    }

    fn as_contact(dev: &Path, label: &str) -> Contact {
        let bundle = own_public_bundle(dev).unwrap();
        Contact {
            fingerprint: bundle.fingerprint().unwrap(),
            label: label.to_string(),
            bundle,
            verified: false,
            added_unix: 0,
        }
    }

    /// Alice és Bob kölcsönösen névjegye egymásnak.
    fn befriend(a: &Path, b: &Path) {
        let ca = as_contact(a, "Alice");
        let cb = as_contact(b, "Bob");
        add_contact(b, ca.bundle, "Alice").unwrap();
        add_contact(a, cb.bundle, "Bob").unwrap();
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("decrypted_") || n.contains(".tmp"))
            .collect()
    }

    fn fake_bundle() -> PublicBundle {
        let x = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let dk = DecapsulationKey768::generate();
        let seeds = generate_signing_seeds();
        let sp = signing_public_from_seeds(seeds.as_slice()).unwrap();
        PublicBundle {
            x25519_b64: B64.encode(x.as_bytes()),
            ml_kem_b64: B64.encode(dk.encapsulation_key().to_bytes().as_slice()),
            ed25519_b64: B64.encode(&sp.ed25519),
            ml_dsa_b64: B64.encode(&sp.ml_dsa),
        }
    }

    // ── tiszta függvények ──

    #[test]
    fn padme_properties() {
        assert_eq!(padded_length(0), 4096);
        assert_eq!(padded_length(1), 4096);
        assert_eq!(padded_length(4095), 4096);
        assert_eq!(padded_length(4096), 4096);
        let mut prev = 0;
        for len in (0u64..300_000).step_by(7).chain([1 << 20, (1 << 20) + 1, 3 << 30, u64::MAX >> 3]) {
            let p = padded_length(len);
            assert!(p >= len && p >= 4096, "len {len} -> {p}");
            assert!(p as f64 <= (len.max(4096)) as f64 * 1.125 + 1.0, "overhead too big: {len} -> {p}");
            assert_eq!(padded_length(p), p, "padding is not idempotent for {len}");
            if len < 300_000 {
                assert!(p >= prev, "padding is not monotonic at {len}");
                prev = p;
            }
        }
    }

    #[test]
    fn safety_number_is_symmetric_and_well_formed() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let n1 = safety_number(&a, &b);
        assert_eq!(n1, safety_number(&b, &a));
        assert_ne!(n1, safety_number(&a, &a));
        assert_eq!(n1.split(' ').count(), 12);
        assert!(n1.split(' ').all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn fingerprint_depends_on_every_key() {
        let base = fake_bundle();
        let fp = base.fingerprint().unwrap();
        assert_eq!(fp.len(), 64);
        assert_eq!(fp, base.fingerprint().unwrap());
        let other = fake_bundle();
        for variant in 0..4 {
            let mut b = base.clone();
            match variant {
                0 => b.x25519_b64 = other.x25519_b64.clone(),
                1 => b.ml_kem_b64 = other.ml_kem_b64.clone(),
                2 => b.ed25519_b64 = other.ed25519_b64.clone(),
                _ => b.ml_dsa_b64 = other.ml_dsa_b64.clone(),
            }
            assert_ne!(b.fingerprint().unwrap(), fp, "variant {variant}");
        }
    }

    #[test]
    fn hybrid_signature_needs_both_halves() {
        let seeds = generate_signing_seeds();
        let signer = HybridSigner::from_seeds(seeds.as_slice()).unwrap();
        let pubs = signing_public_from_seeds(seeds.as_slice()).unwrap();
        let (ed, dsa) = signer.sign(b"msg").unwrap();
        verify_hybrid(&pubs.ed25519, &pubs.ml_dsa, b"msg", &ed, &dsa).unwrap();
        assert!(verify_hybrid(&pubs.ed25519, &pubs.ml_dsa, b"msh", &ed, &dsa).is_err());
        let mut bad_ed = ed.clone();
        bad_ed[3] ^= 1;
        assert!(verify_hybrid(&pubs.ed25519, &pubs.ml_dsa, b"msg", &bad_ed, &dsa).is_err());
        let mut bad_dsa = dsa.clone();
        bad_dsa[100] ^= 1;
        assert!(verify_hybrid(&pubs.ed25519, &pubs.ml_dsa, b"msg", &ed, &bad_dsa).is_err());
        let other = signing_public_from_seeds(generate_signing_seeds().as_slice()).unwrap();
        assert!(verify_hybrid(&other.ed25519, &pubs.ml_dsa, b"msg", &ed, &dsa).is_err());
        assert!(verify_hybrid(&pubs.ed25519, &other.ml_dsa, b"msg", &ed, &dsa).is_err());
    }

    // ── identitás ──

    #[test]
    fn new_identity_has_signing_keys_and_legacy_identity_upgrades() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let dev = new_identity(root.path(), "dev");
        let id = load_identity(&dev).unwrap();
        assert!(!id.ed25519_public_key_b64.is_empty() && !id.ml_dsa_public_key_b64.is_empty());
        let secret = unlock_identity_secret(&id, PW).unwrap();
        assert_eq!(secret.len(), FULL_SK_LEN);

        // Visszalépés a régi, 96 byte-os alakra.
        let mut legacy = load_identity(&dev).unwrap();
        let mut salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let wrapped = wrap_with_password(
            &secret[..COMBINED_SK_LEN],
            PW,
            &salt,
            ARGON2_MEM_KIB,
            ARGON2_TIME_COST,
            ARGON2_LANES,
        )
        .unwrap();
        legacy.protected_private_key_b64 = B64.encode(protect_private_key(&wrapped).unwrap());
        legacy.argon2_salt_b64 = B64.encode(salt);
        legacy.ed25519_public_key_b64.clear();
        legacy.ml_dsa_public_key_b64.clear();
        write_file_atomic(&device_identity_path(&dev), &serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        assert!(own_public_bundle(&dev).is_err());

        // Régi (v5) fájl a frissítés ELŐTT.
        let plain = root.path().join("old.txt");
        fs::write(&plain, b"old v5 data").unwrap();
        let rec = RecipientPublic {
            fingerprint: legacy.fingerprint.clone(),
            public_key_b64: legacy.public_key_b64.clone(),
            ml_kem_public_key_b64: legacy.ml_kem_public_key_b64.clone(),
        };
        let v5 = encrypt_for_recipient(&plain, &rec, false).unwrap();

        // Rossz jelszóval a frissítés sem fut le, és nem módosít semmit.
        let before = fs::read(device_identity_path(&dev)).unwrap();
        assert!(ensure_signing_keys(&dev, b"definitely the wrong password").is_err());
        assert_eq!(before, fs::read(device_identity_path(&dev)).unwrap());

        let upgraded = ensure_signing_keys(&dev, PW).unwrap();
        assert_eq!(upgraded.public_key_b64, legacy.public_key_b64);
        assert_eq!(upgraded.ml_kem_public_key_b64, legacy.ml_kem_public_key_b64);
        assert_eq!(upgraded.fingerprint, legacy.fingerprint);
        assert!(!upgraded.ed25519_public_key_b64.is_empty());
        assert!(dev.join("identity.before-signing.json").exists());
        assert_eq!(unlock_identity_secret(&load_identity(&dev).unwrap(), PW).unwrap().len(), FULL_SK_LEN);
        // Újrahívás: nem generál új kulcsot.
        let again = ensure_signing_keys(&dev, PW).unwrap();
        assert_eq!(again.ed25519_public_key_b64, upgraded.ed25519_public_key_b64);

        // A régi v5 fájl és az új identitás: továbbra is nyitható.
        fs::remove_file(&plain).unwrap();
        let out = decrypt_on_this_device(&v5, &dev, PW).unwrap();
        assert_eq!(fs::read(out).unwrap(), b"old v5 data");
    }

    #[test]
    fn backup_v2_roundtrip_and_v1_compat() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let dev = new_identity(root.path(), "dev");
        let id = load_identity(&dev).unwrap();
        let bp = root.path().join("backup.2bbackup");
        let backup_pw = b"a totally different backup phrase 99";
        export_identity_backup(&dev, PW, backup_pw, &bp).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&bp).unwrap()).unwrap();
        assert_eq!(raw["version"], 2);

        let restored_dir = root.path().join("restored");
        let restored = restore_identity_from_backup(&restored_dir, &bp, backup_pw, PW).unwrap();
        assert_eq!(restored.ed25519_public_key_b64, id.ed25519_public_key_b64);
        assert_eq!(restored.ml_dsa_public_key_b64, id.ml_dsa_public_key_b64);
        assert_eq!(own_identity_fingerprint(&restored_dir).unwrap(), own_identity_fingerprint(&dev).unwrap());

        // Az aláíró publikus kulcsok az AAD részei: kicserélésük megakasztja a mentést.
        let mut tampered: serde_json::Value = raw.clone();
        tampered["ed25519_public_key_b64"] = serde_json::Value::String(B64.encode([7u8; 32]));
        let tp = root.path().join("tampered.2bbackup");
        fs::write(&tp, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(restore_identity_from_backup(&root.path().join("t"), &tp, backup_pw, PW).is_err());

        // Egy aláíró kulcs nélküli (régi) identitás v1 mentést ad, és az visszaállítható.
        let dev2 = new_identity(root.path(), "dev2");
        let id2 = load_identity(&dev2).unwrap();
        let secret = unlock_identity_secret(&id2, PW).unwrap();
        let mut legacy = load_identity(&dev2).unwrap();
        let mut salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let wrapped = wrap_with_password(&secret[..COMBINED_SK_LEN], PW, &salt, ARGON2_MEM_KIB, ARGON2_TIME_COST, ARGON2_LANES).unwrap();
        legacy.protected_private_key_b64 = B64.encode(protect_private_key(&wrapped).unwrap());
        legacy.argon2_salt_b64 = B64.encode(salt);
        legacy.ed25519_public_key_b64.clear();
        legacy.ml_dsa_public_key_b64.clear();
        write_file_atomic(&device_identity_path(&dev2), &serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        let bp1 = root.path().join("legacy.2bbackup");
        export_identity_backup(&dev2, PW, backup_pw, &bp1).unwrap();
        let raw1: serde_json::Value = serde_json::from_slice(&fs::read(&bp1).unwrap()).unwrap();
        assert_eq!(raw1["version"], 1);
        let rd2 = root.path().join("restored2");
        let r2 = restore_identity_from_backup(&rd2, &bp1, backup_pw, PW).unwrap();
        assert!(r2.ed25519_public_key_b64.is_empty());
        ensure_signing_keys(&rd2, PW).unwrap();
        assert!(own_public_bundle(&rd2).is_ok());
    }

    // ── meghívó és névjegyek ──

    #[test]
    fn invite_roundtrip_and_tamper_detection() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let alice = new_identity(root.path(), "alice");
        let bob = new_identity(root.path(), "bob");
        let invite_path = root.path().join("alice.2binvite");
        export_invite(&alice, PW, "Alice", &invite_path).unwrap();
        assert!(export_invite(&alice, PW, "   ", &root.path().join("x.2binvite")).is_err());
        assert!(export_invite(&alice, b"wrong password here!!", "Alice", &root.path().join("y.2binvite")).is_err());

        let v = read_invite(&invite_path).unwrap();
        assert_eq!(v.name, "Alice");
        assert_eq!(v.fingerprint, own_identity_fingerprint(&alice).unwrap());

        let (c, added) = import_invite(&bob, &invite_path, None).unwrap();
        assert!(added && !c.verified && c.label == "Alice");
        let (c2, added2) = import_invite(&bob, &invite_path, Some("Other name")).unwrap();
        assert!(!added2);
        assert_eq!(c2.label, "Alice", "an existing contact must not be silently renamed");
        // Saját meghívó nem importálható.
        assert!(import_invite(&alice, &invite_path, None).is_err());

        // Módosítások: név, kulcs, aláírás, ismeretlen mező, nem JSON.
        let original = fs::read_to_string(&invite_path).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        value["name"] = "Mallory".into();
        let p = root.path().join("t1.2binvite");
        fs::write(&p, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_invite(&p).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        value["bundle"]["x25519_b64"] = B64.encode([9u8; 32]).into();
        fs::write(&p, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_invite(&p).is_err());

        let mut value: serde_json::Value = serde_json::from_str(&original).unwrap();
        let mut sig = B64.decode(value["sig_ml_dsa_b64"].as_str().unwrap()).unwrap();
        sig[10] ^= 0x40;
        value["sig_ml_dsa_b64"] = B64.encode(&sig).into();
        fs::write(&p, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_invite(&p).is_err());

        // Mallory a saját aláírásával nem adhatja ki magát Alice-nek: csak az Alice
        // kulcsait és Mallory aláírását tartalmazó meghívó érvénytelen.
        let mallory = new_identity(root.path(), "mallory");
        let mp = root.path().join("m.2binvite");
        export_invite(&mallory, PW, "Alice", &mp).unwrap();
        let mut mv: serde_json::Value = serde_json::from_slice(&fs::read(&mp).unwrap()).unwrap();
        let av: serde_json::Value = serde_json::from_str(&original).unwrap();
        mv["bundle"] = av["bundle"].clone();
        fs::write(&p, serde_json::to_vec(&mv).unwrap()).unwrap();
        assert!(read_invite(&p).is_err());

        fs::write(&p, b"not json").unwrap();
        assert!(read_invite(&p).is_err());
        fs::write(&p, vec![b' '; 100_000]).unwrap();
        assert!(read_invite(&p).is_err());
    }

    #[test]
    fn contacts_management_and_tamper_detection() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let me = new_identity(root.path(), "me");
        assert!(load_contacts(&me).unwrap().is_empty());
        let b1 = fake_bundle();
        let b2 = fake_bundle();
        let fp1 = b1.fingerprint().unwrap();
        let (c1, _) = add_contact(&me, b1, "  Ann\u{0007}  ").unwrap();
        assert_eq!(c1.label, "Ann");
        add_contact(&me, b2, "").unwrap();
        assert_eq!(load_contacts(&me).unwrap().len(), 2);
        assert!(add_contact(&me, own_public_bundle(&me).unwrap(), "me").is_err());

        set_contact_verified(&me, &fp1, true).unwrap();
        rename_contact(&me, &fp1, "Annabelle").unwrap();
        let c = find_contact(&load_contacts(&me).unwrap(), &fp1).cloned().unwrap();
        assert!(c.verified && c.label == "Annabelle");
        assert!(set_contact_verified(&me, "nope", true).is_err());

        // A fájl módosítása: az ujjlenyomat nem egyezik a kulcsokkal → hiba.
        let path = me.join(CONTACTS_FILE);
        let good = fs::read(&path).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
        value["contacts"][0]["bundle"] = fake_bundle().into_json();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_contacts(&me).is_err());
        // Ismétlődés is hiba.
        let mut value: serde_json::Value = serde_json::from_slice(&good).unwrap();
        let first = value["contacts"][0].clone();
        value["contacts"][1] = first;
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(load_contacts(&me).is_err());
        fs::write(&path, &good).unwrap();

        remove_contact(&me, &fp1).unwrap();
        assert_eq!(load_contacts(&me).unwrap().len(), 1);
        assert!(remove_contact(&me, &fp1).is_err());
    }

    impl PublicBundle {
        fn into_json(self) -> serde_json::Value {
            serde_json::to_value(self).unwrap()
        }
    }

    // ── v6 ──

    #[test]
    fn v6_roundtrip_multi_recipient_for_many_sizes() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let alice = new_identity(root.path(), "alice");
        let bob = new_identity(root.path(), "bob");
        let carol = new_identity(root.path(), "carol");
        let dave = new_identity(root.path(), "dave");
        befriend(&alice, &bob);
        add_contact(&carol, as_contact(&alice, "A").bundle, "Alice").unwrap();
        add_contact(&dave, as_contact(&alice, "A").bundle, "Alice").unwrap();
        let rcpts = [as_contact(&bob, "Bob"), as_contact(&carol, "Carol")];
        assert!(!own_identity_fingerprint(&alice).unwrap().is_empty());

        let work = root.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let mut sizes_by_len = Vec::new();
        for len in [0usize, 1, 4095, 4096, 4097, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 2 * CHUNK_SIZE + 777] {
            let name = format!("file_{len}.bin");
            let src = work.join(&name);
            let content = data(len);
            fs::write(&src, &content).unwrap();
            let enc = encrypt_for_contacts(&src, &alice, PW, &rcpts, true, "Alice", false).unwrap();
            let enc_len = fs::metadata(&enc).unwrap().len();
            sizes_by_len.push((len, enc_len));
            assert_eq!(fs::read(&src).unwrap(), content, "the source must be untouched");

            // Minden címzett (és a feladó) ugyanazt kapja, a feladó azonosítva.
            for (dev, who) in [(&bob, "bob"), (&carol, "carol"), (&alice, "alice")] {
                let reader_contact_needed = who != "alice";
                let out = decrypt_v6(
                    &enc,
                    dev,
                    PW,
                    if reader_contact_needed { SenderPolicy::ContactsOnly } else { SenderPolicy::AcceptUnknown },
                )
                .unwrap_or_else(|e| panic!("{who} len {len}: {e:#}"));
                assert_eq!(fs::read(&out.path).unwrap(), content, "{who} len {len}");
                assert_eq!(out.original_name, name);
                assert_eq!(out.file_len, len as u64);
                assert_eq!(out.sender.fingerprint, own_identity_fingerprint(&alice).unwrap());
                assert_eq!(out.sender.claimed_name, "Alice");
                if reader_contact_needed {
                    assert_eq!(out.sender.contact_label.as_deref(), Some("Alice"));
                    assert!(!out.sender.verified);
                }
                fs::remove_file(&out.path).unwrap();
            }
            // Dave nincs a címzettek között.
            let err = decrypt_v6(&enc, &dave, PW, SenderPolicy::ContactsOnly).unwrap_err();
            assert!(format!("{err:#}").contains("not addressed"), "{err:#}");
            assert!(leftovers(&work).is_empty(), "{:?}", leftovers(&work));
            fs::remove_file(&enc).unwrap();
        }
        // Padmé: a kis fájlok titkosított mérete azonos (a fájlnév hossza különbözik,
        // de a lezárt metaadat 512 byte-os blokkokra kerekített).
        let small: Vec<u64> = sizes_by_len.iter().filter(|(l, _)| *l <= 4096).map(|(_, s)| *s).collect();
        assert!(small.windows(2).all(|w| w[0] == w[1]), "{sizes_by_len:?}");
    }

    #[test]
    fn v6_unknown_sender_policy_and_wrong_password() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let alice = new_identity(root.path(), "alice");
        let bob = new_identity(root.path(), "bob");
        add_contact(&alice, as_contact(&bob, "B").bundle, "Bob").unwrap();
        let src = root.path().join("hello.txt");
        fs::write(&src, b"hello").unwrap();
        let enc = encrypt_for_contacts(&src, &alice, PW, &[load_contacts(&alice).unwrap()[0].clone()], false, "Alice", false).unwrap();

        // Bob még nem ismeri Alice-t.
        let err = decrypt_v6(&enc, &bob, PW, SenderPolicy::ContactsOnly).unwrap_err();
        let unknown = err.downcast_ref::<UnknownSenderError>().expect("typed error");
        assert_eq!(unknown.claimed_name, "Alice");
        assert_eq!(unknown.fingerprint, own_identity_fingerprint(&alice).unwrap());
        assert!(leftovers(root.path()).is_empty());
        // A legacy belépési pont is a biztonságos alapértelmezést használja.
        assert!(decrypt_on_this_device(&enc, &bob, PW).is_err());
        assert!(leftovers(root.path()).is_empty());

        let ok = decrypt_v6(&enc, &bob, PW, SenderPolicy::AcceptUnknown).unwrap();
        assert!(ok.sender.contact_label.is_none() && !ok.sender.verified);
        assert_eq!(fs::read(&ok.path).unwrap(), b"hello");
        fs::remove_file(&ok.path).unwrap();

        // A GUI-folyamat: hozzáadás a hibából kapott csomaggal, majd újrapróbálás.
        add_contact(&bob, unknown.bundle.clone(), &unknown.claimed_name).unwrap();
        let again = decrypt_on_this_device(&enc, &bob, PW).unwrap();
        assert_eq!(fs::read(&again).unwrap(), b"hello");
        fs::remove_file(&again).unwrap();

        // Rossz jelszó.
        assert!(decrypt_v6(&enc, &bob, b"wrong password wrong", SenderPolicy::ContactsOnly).is_err());
        assert!(leftovers(root.path()).is_empty());
    }

    #[test]
    fn v6_detects_every_kind_of_tampering() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let alice = new_identity(root.path(), "alice");
        let bob = new_identity(root.path(), "bob");
        befriend(&alice, &bob);
        let work = root.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let src = work.join("big.bin");
        fs::write(&src, data(3 * CHUNK_SIZE + 100)).unwrap();
        let enc = encrypt_for_contacts(&src, &alice, PW, &[as_contact(&bob, "Bob")], false, "Alice", false).unwrap();
        let good = fs::read(&enc).unwrap();
        fs::remove_file(&enc).unwrap();

        // Az eredeti rendben van.
        let ok_path = work.join("ok.2brecip");
        fs::write(&ok_path, &good).unwrap();
        let ok = decrypt_v6(&ok_path, &bob, PW, SenderPolicy::ContactsOnly).unwrap();
        assert_eq!(fs::read(&ok.path).unwrap(), data(3 * CHUNK_SIZE + 100));
        fs::remove_file(&ok.path).unwrap();
        fs::remove_file(&ok_path).unwrap();

        let header_len = u32::from_be_bytes(good[9..13].try_into().unwrap()) as usize;
        let body_start = 13 + header_len;
        let trailer_len = 8 + ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;
        let trailer_start = good.len() - trailer_len;
        let record = |i: usize| body_start + i * (8 + NONCE_LEN + CHUNK_SIZE + AEAD_TAG_LEN);
        let find = |needle: &[u8]| good.windows(needle.len()).position(|w| w == needle).unwrap();

        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
        let flip = |pos: usize| {
            let mut b = good.clone();
            b[pos] ^= 0x01;
            b
        };
        // Fejléc: a lezárt metaadat egy karaktere, a kulcs-elköteleződés, a slotok.
        cases.push(("meta", flip(find(b"\"meta_sealed_b64\":\"") + 25)));
        cases.push(("commit", flip(find(b"\"key_commit_b64\":\"") + 20)));
        cases.push(("slot", flip(find(b"\"ct_b64\":\"") + 12)));
        cases.push(("kem ct", flip(find(b"\"kem_ct_b64\":\"") + 40)));
        cases.push(("header length", flip(12)));
        cases.push(("version", flip(8)));
        // Chunk-ok.
        cases.push(("chunk 0", flip(record(0) + 8 + NONCE_LEN + 5)));
        cases.push(("chunk 2 tag", flip(record(3) - 1)));
        cases.push(("chunk plain_len", flip(record(1) + 3)));
        cases.push(("chunk nonce", flip(record(1) + 8 + 2)));
        // Aláírás.
        cases.push(("trailer magic", flip(trailer_start)));
        cases.push(("ed25519 sig", flip(trailer_start + 8 + 10)));
        cases.push(("ml-dsa sig", flip(trailer_start + 8 + ED25519_SIG_LEN + 500)));
        // Csonkolás, toldás, csere.
        cases.push(("no trailer", good[..trailer_start].to_vec()));
        cases.push(("cut 1 byte", good[..good.len() - 1].to_vec()));
        cases.push(("drop last chunk", [&good[..record(3)], &good[trailer_start..]].concat()));
        cases.push(("extra byte", [good.clone(), vec![0u8]].concat()));
        {
            let mut b = good.clone();
            let (r0, r1, r2) = (record(0), record(1), record(2));
            let first: Vec<u8> = good[r0..r1].to_vec();
            let second: Vec<u8> = good[r1..r2].to_vec();
            b[r0..r1].copy_from_slice(&second);
            b[r1..r2].copy_from_slice(&first);
            cases.push(("swap chunks", b));
        }
        {
            // Ugyanaz a tartalom, másik fejléccel: a fejléc-hash az AAD és az aláírás része.
            let mut b = good.clone();
            let pos = find(b"\"chunk_size\":");
            b[pos + 14] ^= 0x01;
            cases.push(("chunk_size", b));
        }

        for (name, bytes) in cases {
            let p = work.join("tampered.2brecip");
            fs::write(&p, &bytes).unwrap();
            let result = decrypt_v6(&p, &bob, PW, SenderPolicy::ContactsOnly);
            assert!(result.is_err(), "tampering '{name}' was NOT detected");
            assert!(leftovers(&work).is_empty(), "'{name}' left files behind: {:?}", leftovers(&work));
            fs::remove_file(&p).unwrap();
        }
    }

    #[test]
    fn v6_sender_cannot_be_forged_with_swapped_signature() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let alice = new_identity(root.path(), "alice");
        let bob = new_identity(root.path(), "bob");
        let mallory = new_identity(root.path(), "mallory");
        befriend(&alice, &bob);
        add_contact(&mallory, as_contact(&bob, "B").bundle, "Bob").unwrap();
        let work = root.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let src = work.join("same.txt");
        fs::write(&src, b"the very same content").unwrap();
        let from_alice = encrypt_for_contacts(&src, &alice, PW, &[as_contact(&bob, "Bob")], false, "Alice", false).unwrap();
        let a_bytes = fs::read(&from_alice).unwrap();
        fs::remove_file(&from_alice).unwrap();
        let from_mallory = encrypt_for_contacts(&src, &mallory, PW, &[as_contact(&bob, "Bob")], false, "Alice", false).unwrap();
        let m_bytes = fs::read(&from_mallory).unwrap();
        fs::remove_file(&from_mallory).unwrap();

        // Mallory aláírását Alice fájljára ültetve érvénytelen (más fejléc-/lánc-hash).
        let trailer_len = 8 + ED25519_SIG_LEN + ML_DSA_65_SIG_LEN;
        let franken = [&a_bytes[..a_bytes.len() - trailer_len], &m_bytes[m_bytes.len() - trailer_len..]].concat();
        let p = work.join("franken.2brecip");
        fs::write(&p, franken).unwrap();
        assert!(decrypt_v6(&p, &bob, PW, SenderPolicy::ContactsOnly).is_err());
        assert!(leftovers(&work).is_empty());

        // Mallory saját fájlja "Alice" néven: Bob a feladót az ujjlenyomatról
        // ismeri fel, így Mallory nem Alice-ként, hanem ismeretlenként jelenik meg.
        let pm = work.join("from_mallory.2brecip");
        fs::write(&pm, &m_bytes).unwrap();
        let err = decrypt_v6(&pm, &bob, PW, SenderPolicy::ContactsOnly).unwrap_err();
        let unknown = err.downcast_ref::<UnknownSenderError>().unwrap();
        assert_ne!(unknown.fingerprint, own_identity_fingerprint(&alice).unwrap());
        assert_eq!(unknown.claimed_name, "Alice");
    }

    #[test]
    fn v6_delete_original_and_recipient_limits() {
        let _g = KEYSTORE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !keystore_available() {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let alice = new_identity(root.path(), "alice");
        let src = root.path().join("secret.txt");
        fs::write(&src, b"to be shredded").unwrap();
        // Címzett nélkül (és saját magunk nélkül) nincs mit titkosítani.
        assert!(encrypt_for_contacts(&src, &alice, PW, &[], false, "A", false).is_err());
        let enc = encrypt_for_contacts(&src, &alice, PW, &[], true, "A", true).unwrap();
        assert!(!src.exists(), "the original must be deleted after verification");
        let out = decrypt_v6(&enc, &alice, PW, SenderPolicy::AcceptUnknown).unwrap();
        assert_eq!(fs::read(&out.path).unwrap(), b"to be shredded");

        // 64 címzett még megy, 65 már nem.
        let many: Vec<Contact> = (0..MAX_RECIPIENTS)
            .map(|i| {
                let b = fake_bundle();
                Contact { fingerprint: b.fingerprint().unwrap(), label: format!("c{i}"), bundle: b, verified: false, added_unix: 0 }
            })
            .collect();
        fs::write(&src, b"x").unwrap();
        let big = encrypt_for_contacts(&src, &alice, PW, &many, false, "A", false).unwrap();
        fs::remove_file(&big).unwrap();
        assert!(encrypt_for_contacts(&src, &alice, PW, &many, true, "A", false).is_err());
        // Ismétlődő címzett egynek számít.
        let dup = vec![many[0].clone(), many[0].clone()];
        let ok = encrypt_for_contacts(&src, &alice, PW, &dup, false, "A", false).unwrap();
        let header = {
            let mut f = File::open(&ok).unwrap();
            read_v6_header(&mut f).unwrap().1
        };
        assert_eq!(header.slots.len(), 1);
    }
}
