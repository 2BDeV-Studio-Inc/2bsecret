_English below!_

# 2BSecret

_Figyelem! Töltse le az új .msi fájlt az újabb verzióért!_
_A Linux rendszerre szánt telepítő fáj 2026.06.09-től lesz elérhető!_
_A MacOS-re szánt telepítőfájlok 2026.06.10-től lesz elérhető!_
_Warning! Download the new .msi file for the newer version update!_
_Installation file for Linux systems will be available from 2026.06.09!_
_Installation file for MacOS systems will be available from 2026.06.10!_

A 2BSecret egy offline, címzetthez kötött (zero-trust) fájltitkosító: az egyik eszköz egy kiválasztott másik eszköznek titkosít egy fájlt, és csak az az eszköz tudja visszafejteni.

## 🔐 Röviden: hogyan működik

* Minden eszköz saját **hibrid kulcspárt** generál: **X25519 + ML-KEM-768** (post-quantum). A két publikus kulcsból együtt számolódik az eszköz **32 karakteres (128 bites) ujjlenyomata**.
* A privát kulcs két, egymástól független rétegben védve kerül a lemezre: **Argon2id** (a helyben megadott mesterjelszóból, 256 MiB / 3 iteráció / 4 szál) és az operációs rendszer hitelesítő-tárolója (**DPAPI** Windowson, **Secret Service / Keychain** Linuxon/macOSon).
* A fájl tartalma 1 MiB-os darabokban, **AES-256-GCM-SIV**-vel titkosított, fájlonként új véletlen kulccsal.
* A fájlkulcs, a címzett ujjlenyomata, a darabszám és az eredeti fájlnév egy **titkosított (sealed) metaadat-blokkban** van; egy megfigyelő a `.2brecip` fájlból nem tudja meg, kinek szól és mi van benne.
* **0.6.0-tól:** az identitáshoz **hibrid aláíró kulcspár** (Ed25519 + ML-DSA-65) is tartozik, így a v6 fájlokat a feladó aláírja, a címzett pedig ellenőrzi, kitől jött. Egy fájl **több címzettnek** is szólhat, a méretét **Padmé-párnázás** takarja, a partnereket **névjegyek** és **meghívófájlok** kezelik. Mindez szerver nélkül működik.

**Tipikus használat (v5, egy címzett)**

1. B eszközön: mesterjelszó megadása (és megerősítése), majd `Generate this device keypair`.
2. B eszközön: `Export my public key`, a JSON fájl elküldése az A eszközre.
3. A eszközön: `Import recipient public key`, B fájljának kiválasztása. **Az ujjlenyomatot érdemes egy másik csatornán (pl. telefonon) egyeztetni.**
4. A eszközön: fájl kiválasztása, `Encrypt for recipient`. (Opcionálisan az eredeti biztonságos törlése.)
5. A kapott `.2brecip` fájl elküldése B eszközre.
6. B eszközön: mesterjelszó, a fájl kiválasztása, `Decrypt on this device`.

A mesterjelszó bármikor cserélhető (`Change master password`); ez új sóval újra becsomagolja a privát kulcsot, de **nem változtatja meg** a kulcspárt és az ujjlenyomatot, így a címzetteknek nem kell újra importálniuk semmit.

**Megosztás névjegyekkel (0.6.0, v6, aláírt, több címzett)**

1. Mindkét félnél: mesterjelszó, a saját név megadása (`My name`), majd `Create my invite…`. A `.2binvite` fájl publikus, bármilyen csatornán elküldhető. Az első meghívó/titkosítás a régi identitásodhoz hozzáadja az aláíró kulcsokat (a kulcspár és az ujjlenyomat nem változik).
2. A másik fél `Import an invite…`: az aláírás ellenőrzése után a partner **nem megerősített** névjegyként megjelenik.
3. **Biztonsági szám egyeztetése egy másik csatornán** (telefon, személyesen): a névjegynél `Safety number`. Mindkét félnek ugyanazt a 60 számjegyet kell látnia. Ha egyezik: `They match — mark as verified`. Ez védi a meghívócserét a közbeékelődő támadótól.
4. Fájl kiválasztása, a címzettek bejelölése (egy vagy több), `Encrypt for selected contacts`. Az `Also encrypt for myself` bejelölve a saját küldött fájljaidat is visszaolvashatod.
5. A címzettek a megszokott `Decrypt on this device` gombbal fejtik vissza; a program kijelzi, kitől jött a fájl, és hogy a feladó megerősített-e. Ismeretlen feladónál a program rákérdez: hozzáadás névjegyként, egyszeri visszafejtés, vagy mégse.

# Összefoglaló: Változások a 0.3.0, a 0.4.0 és a jelenlegi (0.6.x / v5 + v6) verzió között

Az alábbi összefoglaló a régi kód (0.3.0, fájlformátum v2), a köztes 0.4.0 (v4) és a jelenlegi, hibrid post-quantum kód (0.6.x, fájlformátum v5 és v6) közötti különbségeket mutatja be.

A régi verzió jellemzői: csak Windows, DPAPI, `VERSION=2`, HKDF‑t használ, de számos biztonsági és funkcionális hiányossággal. A következő verziók ezeket orvosolták, platformfüggetlenné tették az alkalmazást, majd bevezették a hibrid, kvantumbiztos kulcscserét és a titkosított metaadat-blokkot.

## 🔧 Főbb változások

_A „—” jelentése: az adott verzióhoz nincs adat / nem releváns._

| Terület | Régi verzió (0.3.0 / v2) | Köztes (0.4.0 / v4) | Jelenlegi (0.6.x / v5 + v6) |
| :--- | :--- | :--- | :--- |
| **Verziószám / fájlformátum** | 0.3.0, fájlformátum v2 | 0.4.0, fájlformátum v4 | 0.6.0, fájlformátum v6 (aláírt, több címzett) az új megosztásnál; a v5 (`2BRECIP` mágikus bájtok + `VERSION = 5`) az `Encrypt for recipient` gombbal továbbra is írható, v3–v6 olvasható |
| **Platform** | Csak Windows (DPAPI) | Windows DPAPI + más OS keyring (cross‑platform) | Windows (DPAPI), Linux (Secret Service), macOS (Keychain); a `keyring` backendje platformonként explicit be van kapcsolva |
| **Kulcscsere** | X25519 | X25519 | **Hibrid X25519 + ML-KEM-768** (post-quantum); a header kulcsa mindkét kulcscseréből származik |
| **Kulcsvédelem** | DPAPI (user scope) | DPAPI (Windows) vagy AES‑256‑GCM‑SIV + OS keyring (Linux/macOS) | Kétrétegű: **Argon2id** mesterjelszó (256 MiB / 3 / 4, AES‑256‑GCM‑SIV wrap) + DPAPI / keyring; az X25519 és az ML-KEM kulcs egyben védett |
| **Header hitelesítés (AAD)** | Csak a `recipient_fingerprint` és `original_name` (nem teljes) | Teljes: tartalmazza az `ephemeral public key`-t, `chunk_size`-t, `chunk_count`-ot is | **Titkosított (sealed) metaadat-blokk**: fájlkulcs, címzett ujjlenyomata, darabszám, eredeti fájlnév; HKDF‑SHA256, az adott kulcscsere-példányhoz kötve |
| **Wrap nonce** | Statikus, csupa nulla (`WRAP_NONCE = [0u8;12]`) | Véletlenszerű, minden titkosításkor új | Véletlenszerű, minden titkosításkor új |
| **Chunk darabszám ellenőrzés** | Nincs | `chunk_count` a headerben, visszafejtéskor ellenőrzés | A darabszám a titkosított metaadatban van, visszafejtéskor ellenőrzött |
| **Chunk sorrend ellenőrzés** | Van (`nonce_from_index`) | Van (ugyanaz) | Van (ugyanaz); csonkolás és átrendezés az AEAD tag ellenőrzése előtt is kiderül |
| **Fájlnév sanitizálás** | Nincs (csak `file_name()` hívás) | `sanitize_filename()` – véd path traversal és veszélyes karakterek ellen | `sanitize_filename()` (veszélyes karakterek cseréje, vezető pont/szóköz levágása, 200 bájtos korlát) |
| **Memóriatakarítás** | Részleges (néhány `zeroize`) | Teljes (`Zeroizing` minden DPAPI/keyring kimenetre, `Secret` a fájlkulcsokra) | Teljes (`Zeroizing` a kulcsokra, jelszó‑ és header‑kulcsokra is) |
| **Hibakezelés GUI indításnál** | `fs::create_dir_all` `.unwrap()` helyett csendes hiba elnyomás | Kezelt hiba: státuszüzenetben jelzi, ha nem sikerült a könyvtár létrehozása | Kezelt hiba (ugyanaz) |
| **Output path generálás** | Egyszerű, nem törli a félig kész fájlokat | `FileCleanupGuard` – sikertelen művelet esetén automatikusan törli a kimenetet | `FileCleanupGuard` (ugyanaz) |
| **Side‑channel védelem** | Különböző hibaüzenetek (*„wrong recipient”*, *„tampered”*) | Egységes hibaüzenet a visszafejtésnél (*Decryption failed: ...*) | Egységes hibaüzenet (*Decryption failed: ...*) |
| **KDF** | v1 (SHA‑256) + v2 (HKDF) – visszafelé kompatibilis | Csak v4 (HKDF + bővített AAD) – de v3 fájlokat is olvas | HKDF‑SHA256 a header kulcshoz, Argon2id a jelszóból; v3 és v4 fájlokat is olvas |
| **Ujjlenyomat (fingerprint)** | X25519 kulcsból számolva | X25519 kulcsból számolva | v5: **32 hex karakter (128 bit)**, SHA‑256 az X25519 **és** az ML-KEM publikus kulcsból együtt (a régi 16 karakteres értéket is elfogadja). v6 névjegyeknél: **64 hex karakter (256 bit)** mind a négy publikus kulcs fölött |
| **Publikus kulcs importja** | — | — | Az ujjlenyomatot a kulcsokból **újraszámolja**, ellenőrzi a kulcshosszt (32 / 1184 bájt), eltérésnél elutasít; a fájl legfeljebb 64 KiB |
| **Meglévő identitás védelme** | — | — | A `Generate` **nem írja felül** a meglévő `identity.json`-t (`create_new` + `sync_all`) |
| **Keyring hibakezelés (Linux/macOS)** | — | — | Új védelmi kulcs **csak `NoEntry`** esetén jön létre; zárolt vagy elérhetetlen keyringnél hiba, a meglévő kulcs érintetlen marad; feloldáskor sosem jön létre új kulcs |
| **Jelszóerősség** | — | — | Új jelszavaknál (generálás, jelszócsere, mentés): legalább 12 karakter, minta-, sorozat- és gyakori szó-szűrés, becsült entrópia ≥ 64 bit; a meglévő jelszavak feloldását nem érinti |
| **Fájlírás (identitás, mentés)** | — | — | Atomikus: ideiglenes fájl + `fsync` + átnevezés; a kulcsfájlok Unixon 0600 jogosultságúak; generálásnál és jelszócserénél a lemezre írás előtt kör-ellenőrzés (a kulcs visszajön-e) |
| **Identitás-mentés** | — | — | Kifejezetten kért, külön jelszóval védett export (Argon2id + AES‑256‑GCM‑SIV), a kiírás után visszaellenőrzött; visszaállítás új mesterjelszóval, meglévő identitást nem ír felül. A 2-es mentési formátum az aláíró kulcsokat is tartalmazza (az aláíró publikus kulcsok az AAD részei); az 1-es mentések továbbra is visszaállíthatók |
| **Automatikus zárolás (GUI)** | — | — | 5 perc tétlenség után (vagy a `Lock now` gombra) a beírt jelszavak törlődnek a memóriából |
| **Eredeti biztonságos törlése** | — | — | A titkosított kimenet lemezre írva (`fsync`) és visszafejtéssel ellenőrizve (fejléc, darabszám, hossz, SHA‑256), csak ezután törlődik az eredeti |
| **Feladó-hitelesítés** | — | — | A v6 fájlokat a feladó **hibrid aláírással (Ed25519 + ML-DSA-65)** látja el a fejléc és az összes titkosított darab fölött; mindkét aláírás kell az érvényességhez. A v5 fájlokon továbbra sincs feladó-hitelesítés |
| **Aláíró kulcsok az identitásban** | — | — | Az identitás titka 160 bájt: X25519 ‖ ML-KEM seed ‖ Ed25519 seed ‖ ML-DSA seed, ugyanazon kétrétegű védelem alatt. Régi identitás az első mesterjelszó-megadáskor frissül (kulcspár és ujjlenyomat változatlan, a régi `identity.json` megmarad `identity.before-signing.json` néven, a csere előtt kör-ellenőrzéssel) |
| **Meghívó (`.2binvite`)** | — | — | Önaláírt fájl a négy publikus kulccsal és a névvel; mindkét aláírás, a kulcsok érvényessége és a szigorú szerkezet ellenőrzött; legfeljebb 64 KiB; publikus adat, bármilyen csatornán küldhető |
| **Névjegyek és megerősítés** | — | — | `contacts.json`: az azonosító a 256 bites ujjlenyomat; egy sérült, átírt vagy ismétlődést tartalmazó lista **hiba**, nem csendes kihagyás; 60 számjegyes, mindkét félnél azonos **biztonsági szám**; az új névjegy alapból „nem megerősített"; létező névjegyet egy újabb meghívó nem ír át |
| **Több címzett (v6)** | — | — | Legfeljebb 64 címzett fájlonként; címzettenként külön hibrid X25519 + ML-KEM-768 slot (a címzett kulcsaihoz kötve), véletlen sorrendben; **kulcs-elköteleződés**, így mindenki bizonyosan ugyanazt a fájlkulcsot kapja; a címzett kipróbálással találja meg a slotját, a fájlban nincs címzett-azonosító |
| **Fájlméret elrejtése (Padmé)** | — | — | A tartalom legalább 4096 bájtra, felette Padmé-szabály szerint (legfeljebb ~12% többlet) kerekített, így a titkosított méret csak durván árulkodik; a lezárt metaadat 512 bájtos blokkokra kerekített |
| **Darabok kötése (v6)** | — | — | Minden darab AAD-ja: a fejléc SHA-256-ja, a sorszám és az „utolsó darab" jelző; a darabok szigorú méret- és nonce-ellenőrzése; a záradék után a fájlnak véget kell érnie. Csonkolás, átrendezés, toldás, másik fejlécre cserélés észlelt |
| **Ismeretlen feladó** | — | — | Alapból csak ismert névjegytől fogad el fájlt; ismeretlennél a GUI felkínálja a hozzáadást vagy az egyszeri visszafejtést. A kimenet csak a teljes aláírás-ellenőrzés után kerül a végleges helyére, hibánál az ideiglenes fájl törlődik |
| **Windows jogosultság (manifest)** | — | `requireAdministrator` | `asInvoker` (nem kér rendszergazdai jogot) |
| **Függőségek** | `windows-dpapi`, `hmac` (saját HKDF) | Platformfüggő: `windows-dpapi` (Windows) vagy `keyring` (más), `hkdf` crate (standard) | `windows-dpapi` 0.2 (Windows); `keyring` 3.6.3 (`linux-native-sync-persistent` + `crypto-rust` Linuxon, `apple-native` macOS-en, OpenSSL nélkül); `hkdf`, `argon2`, `aes-gcm-siv`, `ml-kem` 0.3, `x25519-dalek` 2; 0.6.0-tól `ed25519-dalek` 2 és `ml-dsa` 0.1 |
| **Kód szervezése** | Minden egy `main.rs` fájlban (GUI + logika) | Szétválasztva: `lib.rs` (logika) + `main.rs` (GUI belépési pont) | `lib.rs` (identitás, v5) + `sharing.rs` (aláírás, meghívó, névjegyek, v6) + `sharing_ui.rs` (megosztás felülete) + `main.rs` (GUI) + `build.rs` (Windows erőforrások) |
| **Verziókezelés `build.rs`** | Statikus verzió (nem olvassa a `Cargo.toml`‑ból) | Automatikusan beolvassa a `CARGO_PKG_VERSION`‑t | A `winres` a verziót a `Cargo.toml`‑ból veszi, és beágyazza a manifestet; keresztfordításnál (Linux → Windows, MinGW) is működik |
| **Tesztek** | Nincsenek | `tests_windows_gui.rs`, `cross_platform.rs` (funkcionális + property‑alapú) | Ezek + v5 rossz címzett elutasítása, chunk‑átrendezés észlelése, többchunkos (> 1 MiB) körút, ujjlenyomat‑ és identitás‑védelmi tesztek, valamint a 0. fázis tesztjei: jelszóerősség, atomikus írás, mentés/visszaállítás és meghamisított mentés elutasítása, a törlés előtti ellenőrzés, a biztonságos törlés (időkorláttal), az automatikus zárolás; az 1. fázis tesztjei: Padmé-tulajdonságok, biztonsági szám, hibrid aláírás (mindkét fél kell), identitás-frissítés és mentés v2/v1, meghívó és névjegyek meghamisításának észlelése, v6 körút több címzettnek és sok méretre, 20 féle módosítási kísérlet észlelése (fejléc, darabok, aláírás, csonkolás, toldás, átrendezés), aláírás-csere, ismeretlen feladó szabálya, címzett-korlát |

## ✅ Amit az új verziók javítanak a régihez képest

### Biztonság
* **Feladó-hitelesítés (v6):** a fájlt a feladó hibrid aláírással látja el; a címzett csak akkor kap kimenetet, ha az aláírás és minden darab hiteles.
* **Több címzett, kulcs-elköteleződéssel:** egy fájl több embernek szólhat, és kriptográfiailag biztosított, hogy mindenki ugyanazt kapja.
* **Teljes header hitelesítés:** Már nem lehet észrevétlenül módosítani a `chunk_size`-t, az ephemeral public key-t vagy a `chunk_count`-ot.
* **Véletlen wrap nonce:** A régi fix nonce elméletileg gyengébb (bár a GCM‑SIV tolerálja, de nem ajánlott).
* **Fájlnév sanitizálás:** Kivédi a path traversal támadásokat (pl. `../../etc/passwd`).
* **Chunk darabszám ellenőrzés:** Érzékeli, ha a fájlt csonkították.
* **Memóriatakarítás:** A privát kulcs, fájlkulcs és egyéb érzékeny adatok garantáltan nullázódnak a `Zeroizing` segítségével.
* **Egységes hibaüzenet:** Csökkenti a side‑channel információszivárgást.
* **Hibrid, post-quantum kulcscsere:** Az X25519 mellé ML-KEM-768 került; a „most letárol, később visszafejt” típusú támadások ellen is véd. Mivel a két algoritmus együtt működik, az X25519 akkor is véd, ha az ML-KEM-ben hiba lenne.
* **Titkosított metaadat:** Az ujjlenyomat, a darabszám és a fájlnév nem látszik a `.2brecip` fájlból.
* **Kétrétegű kulcsvédelem:** Az Argon2id mesterjelszó és az OS hitelesítő-tár együtt kell a privát kulcs feloldásához.
* **Meghamisított publikus kulcs elleni védelem:** Importnál és használatkor az ujjlenyomat a kulcsokból újraszámolódik, így egy átírt kulcsú fájl nem adható el a valódi ujjlenyomattal.
* **Hosszabb ujjlenyomat:** 64 bitről 128 bitre nőtt, így célzott „hasonló ujjlenyomat” kereséssel szemben is elég tartalék marad.

### Platformfüggetlenség
* Linux és macOS rendszereken is működik (OS keyring + AES‑256‑GCM‑SIV a védelmi kulcs tárolására).
* A `keyring` backendje explicit be van kapcsolva; korábban backend nélkül az OS-szintű védelem Linuxon/macOS-en futásidőben nem működött.
* Nincs szükség OpenSSL-re (`libssl3`) a Linux csomaghoz.

### Megbízhatóság
* **`FileCleanupGuard`:** Sikertelen titkosítás/visszafejtés esetén nem marad szemét fájl.
* **Hibakezelés a könyvtár létrehozásánál:** Nem pánikol, hanem jelzi a problémát.
* **Az identitás nem veszhet el véletlenül:** a `Generate` nem írja felül a meglévő `identity.json`-t, és egy átmeneti keyring-hiba nem cseréli le a védelmi kulcsot.

### Karbantarthatóság
* A logika külön `lib.rs` fájlban van, a GUI csak a `main.rs`-ben – könnyebb tesztelni és újrafelhasználni.
* A verziószám a `Cargo.toml`-ból automatikusan bekerül az executable metaadatokba.
* A függőségek `Cargo.lock`-ban rögzítettek (`--locked` build), és RustSec advisory-audit is lefutott rajtuk.

## 📜 Változásnapló

### 0.6.0 (v6 fájlformátum; az 1. fázis és a 0. fázis a 0.5.0 után)
* **Új: hibrid aláíró kulcsok** (Ed25519 + ML-DSA-65) az identitásban; az identitás titka 160 bájt. Régi identitás az első mesterjelszó-megadáskor frissül (X25519/ML-KEM kulcsok és ujjlenyomat változatlan; a régi fájl `identity.before-signing.json` néven megmarad).
* **Új: meghívófájl (`.2binvite`)**, önaláírt, szigorúan ellenőrzött; **névjegyek** (`contacts.json`) 256 bites ujjlenyomattal; **60 számjegyes biztonsági szám**; megerősített/nem megerősített állapot.
* **Új: v6 fájlformátum:** több címzett (legfeljebb 64), hibrid KEM slotok kulcs-elköteleződéssel, a feladó hibrid aláírása a teljes fájlon, Padmé-párnázás, a fejlécre kötött darabok, szigorú feldolgozás. Az `Encrypt for selected contacts` gomb írja; a `Decrypt on this device` automatikusan felismeri.
* **Új: ismeretlen feladó kezelése** (alapból csak névjegytől fogad el fájlt; hozzáadás vagy egyszeri visszafejtés). A kimenet csak a teljes ellenőrzés után kerül a helyére.
* Az identitás-mentés 2-es formátumú (az aláíró kulcsokkal); az 1-es mentések továbbra is visszaállíthatók.
* A GUI görgethető; új szakasz: `Share with contacts`.
* Új függőségek: `ed25519-dalek` 2, `ml-dsa` 0.1 (a `Cargo.lock` frissült, használj `--locked` buildet).
* Fejlesztői/teszt profil: a nehéz kriptó-crate-ek optimalizáltak (a tesztek gyorsabbak), a release build nem változott.
* Verzió: 0.6.0.

A 0.5.0 és a 0.6.0 között (0. fázis) változott:
* A `Generate` nem írja felül a meglévő identitást; az `identity.json` írása `create_new` + `sync_all`.
* Publikus kulcs import/betöltés/titkosítás: az ujjlenyomat újraszámolása a kulcsokból, kulcshossz-ellenőrzés, 64 KiB-os fájlméret-korlát.
* Az ujjlenyomat 128 bitesre (32 hex karakter) bővült; a régi 16 karakteres értékek továbbra is elfogadottak.
* Keyring: új védelmi kulcs csak `NoEntry` esetén; a feloldás sosem hoz létre új kulcsot.
* `build.rs`: `winres`-alapú manifest-beágyazás abszolút útvonallal, MinGW keresztfordítás támogatása; a `2bsecret-manifest.rc` fájlra már nincs szükség.
* **Javítva: a „biztonságos törlés” végtelen ciklusba esett.** A `secure_delete_file` második (nullázó) köre a puffer `zeroize()`-olása után 0 hosszú pufferrel dolgozott, ezért soha nem ért véget, és az „Securely delete original file” jelölőnégyzet lefagyasztotta a programot. Regressziós teszt védi.
* Az eredeti biztonságos törlése előtt a titkosított kimenet `fsync`-elve van, és visszafejtéssel ellenőrzött (fejléc, darabszám, hossz, SHA‑256); hiba esetén az eredeti érintetlen marad, a hibás kimenet törlődik.
* Új identitások Argon2id paramétere: 256 MiB / 3 / 4 (korábban 64 MiB). A régi identitások a tárolt paraméterekkel változatlanul megnyílnak (a paraméterek nélküli, még régebbi identitások a régi értékekkel), az első jelszócsere az újra emeli őket. A fájlból betöltött paraméterekre felső korlát van.
* Jelszóerősség-ellenőrzés új jelszavaknál (generálás, jelszócsere, mentési jelszó).
* Az `identity.json` és az exportok írása atomikus (ideiglenes fájl + `fsync` + átnevezés), Unixon 0600 jogosultsággal; generáláskor és jelszócserekor kör-ellenőrzés a lemezre írás előtt.
* Új: jelszóval védett identitás-mentés és visszaállítás (`Export identity backup…`, `Restore identity from backup…`).
* Új: automatikus zárolás 5 perc tétlenség után és `Lock now` gomb.
* README frissítve.

### v5 fájlformátum (hibrid, post-quantum)
* Hibrid X25519 + ML-KEM-768 kulcscsere, titkosított metaadat-blokk (HKDF‑SHA256, a kulcscsere-példányhoz kötve).
* A 0.3.0/v2 → 0.4.0/v4 közti változásokat lásd a fenti táblázatban.

### 0.5.0
* A `keyring` explicit backend-feature-ökkel (`linux-native-sync-persistent` + `crypto-rust`, illetve `apple-native`); a `libssl3` .deb-függőség elhagyva.
* Windows manifest: `requireAdministrator` helyett `asInvoker`.
* `anyhow` 1.0.104 (RUSTSEC-2026-0190 javítása). A további RustSec-találatok (pl. `quick-xml`, `memmap2`, `webbrowser`, `event-listener`, „unmaintained” jelzések) a GUI-stack tranzitív függőségei, az alkalmazás fenyegetésmodelljében támadó által kontrollált bemenetről nem elérhetők.
* Új tesztek: v5 rossz címzett elutasítása, chunk-átrendezés észlelése, többchunkos körút.
* `SECURITY.md` és README frissítve.

### 0.4.0 (v4) és 0.3.0 (v2)
* Lásd a fenti táblázat első két oszlopát.

## ⚠️ Visszafelé kompatibilitás
* Az újabb formátumú fájlok nem olvashatók a régebbi kliensekkel (a v5 fájlokat a v4-ig terjedő kliensek, a v6 fájlokat a 0.5.x és régebbi kliensek nem nyitják meg).
* A jelenlegi kliens továbbra is olvassa a régi **v3**, **v4** és **v5** fájlokat. Az `Encrypt for recipient` gomb továbbra is v5 fájlt ír (egy címzett, aláírás nélkül), az `Encrypt for selected contacts` v6 fájlt.
* A régi identitások működnek; az aláíró kulcsok az első meghívó-készítéskor vagy v6 titkosításkor kerülnek hozzá (mesterjelszó kell hozzá). Ezután az identitás titka 160 bájtos; a régi `identity.json` `identity.before-signing.json` néven megmarad.
* A régi 16 karakteres ujjlenyomatok (és az azokat tartalmazó v5 fájlok, exportált publikus kulcsok) továbbra is működnek; az export már a 32 karakteres értéket adja.
* A régi, 64 MiB-os Argon2 paraméterű identitások változatlanul megnyílnak; az első jelszócsere az új paraméterekre emeli őket.
* Az identitás az operációs rendszer hitelesítő-tárához kötött (DPAPI felhasználói profil / keyring bejegyzés), ezért az `identity.json` önmagában **újratelepített rendszeren vagy másik felhasználói fiókban nem állítható vissza**. Készíts jelszavas mentést az `Export identity backup…` gombbal (visszaállítás: `Restore identity from backup…`), és jegyezd meg a mesterjelszót.

## 📦 Miben maradt a régi?
* A magas szintű kriptográfia: AES‑256‑GCM‑SIV a tartalomhoz, X25519 (immár az ML-KEM-768 mellett).
* A chunk‑olási mechanizmus (1 MiB blokkok, `nonce_from_index`) alapvetően ugyanaz.
* A GUI (`eframe` / `egui` 0.27) kinézete és működése hasonló (kivéve a jobb hibaüzeneteket).

## 🛠️ Fordítás

**Windows** (Rust + Visual Studio Build Tools „Desktop development with C++” csomaggal):

```
cargo build --release --locked
```

A kész fájl: `target\release\twobsecret.exe`.

**Linux** (Debian/Ubuntu):

```
sudo apt install build-essential pkg-config libdbus-1-dev libgtk-3-dev
cargo build --release --locked
```

A kész fájl: `target/release/twobsecret`.

**`.deb` csomag** (csak Linuxon vagy WSL-ben, Windowson nem működik):

```
cargo install cargo-deb
cargo deb --locked
```

A csomag a `target/debian/` mappába kerül.

## 🧪 Tesztelés
A régi verzióhoz nem tartoztak tesztek. Az újabb verziókhoz a `tests_windows_gui.rs` és `cross_platform.rs` fájlok biztosítják a funkcionális és property‑alapú teszteket, a v5 formátumhoz pedig tesztek vannak a rossz címzett elutasítására, a chunk-átrendezés észlelésére és a többchunkos (> 1 MiB) körútra, valamint az ujjlenyomat- és identitás-védelmi változtatásokra. A 0.6.0 a `lib.rs`-ben és a `sharing.rs`-ben további egységteszteket hoz (aláírás, meghívó, névjegyek, v6 körút és módosítás-észlelés).

```
cargo test --locked
```

A kulcstárat igénylő tesztek automatikusan kihagyják magukat, ha az operációs rendszer hitelesítő-tára nem érhető el (pl. fej nélküli Linux); teljes futtatáshoz kell egy működő Secret Service / Keychain / DPAPI. Fejlesztői buildben az Argon2 (256 MiB) miatt a teljes futás néhány percig tart.

## 🚧 Ismert korlátok és tervek
* **A v5 fájlokon továbbra sincs feladó-hitelesítés:** bárki, aki ismeri a publikus kulcsodat, készíthet neked érvényes v5 fájlt (ugyanez az `age` modellje). A v6 fájlokat a feladó aláírja; ezekre ez nem érvényes.
* **A meghívó önaláírt, ezért a kulcscserét csak a biztonsági szám egyeztetése védi.** Ha nem egyezteted egy másik csatornán, egy közbeékelődő támadó cserélheti a meghívót. A „nem megerősített" jelzés ezért látható a felületen.
* **Nincs előre-titkosság (forward secrecy):** a v6 slotok a címzett tartós kulcsaihoz kötöttek. Ha később kiszivárog valakinek a privát kulcsa (és a fájlt valaki eltette), a fájl visszafejthető. Terv: egyszer használatos előkulcsok (3. fázis).
* **Az aláírás letagadhatatlan:** a feladó aláírása bizonyíték arra, hogy ő küldte a fájlt (nincs „deniability").
* **A `contacts.json` nincs integritásvédve a helyi támadóval szemben:** aki írni tud a profilmappádba, kicserélheti egy névjegy kulcsait. A betöltés az ujjlenyomatot ellenőrzi, de egy összehangolt cseréhez a támadónak a helyi gépen kell lennie (ott a DPAPI/keyring sem véd). Terv: a lista aláírása/MAC-elése az identitás kulcsával.
* **A feladó megadott neve nem hitelesített:** a névjegy címkéje számít, a fájlban lévő név csak tájékoztató; az azonosítás az ujjlenyomaton alapul.
* **Nincs visszavonás:** egy elveszett vagy kompromittált identitást a partnereknek kézzel kell törölniük a névjegyeik közül.
* **Az ML-DSA aláírás determinisztikus változatú** (FIPS 204 megengedi); a tartomány-elválasztás az aláírt üzenet előtagjában van. Az `ml-dsa` és az `ed25519-dalek` crate-ekre ugyanaz érvényes, mint az `ml-kem`-re: viszonylag újak, de a hibrid felépítés miatt mindkét aláírás szükséges.
* **A jelszóerősség-ellenőrzés egyszerű heurisztika** (hossz, minták, gyakori szavak, becsült entrópia), nem egy teljes becslő (pl. zxcvbn). A privát kulcs védelme végső soron a jelszón múlik.
* **A DPAPI/keyring nem véd** az ugyanazon felhasználóként futó rosszindulatú programtól, ott csak a mesterjelszó véd. A kulcs nem TPM-hez/hardverhez kötött.
* **A mentés kézi:** az `Export identity backup…` gombbal kell elkészíteni és biztonságos helyen tartani; a program nem készít magától mentést. A mentés a kulcsot a külön mentési jelszóval védi, ezért az is legyen erős.
* **Biztonságos törlés:** a `secure_delete_file` kétszer felülírja a fájlt (véletlen bájtok, majd nullák), ami a fájlrendszer-szintű visszaállítás ellen hatásos, de kopásszabályozós SSD-n fizikai szinten nem garantált. A törlés előtt a titkosított kimenet lemezre kerül és ellenőrzött.
* **Az `ml-kem` crate viszonylag új.** A hibrid felépítés miatt az X25519 akkor is véd, ha az ML-KEM-ben hiba lenne.
* További ötletek: TPM/hardver-alapú kulcstárolás, saját szerver (postaláda) a megosztáshoz, előre-titkosság egyszer használatos előkulcsokkal.

## 🛡️ Biztonsági bejelentés és licenc
Biztonsági hibát **ne nyilvános issue-ban** jelents: lásd a [SECURITY.md](SECURITY.md) fájlt (e-mail: info@2bdevon.top, vagy GitHub privát advisory). Támogatott verzió: 0.6.0.

Licenc: MIT (lásd a [LICENSE](LICENSE) fájlt), © 2026 2BDeV Studio Inc.

<br>

---

# English Summary: Changes between 0.3.0, 0.4.0 and the current (0.6.x / v5 + v6) version

Below is a comparison between the old code (0.3.0, file format v2), the intermediate 0.4.0 (v4) and the current hybrid post-quantum code (0.6.x, file formats v5 and v6). The old version was Windows‑only, DPAPI, format v2, with several security gaps. The following versions fixed those, added cross‑platform support, and then introduced hybrid post-quantum key exchange and an encrypted metadata block.

## 🔐 In short: how it works

* Every device generates its own **hybrid keypair**: **X25519 + ML-KEM-768** (post-quantum). Both public keys are hashed together into a **32-character (128-bit) fingerprint**.
* The private key is stored on disk under two independent layers: **Argon2id** (derived from a locally set master password, 256 MiB / 3 passes / 4 lanes) and the operating system's credential store (**DPAPI** on Windows, **Secret Service / Keychain** on Linux/macOS).
* File content is encrypted in 1 MiB chunks with **AES-256-GCM-SIV** under a random per-file key.
* The file key, the recipient fingerprint, the chunk count and the original filename live inside an **encrypted (sealed) metadata block**; an observer of a `.2brecip` file cannot tell who it is for or what it contains.
* **Since 0.6.0:** each identity also carries a **hybrid signing key pair** (Ed25519 + ML-DSA-65), so v6 files are signed by the sender and the recipient can verify who sent them. A file can be addressed to **several recipients**, its size is hidden by **Padmé padding**, and partners are managed with **contacts** and **invite files**. All of this works without any server.

**Typical flow (v5, one recipient)**

1. On device B: enter a master password (and confirmation), then click `Generate this device keypair`.
2. On device B: click `Export my public key` and send the JSON file to device A.
3. On device A: click `Import recipient public key` and choose B's file. **Compare the fingerprint over a separate channel (e.g. by phone).**
4. On device A: select a file and click `Encrypt for recipient`. (Optionally securely delete the original.)
5. Send the resulting `.2brecip` file to device B.
6. On device B: enter the master password, select the file and click `Decrypt on this device`.

The master password can be changed at any time (`Change master password`); this re-wraps the private key with a fresh salt but does **not** change the keypair or fingerprint, so recipients never need to re-import anything.

**Sharing with contacts (0.6.0, v6, signed, multi-recipient)**

1. Both sides: enter the master password and your name (`My name`), then click `Create my invite…`. The `.2binvite` file is public and can travel over any channel. The first invite or encryption adds the signing keys to your existing identity (key pair and fingerprint stay the same).
2. The other side clicks `Import an invite…`: after the signature check the partner appears as a **not verified** contact.
3. **Compare the safety number over a separate channel** (phone, in person): click `Safety number` on the contact. Both of you must see the same 60 digits. If they match, click `They match — mark as verified`. This protects the invite exchange against a man in the middle.
4. Select a file, tick the recipients (one or more), click `Encrypt for selected contacts`. With `Also encrypt for myself` ticked you can also reopen your own sent files.
5. Recipients use the usual `Decrypt on this device`; the app shows who sent the file and whether the sender is verified. For an unknown sender the app asks: add as contact, decrypt once, or cancel.

## 🔧 Key changes

_"—" means no data for that version / not applicable._

| Area | Old version (0.3.0 / v2) | Intermediate (0.4.0 / v4) | Current (0.6.x / v5 + v6) |
| :--- | :--- | :--- | :--- |
| **Version / file format** | 0.3.0, file format v2 | 0.4.0, file format v4 | 0.6.0, file format v6 (signed, multi-recipient) for the new sharing; v5 (`2BRECIP` magic bytes + `VERSION = 5`) can still be written with `Encrypt for recipient`, v3–v6 can be read |
| **Platform** | Windows only (DPAPI) | Windows (DPAPI) + Linux/macOS (keyring) | Windows (DPAPI), Linux (Secret Service), macOS (Keychain); the `keyring` backend is explicitly enabled per platform |
| **Key exchange** | X25519 | X25519 | **Hybrid X25519 + ML-KEM-768** (post-quantum); the header key is derived from both exchanges |
| **Key protection** | DPAPI (user scope) | DPAPI on Windows, AES‑256‑GCM‑SIV + OS keyring on others | Two layers: **Argon2id** master password (256 MiB / 3 / 4, AES‑256‑GCM‑SIV wrap) + DPAPI / keyring; X25519 and ML-KEM key material protected together |
| **Header authentication (AAD)** | Only `recipient_fingerprint` + `original_name` | Full: includes ephemeral public key, `chunk_size`, `chunk_count` | **Sealed (encrypted) metadata block**: file key, recipient fingerprint, chunk count, original filename; HKDF‑SHA256, bound to the specific key-exchange instance |
| **Wrap nonce** | Static all‑zero | Random per encryption | Random per encryption |
| **Chunk count check** | None | `chunk_count` in header, verified on decrypt | Chunk count stored in the encrypted metadata, verified on decrypt |
| **Chunk order check** | Yes (`nonce_from_index`) | Yes (same) | Yes (same); truncation and reordering are detected even before the AEAD tag check |
| **Filename sanitisation** | None (only `file_name()`) | `sanitize_filename()` – prevents path traversal | `sanitize_filename()` (replaces dangerous characters, strips leading dots/spaces, 200-byte limit) |
| **Memory cleanup** | Partial (some `zeroize`) | Full (`Zeroizing` for all DPAPI/keyring outputs, `Secret` for file keys) | Full (`Zeroizing` for keys, password-derived and header keys too) |
| **Error handling on startup** | Ignores `fs::create_dir_all` error | Shows warning in status bar | Handled (same) |
| **Output cleanup** | None (partial files left) | `FileCleanupGuard` deletes on failure | `FileCleanupGuard` (same) |
| **Side‑channel** | Different error messages | Uniform error message for decryption failures | Uniform error message (*Decryption failed: ...*) |
| **KDF** | v1 (SHA‑256) + v2 (HKDF) – backwards compat | Only v4 (HKDF + extended AAD), but reads v3 files | HKDF‑SHA256 for the header key, Argon2id for the password; also reads v3 and v4 files |
| **Fingerprint** | Derived from the X25519 key | Derived from the X25519 key | v5: **32 hex characters (128 bit)**, SHA‑256 over the X25519 **and** ML-KEM public keys together (the old 16-character value is still accepted). v6 contacts: **64 hex characters (256 bit)** over all four public keys |
| **Public key import** | — | — | Fingerprint is **recomputed** from the keys, key lengths are checked (32 / 1184 bytes), mismatches are rejected; file size capped at 64 KiB |
| **Existing identity protection** | — | — | `Generate` **never overwrites** an existing `identity.json` (`create_new` + `sync_all`) |
| **Keyring error handling (Linux/macOS)** | — | — | A new protection key is created **only on `NoEntry`**; a locked or unavailable keyring is an error and the stored key stays untouched; unlocking never creates a new key |
| **Password strength** | — | — | For new passwords (generate, change, backup): at least 12 characters, pattern / sequence / common-word filters, estimated entropy ≥ 64 bit; unlocking existing passwords is unaffected |
| **File writes (identity, backup)** | — | — | Atomic: temporary file + `fsync` + rename; key files are 0600 on Unix; generation and password change run a round-trip self-check (does the key come back?) before writing to disk |
| **Identity backup** | — | — | Explicitly requested, separately password-protected export (Argon2id + AES‑256‑GCM‑SIV), re-verified after writing; restore with a new master password, never overwrites an existing identity. Backup format 2 also contains the signing keys (the signing public keys are part of the AAD); format 1 backups can still be restored |
| **Auto-lock (GUI)** | — | — | After 5 minutes of inactivity (or on `Lock now`) the typed passwords are cleared from memory |
| **Secure delete of the original** | — | — | The encrypted output is synced to disk (`fsync`) and verified by decrypting it (header, chunk count, length, SHA‑256) before the original is deleted |
| **Sender authentication** | — | — | v6 files carry the sender's **hybrid signature (Ed25519 + ML-DSA-65)** over the header and all encrypted chunks; both signatures are required. v5 files still have no sender authentication |
| **Signing keys in the identity** | — | — | The identity secret is 160 bytes: X25519 ‖ ML-KEM seed ‖ Ed25519 seed ‖ ML-DSA seed, under the same two-layer protection. An old identity is upgraded the first time the master password is entered (key pair and fingerprint unchanged, the old `identity.json` is kept as `identity.before-signing.json`, round-trip checked before the swap) |
| **Invite (`.2binvite`)** | — | — | Self-signed file with the four public keys and a name; both signatures, key validity and the strict structure are checked; 64 KiB limit; public data that can travel over any channel |
| **Contacts and verification** | — | — | `contacts.json`: the identifier is the 256-bit fingerprint; a damaged, altered or duplicated list is an **error**, not silently skipped; a 60-digit **safety number** that is identical on both sides; a new contact starts as "not verified"; a later invite never overwrites an existing contact |
| **Multiple recipients (v6)** | — | — | Up to 64 recipients per file; one hybrid X25519 + ML-KEM-768 slot per recipient (bound to the recipient's keys), in random order; a **key commitment** guarantees everyone gets the same file key; the recipient finds its slot by trial, so the file contains no recipient identifier |
| **Hiding the file size (Padmé)** | — | — | Content is padded to at least 4096 bytes and above that by the Padmé rule (at most ~12% overhead), so the encrypted size reveals only coarse information; the sealed metadata is rounded to 512-byte blocks |
| **Chunk binding (v6)** | — | — | Each chunk's AAD: the SHA-256 of the header, the index and a "last chunk" flag; strict size and nonce checks; the file must end after the trailer. Truncation, reordering, appending and moving chunks under another header are detected |
| **Unknown sender** | — | — | By default only files from known contacts are accepted; for an unknown sender the GUI offers to add them or to decrypt once. The output reaches its final location only after the full signature check; on failure the temporary file is removed |
| **Windows privileges (manifest)** | — | `requireAdministrator` | `asInvoker` (no administrator rights requested) |
| **Dependencies** | `windows-dpapi`, custom `hmac` | Platform‑specific: `windows-dpapi` (Windows) or `keyring` (others), uses `hkdf` crate | `windows-dpapi` 0.2 (Windows); `keyring` 3.6.3 (`linux-native-sync-persistent` + `crypto-rust` on Linux, `apple-native` on macOS, no OpenSSL); `hkdf`, `argon2`, `aes-gcm-siv`, `ml-kem` 0.3, `x25519-dalek` 2; since 0.6.0 also `ed25519-dalek` 2 and `ml-dsa` 0.1 |
| **Code organisation** | All in one `main.rs` | Separated `lib.rs` (logic) + `main.rs` (GUI entry) | `lib.rs` (identity, v5) + `sharing.rs` (signing, invite, contacts, v6) + `sharing_ui.rs` (sharing GUI) + `main.rs` (GUI) + `build.rs` (Windows resources) |
| **Version in `build.rs`** | Hardcoded | Reads `CARGO_PKG_VERSION` automatically | `winres` takes the version from `Cargo.toml` and embeds the manifest; also works when cross-compiling (Linux → Windows, MinGW) |
| **Tests** | None | `tests_windows_gui.rs`, `cross_platform.rs` (functional + property-based) | Those + v5 wrong-recipient rejection, chunk-reorder detection, multi-chunk (> 1 MiB) round trip, fingerprint and identity-protection tests, plus the Phase 0 tests: password strength, atomic writes, backup/restore and tampered-backup rejection, verification before delete, secure delete (with a timeout), auto-lock; the Phase 1 tests: Padmé properties, safety number, hybrid signature (both halves required), identity upgrade and backup v2/v1, detection of tampered invites and contacts, v6 round trip to several recipients over many sizes, detection of 20 kinds of tampering (header, chunks, signature, truncation, appending, reordering), signature swapping, the unknown-sender policy, the recipient limit |

## ✅ What the new versions fix

### Security
* **Sender authentication (v6):** the sender signs the file with a hybrid signature; the recipient only gets output if the signature and every chunk authenticate.
* **Several recipients with a key commitment:** one file can be addressed to several people, and it is cryptographically ensured that everyone gets the same content.
* **Full header authentication:** Prevents undetected modification of critical fields.
* **Random wrap nonce:** Better practice than static nonce.
* **Filename sanitisation:** Thwarts path traversal.
* **Chunk count check:** Detects truncated files.
* **Proper memory cleanup:** `Zeroizing` used for all sensitive data.
* **Uniform error message:** Reduces side‑channel leakage.
* **Hybrid post-quantum key exchange:** ML-KEM-768 next to X25519 protects against "harvest now, decrypt later" attacks. Because both algorithms are combined, X25519 still protects the data even if a flaw were found in ML-KEM.
* **Encrypted metadata:** The fingerprint, chunk count and filename are not visible in the `.2brecip` file.
* **Two-layer key protection:** The Argon2id master password and the OS credential store are both required to unlock the private key.
* **Protection against tampered public keys:** The fingerprint is recomputed from the keys on import and on use, so a file with swapped keys cannot pass as the genuine fingerprint.
* **Longer fingerprint:** Raised from 64 to 128 bits, leaving enough margin against targeted "look-alike fingerprint" searches.

### Cross‑platform
* Works on Linux and macOS using OS keyring + AES‑256‑GCM‑SIV for the protection key.
* The `keyring` backend is now explicitly enabled; previously, with no backend, OS-level protection failed at runtime on Linux/macOS.
* No OpenSSL (`libssl3`) needed for the Linux package.

### Reliability
* **`FileCleanupGuard`:** No leftover partial files on errors.
* Handles directory creation failure gracefully.
* **The identity cannot be lost by accident:** `Generate` never overwrites an existing `identity.json`, and a transient keyring error no longer replaces the protection key.

### Maintainability
* Logic separated into `lib.rs` – easier to test and reuse.
* Version automatically embedded from `Cargo.toml`.
* Dependencies are pinned in `Cargo.lock` (`--locked` builds) and have been run through a RustSec advisory audit.

## 📜 Changelog

### 0.6.0 (v6 file format; Phase 1 and Phase 0 after 0.5.0)
* **New: hybrid signing keys** (Ed25519 + ML-DSA-65) in the identity; the identity secret is 160 bytes. An old identity is upgraded the first time the master password is entered (X25519/ML-KEM keys and fingerprint unchanged; the old file is kept as `identity.before-signing.json`).
* **New: invite file (`.2binvite`)**, self-signed and strictly validated; **contacts** (`contacts.json`) with a 256-bit fingerprint; a **60-digit safety number**; verified / not verified state.
* **New: v6 file format:** multiple recipients (up to 64), hybrid KEM slots with a key commitment, the sender's hybrid signature over the whole file, Padmé padding, chunks bound to the header, strict parsing. Written by `Encrypt for selected contacts`; `Decrypt on this device` detects it automatically.
* **New: unknown-sender handling** (by default only files from contacts are accepted; add or decrypt once). The output reaches its place only after full verification.
* Identity backup uses format 2 (with the signing keys); format 1 backups can still be restored.
* The GUI is scrollable; new section: `Share with contacts`.
* New dependencies: `ed25519-dalek` 2, `ml-dsa` 0.1 (`Cargo.lock` was updated, use `--locked` builds).
* Dev/test profile: the heavy crypto crates are optimized (tests run faster); the release build is unchanged.
* Version: 0.6.0.

Changed between 0.5.0 and 0.6.0 (Phase 0):
* `Generate` no longer overwrites an existing identity; `identity.json` is written with `create_new` + `sync_all`.
* Public key import/load/encrypt: fingerprint recomputed from the keys, key lengths validated, 64 KiB file size cap.
* Fingerprint extended to 128 bits (32 hex characters); old 16-character values are still accepted.
* Keyring: a new protection key is created only on `NoEntry`; unlocking never creates a new key.
* `build.rs`: `winres`-based manifest embedding with an absolute path, MinGW cross-compile support; `2bsecret-manifest.rc` is no longer needed.
* **Fixed: "secure delete" fell into an infinite loop.** The second (zeroing) pass of `secure_delete_file` worked with a zero-length buffer after `zeroize()` emptied it, so it never ended and the "Securely delete original file" checkbox froze the app. A regression test covers it.
* Before the original is securely deleted, the encrypted output is `fsync`ed and verified by decrypting it (header, chunk count, length, SHA‑256); on failure the original stays untouched and the bad output is removed.
* Argon2id parameters for new identities: 256 MiB / 3 / 4 (was 64 MiB). Older identities still open with their stored parameters (even older ones without stored parameters use the old values); the first password change upgrades them. Parameters loaded from a file have an upper bound.
* Password strength check for new passwords (generate, change, backup password).
* Writing `identity.json` and exports is atomic (temporary file + `fsync` + rename) with 0600 permissions on Unix; generation and password change run a round-trip self-check before writing to disk.
* New: password-protected identity backup and restore (`Export identity backup…`, `Restore identity from backup…`).
* New: automatic lock after 5 minutes of inactivity and a `Lock now` button.
* README updated.

### v5 file format (hybrid, post-quantum)
* Hybrid X25519 + ML-KEM-768 key exchange, encrypted metadata block (HKDF‑SHA256, bound to the key-exchange instance).
* For the changes between 0.3.0/v2 and 0.4.0/v4, see the table above.

### 0.5.0
* `keyring` with explicit backend features (`linux-native-sync-persistent` + `crypto-rust`, and `apple-native`); the `libssl3` .deb dependency was dropped.
* Windows manifest: `asInvoker` instead of `requireAdministrator`.
* `anyhow` 1.0.104 (fixes RUSTSEC-2026-0190). The remaining RustSec hits (e.g. `quick-xml`, `memmap2`, `webbrowser`, `event-listener`, "unmaintained" notices) are transitive dependencies of the GUI stack and are not reachable with attacker-controlled input in this application's threat model.
* New tests: v5 wrong-recipient rejection, chunk-reorder detection, multi-chunk round trip.
* `SECURITY.md` and README updated.

### 0.4.0 (v4) and 0.3.0 (v2)
* See the first two columns of the table above.

## ⚠️ Backward compatibility
* Files in newer formats cannot be read by older clients (v5 files do not open in clients up to v4, v6 files do not open in 0.5.x and older).
* The current client still reads old **v3**, **v4** and **v5** files. `Encrypt for recipient` still writes a v5 file (one recipient, no signature), `Encrypt for selected contacts` writes a v6 file.
* Old identities keep working; the signing keys are added the first time you create an invite or encrypt in v6 (the master password is needed). After that the identity secret is 160 bytes; the old `identity.json` is kept as `identity.before-signing.json`.
* Old 16-character fingerprints (and v5 files / exported public keys containing them) keep working; export now produces the 32-character value.
* Old identities with the 64 MiB Argon2 parameters still open unchanged; the first password change upgrades them to the new parameters.
* The identity is bound to the operating system's credential store (DPAPI user profile / keyring entry), so `identity.json` alone **cannot be restored on a reinstalled system or another user account**. Make a password-protected backup with `Export identity backup…` (restore with `Restore identity from backup…`) and remember your master password.

## 📦 What stayed the same
* **Core crypto:** AES‑256‑GCM‑SIV for content, X25519 (now alongside ML-KEM-768).
* **Chunking mechanism:** 1 MiB blocks, `nonce_from_index`.
* **GUI look and feel:** `eframe`/`egui` 0.27.

## 🛠️ Building

**Windows** (Rust + Visual Studio Build Tools with the "Desktop development with C++" workload):

```
cargo build --release --locked
```

Output: `target\release\twobsecret.exe`.

**Linux** (Debian/Ubuntu):

```
sudo apt install build-essential pkg-config libdbus-1-dev libgtk-3-dev
cargo build --release --locked
```

Output: `target/release/twobsecret`.

**`.deb` package** (Linux or WSL only; does not work on Windows):

```
cargo install cargo-deb
cargo deb --locked
```

The package ends up in `target/debian/`.

## 🧪 Testing
The old code had no tests. The newer versions include functional and property tests (`tests_windows_gui.rs` and `cross_platform.rs`), and the v5 format adds tests for wrong-recipient rejection, chunk-reorder detection, multi-chunk (> 1 MiB) round trips, and the fingerprint and identity-protection changes. 0.6.0 adds further unit tests in `lib.rs` and `sharing.rs` (signatures, invite, contacts, v6 round trip and tamper detection).

```
cargo test --locked
```

Tests that need a key store skip themselves when the operating system's credential store is unavailable (e.g. headless Linux); a full run needs a working Secret Service / Keychain / DPAPI. In a debug build the full run takes a few minutes because of Argon2 (256 MiB).

## 🚧 Known limitations and plans
* **v5 files still have no sender authentication:** anyone who knows your public key can create a valid v5 file for you (the same model as `age`). v6 files are signed by the sender; this does not apply to them.
* **The invite is self-signed, so the key exchange is protected only by comparing the safety number.** If you do not compare it over another channel, a man in the middle can swap the invite. That is why the "not verified" marker is visible in the UI.
* **No forward secrecy:** v6 slots are bound to the recipient's long-term keys. If a private key leaks later (and someone kept the file), the file can be decrypted. Planned: one-time prekeys (Phase 3).
* **Signatures are not deniable:** the sender's signature proves that they sent the file.
* **`contacts.json` is not integrity-protected against a local attacker:** whoever can write to your profile folder can swap a contact's keys. Loading checks the fingerprint, but a coordinated swap needs the attacker on the local machine (where DPAPI/keyring do not help either). Planned: sign/MAC the list with the identity key.
* **The sender name given in a file is not authenticated:** the contact's label counts; the name inside the file is informational; identification is based on the fingerprint.
* **No revocation:** a lost or compromised identity must be removed by your partners from their contacts by hand.
* **ML-DSA signing uses the deterministic variant** (allowed by FIPS 204); domain separation is in the prefix of the signed message. The same caveat as for `ml-kem` applies to the `ml-dsa` and `ed25519-dalek` crates: relatively new, but because of the hybrid design both signatures are required.
* **The password strength check is a simple heuristic** (length, patterns, common words, estimated entropy), not a full estimator such as zxcvbn. The private key's protection ultimately depends on the password.
* **DPAPI/keyring do not protect** against malware running as the same user; only the master password does. The key is not TPM/hardware-backed.
* **Backups are manual:** create one with `Export identity backup…` and keep it somewhere safe; the app never makes one on its own. The backup protects the key with its own password, so make that one strong too.
* **Secure delete:** `secure_delete_file` overwrites the file twice (random bytes, then zeros). This is effective against filesystem-level recovery but not guaranteed against physical-media recovery on wear-leveling SSDs. Before deletion, the encrypted output is synced to disk and verified.
* **The `ml-kem` crate is relatively new.** Thanks to the hybrid design, X25519 still protects the data even if a flaw were found in ML-KEM.
* More ideas: TPM/hardware-backed key storage, your own server (mailbox) for sharing, forward secrecy with one-time prekeys.

## 🛡️ Security reports and license
Please **do not open a public issue** for security bugs: see [SECURITY.md](SECURITY.md) (e-mail: info@2bdevon.top, or a GitHub private advisory). Supported version: 0.6.0.

License: MIT (see [LICENSE](LICENSE)), © 2026 2BDeV Studio Inc.
