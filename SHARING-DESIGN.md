# 2BSecret Share: tervezet (v6 formátum + postaláda-szerver)

**Státusz:** tervezet. Nincs implementálva, és nem esett át külső biztonsági felülvizsgálaton. A kriptográfiai részletek (különösen a 5. fejezet) implementálás előtt formális modellezést és külső szakértői átnézést igényelnek.

**Cél:** egy fájl eljuttatása egyik eszközről a másikra úgy, hogy a szerver, a hálózat és (amennyire lehet) egy későbbi kulcskompromittálás sem tudja olvasni, minimális felhasználói lépéssel.

---

## 1. Fenyegetésmodell

**Védünk ellen:**

| Támadó | Amit nem érhet el |
| :--- | :--- |
| Teljesen rosszindulatú vagy feltört szerver | Fájltartalom, fájlnév, kulcsok. A szerver csak titkosított, azonos méretű blokkokat lát. |
| Hálózati támadó (lehallgatás, módosítás) | Ugyanez, plusz a kapcsolat nem hamisítható (kulcs-rögzítés). |
| „Most letárol, később visszafejt” (kvantumgép) | Minden kulcscsere hibrid: X25519 + ML-KEM-768. |
| Későbbi eszköz- vagy kulcslopás | A korábban lehallgatott fájlok (előre-titkosság, egyszer használatos kulcsokkal). |
| Hamis feladó | Minden fájl hibrid aláírást hordoz (Ed25519 + ML-DSA-65), a címzett ismert névjegyhez köti. |
| Kicserélt publikus kulcs | A meghívó ellenőrzi az ujjlenyomatot, kulcsváltozásnál az app megáll. |
| Ellopott, kikapcsolt eszköz | A privát kulcsok Argon2id + OS/hardver réteg mögött vannak. |

**Nem védünk ellen** (ezt őszintén ki kell mondani):

* Az eszközön futó rosszindulatú program vagy billentyűzetfigyelő, amíg az identitás fel van oldva.
* Gyenge jelszó. A program kikényszeríti a minimumot, de a jelszó az utolsó védelmi vonal.
* Metaadatok teljes elrejtése: a szerver látja az IP-címet, az időzítést és a (kerekített) méretet. Ez ellen az app mellett külső eszköz (saját VPN, Tor) véd, az appba nem építünk VPN-t.
* A felhasználó hibája: elveszett jelszó vagy elveszett eszköz mentés nélkül.

A „bombabiztos” nem létezik. A cél az, hogy a fenti listán belül minden támadáshoz kriptográfiai vagy az eszköz fizikai kompromittálását igénylő erőfeszítés kelljen.

## 2. Döntések összefoglalva

| Kérdés | Döntés | Indok |
| :--- | :--- | :--- |
| Mozog-e privát kulcs eszközök között? | **Soha** (kivéve a kifejezetten kért, jelszavas mentést) | Ami nem mozog, az nem szivároghat ki. |
| Több eszköz | **Eszközönként saját identitás**, a feladó minden címzett-eszköznek külön „slotot” készít | Egyszerűbb és biztonságosabb, mint közös kulcs párosítása. |
| Kulcscsere | **Hibrid X25519 + ML-KEM-768** (a meglévő v5 alapja) | Kvantumbiztos és klasszikus védelem együtt. |
| Előre-titkosság | **Egyszer használatos hibrid prekey-ek** (Signal PQXDH-szerű) | Később ellopott kulcs a régi fájlokat nem nyitja. |
| Feladó-hitelesítés | **Hibrid aláírás: Ed25519 + ML-DSA-65**, mindkettőnek érvényesnek kell lennie | Hosszú életű, ezért kvantumbiztosnak kell lennie. |
| Szállítás | **TLS 1.3 + szerverkulcs-rögzítés (pinning)**, CA nélkül is működik | LAN-on domain és Let's Encrypt nélkül is használható. |
| Postaláda-azonosító | **Véletlen 128 bites, rotálható**, nem az ujjlenyomatból számolt | Ne lehessen az identitást a szerveren követni. |
| Feltöltés jogosultsága | **Névjegyenkénti, visszavonható feltöltő-token** | Nincs nyílt feltöltő; nincs fiók. |
| Szerver | Kis Rust program, **nincs fiók, nincs felhasználói adat** | Kis támadási felület. |
| Linkes megosztás | **Nem része** | A linkkel bárki visszafejthet, ellentétes a céllal. |
| In-app VPN | **Elvetve** | Az E2E mellett nincs mit védenie, rendszergazdai jogot kér, NAT-gondok. |
| Közös identitás több eszközön | **Elvetve** | Privát kulcsot kellene mozgatni. |

## 3. Kulcsok és identitás

Minden eszköz generál:

| Kulcs | Algoritmus | Élettartam | Cél |
| :--- | :--- | :--- | :--- |
| **IK_sig** (identitás-aláíró) | Ed25519 + ML-DSA-65 | hosszú | Feladó-hitelesítés, prekey-aláírás |
| **SPK** (aláírt prekey) | X25519 + ML-KEM-768 | kb. 1 hét (rotálva) | Tartalék, ha elfogynak az egyszeriek |
| **OPK[ ]** (egyszer használatos prekey-ek) | X25519 + ML-KEM-768 | egy fájl | Előre-titkosság |
| **MAK** (postaláda-hitelesítő) | Ed25519 | hosszú | Belépés a postaládába (online hitelesítés, ezért elég a klasszikus) |

* Az SPK-t és az OPK-kat az IK_sig mindkét algoritmusával alá kell írni. A feladó ellenőrzi az aláírást, mielőtt használná.
* Az OPK-kból egy köteg (pl. 100) van fent. Ha 20 alá esik, az app feltölt újat.
* **Ujjlenyomat:** az IK_sig összes publikus kulcsából SHA-512/256 (256 bit). Megjelenítve Signal-féle „biztonsági szám” (60 számjegy) és QR-kód.
* Minden privát kulcs a jelenlegi kétrétegű védelemmel kerül lemezre (Argon2id + DPAPI/keyring), lehetőség szerint hardveres (TPM / Secure Enclave / StrongBox) csomagolóval kiegészítve.

## 4. Meghívó és névjegy hozzáadása

A meghívó (QR-kód vagy szöveges kód) tartalma:

```
version, server_url, server_spki_pin (SHA-256),
mailbox_id, upload_token (egyszer használatos, rövid lejáratú),
IK_sig publikus kulcsok (Ed25519 + ML-DSA-65), ujjlenyomat (256 bit)
```

1. B megjeleníti a meghívót. A meghívó a feltöltő-tokent is tartalmazza, ezért **csak azon a csatornán adható át, ahol B és A találkozik** (kamera, vagy bizalmas üzenet).
2. A beolvassa. Az app a QR-ból **automatikusan összeveti az ujjlenyomatot**, így nincs külön ellenőrzés. Kézi bevitelnél a biztonsági számot kell összehasonlítani.
3. A az első fájlja előtt egy „névjegy-elfogadás” üzenetet küld B postaládájába (A saját meghívójával, B-nek titkosítva). B appja a beolvasás után automatikusan felveszi A-t. **Egy beolvasással mindkét irány megvan.**
4. **Kulcsváltozás:** ha egy névjegy identitása megváltozik, az app megáll, és csak újabb ellenőrzés után folytatja. Csendes elfogadás nincs.
5. **Eszköz visszavonása:** a felhasználó kiveheti az elveszett eszközt a saját eszközlistájából, és a névjegyek szólnak a feladóknak, hogy többé ne készítsenek neki slotot.

## 5. A fájlüzenet (v6 formátum)

A v6 egy fájl, több címzett-eszköz. A jelenlegi v5 egycímzettes, ezért új verzió kell.

### 5.1 Szerkezet

```
[Külső fejléc (nyílt, de a titkosított részek AAD-ja)]
    MAGIC "2BRECIP\0", VERSION = 6, slot_count, chunk_size, padded_len

[Slotok, címzett-eszközönként]
    slot_tag     = H(címzett-eszköz azonosítója ‖ prekey_id) (rövid, nem hivatkozható identitásra)
    prekey_id
    eph_x_pub    (32 bájt)
    kem_ct       (1088 bájt, ML-KEM-768)
    wrapped_file_key = AES-256-GCM-SIV(header_key, véletlen nonce, file_key, AAD = külső fejléc ‖ slot_tag)

[Titkosított metaadat-blokk]   (file_key alatt, AES-256-GCM-SIV)
    sender_ik_fingerprint, eredeti fájlnév, chunk_count, msg_id, időbélyeg, fájlméret,
    sender_signature (Ed25519 + ML-DSA-65)

[Adat-chunkok]  1 MiB, AES-256-GCM-SIV, nonce a chunk sorszámából (mint v5), padding a végén
```

### 5.2 Kulcsszármaztatás slotonként

A feladó a címzett-eszköz egy OPK-ját használja (ha nincs, az SPK-t, ekkor ennek a fájlnak az előre-titkosságát a SPK rotációja korlátozza).

```
(kem_ct, ss_kem) = ML-KEM-768.Encaps(OPK.ek)
ss_x             = X25519(eph_x_priv, OPK.x_pub)
header_key       = HKDF-SHA256(
                      salt = eph_x_pub ‖ kem_ct ‖ OPK.x_pub ‖ H(OPK.ek) ‖ címzett_IK_ujjlenyomat,
                      ikm  = ss_x ‖ ss_kem,
                      info = "2BSecret v6 slot key")
```

A kombináló lépés a **publikus kulcsokat és a rejtjelezett szöveget is tartalmazza** (X-Wing-szerű kötés), így egy később felfedezett gyengeség sem engedi a részek átkötését.

### 5.3 Feladó-hitelesítés

* A `sender_signature` a következő adatokra készül, hibrid módon: tartomány-elválasztó szöveg ‖ külső fejléc ‖ az összes slot ‖ címzettek ujjlenyomatai ‖ a metaadat ‖ **a titkosított adat-chunkok SHA-256 lánchash-e**.
* A feladó identitása a titkosított blokkban van, ezért a szerver nem látja, ki küldte.
* A címzett a visszafejtés során számolja a lánchasht, és **az aláírás ellenőrzése után** véglegesíti a kimeneti fájlt. Ismeretlen feladó esetén az app alapból elutasít, vagy kifejezett jóváhagyást kér.

### 5.4 Előre-titkosság és az ára

* Sikeres visszafejtés és aláírás-ellenőrzés után a címzett **biztonságosan törli** az OPK privát felét. Ugyanarra a fájlra újabb visszafejtés nem lehetséges, ezért a felhasználónak el kell mentenie a kapott fájlt. Erről az app egyértelműen figyelmeztet.
* Aki újra is vissza akar tudni fejteni, annak két mód közül választ:
  * **Postaláda (alapértelmezett):** előre-titkos, egyszeri.
  * **Archív:** a címzett statikus kulcsára készül (a mostani v5 viselkedés), újra visszafejthető, de nincs előre-titkossága. Az app jelzi ezt.
* Az OPK-t csak sikeres visszafejtés után töröljük, lejárat után (pl. 30 nap) pedig a megmaradtat is. Egy hibás üzenet így nem éget el kulcsot.
* **Visszajátszás elleni védelem:** az OPK egyszer használatos, a törlése után ugyanaz az üzenet nem nyitható meg újra.

### 5.5 Méretrejtés

A tartalom **Padmé-paddinggel** kerül kerekítésre, így a szerver csak durva méretet lát (a kiszivárgó információ logaritmikusan kicsi).

## 6. Postaláda-szerver

Egy kicsi, felhasználófiók nélküli Rust szolgáltatás. Az eszközök kulcsa a „fiók”.

| Végpont | Jogosultság | Cél |
| :--- | :--- | :--- |
| `PUT /v1/m/{mid}/prekeys` | postaláda-tulajdonos (MAK aláírás) | SPK és OPK-k feltöltése |
| `POST /v1/m/{mid}/bundle` | névjegy feltöltő-tokenje | Egy címzett-bundle lekérése. A szerver **atomikusan** kiad egy OPK-t, és jelöli használtként. |
| `PUT /v1/m/{mid}/files/{fid}/{part}` | névjegy feltöltő-tokenje | Fájl feltöltése, újraindítható darabokban |
| `GET /v1/m/{mid}/files` | postaláda-tulajdonos | Érkezett fájlok listája |
| `GET /v1/m/{mid}/files/{fid}/{part}` | postaláda-tulajdonos | Letöltés |
| `DELETE /v1/m/{mid}/files/{fid}` | postaláda-tulajdonos | Nyugtázás, a szerver azonnal töröl |

* **Hitelesítés:** a tulajdonos kihívás-válasz aláírással lép be, amely a TLS-csatornához van kötve (exporter-kötés), így továbbítani nem lehet.
* **Feltöltő-token:** névjegyenként véletlen 256 bit, a szerver csak a hash-ét tárolja. Visszavonható. Kvóta és sebességkorlát tokenenként, így egy kompromittált névjegy sem tudja kimeríteni a kulcsokat vagy a tárat.
* **Tárolás:** csak átlátszatlan bájtok. Alapértelmezett lejárat 7 nap, nyugtázás után azonnali törlés. Nincs fájlnév, nincs felhasználónév.
* **Naplózás:** alapból nincs IP-napló.
* **Visszajátszás/elavult bundle:** az SPK és az OPK-k aláírása időbélyeget tartalmaz, a feladó elutasítja a N napnál régebbi bundle-t, így a szerver nem tud régi kulcsot ráerőltetni.
* **Működés:** nem root, csak olvasható fájlrendszer, Docker; LAN-módban öntanúsítvány + pin, domain-módban normál tanúsítvány + pin.

## 7. Szállítási réteg

* **TLS 1.3**, `rustls`, a kliens a meghívóban kapott **szerverkulcs-ujjlenyomatot (SPKI pin)** ellenőrzi. Domain-módban a CA-ellenőrzés mellett is érvényes a pin.
* Ha a rustls kriptoszolgáltatója támogatja, a **hibrid X25519 + ML-KEM TLS-kulcscsere** be van kapcsolva.
* A pin cseréje: a szerver két pint hirdet (aktuális és következő), így a rotáció nem szakítja meg a kapcsolatot.
* A TLS csak mélységi védelem: minden tartalom akkor is E2E titkosított, ha a TLS-t feltörnék.

## 8. Kliens oldali védelem

* **Jelszó:** minimum 12 karakter vagy erősségellenőrzés (zxcvbn ≥ 3), jelmondat-generátor.
* **Argon2id:** a jelenlegi 64 MiB / 3 / 4 helyett célérték kb. 1 másodperc feloldási idő, legalább 256 MiB; a paraméterek az identitásfájlban vannak, így a régiek is megnyílnak.
* **Memória:** `Zeroizing`, `mlock`/`VirtualLock`, core dump és Windows hibajelentés-dump tiltása, a feloldás csak a művelet idejére tart, **tétlenség esetén 5 perc után az app automatikusan zár**.
* **Fájlírás:** minden kulcsfájl atomikusan íródik (ideiglenes fájl + `fsync` + átnevezés).
* **Mentés:** az egyetlen kijárat a privát kulcsnak a **jelszóval védett, kifejezetten kért export** (Argon2id + AES-256-GCM-SIV), figyelmeztetéssel.
* **Biztonságos törlés előtt:** a kimeneti fájl `fsync`-je és próbadekódolás.
* **Naplózás:** titkos adat soha nem kerül naplóba, nincs telemetria.

## 9. Implementációs szabályok

* **Nincs saját primitív.** Csak auditált, széles körben használt komponensek: RustCrypto, `rustls`. Az `ml-kem` és az `ml-dsa` viszonylag új, ezért a hibrid felépítés kötelező, és a crate-ek állapotát (audit, ismert hibák) a kiadás előtt újra ellenőrizni kell.
* A protokoll külön crate-ben, `#![forbid(unsafe_code)]`-dal.
* Tesztvektorok, property-alapú tesztek, **fuzzolás** (`cargo-fuzz`) minden bemeneti elemzőre (fejléc, slotok, meghívó, szerverkérések).
* Összehasonlítások állandó idejűek (`subtle`), minden származtatásnál tartomány-elválasztó (`info`) szöveg.
* **Nincs visszaminősítés:** a kliens a minimális elfogadott verziót kikényszeríti, a v5-ös fájlok csak az „Archív” módban nyílnak.
* CI: `cargo audit`, `cargo deny`, `cargo vet`; `--locked` build; reprodukálható build, aláírt kiadások, SBOM.
* **A kiadás előtt:** a kézfogás formális modellezése (Tamarin vagy ProVerif), majd külső szakértői audit. Ennek elvégzése nélkül nem szabad „biztonságosként” hirdetni.

## 10. Megvalósítási fázisok

| Fázis | Tartalom | Szerver kell? |
| :--- | :--- | :--- |
| **0. Keményítés** (kész, 0.5.x utáni kiadatlan állapot) | Jelszóerősség, atomikus írás, mentés/export, `fsync` + próbadekódolás törlés előtt, Argon2id emelés, automatikus zárolás | nem |
| **1. Identitás és névjegyek** (kész, 0.6.0) | IK_sig (hibrid), meghívó (fájl, nem QR, lásd a 12. fejezetet), v6 formátum (többcímzetteses, feladó-aláírás, Padmé) a jelenlegi kézi fájlátadással; a kulcsváltozás-figyelés a 12. fejezet szerint egyszerűsödött | nem |
| **2. Postaláda** | Szerver, TLS + pinning, feltöltő-tokenek, „húzd rá, küldd el” felület | igen |
| **3. Előre-titkosság** | SPK/OPK kezelés, bundle-kiadás, törlés használat után | igen |
| **4. Lezárás** | Hardveres kulcstárolás, TLS PQ, formális modell, külső audit, aláírt csomagok | igen |

Az 1. fázis szerver nélkül is használható, és a 0. fázis már ma javítja a jelenlegi programot.

## 11. Ismert kockázatok és nyitott kérdések

* **Kulcsok elfogyása:** egy rosszindulatú névjegy kimerítheti az OPK-kat. Ellene a tokenenkénti sebességkorlát véd, a tartalék az SPK (gyengébb előre-titkosság az adott időszakra).
* **IK_sig ellopása:** a támadó a tulajdonos nevében küldhet. Helyreállítás: új identitás és minden névjegy újraellenőrzése.
* **Szerver mint metaadat-forrás:** IP, időzítés, durva méret. Saját szerveren (LAN vagy saját domain) ez a saját adatod.
* **Eszközvesztés:** a visszavonás csak akkor hatásos, ha a névjegyek értesülnek róla.
* **Ismeretlen a `ml-dsa` crate pontos kiforrottsága** a megvalósítás időpontjában; ez a 9. fejezetben szereplő ellenőrzés tárgya.
* Elvetett ötletek (ha később mégis felmerülnek): linkes megosztás, közös identitás több eszközön, beépített VPN, szerveroldali kulcskönyvtár bizalmi kulcsokkal.

## 12. Az 1. fázis tényleges megvalósítása (0.6.0): eltérések a tervtől

Az 1. fázis a fenti tervből szerver nélkül megvalósítható részt adja. Ahol a megvalósítás eltér a tervtől, itt az indoklás. A 3., 4., 5. fejezet a teljes (3. fázisig tartó) célállapotot írja le, ez a fejezet az aktuális kódot.

| Terv | Megvalósítva az 1. fázisban | Miért |
| :--- | :--- | :--- |
| Meghívó **QR-kód** vagy szöveges kód | Meghívó **fájl** (`.2binvite`), önaláírt | A négy publikus kulcs együtt kb. 3,2 KB (ML-KEM 1184 + ML-DSA 1952 + 2×32 bájt), ez meghaladja a QR-kód kapacitását (kb. 2,9 KB bináris adat a legnagyobb méretben). Szerver nélkül a meghívó nem is hordoz szerver-URL-t vagy tokent. A QR később, a 2. fázisban kerülhet vissza egy rövid, a kulcsokat csak ujjlenyomattal hivatkozó formában. |
| Ujjlenyomat: SHA-512/256 az IK_sig kulcsairól | **SHA-256, 256 bit, mind a négy publikus kulcs fölött** (X25519, ML-KEM, Ed25519, ML-DSA), tartomány-elválasztással és hossz-előtagokkal | Az identitás a teljes kulcskészlet; a v5 ujjlenyomat (128 bit, két kulcs) a régi fájlokhoz változatlan marad. |
| Biztonsági szám + QR automatikus egyeztetés | 60 számjegyes biztonsági szám (SHA-512 alapú, a két ujjlenyomatból, sorrendfüggetlenül), kézi egyeztetés, „megerősítettnek jelölés” | QR nincs, lásd fent. A névjegy alapból „nem megerősített”, és a felület ezt végig jelzi. |
| `slot_tag` + `prekey_id` a slotokban | **Nincs slot-azonosító:** a címzett a slotjait kipróbálással nyitja | A fájl így semmilyen címzett-azonosítót nem tartalmaz (jobb adatvédelem); a költség címzettenként egy ML-KEM-dekapszuláció (max. 64 slot). |
| OPK/SPK előkulcsok, előre-titkosság | **Még nincs:** a slotok a címzett tartós X25519 + ML-KEM kulcsaihoz kötöttek | Az előkulcsokhoz szerver kell (3. fázis). Az 1. fázis v6 fájljai ezért a v5-tel azonos előre-titkossági szinten vannak: ha a címzett privát kulcsa később kiszivárog, és a fájl megvan, visszafejthető. A slot kulcs-levezetése a címzett kulcsait már most tartalmazza (X-Wing-szerű kötés), így a 3. fázis csak a kulcsforrást cseréli. |
| `sender_signature` a metaadat-blokkban | Az aláírás a fájl **végén egy záradékban** van, a feladó publikus csomagja a lezárt metaadatban | Az aláírás a titkosított chunkok lánchash-e fölött készül, amit csak a chunkok kiírása után ismerünk; így a titkosítás egy menetben, memóriában tartott fájl nélkül megy. A visszafejtés a kimenetet ideiglenes fájlba írja, és csak a sikeres aláírás-ellenőrzés után teszi a helyére. |
| Aláírt adat: külső fejléc, slotok, metaadat, lánchash | Fejléc SHA-256 (slotokkal és a lezárt metaadattal együtt) ‖ a chunk-rekordok láncolt SHA-256-ja, tartomány-elválasztóval; mindkét aláírás (Ed25519 és ML-DSA-65) kell | A chunk AAD-ja ezen felül a fejléc-hash, a sorszám és az „utolsó chunk” jelző. |
| — (a tervben nincs) | **Kulcs-elköteleződés** a fejlécben (HKDF-ből levezetett érték a fájlkulcsról) | Többcímzetteses fájlnál egy rosszindulatú feladó különböző kulcsokat tehetne a különböző slotokba. A GCM-SIV nem kulcs-elkötelező, ezért az elköteleződés kényszeríti, hogy mindenki ugyanazt a kulcsot kapja. |
| — | **Lezárt metaadat 512 bájtos blokkokra kerekítve** | A fájlnév hossza és a hosszok számjegyei ne látsszanak a fejléc méretéből. |
| Padmé | Padmé, legalább 4096 bájt, legfeljebb 64 címzett | A kis fájlok mérete nem különböztethető meg. |
| Kulcsváltozás-figyelés: az app megáll és újabb ellenőrzést kér | A névjegy azonosítója az ujjlenyomat. **Egy új kulcsú partner új, ismeretlen identitásként jelenik meg**, és az „ismeretlen feladó” szabály (alapból elutasít) vonatkozik rá; a régi névjegy érintetlen marad | Csendes lecserélés így lehetetlen. Külön „ez a névjegy kulcsot váltott” üzenet és kulcs-migráció még nincs. |
| Névjegy-elfogadó üzenet a postaládába (4/3. pont) | Nincs, a meghívócsere kétirányú, kézi | Szerver nélkül nincs hová küldeni. A 2. fázisban jön. |
| Eszköz visszavonása | Nincs | Visszavonási lista és értesítés a postaládával együtt értelmes (2. fázis). |
| A titkosítás nem kér jelszót (v5) | **A v6 titkosítás kéri a mesterjelszót** | Az aláíráshoz a titkos aláíró kulcsot fel kell oldani. A régi identitások aláíró kulcsai ekkor jönnek létre (egyszeri, kör-ellenőrzött frissítés, a régi `identity.json` megmarad). |

### Amit az 1. fázis garantál

* **Hitelesség:** a visszafejtett fájlt a feladó mindkét aláíró kulcsa aláírta, és minden bájt (fejléc, slotok, chunkok sorrendje és tartalma) hiteles; módosítás, csonkolás, toldás, átrendezés, aláírás-csere kimutatható.
* **Egyezés:** minden címzett pontosan ugyanazt a tartalmat kapja (kulcs-elköteleződés).
* **Adatvédelem a megfigyelővel szemben:** a fájlból nem látszik a feladó, a címzettek, a fájlnév, a pontos méret.
* **Kvantum-ellenállás:** a kulcscsere és az aláírás is hibrid (klasszikus + posztkvantum), mindkét fél kell az érvényességhez.

### Amit az 1. fázis NEM garantál

* **Előre-titkosság:** lásd fent (3. fázis).
* **Letagadhatóság:** az aláírás bizonyíték a feladóra (nincs „deniability”).
* **A meghívócsere hitelessége** a biztonsági szám önálló egyeztetése nélkül: a meghívó önaláírt, tehát a közbeékelődő támadót csak az egyeztetés fogja meg.
* **Helyi támadó elleni védelem a névjegyek fájlján:** a `contacts.json` ujjlenyomatait a betöltés ellenőrzi, de a fájl nincs MAC-elve (4. fázis: a lista védelme az identitás kulcsával).
* **Külső audit, formális modell:** még nem történt (lásd a 9. fejezetet). A formátum új, ezért kiadás előtt független szakértői átnézés javasolt.
