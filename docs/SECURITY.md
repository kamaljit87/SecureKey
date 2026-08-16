# SecureKey — Security Architecture

This document describes the security redesign of SecureKey's password-storage
architecture: the threat model, the cryptographic design, the migration path
from the old plaintext format, and the ESP32-S3 platform security features
(Flash Encryption / Secure Boot / NVS Encryption) that harden the device
further in production. It also states plainly what this architecture does
**not** protect against.

**No cryptography was invented for this project.** Every cryptographic
primitive is a call into mbedTLS (bundled with the ESP32 Arduino core) or the
ESP32-S3 hardware RNG — see [Cryptographic primitives used](#cryptographic-primitives-used).

---

## 1. Threat model

| # | Threat | Old (v1) behavior | New (v2) behavior |
|---|---|---|---|
| 1 | Flash chip desoldered/dumped | `/db.bin` is plaintext `PassRecord` structs — every password readable with a hex editor | `/db.bin` is AES-256-GCM ciphertext per record; unreadable without the master key, which is never stored |
| 2 | FFat partition read via any means (JTAG, `esptool.py read_flash`, debug UART) | Same as #1 | Same as #1 — ciphertext only. **With Flash Encryption enabled (production)**, the raw NAND image is also encrypted at the flash-controller level, so even the ciphertext structure/metadata is hidden |
| 3 | Full firmware dump (`esptool.py read_flash 0 0x1000000 dump.bin`) | Recovers plaintext vault + plaintext PIN string from NVS | Recovers only: encrypted vault, PBKDF2 salt, wrapped (still-encrypted) master key. PIN is never in the dump because it was never stored |
| 4 | Device stolen while **locked** | Recovers plaintext DB from flash directly (bypasses PIN entirely — PIN only gated the UI, not the data) | Attacker must brute-force the PIN through PBKDF2-HMAC-SHA256 (50,000 iterations) for every guess; there is no faster path since the master key only exists as GCM-wrapped ciphertext |
| 5 | Repeated PIN guessing on-device | Escalating lockout (30s/60s/2m/5m), fail count in NVS | Same escalating lockout, **plus** every guess costs a real PBKDF2 computation (~150-300ms on S3) even if the on-device counter were bypassed — see [PIN security](#4-pin-security) |
| 6 | Firmware reflash / modification | No protection (dev and prod identical) | **Development**: no protection (by design, for iteration speed). **Production**: Secure Boot v2 rejects any firmware not signed with the project's private key — see [Flash Encryption / Secure Boot](#6-flash-encryption--secure-boot-esp32-s3) |
| 7 | Serial output inspection | `Serial.printf` logged plaintext passwords, PINs-adjacent data, and full record dumps | All password/username/PIN/key values are never logged, in any build; operational logs are gated behind `SECUREKEY_DEBUG` (theme.h) — see [Serial logging audit](#8-serial-logging-audit) |
| 8 | Temporary physical access to an **unlocked** device | Full vault plaintext in PSRAM at all times after unlock | Only non-secret metadata (id/title/folder/favorite) is resident; a specific record's plaintext exists in RAM only while its detail screen is open, and is wiped on navigation away — see [Reduced plaintext residence time](#5-reduced-plaintext-residence-time) |
| 9 | USB host connects | HID keyboard enumerates; typing was already gated behind explicit user taps, but no separate audit had been done | Confirmed: USB HID only ever transmits when the user taps a specific field on an already-unlocked, on-screen record. A USB host cannot request "all passwords" — there is no such protocol surface, HID is output-only and reactive to on-device taps |
| 10 | BLE central connects | Pairing gate (Accept/Reject/Block) already existed and requires unlock first | Unchanged design, confirmed correct; hardened by ensuring locking always drops `bleAuthorized` and wipes in-flight key material |

---

## 2. Vulnerabilities found in the original implementation

1. **PIN stored in plaintext** — `Preferences::putString("pin", settings.pin)` / `getString("pin","1234")` in `loadSettings()`/`saveSettings()`. Anyone with NVS read access (flash dump, debug tools) recovered the literal PIN.
2. **Password database stored entirely in plaintext** — `/db.bin` was a raw array of fixed-size `PassRecord` structs with `char password[48]` etc. written directly to FFat with no encryption at all.
3. **PIN doubled as the only secret and was directly comparable** — `strcmp(pinEntry, settings.pin)`. No KDF, no salt, no iteration cost — a stored value an attacker could read and replay directly.
4. **Hard-coded demo credentials compiled into every build** — `dbSeed()` contained 24 realistic-looking site/username/password combinations (Amazon, Gmail, HDFC Bank, etc.) that would seed into a fresh vault.
5. **Sensitive serial logging** — `Serial.printf("[DB] Load id=%u OK title='%s' pass_len=%u")`, `Serial.printf("[ADD] Saving new id=%u title='%s' user='%s' pass='%s' url='%s'")`, `Serial.printf("[HID] typeViaHID('%s')")` (called directly with the decrypted password), `Serial.printf("[BLE] hidBlePrint('%s')")`, and similar — several call sites printed passwords, usernames, or full records to the serial console.
6. **No authenticated encryption anywhere** — nothing in the original design used AES-GCM, ChaCha20-Poly1305, or any AEAD construction; there was no ciphertext, so the question of nonce reuse etc. didn't even arise.
7. **Whole database decrypted-equivalent residence in PSRAM** — since the DB was never encrypted, the entire vault (title/user/pass/url/note for the whole index, functionally) was one `FFat.open()` + sequential read away at all times after boot, unlocked or not (the file itself has no access control).
8. **No crash-safety analysis for the encryption path** — moot in v1 (nothing was encrypted), but the transactional-rewrite pattern (`/db_tmp.bin` → rename) needed to be re-verified once ciphertext, nonces, and auth tags were introduced (see [Crash safety](#7-crash-safety--power-loss)).
9. **Factory reset left crypto-relevant NVS namespaces untouched** — the original `factoryReset()` only cleared the `"skset"` namespace; a v2 factory reset that made the same mistake would have left the wrapped master key + salt in NVS, meaning "factory reset" would not actually create a new cryptographic identity (fixed — see [Factory reset](#3-factory-reset)).
10. **WiFi import/export portal read/wrote the raw plaintext file directly**, bypassing the app's own DB API, and logged the portal's WPA2 password and 6-digit access code to serial — undermining the documented "shown only on-device" security property.
11. **Password generator did not exist** — a real password manager needs one; added using the ESP32-S3 hardware RNG with rejection sampling (no modulo bias) — see [Password generator](#password-generator).

---

## 3. Architecture

```
                 User PIN (never stored)
                        │
                        ▼
      PBKDF2-HMAC-SHA256  (50,000 iterations, 16-byte random salt)
                        │
                        ▼
                  PIN-derived KEK   (256-bit, RAM only)
                        │
                        ▼
     AES-256-GCM(KEK, wrapIV) applied to the Master Key
                        │
          ┌─────────────┴─────────────┐
          │                           │
   Wrapped Master Key           GCM Auth Tag
   (stored in NVS)              (stored in NVS — doubles as the
                                 PIN-correctness check: a wrong
                                 PIN derives a wrong KEK, which
                                 fails to authenticate here)
                        │
                        ▼ (successful unlock only)
        Random 256-bit Master Key   (generated ONCE at setup
                                     via ESP32-S3 hardware RNG;
                                     lives in RAM ONLY while unlocked)
                        │
                        ▼
     AES-256-GCM(MasterKey, per-record random nonce)
     applied independently to EVERY password record
                        │
                        ▼
          Encrypted Password Database  (/db.bin)
```

### What's stored where

| Data | Location | Form |
|---|---|---|
| PIN | **nowhere** | never persisted in any form |
| PBKDF2 salt | NVS `skcrypt` namespace | 16 random bytes |
| PBKDF2 iteration count / KDF version | NVS `skcrypt` namespace | plain integers (not secret) |
| Wrapped master key + its GCM nonce + tag | NVS `skcrypt` namespace | AES-256-GCM ciphertext (256-bit key wrapped) |
| PIN length (4/6/8 digits) | NVS `skcrypt` namespace | plain integer (length isn't a secret — the keypad UI already reveals it via dot count) |
| Master key | **RAM only**, while unlocked | raw bytes, wiped on lock |
| Password records | FFat `/db.bin` | AES-256-GCM ciphertext, one nonce+tag per record |
| Record title / folder / favorite / id | PSRAM index (`passwordIndex`), while unlocked | **plaintext** — see [why below](#why-titlefolder-are-plaintext-in-the-index) |
| Password / username / URL / note | RAM | plaintext **only** while a specific record's detail screen is open; wiped immediately on navigating away |

### Why title/folder are plaintext in the index

The list/search UI needs to render up to thousands of rows without decrypting
the whole vault on every scroll frame or keystroke of a search. Title and
folder are UI labels — what you see in the list *before* opening a specific
entry — not secrets in the same sense as the password itself. Username,
password, URL, and note are **always** the encrypted payload, and are only
ever decrypted into RAM for the *one* record currently open on the detail
screen (`dbLoadRecord`), and wiped again the moment you navigate away, edit,
or delete it.

### Unlock flow

1. User enters PIN on the keypad.
2. `ckDeriveKey()` runs PBKDF2-HMAC-SHA256 with the stored salt + iteration
   count → 256-bit KEK (RAM only).
3. `ckAesGcmDecrypt()` attempts to unwrap the stored wrapped master key using
   that KEK. **This decryption's authentication check IS the PIN check** —
   there is no separate stored PIN hash to compare against. A wrong PIN
   derives a wrong KEK, which fails GCM authentication, and decryption
   returns failure with no partial output ever exposed.
4. On success, the recovered 256-bit master key is held in RAM
   (`vaultMasterKey`) for as long as the device stays unlocked.
5. `dbLoadIndex()` decrypts every record just enough to populate the
   non-secret list index (title/folder/favorite/id), wiping each record's
   full plaintext immediately after copying those four fields out.
6. Opening a specific entry calls `dbLoadRecord()`, which decrypts that one
   record's full payload (username/password/url/note) into a screen-local
   buffer.

### Lock flow

Locking (idle auto-lock, physical button, explicit lock, or losing PIN entry)
calls `vaultLock()`, which:

- Securely wipes `vaultMasterKey` (`ckSecureZero`, backed by
  `mbedtls_platform_zeroize` — not a plain `memset` that an optimizer could
  legally elide).
- Clears `vaultUnlocked`.
- Drops the in-memory password index (`passwordCount = 0`) so nothing but
  the lock screen's own state remains resident.
- Wipes the in-flight PIN entry buffer.

---

## 4. PIN security

- **Never stored.** Removed entirely: `prefs.putString("pin", ...)` /
  `prefs.getString("pin", "1234")` no longer exist anywhere in the codebase
  (verified — see [Static security checks](#static-security-checks)).
- **KDF**: PBKDF2-HMAC-SHA256 via `mbedtls_pkcs5_pbkdf2_hmac()`, 50,000
  iterations, 16-byte random salt generated per-device (and refreshed on
  every PIN change). This is not "plain SHA256(PIN)", not MD5, not CRC, not
  XOR, and not a custom hash.
- **PIN length**: the on-screen setup/change-PIN flow supports 4, 6, or 8
  digits, defaulting to 6 (recommended) for new setups. Changing an
  *existing* device's PIN never happens silently — it requires the explicit
  Settings → Change PIN flow, re-entering the current PIN first.
- **Brute-force lockout**: unchanged escalating design (3rd wrong attempt →
  30s, then 60s, 2m, 5m), fail count persisted in NVS so a reboot doesn't
  reset the escalation. **Layered on top of, not instead of**, the PBKDF2
  cost — see the in-code note in `06_PasswordManager.ino` next to
  `pinLockDelayMs()` for the full reasoning: even if the on-device counter
  were reset (e.g. by directly editing NVS on an unencrypted-flash device),
  every PIN guess still has to pay the KDF cost, because the check is "does
  this PIN's derived KEK unwrap the master key", not "does this string equal
  a stored string."
- **PIN change requires the current PIN.** `vaultVerifyPin()` checks the
  entered "current PIN" against the *already-unlocked* live session without
  disturbing `vaultMasterKey` on a wrong guess (a dedicated function from
  `vaultUnlock()`, which is only for the lock screen) — so a mistyped
  "current PIN" during a change attempt can never lock the user out of the
  session they're already authenticated into.
- **Lockout state**: the fail counter and lockout timer are plain NVS state,
  not cryptographically bound to anything — see the [Security limitations](#8-security-limitations)
  section for why this is a UI-level throttle, not the primary defense, on a
  device without Flash Encryption.

---

## 5. Reduced plaintext residence time

| Old design | New design |
|---|---|
| Load entire plaintext DB → keep resident in PSRAM | Decrypt only the currently-open record → erase after use |
| Password shown/typed straight from a permanently-resident buffer | `detailRec` (screen_detail.ino) is wiped (`ckSecureZero`) on every path out of the screen: back, edit, delete, confirm-delete |
| Add/Edit form buffer (`kbBuffer`, `addRec`) never explicitly cleared | `kbReset()` and `addInit()`/the post-save cleanup now securely wipe both, since the password field's plaintext passes through them |
| — | PIN entry buffer (`pinEntry`) wiped after every unlock attempt (success or failure), and again on lock |

---

## 6. Flash Encryption / Secure Boot (ESP32-S3)

Espressif documents three complementary platform security mechanisms on the
ESP32-S3: **Flash Encryption**, **Secure Boot V2**, and **NVS Encryption**
(which depends on Flash Encryption being enabled). SecureKey's application
layer (Sections 3-5 above) protects the *data* even on a device with none of
these enabled. These platform features additionally protect the *firmware
and flash contents as a whole* — they are what Espressif recommends for a
genuinely production/adversarial deployment.

**This project does not, and will never, burn any eFuse automatically from
the build or the firmware itself.** Enabling any of the below is an explicit,
manual, documented step you run yourself, once, per device, using
`espsecure.py`/`espefuse.py` (both ship inside the `esptool_py` tool
Arduino's ESP32 core already installs).

### Development configuration (default — what this repo builds today)

- Flash Encryption: **off**
- Secure Boot: **off**
- NVS Encryption: **off**
- Any `.bin` can be flashed over USB with `esptool.py` or the Arduino IDE,
  repeatedly, with no signing key and no risk of bricking the board.
- **This is intentional and safe for development** — do not enable
  production eFuses on a board you intend to keep re-flashing casually.

### Production configuration (opt-in, manual, documented here — never automated)

> ⚠️ **eFuses that get burned in this flow are, on the ESP32-S3, permanent.**
> Once set, they cannot be unset by any software means — not by re-flashing,
> not by factory-resetting the app, not by erasing flash. Read every step
> below before running anything against real hardware. Practice first on a
> **spare/development board**, never on your only device.

#### What becomes permanent, and the consequence

| eFuse / action | Irreversible? | Consequence once set |
|---|---|---|
| `SECURE_BOOT_EN` | **Yes** | Bootloader will refuse to boot any image not signed with your Secure Boot key. Losing that private key means the device can never be updated again (a full re-image requires re-flashing while unlocked, which is no longer possible). |
| `SPI_BOOT_CRYPT_CNT` (Flash Encryption enable) | **Yes** (the *enable* eFuse; the AES-XTS key itself may optionally remain re-writable a limited number of times depending on `FLASH_CRYPT_CNT`/key-purpose eFuse settings you choose — see the espefuse docs for your exact eFuse block choice) | Every plaintext `esptool.py write_flash` from that point on gets **transparently encrypted on write** by the flash controller (or, if you also lock the encryption key eFuse, further re-flashing requires the encrypted-update flow). A device with Flash Encryption on but no backup of the auto-generated key can become very difficult to service via raw flash tools. |
| `DIS_DOWNLOAD_MODE` / disabling UART/USB download mode | **Yes, if you choose to set it** | Removes the ability to enter download mode via strapping pins at all — this is an *optional* extra hardening step; SecureKey's documented flow does **not** require or recommend disabling download mode, since it makes field recovery much harder for comparatively little benefit on a device that already has Flash + Secure Boot. |
| NVS Encryption keys (`nvs_keys` partition, XTS keys) | Keys can be regenerated only if Flash Encryption's own key is still usable; if that's locked down, NVS keys become effectively as permanent as Flash Encryption itself | Loss of the NVS key partition (or the flash-encryption key protecting it) makes the `skcrypt`/`skset` NVS namespaces (wrapped master key, PIN salt, etc.) unrecoverable — which, note, is **equivalent to a factory reset from the vault's perspective**, since without that wrapped key material the encrypted database can never be unwrapped again either. |

#### Step-by-step (run manually, once, per production device)

These are the standard Espressif ESP32-S3 flows; SecureKey does not alter
them. All commands use `espsecure.py` / `espefuse.py`, which ship inside the
Arduino ESP32 core's bundled `esptool_py` (find it at
`~/Library/Arduino15/packages/esp32/tools/esptool_py/<version>/esptool/`,
or `pip install esptool` for a standalone copy).

**1. Generate a Secure Boot V2 signing key** (once — protect this file like
   a root credential; back it up somewhere durable and offline):

```bash
espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem
```

**2. Build the production firmware and partition table** using
   `partitions_securekey_prod.csv` (included in this project) instead of the
   default scheme, so an `nvs_keys` partition exists for NVS Encryption:

```bash
# One-time: install the custom partition CSV where the Arduino ESP32 core
# looks for named partition schemes.
cp 06_PasswordManager/partitions_securekey_prod.csv \
   ~/Library/Arduino15/packages/esp32/hardware/esp32/2.0.16/tools/partitions/

# Compile referencing it directly (arduino-cli example — the Arduino IDE
# GUI can do the same via a custom board.txt entry, or just compile with
# Tools > Partition Scheme temporarily pointed at a copy of the stock
# "Minimal SPIFFS"/custom entry you add for this file).
arduino-cli compile \
  --build-property "build.partitions=partitions_securekey_prod" \
  --build-property "upload.maximum_size=3145728" \
  --fqbn "esp32:esp32:esp32s3:PartitionScheme=default,PSRAM=opi,FlashSize=16M,USBMode=default,CDCOnBoot=cdc" \
  06_PasswordManager
```

**3. Sign the application binary:**

```bash
espsecure.py sign_data --version 2 \
  --keyfile secure_boot_signing_key.pem \
  --output 06_PasswordManager.ino.signed.bin \
  06_PasswordManager.ino.bin
```

**4. Flash everything to a device that has NEVER had Flash Encryption or
   Secure Boot enabled** (first-time production flash — bootloader,
   partition table, and the signed app):

```bash
esptool.py --chip esp32s3 write_flash \
  0x0     06_PasswordManager.ino.bootloader.bin \
  0x8000  06_PasswordManager.ino.partitions.bin \
  0x10000 06_PasswordManager.ino.signed.bin
```

**5. Enable Flash Encryption** (the device will auto-generate its own AES-XTS
   key in eFuse on first boot after this if you use "Development" flash
   encryption mode — Espressif's guidance is to use "Release" mode for
   production, which requires the key to be pre-generated and NOT
   re-readable):

```bash
# Release-mode flash encryption (recommended for production):
#   this burns FLASH_CRYPT_CNT and disables further plaintext writes to
#   the flash-encryption key eFuse block — irreversible.
espefuse.py --chip esp32s3 burn_efuse SPI_BOOT_CRYPT_CNT 1
```

**6. Enable Secure Boot V2** (burns the public-key digest of the signing key
   from step 1 into eFuse, and the enable bit — irreversible):

```bash
espsecure.py digest_rsa_public_key \
  --keyfile secure_boot_signing_key.pem \
  --output secure_boot_pubkey_digest.bin

espefuse.py --chip esp32s3 burn_key BLOCK_KEY0 \
  secure_boot_pubkey_digest.bin SECURE_BOOT_DIGEST0

espefuse.py --chip esp32s3 burn_efuse SECURE_BOOT_EN 1
```

**7. Enable NVS Encryption** (generates and burns the NVS XTS keys into the
   `nvs_keys` partition, protected by Flash Encryption from step 5):

```bash
espsecure.py generate_flash_encryption_key nvs_keys.bin
esptool.py --chip esp32s3 write_flash --encrypt 0x10000 nvs_keys.bin
```
   The firmware side of NVS Encryption (calling `nvs_flash_secure_init()`
   with the generated key config instead of the default `nvs_flash_init()`)
   is **not** wired up in this repo's default build — see
   [NVS Encryption firmware integration](#nvs-encryption-firmware-integration-not-yet-wired-up)
   below for why, and what to add if you need it.

After all of the above, every subsequent `esptool.py write_flash` to that
device must use `--encrypt` (or an equivalent OTA-signed-update flow) — a
plain unencrypted `write_flash` will no longer produce a bootable image.

#### NVS Encryption firmware integration (not yet wired up)

The application code in this repo calls the plain `Preferences` API, which
uses `nvs_flash_init()` under the hood. **NVS Encryption requires calling
`nvs_flash_secure_init()` with an `nvs_sec_cfg_t` populated from the
`nvs_keys` partition instead.** This is a firmware-side change beyond what
this security pass modifies, because:

- It only matters once Flash Encryption is already enabled (development
  builds get no benefit from it and the extra init complexity would slow
  down iteration).
- It requires the `nvs_keys` partition to exist, which changes the
  partition table (see `partitions_securekey_prod.csv` above) — a
  production-only change, not something the default dev build should carry.

**If you enable Flash Encryption for production, plan to also switch
`Preferences`'s underlying init (or replace it with direct `nvs_flash_secure_init()`
+ `nvs_open()` calls) to the secure variant** — otherwise the `skcrypt` /
`skset` NVS namespaces are protected by Flash Encryption at the flash-chip
level (a real improvement) but not by the *additional* per-namespace XTS
layer NVS Encryption adds. Flash Encryption alone is already a substantial
improvement over the development configuration; NVS Encryption is defense
in depth on top of it. Espressif's `nvs_flash_secure_init_partition()` API
reference documents the exact call shape needed.

---

## 7. Crash safety / power loss

Every mutating database operation (`dbAppend`, `dbUpdate`, `dbDelete`) goes
through one shared transactional path (`dbRewriteTransacted()` in
`storage.ino`):

1. Write a **complete new file** to `/db_tmp.bin` — header, then every
   record (mutated or not), each freshly encrypted with its own new nonce
   where applicable.
2. Patch the real record count into the header once the full pass completes.
3. **Re-open and verify** the new file: magic bytes, format version, header
   record count matches what was written, and the file size matches
   `sizeof(header) + count * DB_RECORD_SIZE` exactly (catches a truncated
   write from a brownout mid-flush).
4. **Only if verification passes**: remove the old `/db.bin` and rename the
   verified new file over it.

A power loss at any point before step 4 leaves the **old** `/db.bin`
untouched and valid — the in-progress `/db_tmp.bin` is simply abandoned (and
overwritten on the next successful write). A power loss *during* step 4's
remove+rename is the only narrow window with no valid `/db.bin` present
momentarily; FAT filesystems have no atomic rename-over, so this is an
inherent limitation of the storage layer, not something unique to the
encryption work — the same window existed in the original plaintext version.
Nonces are always freshly drawn per write (never reused), so there is no
"replay the same nonce after a partial write" risk either.

The one-time legacy-database migration (`db_migrate.ino`) uses the same
verify-before-delete discipline, with its own separate temp filename
(`/db_migrate.bin`, distinct from the ordinary edit path's `/db_tmp.bin`) so
a crash mid-migration can never be confused with a crash mid-ordinary-edit —
see [Migration](#9-migration-from-a-plaintext-v1-vault).

---

## 8. Serial logging audit

Every `Serial.print`/`Serial.printf` call site in the project was reviewed.
Removed or rewritten:

- `storage.ino`: `[DB] Load id=%u OK title='%s' pass_len=%u`, `[DB] Appended id=%u '%s'` — deleted (the new storage layer never logs record contents at all).
- `screen_add.ino`: `[ADD] Saving new id=%u title='%s' user='%s' pass='%s' url='%s'` → now logs only the id.
- `06_PasswordManager.ino`: `[HID] typeViaHID('%s')`, `[HID] quickFill→BLE user='%s'`, `[HID] quickFill→USB user='%s'` → now log only length/transport-state flags, never the string being typed.
- `hid_usb.cpp` / `hid_ble.cpp`: `hidUsbPrint('%s')`, `hidBlePrint('%s')`, `quickFill user='%s'` → same fix, since these are the actual functions that receive the plaintext password from the detail screen.
- `wifi_portal.ino`: `[WIFI] portal up: SSID=%s PASS=%s CODE=%s` → now logs SSID + IP only; the WPA2 password and 6-digit access code are never written to serial (shown only on the device's own display, as the in-code security comment already promised but the log line contradicted).

A compile-time switch, `SECUREKEY_DEBUG` (default `1` in `theme.h`, flip to
`0` for a release build), gates all *operational* logging (`SK_LOG`/`SK_LOGLN`
macros) — BLE state transitions, boot diagnostics, storage operation
success/failure, etc. **Even at `SECUREKEY_DEBUG=1`, no password, PIN,
encryption key, or decrypted record content is ever printed** — the switch
controls verbosity of non-sensitive operational logging only, not a
sensitive/non-sensitive toggle. A handful of genuinely fatal boot errors
(PSRAM/canvas init failure, FFat mount failure) remain unconditional `Serial`
calls, since they're needed to diagnose a dead unit even in a "release"
build and contain no sensitive data.

### Static security checks

Run from `06_PasswordManager/`:

```bash
grep -rn 'putString("pin"'        *.ino *.cpp *.h   # → no matches
grep -rn 'settings\.pin\b'        *.ino *.cpp *.h   # → no matches
grep -rnE '\brand\(\)|\brandom\(\)' *.ino *.cpp *.h  # → no matches (only in comments)
grep -rniE '\bmd5\b|\bcrc\b'      *.ino *.cpp *.h   # → no matches
grep -rn 'FFat\.write'            *.ino             # → only inside storage.ino/db_migrate.ino
```

All of the above were run against the final code in this pass — see the
[Testing](#10-testing) section for the flash-extraction verification
procedure, which checks the actual compiled artifact rather than just source.

---

## 9. Migration from a plaintext v1 vault

A device already in the field with the old plaintext `/db.bin` migrates
automatically the first time it boots this firmware — but nothing happens
silently:

1. **Detect**: `dbLegacyPlaintextExists()` checks the file's size (a multiple
   of the old 256-byte record size) and the absence of the new format's
   `"SKV2"` magic header.
2. **Require authentication**: boot routes to `SCR_SETUP_PIN` (the old
   firmware never had a real PIN-derived key — only a plaintext PIN string —
   so there is no cryptographic material to "carry forward"; the user sets a
   PIN as part of this flow, same UX as first-time setup).
3. Once a new PIN is confirmed, `vaultCryptoProvision()` generates a fresh
   random master key and the app hands off to `SCR_MIGRATE`, which shows the
   number of entries found and requires an explicit **MIGRATE NOW** tap —
   nothing is read from or written to the old file before this tap.
4. `dbMigrateLegacyPlaintext()` **streams** the legacy file straight into a
   brand-new encrypted file, one record at a time (no full-vault RAM buffer
   — see the in-code note for why an earlier draft that buffered everything
   in PSRAM was replaced with this streaming design).
5. **Verify**: a second pass re-reads both the old and new files in lockstep,
   decrypts every new record, and compares it field-by-field against the
   original. Only if every single record round-trips exactly does migration
   proceed.
6. **Only then** is the old plaintext file deleted, and the new encrypted
   file renamed into place.

If verification fails at any point, the old plaintext file is left
completely untouched, the unverified scratch file is discarded, and the
migration screen reports failure with the message *"Your OLD data is safe
and was NOT deleted or changed... Export/back up your vault via Settings
before retrying."* — the app fails closed rather than risking data loss.

---

## 10. Testing

### Firmware build/functional checklist

1. Compile the project (`arduino-cli compile` against the FQBN in
   `.github/workflows/build.yml`, or the Arduino IDE with the same board
   settings) — confirmed passing as of this security pass.
2. First boot on a blank device → lands on the PIN-length picker
   (`SCR_SETUP_PIN`), not the old lock screen.
3. Set a PIN → vault provisions → "VAULT READY" → Home screen.
4. Add a password → appears in the list immediately.
5. Edit a password → detail screen reflects the change after re-opening.
6. Delete a password → removed from the list; confirm-delete dialog still
   works.
7. Search → filters by title/URL as before (index-only, no decrypt needed).
8. Generate a password (Add/Edit screen → PASSWORD field → GENERATE) →
   produces a random string honoring the selected length.
9. Type a password via HID (tap a detail row) → still requires an active,
   accepted BLE connection or a mounted USB host, same gating as before.
10. PIN unlock with the correct PIN → Home.
11. PIN unlock with 3 wrong PINs in a row → lockout countdown appears; wait
    it out → keypad usable again.
12. Settings → Change PIN → old PIN, new PIN, confirm → "PIN CHANGED"; power
    cycle and confirm the **new** PIN (and only the new PIN) unlocks.
13. Auto-lock (set to 15s in Settings, leave the app idle) → returns to the
    lock screen; master key is wiped (verified in code — see
    [Reduced plaintext residence time](#5-reduced-plaintext-residence-time)).
14. Confirm a brand-new encrypted database is created and its header starts
    with the `"SKV2"` magic bytes (see the flash-extraction test below).
15. Reboot while locked (unplug/replug, or side-button "screen off" then
    power cycle) → still lands on the lock screen, vault stays encrypted.
16. Reboot and unlock → same PIN still works, same vault contents present.
17. Migration: flash an OLD (pre-encryption) build, add a few passwords,
    then flash this build over it → confirm the setup → migrate flow
    triggers and every password survives with identical values.
18. Factory reset (Settings → Factory Reset, PIN-gated, then confirm) →
    reboots to `SCR_SETUP_PIN` as if brand new; confirm the OLD PIN no
    longer works and no old passwords are recoverable after setting up a
    fresh vault.
19. USB HID: plug into a PC, confirm typing only happens when a specific
    field is tapped on an unlocked device — never automatically on connect.
20. BLE HID: pair from a phone, confirm the on-device Accept/Reject/Block
    gate still appears and typing is blocked until Accept.
21. Media controls (if/when the Media Controller mode described in the
    original request is added): confirm they function while `current ==
    SCR_LOCK` — they must never call `vaultUnlock()` or read `vaultMasterKey`.

### Flash/database inspection (verifying plaintext is actually gone)

You do **not** need to expose any real password to run this check — it only
confirms *absence* of known plaintext strings.

```bash
# 1. Dump the whole flash (or just read the FFat partition's ciphertext file
#    off-device via the WiFi export/import portal's /list endpoint is NOT
#    what you want here — that's authenticated plaintext-by-design for the
#    user's own use. For a real flash-level check, dump raw flash instead):
esptool.py --chip esp32s3 read_flash 0 0x1000000 full_dump.bin

# 2. Confirm none of your ACTUAL passwords/usernames/titles appear as
#    readable strings anywhere in the dump. Do this with placeholder
#    values you added yourself for the test — never your real credentials.
#    Example, if you added a test entry titled "ZzTestEntryQQQ" with
#    password "Zz-Test-Pw-12345!":
strings full_dump.bin | grep -F "ZzTestEntryQQQ"      # → no output
strings full_dump.bin | grep -F "Zz-Test-Pw-12345"    # → no output

# 3. Confirm the OLD demo-seed strings (if this device ever ran a build
#    with SECUREKEY_DEMO_MODE, or an old plaintext version) are also gone:
strings full_dump.bin | grep -F "Amazon"              # → no output (was a v1 demo title)
strings full_dump.bin | grep -F "password"             # → no output as vault data
                                                        # (note: this WILL still match the
                                                        #  literal word "password" used in UI
                                                        #  label strings compiled into the
                                                        #  firmware binary itself — e.g.
                                                        #  "PASSWORD" the field label. That's
                                                        #  expected and not a leak; only vault
                                                        #  CONTENT should be absent.)

# 4. Confirm the encrypted database's header magic IS present and its
#    payload does NOT look like readable text immediately after it:
strings full_dump.bin | grep -F "SKV2"
xxd full_dump.bin | grep -A4 "SKV2"    # eyeball: bytes after the 12-byte
                                        # header should look random, not ASCII
```

If step 2 or 3 produces any output, that is a real finding — stop and
investigate before treating the device as secure.

---

## 11. Cryptographic primitives used

All from mbedTLS (bundled with `esp32:esp32@2.0.16`) or the ESP32-S3
hardware RNG. **No custom AES, SHA, PBKDF, or RNG implementation exists
anywhere in this project.**

| Purpose | API | File |
|---|---|---|
| Random bytes (salts, nonces, master key generation, password generator) | `esp_fill_random()` | `crypto_core.cpp` |
| Key derivation (PIN → KEK) | `mbedtls_pkcs5_pbkdf2_hmac()` with `mbedtls_md_setup(MBEDTLS_MD_SHA256, hmac=1)` | `crypto_core.cpp` |
| Authenticated encryption (master-key wrapping, every DB record) | `mbedtls_gcm_setkey()` / `mbedtls_gcm_crypt_and_tag()` / `mbedtls_gcm_auth_decrypt()`, `MBEDTLS_CIPHER_ID_AES`, 256-bit keys | `crypto_core.cpp` |
| Secure memory wipe | `mbedtls_platform_zeroize()` | `crypto_core.cpp` (`ckSecureZero`) |

---

## 12. Security limitations

Stated honestly, per this project's own requirement not to overclaim.

**Protects against:**
- Raw flash inspection recovering plaintext passwords.
- Plaintext database extraction (the file itself is always ciphertext).
- Casual firmware extraction recovering the PIN (the PIN was never stored).
- Unauthorized password access while the device is locked (no plaintext
  password is derivable without the correct PIN going through PBKDF2 →
  AES-GCM unwrap).
- Simple PIN brute force on the keypad UI itself (escalating lockout).
- Nonce reuse (fresh random nonce per record, per write, always).
- Silent data loss during power interruption mid-write (verify-then-replace
  transactional design).
- Accidentally shipping demo/example credentials in a production build
  (`SECUREKEY_DEMO_MODE` gate, off by default).

**Does not completely protect against:**
- **A compromised or unlocked device.** While unlocked, the master key is in
  RAM and any code execution on the device (a firmware vulnerability, a
  malicious BLE/USB host chained with some other bug, physical debug access
  via JTAG on a non-Secure-Boot device) can read it. This architecture
  reduces the *window* (plaintext residence time) but cannot make an
  actively-compromised, currently-unlocked device safe.
- **Sophisticated hardware attacks** — voltage/clock glitching, side-channel
  power analysis against the AES/PBKDF2 computations, decapping and reading
  eFuses directly, or similar bench-level attacks are outside what any
  microcontroller-class device (with or without Secure Boot/Flash
  Encryption) can fully defend against.
- **Physical attacks while the device is unlocked** — someone with the
  device in hand while it's unlocked can simply read passwords off the
  screen or have the device type them, same as any password manager, hardware
  or software.
- **Firmware vulnerabilities in general.** This work hardens the storage and
  authentication design specifically; it is not a substitute for a broader
  code-level security review of every screen/parser/HID-handling path (the
  WiFi import portal's HTTP handlers, BLE GATT handling, etc.) for classic
  memory-safety or logic bugs.
- **A device without Flash Encryption enabled being read at the raw NAND
  level with equipment that bypasses the ESP32-S3's own flash controller**
  (extremely unlikely for FFat's regular SPI NOR flash, but theoretically
  the ciphertext structure — record boundaries, which entries are
  deleted, — remains visible even though content doesn't decrypt without
  the master key). Enabling Flash Encryption (Section 6) closes this gap by
  encrypting the whole flash image, not just the vault's own payload.
- **Loss of the PIN with no backup.** By design, there is no recovery
  mechanism that doesn't involve a factory reset (which discards the vault).
  This is the standard, expected trade-off for "the vendor cannot recover
  your data either" — the same trade-off any serious password manager makes.

This is a genuine hardening of the storage and authentication architecture
for a hobbyist/enthusiast hardware password manager. It is **not** described
here, and should not be marketed, as "military grade" or "unhackable" —
no realistic system earns those claims.
