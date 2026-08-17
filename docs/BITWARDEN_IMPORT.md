# SecureKey — Bitwarden Import

This document describes the Bitwarden vault-import feature: how to export
from Bitwarden, how to start an import on-device, exactly what data is
supported and unsupported, how the import is secured, what happens to the
temporary data involved, and how duplicates are handled.

Imported credentials are written through the **exact same**
`dbEncryptRecord()` / AES-256-GCM path every on-device-created password
goes through (see [`docs/SECURITY.md`](SECURITY.md) for the underlying
vault architecture, which this feature reuses unchanged). There is no
separate "import database," no new master key, and no weakening of the
existing vault encryption.

---

## 1. Exporting from Bitwarden

1. In the Bitwarden web vault or desktop app: **Settings → Export Vault**.
2. **File Format: `.json`** — select the plain `.json` export, **not** the
   "Password Protected" / encrypted `.json` variant. SecureKey does not
   implement Bitwarden's encrypted-export format (see
   [§5, Encrypted exports](#5-encrypted-exports-not-supported) below).
3. Confirm your Bitwarden master password when prompted.
4. Save the resulting `.json` file somewhere you control (your computer or
   phone's own storage) — **do not** upload it to any third-party website.
   Bitwarden's own docs are authoritative for exact menu wording, since
   this project doesn't control that UI.

## 2. Starting an import on SecureKey

1. Unlock the device with your PIN.
2. **Settings → Import** → **Bitwarden Import**.
3. Read and accept the on-device warning:

   > *This export contains your passwords in plaintext. Only import it
   > over a trusted connection. SecureKey will encrypt the vault after
   > import.*

   This is not a formality — the file genuinely contains every password
   in cleartext until SecureKey encrypts it. Tapping **CONTINUE** is a
   deliberate acknowledgment, not a rubber stamp.
4. The device starts a temporary WiFi hotspot and shows an SSID, a
   randomly-generated WPA2 password, and a randomly-generated 6-digit code
   — all fresh for this session, all shown **only on the device screen**.
5. On your computer or phone: join that WiFi network, open a browser to
   the device's address, enter the 6-digit code, choose your exported
   `.json` file, and tap **Upload**.
6. Once the upload finishes, the device shows a **preview**: counts of
   logins, secure notes, and folders found, plus how many items are
   unsupported or look like duplicates — never any password, username, or
   item name content (see [§7](#7-what-the-preview-shows-and-does-not-show)).
7. Tap **IMPORT** to commit, or **CANCEL** to discard everything with no
   changes to your vault.
8. On success: a summary of how many entries were added, and the WiFi
   hotspot shuts down automatically.

## 3. How the import is secured

| Concern | Behavior |
|---|---|
| Portal availability | Disabled by default. Only reachable via Settings → Import → Bitwarden, which requires the device to already be **unlocked** (PIN-authenticated) |
| Session credentials | A fresh random WPA2 password (8 chars) and 6-digit access code are generated for every session (`ckRandomBytes()` — the ESP32-S3 hardware RNG, the same source used for every other secret in this project), shown only on the device's own screen, never logged |
| Route isolation | Import-mode sessions register a **restricted** route set — no `/save`, `/list`, `/edit`, `/delete`, `/export`. An import session's web page has no path to browse or export your *existing* vault, even with the correct code |
| Authorization | Every state-changing request (including the upload itself) requires the session's 6-digit code, checked against `vaultUnlocked` on every request — an idle timeout or lock mid-transfer fails the request closed |
| Auto-shutdown | The portal stops automatically on: import complete, explicit cancel, 3 minutes of no requests, a 10-minute hard session cap regardless of activity, or the device locking for any reason (auto-lock, side-button sleep) |
| Transport | WPA2-encrypted WiFi, single-client SoftAP with no internet uplink — the same isolated-network model the general WiFi manager already uses |
| Encryption at rest | The uploaded data is parsed incrementally and never itself written to flash — see [§8](#8-temporary-data-handling) for exactly what temporary state does exist |
| Atomicity | The vault is only ever replaced by a **fully built and verified** new file — see [§9](#9-how-the-commit-is-verified-before-anything-is-replaced) |

## 4. What's supported

| Bitwarden field | Maps to | Notes |
|---|---|---|
| `name` | title | |
| `login.username` | username | |
| `login.password` | password | Never truncated or dropped |
| `login.uris[0].uri` | url | The **first/primary** URI |
| `login.uris[1+].uri` | note (`[URL2] ...` line) | Additional URIs are preserved, not discarded — but see the truncation note below |
| `folderId` | folder | Resolved through a real folder table (see [§10](#10-duplicate-handling)) — folders import as first-class SecureKey folders, not text labels |
| `notes` | note | |
| `login.totp` | note (`[TOTP] ...` line) | Never shown in the import preview. See the truncation note below |
| custom fields (`fields[]`) | note (`[Custom] name: value` lines) | Never shown in the import preview |
| item type `1` (Login) | a SecureKey password entry | |
| item type `2` (Secure Note) | a SecureKey entry with no username/password | |

### The note-field truncation limitation

**Read this before relying on TOTP or custom fields surviving intact.**
SecureKey's encrypted `note` field is intentionally small (16 bytes) —
unchanged by this feature, since growing it would mean changing the
encrypted payload's on-disk layout for every existing vault. Extra URIs,
TOTP secrets, and custom fields are all folded into that same small field
alongside your real notes text. In practice: **if an item also has real
notes text, anything appended after it will very likely be cut off** after
about 15 characters total. The password itself is never affected — this
limitation is specific to the note field only.

If TOTP or a custom field's exact value matters to you, open that entry on
the device after import and check its note field directly — don't assume
it made it through fully intact. Keeping Bitwarden notes short before
exporting reduces how much gets cut off.

## 5. Encrypted exports (not supported)

Bitwarden also offers a "Password Protected" encrypted `.json` export.
**SecureKey does not implement Bitwarden's encryption/decryption** — this
project never invents or assumes a third-party crypto scheme from
documentation alone, and doing so incorrectly would be worse than not
supporting it. Use the plain (unencrypted) `.json` export, protected instead
by the on-device warning and the WiFi session's own security properties
described above.

An export whose top-level `"encrypted"` field is `true` is detected and
rejected cleanly by the parser — the import fails immediately with a clear
message, before anything is written anywhere.

## 6. What's unsupported

| Item type | Behavior |
|---|---|
| Identity (type `3`) | Counted as "unsupported," never imported, never partially imported |
| Card (type `4`) | Same |
| Attachments / attachment metadata | Never downloaded, never executed, never referenced — Bitwarden export JSON only contains attachment *metadata* (not the file content itself), and this importer does not act on it at all |

Unsupported items are always **counted and reported** in the preview and
final summary — never silently dropped without being acknowledged.

## 7. What the preview shows (and does not show)

The preview screen, shown after upload and before you confirm anything,
shows **only**:

- Count of logins found
- Count of secure notes found
- Count of folders found
- Count of unsupported items (with a note about which types)
- Count of likely duplicates

It **never** shows: passwords, PINs, TOTP secrets, card numbers, private
notes content, or even item/entry **names** — the safest reading of "handle
item names carefully" is to not show them at all in this preview.

## 8. Temporary data handling

The **raw Bitwarden JSON file is never written to flash at all** — it only
ever exists as small (~1.4 KB) chunks in memory while the upload is
streaming in, parsed and discarded chunk by chunk.

What *is* written to flash temporarily is an already-parsed, normalized
intermediate form — just the extracted fields (title/username/password/
url/note/folder), one small fixed-size record per accepted item — in a file
called `/bw_staging.bin` (plus a small `/bw_folders_staging.bin` for
folder names). This staging file:

- Exists only between the moment the upload finishes and either a
  successful commit or a cancel/failure.
- Is deleted on **every** exit path: successful import, explicit cancel,
  parse failure, verification failure, or the portal being torn down for
  any reason (lock, timeout, navigating away).
- Is protected only by the same on-device filesystem access model as this
  project's other crash-safety temp files (`/db_tmp.bin`, `/db_migrate.bin`)
  — it is **not** encrypted, because it holds plaintext by necessity for
  the short window it exists. This is a real, documented limitation, not
  an oversight: someone with raw flash access during that narrow window
  could recover it, exactly as they already could recover the encrypted
  vault's contents by brute-forcing the PIN. See `docs/SECURITY.md`'s
  "Security limitations" section for this project's general posture on
  flash-level access.

## 9. How the commit is verified before anything is replaced

Confirming the preview does **not** immediately touch your real vault.
Instead:

1. A brand-new database file is built: every one of your *existing*
   records is copied through unchanged, plus every newly-imported record
   freshly encrypted with the same master key and a fresh random nonce.
2. That new file is then **completely re-read and decrypted, record by
   record** — confirming the total count is right, every pre-existing
   record is untouched, and every new record's fields match what was
   staged.
3. **Only if every single record verifies successfully** does the device
   atomically replace the real vault file with the new one.
4. If verification fails at any point, the new (unverified) file is
   deleted and your existing vault is left completely untouched — the
   device tells you the import failed and your vault is safe, and it
   means that literally.

This mirrors the same verify-before-delete discipline this project already
uses for its plaintext-to-encrypted database upgrade (see
`docs/SECURITY.md`).

## 10. Duplicate handling

An imported login is compared against your **existing** vault by
**title + username + URL together** — not title alone, since many
different accounts share a title like "Email." A match on all three is
treated as a duplicate.

Secure Notes (which have no username/URL) are matched by title only — the
best signal available for that item type.

The default (and only, in this version) policy is **skip**: a duplicate is
never imported and never overwrites an existing entry — it's counted and
reported, nothing more. There is currently no "replace" or "keep both"
option; if you want to intentionally re-import something you've since
edited, delete the old entry on-device first.

Duplicates are checked both against your existing vault and within the
imported file itself (two identical entries in the same export are only
imported once).

## 11. Manual test procedure

This project has no automated test harness (it's Arduino firmware, tested
manually against real hardware — the same convention `docs/SECURITY.md`
uses for its own testing checklist). A small fake fixture lives at
[`06_PasswordManager/test_fixtures/bitwarden_export_sample.json`](../06_PasswordManager/test_fixtures/bitwarden_export_sample.json)
(5 logins with 1 intentional duplicate, 2 secure notes, 2 folders, 1 custom
field, 1 TOTP value, 1 unsupported item — all `*.example.invalid` fake
data; see that file's own `README.md`).

1. **Valid import** — flash firmware, unlock, Settings → Import → Bitwarden
   → accept the warning → join the AP, browse to the device IP, enter the
   code, select `bitwarden_export_sample.json`, upload. Confirm the preview
   shows 4 new logins (5 minus 1 duplicate), 2 secure notes, 2 folders, 1
   unsupported. Confirm the import, then verify all 6 new entries appear in
   the password list under the correct folders, the TOTP-bearing entry's
   note shows a `[TOTP]` prefix (likely truncated), and the custom-field
   entry shows a `[Custom]` line.
2. **Malformed JSON** — truncate the fixture mid-string and upload. Expect
   a clean "Import failed" message on-device; confirm the existing vault is
   unchanged.
3. **Empty vault** — upload `{"encrypted":false,"folders":[],"items":[]}`.
   Preview should show all-zero counts; confirming should complete as a
   no-op with no crash and no phantom records.
4. **Large vault** — generate (off-device, not committed to this repo) a
   fixture with ~1500 fake login items and upload it. Confirm no watchdog
   reset, the progress screen's "N / M" count advances, and the final tally
   matches.
5. **Duplicates** — use the fixture's built-in duplicate ("Example Mail"
   appears twice). Confirm exactly 1 is imported and 1 is reported as a
   duplicate. Re-run the same import a second time — this time all 5 logins
   should be reported as duplicates (proving the check is against the
   *now-updated* vault, not just within one batch).
6. **Missing fields** — craft a login item with no `password` key at all.
   Confirm it imports with an empty password field rather than crashing or
   being silently dropped (an item is not required to have every field to
   be imported — only its *contents* determine what SecureKey actually
   stores).
7. **Unsupported item types** — confirm an Identity (type 3) or Card (type
   4) item is counted as "unsupported" and never appears as a password or
   note entry.
8. **Oversized fields** — craft a variant with a 5,000-character password
   and a 10,000-character notes field. Confirm the imported password is
   exactly 47 characters (not corrupted, not longer) and the device doesn't
   hang or crash while parsing the oversized string.
9. **Cancelled import** — start an upload, reach the preview screen, tap
   CANCEL. Confirm the existing vault is unchanged and a subsequent fresh
   import doesn't show any leftover state from the cancelled one.
10. **Interrupted import (power-cycle mid-transfer)** — start uploading the
    large-vault fixture, power off the device partway through. On reboot,
    confirm the device boots normally, the existing vault (all
    pre-import passwords) is completely intact, and starting a fresh
    import works normally.
11. **Existing vault survives a failed commit** — deliberately force a
    verification failure (a temporary debug-only build hook is the
    practical way to do this, removed before release) and confirm the
    on-device message says the import failed and the vault is safe, then
    spot-check a known pre-existing password still decrypts correctly and
    is unchanged.
12. **Imported passwords work via HID** — after a successful import, open
    a newly-imported entry and type it via USB or BLE HID (same as any
    other entry). Confirm the typed text matches the fixture's known fake
    password exactly.
13. **No plaintext in serial logs** — with `SECUREKEY_DEBUG` on, run a full
    import over a USB-serial-monitored session, capture the log, and
    `grep` it for every fake password/TOTP string from the fixture
    (`Demo-Pass-0001!`, `JBSWY3DPEHPK3PXP`, etc.). Expect zero matches —
    matching `docs/SECURITY.md`'s own grep-based verification approach.
14. **Temporary files are gone after success** — after a successful
    import, confirm `/bw_staging.bin`, `/bw_folders_staging.bin`,
    `/bw_import_new.bin`, and `/bw_folders_new.bin` no longer exist on
    flash.

## 12. Limitations

- **Encrypted Bitwarden exports are not supported** — see [§5](#5-encrypted-exports-not-supported).
- **Notes, TOTP secrets, extra URIs, and custom fields are all subject to
  truncation** into a 16-byte field — see the dedicated note above. The
  password itself is never truncated.
- **No "replace" or "keep both" for duplicates** in this version — matches
  always skip. If you need to intentionally re-import an edited entry,
  delete the old one first.
- **Identity and Card items are not imported** — reported as unsupported,
  never partially converted into a password entry.
- **The parsed-but-not-yet-committed staging file is plaintext on flash**
  for the (short) window between upload and commit/cancel — see
  [§8](#8-temporary-data-handling) for exactly what that means and why it's
  unavoidable without changing the transfer mechanism entirely.
- **Item names are never shown during import**, including in the preview —
  a deliberate, conservative choice; you only see aggregate counts until
  the import is committed and you're looking at your actual, decrypted
  vault.
