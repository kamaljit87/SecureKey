# SecureKey — Architecture & Feature Concepts

A deep dive into how SecureKey works, for contributors and the curious. For the high‑level pitch and setup, see the [README](../README.md).

---

## 1. The big picture

SecureKey is a single‑threaded Arduino sketch built around a **screen state machine** and a **non‑blocking main loop**. There is no RTOS scheduling in user code — instead `loop()` polls touch at ~60 Hz, runs lightweight per‑screen animation timers, and services background managers (BLE, Wi‑Fi portal, auto‑lock). The two HID stacks (USB via TinyUSB, BLE via NimBLE) run their own tasks under the hood.

```
            ┌────────────────────────── loop() @ ~60 Hz ──────────────────────────┐
            │  pollTouch() ─► tap / drag / swipe / long-press  ─►  onTapXxx()      │
            │  per-screen animation ticks (lock pulse, PIN shake, list inertia)    │
            │  BLE manager (advertise state, connect gate)                         │
            │  Wi-Fi captive portal service                                        │
            │  auto-lock / LED auto-clear / physical button                        │
            └──────────────────────────────────────────────────────────────────────┘
```

---

## 2. Screen state machine & navigation

Every screen is a pair of functions:

```c
void drawXxx();                       // render the whole screen into the canvas
void onTapXxx(int16_t x, int16_t y);  // handle a tap at (x, y)
```

`current` holds the active `Screen` enum. A small **navigation stack** (`navStack[10]`, `navTop`) gives Android‑style back behaviour:

- `pushNav(SCR_X)` — go deeper (also runs per‑screen entry hooks, e.g. `buildList()` for the list, `pinSlideIn()` for the PIN animation).
- `popNav()` — go back one level.
- `popToLock()` — collapse to the lock screen (idle timeout, physical button).

`drawAll()` and `dispatchTap()` are the two switch statements that route to the active screen. **Adding a screen = write the pair, add a `SCR_` enum, register in both switches.**

Rendering is **double‑buffered**: everything is drawn into an `Arduino_Canvas` in PSRAM, then `flushScreen()` (`gfx->flush()`) pushes the whole frame to the AMOLED over QSPI in one shot. No partial draws, no flicker, no tearing.

---

## 3. Touch: from capacitive blob to gesture

`touch_input.ino` reads the FT3168 over I²C (`ftReadTouch()` — register `0x02` for the touch count, `0x03` for the first point) and runs a small state machine in `pollTouch()`:

| Transition | Meaning | Fires |
|---|---|---|
| no‑touch → touch | finger down | records start point + time |
| touch → touch (moved > `DRAG_THRESHOLD`) | it's a drag | `onDrag()` live callback |
| touch held > 500 ms, no move | **long‑press** | `homeLongPress()` (home only) |
| touch → release, was a drag | swipe/scroll end | `onSwipeEnd()` |
| touch → release, was short & still | **tap** | `dispatchTap()` |

This single machine powers list scrolling (with inertia/friction), swipe‑back, the slide‑up PIN entrance, and the home drag‑to‑reorder — all without blocking the loop.

---

## 4. Data model & storage

> 🔐 The vault is **encrypted at rest** (AES‑256‑GCM, per‑record nonces, a
> random master key wrapped by a PBKDF2‑derived, PIN‑based key). This
> section covers the in‑RAM `PassRecord`/`ListItem` shapes the UI code
> works with — for the actual on‑disk format, the key‑derivation design,
> the threat model, and the migration path from the old plaintext format,
> see **[docs/SECURITY.md](SECURITY.md)**.

### Record layout (in‑RAM representation)

The UI/business logic still works with a **fixed‑size 256‑byte** in‑RAM
`PassRecord` — unchanged from before, so screens and features didn't need to
be rewritten:

```c
struct __attribute__((packed)) PassRecord {  // 256 bytes, RAM-side shape
  uint16_t id;            // stable identifier
  uint8_t  deleted;       // tombstone flag
  char     folder[24];    // reused as the URL/subtitle
  char     title[40];
  char     username[64];
  char     password[48];
  char     url[60];
  char     note[16];
  uint8_t  favorite;      // heart flag
};
```

What changed is what happens *between* a `PassRecord` and the file: every
write goes through `dbEncryptRecord()` (AES‑256‑GCM, fresh random nonce every
time), and every read that needs the full record goes through
`dbDecryptRecord()`. Only the *current* screen's record is ever decrypted
into RAM at a time — see SECURITY.md's "reduced plaintext residence time".

### Why a separate PSRAM index?

Re‑reading flash to render a scrolling list would be slow, wear the flash,
**and** require decrypting the whole vault on every scroll frame. Instead,
at boot (once unlocked) `dbLoadIndex()` builds a compact **64‑byte
`ListItem`** per entry (id, favorite, title, subtitle) in **PSRAM** — the
only fields it needs are the ones already treated as UI labels rather than
secrets (see SECURITY.md for why title/folder are the one exception kept in
plaintext in RAM):

```c
struct __attribute__((packed)) ListItem {  // 64 bytes
  uint16_t id;
  uint8_t  favorite;
  char     folder[21];
  char     title[40];
};
```

Searching, sorting (`qsort` by title), and the virtual‑scroll list all operate on this in‑RAM index — flash is only touched to open a single full (encrypted) record (`dbLoadRecord()`, which decrypts it) or to write (`dbAppend`/`dbUpdate`/`dbDelete`, which re‑encrypt).

### Operations

| Op | Strategy |
|---|---|
| Add | encrypt + append one record (`dbAppend`) |
| Edit | rewrite file transactionally, replace matching `id`'s ciphertext in place |
| Delete | rewrite file with `deleted = 1` (tombstone) — record stays encrypted, just flagged |
| Toggle favorite | decrypt, flip flag, re‑encrypt with a fresh nonce, reload index |

All of the above share one transactional rewrite path (`dbRewriteTransacted()`
in `storage.ino`) that verifies a complete new file before ever replacing
the old one — see SECURITY.md § Crash safety.

### Capacity

`MAX_PASSWORDS = 30000`. That's ≈ **1.9 MB** of index in the 8 MB OPI PSRAM, plus a 2‑byte‑per‑entry sort array, and the on‑disk encrypted record size (id/flags + 12‑byte nonce + 16‑byte auth tag + ciphertext payload) comfortably fits the 9 MB FAT partition at the same ~30,000‑entry cap. `uint16_t` ids/counters comfortably cover 30 000 entries.

---

## 5. HID: the device pretends to be a keyboard

Both transports advertise a standard **HID keyboard**, so the host needs no driver or software. The firmware sends USB HID **usage codes** (scancodes); the **host** maps them to characters using *its* keyboard layout.

### Why two translation units?

`USBHIDKeyboard.h` (TinyUSB) and `BleKeyboard.h` (NimBLE) both `#define KEY_TAB`, `KEY_RETURN`, etc. and both declare a `KeyReport` — they **cannot** be `#include`d in the same `.cpp`. So:

- `hid_usb.cpp` owns the USB keyboard.
- `hid_ble.cpp` owns the BLE keyboard.
- Each exposes a tiny `extern "C"` surface (`hidUsbPrint`, `hidBlePrint`, …). The `.ino` code never sees the library headers.

### Dual‑transport dispatch

`typeViaHID()` doesn't pick one transport — it sends to **every** ready one:

```
if (BLE enabled && connected && user-accepted)  hidBlePrint(s);
if (USB enabled && host has enumerated us)       hidUsbPrint(s);
```

NimBLE runs its radio work on its own task and coexists with native USB on the dual‑core S3, so "BLE on" never disables USB and vice‑versa.

### USB mount detection

USB typing only fires once `tud_mounted()` (TinyUSB) reports the host has enumerated the keyboard — that's why plugging into a *charger* (no data) won't type, and why the firmware waits briefly after `USB.begin()` for Windows to enumerate.

---

## 6. Bluetooth: pairing gate & the stuck‑key fix

### The pairing gate

A BLE *central* (phone/PC) can connect to our peripheral at any time, but SecureKey **types nothing until the user accepts on‑device** — and only once unlocked. The `loop()` BLE manager detects a new connection and, if unlocked + screen on + not in a block window, calls `bleConnectGate()`:

- **Accept** → `bleAuthorized = true`; typing allowed.
- **Reject** → keep the link up (a paired phone auto‑reconnects instantly, which would loop the prompt) but stay unauthorized, and **snooze** the prompt 20 s.
- **Block 5 min** → drop the radio entirely for 5 minutes.

The prompt shows the peer's Bluetooth address (`hidBlePeerAddr()` → `NimBLEServer::getPeerIDInfo().getAddress()`). A central doesn't transmit a friendly name to a keyboard, so the MAC is what's identifiable.

### Live on/off without reboot

The patched `BleKeyboard::end()` is a no‑op and calling `begin()` twice duplicates GATT services, so `hid_ble.cpp` calls `kb.begin()` **exactly once per boot** (`everStarted`). Turning BLE on/off afterward uses raw NimBLE: `getAdvertising()->start()/stop()` plus `server->disconnect(peer)`.

### Just‑Works pairing

The library default `setSecurityAuth(true, true, true)` demands MITM protection, but this device has no passkey entry/display — so Windows and some Androids paired but never encrypted (connected, never typed). Patched to `(true, false, false)` = **bonded "Just Works"** pairing, the correct profile for a display‑less keyboard.

### The "…gmmmmm" stuck‑key bug

A HID keystroke is a **key‑down report** followed by a **key‑up report**. `kb.write()` sends both back‑to‑back, so over BLE they can land in the *same* connection event and the host misses the release → it auto‑repeats the last key forever. The fix in `bleType()`:

```
press(key)  →  hold ~32 ms (spans a connection interval)  →  releaseAll()  →  small gap
```

Key‑down and key‑up now land in **different** connection events. We also request a tighter connection interval (`updateConnParams`) so typing is prompt, and `releaseAll()` at the start/end guarantees nothing is left held.

### The Android `@`→`"` fix

HID sends key *positions*. On a UK/Android layout, `Shift+2` is `"` and `@` lives on `Shift+'`. The **Android @ Fix** toggle makes `bleType()` send `@` as `Shift+apostrophe` (usage `0x34`) and `"` as `Shift+2` (usage `0x1F`), which produce the right glyphs on those hosts — the classic US↔UK swap, fixed in firmware. (Only enable it for Android; on a US host it would invert them.)

---

## 7. Security: PIN, lockout, auto‑lock

> 🔐 Full detail — threat model, cryptographic design, eFuse/Flash
> Encryption/Secure Boot production steps, and stated limitations — lives in
> **[docs/SECURITY.md](SECURITY.md)**. Summary:

- **PIN** is never stored, in any form. It's checked by deriving a key
  (PBKDF2‑HMAC‑SHA256) and attempting to unwrap the AES‑256‑GCM‑wrapped
  master key with it — a wrong PIN fails that unwrap (GCM authentication),
  there is no separate stored PIN/hash to compare against. Correct entry
  jumps straight to Home.
- **Brute‑force backoff** (`pinRegisterFail`): the 3rd wrong attempt locks the keypad 30 s, then 60 s, 2 m, 5 m. The cumulative fail count is **persisted in NVS**, so a power‑cycle doesn't reset the penalty (millis() resets, but the next wrong attempt jumps straight back to a long wait). This sits on top of, not instead of, the PBKDF2 cost every guess pays regardless.
- **Auto‑lock** after configurable idle, and the physical button → instant lock. Locking wipes the master key from RAM (`vaultLock()`), not just switching screens.
- **Factory reset** is **PIN‑gated**, then a second confirm, then wipes `db.bin` **and** the crypto‑material NVS namespace (salt, wrapped master key) **and** BLE bonds, then reboots into first‑time setup with an entirely new random master key — a reset can't be used to silently recover the old vault.

> The vault **is encrypted at rest**: AES‑256‑GCM per record, random master
> key wrapped by a PIN‑derived key (never the PIN itself, never a
> hard‑coded key). Optional ESP32‑S3 Flash Encryption + Secure Boot v2 (a
> manual, documented, non‑automated production step — see SECURITY.md)
> harden the firmware/flash‑image layer on top of this. Treat SecureKey as
> a serious hobbyist‑grade hardening project — see SECURITY.md's own
> "Security limitations" section for what this does *not* protect against.

---

## 8. Wi‑Fi import/export portal

Typing many entries on a touchscreen is painful, so Settings can start a **SoftAP + HTTP server** (`wifi_portal.ino`) serving a single‑page web app (`portal_html.h`):

- Join the device's Wi‑Fi, open the page, enter a one‑time **access code**.
- **Import**: paste lines or a CSV — Chrome/Google password exports are auto‑detected (`title,url,username,password` order).
- **Export**: download the vault as CSV.
- Every entry requires **title + username + password** — validated in the browser *and* server‑side in `portalSaveEntry()` (so even bulk lines can't create half‑empty records).

The portal is torn down automatically when you navigate away from the Wi‑Fi screen.

---

## 9. Home drag‑to‑reorder

`homeOrder[slot] = item` maps grid positions to menu items. A long‑press lifts a tile (`homeLongPress`), it follows the finger (`homeDrag`), and on release it drops into the nearest slot, shuffling the rest (`homeRelease`). The order is saved to NVS (`horder`) and **validated as a permutation** on load, so a corrupt value can never brick the home screen. Tap **DONE** to leave arrange mode (also forced on lock).

---

## 10. Rendering style on AMOLED

`gfx_lib.ino` is the drawing toolkit: text helpers, icons, status/nav bars, and a small **color engine** (`lerp565` blend, `glowCircle` banded radial gradient, letter‑avatar palette). Because AMOLED black is genuinely *off*, the theme uses black backgrounds with **glow halos** and a blue/red accent system, color **letter‑avatars** for entries, and iOS‑style pill toggles — all hand‑drawn, no LVGL, into the double‑buffered canvas.

---

## File map

| File | Responsibility |
|------|----------------|
| `06_PasswordManager.ino` | setup/loop, nav stack, HID dispatch, BLE gate, PIN lockout, settings persistence |
| `theme.h` | palette, layout constants, `PassRecord`/`ListItem`, capacity, `UserSettings`, `SECUREKEY_DEBUG`/`SK_LOG` |
| `pin_config.h` | board pin map |
| `crypto_core.h` / `.cpp` | mbedTLS wrappers: PBKDF2, AES‑256‑GCM, HW RNG, secure‑wipe — **see [SECURITY.md](SECURITY.md)** |
| `shared_types.h` | cross‑file structs/typedefs (on‑disk DB layout, vault crypto params, legacy‑migration record, password‑generator options) |
| `vault_crypto.ino` | PIN → KEK → master‑key lifecycle (provision/unlock/rewrap/lock/erase) |
| `db_migrate.ino` | one‑time legacy plaintext → encrypted DB migration (streamed, verify‑before‑delete) |
| `pwgen.ino` | cryptographically‑secure password generator (HW RNG, rejection sampling) |
| `hid_usb.cpp` / `hid_ble.cpp` | the two isolated HID keyboards |
| `storage.ino` | encrypted FFat DB (AES‑256‑GCM per record) + demo‑mode‑only seed data |
| `touch_input.ino` | FT3168 reader + gesture state machine |
| `gfx_lib.ino` | drawing helpers + color engine |
| `keyboard.ino` | on‑screen keyboard |
| `screen_*.ino` | one file per screen (`draw` + `onTap`), including `screen_setup_pin.ino` (first‑boot/reset PIN setup) and `screen_migrate.ino` (migration confirm/progress) |
| `wifi_portal.ino` + `portal_html.h` | import/export web app — now reads/writes exclusively through the encrypted‑DB API, never raw FFat |
| `partitions_securekey_prod.csv` | production partition table with an `nvs_keys` slot (for NVS Encryption) — see SECURITY.md |
