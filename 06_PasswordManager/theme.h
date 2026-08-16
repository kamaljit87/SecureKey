// =============================================================
//  theme.h  —  SecureKey  (pure monochrome)
// =============================================================
#pragma once
#include <Arduino.h>

// ── Build-time security switches ───────────────────────────────
// SECUREKEY_DEBUG: verbose/diagnostic serial logging. Even at 1, sensitive
// values (passwords, PINs, keys, tokens) are NEVER printed — see the
// "never log" list in docs/SECURITY.md. This only gates *extra* operational
// logging (mount status, record counts, BLE state machine, etc). Set to 0
// for anything you'd hand to someone else / a production unit.
#ifndef SECUREKEY_DEBUG
#define SECUREKEY_DEBUG 1
#endif

// SECUREKEY_DEMO_MODE: compiles in a handful of obviously-fake example
// entries (example.invalid) for screenshots/UI dev, seeded into an EMPTY
// vault only. Must be OFF for anything built to actually hold real
// passwords. Define it in the .ino (or via a build flag) — never enabled
// by default.
// #define SECUREKEY_DEMO_MODE

// Debug-gated serial helpers — use these instead of raw Serial.print* for
// anything that isn't safety-critical (boot errors, fatal init failures
// stay as plain Serial calls so they're visible even in release builds).
#if SECUREKEY_DEBUG
  #define SK_LOG(...)   Serial.printf(__VA_ARGS__)
  #define SK_LOGLN(s)   Serial.println(s)
#else
  #define SK_LOG(...)   do {} while (0)
  #define SK_LOGLN(s)   do {} while (0)
#endif

// ── Monochrome palette ───────────────────────────────────────
#define C_BLACK    0x0000
#define C_GRAY_1   0x10A2   // very dark   (card bg)
#define C_GRAY_2   0x2945   // dark        (borders, separators)
#define C_GRAY_3   0x528A   // mid         (secondary text)
#define C_GRAY_4   0x8C71   // light       (status / hint text)
#define C_GRAY_5   0xC618   // very light
#define C_WHITE    0xFFFF

// One specific accent: the BLE icon turns blue when Bluetooth is on,
// so the user can tell BLE-pairing state at a glance.
#define C_BLUE     0x4D9F   // sky-blue (RGB565)

// Red accent: a favorited entry's heart fills red.
#define C_RED      0xF800   // pure red (RGB565)

// ── Layout constants ─────────────────────────────────────────
#define STATUS_H    44      // status bar height
#define NAV_H       48      // nav bar height
#define SAFE_PAD    16      // edge margin (rounded AMOLED corners)
#define LIST_TOP    (STATUS_H + NAV_H)   // 92  — where lists start

// Generic row sizes — bigger tap targets per user feedback
#define HOME_ITEM_H 54      // home menu rows (compact — fits 6 items)
#define LIST_ITEM_H 70      // password list rows
#define SET_ITEM_H  62      // settings rows

// Keyboard placement (shared between passwords + add screens)
// Grid: 200 + 5 rows*(44+4) - 4 = 436, leaving a 12px bottom margin (448px screen).
#define KB_TOP_Y    200     // y of first keyboard row (6-col grid)

// ── 7-segment (for lock-screen clock) ────────────────────────
const uint8_t SEG7[10] = {
  0x7D,0x0C,0x37,0x1F,0x4E,0x5B,0x7B,0x0D,0x7F,0x5F
};

// ── Screen states ─────────────────────────────────────────────
enum Screen {
  SCR_LOCK,            // branded lock screen
  SCR_PIN,             // PIN entry (4/6/8 digits, per-device — see PIN_MIN_LEN/PIN_MAX_LEN)
  SCR_HOME,            // home grid (Passwords / Add / Flashlight / Settings)
  SCR_LIST,            // password list
  SCR_DETAIL,          // password detail
  SCR_SEARCH,          // (vestigial — search merged into list)
  SCR_SEARCH_RES,      // (vestigial)
  SCR_ADD,             // add / edit password form
  SCR_SETTINGS,        // settings list
  SCR_CHGPIN,          // change-PIN flow
  SCR_FLASH,           // flashlight (full white)
  SCR_WIFI,            // WiFi captive-portal import (shows AP credentials)
  SCR_DEVICES,         // saved BLE devices manager (whitelist)
  SCR_SETUP_PIN,       // first-boot / post-factory-reset: choose a new PIN
  SCR_MIGRATE          // one-time legacy-plaintext-DB → encrypted DB migration
};

// ── Password record (256 bytes fixed) ─────────────────────────
struct __attribute__((packed)) PassRecord {
  uint16_t id;          //  2
  uint8_t  deleted;     //  1
  char     folder[24];  // 24   (currently unused — was folder colour)
  char     title[40];   // 40
  char     username[64];// 64
  char     password[48];// 48
  char     url[60];     // 60
  char     note[16];    // 16
  uint8_t  favorite;    //  1   (1 = favorite / heart)
};
static_assert(sizeof(PassRecord) == 256, "PassRecord must be 256 bytes");

// ── List index entry (64 bytes) ───────────────────────────────
struct __attribute__((packed)) ListItem {
  uint16_t id;          //  2
  uint8_t  favorite;    //  1
  char     folder[21];  // 21
  char     title[40];   // 40
};
static_assert(sizeof(ListItem) == 64, "ListItem must be 64 bytes");

// ── Capacity ─────────────────────────────────────────────────
//   Storage limit:   9 MB FATFS / ~276 bytes (encrypted, see storage.ino
//                    DB_RECORD_SIZE)         ≈ 33,000 records
//   PSRAM index :    8 MB / 64 bytes           ≈ 130,000 records
//   Cap at 30,000 — index uses 30000*64 ≈ 1.9 MB PSRAM + 30000*2
//   for the sort array ≈ 60 KB, well within the 8 MB OPI PSRAM, and
//   comfortably fits the 9 MB FAT partition at the encrypted record size.
#define MAX_PASSWORDS   30000

// LEGACY plaintext (pre-encryption, SecureKey v1) on-disk record size —
// kept ONLY so db_migrate.ino can recognize and safely convert an old
// device's plaintext /db.bin. Never used to write anything in this
// firmware; the live encrypted format's record size is DB_RECORD_SIZE
// (storage.ino), which is larger (adds nonce/tag framing).
#define RECORD_SIZE     256

// ── Saved BLE devices (the "whitelist") ──────────────────────
//  A device the user ACCEPTED once is remembered by its RESOLVED identity
//  address (stable across the phone's rotating-private-address changes).
//  On a later reconnect a saved device is auto-approved — no Accept prompt.
//  Managed on the Devices screen (rename / forget).
#define MAX_BLE_DEVICES  8
struct __attribute__((packed)) SavedDevice {
  char    addr[18];     // identity address "AA:BB:CC:DD:EE:FF"
  uint8_t addrType;     // NimBLEAddress type (for bond removal)
  char    name[19];     // user alias (defaults to the address tail)
};

// ── Settings stored in Preferences (NVS) ──────────────────────
// NOTE: the PIN is intentionally NOT a field here. It never exists
// anywhere except a transient stack buffer while the user is typing it
// (see PIN_MAX_LEN below) — see vault_crypto.ino for the PBKDF2-derived
// key-wrapping design that replaces "store the PIN and strcmp() it".
struct UserSettings {
  uint8_t brightness;       // 20–250
  bool    bleEnabled;
  bool    usbHidEnabled;
  uint8_t autoLockSec;      // 0=off, else 15/30/60/120 s idle → re-lock
                            // (screen stays ON — sleep modes were removed)
  bool    androidFix;       // swap @ / " keycodes for UK/Android BLE hosts
};

// PIN length: 4 digits kept as the supported minimum for backward
// compatibility with existing devices/muscle memory, but PIN_MAX_LEN is
// 8 so Settings → Change PIN can offer 6-digit (recommended) or longer.
// Changing MIN below only affects the on-screen PIN-length picker — it
// does not silently change any existing user's PIN.
#define PIN_MIN_LEN  4
#define PIN_MAX_LEN  8
#define PIN_RECOMMENDED_LEN  6
