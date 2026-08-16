// =============================================================
//  shared_types.h  —  Cross-file types for the encrypted vault
//
//  Home for every struct/typedef that is (a) used as a function
//  parameter/return type and (b) referenced from more than one .ino
//  file, OR whose owning .ino file needs its own prototype resolved
//  before the struct would otherwise be defined.
//
//  Why this has to be a header: Arduino's automatic function-prototype
//  generator scans the WHOLE concatenated sketch (every .ino file
//  pasted together, main sketch first, then alphabetical) and hoists a
//  forward declaration for every function to the very TOP of that
//  combined file — before ANY .ino-local type definition has been seen,
//  regardless of which file the function or the type live in. A
//  function whose signature takes a custom struct by value/reference
//  therefore fails to compile ("does not name a type") unless that
//  struct comes from a header, which is included (and fully parsed)
//  before the hoisted prototypes are emitted. Plain data flow (a function
//  only used from its own file, taking only built-in types) doesn't hit
//  this — it only bites custom struct/typedef parameters.
// =============================================================
#pragma once
#include "crypto_core.h"

#define DB_PATH      "/db.bin"
#define DB_TMP_PATH  "/db_tmp.bin"
#define DB_MAGIC     "SKV2"        // 4 bytes, no NUL
#define DB_FORMAT_VERSION 2        // on-disk layout version

// KDF/crypto scheme version, stored in both the DB header and the
// vault_crypto NVS params. Defined here (rather than in vault_crypto.ino)
// because it's a preprocessor macro: Arduino concatenates all .ino files
// into one translation unit and preprocesses it top-to-bottom, so a
// #define in a file that sorts alphabetically AFTER its first use (e.g.
// vault_crypto.ino vs storage.ino) would not be visible yet. Living in a
// header pulled in up front avoids that ordering trap entirely.
#define SECURITY_VERSION  2        // bumped from the old plaintext design (v1)

// Legacy (SecureKey v1) plaintext format — kept ONLY to detect and migrate
// an old plaintext /db.bin left over from a pre-encryption firmware. Never
// written by this firmware.
#define LEGACY_RECORD_SIZE 256

// ── On-disk layout ───────────────────────────────────────────
struct __attribute__((packed)) DbHeader {
  char     magic[4];         // "SKV2"
  uint16_t formatVersion;    // DB_FORMAT_VERSION
  uint16_t securityVersion;  // matches vault_crypto's SECURITY_VERSION at write time
  uint16_t recordCount;      // informational only (live count comes from scanning)
  uint16_t reserved;
};
static_assert(sizeof(DbHeader) == 12, "DbHeader layout changed");

// Max plaintext payload packed into one record (matches the old PassRecord
// field budget so no user-visible field limits shrink).
#define PT_TITLE_LEN     40
#define PT_USERNAME_LEN  64
#define PT_PASSWORD_LEN  48
#define PT_URL_LEN       60
#define PT_NOTE_LEN      16
#define PT_FOLDER_LEN    24

// The plaintext structure that gets AES-GCM encrypted as a single blob.
// (Not written to flash directly — only its ciphertext is.)
struct __attribute__((packed)) DbPlainPayload {
  char folder[PT_FOLDER_LEN];
  char title[PT_TITLE_LEN];
  char username[PT_USERNAME_LEN];
  char password[PT_PASSWORD_LEN];
  char url[PT_URL_LEN];
  char note[PT_NOTE_LEN];
};
#define DB_PAYLOAD_LEN sizeof(DbPlainPayload)

// One on-disk record: metadata (authenticated but NOT secret) + the
// encrypted payload + its GCM tag. Fixed size → O(1) seek, same as v1.
struct __attribute__((packed)) DbRecordOnDisk {
  uint16_t id;
  uint8_t  deleted;
  uint8_t  favorite;
  uint8_t  nonce[CK_GCM_IV_LEN];
  uint8_t  tag[CK_GCM_TAG_LEN];
  uint8_t  ciphertext[DB_PAYLOAD_LEN];
};
#define DB_RECORD_SIZE sizeof(DbRecordOnDisk)

#define DB_AAD_LEN 4

// ── vault_crypto.ino's on-disk (NVS) crypto parameter bundle ──────────
// Defined here (rather than in vault_crypto.ino) for the same reason as
// everything else in this header: Arduino's automatic function-prototype
// generator scans the WHOLE concatenated sketch and hoists prototypes to
// the very top of the file, before any .ino-local struct definition has
// been seen — so a function taking a custom struct by reference fails to
// compile ("does not name a type") unless the struct comes from a header
// included up front. See also DbMutateFn/DbAppendFn and PwGenOptions
// below for the same pattern.
struct VaultCryptoParams {
  uint8_t  salt[CK_SALT_LEN];
  uint32_t iterations;
  uint16_t kdfVersion;
  uint8_t  wrapIv[CK_GCM_IV_LEN];
  uint8_t  wrappedKey[CK_KEY_LEN];
  uint8_t  wrapTag[CK_GCM_TAG_LEN];
};

// ── storage.ino's transactional-rewrite callback types ────────────────
typedef bool (*DbMutateFn)(DbRecordOnDisk &rec, void *ctx);
typedef bool (*DbAppendFn)(DbRecordOnDisk &out, void *ctx);

// ── db_migrate.ino's legacy (SecureKey v1) on-disk record layout ──────
// Must match the OLD theme.h PassRecord exactly, since that's the byte
// layout already on flash on any device upgrading from before this
// security rework.
struct __attribute__((packed)) LegacyPassRecordV1 {
  uint16_t id;
  uint8_t  deleted;
  char     folder[24];
  char     title[40];
  char     username[64];
  char     password[48];
  char     url[60];
  char     note[16];
  uint8_t  favorite;
};
static_assert(sizeof(LegacyPassRecordV1) == 256, "legacy v1 record layout changed");

// ── pwgen.ino's generator options ──────────────────────────────────────
struct PwGenOptions {
  uint8_t length;
  bool    upper;
  bool    lower;
  bool    digits;
  bool    symbols;
};
