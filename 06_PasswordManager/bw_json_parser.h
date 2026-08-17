// =============================================================
//  bw_json_parser.h  —  Streaming Bitwarden JSON export parser
//
//  NOT a general-purpose JSON library. Understands ONLY the fixed shape of
//  a Bitwarden unencrypted vault export:
//
//    {"encrypted":false,
//     "folders":[{"id":"...","name":"..."}, ...],
//     "items":[
//       {"type":1,"name":"...","notes":"...","folderId":"...",
//        "login":{"username":"...","password":"...",
//                 "uris":[{"uri":"..."}, ...],"totp":"..."},
//        "fields":[{"name":"...","value":"...","type":0}, ...]},
//       ...]}
//
//  Fed incrementally, up to BW_UPLOAD_CHUNK bytes at a time (matches the
//  ESP32 WebServer's HTTPUpload chunk size), via bwParserFeed(). All parser
//  state lives in the BwParserState struct passed by reference — nothing is
//  a local/stack variable across calls — so a token or string value that
//  spans two chunk boundaries (e.g. a password split across two 1436-byte
//  reads) resumes correctly on the next feed() call.
//
//  Isolated in its own .h/.cpp pair (like crypto_core.h/.cpp) — pure
//  algorithmic code, no Arduino-sketch type-visibility concerns, no
//  library headers leak into the rest of the sketch.
// =============================================================
#pragma once
#include <Arduino.h>
#include "shared_types.h"

// ── Bounds — enforced DURING accumulation, one byte at a time, never after.
// A field hitting its cap stops growing (further bytes are consumed and
// discarded, not rejected) — the parser stays in sync with the input
// stream regardless of how oversized a single value is.
#define BW_MAX_TITLE_LEN       PT_TITLE_LEN        // 40
#define BW_MAX_USERNAME_LEN    PT_USERNAME_LEN      // 64
#define BW_MAX_PASSWORD_LEN    PT_PASSWORD_LEN       // 48
#define BW_MAX_URL_LEN         PT_URL_LEN            // 60 (primary URI)
#define BW_MAX_NOTE_ACCUM_LEN  512    // scratch accumulation for notes + extra
                                       // URIs + TOTP + custom fields BEFORE the
                                       // final strncpy into the real 16-byte
                                       // note field — see bw_import.ino for why
                                       // truncation there is an accepted,
                                       // documented trade-off (PT_NOTE_LEN is
                                       // small and is NOT being grown for this
                                       // feature).
#define BW_MAX_FOLDER_NAME_LEN PT_FOLDER_NAME_LEN    // 48
#define BW_MAX_KEY_LEN         24     // JSON key-name scratch — Bitwarden's
                                       // known keys are all short constants
#define BW_MAX_ITEMS           2000   // hard cap on item count processed
#define BW_MAX_FOLDERS_IMPORT  MAX_FOLDERS   // 256
#define BW_MAX_UPLOAD_BYTES    (2 * 1024 * 1024)   // 2 MB whole-file cap
#define BW_MAX_SKIP_DEPTH      64     // sanity cap on the skip-depth counter

// ── Bitwarden item.type values we care about — everything else (Identity=3,
// Card=4, SSHKey and any future/unknown type) is classified Unsupported.
#define BW_ITEM_TYPE_LOGIN 1
#define BW_ITEM_TYPE_NOTE  2

// One fully-parsed item, handed to the caller's item-complete callback.
// This is intentionally PassRecord-shaped (already-extracted fields) rather
// than raw JSON — bw_import.ino writes this straight to a staging file.
struct BwParsedItem {
  int      itemType;                          // BW_ITEM_TYPE_* or 0 = unrecognized/unsupported
  char     title[BW_MAX_TITLE_LEN];
  char     username[BW_MAX_USERNAME_LEN];
  char     password[BW_MAX_PASSWORD_LEN];
  char     url[BW_MAX_URL_LEN];
  char     noteAccum[BW_MAX_NOTE_ACCUM_LEN];   // notes + extra URIs + TOTP + custom fields
  char     bwFolderId[40];                     // Bitwarden's own string folder id (or empty)
  bool     hasLogin;                           // true if a "login" object was present at all
};

// One fully-parsed folder entry.
struct BwParsedFolder {
  char bwId[40];
  char name[BW_MAX_FOLDER_NAME_LEN];
};

// bw_import.ino's Bitwarden-folder-id -> SecureKey-folder-id lookup entry,
// built once per commit (bwImportCommit()) and passed to bwResolveFolderId().
// Lives here (not in bw_import.ino) for the same hoisting reason as
// everything else in this header — it's used as a function parameter type.
struct BwFolderMapEntry {
  char     bwId[40];
  uint16_t skId;
};

// ── Internal state machine states ────────────────────────────────────────
enum BwState {
  BW_EXPECT_TOP_OBJ_OPEN,
  BW_IN_TOP_OBJECT,
  BW_IN_FOLDERS_ARRAY,
  BW_IN_FOLDER_OBJECT,
  BW_IN_ITEMS_ARRAY,
  BW_IN_ITEM_OBJECT,
  BW_IN_LOGIN_OBJECT,
  BW_IN_URIS_ARRAY,
  BW_IN_URI_OBJECT,
  BW_IN_FIELDS_ARRAY,
  BW_IN_FIELD_OBJECT,
  BW_DONE,
  BW_ERROR
};

// Generic value sub-parser states — used both when accumulating a value we
// care about, and when skipping one we don't.
enum BwValState {
  BW_VAL_NONE,
  BW_VAL_STRING,
  BW_VAL_STRING_ESCAPE,
  BW_VAL_NUMBER,
  BW_VAL_LITERAL,        // true / false / null
  BW_VAL_SKIP,           // generic skip (object/array/string/number/literal)
};

// Which known field the current string value is being accumulated into
// (only meaningful while state/valState indicate "accumulating a known
// value"). BW_TARGET_NONE means "discard" (used by the key-name buffer
// itself, and by skipped/unknown values).
enum BwTarget {
  BW_TARGET_NONE,
  BW_TARGET_KEY,
  BW_TARGET_ITEM_TYPE,
  BW_TARGET_ITEM_NAME,
  BW_TARGET_ITEM_NOTES,
  BW_TARGET_ITEM_FOLDERID,
  BW_TARGET_LOGIN_USERNAME,
  BW_TARGET_LOGIN_PASSWORD,
  BW_TARGET_LOGIN_TOTP,
  BW_TARGET_URI_VALUE,
  BW_TARGET_FIELD_NAME,
  BW_TARGET_FIELD_VALUE,
  BW_TARGET_FOLDER_ID,
  BW_TARGET_FOLDER_NAME,
};

#define BW_KEY_BUF_LEN     BW_MAX_KEY_LEN
#define BW_VAL_BUF_LEN     BW_MAX_NOTE_ACCUM_LEN   // largest single scratch buffer needed

struct BwParserState {
  BwState    state;
  BwValState valState;
  bool       escapePending;
  int        skipDepth;         // depth counter while valState==BW_VAL_SKIP on an object/array
  char       skipOpenChar;      // '{' or '[' — which bracket we're skipping (0 = none/string/etc)
  bool       skipInString;      // true while skip-scanning is currently inside a quoted string
                                 // (so embedded { } [ ] characters don't perturb skipDepth)

  char       keyBuf[BW_KEY_BUF_LEN];
  uint8_t    keyLen;
  bool       expectKey;    // true = next '"' starts a KEY name; false = next
                            // token is that key's VALUE. Distinct from
                            // target==BW_TARGET_NONE, which is ALSO true right
                            // after a key finishes flushing — target alone
                            // can't tell "about to read a key" from "about to
                            // read an unrecognized value" apart.

  BwTarget   target;
  char       valBuf[BW_VAL_BUF_LEN];
  uint16_t   valLen;
  bool       valOverflowed;     // true if valBuf hit its cap this value (informational only)

  // Numeric accumulator (item.type / field.type) — bounded, never used as a
  // memory index or size, so no overflow can cause a memory-safety issue;
  // clamped to a safe "unknown" sentinel if it grows unreasonably large.
  long       numVal;
  bool       numNegative;

  // In-progress item/folder being assembled.
  BwParsedItem   curItem;
  BwParsedFolder curFolder;
  bool           curItemHasNote;   // has anything been appended to noteAccum yet? (for separators)

  // Whole-upload counters (also readable by the caller after each feed()).
  uint32_t bytesFed;
  uint32_t itemsSeen;
  uint32_t foldersSeen;
  bool     sawEncryptedTrue;   // "encrypted":true seen at top level -> reject the whole file

  bool     errored;            // sticky — true once BW_ERROR is reached
};

// ── Public API ────────────────────────────────────────────────────────
void bwParserInit(BwParserState &st);

// Feed up to `len` bytes (one HTTPUpload WRITE chunk). Returns false once
// the parser has entered BW_ERROR (sticky — all further bytes are ignored
// and every subsequent call also returns false). Callback signatures below
// are invoked synchronously, from within this call, whenever a complete
// item/folder is parsed.
typedef void (*BwOnItemFn)(const BwParsedItem &item, void *ctx);
typedef void (*BwOnFolderFn)(const BwParsedFolder &folder, void *ctx);

bool bwParserFeed(BwParserState &st, const uint8_t *chunk, size_t len,
                  BwOnItemFn onItem, void *itemCtx,
                  BwOnFolderFn onFolder, void *folderCtx);

// True once the parser has seen the matching close of the top-level object
// (a well-formed end of input) OR entered BW_ERROR.
bool bwParserDone(const BwParserState &st);
bool bwParserErrored(const BwParserState &st);
