// =============================================================
//  folders.ino  —  Encrypted folder table (/folders.bin)
//
//  A small sibling of storage.ino's /db.bin: its own header/magic, its own
//  fixed-size encrypted records, same AES-256-GCM primitive and the SAME
//  vaultMasterKey (no second key, no separate crypto scheme — see
//  shared_types.h's folder-table comment block).
//
//  PassRecord.folder[24] (theme.h) holds the DECIMAL STRING of a folder id
//  from this table — never a name directly. folderNameForId()/
//  folderIdForName() are the only translation points; every other file
//  (screen_list.ino, storage.ino's dbLoadIndex()) just treats the
//  RESOLVED name as an opaque display string, same as before this file
//  existed.
//
//  In-RAM index: a small array (max MAX_FOLDERS=256 entries, ~12 KB) loaded
//  once per unlock — far smaller than the password index, so it lives in
//  regular RAM, not PSRAM.
// =============================================================
#include "crypto_core.h"
#include "shared_types.h"

struct FolderIndexEntry {
  uint16_t id;
  char     name[PT_FOLDER_NAME_LEN];
};

static FolderIndexEntry folderIndex[MAX_FOLDERS];
static uint16_t         folderIndexCount = 0;

// ── AAD binding: id + deleted are authenticated but not encrypted ───────
static void folderBuildAad(uint8_t *aad, uint16_t id, uint8_t deleted) {
  memcpy(aad, &id, 2);
  aad[2] = deleted;
}

// ── Encrypt/decrypt one folder record's payload ──────────────────────────
// Non-static: db_migrate_v3.ino and bw_import.ino (which sort alphabetically
// around this file) call these directly too — same reasoning as storage.ino's
// dbEncryptRecord/dbDecryptRecord being non-static.
bool folderEncryptRecord(const char *name, uint16_t id, uint8_t deleted,
                         FolderRecordOnDisk &out) {
  out.id      = id;
  out.deleted = deleted;
  out.reserved = 0;
  ckRandomBytes(out.nonce, sizeof(out.nonce));   // fresh nonce EVERY write

  FolderPlainPayload pt;
  memset(&pt, 0, sizeof(pt));
  strncpy(pt.name, name, sizeof(pt.name) - 1);

  uint8_t aad[FOLDER_AAD_LEN];
  folderBuildAad(aad, out.id, out.deleted);

  bool ok = ckAesGcmEncrypt(vaultMasterKey, out.nonce, sizeof(out.nonce),
                            aad, sizeof(aad),
                            (const uint8_t *)&pt, sizeof(pt),
                            out.ciphertext, out.tag);
  ckSecureZero(&pt, sizeof(pt));
  return ok;
}

bool folderDecryptRecord(const FolderRecordOnDisk &in, char *outName, size_t outLen) {
  uint8_t aad[FOLDER_AAD_LEN];
  folderBuildAad(aad, in.id, in.deleted);

  FolderPlainPayload pt;
  bool ok = ckAesGcmDecrypt(vaultMasterKey, in.nonce, sizeof(in.nonce),
                            aad, sizeof(aad),
                            in.ciphertext, sizeof(in.ciphertext),
                            in.tag, (uint8_t *)&pt);
  if (!ok) {
    ckSecureZero(&pt, sizeof(pt));
    if (outLen) outName[0] = 0;
    return false;
  }
  strncpy(outName, pt.name, outLen - 1);
  outName[outLen - 1] = 0;
  ckSecureZero(&pt, sizeof(pt));
  return true;
}

// ── Header helpers (mirror storage.ino's dbReadHeader/dbWriteHeader) ────
bool folderReadHeader(File &f, FolderHeader &hdr) {
  if (f.read((uint8_t *)&hdr, sizeof(hdr)) != sizeof(hdr)) return false;
  return memcmp(hdr.magic, FOLDER_MAGIC, 4) == 0;
}
void folderWriteHeader(File &f, uint16_t count) {
  FolderHeader hdr;
  memcpy(hdr.magic, FOLDER_MAGIC, 4);
  hdr.formatVersion = FOLDER_FORMAT_VERSION;
  hdr.recordCount   = count;
  hdr.reserved      = 0;
  f.write((uint8_t *)&hdr, sizeof(hdr));
}

bool foldersExists() {
  File f = FFat.open(FOLDER_PATH, "r");
  if (!f) return false;
  FolderHeader hdr;
  bool ok = folderReadHeader(f, hdr);
  f.close();
  return ok;
}

bool foldersCreateEmpty() {
  if (!vaultUnlocked) return false;
  File f = FFat.open(FOLDER_PATH, "w");
  if (!f) return false;
  folderWriteHeader(f, 0);
  f.flush();
  f.close();
  return true;
}

// ── Load the folder table into the in-RAM index ─────────────────────────
void foldersLoadIndex() {
  folderIndexCount = 0;
  if (!vaultUnlocked) return;
  File f = FFat.open(FOLDER_PATH, "r");
  if (!f) return;
  FolderHeader hdr;
  if (!folderReadHeader(f, hdr)) { f.close(); return; }

  FolderRecordOnDisk rec;
  while (f.available() >= (int)FOLDER_RECORD_SIZE && folderIndexCount < MAX_FOLDERS) {
    if (f.read((uint8_t *)&rec, FOLDER_RECORD_SIZE) != FOLDER_RECORD_SIZE) break;
    if (rec.deleted) continue;
    char name[PT_FOLDER_NAME_LEN];
    if (!folderDecryptRecord(rec, name, sizeof(name))) continue;   // skip corrupt
    folderIndex[folderIndexCount].id = rec.id;
    strncpy(folderIndex[folderIndexCount].name, name, sizeof(folderIndex[folderIndexCount].name) - 1);
    folderIndex[folderIndexCount].name[sizeof(folderIndex[folderIndexCount].name) - 1] = 0;
    folderIndexCount++;
    ckSecureZero(name, sizeof(name));
  }
  f.close();
}

uint16_t foldersCount() { return folderIndexCount; }
bool foldersGetAt(uint16_t idx, uint16_t &id, char *outName, size_t outLen) {
  if (idx >= folderIndexCount) return false;
  id = folderIndex[idx].id;
  strncpy(outName, folderIndex[idx].name, outLen - 1);
  outName[outLen - 1] = 0;
  return true;
}

// ── id -> name resolution (used by dbLoadIndex() to populate ListItem.folder) ──
// Falls back to a safe placeholder rather than failing — a missing/unknown id
// must never crash or leave a caller's buffer uninitialized (matters for
// crash-safety during the v2->v3 migration: if power is lost exactly between
// the DB swap and the folders-file swap, folderNameForId() may transiently be
// asked to resolve an id from the NEW db against the OLD folders file).
bool folderNameForId(uint16_t id, char *outName, size_t outLen) {
  if (!outName || outLen == 0) return false;
  if (id == 0) { strncpy(outName, "", outLen - 1); outName[outLen - 1] = 0; return true; }
  for (uint16_t i = 0; i < folderIndexCount; i++) {
    if (folderIndex[i].id == id) {
      strncpy(outName, folderIndex[i].name, outLen - 1);
      outName[outLen - 1] = 0;
      return true;
    }
  }
  strncpy(outName, "Folder", outLen - 1);   // fallback placeholder — never fails
  outName[outLen - 1] = 0;
  return false;
}

// ── name -> id resolution, creating a new folder if none matches ────────
// Case-insensitive match. Used by the Add/Edit "+ New Folder" path and by
// the Bitwarden import pipeline (bw_import.ino). Writes straight to
// /folders.bin using the same crash-safe transactional-append shape as
// storage.ino's dbAppend() — but hand-rolled here since folders.ino has no
// shared dbRewriteTransacted-equivalent of its own (this file is small
// enough that a dedicated append path is simpler than building a second
// generic rewrite primitive for a table this size).
static uint16_t foldersNextId() {
  uint16_t maxId = 0;
  for (uint16_t i = 0; i < folderIndexCount; i++)
    if (folderIndex[i].id > maxId) maxId = folderIndex[i].id;
  return (uint16_t)(maxId + 1);
}

// Crash-safe transactional append, mirroring storage.ino's dbRewriteTransacted
// shape at a smaller scale: copy every existing record through unchanged,
// append the new one, verify, then atomically swap.
static bool foldersAppend(uint16_t newId, const char *name) {
  if (!vaultUnlocked) return false;
  if (!foldersExists()) { if (!foldersCreateEmpty()) return false; }

  File dst = FFat.open(FOLDER_TMP_PATH, "w");
  if (!dst) return false;
  uint16_t count = 0;
  folderWriteHeader(dst, 0);   // placeholder, patched below

  File src = FFat.open(FOLDER_PATH, "r");
  if (src) {
    FolderHeader shdr;
    if (folderReadHeader(src, shdr)) {
      FolderRecordOnDisk rec;
      while (src.available() >= (int)FOLDER_RECORD_SIZE) {
        if (src.read((uint8_t *)&rec, FOLDER_RECORD_SIZE) != (int)FOLDER_RECORD_SIZE) break;
        dst.write((uint8_t *)&rec, FOLDER_RECORD_SIZE);
        count++;
      }
    }
    src.close();
  }

  FolderRecordOnDisk newRec;
  bool ok = folderEncryptRecord(name, newId, 0, newRec);
  if (ok) { dst.write((uint8_t *)&newRec, FOLDER_RECORD_SIZE); count++; }
  ckSecureZero(&newRec, sizeof(newRec));

  dst.flush();
  dst.seek(0);
  folderWriteHeader(dst, count);
  dst.flush();
  dst.close();

  if (!ok) { FFat.remove(FOLDER_TMP_PATH); return false; }

  // Verify before touching the real file.
  File verify = FFat.open(FOLDER_TMP_PATH, "r");
  if (!verify) { FFat.remove(FOLDER_TMP_PATH); return false; }
  FolderHeader vhdr;
  bool verifyOk = folderReadHeader(verify, vhdr) && vhdr.recordCount == count;
  size_t expectedSize = sizeof(FolderHeader) + (size_t)count * FOLDER_RECORD_SIZE;
  verifyOk = verifyOk && (verify.size() == expectedSize);
  verify.close();
  if (!verifyOk) { FFat.remove(FOLDER_TMP_PATH); return false; }

  FFat.remove(FOLDER_PATH);
  FFat.rename(FOLDER_TMP_PATH, FOLDER_PATH);
  return true;
}

uint16_t folderIdForName(const char *name) {
  if (!name || !name[0]) return 0;   // empty name -> "no folder" sentinel
  for (uint16_t i = 0; i < folderIndexCount; i++) {
    if (strcasecmp(folderIndex[i].name, name) == 0) return folderIndex[i].id;
  }
  if (folderIndexCount >= MAX_FOLDERS) return 0;   // table full — fall back to "no folder"

  uint16_t newId = foldersNextId();
  if (!foldersAppend(newId, name)) return 0;

  // Keep the in-RAM index in sync without a full reload.
  folderIndex[folderIndexCount].id = newId;
  strncpy(folderIndex[folderIndexCount].name, name, sizeof(folderIndex[folderIndexCount].name) - 1);
  folderIndex[folderIndexCount].name[sizeof(folderIndex[folderIndexCount].name) - 1] = 0;
  folderIndexCount++;
  return newId;
}
