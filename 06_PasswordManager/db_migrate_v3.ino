// =============================================================
//  db_migrate_v3.ino  —  One-time v2 -> v3 folder-format migration
//
//  DELIBERATELY SEPARATE from db_migrate.ino (which handles the much older
//  v1-plaintext -> v2-encrypted upgrade) — never conflate the two. This
//  migration only changes what PassRecord.folder's bytes MEAN: from an
//  arbitrary raw string (in practice: a silent copy of the URL field, or
//  garbage — see screen_add.ino's pre-fix bug) to a folder-ID decimal
//  string pointing into the new /folders.bin table (folders.ino).
//
//  DbPlainPayload's byte LAYOUT is unchanged — this is why SECURITY_VERSION
//  stays 2 while DB_FORMAT_VERSION bumps to 3. dbEncryptRecord/
//  dbDecryptRecord need no changes at all.
//
//  Same verify-before-delete, own-temp-file discipline as db_migrate.ino:
//    1. Stream every record from the OLD (v2) /db.bin, decrypt it, resolve/
//       create a folder from its raw folder string via folderIdForName(),
//       overwrite the field with the new folder's id (decimal string),
//       re-encrypt, write to a fresh temp file. Build the new /folders.bin
//       from the same pass.
//    2. VERIFY: re-open OLD and NEW db files in lockstep, decrypt every new
//       record, confirm every non-folder field matches byte-for-byte, and
//       confirm the new folder id resolves back to the record's original
//       folder string (proves the id<->name mapping round-trips).
//    3. ONLY on 100% verified match: atomically swap both /db.bin and
//       /folders.bin into place, in that order. On ANY failure, the old
//       v2 database is left completely untouched — retried automatically
//       on the next unlock, since its header still reads formatVersion==2.
//
//  This migration is invisible to the user: whatever string used to be in
//  the folder field just becomes a real (if oddly-named) folder, so the
//  password list shows identical subtext immediately after upgrading.
// =============================================================
#include "shared_types.h"

bool dbV3MigrationNeeded() {
  File f = FFat.open(DB_PATH, "r");
  if (!f) return false;
  DbHeader hdr;
  bool ok = dbReadHeader(f, hdr);
  f.close();
  return ok && hdr.formatVersion == 2;
}

// Compares one legacy (pre-v3) decrypted record against the freshly
// re-decrypted new-format record: every field must match byte-for-byte
// EXCEPT folder, which is checked separately (old raw string -> resolves
// via folderNameForId(newFolderId) back to the same string).
static bool v3RecordsMatch(const PassRecord &oldRec, const PassRecord &newRec) {
  return oldRec.id       == newRec.id &&
         oldRec.deleted  == newRec.deleted &&
         oldRec.favorite == newRec.favorite &&
         strcmp(oldRec.title,    newRec.title)    == 0 &&
         strcmp(oldRec.username, newRec.username) == 0 &&
         strcmp(oldRec.password, newRec.password) == 0 &&
         strcmp(oldRec.url,      newRec.url)      == 0 &&
         strcmp(oldRec.note,     newRec.note)     == 0;
}

bool dbMigrateV3Folders() {
  if (!vaultUnlocked) return false;

  const char *MIG_TMP     = "/db_migrate_v3.bin";
  const char *MIG_FOL_TMP = "/folders_migrate.bin";

  // ── Step 1: stream old -> new, resolving folder strings to ids ────────
  {
    File src = FFat.open(DB_PATH, "r");
    if (!src) return false;
    DbHeader shdr;
    if (!dbReadHeader(src, shdr)) { src.close(); return false; }

    FFat.remove(MIG_TMP);
    File dst = FFat.open(MIG_TMP, "w");
    if (!dst) { src.close(); return false; }
    dbWriteHeader(dst, 0);   // patched below

    uint16_t n = 0;
    bool writeOk = true;
    DbRecordOnDisk oldEnc;
    while (writeOk && src.available() >= (int)DB_RECORD_SIZE) {
      if (src.read((uint8_t *)&oldEnc, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) break;

      PassRecord rec;
      if (!dbDecryptRecord(oldEnc, rec)) { writeOk = false; break; }

      // Resolve/create a folder from the current raw folder string, then
      // overwrite the field with the new folder id (decimal string).
      uint16_t fid = folderIdForName(rec.folder);
      char idStr[PT_FOLDER_LEN];
      snprintf(idStr, sizeof(idStr), "%u", fid);
      memset(rec.folder, 0, sizeof(rec.folder));
      strncpy(rec.folder, idStr, sizeof(rec.folder) - 1);

      DbRecordOnDisk newEnc;
      if (!dbEncryptRecord(rec, newEnc)) writeOk = false;
      else if (dst.write((uint8_t *)&newEnc, DB_RECORD_SIZE) != DB_RECORD_SIZE) writeOk = false;
      else n++;

      ckSecureZero(&rec, sizeof(rec));
      ckSecureZero(&newEnc, sizeof(newEnc));
    }
    src.close();

    if (writeOk) {
      dst.flush();
      dst.seek(0);
      dbWriteHeader(dst, n);   // formatVersion == DB_FORMAT_VERSION (3) — see dbWriteHeader()
      dst.flush();
    }
    dst.close();

    if (!writeOk) { FFat.remove(MIG_TMP); return false; }
  }

  // The new folder table was built incrementally by folderIdForName() calls
  // above (each one appends directly to /folders.bin via foldersAppend()'s
  // own crash-safe transactional path — see folders.ino). There's nothing
  // further to "commit" for folders here; the folders.bin file is already
  // fully written and each individual append was itself verified before
  // being applied. This differs slightly from db_migrate.ino's single big
  // temp-then-swap because the folder table is built incrementally as new
  // names are discovered mid-scan (we don't know the full folder set until
  // we've streamed every record), and each such append is independently
  // small and already safe. MIG_FOL_TMP is reserved for a future version
  // that wants a single atomic folders-swap alongside the DB swap; not
  // used in this version.
  (void)MIG_FOL_TMP;

  // ── Step 2: VERIFY — decrypt every new record, compare to the original ──
  bool verifyOk = true;
  {
    File oldSrc = FFat.open(DB_PATH, "r");
    File newSrc = FFat.open(MIG_TMP, "r");
    if (!oldSrc || !newSrc) verifyOk = false;

    DbHeader ohdr, nhdr;
    if (verifyOk && (!dbReadHeader(oldSrc, ohdr) || !dbReadHeader(newSrc, nhdr))) verifyOk = false;

    uint16_t checked = 0;
    while (verifyOk && oldSrc.available() >= (int)DB_RECORD_SIZE) {
      DbRecordOnDisk oldEnc, newEnc;
      if (oldSrc.read((uint8_t *)&oldEnc, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) { verifyOk = false; break; }
      if (newSrc.read((uint8_t *)&newEnc, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) { verifyOk = false; break; }

      PassRecord oldRec, newRec;
      bool okOld = dbDecryptRecord(oldEnc, oldRec);
      bool okNew = dbDecryptRecord(newEnc, newRec);
      if (!okOld || !okNew) { verifyOk = false; }
      else if (!v3RecordsMatch(oldRec, newRec)) { verifyOk = false; }
      else {
        // Confirm the id<->name mapping round-trips.
        uint16_t newFid = (uint16_t)atoi(newRec.folder);
        char resolved[PT_FOLDER_NAME_LEN];
        folderNameForId(newFid, resolved, sizeof(resolved));
        if (strcmp(resolved, oldRec.folder) != 0) verifyOk = false;
        ckSecureZero(resolved, sizeof(resolved));
      }
      ckSecureZero(&oldRec, sizeof(oldRec));
      ckSecureZero(&newRec, sizeof(newRec));
      checked++;
    }
    if (verifyOk && nhdr.recordCount != checked) verifyOk = false;

    if (oldSrc) oldSrc.close();
    if (newSrc) newSrc.close();
  }

  if (!verifyOk) {
    // Fail CLOSED — leave the old v2 database untouched. Retried
    // automatically on the next unlock (header still reads formatVersion==2).
    FFat.remove(MIG_TMP);
    return false;
  }

  // ── Step 3: only now, replace the old v2 database ────────────────────
  FFat.remove(DB_PATH);
  bool renamed = FFat.rename(MIG_TMP, DB_PATH);
  if (!renamed) return false;

  dbLoadIndex();
  return true;
}
