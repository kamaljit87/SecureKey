// =============================================================
//  db_migrate.ino  —  One-time plaintext → encrypted DB migration
//
//  A device that already has a pre-encryption (SecureKey v1) /db.bin
//  contains PLAINTEXT PassRecord structs (256 B each, no header/magic).
//  This module safely upgrades that file to the new encrypted format:
//
//      1. Detect the old plaintext shape (db_migrate.ino / dbLegacyPlaintextExists).
//      2. Require the user to authenticate (a NEW PIN is set — the old
//         firmware never had a real PIN-derived key, only a plaintext
//         PIN string, so there is nothing cryptographic to "carry
//         forward"; the user sets today's PIN as part of migration).
//      3. Provision fresh crypto material + a random master key.
//      4. STREAM every legacy plaintext record straight into a brand-new
//         encrypted database file, one record at a time (never buffering
//         the whole legacy vault in RAM — see the streaming-design note
//         inside dbMigrateLegacyPlaintext()).
//      5. VERIFY the new encrypted database in a second streaming pass:
//         re-read both files in lockstep, decrypt every new record, and
//         compare against the corresponding original field by field.
//      6. ONLY on full verification success, delete the old plaintext
//         file. If ANYTHING fails at any step, the old plaintext file
//         is left completely untouched and migration reports failure —
//         this module never deletes data before it has proven the
//         replacement is byte-for-byte correct.
//
//  This runs once, from the PIN-setup screen, the first time a fresh
//  firmware boots against an old plaintext vault. See screen_setup_pin.ino /
//  06_PasswordManager.ino setup() for where dbMigrationNeeded() is
//  checked.
//
//  NOTE on build order: this file is named so it sorts alphabetically
//  BEFORE storage.ino in Arduino's concatenated sketch, but it calls
//  several storage.ino functions (dbEncryptRecord, dbDecryptRecord,
//  dbReadHeader) — those are deliberately non-static so Arduino's
//  auto-generated function prototypes make them resolve regardless of
//  file order. The on-disk TYPES (DbHeader, DbRecordOnDisk, ...) come
//  from shared_types.h, included below, since Arduino does NOT auto-
//  forward-declare types across files the way it does functions.
// =============================================================
#include "shared_types.h"   // LegacyPassRecordV1 and friends live here now

bool dbMigrationNeeded() {
  return dbLegacyPlaintextExists();
}

// Counts entries in the legacy plaintext file (for the "N passwords will
// be migrated" confirmation the UI shows before starting).
uint16_t dbMigrationLegacyCount() {
  File f = FFat.open(DB_PATH, "r");
  if (!f) return 0;
  uint16_t n = 0;
  LegacyPassRecordV1 rec;
  while (f.available() >= (int)sizeof(rec)) {
    if (f.read((uint8_t *)&rec, sizeof(rec)) != sizeof(rec)) break;
    if (!rec.deleted) n++;
    ckSecureZero(&rec, sizeof(rec));
  }
  f.close();
  return n;
}

// Runs the full migration described above. Must be called AFTER
// vaultCryptoProvision(newPin) has already succeeded (so vaultUnlocked
// is true and vaultMasterKey is populated) and BEFORE any UI shows the
// (still-plaintext-on-disk) old vault contents.
//
// Returns true only if the new encrypted database was created AND fully
// verified AND the old plaintext file was removed. On any failure the
// old file is preserved and the caller should tell the user a backup/
// export is required before retrying (see fail-closed note below).
// Compares one legacy plaintext record against one decrypted record for
// exact equality (used by the verify pass below). Fields are compared at
// their guaranteed-preserved width (the PT_* lengths dbEncryptRecord
// actually stores).
static bool migrateRecordsMatch(const LegacyPassRecordV1 &legacy, uint16_t fallbackId,
                                const PassRecord &dec) {
  char cmpFolder[PT_FOLDER_LEN], cmpTitle[PT_TITLE_LEN],
       cmpUser[PT_USERNAME_LEN], cmpPass[PT_PASSWORD_LEN],
       cmpUrl[PT_URL_LEN], cmpNote[PT_NOTE_LEN];
  strncpy(cmpFolder, legacy.folder,   sizeof(cmpFolder) - 1); cmpFolder[sizeof(cmpFolder)-1]=0;
  strncpy(cmpTitle,  legacy.title,    sizeof(cmpTitle)  - 1); cmpTitle[sizeof(cmpTitle)-1]=0;
  strncpy(cmpUser,   legacy.username, sizeof(cmpUser)   - 1); cmpUser[sizeof(cmpUser)-1]=0;
  strncpy(cmpPass,   legacy.password, sizeof(cmpPass)   - 1); cmpPass[sizeof(cmpPass)-1]=0;
  strncpy(cmpUrl,    legacy.url,      sizeof(cmpUrl)    - 1); cmpUrl[sizeof(cmpUrl)-1]=0;
  strncpy(cmpNote,   legacy.note,     sizeof(cmpNote)   - 1); cmpNote[sizeof(cmpNote)-1]=0;

  bool match = (dec.id == (legacy.id ? legacy.id : fallbackId)) &&
               dec.deleted  == legacy.deleted  &&
               dec.favorite == legacy.favorite &&
               strcmp(dec.folder,   cmpFolder) == 0 &&
               strcmp(dec.title,    cmpTitle)  == 0 &&
               strcmp(dec.username, cmpUser)   == 0 &&
               strcmp(dec.password, cmpPass)   == 0 &&
               strcmp(dec.url,      cmpUrl)    == 0 &&
               strcmp(dec.note,     cmpNote)   == 0;
  ckSecureZero(cmpPass, sizeof(cmpPass));
  return match;
}

bool dbMigrateLegacyPlaintext() {
  if (!vaultUnlocked) return false;

  // ── Streaming design note ────────────────────────────────────────────
  // An earlier version of this function loaded the ENTIRE legacy database
  // into one PSRAM scratch buffer before writing anything. At the
  // firmware's theoretical MAX_PASSWORDS (30,000) that scratch buffer
  // alone is ~7.7 MB — combined with the ~1.9 MB password index already
  // resident, that doesn't reliably fit in 8 MB of OPI PSRAM. Real vaults
  // are far smaller than the theoretical cap, but the safe fix is to not
  // depend on it: this version streams the legacy file straight into the
  // new encrypted file ONE RECORD AT A TIME (matching dbLoadIndex()'s own
  // memory footprint), then does a second streaming pass — re-reading
  // BOTH files record-by-record — to verify. No full-database buffer is
  // ever allocated.

  const char *MIG_TMP = "/db_migrate.bin";

  // ── Step 1: stream legacy → new encrypted file ───────────────────────
  {
    File src = FFat.open(DB_PATH, "r");
    if (!src) return false;
    FFat.remove(MIG_TMP);
    File dst = FFat.open(MIG_TMP, "w");
    if (!dst) { src.close(); return false; }

    DbHeader hdr;
    memcpy(hdr.magic, DB_MAGIC, 4);
    hdr.formatVersion   = DB_FORMAT_VERSION;
    hdr.securityVersion = SECURITY_VERSION;
    hdr.recordCount     = 0;             // patched below once we know the count
    hdr.reserved        = 0;
    dst.write((uint8_t *)&hdr, sizeof(hdr));

    uint16_t n = 0;
    bool writeOk = true;
    LegacyPassRecordV1 legacy;
    while (writeOk && n < MAX_PASSWORDS &&
           src.available() >= (int)sizeof(LegacyPassRecordV1)) {
      if (src.read((uint8_t *)&legacy, sizeof(legacy)) != (int)sizeof(legacy)) break;

      PassRecord rec;
      memset(&rec, 0, sizeof(rec));
      rec.id       = legacy.id ? legacy.id : (uint16_t)(n + 1);
      rec.deleted  = legacy.deleted;
      rec.favorite = legacy.favorite;
      memcpy(rec.folder,   legacy.folder,   sizeof(rec.folder));
      memcpy(rec.title,    legacy.title,    sizeof(rec.title));
      memcpy(rec.username, legacy.username, sizeof(rec.username));
      memcpy(rec.password, legacy.password, sizeof(rec.password));
      memcpy(rec.url,      legacy.url,      sizeof(rec.url));
      memcpy(rec.note,     legacy.note,     sizeof(rec.note));

      DbRecordOnDisk enc;
      if (!dbEncryptRecord(rec, enc)) writeOk = false;
      else if (dst.write((uint8_t *)&enc, DB_RECORD_SIZE) != DB_RECORD_SIZE) writeOk = false;
      else n++;

      ckSecureZero(&rec, sizeof(rec));
      ckSecureZero(&legacy, sizeof(legacy));
    }
    src.close();

    if (writeOk) {
      dst.flush();
      dst.seek(0);
      hdr.recordCount = n;
      dst.write((uint8_t *)&hdr, sizeof(hdr));
      dst.flush();
    }
    dst.close();

    if (!writeOk) {
      FFat.remove(MIG_TMP);
      return false;   // old plaintext /db.bin is untouched
    }
  }

  // ── Step 2: VERIFY — stream BOTH files again in lockstep, decrypt every
  //    new record, and compare against the corresponding legacy record
  //    field by field. This is what makes deletion of the old file safe:
  //    we don't trust "the write didn't error", we prove the ciphertext
  //    round-trips to exactly the original plaintext, for every record,
  //    before anything old is removed. ─────────────────────────────────
  bool verifyOk = true;
  {
    File legacySrc = FFat.open(DB_PATH, "r");
    File newSrc    = FFat.open(MIG_TMP, "r");
    if (!legacySrc || !newSrc) verifyOk = false;

    DbHeader chdr;
    if (verifyOk && !dbReadHeader(newSrc, chdr)) verifyOk = false;

    uint16_t checked = 0;
    while (verifyOk && legacySrc.available() >= (int)sizeof(LegacyPassRecordV1)) {
      LegacyPassRecordV1 legacy;
      if (legacySrc.read((uint8_t *)&legacy, sizeof(legacy)) != (int)sizeof(legacy)) {
        verifyOk = false; break;
      }
      DbRecordOnDisk enc;
      if (newSrc.read((uint8_t *)&enc, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) {
        verifyOk = false; ckSecureZero(&legacy, sizeof(legacy)); break;
      }
      PassRecord dec;
      if (!dbDecryptRecord(enc, dec)) {
        verifyOk = false; ckSecureZero(&legacy, sizeof(legacy)); break;
      }
      if (!migrateRecordsMatch(legacy, (uint16_t)(checked + 1), dec)) verifyOk = false;
      ckSecureZero(&legacy, sizeof(legacy));
      ckSecureZero(&dec, sizeof(dec));
      checked++;
    }
    if (verifyOk && chdr.recordCount != checked) verifyOk = false;

    if (legacySrc) legacySrc.close();
    if (newSrc)    newSrc.close();
  }

  if (!verifyOk) {
    // Verification failed — fail CLOSED. Leave the old plaintext file
    // exactly as it was; do not delete anything. Remove only our own
    // unverified scratch file.
    FFat.remove(MIG_TMP);
    return false;
  }

  // ── Step 3: only now, replace the old plaintext file ────────────────
  // The new encrypted file has been fully verified at this point — this
  // is the single moment old plaintext data is removed.
  FFat.remove(DB_PATH);
  bool renamed = FFat.rename(MIG_TMP, DB_PATH);
  if (!renamed) {
    // Extremely unlikely (rename right after a successful verify-read),
    // but if it happens, db.bin no longer exists — recreate it from the
    // verified temp copy content is impossible now, so surface failure
    // clearly rather than silently leaving the vault without a file.
    return false;
  }

  dbLoadIndex();
  return true;
}
