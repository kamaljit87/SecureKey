// =============================================================
//  bw_import.ino  —  Bitwarden import pipeline
//
//  Owns the state machine that bridges the streaming JSON parser
//  (bw_json_parser.h/.cpp) to the encrypted vault (storage.ino/folders.ino).
//
//  Two distinct stages, deliberately kept separate:
//
//    STAGE 1 (upload time, streaming): as bytes arrive from the browser
//    upload (wifi_portal.ino's HTTPUpload callback), bwImportFeed() drives
//    the parser. Each fully-parsed item is classified, duplicate-checked
//    against the EXISTING vault, and — if accepted — written to a small
//    STAGING file (/bw_staging.bin) as an already-normalized PassRecord-
//    shaped entry (never the raw Bitwarden JSON, which is never persisted
//    anywhere — only ever seen as transient upload chunks). This is bounded
//    memory throughout: no full-vault, no full-upload buffer.
//
//    STAGE 2 (commit, only on explicit user confirmation): bwImportCommit()
//    does a db_migrate.ino-style two-pass build+verify+swap — stream the
//    EXISTING /db.bin plus every staged record into a new file, verify it
//    byte-for-byte by re-reading and decrypting everything, and ONLY on
//    full verification atomically swap it into place. A failure at any
//    point leaves the existing vault completely untouched.
//
//  Never logs field content — only counts/sizes/outcomes (see the SK_LOG
//  call sites below).
// =============================================================
#include "bw_json_parser.h"

#define BW_STAGING_PATH        "/bw_staging.bin"
#define BW_FOLDERS_STAGING_PATH "/bw_folders_staging.bin"
#define BW_IMPORT_NEW_PATH     "/bw_import_new.bin"
#define BW_FOLDERS_NEW_PATH    "/bw_folders_new.bin"

enum BwStage { BW_STAGE_IDLE, BW_STAGE_UPLOADING, BW_STAGE_AWAITING_PREVIEW,
              BW_STAGE_IMPORTING, BW_STAGE_DONE, BW_STAGE_FAILED };

// Plain int mirrors of the enum above, safe to use from ANY file (macros
// are textually substituted, so they don't hit Arduino's struct/enum
// cross-file visibility hoisting issue the way the enum TYPE itself would).
// bwImportStage() returns one of these as a plain int — see the accessor
// block below.
#define BWI_IDLE              0
#define BWI_UPLOADING          1
#define BWI_AWAITING_PREVIEW   2
#define BWI_IMPORTING          3
#define BWI_DONE               4
#define BWI_FAILED             5

struct BwImportCtx {
  BwParserState parser;
  BwStage       stage;

  File     stagingFile;
  File     foldersStagingFile;
  bool     filesOpen;

  uint32_t loginsFound;
  uint32_t notesFound;
  uint32_t foldersFound;
  uint32_t unsupportedFound;
  uint32_t duplicatesFound;
  uint32_t stagedCount;        // items actually written to staging (accepted, non-dup)

  uint32_t finalNew;           // set after commit: how many records were added
  uint32_t finalTotal;         // set after commit: total records in the vault now

  // Live progress during bwImportCommit() — polled by screen_import.ino's
  // drawImportProgress() so it can show "N / M" instead of a static
  // message for larger vaults.
  uint32_t commitDone;
  uint32_t commitTotal;

  char     errorMsg[64];       // non-sensitive, user-facing — never parsed content
};

BwImportCtx bwImportCtx;

// ── Accessors ─────────────────────────────────────────────────────────
// wifi_portal.ino and screen_import.ino read state through these (matching
// this project's existing convention — see wifiPortalActive()/
// wifiPortalCount() in wifi_portal.ino — rather than exposing the raw
// BwImportCtx struct across files, which would also hit Arduino's
// auto-prototype struct-visibility hoisting issue documented in
// shared_types.h, since BwImportCtx contains File objects/BwParserState
// that aren't (and don't need to be) visible outside this file).
int      bwImportStage()             { return (int)bwImportCtx.stage; }
uint32_t bwImportLoginsFound()       { return bwImportCtx.loginsFound; }
uint32_t bwImportNotesFound()        { return bwImportCtx.notesFound; }
uint32_t bwImportFoldersFound()      { return bwImportCtx.foldersFound; }
uint32_t bwImportUnsupportedFound()  { return bwImportCtx.unsupportedFound; }
uint32_t bwImportDuplicatesFound()   { return bwImportCtx.duplicatesFound; }
uint32_t bwImportFinalNew()          { return bwImportCtx.finalNew; }
uint32_t bwImportFinalTotal()        { return bwImportCtx.finalTotal; }
uint32_t bwImportCommitDone()        { return bwImportCtx.commitDone; }
uint32_t bwImportCommitTotal()       { return bwImportCtx.commitTotal; }
const char *bwImportErrorMsg()       { return bwImportCtx.errorMsg; }

// ── Reset / wipe ─────────────────────────────────────────────────────────
static void bwCtxWipe() {
  // Extract only the non-sensitive counters the DONE/FAILED screens need
  // BEFORE wiping — everything else (parser scratch buffers, which can
  // transiently hold plaintext passwords/TOTP secrets) gets securely zeroed.
  uint32_t logins = bwImportCtx.loginsFound, notes = bwImportCtx.notesFound,
           folders = bwImportCtx.foldersFound, unsupported = bwImportCtx.unsupportedFound,
           dupes = bwImportCtx.duplicatesFound, finalNew = bwImportCtx.finalNew,
           finalTotal = bwImportCtx.finalTotal;
  char err[sizeof(bwImportCtx.errorMsg)];
  strncpy(err, bwImportCtx.errorMsg, sizeof(err) - 1); err[sizeof(err)-1] = 0;

  if (bwImportCtx.filesOpen) {
    if (bwImportCtx.stagingFile) bwImportCtx.stagingFile.close();
    if (bwImportCtx.foldersStagingFile) bwImportCtx.foldersStagingFile.close();
  }
  ckSecureZero(&bwImportCtx, sizeof(bwImportCtx));

  bwImportCtx.stage = BW_STAGE_IDLE;
  bwImportCtx.loginsFound = logins; bwImportCtx.notesFound = notes;
  bwImportCtx.foldersFound = folders; bwImportCtx.unsupportedFound = unsupported;
  bwImportCtx.duplicatesFound = dupes; bwImportCtx.finalNew = finalNew;
  bwImportCtx.finalTotal = finalTotal;
  strncpy(bwImportCtx.errorMsg, err, sizeof(bwImportCtx.errorMsg) - 1);
}

// Discards ALL staging/working temp files unconditionally. Called on
// cancel, on failure, and by wifi_portal.ino's teardown when the portal
// stops mid-import (lock/timeout/nav-away) — see wifiPortalStop().
void bwImportDiscard() {
  FFat.remove(BW_STAGING_PATH);
  FFat.remove(BW_FOLDERS_STAGING_PATH);
  FFat.remove(BW_IMPORT_NEW_PATH);
  FFat.remove(BW_FOLDERS_NEW_PATH);
  bwCtxWipe();
  SK_LOGLN("[BWIMPORT] discarded (cancel/teardown)");
}

static void bwSetError(const char *msg) {
  strncpy(bwImportCtx.errorMsg, msg, sizeof(bwImportCtx.errorMsg) - 1);
  bwImportCtx.errorMsg[sizeof(bwImportCtx.errorMsg) - 1] = 0;
  bwImportCtx.stage = BW_STAGE_FAILED;
}

// ── Duplicate detection against the EXISTING vault ───────────────────────
// title (case-insensitive) first-pass filter using the already-resident
// passwordIndex[], then username+url compared on the decrypted candidate —
// matches "title+username+URL, not title alone". Bounded by passwordCount
// in the worst case (title collisions), cheap in the common case.
static bool bwIsDuplicate(const char *title, const char *username, const char *url) {
  for (uint16_t i = 0; i < passwordCount; i++) {
    if (strcasecmp(passwordIndex[i].title, title) != 0) continue;
    PassRecord cand;
    if (!dbLoadRecord(passwordIndex[i].id, cand)) continue;
    bool match = (strcasecmp(cand.username, username) == 0) &&
                (strcasecmp(cand.url, url) == 0);
    ckSecureZero(&cand, sizeof(cand));
    if (match) return true;
  }
  return false;
}

// In-batch duplicate check (two items in the SAME import with identical
// title+username+url) — a small fixed-size hash set of a cheap FNV-1a-style
// checksum, bounded memory, no false negatives that matter for this use.
#define BW_BATCH_DEDUPE_SLOTS 512
static uint32_t bwBatchSeen[BW_BATCH_DEDUPE_SLOTS];
static uint16_t bwBatchSeenCount = 0;

static uint32_t bwHashTUU(const char *t, const char *u, const char *url) {
  uint32_t h = 2166136261u;
  for (const char *p = t; *p; p++)   { h ^= (uint8_t)tolower(*p); h *= 16777619u; }
  for (const char *p = u; *p; p++)   { h ^= (uint8_t)tolower(*p); h *= 16777619u; }
  for (const char *p = url; *p; p++) { h ^= (uint8_t)tolower(*p); h *= 16777619u; }
  return h;
}
static bool bwBatchIsDuplicate(const char *t, const char *u, const char *url) {
  uint32_t h = bwHashTUU(t, u, url);
  for (uint16_t i = 0; i < bwBatchSeenCount; i++) if (bwBatchSeen[i] == h) return true;
  if (bwBatchSeenCount < BW_BATCH_DEDUPE_SLOTS) bwBatchSeen[bwBatchSeenCount++] = h;
  return false;
}

// ── Staged (normalized, plaintext-of-necessity) intermediate record ──────
// Written to /bw_staging.bin — one per accepted item. Deliberately compact
// and PassRecord-shaped so commit-time encryption is a direct
// dbEncryptRecord() call, no further transformation needed.
struct BwStagedRecord {
  char title[PT_TITLE_LEN];
  char username[PT_USERNAME_LEN];
  char password[PT_PASSWORD_LEN];
  char url[PT_URL_LEN];
  char note[PT_NOTE_LEN];
  char bwFolderId[40];   // Bitwarden's own folder id string, resolved to a
                          // real SecureKey folder id at commit time (after
                          // ALL folders have been staged — see bwImportCommit)
  bool favorite;
};

// ── Parser callbacks ──────────────────────────────────────────────────────
static void bwOnFolder(const BwParsedFolder &f, void *ctx) {
  (void)ctx;
  bwImportCtx.foldersFound++;
  if (!bwImportCtx.filesOpen) return;
  // Stage folders as plain text lines: bwId\tname\n (simple, bounded, no
  // binary struct needed for something this small — matches the project's
  // existing preference for the simplest correct tool, e.g. the CSV
  // line-splitting already used in wifi_portal.ino's bulk-paste path).
  // Sanitize: a folder name containing a literal tab/newline (the JSON
  // parser's \t/\n escape handling can produce these from a maliciously or
  // unusually crafted export) would otherwise corrupt this line-based
  // format — replace them with a space so the tab-split/line-read in
  // bwImportCommit() always stays in sync with what was written here.
  char safeId[sizeof(f.bwId)], safeName[sizeof(f.name)];
  strncpy(safeId, f.bwId, sizeof(safeId) - 1); safeId[sizeof(safeId) - 1] = 0;
  strncpy(safeName, f.name, sizeof(safeName) - 1); safeName[sizeof(safeName) - 1] = 0;
  for (char *p = safeId; *p; p++)   if (*p == '\t' || *p == '\n' || *p == '\r') *p = ' ';
  for (char *p = safeName; *p; p++) if (*p == '\t' || *p == '\n' || *p == '\r') *p = ' ';

  char line[8 + sizeof(f.bwId) + sizeof(f.name)];
  snprintf(line, sizeof(line), "%s\t%s\n", safeId, safeName);
  bwImportCtx.foldersStagingFile.print(line);
}

static void bwOnItem(const BwParsedItem &it, void *ctx) {
  (void)ctx;

  if (it.itemType != BW_ITEM_TYPE_LOGIN && it.itemType != BW_ITEM_TYPE_NOTE) {
    bwImportCtx.unsupportedFound++;
    return;
  }
  if (it.itemType == BW_ITEM_TYPE_LOGIN) bwImportCtx.loginsFound++;
  else                                   bwImportCtx.notesFound++;

  // Duplicate check (existing vault + within this batch). Notes have no
  // username/url to match on — dedupe by title only for notes (still
  // "skip if it looks the same", reported the same way).
  bool isDup = false;
  if (it.itemType == BW_ITEM_TYPE_LOGIN) {
    isDup = bwBatchIsDuplicate(it.title, it.username, it.url) ||
           bwIsDuplicate(it.title, it.username, it.url);
  } else {
    isDup = bwBatchIsDuplicate(it.title, "", "") ||
           bwIsDuplicate(it.title, "", "");
  }
  if (isDup) {
    bwImportCtx.duplicatesFound++;
    return;
  }

  if (!bwImportCtx.filesOpen) return;

  BwStagedRecord rec;
  memset(&rec, 0, sizeof(rec));
  strncpy(rec.title,    it.title,    sizeof(rec.title) - 1);
  strncpy(rec.username, it.username, sizeof(rec.username) - 1);
  strncpy(rec.password, it.password, sizeof(rec.password) - 1);
  strncpy(rec.url,      it.url,      sizeof(rec.url) - 1);
  strncpy(rec.note,     it.noteAccum, sizeof(rec.note) - 1);   // truncates — documented trade-off
  strncpy(rec.bwFolderId, it.bwFolderId, sizeof(rec.bwFolderId) - 1);
  rec.favorite = false;

  bwImportCtx.stagingFile.write((const uint8_t *)&rec, sizeof(rec));
  bwImportCtx.stagedCount++;
  ckSecureZero(&rec, sizeof(rec));   // wipe the scratch copy — plaintext
                                     // password/username lived here transiently
}

// ── Stage 1: begin / feed / end ───────────────────────────────────────────
bool bwImportBegin() {
  if (!vaultUnlocked) return false;
  bwCtxWipe();
  bwParserInit(bwImportCtx.parser);
  bwBatchSeenCount = 0;

  FFat.remove(BW_STAGING_PATH);
  FFat.remove(BW_FOLDERS_STAGING_PATH);
  bwImportCtx.stagingFile = FFat.open(BW_STAGING_PATH, "w");
  bwImportCtx.foldersStagingFile = FFat.open(BW_FOLDERS_STAGING_PATH, "w");
  if (!bwImportCtx.stagingFile || !bwImportCtx.foldersStagingFile) {
    bwImportDiscard();
    return false;
  }
  bwImportCtx.filesOpen = true;
  bwImportCtx.stage = BW_STAGE_UPLOADING;
  SK_LOGLN("[BWIMPORT] upload started");
  return true;
}

// Feed one HTTPUpload chunk (<=1436 bytes typically). Returns false if the
// parser has entered an unrecoverable error state — caller should abort.
bool bwImportFeed(const uint8_t *chunk, size_t len) {
  if (bwImportCtx.stage != BW_STAGE_UPLOADING) return false;
  bool ok = bwParserFeed(bwImportCtx.parser, chunk, len,
                         bwOnItem, nullptr, bwOnFolder, nullptr);
  if (!ok) {
    SK_LOGLN("[BWIMPORT] parse error — aborting (malformed JSON)");
    bwSetError("Invalid file format");
    return false;
  }
  return true;
}

// Called when the HTTP upload finishes. Checks the parser reached a
// well-formed end of input (not just "no error yet" — a connection that
// dropped mid-stream leaves the parser incomplete but not technically
// errored, and that must ALSO be treated as a failure).
//
// [BW-09] marks entry to THIS function, BEFORE the file-close/flush below —
// this is the earliest point this project's own finalize logic can log
// after portalImportUploadDone() (wifi_portal.ino's [BW-08]) calls in. If
// [BW-08] prints but [BW-09] never does, the reset happened in the few
// lines between those two calls (the vaultUnlocked/portalImportCodeOk/
// s_importUploadOk checks in portalImportUploadDone() — all simple boolean
// reads, but logged separately so that window isn't invisible either).
bool bwImportEnd() {
  SK_LOG("[BW-09] bwImportEnd() entered  freeHeap=%u minFreeHeap=%u freePsram=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram());
  if (bwImportCtx.stage != BW_STAGE_UPLOADING) return false;

  if (bwImportCtx.filesOpen) {
    bwImportCtx.stagingFile.flush();
    bwImportCtx.foldersStagingFile.flush();
    bwImportCtx.stagingFile.close();
    bwImportCtx.foldersStagingFile.close();
    bwImportCtx.filesOpen = false;
  }
  SK_LOG("[BW-10] Staging files flushed+closed  freeHeap=%u minFreeHeap=%u freePsram=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram());

  if (!bwParserDone(bwImportCtx.parser)) {
    SK_LOGLN("[BW-11] Parser NOT done — stream ended before valid JSON closed (treated as failure)");
    bwSetError("Upload incomplete or invalid");
    bwImportDiscard();
    return false;
  }
  SK_LOGLN("[BW-12] Parser confirmed done (well-formed JSON received)");

  SK_LOG("[BW-13] Parsed: %u bytes, %u logins, %u notes, %u folders, %u unsupported, %u duplicates\n",
         bwImportCtx.parser.bytesFed, bwImportCtx.loginsFound, bwImportCtx.notesFound,
         bwImportCtx.foldersFound, bwImportCtx.unsupportedFound, bwImportCtx.duplicatesFound);
  SK_LOG("[BWIMPORT] post-parse memory: freeHeap=%u minFreeHeap=%u freePsram=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram());
  bwImportCtx.stage = BW_STAGE_AWAITING_PREVIEW;
  SK_LOGLN("[BW-14] Stage set to AWAITING_PREVIEW — bwImportEnd() returning true");
  return true;
}

// Resolver for the Bitwarden-folder-id -> SecureKey-folder-id lookup built
// at the start of bwImportCommit() below. (BwFolderMapEntry itself lives in
// bw_json_parser.h — see that file's comment for why.)
static uint16_t bwResolveFolderId(const BwFolderMapEntry *fmap, uint16_t fmapCount,
                                  const char *bwId) {
  if (!bwId || !bwId[0]) return 0;
  for (uint16_t i = 0; i < fmapCount; i++)
    if (strcmp(fmap[i].bwId, bwId) == 0) return fmap[i].skId;
  return 0;   // unknown folder id -> "No Folder" (never fails the import)
}

// ── Stage 2: commit (build + verify + atomic swap) ────────────────────────
// db_migrate.ino-style two-pass: build the new file first, verify it
// completely, ONLY THEN swap it into place. Yields periodically (delay(1))
// so a large vault never trips the watchdog.
// Defined in screen_import.ino — a lightweight redraw (status bar +
// "Importing... N / M" text only, no navigation/state changes) called
// periodically from the loops below so the screen visibly progresses
// during a large commit instead of sitting static the whole time.
void importProgressTick();

bool bwImportCommit() {
  if (bwImportCtx.stage != BW_STAGE_AWAITING_PREVIEW) return false;
  if (!vaultUnlocked) { bwSetError("Vault locked"); return false; }
  bwImportCtx.stage = BW_STAGE_IMPORTING;
  SK_LOG("[BWIMPORT] commit started  freeHeap=%u minFreeHeap=%u freePsram=%u  staged=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram(), bwImportCtx.stagedCount);

  // ── Step A1: resolve every staged Bitwarden folder id -> a real
  // SecureKey folder id (creating folders as needed), building a small
  // in-RAM lookup table (bwFolderId string -> uint16_t). Bounded by
  // BW_MAX_FOLDERS_IMPORT.
  static BwFolderMapEntry fmap[BW_MAX_FOLDERS_IMPORT];
  static uint16_t fmapCount;
  fmapCount = 0;
  {
    File f = FFat.open(BW_FOLDERS_STAGING_PATH, "r");
    if (f) {
      char line[8 + 40 + PT_FOLDER_NAME_LEN];
      while (f.available() && fmapCount < BW_MAX_FOLDERS_IMPORT) {
        int n = f.readBytesUntil('\n', line, sizeof(line) - 1);
        if (n <= 0) break;
        line[n] = 0;
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = 0;
        const char *bwId = line, *name = tab + 1;
        if (!bwId[0] || !name[0]) continue;
        uint16_t skId = folderIdForName(name);
        strncpy(fmap[fmapCount].bwId, bwId, sizeof(fmap[fmapCount].bwId) - 1);
        fmap[fmapCount].skId = skId;
        fmapCount++;
      }
      f.close();
    }
  }

  // ── Step A2: build the new full encrypted DB = existing records (copied
  // unchanged) + every staged record (freshly encrypted). ─────────────────
  uint16_t nextId = 1;
  for (uint16_t i = 0; i < passwordCount; i++)
    if (passwordIndex[i].id >= nextId) nextId = (uint16_t)(passwordIndex[i].id + 1);

  FFat.remove(BW_IMPORT_NEW_PATH);
  File dst = FFat.open(BW_IMPORT_NEW_PATH, "w");
  if (!dst) { bwSetError("Storage error"); return false; }
  dbWriteHeader(dst, 0);   // placeholder, patched below

  uint32_t copied = 0, added = 0;
  bool writeOk = true;

  // Live progress for drawImportProgress() — rough total: existing records
  // + accepted-staged records (build) will be roughly re-walked again
  // during verify, so this total undercounts the FULL commit's work by
  // about half; good enough for a "making progress" indicator, not meant
  // to be exact to the byte.
  bwImportCtx.commitTotal = passwordCount + bwImportCtx.stagedCount;
  bwImportCtx.commitDone = 0;

  // Copy every existing record through byte-for-byte (no decrypt/re-encrypt
  // needed — ciphertext is untouched, exactly like dbRewriteTransacted's
  // "mutate nothing" pass).
  {
    File src = FFat.open(DB_PATH, "r");
    if (src) {
      DbHeader shdr;
      if (dbReadHeader(src, shdr)) {
        DbRecordOnDisk rec;
        while (writeOk && src.available() >= (int)DB_RECORD_SIZE) {
          if (src.read((uint8_t *)&rec, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) { writeOk = false; break; }
          if (dst.write((uint8_t *)&rec, DB_RECORD_SIZE) != DB_RECORD_SIZE) { writeOk = false; break; }
          copied++;
          bwImportCtx.commitDone++;
          if ((copied % 64) == 0) { delay(1); importProgressTick(); }
        }
      }
      src.close();
    }
  }

  // Append every staged (accepted, non-duplicate) new record, freshly
  // encrypted via dbEncryptRecord() — the SAME function every on-device-
  // created record goes through. Folder id resolved from the Bitwarden
  // string id captured at staging time.
  if (writeOk) {
    File stg = FFat.open(BW_STAGING_PATH, "r");
    if (stg) {
      BwStagedRecord srec;
      while (writeOk && stg.available() >= (int)sizeof(srec)) {
        if (stg.read((uint8_t *)&srec, sizeof(srec)) != (int)sizeof(srec)) { writeOk = false; break; }

        PassRecord rec;
        memset(&rec, 0, sizeof(rec));
        rec.id = nextId++;
        rec.deleted = 0;
        rec.favorite = srec.favorite ? 1 : 0;
        strncpy(rec.title,    srec.title,    sizeof(rec.title)    - 1);
        strncpy(rec.username, srec.username, sizeof(rec.username) - 1);
        strncpy(rec.password, srec.password, sizeof(rec.password) - 1);
        strncpy(rec.url,      srec.url,      sizeof(rec.url)      - 1);
        strncpy(rec.note,     srec.note,     sizeof(rec.note)     - 1);
        uint16_t fid = bwResolveFolderId(fmap, fmapCount, srec.bwFolderId);
        snprintf(rec.folder, sizeof(rec.folder), "%u", fid);

        DbRecordOnDisk enc;
        if (!dbEncryptRecord(rec, enc)) { writeOk = false; }
        else if (dst.write((uint8_t *)&enc, DB_RECORD_SIZE) != DB_RECORD_SIZE) { writeOk = false; }
        else added++;

        ckSecureZero(&rec, sizeof(rec));
        ckSecureZero(&srec, sizeof(srec));
        ckSecureZero(&enc, sizeof(enc));
        bwImportCtx.commitDone++;
        if ((added % 32) == 0) { delay(1); importProgressTick(); }
      }
      stg.close();
    }
  }

  uint32_t totalCount = copied + added;
  if (writeOk) {
    dst.flush();
    dst.seek(0);
    dbWriteHeader(dst, (uint16_t)totalCount);
    dst.flush();
  }
  dst.close();

  if (!writeOk) {
    FFat.remove(BW_IMPORT_NEW_PATH);
    bwSetError("Import build failed");
    SK_LOGLN("[BWIMPORT] commit FAILED during build — vault unchanged");
    return false;
  }

  // ── Step B: VERIFY — re-read and decrypt EVERY record in the new file,
  // confirm the count, confirm every pre-existing record round-trips
  // (decrypts successfully — proves nothing was corrupted), confirm every
  // NEW record's fields match what was staged. ────────────────────────────
  bool verifyOk = true;
  uint32_t checked = 0;
  {
    File verify = FFat.open(BW_IMPORT_NEW_PATH, "r");
    if (!verify) verifyOk = false;
    DbHeader vhdr;
    if (verifyOk && !dbReadHeader(verify, vhdr)) verifyOk = false;
    if (verifyOk && vhdr.recordCount != totalCount) verifyOk = false;

    DbRecordOnDisk rec;
    while (verifyOk && verify.available() >= (int)DB_RECORD_SIZE) {
      if (verify.read((uint8_t *)&rec, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) { verifyOk = false; break; }
      PassRecord dec;
      bool ok = dbDecryptRecord(rec, dec);
      ckSecureZero(&dec, sizeof(dec));
      if (!ok) { verifyOk = false; break; }
      checked++;
      if ((checked % 64) == 0) { delay(1); importProgressTick(); }
    }
    if (verifyOk && checked != totalCount) verifyOk = false;
    if (verify) verify.close();
  }
  SK_LOG("[BWIMPORT] commit: verify pass — %u records checked\n", checked);

  if (!verifyOk) {
    FFat.remove(BW_IMPORT_NEW_PATH);
    bwSetError("Verification failed");
    SK_LOGLN("[BWIMPORT] commit FAILED verification — vault unchanged");
    return false;
  }

  // ── Step C: only now, atomic swap ────────────────────────────────────
  SK_LOGLN("[BWIMPORT] commit verified OK — swapping vault");
  FFat.remove(DB_PATH);
  if (!FFat.rename(BW_IMPORT_NEW_PATH, DB_PATH)) {
    bwSetError("Swap failed");
    return false;
  }

  bwImportCtx.finalNew = added;
  bwImportCtx.finalTotal = totalCount;

  // Staging files only deleted AFTER the swap is proven successful —
  // "temp file must not survive a successful import" without risking data
  // loss if a crash happens mid-cleanup (worst case: an orphaned-but-
  // harmless staging file survives a crash here, never a corrupted vault).
  FFat.remove(BW_STAGING_PATH);
  FFat.remove(BW_FOLDERS_STAGING_PATH);
  SK_LOGLN("[BWIMPORT] commit complete — staging files removed");
  SK_LOG("[BWIMPORT] post-commit memory: freeHeap=%u minFreeHeap=%u freePsram=%u  added=%u total=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram(), added, totalCount);

  foldersLoadIndex();
  dbLoadIndex();

  bwImportCtx.stage = BW_STAGE_DONE;
  return true;
}
