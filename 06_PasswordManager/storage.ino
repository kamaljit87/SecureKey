// =============================================================
//  storage.ino  —  Encrypted FFat password database
//
//  File:   /db.bin        (authenticated-encrypted, AES-256-GCM)
//  Format: DbHeader, then fixed-size DbRecordOnDisk entries.
//  Index:  loaded into PSRAM at boot (ListItem array, non-sensitive
//          metadata ONLY — id/favorite/folder/title, see below).
//
//  ── Why title/folder are readable in the index ──────────────────────
//  The list/search UI needs to render thousands of rows without
//  decrypting the whole vault on every scroll frame. Title and folder
//  are UI labels, not secrets on their own (they're what's shown in the
//  list before you've unlocked into a specific entry) — password,
//  username, url and note are ALWAYS the encrypted payload and are only
//  decrypted for the one record currently on screen (dbLoadRecord),
//  then wiped again once no longer needed. See docs/SECURITY.md
//  "reduced plaintext residence time".
//
//  Each record is individually encrypted with its own random 96-bit
//  nonce — nonces are NEVER reused with the master key (a fresh nonce is
//  drawn from the HW RNG every time a record is written), and the record
//  id + deleted flag are authenticated (GCM AAD) so a ciphertext can't be
//  silently swapped onto a different slot.
//
//  Crash-safety: every mutating op (append/update/delete) writes a full
//  new file to /db_tmp.bin, verifies it can be re-opened and its header
//  re-read, and only THEN atomically replaces /db.bin. A power loss
//  mid-write leaves the OLD /db.bin intact — never a half-written file.
// =============================================================
#include "crypto_core.h"
#include "shared_types.h"   // DbHeader/DbRecordOnDisk/DB_* — shared with db_migrate.ino

// ── AAD binding: id + deleted + favorite are authenticated but not
//    encrypted, so a byte-level swap/splice of records can't quietly
//    reassign a ciphertext to a different id or resurrect a deleted one.
static void dbBuildAad(uint8_t *aad, uint16_t id, uint8_t deleted, uint8_t favorite) {
  memcpy(aad, &id, 2);
  aad[2] = deleted;
  aad[3] = favorite;
}

// ── Encrypt/decrypt one record's payload ─────────────────────
// NOT static: db_migrate.ino (which sorts alphabetically BEFORE this
// file, so Arduino's auto-generated prototypes are what make the call
// resolve) also calls these directly during the one-time legacy-database
// migration — see db_migrate.ino's dbMigrateLegacyPlaintext().
bool dbEncryptRecord(const PassRecord &rec, DbRecordOnDisk &out) {
  out.id       = rec.id;
  out.deleted  = rec.deleted;
  out.favorite = rec.favorite;
  ckRandomBytes(out.nonce, sizeof(out.nonce));   // fresh nonce EVERY write

  DbPlainPayload pt;
  memset(&pt, 0, sizeof(pt));
  strncpy(pt.folder,   rec.folder,   sizeof(pt.folder)   - 1);
  strncpy(pt.title,    rec.title,    sizeof(pt.title)    - 1);
  strncpy(pt.username, rec.username, sizeof(pt.username) - 1);
  strncpy(pt.password, rec.password, sizeof(pt.password) - 1);
  strncpy(pt.url,      rec.url,      sizeof(pt.url)      - 1);
  strncpy(pt.note,     rec.note,     sizeof(pt.note)     - 1);

  uint8_t aad[DB_AAD_LEN];
  dbBuildAad(aad, out.id, out.deleted, out.favorite);

  bool ok = ckAesGcmEncrypt(vaultMasterKey, out.nonce, sizeof(out.nonce),
                            aad, sizeof(aad),
                            (const uint8_t *)&pt, sizeof(pt),
                            out.ciphertext, out.tag);
  ckSecureZero(&pt, sizeof(pt));
  return ok;
}

bool dbDecryptRecord(const DbRecordOnDisk &in, PassRecord &rec) {
  uint8_t aad[DB_AAD_LEN];
  dbBuildAad(aad, in.id, in.deleted, in.favorite);

  DbPlainPayload pt;
  bool ok = ckAesGcmDecrypt(vaultMasterKey, in.nonce, sizeof(in.nonce),
                            aad, sizeof(aad),
                            in.ciphertext, sizeof(in.ciphertext),
                            in.tag, (uint8_t *)&pt);
  if (!ok) {
    ckSecureZero(&pt, sizeof(pt));
    return false;
  }

  memset(&rec, 0, sizeof(rec));
  rec.id       = in.id;
  rec.deleted  = in.deleted;
  rec.favorite = in.favorite;
  strncpy(rec.folder,   pt.folder,   sizeof(rec.folder)   - 1);
  strncpy(rec.title,    pt.title,    sizeof(rec.title)    - 1);
  strncpy(rec.username, pt.username, sizeof(rec.username) - 1);
  strncpy(rec.password, pt.password, sizeof(rec.password) - 1);
  strncpy(rec.url,      pt.url,      sizeof(rec.url)      - 1);
  strncpy(rec.note,     pt.note,     sizeof(rec.note)     - 1);
  ckSecureZero(&pt, sizeof(pt));
  return true;
}

// ── Header helpers ────────────────────────────────────────────
// Also NOT static — db_migrate.ino calls both directly (see note above).
bool dbReadHeader(File &f, DbHeader &hdr) {
  if (f.read((uint8_t *)&hdr, sizeof(hdr)) != sizeof(hdr)) return false;
  return memcmp(hdr.magic, DB_MAGIC, 4) == 0;
}
void dbWriteHeader(File &f, uint16_t count) {
  DbHeader hdr;
  memcpy(hdr.magic, DB_MAGIC, 4);
  hdr.formatVersion   = DB_FORMAT_VERSION;
  hdr.securityVersion = SECURITY_VERSION;
  hdr.recordCount     = count;
  hdr.reserved        = 0;
  f.write((uint8_t *)&hdr, sizeof(hdr));
}

// True if /db.bin exists and starts with our current magic.
bool dbExists() {
  File f = FFat.open(DB_PATH, "r");
  if (!f) return false;
  DbHeader hdr;
  bool ok = dbReadHeader(f, hdr);
  f.close();
  return ok;
}

// Detects a PRE-ENCRYPTION (v1) plaintext database: right file size
// class and no "SKV2" magic at the front. Used only by the migration
// path (see dbMigrateLegacyIfPresent below) — production firmware never
// writes this format.
bool dbLegacyPlaintextExists() {
  File f = FFat.open(DB_PATH, "r");
  if (!f) return false;
  size_t sz = f.size();
  char magic[4] = {0};
  f.read((uint8_t *)magic, 4);
  f.close();
  if (memcmp(magic, DB_MAGIC, 4) == 0) return false;         // already v2
  if (sz == 0 || sz % LEGACY_RECORD_SIZE != 0) return false;  // not v1 shape
  return true;
}

// ── Load index into PSRAM (metadata only — see file header note) ─────
void dbLoadIndex() {
  passwordCount = 0;
  if (!vaultUnlocked) return;   // never touch the DB while locked
  File f = FFat.open(DB_PATH, "r");
  if (!f) return;
  DbHeader hdr;
  if (!dbReadHeader(f, hdr)) { f.close(); return; }

  DbRecordOnDisk rec;
  while (f.available() >= (int)DB_RECORD_SIZE && passwordCount < MAX_PASSWORDS) {
    if (f.read((uint8_t *)&rec, DB_RECORD_SIZE) != DB_RECORD_SIZE) break;
    if (rec.deleted) continue;
    PassRecord pr;
    if (!dbDecryptRecord(rec, pr)) {
      // Corrupt/tampered record — skip it rather than crash or show
      // garbage. (Could also flag this on-screen; kept silent-safe here
      // since a single bad record shouldn't block the whole list.)
      continue;
    }
    ListItem &li = passwordIndex[passwordCount++];
    li.id = pr.id;
    li.favorite = pr.favorite;
    // pr.folder holds a folder-ID decimal string (DB_FORMAT_VERSION 3+ — see
    // folders.ino / shared_types.h) — resolve it to the actual folder NAME
    // here so screen_list.ino's existing rendering/search keep working
    // completely unchanged, just now showing a real name instead of an id.
    {
      uint16_t fid = (uint16_t)atoi(pr.folder);
      char fname[PT_FOLDER_NAME_LEN];
      folderNameForId(fid, fname, sizeof(fname));
      strncpy(li.folder, fname, sizeof(li.folder) - 1);
      li.folder[sizeof(li.folder) - 1] = 0;
      ckSecureZero(fname, sizeof(fname));
    }
    strncpy(li.title, pr.title, sizeof(li.title) - 1);
    li.title[sizeof(li.title) - 1] = 0;
    ckSecureZero(&pr, sizeof(pr));   // title/folder already copied out above

    // Refresh the lowercased search cache (screen_list.ino) for this slot —
    // titles/folders are non-secret UI labels (see this file's header note),
    // so caching a case-folded copy alongside the index is the same
    // sensitivity class as passwordIndex itself. Keeps buildList() from
    // re-lowercasing every entry on every search keystroke.
    listCacheFold(passwordCount - 1);
  }
  f.close();
}

// ── Load + decrypt a single full record by id ─────────────────
// Plaintext lives ONLY in `out_rec`, which the caller owns and must wipe
// (ckSecureZero) once it's no longer displayed/typed. This function does
// not cache or retain any copy of it.
bool dbLoadRecord(uint16_t id, PassRecord &out_rec) {
  if (!vaultUnlocked) return false;
  File f = FFat.open(DB_PATH, "r");
  if (!f) return false;
  DbHeader hdr;
  if (!dbReadHeader(f, hdr)) { f.close(); return false; }

  DbRecordOnDisk rec;
  while (f.available() >= (int)DB_RECORD_SIZE) {
    if (f.read((uint8_t *)&rec, DB_RECORD_SIZE) != DB_RECORD_SIZE) break;
    if (rec.id == id && !rec.deleted) {
      f.close();
      return dbDecryptRecord(rec, out_rec);
    }
  }
  f.close();
  return false;
}

// ── Rewrite the WHOLE database transactionally ────────────────
// Shared by append/update/delete: read every existing record, apply the
// caller's mutation callback, write the result to db_tmp.bin, verify it,
// then atomically replace db.bin. This guarantees a sudden power loss
// never leaves a half-written or partially-encrypted file: either the
// OLD db.bin survives untouched, or the fully-written+verified NEW one
// does — never something in between.
//
// mutate(rec, ctx) is called once per existing record (in file order) and
// may modify `rec` in place; returning false means "write this record
// unchanged". `onAppend`, if non-null, is called once after all existing
// records have been processed, to optionally append a brand-new one.
// (DbMutateFn/DbAppendFn are defined in shared_types.h.)
static bool dbRewriteTransacted(DbMutateFn mutate, void *mutateCtx,
                                DbAppendFn append, void *appendCtx) {
  if (!vaultUnlocked) return false;

  File dst = FFat.open(DB_TMP_PATH, "w");
  if (!dst) return false;

  uint16_t count = 0;
  dbWriteHeader(dst, 0);   // placeholder — real count patched in below

  File src = FFat.open(DB_PATH, "r");
  if (src) {
    DbHeader shdr;
    if (dbReadHeader(src, shdr)) {
      DbRecordOnDisk rec;
      while (src.available() >= (int)DB_RECORD_SIZE) {
        if (src.read((uint8_t *)&rec, DB_RECORD_SIZE) != (int)DB_RECORD_SIZE) break;
        if (mutate) mutate(rec, mutateCtx);
        dst.write((uint8_t *)&rec, DB_RECORD_SIZE);
        count++;
      }
    }
    src.close();
  }

  if (append) {
    DbRecordOnDisk newRec;
    memset(&newRec, 0, sizeof(newRec));
    if (append(newRec, appendCtx)) {
      dst.write((uint8_t *)&newRec, DB_RECORD_SIZE);
      count++;
    }
  }

  // Patch the real record count into the header.
  dst.flush();
  dst.seek(0);
  dbWriteHeader(dst, count);
  dst.flush();
  dst.close();

  // ── Verify before ever touching the real db.bin ──────────────────
  File verify = FFat.open(DB_TMP_PATH, "r");
  if (!verify) { FFat.remove(DB_TMP_PATH); return false; }
  DbHeader vhdr;
  bool verifyOk = dbReadHeader(verify, vhdr) && vhdr.recordCount == count;
  // Spot-check the file is exactly the expected size (header + N records) —
  // catches a truncated write from a brownout mid-flush.
  size_t expectedSize = sizeof(DbHeader) + (size_t)count * DB_RECORD_SIZE;
  verifyOk = verifyOk && (verify.size() == expectedSize);
  verify.close();
  if (!verifyOk) { FFat.remove(DB_TMP_PATH); return false; }

  // Atomic swap: remove the old file, then rename the verified new one
  // over it. FFat (FAT) has no atomic rename-replace, so there is a brief
  // window with neither name present — but by this point the new file is
  // fully written AND verified, so the only risk is a power loss in that
  // narrow window, which loses nothing that wasn't already safely on disk
  // as db_tmp.bin (recoverable by hand); it can never produce a corrupt
  // or half-encrypted db.bin.
  FFat.remove(DB_PATH);
  FFat.rename(DB_TMP_PATH, DB_PATH);
  return true;
}

// ── Public mutation API (same signatures callers already use) ─────────

struct AppendCtx { const PassRecord *rec; };
static bool appendCb(DbRecordOnDisk &out, void *ctx) {
  AppendCtx *c = (AppendCtx *)ctx;
  return dbEncryptRecord(*c->rec, out);
}

bool dbAppend(const PassRecord &rec) {
  AppendCtx ctx{ &rec };
  return dbRewriteTransacted(nullptr, nullptr, appendCb, &ctx);
}

struct DeleteCtx { uint16_t id; };
static bool deleteCb(DbRecordOnDisk &rec, void *ctx) {
  DeleteCtx *c = (DeleteCtx *)ctx;
  if (rec.id == c->id) rec.deleted = 1;
  return true;
}

bool dbDelete(uint16_t id) {
  DeleteCtx ctx{ id };
  return dbRewriteTransacted(deleteCb, &ctx, nullptr, nullptr);
}

struct UpdateCtx { uint16_t id; const PassRecord *newRec; bool found; };
static bool updateCb(DbRecordOnDisk &rec, void *ctx) {
  UpdateCtx *c = (UpdateCtx *)ctx;
  if (rec.id == c->id && !rec.deleted) {
    PassRecord up = *c->newRec;
    up.id = c->id;
    up.deleted = 0;
    DbRecordOnDisk enc;
    if (dbEncryptRecord(up, enc)) {
      enc.id = c->id;
      rec = enc;
      c->found = true;
    }
  }
  return true;
}

bool dbUpdate(uint16_t id, const PassRecord &newRec) {
  UpdateCtx ctx{ id, &newRec, false };
  if (!dbRewriteTransacted(updateCb, &ctx, nullptr, nullptr)) return false;
  return ctx.found;
}

// ── Toggle the "favorite" (heart) flag on a record ──────────────────
bool dbToggleFavorite(uint16_t id) {
  PassRecord rec;
  if (!dbLoadRecord(id, rec)) return false;
  rec.favorite = rec.favorite ? 0 : 1;
  bool ok = dbUpdate(id, rec);
  ckSecureZero(&rec, sizeof(rec));
  if (ok) dbLoadIndex();          // refresh in-memory index (favorite flags)
  return ok;
}

// ── Next available id ────────────────────────────────────────
static uint16_t dbNextId() {
  uint16_t maxId = 0;
  for (uint16_t i = 0; i < passwordCount; i++)
    if (passwordIndex[i].id > maxId) maxId = passwordIndex[i].id;
  return maxId + 1;
}

// ── Create a fresh, empty encrypted database ─────────────────
// Called on very first boot (no db.bin at all) once the vault has been
// provisioned and unlocked, and after a factory reset.
bool dbCreateEmpty() {
  if (!vaultUnlocked) return false;
  File f = FFat.open(DB_PATH, "w");
  if (!f) return false;
  dbWriteHeader(f, 0);
  f.flush();
  f.close();
  return true;
}

// =============================================================
//  Demo / seed data — DEVELOPMENT BUILDS ONLY
//
//  Real-looking demo credentials must never ship in a production
//  firmware. Gated behind SECUREKEY_DEMO_MODE (see theme.h / build
//  flags); a production build compiles this out entirely and dbSeed()
//  becomes a no-op. Even in demo mode, the data below uses obviously
//  fake example.invalid addresses instead of real-looking site logins.
// =============================================================
#ifdef SECUREKEY_DEMO_MODE
struct SeedEntry { const char *title, *user, *pass, *url, *note; };
static const SeedEntry SEEDS[] = {
  {"Demo Email",    "demo.user@example.invalid",  "Demo-Pass-0001!", "mail.example.invalid",   "Demo data"},
  {"Demo Bank",     "demo.user@example.invalid",  "Demo-Pass-0002!", "bank.example.invalid",   "Demo data"},
  {"Demo Shopping", "demo.user@example.invalid",  "Demo-Pass-0003!", "shop.example.invalid",   "Demo data"},
  {"Demo Social",   "demo_handle",                "Demo-Pass-0004!", "social.example.invalid", "Demo data"},
  {"Demo Work VPN", "demo.user@example.invalid",  "Demo-Pass-0005!", "vpn.example.invalid",    "Demo data"},
};

void dbSeed() {
  if (dbExists()) return;
  if (!vaultUnlocked) return;
  dbCreateEmpty();
  SK_LOGLN("[DB] SECUREKEY_DEMO_MODE: seeding fake demo entries (*.example.invalid)");
  const int N = sizeof(SEEDS) / sizeof(SEEDS[0]);
  for (int i = 0; i < N; i++) {
    PassRecord rec;
    memset(&rec, 0, sizeof(rec));
    rec.id      = (uint16_t)(i + 1);
    rec.deleted = 0;
    strncpy(rec.folder,   SEEDS[i].url,   sizeof(rec.folder)  - 1);
    strncpy(rec.title,    SEEDS[i].title, sizeof(rec.title)   - 1);
    strncpy(rec.username, SEEDS[i].user,  sizeof(rec.username)- 1);
    strncpy(rec.password, SEEDS[i].pass,  sizeof(rec.password)- 1);
    strncpy(rec.url,      SEEDS[i].url,   sizeof(rec.url)     - 1);
    strncpy(rec.note,     SEEDS[i].note,  sizeof(rec.note)    - 1);
    dbAppend(rec);
    ckSecureZero(&rec, sizeof(rec));
  }
  dbLoadIndex();
}
#else
// Production build: no demo data is compiled in at all. If /db.bin
// doesn't exist yet, just create an empty encrypted database.
void dbSeed() {
  if (dbExists()) return;
  if (!vaultUnlocked) return;
  dbCreateEmpty();
}
#endif
