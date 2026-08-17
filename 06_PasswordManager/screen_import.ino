// =============================================================
//  screen_import.ino  —  Import source-select + Bitwarden import flow
//
//  Settings -> "Import (WiFi)" now opens SCR_IMPORT_SOURCE, a tiny menu:
//    • "General WiFi Manager" — today's UNCHANGED wifiPortalStart()/SCR_WIFI
//      flow (bulk paste, edit, export existing vault).
//    • "Bitwarden Import"     — the new flow implemented here.
//
//  Bitwarden flow: mandatory on-device plaintext-data warning -> waiting
//  for the browser upload (SCR_IMPORT_WAIT, shows the SAME AP creds as the
//  general manager) -> counts-only preview (SCR_IMPORT_PREVIEW, NEVER shows
//  passwords/PINs/TOTP/item names — aggregate counts only) -> explicit
//  CONFIRM kicks off the build+verify+swap (SCR_IMPORT_PROGRESS, blocking
//  with periodic progress redraws, mirrors screen_migrate.ino's MIG_RUNNING
//  idiom) -> result summary (SCR_IMPORT_DONE).
//
//  The vault stays fully protected throughout: bw_import.ino's commit step
//  reuses dbEncryptRecord() (the SAME path every on-device-created record
//  goes through) and never swaps the real vault in until every new record
//  has been verified by re-reading and decrypting it.
// =============================================================

// ── SCR_IMPORT_SOURCE ──────────────────────────────────────────────────
void drawImportSource() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  drawNavBar("Import", true, nullptr);

  textCenter(STATUS_H + NAV_H + 30, "Select a source", 2, C_GRAY_4);

  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 64, gap = 14;
  const int16_t y1 = STATUS_H + NAV_H + 70;
  const int16_t y2 = y1 + bh + gap;

  gfx->fillRoundRect(bx, y1, bw, bh, 14, C_GRAY_1);
  gfx->drawRoundRect(bx, y1, bw, bh, 14, C_GRAY_2);
  textCenter(y1 + 14, "General WiFi Manager", 2, C_WHITE);
  textCenter(y1 + 40, "browse, edit, export vault", 1, C_GRAY_4);

  gfx->fillRoundRect(bx, y2, bw, bh, 14, C_GRAY_1);
  gfx->drawRoundRect(bx, y2, bw, bh, 14, C_BLUE);
  textCenter(y2 + 14, "Bitwarden Import", 2, C_WHITE);
  textCenter(y2 + 40, "bring in an exported vault", 1, C_GRAY_4);

  flushScreen();
}

void onTapImportSource(int16_t tx, int16_t ty) {
  bool back = (ty >= STATUS_H + 2 && ty < STATUS_H + NAV_H - 2
              && tx >= SAFE_PAD && tx < SAFE_PAD + 46);
  if (back) { popNav(); return; }

  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 64, gap = 14;
  const int16_t y1 = STATUS_H + NAV_H + 70;
  const int16_t y2 = y1 + bh + gap;

  if (tx >= bx && tx < bx + bw && ty >= y1 && ty < y1 + bh) {
    // General manager — EXACT unchanged behavior.
    wifiPortalStart();
    pushNav(SCR_WIFI);
    return;
  }
  if (tx >= bx && tx < bx + bw && ty >= y2 && ty < y2 + bh) {
    importWarnShow();
    return;
  }
}

// ── Mandatory plaintext-data warning (blocking confirm, shown BEFORE the
//    AP even starts) ─────────────────────────────────────────────────────
static bool importWarnPending = false;

void importWarnShow() {
  importWarnPending = true;
  // Must actually NAVIGATE to SCR_IMPORT_WAIT here, not just call drawAll()
  // — the only place that checks importWarnPending is drawImportWait()/
  // onTapImportWait() (the warning is drawn as a pre-AP sub-state of the
  // wait screen). Calling drawAll() while `current` was still
  // SCR_IMPORT_SOURCE just redrew the source-select list unchanged, which
  // looked exactly like the "Bitwarden Import" row silently doing nothing
  // on tap — pushNav() is what actually gets us onto SCR_IMPORT_WAIT so its
  // importWarnPending check is reachable at all.
  pushNav(SCR_IMPORT_WAIT);
}

static void drawImportWarn() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  textCenter(STATUS_H + 30, "BEFORE YOU IMPORT", 2, C_WHITE);

  int16_t y = STATUS_H + 76;
  textCenter(y, "This export contains your", 1, C_GRAY_5);      y += 18;
  textCenter(y, "passwords in plaintext.",    1, C_GRAY_5);     y += 30;
  textCenter(y, "Only import it over a",      1, C_GRAY_5);     y += 18;
  textCenter(y, "trusted connection.",        1, C_GRAY_5);     y += 30;
  textCenter(y, "SecureKey will encrypt",     1, C_GRAY_5);     y += 18;
  textCenter(y, "the vault after import.",    1, C_GRAY_5);

  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54, gap = 12;
  const int16_t by2 = LCD_HEIGHT - bh - 40;
  const int16_t by1 = by2 - bh - gap;

  gfx->fillRoundRect(bx, by1, bw, bh, 12, C_WHITE);
  textCenter(by1 + bh/2 - 8, "CONTINUE", 2, C_BLACK);
  gfx->fillRoundRect(bx, by2, bw, bh, 12, C_GRAY_1);
  gfx->drawRoundRect(bx, by2, bw, bh, 12, C_GRAY_3);
  textCenter(by2 + bh/2 - 8, "CANCEL", 2, C_WHITE);

  flushScreen();
}

static void onTapImportWarn(int16_t tx, int16_t ty) {
  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54, gap = 12;
  const int16_t by2 = LCD_HEIGHT - bh - 40;
  const int16_t by1 = by2 - bh - gap;

  if (tx >= bx && tx < bx + bw && ty >= by1 && ty < by1 + bh) {
    // We're already ON SCR_IMPORT_WAIT here — importWarnShow() (above)
    // pushed it before drawing this warning as a pre-AP sub-state of that
    // same screen. Do NOT pushNav(SCR_IMPORT_WAIT) again (that would double
    // it on the nav stack, and CANCEL's popNav() on the next screen would
    // land back on a stale warning-flagged SCR_IMPORT_WAIT instead of
    // SCR_IMPORT_SOURCE). Just clear the flag, start the portal, and
    // redraw — the next drawAll() falls through to the normal
    // drawImportWait() body since importWarnPending is now false.
    importWarnPending = false;
    wifiPortalStartImportMode();
    drawAll();
    return;
  }
  if (tx >= bx && tx < bx + bw && ty >= by2 && ty < by2 + bh) {
    // CANCEL: back OUT of the SCR_IMPORT_WAIT that importWarnShow() pushed
    // us onto — popNav() returns to SCR_IMPORT_SOURCE, matching what this
    // button looked like it did before the warning screen had its own nav
    // entry (a bare drawAll() here would instead redraw the NORMAL
    // drawImportWait() body against a portal that was never started, i.e.
    // "Starting WiFi..." forever — a dead end, not a cancel).
    importWarnPending = false;
    popNav();
    return;
  }
}

// ── SCR_IMPORT_WAIT ────────────────────────────────────────────────────
// Mirrors screen_wifi.ino's drawWifi() layout (same accessors, mode-
// agnostic), but with upload-specific instructions. Auto-advances once
// bw_import.ino's stage reaches AWAITING_PREVIEW (checked by the ~1 Hz
// redraw hook in 06_PasswordManager.ino's loop()).
void drawImportWait() {
  if (importWarnPending) { drawImportWarn(); return; }

  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  drawNavBar("Bitwarden Import", true, nullptr);

  if (!wifiPortalActive()) {
    textCenter(STATUS_H + NAV_H + 60, "Starting WiFi...", 2, C_GRAY_4);
    flushScreen();
    return;
  }

  // Auto-advance once the upload has finished parsing.
  if (bwImportStage() == BWI_AWAITING_PREVIEW) {
    navTop--;   // pop SCR_IMPORT_WAIT
    pushNav(SCR_IMPORT_PREVIEW);
    return;
  }
  if (bwImportStage() == BWI_FAILED) {
    navTop--;
    pushNav(SCR_IMPORT_DONE);
    return;
  }

  int16_t y = STATUS_H + NAV_H + 6;
  textCenter(y, "1. Join this WiFi", 1, C_GRAY_4);   y += 20;
  textCenter(y, wifiPortalSsid(), 3, C_WHITE);       y += 38;

  textCenter(y, "2. WiFi password", 1, C_GRAY_4);    y += 20;
  textCenter(y, wifiPortalPass(), 3, C_WHITE);       y += 40;

  textCenter(y, "3. Open the page, enter code,", 1, C_GRAY_4);  y += 18;
  textCenter(y, "choose your export file", 1, C_GRAY_4);        y += 26;
  textCenter(y, wifiPortalCode(), 4, C_BLUE);        y += 44;

  textCenter(y, "Waiting for upload...", 1, C_GRAY_4);

  // Turn-off / cancel button
  const int16_t bw = 220, bh = 56, bx = (LCD_WIDTH - bw) / 2, by = LCD_HEIGHT - 70;
  gfx->fillRoundRect(bx, by, bw, bh, 14, C_GRAY_1);
  gfx->drawRoundRect(bx, by, bw, bh, 14, C_WHITE);
  textCenter(by + 18, "Cancel", 2, C_WHITE);

  flushScreen();
}

void onTapImportWait(int16_t tx, int16_t ty) {
  if (importWarnPending) { onTapImportWarn(tx, ty); return; }

  bool back = (ty >= STATUS_H + 2 && ty < STATUS_H + NAV_H - 2
              && tx >= SAFE_PAD && tx < SAFE_PAD + 46);
  const int16_t bh = 56, by = LCD_HEIGHT - 70;
  bool cancelBtn = (ty >= by && ty < by + bh);

  if (back || cancelBtn) {
    bwImportDiscard();
    wifiPortalStop();
    popNav();
    return;
  }
}

// ── SCR_IMPORT_PREVIEW ─────────────────────────────────────────────────
// Counts ONLY — never item names, never any field content. Matches the
// spec's explicit "be thoughtful about even showing item names" — the
// safest reading is to omit them entirely.
void drawImportPreview() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  drawNavBar("Import Preview", false, nullptr);

  int16_t y = STATUS_H + NAV_H + 24;
  char b[48];

  snprintf(b, sizeof(b), "Logins:        %u", bwImportLoginsFound());
  textCenter(y, b, 2, C_WHITE); y += 32;
  snprintf(b, sizeof(b), "Secure Notes:  %u", bwImportNotesFound());
  textCenter(y, b, 2, C_WHITE); y += 32;
  snprintf(b, sizeof(b), "Folders:       %u", bwImportFoldersFound());
  textCenter(y, b, 2, C_WHITE); y += 44;

  if (bwImportUnsupportedFound() > 0) {
    snprintf(b, sizeof(b), "%u unsupported (skipped)", bwImportUnsupportedFound());
    textCenter(y, b, 1, C_GRAY_4); y += 20;
  }
  if (bwImportDuplicatesFound() > 0) {
    snprintf(b, sizeof(b), "%u duplicates (skipped)", bwImportDuplicatesFound());
    textCenter(y, b, 1, C_GRAY_4); y += 20;
  }
  y += 10;
  textCenter(y, "Notes/TOTP/custom fields may", 1, C_GRAY_3); y += 16;
  textCenter(y, "be truncated — see docs.",      1, C_GRAY_3);

  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 56, gap = 12;
  const int16_t by1 = LCD_HEIGHT - bh - 40;
  const int16_t by2 = by1 - bh - gap;

  gfx->fillRoundRect(bx, by2, bw, bh, 12, C_WHITE);
  textCenter(by2 + bh/2 - 8, "IMPORT", 2, C_BLACK);
  gfx->fillRoundRect(bx, by1, bw, bh, 12, C_GRAY_1);
  gfx->drawRoundRect(bx, by1, bw, bh, 12, C_GRAY_3);
  textCenter(by1 + bh/2 - 8, "CANCEL", 2, C_WHITE);

  flushScreen();
}

void onTapImportPreview(int16_t tx, int16_t ty) {
  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 56, gap = 12;
  const int16_t by1 = LCD_HEIGHT - bh - 40;
  const int16_t by2 = by1 - bh - gap;

  if (tx >= bx && tx < bx + bw && ty >= by2 && ty < by2 + bh) {   // IMPORT
    navTop--;
    pushNav(SCR_IMPORT_PROGRESS);
    return;
  }
  if (tx >= bx && tx < bx + bw && ty >= by1 && ty < by1 + bh) {   // CANCEL
    bwImportDiscard();
    wifiPortalStop();
    navTop = 0; navStack[0] = SCR_HOME; current = SCR_HOME;
    drawAll();
    return;
  }
}

// ── SCR_IMPORT_PROGRESS ────────────────────────────────────────────────
// Blocking call with periodic on-screen updates — mirrors screen_migrate.
// ino's MIG_RUNNING idiom (already proven for thousands of records), but
// additionally shows a live "N / M" count via importProgressTick(), called
// directly by bw_import.ino's bwImportCommit() every few dozen records.
static bool importProgressRan = false;

// Lightweight redraw — status bar + live count only, no navigation/state
// changes. Called from INSIDE bwImportCommit()'s loops (bw_import.ino), so
// it must never touch anything that could recurse back into the commit.
void importProgressTick() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  textCenter(LCD_HEIGHT/2 - 30, "Importing...", 3, C_WHITE);
  uint32_t total = bwImportCommitTotal();
  if (total > 0) {
    char b[32];
    snprintf(b, sizeof(b), "%u / %u", bwImportCommitDone(), total);
    textCenter(LCD_HEIGHT/2 + 10, b, 2, C_WHITE);
  }
  textCenter(LCD_HEIGHT/2 + 44, "Encrypting vault...", 1, C_GRAY_4);
  flushScreen();
}

void drawImportProgress() {
  importProgressTick();

  if (!importProgressRan) {
    importProgressRan = true;
    bool ok = bwImportCommit();
    importProgressRan = false;
    navTop--;
    pushNav(SCR_IMPORT_DONE);
    (void)ok;   // drawImportDone() reads bwImportStage()/errorMsg directly
  }
}

void onTapImportProgress(int16_t tx, int16_t ty) {
  (void)tx; (void)ty;   // non-interactive while running
}

// ── SCR_IMPORT_DONE ────────────────────────────────────────────────────
void drawImportDone() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();

  bool ok = (bwImportStage() == BWI_DONE);
  char b[48];

  if (ok) {
    textCenter(STATUS_H + 50, "IMPORT COMPLETE", 3, C_WHITE);
    int16_t y = STATUS_H + 110;
    snprintf(b, sizeof(b), "%u new entries added", bwImportFinalNew());
    textCenter(y, b, 2, C_WHITE); y += 32;
    snprintf(b, sizeof(b), "%u total in vault", bwImportFinalTotal());
    textCenter(y, b, 1, C_GRAY_4); y += 26;
    if (bwImportDuplicatesFound() > 0) {
      snprintf(b, sizeof(b), "%u duplicates skipped", bwImportDuplicatesFound());
      textCenter(y, b, 1, C_GRAY_4); y += 20;
    }
    if (bwImportUnsupportedFound() > 0) {
      snprintf(b, sizeof(b), "%u unsupported skipped", bwImportUnsupportedFound());
      textCenter(y, b, 1, C_GRAY_4);
    }
  } else {
    textCenter(STATUS_H + 50, "IMPORT FAILED", 3, C_RED);
    textCenter(STATUS_H + 100, bwImportErrorMsg(), 2, C_WHITE);
    textCenter(STATUS_H + 140, "Your existing vault was", 1, C_GRAY_5);
    textCenter(STATUS_H + 158, "NOT changed.", 1, C_GRAY_5);
  }

  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 56;
  const int16_t by = LCD_HEIGHT - bh - 40;
  gfx->fillRoundRect(bx, by, bw, bh, 12, C_WHITE);
  textCenter(by + bh/2 - 8, "DONE", 2, C_BLACK);

  flushScreen();
}

void onTapImportDone(int16_t tx, int16_t ty) {
  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 56;
  const int16_t by = LCD_HEIGHT - bh - 40;
  if (tx >= bx && tx < bx + bw && ty >= by && ty < by + bh) {
    wifiPortalStop();
    bwImportDiscard();
    navTop = 0; navStack[0] = SCR_HOME; current = SCR_HOME;
    drawAll();
  }
}
