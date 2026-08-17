// =============================================================
//  screen_migrate_v3.ino  —  v2 -> v3 folder-format migration UI
//
//  Reached from screen_pin.ino's pinUnlockSuccess() when db_migrate_v3.ino's
//  dbV3MigrationNeeded() detects an old-format database right after a
//  normal PIN unlock. Deliberately a SEPARATE screen from screen_migrate.ino
//  (which handles the older v1-plaintext upgrade) — same UI idiom, kept
//  distinct in code and on-screen so the two migrations are never confused.
//  This one is fully invisible/automatic from the user's perspective (no
//  "old data found" language — it's just "upgrading" bookkeeping), but
//  still shows a brief progress state and fails closed with a clear message
//  if verification doesn't pass.
// =============================================================

enum MigrateV3UiState { MIG3_RUNNING, MIG3_DONE, MIG3_FAILED };
static MigrateV3UiState mig3State = MIG3_RUNNING;

void migrateV3Init() {
  mig3State = MIG3_RUNNING;
}

void drawMigrateV3() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();

  if (mig3State == MIG3_RUNNING) {
    textCenter(LCD_HEIGHT/2 - 20, "Upgrading vault...", 3, C_WHITE);
    textCenter(LCD_HEIGHT/2 + 20, "please wait", 1, C_GRAY_4);
  } else if (mig3State == MIG3_DONE) {
    textCenter(LCD_HEIGHT/2 - 20, "VAULT UPGRADED", 3, C_WHITE);
    textCenter(LCD_HEIGHT/2 + 20, "folders are now available", 1, C_GRAY_4);
  } else { // MIG3_FAILED
    textCenter(STATUS_H + 60, "UPGRADE FAILED", 3, C_RED);
    textCenter(STATUS_H + 110, "Your vault is safe and", 1, C_GRAY_5);
    textCenter(STATUS_H + 128, "was NOT changed.", 1, C_GRAY_5);
    textCenter(STATUS_H + 156, "This will be retried", 1, C_GRAY_5);
    textCenter(STATUS_H + 174, "automatically next unlock.", 1, C_GRAY_5);

    const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54;
    const int16_t y = LCD_HEIGHT - bh - 40;
    gfx->fillRoundRect(bx, y, bw, bh, 12, C_GRAY_1);
    gfx->drawRoundRect(bx, y, bw, bh, 12, C_WHITE);
    textCenter(y + bh/2 - 8, "CONTINUE", 2, C_WHITE);
  }

  flushScreen();
}

// Runs the migration synchronously the first time this screen is drawn via
// pushNav-equivalent entry (see the trigger in screen_pin.ino). There is no
// tap target while MIG3_RUNNING — same "ignore taps mid-operation" rule as
// screen_migrate.ino.
void migrateV3Run() {
  mig3State = MIG3_RUNNING;
  drawAll();
  bool ok = dbMigrateV3Folders();
  mig3State = ok ? MIG3_DONE : MIG3_FAILED;
  drawAll();
  if (ok) {
    delay(1200);
    navTop = 0; navStack[0] = SCR_HOME; current = SCR_HOME;
    drawAll();
  }
}

void onTapMigrateV3(int16_t tx, int16_t ty) {
  if (mig3State == MIG3_RUNNING) return;   // ignore taps mid-operation

  if (mig3State == MIG3_FAILED) {
    const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54;
    const int16_t y = LCD_HEIGHT - bh - 40;
    if (tx >= bx && tx < bx + bw && ty >= y && ty < y + bh) {
      // Proceed into the vault anyway — the OLD (v2) database is still
      // fully intact and readable; only the folder-name resolution falls
      // back to id-string display until the migration succeeds on a later
      // unlock (folderNameForId()'s "Folder" placeholder fallback covers
      // this gracefully — see folders.ino).
      navTop = 0; navStack[0] = SCR_HOME; current = SCR_HOME;
      drawAll();
    }
  }
}
