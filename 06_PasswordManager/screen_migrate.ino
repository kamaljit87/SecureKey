// =============================================================
//  screen_migrate.ino  —  Legacy plaintext DB → encrypted DB migration
//
//  Reached only when db_migrate.ino's dbMigrationNeeded() detected an
//  old pre-encryption plaintext /db.bin AND the user has just set a new
//  PIN on SCR_SETUP_PIN (so vaultUnlocked==true, a fresh master key
//  exists). Nothing here runs silently: the user sees a count of
//  entries found and must explicitly tap MIGRATE before anything is
//  read or written. See db_migrate.ino for the actual verify-then-
//  delete transaction.
// =============================================================

enum MigrateUiState { MIG_CONFIRM, MIG_RUNNING, MIG_DONE, MIG_FAILED };
static MigrateUiState migState = MIG_CONFIRM;
static uint16_t        migCount = 0;

void migrateInit() {
  migState = MIG_CONFIRM;
  migCount = dbMigrationLegacyCount();
}

void drawMigrate() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();

  if (migState == MIG_CONFIRM) {
    textCenter(STATUS_H + 40, "Upgrade Vault", 3, C_WHITE);
    textCenter(STATUS_H + 84, "An older unencrypted", 1, C_GRAY_5);
    textCenter(STATUS_H + 102, "password database was found.", 1, C_GRAY_5);

    char b[40];
    snprintf(b, sizeof(b), "%u entries will be", migCount);
    textCenter(STATUS_H + 138, b, 2, C_WHITE);
    textCenter(STATUS_H + 164, "encrypted and verified.", 2, C_WHITE);

    textCenter(STATUS_H + 200, "The old file is deleted", 1, C_GRAY_4);
    textCenter(STATUS_H + 218, "ONLY after every entry", 1, C_GRAY_4);
    textCenter(STATUS_H + 236, "is confirmed to match.", 1, C_GRAY_4);

    const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54;
    const int16_t y = LCD_HEIGHT - bh - 40;
    gfx->fillRoundRect(bx, y, bw, bh, 12, C_WHITE);
    textCenter(y + bh/2 - 8, "MIGRATE NOW", 2, C_BLACK);
  } else if (migState == MIG_RUNNING) {
    textCenter(LCD_HEIGHT/2 - 20, "Encrypting...", 3, C_WHITE);
    textCenter(LCD_HEIGHT/2 + 20, "please wait", 1, C_GRAY_4);
  } else if (migState == MIG_DONE) {
    textCenter(LCD_HEIGHT/2 - 20, "VAULT UPGRADED", 3, C_WHITE);
    char b[40];
    snprintf(b, sizeof(b), "%u entries migrated", migCount);
    textCenter(LCD_HEIGHT/2 + 20, b, 2, C_GRAY_4);
  } else { // MIG_FAILED
    textCenter(STATUS_H + 60, "MIGRATION FAILED", 3, C_RED);
    textCenter(STATUS_H + 110, "Your OLD data is safe and", 1, C_GRAY_5);
    textCenter(STATUS_H + 128, "was NOT deleted or changed.", 1, C_GRAY_5);
    textCenter(STATUS_H + 156, "Export/back up your vault", 1, C_GRAY_5);
    textCenter(STATUS_H + 174, "via Settings before retrying.", 1, C_GRAY_5);

    const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54;
    const int16_t y = LCD_HEIGHT - bh - 40;
    gfx->fillRoundRect(bx, y, bw, bh, 12, C_GRAY_1);
    gfx->drawRoundRect(bx, y, bw, bh, 12, C_WHITE);
    textCenter(y + bh/2 - 8, "RETRY", 2, C_WHITE);
  }

  flushScreen();
}

void onTapMigrate(int16_t tx, int16_t ty) {
  if (migState == MIG_RUNNING) return;   // ignore taps mid-operation

  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = 54;
  const int16_t y = LCD_HEIGHT - bh - 40;
  bool hitButton = (tx >= bx && tx < bx + bw && ty >= y && ty < y + bh);

  if (migState == MIG_CONFIRM && hitButton) {
    migState = MIG_RUNNING;
    drawAll();
    bool ok = dbMigrateLegacyPlaintext();
    migState = ok ? MIG_DONE : MIG_FAILED;
    drawAll();
    if (ok) {
      delay(1400);
      navTop = 0; navStack[0] = SCR_HOME; current = SCR_HOME;
      drawAll();
    }
    return;
  }

  if (migState == MIG_FAILED && hitButton) {
    migrateInit();
    drawAll();
    return;
  }
}
