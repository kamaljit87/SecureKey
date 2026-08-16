// =============================================================
//  screen_setup_pin.ino  —  First-boot / post-factory-reset PIN setup
//
//  Runs whenever vaultCryptoProvisioned() is false: brand-new device,
//  or right after a factory reset. Steps:
//
//      0: choose PIN length   (4 / 6 / 8 digits — 6+ recommended)
//      1: enter new PIN
//      2: confirm new PIN
//
//  On confirm: vaultCryptoProvision(pin) generates a fresh random 256-bit
//  master key, wraps it under a PBKDF2-derived KEK, and stores ONLY the
//  salt + wrapped key + KDF params in NVS — never the PIN itself.
//
//  After provisioning: if a legacy plaintext /db.bin is present (firmware
//  upgrade from a pre-encryption build), hand off to SCR_MIGRATE. Otherwise
//  create a fresh empty encrypted database and go straight to HOME.
// =============================================================

static uint8_t  spStep     = 0;     // 0=length, 1=new, 2=confirm
static uint8_t  spPinLen   = PIN_RECOMMENDED_LEN;
static char     spBuf[PIN_MAX_LEN + 1] = {0};
static uint8_t  spLen      = 0;
static char     spNew[PIN_MAX_LEN + 1] = {0};
static uint32_t spShake    = 0;

static void spBufWipe()  { ckSecureZero(spBuf, sizeof(spBuf));  spLen = 0; }
static void spNewWipe()  { ckSecureZero(spNew, sizeof(spNew)); }

void setupPinInit() {
  spStep = 0; spPinLen = PIN_RECOMMENDED_LEN;
  spBufWipe(); spNewWipe();
  spShake = 0;
}

// ── Keypad geometry (mirrors screen_chgpin.ino's layout) ─────
static const char *SP_KEYS[12] = {
  "1","2","3","4","5","6","7","8","9","BS","0","OK"
};
#define SP_W   96
#define SP_H   54
#define SP_G   8
#define SP_X0  ((LCD_WIDTH - (3*SP_W + 2*SP_G)) / 2)
#define SP_Y0  190
static int16_t spkX(uint8_t i) { return SP_X0 + (i % 3) * (SP_W + SP_G); }
static int16_t spkY(uint8_t i) { return SP_Y0 + (i / 3) * (SP_H + SP_G); }

static void drawSpKey(uint8_t i, bool pressed) {
  int16_t x = spkX(i), y = spkY(i);
  const char *k = SP_KEYS[i];
  bool isOK = (strcmp(k, "OK") == 0);
  uint16_t bg = (pressed || isOK) ? C_WHITE  : C_GRAY_1;
  uint16_t fg = (pressed || isOK) ? C_BLACK  : C_WHITE;
  gfx->fillRoundRect(x, y, SP_W, SP_H, 8, bg);
  if (!pressed && !isOK) gfx->drawRoundRect(x, y, SP_W, SP_H, 8, C_GRAY_2);

  const char *lbl = (strcmp(k, "BS") == 0) ? "<" : k;
  uint8_t fs = (strlen(lbl) <= 1) ? 3 : 2;
  gfx->setTextSize(fs); gfx->setTextColor(fg);
  int16_t x1, y1; uint16_t tw, th;
  gfx->getTextBounds(lbl, 0, 0, &x1, &y1, &tw, &th);
  gfx->setCursor(x + (SP_W - (int16_t)tw) / 2, y + (SP_H - (int16_t)th) / 2);
  gfx->print(lbl);
}

// ── Step 0: PIN-length picker ─────────────────────────────────
#define SP_LENOPT_Y   190
#define SP_LENOPT_H   54
static void drawLengthPicker() {
  textCenter(STATUS_H + 40, "Choose PIN length", 2, C_WHITE);
  textCenter(STATUS_H + 64, "6+ digits recommended", 1, C_GRAY_4);

  const uint8_t opts[3] = {4, 6, 8};
  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = SP_LENOPT_H;
  for (int i = 0; i < 3; i++) {
    int16_t y = SP_LENOPT_Y + i * (bh + 12);
    bool sel = (spPinLen == opts[i]);
    gfx->fillRoundRect(bx, y, bw, bh, 12, sel ? C_WHITE : C_GRAY_1);
    gfx->drawRoundRect(bx, y, bw, bh, 12, sel ? C_WHITE : C_GRAY_3);
    char lbl[32];
    snprintf(lbl, sizeof(lbl), "%u digits%s", opts[i],
             opts[i] == PIN_RECOMMENDED_LEN ? "  (recommended)" : "");
    textCenter(y + bh/2 - 8, lbl, 2, sel ? C_BLACK : C_WHITE);
  }
  textCenter(SP_LENOPT_Y + 3*(bh+12) + 20, "tap to continue", 1, C_GRAY_4);
}

static bool spTapLengthPicker(int16_t tx, int16_t ty) {
  const uint8_t opts[3] = {4, 6, 8};
  const int16_t bx = SAFE_PAD, bw = LCD_WIDTH - 2*SAFE_PAD, bh = SP_LENOPT_H;
  for (int i = 0; i < 3; i++) {
    int16_t y = SP_LENOPT_Y + i * (bh + 12);
    if (tx >= bx && tx < bx + bw && ty >= y && ty < y + bh) {
      spPinLen = opts[i];
      spStep = 1;
      return true;
    }
  }
  return false;
}

void drawSetupPin() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();

  if (spStep == 0) {
    drawLengthPicker();
    flushScreen();
    return;
  }

  const char *titles[3] = { "", "Set a new PIN", "Confirm new PIN" };
  textCenter(STATUS_H + 30, "SecureKey Setup", 2, C_GRAY_4);
  textCenter(STATUS_H + 56, titles[spStep], 2, C_WHITE);

  int16_t cx = LCD_WIDTH / 2;
  int16_t dy = STATUS_H + 96;
  int16_t shake = (millis() < spShake) ? ((millis() / 40) % 2 ? -8 : 8) : 0;
  int16_t spacing = (spPinLen > 6) ? 26 : 36;
  for (int i = 0; i < spPinLen; i++) {
    int16_t x = cx - (spacing * (spPinLen - 1)) / 2 + i * spacing + shake;
    if (i < spLen)
      gfx->fillCircle(x, dy, 8, (millis() < spShake) ? C_RED : C_WHITE);
    else
      gfx->drawCircle(x, dy, 8, C_GRAY_3);
  }

  for (uint8_t i = 0; i < 12; i++) drawSpKey(i, false);
  flushScreen();
}

// ── Finish: provision the vault, then either migrate or start fresh ──
static void spFinishProvision() {
  bool ok = vaultCryptoProvision(spNew);
  spNewWipe();
  if (!ok) {
    gfx->fillScreen(C_BLACK); drawStatusBar();
    textCenter(LCD_HEIGHT/2 - 10, "SETUP FAILED", 3, C_RED);
    textCenter(LCD_HEIGHT/2 + 26, "Please retry", 2, C_GRAY_4);
    flushScreen();
    ledSet(0xFF0000, 600);
    delay(1800);
    setupPinInit();
    drawAll();
    return;
  }

  ledSet(0x00FF00, 300);

  if (dbMigrationNeeded()) {
    // Hand off to the migration screen — it will call
    // dbMigrateLegacyPlaintext() explicitly after a confirm tap, never
    // automatically/silently.
    extern void migrateInit();
    migrateInit();
    navTop = 0; navStack[0] = SCR_MIGRATE; current = SCR_MIGRATE;
    drawAll();
    return;
  }

  // Brand-new vault: no old data to migrate. dbSeed() creates the empty
  // encrypted database and, ONLY on a SECUREKEY_DEMO_MODE build (see
  // storage.ino), also seeds a few obviously-fake example.invalid demo
  // entries — production builds never compile in demo credentials, so
  // this call is always safe to leave in place.
  dbSeed();
  dbLoadIndex();
  gfx->fillScreen(C_BLACK); drawStatusBar();
  textCenter(LCD_HEIGHT/2 - 10, "VAULT READY", 3, C_WHITE);
  flushScreen();
  delay(900);
  navTop = 0; navStack[0] = SCR_HOME; current = SCR_HOME;
  drawAll();
}

static void spProcess() {
  spBuf[spLen] = 0;
  if (spStep == 1) {                       // capture new
    if (spLen != spPinLen) return;         // shouldn't happen (auto-submits at len)
    strncpy(spNew, spBuf, sizeof(spNew) - 1);
    spBufWipe();
    spStep = 2;
  } else if (spStep == 2) {                // confirm
    if (spLen != spPinLen) return;
    if (strcmp(spBuf, spNew) == 0) {
      spBufWipe();
      spFinishProvision();
      return;
    } else {
      spShake = millis() + 500;
      spBufWipe(); spNewWipe();
      spStep = 1;
      ledSet(0xFF0000, 400);
    }
  }
  drawSetupPin();
}

void onTapSetupPin(int16_t tx, int16_t ty) {
  if (spStep == 0) { if (spTapLengthPicker(tx, ty)) drawSetupPin(); return; }

  for (uint8_t i = 0; i < 12; i++) {
    int16_t x = spkX(i), y = spkY(i);
    if (tx < x || tx >= x + SP_W) continue;
    if (ty < y || ty >= y + SP_H) continue;

    drawSpKey(i, true); flushScreen(); delay(15);

    const char *k = SP_KEYS[i];
    if (strcmp(k, "BS") == 0) {
      if (spLen) { spBuf[--spLen] = 0; }
    } else if (strcmp(k, "OK") == 0) {
      if (spLen == spPinLen) spProcess();
    } else if (spLen < spPinLen) {
      spBuf[spLen++] = k[0]; spBuf[spLen] = 0;
      if (spLen == spPinLen) { spProcess(); return; }
    }
    drawSetupPin();
    return;
  }
}
