// =============================================================
//  screen_chgpin.ino  —  Change-PIN flow (3 steps)
//
//     Enter current PIN  →  Enter new PIN  →  Confirm new PIN
//
//  The OLD PIN is verified with vaultUnlock() — the same call the lock
//  screen uses — so there is no separate stored PIN to strcmp() against.
//  On success, vaultRewrapKey() re-wraps the EXISTING master key under a
//  freshly PBKDF2-derived KEK (new random salt + nonce): the database
//  itself is untouched (still the same master key, so no re-encryption
//  of every record is needed), only the wrapping around that key changes.
//
//  Self-contained keypad (doesn't reuse screen_pin's PKEYS, since
//  Arduino concatenates files alphabetically and this one comes
//  first — file-scope vars wouldn't be visible yet).
// =============================================================

static uint8_t  cpStep = 0;          // 0=current, 1=new, 2=confirm
static char     cpBuf[PIN_MAX_LEN + 1]  = {0};
static uint8_t  cpLen     = 0;
static char     cpNew[PIN_MAX_LEN + 1]  = {0};
static uint32_t cpShake   = 0;
static uint8_t  cpTargetLen = PIN_MIN_LEN;   // length of the CURRENT pin (step 0)
static uint8_t  cpNewLen    = PIN_RECOMMENDED_LEN; // chosen length for the NEW pin

static void cpBufWipe() { ckSecureZero(cpBuf, sizeof(cpBuf)); cpLen = 0; }
static void cpNewWipe() { ckSecureZero(cpNew, sizeof(cpNew)); }

void chgPinInit() {
  cpStep = 0; cpShake = 0;
  cpBufWipe(); cpNewWipe();
  cpTargetLen = pinDisplayLen();   // how many digits the EXISTING PIN has
  cpNewLen    = PIN_RECOMMENDED_LEN;
}

// ── Keypad geometry ───────────────────────────────────────────
static const char *CP_KEYS[12] = {
  "1","2","3","4","5","6","7","8","9","BS","0","OK"
};
#define CP_W   96
#define CP_H   54
#define CP_G   8
#define CP_X0  ((LCD_WIDTH - (3*CP_W + 2*CP_G)) / 2)
#define CP_Y0  158
static int16_t cpkX(uint8_t i) { return CP_X0 + (i % 3) * (CP_W + CP_G); }
static int16_t cpkY(uint8_t i) { return CP_Y0 + (i / 3) * (CP_H + CP_G); }

static void drawCpKey(uint8_t i, bool pressed) {
  int16_t x = cpkX(i), y = cpkY(i);
  const char *k = CP_KEYS[i];
  bool isOK = (strcmp(k, "OK") == 0);
  uint16_t bg = (pressed || isOK) ? C_WHITE  : C_GRAY_1;
  uint16_t fg = (pressed || isOK) ? C_BLACK  : C_WHITE;
  gfx->fillRoundRect(x, y, CP_W, CP_H, 8, bg);
  if (!pressed && !isOK) gfx->drawRoundRect(x, y, CP_W, CP_H, 8, C_GRAY_2);

  const char *lbl = (strcmp(k, "BS") == 0) ? "<" : k;
  uint8_t fs = (strlen(lbl) <= 1) ? 3 : 2;
  gfx->setTextSize(fs); gfx->setTextColor(fg);
  int16_t x1, y1; uint16_t tw, th;
  gfx->getTextBounds(lbl, 0, 0, &x1, &y1, &tw, &th);
  gfx->setCursor(x + (CP_W - (int16_t)tw) / 2, y + (CP_H - (int16_t)th) / 2);
  gfx->print(lbl);
}

static uint8_t cpCurrentStepLen() {
  return (cpStep == 0) ? cpTargetLen : cpNewLen;
}

void drawChgPin() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  drawNavBar("Change PIN", true, nullptr);

  const char *titles[3] = {
    "Enter current PIN", "Enter new PIN", "Confirm new PIN"
  };
  textCenter(STATUS_H + NAV_H + 8, titles[cpStep], 2, C_WHITE);

  // Dots — sized to whichever PIN length this step expects.
  int16_t cx = LCD_WIDTH / 2;
  int16_t dy = STATUS_H + NAV_H + 40;
  int16_t shake = (millis() < cpShake) ? ((millis() / 40) % 2 ? -8 : 8) : 0;
  uint8_t n = cpCurrentStepLen();
  int16_t spacing = (n > 6) ? 26 : 36;
  for (int i = 0; i < n; i++) {
    int16_t x = cx - (spacing * (n - 1)) / 2 + i * spacing + shake;
    if (i < cpLen)
      gfx->fillCircle(x, dy, 9, (millis() < cpShake) ? C_GRAY_3 : C_WHITE);
    else
      gfx->drawCircle(x, dy, 9, C_GRAY_3);
  }

  // On the "new PIN" step, offer a quick length picker above the keypad —
  // tapping it restarts entry at the chosen length (never silently changes
  // length mid-entry).
  if (cpStep == 1 && cpLen == 0) {
    char lb[36];
    snprintf(lb, sizeof(lb), "Length: %u  (tap to change)", cpNewLen);
    textCenter(dy + 26, lb, 1, C_GRAY_4);
  }

  for (uint8_t i = 0; i < 12; i++) drawCpKey(i, false);
  flushScreen();
}

// Process a completed entry for the current step.
static void cpProcess() {
  cpBuf[cpLen] = 0;
  if (cpStep == 0) {                       // verify current PIN
    // vaultVerifyPin() checks the PIN against the LIVE unlocked session
    // without touching vaultMasterKey/vaultUnlocked — a wrong re-entry
    // here must not lock the user out of the session they're already in
    // (unlike vaultUnlock(), which is for the lock screen itself).
    if (vaultVerifyPin(cpBuf)) {
      cpBufWipe();
      cpStep = 1;
    } else {
      cpShake = millis() + 500; cpBufWipe(); ledSet(0xFF0000, 400);
    }
  } else if (cpStep == 1) {                // capture new
    strncpy(cpNew, cpBuf, sizeof(cpNew) - 1);
    cpBufWipe();
    cpStep = 2;
  } else {                                 // confirm
    if (strcmp(cpBuf, cpNew) == 0) {
      bool ok = vaultRewrapKey(cpNew);
      cpBufWipe(); cpNewWipe();
      if (ok) pinRefreshLength();   // new PIN may be a different length
      gfx->fillScreen(C_BLACK); drawStatusBar();
      if (ok) {
        textCenter(LCD_HEIGHT/2 - 16, "PIN CHANGED", 3, C_WHITE);
        flushScreen(); ledSet(0x00FF00, 500); delay(1200);
        popNav(); return;
      } else {
        textCenter(LCD_HEIGHT/2 - 16, "CHANGE FAILED", 3, C_RED);
        textCenter(LCD_HEIGHT/2 + 20, "PIN unchanged. Try again.", 1, C_GRAY_4);
        flushScreen(); ledSet(0xFF0000, 600); delay(1600);
        chgPinInit();
        drawChgPin(); return;
      }
    } else {                               // mismatch — restart at "new"
      cpShake = millis() + 500;
      cpStep = 1; cpBufWipe(); cpNewWipe();
      ledSet(0xFF0000, 400);
    }
  }
  drawChgPin();
}

static bool cpTapLengthPicker(int16_t tx, int16_t ty) {
  int16_t dy = STATUS_H + NAV_H + 40 + 26;
  if (ty < dy - 14 || ty > dy + 14) return false;
  // Cycle 4 -> 6 -> 8 -> 4 on tap, without needing separate hit boxes.
  cpNewLen = (cpNewLen == 4) ? 6 : (cpNewLen == 6) ? 8 : 4;
  return true;
}

void onTapChgPin(int16_t tx, int16_t ty) {
  // Back
  if (ty >= STATUS_H + 2 && ty < STATUS_H + NAV_H - 2
      && tx >= SAFE_PAD && tx < SAFE_PAD + 46) {
    cpBufWipe(); cpNewWipe();
    popNav(); return;
  }

  if (cpStep == 1 && cpLen == 0 && cpTapLengthPicker(tx, ty)) {
    drawChgPin();
    return;
  }

  for (uint8_t i = 0; i < 12; i++) {
    int16_t x = cpkX(i), y = cpkY(i);
    if (tx < x || tx >= x + CP_W) continue;
    if (ty < y || ty >= y + CP_H) continue;

    drawCpKey(i, true); flushScreen(); delay(50);

    const char *k = CP_KEYS[i];
    uint8_t need = cpCurrentStepLen();
    if (strcmp(k, "BS") == 0) {
      if (cpLen) { cpBuf[--cpLen] = 0; }
    } else if (strcmp(k, "OK") == 0) {
      if (cpLen == need) { cpProcess(); return; }
    } else if (cpLen < need) {
      cpBuf[cpLen++] = k[0]; cpBuf[cpLen] = 0;
      if (cpLen == need) { cpProcess(); return; }
    }
    drawChgPin();
    return;
  }
}
