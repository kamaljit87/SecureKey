// =============================================================
//  screen_add.ino  —  Add / edit a password (multi-step form)
//
//  6 fields, one at a time:
//     TITLE → USER → PASS → URL → FOLDER → NOTE
//
//  Each "OK" on the keyboard advances to the next field. The FOLDER step is
//  special: instead of the keyboard, it shows a picker overlay (existing
//  folders + "No Folder" + "+ New Folder") — see drawFolderPicker()/
//  onTapFolderPicker() below.
//
//  After NOTE: appends a new PassRecord to FFat, reloads
//  the index, and returns directly to the Passwords list with
//  the new entry visible.
//
//  Critical: addInit() must be called by pushNav(SCR_ADD) to
//  reset state — without it the static record from a previous
//  session would leak into the new one.
// =============================================================

static uint8_t    addField = 0;
static PassRecord addRec;

// Folder picker sub-mode (a sub-mode of SCR_ADD, not its own top-level
// screen — same pattern as the PASSWORD field's GENERATE button being a
// sub-mode rather than a separate screen). addPickingNewFolder distinguishes
// "showing the picker list" from "typing a brand-new folder name" (which
// reuses the normal keyboard UI).
static bool addPickingFolder    = false;
static bool addPickingNewFolder = false;

#define FIELD_COUNT 6
static const char *FIELD_LABELS[FIELD_COUNT] = {
  "TITLE", "USERNAME", "PASSWORD", "URL", "FOLDER", "NOTE"
};
static const char *FIELD_HINTS[FIELD_COUNT] = {
  "e.g. Amazon", "user@example.com", "your password",
  "www.example.com", "tap to choose", "optional"
};
#define FIELD_FOLDER 4

// ── Reset state before entering Add screen ───────────────────
void addInit() {
  ckSecureZero(&addRec, sizeof(addRec));
  addField = 0;
  addPickingFolder = false;
  addPickingNewFolder = false;
  kbReset();
}

// ── Enter Add screen pre-filled for editing an existing record ───
//  Caller sets editingId = rec.id first; the save path then rewrites that
//  record in place instead of appending a new one.
void addEditInit(const PassRecord &rec) {
  addRec   = rec;
  addField = 0;
  addPickingFolder = false;
  addPickingNewFolder = false;
  kbReset();
  loadFromField(0);     // prefill the first field (TITLE) into the kb buffer
}

// ── Save kb input into addRec for the current field ──────────
// Case 3 (URL) used to ALSO silently overwrite addRec.folder with the URL
// text — that was a bug (folders never actually worked; the "folder"
// subtext shown on list rows was really just a URL copy). URL and folder
// are now fully independent fields.
static void copyToField(uint8_t f, const char *src) {
  switch (f) {
    case 0: strncpy(addRec.title,    src, sizeof(addRec.title)    - 1); break;
    case 1: strncpy(addRec.username, src, sizeof(addRec.username) - 1); break;
    case 2: strncpy(addRec.password, src, sizeof(addRec.password) - 1); break;
    case 3: strncpy(addRec.url,      src, sizeof(addRec.url)      - 1); break;
    // case FIELD_FOLDER (4) is handled separately by the picker/"+ New
    // Folder" flow — see onTapFolderPicker() — not by this keyboard-submit
    // path, so there's no case 4 here.
    case 5: strncpy(addRec.note,     src, sizeof(addRec.note)     - 1); break;
  }
}

// ── Load existing field value into kb buffer (for editing) ───
static void loadFromField(uint8_t f) {
  const char *src = "";
  switch (f) {
    case 0: src = addRec.title;    break;
    case 1: src = addRec.username; break;
    case 2: src = addRec.password; break;
    case 3: src = addRec.url;      break;
    case 5: src = addRec.note;     break;
    // case FIELD_FOLDER (4): nothing to prefill into the keyboard buffer —
    // the picker reads addRec.folder (a folder-id string) directly.
  }
  strncpy(kbBuffer, src, KB_MAX_LEN);
  kbBuffer[KB_MAX_LEN] = 0;
  kbLen = strlen(kbBuffer);
}

// ── Save the new record and return to list ───────────────────
// Goes through the same encrypted-DB API (dbAppend/dbUpdate) the rest of
// the app uses — no raw FFat file access here, so a new/edited record is
// always AES-256-GCM encrypted with its own fresh nonce before it ever
// touches flash. NEVER logs field contents (title/user/pass/url can all
// be sensitive).
static void saveNewRecord() {
  if (editingId == 0) {
    // New — pick next id
    uint16_t maxId = 0;
    for (uint16_t i = 0; i < passwordCount; i++)
      if (passwordIndex[i].id > maxId) maxId = passwordIndex[i].id;
    addRec.id      = maxId + 1;
    addRec.deleted = 0;
    SK_LOG("[ADD] saving new record id=%u\n", addRec.id);
    dbAppend(addRec);
  } else {
    SK_LOG("[ADD] updating record id=%u\n", editingId);
    dbUpdate(editingId, addRec);
  }
  dbLoadIndex();
  ledSet(0x00FF00, 350);
}

// ── Success splash (brief checkmark) ─────────────────────────
static void drawSavedSplash() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  int16_t cx = LCD_WIDTH/2, cy = LCD_HEIGHT/2 + 40;
  // Green-glow success check (banded halo + tick) — drawn BEFORE the
  // text so the glow can never paint over the "SAVED" glyphs.
  glowCircle(cx, cy + 4, 56, 34, lerp565(C_BLACK, 0x362B, 140));
  gfx->fillCircle(cx, cy + 4, 32, lerp565(C_BLACK, 0x362B, 110));
  gfx->drawCircle(cx, cy + 4, 32, 0x362B);
  for (int t = 0; t < 4; t++) {
    gfx->drawLine(cx - 14, cy + t,      cx - 4,  cy + 12 + t, C_WHITE);
    gfx->drawLine(cx - 4,  cy + 12 + t, cx + 16, cy - 8  + t, C_WHITE);
  }
  textCenter(LCD_HEIGHT/2 - 30, "SAVED", 4, C_WHITE);
  flushScreen();
}

// ── Called by keyboard.ino → onKeyboardSubmit (OK key) ───────
// NOTE: FIELD_FOLDER (4) never reaches this path via the normal keyboard OK
// key — the picker advances the field directly (see onTapFolderPicker()).
// This function's addField==FIELD_FOLDER branch only exists to handle the
// "+ New Folder" keyboard submission, which routes back here.
void addNextField() {
  if (addPickingNewFolder) {
    // Submitting a brand-new folder name from the keyboard (routed here by
    // keyboard.ino's normal OK-key path, since the "+ New Folder" step
    // reuses the shared keyboard UI). Empty name = treat as cancel.
    if (kbLen > 0) {
      uint16_t fid = folderIdForName(kbBuffer);
      char idStr[PT_FOLDER_LEN];
      snprintf(idStr, sizeof(idStr), "%u", fid);
      memset(addRec.folder, 0, sizeof(addRec.folder));
      strncpy(addRec.folder, idStr, sizeof(addRec.folder) - 1);
    }
    addPickingNewFolder = false;
    addPickingFolder = false;
    addField++;
    kbReset();
    if (addField < FIELD_COUNT) loadFromField(addField);
    drawAdd();
    return;
  }

  // Required-field validation: TITLE (0), USER (1), PASS (2) cannot be
  // empty.  URL (3), FOLDER (4) and NOTE (5) are optional.
  bool isRequired = (addField <= 2);
  if (isRequired && kbLen == 0) {
    // No nag popup. The OK button simply stays white (not blue) to show the
    // field isn't ready yet — just ignore the tap.
    return;
  }

  copyToField(addField, kbBuffer);
  addField++;

  if (addField >= FIELD_COUNT) {
    saveNewRecord();
    drawSavedSplash();
    delay(700);

    // Fully close the add/edit flow: clear the form, the keyboard, the edit
    // target and the whole nav stack, and land on a clean Home screen. (Was
    // dropping onto the Passwords list; per request, saving now closes
    // everything out.) addRec/kbBuffer held a plaintext password during
    // this whole flow — securely wipe both now that they're saved.
    addField = 0;
    addPickingFolder = false;
    addPickingNewFolder = false;
    ckSecureZero(&addRec, sizeof(addRec));
    kbReset();
    editingId      = 0;
    listSearchMode = false;
    listQuery[0]   = 0;
    homeExitReorder();          // never leave Home in arrange mode
    navTop      = 0;
    navStack[0] = SCR_HOME;
    current     = SCR_HOME;
    drawAll();
    return;
  }

  if (addField == FIELD_FOLDER) {
    // Enter the picker sub-mode instead of the normal keyboard step.
    addPickingFolder = true;
  } else {
    loadFromField(addField);
  }
  drawAdd();
}

// ── Folder picker (sub-mode of the FOLDER field) ─────────────────────────
// Row 0 = "No Folder", rows 1..N = existing folders (from the in-RAM index
// — folders.ino), final row = "+ New Folder". Scrolling isn't implemented
// (MAX_FOLDERS=256 could in theory overflow one screen, but in practice a
// handful of folders is the common case; a future pass could add the same
// scroll idiom screen_list.ino already uses if this becomes a real
// limitation — noted, not blocking for this feature).
#define FP_ROW_Y0  (STATUS_H + NAV_H + 8)
#define FP_ROW_H   46
#define FP_ROW_GAP 6

static uint8_t fpVisibleRows() {
  // No-Folder + existing folders + New-Folder, capped to what fits on screen.
  uint16_t n = 2 + foldersCount();
  uint16_t maxFit = (uint16_t)((LCD_HEIGHT - FP_ROW_Y0 - 40) / (FP_ROW_H + FP_ROW_GAP));
  return (uint8_t)(n < maxFit ? n : maxFit);
}

static void drawFolderPicker() {
  textCenter(STATUS_H + NAV_H + 4, "Choose a folder", 1, C_GRAY_4);

  uint16_t curFid = (uint16_t)atoi(addRec.folder);
  uint8_t rows = fpVisibleRows();
  uint16_t existing = foldersCount();

  for (uint8_t i = 0; i < rows; i++) {
    int16_t y = FP_ROW_Y0 + i * (FP_ROW_H + FP_ROW_GAP);
    bool isNoFolder = (i == 0);
    bool isNewFolder = (i == rows - 1) && (i >= existing + 1);
    bool sel = false;
    char label[PT_FOLDER_NAME_LEN + 8] = {0};

    if (isNoFolder) {
      strncpy(label, "No Folder", sizeof(label) - 1);
      sel = (curFid == 0);
    } else if (isNewFolder) {
      strncpy(label, "+ New Folder", sizeof(label) - 1);
    } else {
      uint16_t fid; char fname[PT_FOLDER_NAME_LEN];
      if (foldersGetAt(i - 1, fid, fname, sizeof(fname))) {
        strncpy(label, fname, sizeof(label) - 1);
        sel = (curFid == fid);
      }
    }

    uint16_t bg = sel ? C_GRAY_2 : C_GRAY_1;
    uint16_t bd = sel ? C_BLUE   : C_GRAY_2;
    gfx->fillRoundRect(SAFE_PAD, y, LCD_WIDTH - 2*SAFE_PAD, FP_ROW_H, 10, bg);
    gfx->drawRoundRect(SAFE_PAD, y, LCD_WIDTH - 2*SAFE_PAD, FP_ROW_H, 10, bd);
    textClipped(SAFE_PAD + 14, y + (FP_ROW_H - 14) / 2, label, 2,
               isNewFolder ? C_BLUE : C_WHITE, LCD_WIDTH - 2*SAFE_PAD - 28);
  }
}

static void onTapFolderPicker(int16_t tx, int16_t ty) {
  uint8_t rows = fpVisibleRows();
  uint16_t existing = foldersCount();

  for (uint8_t i = 0; i < rows; i++) {
    int16_t y = FP_ROW_Y0 + i * (FP_ROW_H + FP_ROW_GAP);
    if (ty < y || ty >= y + FP_ROW_H) continue;

    bool isNoFolder  = (i == 0);
    bool isNewFolder = (i == rows - 1) && (i >= existing + 1);

    if (isNoFolder) {
      memset(addRec.folder, 0, sizeof(addRec.folder));
      addPickingFolder = false;
      addField++;
      if (addField < FIELD_COUNT) loadFromField(addField);
      drawAdd();
      return;
    }
    if (isNewFolder) {
      addPickingNewFolder = true;
      kbReset();
      drawAdd();
      return;
    }
    // Existing folder row
    uint16_t fid; char fname[PT_FOLDER_NAME_LEN];
    if (foldersGetAt(i - 1, fid, fname, sizeof(fname))) {
      char idStr[PT_FOLDER_LEN];
      snprintf(idStr, sizeof(idStr), "%u", fid);
      memset(addRec.folder, 0, sizeof(addRec.folder));
      strncpy(addRec.folder, idStr, sizeof(addRec.folder) - 1);
    }
    addPickingFolder = false;
    addField++;
    if (addField < FIELD_COUNT) loadFromField(addField);
    drawAdd();
    return;
  }
}

// ── Draw ──────────────────────────────────────────────────────
void drawAdd() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();

  char navT[32];
  snprintf(navT, sizeof(navT), "%s  %u/%u",
           editingId == 0 ? "Add New" : "Edit", addField + 1, (unsigned)FIELD_COUNT);
  drawNavBar(navT, true, addPickingFolder ? nullptr : "OK");

  if (addPickingFolder) {
    drawFolderPicker();
    flushScreen();
    return;
  }

  // OK button: white when the field is empty, blue once you've typed
  // something — a clear "ready" cue instead of a nagging popup.
  if (kbLen > 0) {
    int16_t bx = LCD_WIDTH - SAFE_PAD - 36, by = STATUS_H + 6;
    gfx->fillRoundRect(bx, by, 36, 34, 6, C_GRAY_1);
    gfx->drawRoundRect(bx, by, 36, 34, 6, C_BLUE);
    gfx->setTextSize(2); gfx->setTextColor(C_BLUE);
    gfx->setCursor(bx + 8, by + 8);
    gfx->print("OK");
  }

  // Field label
  textAt(SAFE_PAD, STATUS_H + NAV_H + 6, FIELD_LABELS[addField], 1, C_GRAY_3);

  // Input box
  int16_t y = STATUS_H + NAV_H + 22;
  int16_t x = SAFE_PAD;
  int16_t w = LCD_WIDTH - 2*SAFE_PAD;
  int16_t h = 44;

  gfx->fillRoundRect(x, y, w, h, 10, C_GRAY_1);
  gfx->drawRoundRect(x, y, w, h, 10, C_WHITE);

  // Value
  gfx->setTextSize(2);
  if (kbLen == 0) {
    gfx->setTextColor(C_GRAY_3);
    gfx->setCursor(x + 12, y + 14);
    gfx->print(FIELD_HINTS[addField]);
  } else {
    gfx->setTextColor(C_WHITE);
    textClipped(x + 12, y + 14, kbBuffer, 2, C_WHITE, w - 24);
  }
  // Cursor blink
  if ((millis() / 500) % 2) {
    int16_t tx = x + 12 + (int16_t)kbLen * 12;
    if (tx < x + w - 8) gfx->fillRect(tx + 2, y + 12, 2, 22, C_WHITE);
  }

  // (progress dots removed — the nav bar already shows the "N/5" step,
  //  and the taller grid keyboard now needs that vertical space)

  // Suggestions just above keyboard (only for non-password fields).
  // The PASSWORD field gets a GENERATE button in that same slot instead —
  // draws a cryptographically random password (pwgen.ino, HW RNG) straight
  // into the field, which the user can still edit afterward.
  if (addField != 2) {
    kbDrawSuggestions(KB_TOP_Y - 36);
  } else {
    int16_t gy = KB_TOP_Y - 36;
    int16_t gx = SAFE_PAD, gw = LCD_WIDTH - 2*SAFE_PAD;
    int16_t lenW = 64;
    int16_t genW = gw - lenW - 8;
    // GENERATE (left, wide) + tap-to-cycle length (right, narrow: 12/16/20/24)
    gfx->fillRoundRect(gx, gy, genW, 30, 8, C_GRAY_1);
    gfx->drawRoundRect(gx, gy, genW, 30, 8, C_BLUE);
    textCenter(gy + 8, "GENERATE PASSWORD", 1, C_BLUE);

    int16_t lx = gx + genW + 8;
    gfx->fillRoundRect(lx, gy, lenW, 30, 8, C_GRAY_1);
    gfx->drawRoundRect(lx, gy, lenW, 30, 8, C_GRAY_3);
    char lb[8]; snprintf(lb, sizeof(lb), "%u", pwgenOpts.length);
    textCenter(gy + 8, lb, 1, C_WHITE, lx + lenW/2);
  }

  kbDraw(KB_TOP_Y);
  flushScreen();
}

void onTapAdd(int16_t tx, int16_t ty) {
  bool back = (ty >= STATUS_H + 2 && ty < STATUS_H + NAV_H - 2
               && tx >= SAFE_PAD && tx < SAFE_PAD + 46);

  // Folder picker sub-mode intercepts taps before the normal field UI.
  if (addPickingFolder) {
    if (addPickingNewFolder) {
      // "+ New Folder" reuses the shared keyboard UI — Back cancels typing
      // and returns to the picker list rather than leaving the whole form.
      if (back) { addPickingNewFolder = false; kbReset(); drawAdd(); return; }
      if (kbHandleTap(tx, ty)) drawAdd();
      return;
    }
    if (back) { addPickingFolder = false; drawAdd(); return; }
    onTapFolderPicker(tx, ty);
    return;
  }

  // Back
  if (back) {
    addInit();
    popNav();
    return;
  }
  // "OK" in nav bar (alternate Done)
  if (ty >= STATUS_H + 2 && ty < STATUS_H + NAV_H - 2
      && tx >= LCD_WIDTH - SAFE_PAD - 40) {
    addNextField();
    return;
  }
  // Keyboard
  // Suggestion tap (above the keyboard) — only non-password fields
  if (addField != 2 && kbHandleSuggestionTap(tx, ty, KB_TOP_Y - 36)) {
    drawAdd();
    return;
  }
  // GENERATE + length-cycle controls (password field only, same slot as
  // the suggestions row on other fields).
  if (addField == 2) {
    int16_t gy = KB_TOP_Y - 36;
    int16_t gx = SAFE_PAD, gw = LCD_WIDTH - 2*SAFE_PAD;
    int16_t lenW = 64;
    int16_t genW = gw - lenW - 8;
    int16_t lx = gx + genW + 8;

    if (ty >= gy && ty < gy + 30) {
      if (tx >= gx && tx < gx + genW) {              // GENERATE
        char generated[PWGEN_MAX_LEN + 1];
        pwgenGenerate(generated, pwgenOpts);
        strncpy(kbBuffer, generated, KB_MAX_LEN);
        kbBuffer[KB_MAX_LEN] = 0;
        kbLen = (uint8_t)strlen(kbBuffer);
        ckSecureZero(generated, sizeof(generated));
        ledSet(0x0000FF, 150);
        drawAdd();
        return;
      }
      if (tx >= lx && tx < lx + lenW) {               // cycle length
        pwgenOpts.length = (pwgenOpts.length == 12) ? 16
                          : (pwgenOpts.length == 16) ? 20
                          : (pwgenOpts.length == 20) ? 24 : 12;
        drawAdd();
        return;
      }
    }
  }
  if (kbHandleTap(tx, ty)) drawAdd();
}
