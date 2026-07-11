// =============================================================
//  screen_devices.ino  —  Saved BLE devices manager (whitelist)
//
//  Settings → Devices. Lists every device the user has ACCEPTED
//  (saved by stable identity address in NVS). Tap a device for:
//     • RENAME      — give it a friendly alias (on-screen keyboard)
//     • DISCONNECT  — kick it now (it can reconnect: still saved)
//     • FORGET      — delete alias + NVS entry + the BLE bond
//
//  NOTE: there is deliberately no "Connect" button — SecureKey is
//  a BLE *peripheral* (a keyboard): the PHONE initiates the
//  connection. A saved device connects itself and is auto-approved
//  by the main loop; this screen manages that trust, it can't dial.
// =============================================================

// View state: -1 = list, >=0 = card for savedDevs[devSel]
static int8_t devSel        = -1;
static bool   devRenameMode = false;

// Card button layout (mirrors bleConnectGate's button stack)
#define DEV_BTN_X   SAFE_PAD
#define DEV_BTN_W   (LCD_WIDTH - 2*SAFE_PAD)
#define DEV_BTN_H   54
#define DEV_BTN_Y1  (STATUS_H + NAV_H + 118)              // Rename
#define DEV_BTN_Y2  (DEV_BTN_Y1 + DEV_BTN_H + 12)         // Disconnect
#define DEV_BTN_Y3  (DEV_BTN_Y2 + DEV_BTN_H + 12)         // Forget

// List row geometry — compact so all MAX_BLE_DEVICES (8) fit, no scroll.
#define DEV_ROW_Y0  (STATUS_H + NAV_H + 8)
#define DEV_ROW_H   38
#define DEV_ROW_GAP 4

void devicesInit() {
  devSel = -1;
  devRenameMode = false;
}

// Is savedDevs[i] the peer that's connected right now?
// Reads the CACHED peer identity (connPeerId, refreshed once per BLE tick in
// the main loop) — never calls NimBLE here. drawDevList() runs this per device
// on every redraw; querying NimBLE from the draw path raced the NimBLE core-0
// task and reset the device (the "restarts in the Devices section" crash).
static bool devIsConnected(uint8_t i) {
  extern char connPeerId[18];
  if (i >= savedDevCount) return false;
  if (!connPeerId[0]) return false;
  return strcasecmp(savedDevs[i].addr, connPeerId) == 0;
}

static void drawDevList() {
  drawNavBar("Devices", true, nullptr);

  if (savedDevCount == 0) {
    textCenter(STATUS_H + NAV_H + 90,  "No saved devices", 2, C_GRAY_4);
    textCenter(STATUS_H + NAV_H + 130, "Accept a Bluetooth request", 1, C_GRAY_3);
    textCenter(STATUS_H + NAV_H + 148, "once and it is remembered —", 1, C_GRAY_3);
    textCenter(STATUS_H + NAV_H + 166, "no prompt on reconnect.", 1, C_GRAY_3);
    return;
  }

  for (uint8_t i = 0; i < savedDevCount; i++) {
    int16_t y = DEV_ROW_Y0 + i * (DEV_ROW_H + DEV_ROW_GAP);
    bool conn = devIsConnected(i);
    gfx->fillRoundRect(SAFE_PAD, y, DEV_BTN_W, DEV_ROW_H, 8, C_GRAY_1);
    gfx->drawRoundRect(SAFE_PAD, y, DEV_BTN_W, DEV_ROW_H, 8,
                       conn ? C_BLUE : C_GRAY_2);
    textClipped(SAFE_PAD + 14, y + (DEV_ROW_H - 14) / 2,
                savedDevs[i].name, 2, C_WHITE, DEV_BTN_W - 100);
    if (conn) {
      gfx->setTextSize(1); gfx->setTextColor(C_BLUE);
      gfx->setCursor(SAFE_PAD + DEV_BTN_W - 62, y + (DEV_ROW_H - 8) / 2);
      gfx->print("LINKED");
    }
  }
  textCenter(LCD_HEIGHT - 28, "tap a device to manage it", 1, C_GRAY_3);
}

static void drawDevCard() {
  drawNavBar("Device", true, nullptr);
  SavedDevice &d = savedDevs[devSel];
  bool conn = devIsConnected(devSel);

  int16_t y = STATUS_H + NAV_H + 14;
  textCenter(y, d.name, 3, C_WHITE);                         y += 36;
  textCenter(y, d.addr, 1, C_GRAY_4);                        y += 22;
  textCenter(y, conn ? "CONNECTED" : (bleUserPaused ? "PAUSED" : "not connected"),
             2, conn ? C_BLUE : C_GRAY_3);

  gfx->fillRoundRect(DEV_BTN_X, DEV_BTN_Y1, DEV_BTN_W, DEV_BTN_H, 12, C_WHITE);
  textCenter(DEV_BTN_Y1 + DEV_BTN_H/2 - 8, "RENAME", 2, C_BLACK);

  // Middle button: DISCONNECT while linked (pauses the radio so the phone
  // can't bounce straight back), CONNECT otherwise (resume advertising; a
  // bonded phone reconnects on its own — a keyboard can't dial out).
  gfx->fillRoundRect(DEV_BTN_X, DEV_BTN_Y2, DEV_BTN_W, DEV_BTN_H, 12, C_GRAY_1);
  gfx->drawRoundRect(DEV_BTN_X, DEV_BTN_Y2, DEV_BTN_W, DEV_BTN_H, 12, C_BLUE);
  textCenter(DEV_BTN_Y2 + DEV_BTN_H/2 - 8, conn ? "DISCONNECT" : "CONNECT",
             2, C_WHITE);

  gfx->fillRoundRect(DEV_BTN_X, DEV_BTN_Y3, DEV_BTN_W, DEV_BTN_H, 12, C_GRAY_1);
  gfx->drawRoundRect(DEV_BTN_X, DEV_BTN_Y3, DEV_BTN_W, DEV_BTN_H, 12, C_RED);
  textCenter(DEV_BTN_Y3 + DEV_BTN_H/2 - 8, "FORGET", 2, C_RED);
}

static void drawDevRename() {
  drawNavBar("Rename", true, nullptr);

  // Text field showing the alias being typed
  int16_t fy = STATUS_H + NAV_H + 14;
  gfx->fillRoundRect(SAFE_PAD, fy, DEV_BTN_W, 44, 10, C_GRAY_1);
  gfx->drawRoundRect(SAFE_PAD, fy, DEV_BTN_W, 44, 10, C_BLUE);
  textClipped(SAFE_PAD + 12, fy + 15, kbBuffer, 2, C_WHITE, DEV_BTN_W - 24);

  kbDraw(KB_TOP_Y);
}

void drawDevices() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();
  if (devRenameMode)      drawDevRename();
  else if (devSel >= 0)   drawDevCard();
  else                    drawDevList();
  flushScreen();
}

// Keyboard OK on the rename field (routed via onKeyboardSubmit).
void devicesRenameSubmit() {
  if (devSel >= 0 && devSel < (int8_t)savedDevCount && kbLen > 0) {
    strncpy(savedDevs[devSel].name, kbBuffer,
            sizeof(savedDevs[devSel].name) - 1);
    savedDevs[devSel].name[sizeof(savedDevs[devSel].name) - 1] = 0;
    devsSave();
  }
  devRenameMode = false;
  drawDevices();
}

void onTapDevices(int16_t tx, int16_t ty) {
  // Back arrow: rename → card → list → Settings
  bool back = (ty >= STATUS_H + 2 && ty < STATUS_H + NAV_H - 2
               && tx >= SAFE_PAD && tx < SAFE_PAD + 46);

  if (devRenameMode) {
    if (back) { devRenameMode = false; drawDevices(); return; }
    if (kbHandleTap(tx, ty)) drawDevices();
    return;
  }

  if (devSel >= 0) {
    if (back) { devSel = -1; drawDevices(); return; }
    if (devSel >= (int8_t)savedDevCount) { devSel = -1; drawDevices(); return; }

    if (ty >= DEV_BTN_Y1 && ty < DEV_BTN_Y1 + DEV_BTN_H) {        // RENAME
      kbReset();
      strncpy(kbBuffer, savedDevs[devSel].name, KB_MAX_LEN);
      kbBuffer[KB_MAX_LEN] = 0;
      kbLen = strlen(kbBuffer);
      devRenameMode = true;
      drawDevices();
      return;
    }
    if (ty >= DEV_BTN_Y2 && ty < DEV_BTN_Y2 + DEV_BTN_H) {  // CONNECT / DISCONNECT
      if (devIsConnected(devSel)) {
        // DISCONNECT = pause the RADIO: drop the link AND stop advertising.
        // (The old approach — keep advertising but kick the phone each time
        // it auto-reconnected — made iOS flap: "connected" in its settings,
        // typed nothing, dropped, retried... until the user had to Forget.)
        bleUserPaused = true;
        bleAuthorized = false;
        hidBleEnd();                          // kick + stop advertising
        connPeerId[0] = 0; connPeerOta[0] = 0;      // cache is stale now
        connPeerBonded = false; connPeerCaptured = false;
        ledSet(0xFF0000, 200);
      } else {
        // CONNECT: resume advertising — the bonded phone reconnects on its
        // own within a few seconds and is auto-approved.
        bleUserPaused = false;
        if (settings.bleEnabled) hidBleBegin();
        ledSet(0x00FF00, 200);
      }
      drawDevices();
      return;
    }
    if (ty >= DEV_BTN_Y3 && ty < DEV_BTN_Y3 + DEV_BTN_H) {        // FORGET
      // Kick FIRST, then delete the bond — deleting a live peer's keys under
      // an encrypted link confuses hosts. And remind the user: the PHONE still
      // holds its copy of the bond; until "SecureKey" is forgotten there too,
      // its reconnects fail half-way (shows connected, types nothing).
      if (devIsConnected(devSel)) {
        hidBleDisconnectCached();
        bleAuthorized = false;
        delay(250);                       // let the link actually drop
      }
      devsRemove((uint8_t)devSel);        // NVS entry + our stored bond
      gfx->fillScreen(C_BLACK);
      drawStatusBar();
      textCenter(LCD_HEIGHT/2 - 44, "FORGOTTEN", 3, C_WHITE);
      textCenter(LCD_HEIGHT/2 + 2,  "Also forget 'SecureKey' in", 1, C_GRAY_5);
      textCenter(LCD_HEIGHT/2 + 20, "the phone's Bluetooth list,", 1, C_GRAY_5);
      textCenter(LCD_HEIGHT/2 + 38, "then pair fresh.", 1, C_GRAY_5);
      flushScreen();
      delay(2400);
      devSel = -1;
      drawDevices();
      return;
    }
    return;
  }

  if (back) { popNav(); return; }

  // List: tap a row → open its card
  for (uint8_t i = 0; i < savedDevCount; i++) {
    int16_t y = DEV_ROW_Y0 + i * (DEV_ROW_H + DEV_ROW_GAP);
    if (ty >= y && ty < y + DEV_ROW_H) { devSel = (int8_t)i; drawDevices(); return; }
  }
}
