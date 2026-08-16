// =============================================================
//  hid_ble.cpp  —  Isolated BLE-HID wrapper
//
//  Pairs hid_usb.cpp.  Owns the BleKeyboard library (T-vK's
//  "ESP32 BLE Keyboard", configured here for the NimBLE backend so
//  it coexists with native USB HID on the ESP32-S3).  Lives in its
//  own translation unit so its KEY_xxx macros can't collide with
//  USBHIDKeyboard's.
//
//  Disable here if the library isn't installed:
//      set HID_BLE_ENABLE 0
//
//  ── Media Controller compatibility note ───────────────────────
//  Vault-gated typing (bleAuthorized / typeViaHID in the main .ino) is
//  layered ON TOP of this file's connection/advertising primitives
//  (hidBleBegin/hidBleConnected/kb.isConnected), not mixed into them.
//  hidBleBegin() keeps the BLE radio advertising/connectable regardless
//  of the vault's lock state — only the PASSWORD-typing calls
//  (hidBlePrint/hidBleQuickFill) are gated by bleAuthorized, which is
//  itself only ever set true from the post-unlock Accept gate. A future
//  media-control HID report path (volume/mute/play-pause/track-skip)
//  should call BleKeyboard's consumer-control report primitives directly,
//  the same way this file calls its keyboard-report primitives — it must
//  NOT be routed through typeViaHID()/bleAuthorized, and must NOT require
//  vaultUnlocked. That keeps "media controls work while locked" true by
//  construction rather than by a special-case check sprinkled through the
//  vault-typing path.
// =============================================================
#define HID_BLE_ENABLE 1

#include <Arduino.h>
#include "theme.h"   // SK_LOG/SK_LOGLN (debug-gated logging) — header-only, safe here

#if HID_BLE_ENABLE
  #include <BleKeyboard.h>
  #include <NimBLEDevice.h>
  static BleKeyboard kb("SecureKey", "techiesms", 100);
  static bool everStarted = false;   // kb.begin() may only EVER run once/boot
  static bool active      = false;   // advertising / accepting connections?
  static bool androidFix  = false;   // UK/Android layout: swap @ <-> " keycodes

  // BLE HID timing — the "likkkke" repeat bug, explained:
  //   The library's notify() (sendReport) is FIRE-AND-FORGET — if the radio's
  //   tx buffer is full, the report is silently DROPPED. releaseAll() even
  //   sends TWO reports (keyboard + an unused media report). Type fast and the
  //   buffer overflows; the dropped reports are usually key-UPS, so the host
  //   thinks the key is held and auto-repeats it ("likkkke" — and it gets
  //   worse later in the word as the buffer fills up).
  //   Fix: (a) one keyboard-only release per key via kb.release() (half the
  //   traffic of releaseAll), and (b) a gap big enough that the tx buffer
  //   fully drains before the next key — EVEN if the host rejected our tight
  //   interval request and runs a slow ~50ms interval. At 2 reports/key and a
  //   120ms gap the buffer always shrinks, so it can never overflow (which is
  //   what caused the occasional "ssshhh" bursts). Slower, but no drops.
  static const uint16_t BLE_HOLD_MS  = 40;   // key held before release (spans a
                                             // 30ms interval — our negotiated max)
  static const uint16_t BLE_GAP_MS   = 120;  // gap so the tx buffer drains
  static const uint16_t BLE_SETTLE_MS = 240; // wait before the 1st key (host subscribe)
  static bool everConn = false;              // have we ever been connected this link?

  // Cached connection handle of the current peer, set during hidBleCapturePeer().
  // Lets us disconnect / retune BY HANDLE (thread-safe ble_gap C calls) instead
  // of copying NimBLE's connection vector again — that copy racing the BLE core
  // was the remaining "minor" reset source.
  static uint16_t s_peerHandle      = 0xFFFF;
  static bool     s_peerHandleValid = false;

  // Type one character: press, hold past one connection interval, then a clean
  // key-up. The library's US asciimap is correct; the host applies its own
  // layout. In "Android fix" mode (for UK/Android-layout hosts where Shift+2
  // produces " instead of @) we swap the two affected keys: @ is sent as
  // Shift+' and " as Shift+2, which come out right on those hosts.
  static void bleType(char c) {
    // The library's asciimap only covers 0..127. A byte >= 128 (a UTF-8 /
    // extended char in a password) would fall through to the library's
    // function-key path and emit a stray F-key / modifier — skip it instead.
    if ((uint8_t)c >= 128) return;
    if (androidFix && c == '@') {
      kb.press(KEY_LEFT_SHIFT); kb.press('\'');   // @ on UK/Android
      delay(BLE_HOLD_MS);
      kb.release('\''); kb.release(KEY_LEFT_SHIFT);
    } else if (androidFix && c == '"') {
      kb.press(KEY_LEFT_SHIFT); kb.press('2');     // " on UK/Android
      delay(BLE_HOLD_MS);
      kb.release('2'); kb.release(KEY_LEFT_SHIFT);
    } else {
      kb.press((uint8_t)c);
      delay(BLE_HOLD_MS);
      kb.release((uint8_t)c);   // keyboard-only release (1 notify; clears shift too)
    }
    delay(BLE_GAP_MS);
  }

  // Same press/hold/release discipline for a raw key (Tab, Enter, ...).
  static void bleRawKey(uint8_t k) {
    kb.press(k);
    delay(BLE_HOLD_MS);
    kb.release(k);
    delay(BLE_GAP_MS);
  }
#endif

extern "C" {

// Re-arm the connection settle delay (called by the main loop when it sees a
// peer disconnect, so the next connection waits for a fresh HID subscription).
void hidBleSettleReset() {
#if HID_BLE_ENABLE
  everConn = false;
  s_peerHandleValid = false;   // handle is stale once the peer drops
#endif
}

// Retune / disconnect BY CACHED HANDLE — these avoid getPeerDevices() entirely
// (updateConnParams/disconnect take a conn handle and are ble_hs-locked inside
// NimBLE, so they're safe to call from the loop). Used instead of the
// list-copying variants on the hot paths (per-connection tune, pause-kick).
void hidBleTuneCached() {
#if HID_BLE_ENABLE
  if (!s_peerHandleValid || !kb.isConnected()) return;
  NimBLEServer *srv = NimBLEDevice::getServer();
  // Apple-compliant params (Accessory Design Guidelines): interval 15–30 ms
  // (min 15, max = min + 15), latency 0, supervision timeout 5 s (≤ 6 s).
  // The old 15–22.5 ms / 4 s violated "max ≥ min + 15 ms", so iOS rejected it
  // and the link drifted/dropped. Set ONCE per connection — iOS penalises
  // peripherals that spam update requests.
  if (srv) srv->updateConnParams(s_peerHandle, 12, 24, 0, 500);
#endif
}

void hidBleDisconnectCached() {
#if HID_BLE_ENABLE
  if (!s_peerHandleValid) return;
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (srv) srv->disconnect(s_peerHandle);
  s_peerHandleValid = false;
#endif
}

// Request a tight connection interval. Called ONCE by the main loop when a new
// peer connects — NOT during typing (renegotiating mid-stream drops reports).
// By the time the user accepts and taps a field, the interval has settled, so
// our key-hold reliably spans it and typing is prompt.
void hidBleTune() {
#if HID_BLE_ENABLE
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (!srv) return;
  std::vector<uint16_t> peers = srv->getPeerDevices();
  if (peers.empty()) return;
  // min 15ms, max 22.5ms, latency 0, supervision timeout 4s
  srv->updateConnParams(peers[0], 12, 24, 0, 500);   // Apple-compliant (see hidBleTuneCached)
#endif
}

// Clear all stored BLE bonds. macOS/iOS (and sometimes Windows) refuse to
// reconnect when the device still holds a stale bond from an older security
// setting — wiping bonds lets the host pair fresh. Called when BLE is turned
// OFF in Settings, so "toggle BLE off then on, then re-pair" is the recovery.
void hidBleForget() {
#if HID_BLE_ENABLE
  NimBLEDevice::deleteAllBonds();
  everConn = false;
  SK_LOGLN("[BLE] all bonds cleared — pair fresh on the host");
#endif
}

// Toggle the UK/Android @ <-> " keycode swap (called when the Settings
// "Android @ Fix" toggle changes, and once at boot from loadSettings()).
void hidBleSetAndroidFix(int on) {
#if HID_BLE_ENABLE
  androidFix = on ? true : false;
#else
  (void)on;
#endif
}

// IMPORTANT: this library's BleKeyboard::end() is EMPTY, and calling
// kb.begin() twice duplicates the HID GATT services (breaks pairing).
// So: kb.begin() exactly once per boot; after that, on/off is done with
// the real NimBLE radio calls — stop/start advertising + drop peers.
void hidBleBegin() {
#if HID_BLE_ENABLE
  if (!everStarted) {
    SK_LOGLN("[BLE] kb.begin() (first start)");
    kb.setDelay(5);     // 5 ms between key reports (library internal)
    kb.begin();
    everStarted = true;
    active = true;

    // Leave NimBLE's advertiseOnDisconnect at its default (true): the BLE host
    // task restarts advertising immediately in-context after a disconnect —
    // smooth and reliable. (We briefly disabled this and re-advertised manually
    // from the loop to dodge a suspected race, but the real crash was the
    // getPeerDevices() list-copy, now fixed by caching. Manual re-advertising
    // just added a 500 ms reconnect gap and log spam.) The "requests keep
    // coming" worry is now handled by auto-approve for saved devices + the
    // gate snooze for the rest.
    SK_LOGLN("[BLE] advertising as 'SecureKey'");
  } else if (!active) {
    SK_LOGLN("[BLE] resume advertising");
    NimBLEDevice::getAdvertising()->start();
    active = true;
  }
#endif
}

void hidBleEnd() {
#if HID_BLE_ENABLE
  everConn = false;                  // next connection re-arms the settle wait
  if (!everStarted || !active) { active = false; return; }
  SK_LOGLN("[BLE] stop: drop peers + stop advertising");
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (srv) {
    std::vector<uint16_t> peers = srv->getPeerDevices();
    for (uint16_t id : peers) srv->disconnect(id);
    if (!peers.empty()) delay(400);  // let onDisconnect fire (it restarts adv)
  }
  NimBLEDevice::getAdvertising()->stop();
  active = false;
#endif
}

int hidBleConnected() {
#if HID_BLE_ENABLE
  return everStarted && active && kb.isConnected() ? 1 : 0;
#else
  return 0;
#endif
}

// Re-arm advertising after a disconnect. Because we turned advertiseOnDisconnect
// OFF (see hidBleBegin), NimBLE no longer restarts advertising itself, so the
// main loop calls this — from ONE task only — once a peer has dropped. Idempotent:
// does nothing if already advertising or currently connected.
void hidBleReadvertise() {
#if HID_BLE_ENABLE
  if (!everStarted || !active) return;
  if (kb.isConnected()) return;
  NimBLEAdvertising *adv = NimBLEDevice::getAdvertising();
  if (adv && !adv->isAdvertising()) {
    adv->start();
    SK_LOGLN("[BLE] re-advertising (post-disconnect, we own advertising)");
  }
#endif
}

// NEVER log `s` — it is frequently a password (called directly with the
// decrypted PassRecord.password from screen_detail.ino). Only its length
// and connection-state flags are logged, and only in debug builds.
void hidBlePrint(const char *s) {
#if HID_BLE_ENABLE
  SK_LOG("[BLE] hidBlePrint() len=%d  active=%d  connected=%d\n",
         (int)strlen(s), active, everStarted ? (int)kb.isConnected() : 0);
  if (!active) { SK_LOGLN("[BLE]   not active — begin()"); hidBleBegin(); delay(500); }
  if (!kb.isConnected()) {
    SK_LOGLN("[BLE]   isConnected()=false — aborting print");
    return;
  }
  // Settle: the FIRST type on a fresh link waits for the host to subscribe to
  // our HID report; later types just need a short beat. (No per-type param
  // retune anymore — the params are set correctly once at connect, and iOS
  // dislikes repeated update requests.)
  delay(everConn ? 60 : BLE_SETTLE_MS);
  everConn = true;
  int n = strlen(s);
  SK_LOG("[BLE]   sending %d chars...\n", n);
  kb.releaseAll();                 // make sure nothing is held before we start
  delay(BLE_GAP_MS);
  for (int i = 0; i < n; i++) bleType(s[i]);
  kb.releaseAll();                 // final safety key-up
  SK_LOGLN("[BLE]   done");
#else
  (void)s;
#endif
}

// One-tap login over BLE: username, Tab, password, Enter. NEVER log
// `user`/`pass` — see hidBlePrint() above.
void hidBleQuickFill(const char *user, const char *pass) {
#if HID_BLE_ENABLE
  if (!active || !kb.isConnected()) {
    SK_LOGLN("[BLE] quickFill aborted — not connected");
    return;
  }
  delay(everConn ? 60 : BLE_SETTLE_MS);
  everConn = true;
  kb.releaseAll();
  delay(BLE_GAP_MS);
  for (const char *p = user; *p; p++) bleType(*p);
  bleRawKey(KEY_TAB);
  for (const char *p = pass; *p; p++) bleType(*p);
  bleRawKey(KEY_RETURN);
  kb.releaseAll();
  SK_LOGLN("[BLE]   quickFill done");
#else
  (void)user; (void)pass;
#endif
}

int hidBleCompiled() {
#if HID_BLE_ENABLE
  return 1;
#else
  return 0;
#endif
}

// Identify the connected peer for the on-device Accept/Reject prompt.
// NOTE: a BLE central (phone/PC) does NOT hand its friendly name ("iPhone",
// "Microsoft") to the keyboard it connects to — only its Bluetooth address
// is available — so we surface the MAC address. Writes a short string like
// "AA:BB:CC:DD:EE:FF" into out, or "unknown" if no peer / not compiled.
void hidBlePeerAddr(char *out, int n) {
  if (!out || n <= 0) return;
  out[0] = 0;
#if HID_BLE_ENABLE
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (srv) {
    std::vector<uint16_t> peers = srv->getPeerDevices();
    if (!peers.empty()) {
      std::string a = srv->getPeerIDInfo(peers[0]).getAddress().toString();
      strncpy(out, a.c_str(), n - 1);
      out[n - 1] = 0;
    }
  }
#endif
  if (!out[0]) strncpy(out, "unknown", n - 1), out[n - 1] = 0;
}

// Resolved IDENTITY address of the connected peer (+ its address type).
// Unlike hidBlePeerAddr (the over-the-air address, which on modern phones is
// a rotating private address that changes every ~15 min), the identity
// address is resolved via the bond's IRK and is STABLE — this is what the
// saved-devices whitelist keys on. Writes "unknown" if no peer.
// Returns 1 only when the peer is BONDED (so the identity address is resolved
// and STABLE across the phone's private-address rotation) — that's the value
// safe to store in the whitelist. Returns 0 (and "unknown") before bonding, so
// callers never save a rotating address (which looked like a "new device every
// time"). MUST be called from ONE task only (the main loop) — it touches the
// NimBLE server; calling it per-draw from the UI raced the NimBLE core-0 task
// and reset the device.
int hidBlePeerIdAddr(char *out, int n, int *type) {
  if (type) *type = 0;
  if (!out || n <= 0) return 0;
  out[0] = 0;
  int bonded = 0;
#if HID_BLE_ENABLE
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (srv) {
    std::vector<uint16_t> peers = srv->getPeerDevices();
    if (!peers.empty()) {
      NimBLEConnInfo ci = srv->getPeerIDInfo(peers[0]);
      NimBLEAddress ida = ci.getIdAddress();
      std::string a = ida.toString();
      strncpy(out, a.c_str(), n - 1);
      out[n - 1] = 0;
      if (type) *type = (int)ida.getType();
      bonded = ci.isBonded() ? 1 : 0;
    }
  }
#endif
  if (!out[0]) strncpy(out, "unknown", n - 1), out[n - 1] = 0;
  return bonded;
}

// Capture EVERYTHING about the connected peer in a SINGLE getPeerDevices()
// pass — over-the-air address, resolved identity address, address type, and
// bonded flag. The whole "random reset" bug was the main loop / Devices screen
// calling getPeerDevices() over and over: that copies NimBLE's connection
// vector on core 1 while the BLE task resizes it on core 0 (connect/disconnect)
// → reading freed memory → LoadProhibited PANIC. Callers now hit this ONCE per
// connection and cache the result, so the racy read basically never lines up
// with a connect/disconnect event. Returns 1 if a peer was read.
// MUST be called from the main loop only.
int hidBleCapturePeer(char *ota, int otaN, char *id, int idN,
                      int *type, int *bonded) {
  if (ota && otaN > 0) ota[0] = 0;
  if (id  && idN  > 0) id[0]  = 0;
  if (type)   *type   = 0;
  if (bonded) *bonded = 0;
#if HID_BLE_ENABLE
  if (!everStarted || !active || !kb.isConnected()) return 0;  // safe bool gate
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (!srv) return 0;
  std::vector<uint16_t> peers = srv->getPeerDevices();   // the ONE risky read
  if (peers.empty()) return 0;
  s_peerHandle = peers[0];            // cache the handle for handle-based ops
  s_peerHandleValid = true;
  NimBLEConnInfo ci = srv->getPeerIDInfo(peers[0]);
  NimBLEAddress oa = ci.getAddress();
  NimBLEAddress ia = ci.getIdAddress();
  if (ota && otaN > 0) { strncpy(ota, oa.toString().c_str(), otaN - 1); ota[otaN - 1] = 0; }
  if (id  && idN  > 0) { strncpy(id,  ia.toString().c_str(), idN  - 1); id[idN  - 1] = 0; }
  if (type)   *type   = (int)ia.getType();
  if (bonded) *bonded = ci.isBonded() ? 1 : 0;
  return 1;
#else
  return 0;
#endif
}

// Delete ONE stored bond (by identity address) — used by "Forget" on the
// Devices screen. Replaces the old wipe-everything deleteAllBonds() habit.
void hidBleForgetOne(const char *addr, int type) {
#if HID_BLE_ENABLE
  NimBLEDevice::deleteBond(NimBLEAddress(std::string(addr), (uint8_t)type));
  SK_LOG("[BLE] bond deleted\n");
#else
  (void)addr; (void)type;
#endif
}

// Disconnect only the current peer — advertising keeps running so OTHER
// devices can still connect.  Used by BLOCK so only that one MAC is kicked.
void hidBleDisconnectPeer() {
#if HID_BLE_ENABLE
  if (!everStarted || !active) return;
  NimBLEServer *srv = NimBLEDevice::getServer();
  if (!srv) return;
  std::vector<uint16_t> peers = srv->getPeerDevices();
  for (uint16_t id : peers) srv->disconnect(id);
  if (!peers.empty()) delay(200);
  everConn = false;
  SK_LOGLN("[BLE] peer kicked (advertising continues for other devices)");
#endif
}

// Send a bare Return keystroke — called after typing a field so the host
// advances to the next field or submits the form.
void hidBleReturn() {
#if HID_BLE_ENABLE
  if (!active || !kb.isConnected()) return;
  bleRawKey(KEY_RETURN);
#endif
}

// Is BLE currently active (advertising or connected)?  Lets the main loop
// manage the radio live (toggle on/off, 5-min block window) without rebooting.
int hidBleStarted() {
#if HID_BLE_ENABLE
  return active ? 1 : 0;
#else
  return 0;
#endif
}

}  // extern "C"
