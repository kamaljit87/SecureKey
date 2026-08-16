// =============================================================
//  wifi_portal.ino  —  On-device WiFi captive-portal import/export
//
//  The whole thing lives ON the device — no app, no hosting, no
//  GitHub. The user just joins the device's WiFi and the page pops
//  up (captive portal, like hotel WiFi), fills a form / pastes a
//  CSV, and the device saves it straight into the vault.
//
//  ── Security boundary — treat this as untrusted network surface ──────
//    • The portal can ONLY be started while the vault is UNLOCKED (the
//      Settings menu that starts it is itself behind the PIN screen),
//      and it is explicitly torn down (wifiPortalStop) the moment the
//      user navigates away from the WiFi screen, on auto-lock, and on
//      idle timeout — it can never be left silently running.
//    • Every state-changing/data-revealing route (/save, /list, /edit,
//      /delete, /export) requires the 6-digit on-screen CODE, which is
//      freshly randomized every session and shown ONLY on the device's
//      own display — never over serial, never in a log, never echoed
//      back by the HTTP server.
//    • ALL vault reads/writes here go through the same encrypted-DB API
//      (dbLoadRecord/dbAppend/dbUpdate/dbDelete) as the on-device UI —
//      there is no separate raw-file code path, so nothing here can see
//      or write plaintext that bypasses AES-256-GCM at rest.
//    • The SoftAP is isolated (no internet uplink), single-client, and
//      auto-shuts-down after 3 minutes of no requests.
//    • WPA2 with a fresh RANDOM password each session (shown only on the
//      device screen — see the "never log" note by wifiPortalStart()).
//
//  Built-in libs only (WiFi / WebServer / DNSServer) — no deps.
// =============================================================
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>

static WebServer  portalSrv(80);
static DNSServer  portalDns;
static bool       portalActive   = false;
static bool       portalBleWasOn = false;   // BLE state to restore on stop
static char       portalSsid[20] = "SecureKey-Setup";
static char       portalPass[12] = {0};   // random WPA2 (8 chars)
static char       portalCode[7]  = {0};   // 6-digit on-screen gate
static uint32_t   portalLastSeen = 0;     // for idle auto-off
static uint32_t   portalStartedAt = 0;    // for the hard session cap
static int        portalImported = 0;     // running count (for the screen)
static bool       portalNeedReload = false;

// Hard cap on how long the portal can stay up in one session REGARDLESS of
// request activity — bounds "device left unattended with the import screen
// open and someone keeps poking it" to a fixed window, on top of the
// idle-no-requests timeout below. Not adjustable at runtime.
#define PORTAL_MAX_SESSION_MS   600000UL   // 10 minutes

// ── Accessors for the Settings screen ────────────────────────────────
bool        wifiPortalActive()   { return portalActive; }
const char* wifiPortalSsid()     { return portalSsid; }
const char* wifiPortalPass()     { return portalPass; }
const char* wifiPortalCode()     { return portalCode; }
int         wifiPortalCount()    { return portalImported; }
String      wifiPortalIp()       { return WiFi.softAPIP().toString(); }

// ── Save one parsed entry (Arduino-task context — vault must be unlocked) ──
static bool portalSaveEntry(const char *title, const char *user,
                            const char *pass, const char *url, uint16_t id) {
  if (!vaultUnlocked) return false;
  // Title, username AND password are all mandatory — enforced server-side so
  // neither the form nor a bulk-import line can create half-empty entries.
  if (!title || !title[0]) return false;
  if (!user  || !user[0])  return false;
  if (!pass  || !pass[0])  return false;
  PassRecord rec; memset(&rec, 0, sizeof(rec));
  rec.id = id; rec.deleted = 0;
  strncpy(rec.title,    title, sizeof(rec.title)    - 1);
  strncpy(rec.username, user ? user : "", sizeof(rec.username) - 1);
  strncpy(rec.password, pass ? pass : "", sizeof(rec.password) - 1);
  strncpy(rec.url,      url ? url : "",   sizeof(rec.url)      - 1);
  strncpy(rec.folder,   url ? url : "",   sizeof(rec.folder)   - 1);
  bool ok = dbAppend(rec);
  ckSecureZero(&rec, sizeof(rec));   // imported plaintext wiped once written
  return ok;
}

static uint16_t portalNextId() {
  uint16_t maxId = 0;
  for (uint16_t i = 0; i < passwordCount; i++)
    if (passwordIndex[i].id > maxId) maxId = passwordIndex[i].id;
  return maxId + 1;
}

// ── The page (served from flash) ─────────────────────────────────────
#include "portal_html.h"

// ── HTTP handlers ────────────────────────────────────────────────────
static void portalSendHtml() {
  portalLastSeen = millis();
  portalSrv.send_P(200, "text/html", PORTAL_HTML);
}

static void portalHandleSave() {
  portalLastSeen = millis();
  if (portalSrv.arg("code") != String(portalCode)) {
    portalSrv.send(200, "text/html",
      "<meta name=viewport content='width=device-width'><body style='background:#0b0e13;color:#ff5f6d;"
      "font-family:sans-serif;padding:30px;text-align:center'><h2>Wrong code</h2>"
      "<p style='color:#8a93a4'>Enter the 6-digit code shown on the device.</p>"
      "<a href='/' style='color:#4d9fff'>Back</a></body>");
    return;
  }
  if (!vaultUnlocked) { portalSrv.send(423, "text/plain", "vault locked"); return; }

  uint16_t id = portalNextId();
  int added = 0;
  String bulk = portalSrv.arg("bulk");
  if (bulk.length() > 0) {
    // line-by-line; detect a Chrome CSV header
    int start = 0;
    bool first = true, chromeCsv = false;
    while (start < (int)bulk.length()) {
      int nl = bulk.indexOf('\n', start);
      if (nl < 0) nl = bulk.length();
      String line = bulk.substring(start, nl); line.trim();
      start = nl + 1;
      if (line.length() == 0) { first = false; continue; }
      if (first) {
        String h = line; h.toLowerCase();
        chromeCsv = h.indexOf("password") >= 0 && h.indexOf("url") >= 0 && h.indexOf(",") >= 0;
        first = false;
        if (chromeCsv) continue;   // skip header
      }
      // split into <=4 fields on tab or comma
      char sep = line.indexOf('\t') >= 0 ? '\t' : ',';
      String f[4] = {"", "", "", ""};
      int fi = 0, p = 0;
      while (fi < 4 && p <= (int)line.length()) {
        int s = line.indexOf(sep, p);
        if (s < 0) s = line.length();
        f[fi++] = line.substring(p, s); p = s + 1;
        if (s == (int)line.length()) break;
      }
      const char *title, *user, *pass, *url;
      if (chromeCsv) { title = f[0].c_str(); url = f[1].c_str(); user = f[2].c_str(); pass = f[3].c_str(); }
      else           { title = f[0].c_str(); user = f[1].c_str(); pass = f[2].c_str(); url = f[3].c_str(); }
      if (portalSaveEntry(title, user, pass, url, id)) { id++; added++; }
    }
    // The bulk paste (which may still contain plaintext passwords) lived in
    // an Arduino String on the heap for the duration of this handler — clear
    // it now rather than leaving it to whenever the allocator reuses the
    // buffer.
    for (size_t i = 0; i < bulk.length(); i++) bulk.setCharAt(i, '\0');
  } else {
    String t = portalSrv.arg("title"), u = portalSrv.arg("user"),
           p = portalSrv.arg("pass"),  w = portalSrv.arg("url");
    if (portalSaveEntry(t.c_str(), u.c_str(), p.c_str(), w.c_str(), id)) added++;
    for (size_t i = 0; i < p.length(); i++) p.setCharAt(i, '\0');
  }

  portalImported += added;
  if (added > 0) portalNeedReload = true;   // reload index in the loop

  char body[260];
  snprintf(body, sizeof(body),
    "<meta name=viewport content='width=device-width'><body style='background:#0b0e13;color:#36d67a;"
    "font-family:sans-serif;padding:30px;text-align:center'><h2>Saved %d</h2>"
    "<p style='color:#8a93a4'>Total imported this session: %d</p>"
    "<a href='/' style='color:#4d9fff'>Add more</a></body>", added, portalImported);
  portalSrv.send(200, "text/html", body);
}

// Captive-portal: send every unknown request to our page so the phone's
// "Sign in to network" sheet pops up automatically.
static void portalHandleNotFound() {
  portalLastSeen = millis();
  portalSrv.sendHeader("Location", String("http://") + WiFi.softAPIP().toString(), true);
  portalSrv.send(302, "text/plain", "");
}

// ── Vault management routes (all gated on the 6-digit code AND the vault
//    being unlocked — the portal can only ever be started from an
//    authenticated session, but this is checked again per-request since
//    an idle-timeout auto-lock could fire mid-session). ───────────────
static bool portalCodeOk() {
  return vaultUnlocked && portalSrv.arg("code") == String(portalCode);
}

static String jsonEsc(const char *s) {
  String o;
  for (const char *p = s; *p; p++) {
    char c = *p;
    if (c == '\n' || c == '\r') continue;
    if (c == '"' || c == '\\') o += '\\';
    o += c;
  }
  return o;
}
static String csvField(const char *s) {
  String v(s);
  if (v.indexOf(',') >= 0 || v.indexOf('"') >= 0) {
    v.replace("\"", "\"\"");
    return "\"" + v + "\"";
  }
  return v;
}

// GET /list?code=XXX  →  streamed JSON array of every entry.
// Uses the same decrypt-one-record-at-a-time path as the on-device UI
// (dbLoadRecord) — never a raw read of the encrypted file. Requires the
// code AND an unlocked vault (see portalCodeOk), so the portal cannot
// dump the vault before the user has authenticated on-device.
static void portalHandleList() {
  portalLastSeen = millis();
  if (!portalCodeOk()) { portalSrv.send(403, "application/json", "[]"); return; }
  portalSrv.setContentLength(CONTENT_LENGTH_UNKNOWN);
  portalSrv.send(200, "application/json", "");
  portalSrv.sendContent("[");
  bool first = true;
  for (uint16_t i = 0; i < passwordCount; i++) {
    PassRecord rec;
    if (!dbLoadRecord(passwordIndex[i].id, rec)) continue;
    String item = (first ? "" : ",");
    first = false;
    item += "{\"id\":" + String(rec.id)
          + ",\"title\":\"" + jsonEsc(rec.title)    + "\""
          + ",\"user\":\""  + jsonEsc(rec.username) + "\""
          + ",\"pass\":\""  + jsonEsc(rec.password) + "\""
          + ",\"url\":\""   + jsonEsc(rec.url)      + "\"}";
    portalSrv.sendContent(item);
    ckSecureZero(&rec, sizeof(rec));
  }
  portalSrv.sendContent("]");
  portalSrv.sendContent("");
}

// POST /edit  (code,id,title,user,pass,url) → update one record.
static void portalHandleEdit() {
  portalLastSeen = millis();
  if (!portalCodeOk()) { portalSrv.send(403, "text/plain", "bad code"); return; }
  uint16_t id = (uint16_t)portalSrv.arg("id").toInt();
  PassRecord rec; memset(&rec, 0, sizeof(rec));
  String t = portalSrv.arg("title"), u = portalSrv.arg("user"),
         p = portalSrv.arg("pass"),  w = portalSrv.arg("url");
  strncpy(rec.title,    t.c_str(), sizeof(rec.title)    - 1);
  strncpy(rec.username, u.c_str(), sizeof(rec.username) - 1);
  strncpy(rec.password, p.c_str(), sizeof(rec.password) - 1);
  strncpy(rec.url,      w.c_str(), sizeof(rec.url)      - 1);
  strncpy(rec.folder,   w.c_str(), sizeof(rec.folder)   - 1);
  bool ok = dbUpdate(id, rec);
  ckSecureZero(&rec, sizeof(rec));
  for (size_t i = 0; i < p.length(); i++) p.setCharAt(i, '\0');
  portalNeedReload = true;
  portalSrv.send(200, "text/plain", ok ? "ok" : "notfound");
}

// POST /delete  (code,id) → soft-delete one record.
static void portalHandleDelete() {
  portalLastSeen = millis();
  if (!portalCodeOk()) { portalSrv.send(403, "text/plain", "bad code"); return; }
  uint16_t id = (uint16_t)portalSrv.arg("id").toInt();
  bool ok = dbDelete(id);
  portalNeedReload = true;
  portalSrv.send(200, "text/plain", ok ? "ok" : "notfound");
}

// GET /export?code=XXX → streamed CSV download (title,username,password,url).
// Same authenticated-decrypt-per-record path as /list.
static void portalHandleExport() {
  portalLastSeen = millis();
  if (!portalCodeOk()) { portalSrv.send(403, "text/plain", "bad code"); return; }
  portalSrv.sendHeader("Content-Disposition", "attachment; filename=securekey-vault.csv");
  portalSrv.setContentLength(CONTENT_LENGTH_UNKNOWN);
  portalSrv.send(200, "text/csv", "");
  portalSrv.sendContent("title,username,password,url\n");
  for (uint16_t i = 0; i < passwordCount; i++) {
    PassRecord rec;
    if (!dbLoadRecord(passwordIndex[i].id, rec)) continue;
    String line = csvField(rec.title) + "," + csvField(rec.username) + ","
                + csvField(rec.password) + "," + csvField(rec.url) + "\n";
    portalSrv.sendContent(line);
    ckSecureZero(&rec, sizeof(rec));
  }
  portalSrv.sendContent("");
}

// ── Public control ───────────────────────────────────────────────────
void wifiPortalStart() {
  if (portalActive) return;
  // Fail closed: never start the portal (and never expose vault routes)
  // if the device somehow isn't unlocked. Settings is only reachable
  // post-PIN, so this should be unreachable in normal use — defense in
  // depth against a future navigation bug.
  if (!vaultUnlocked) return;

  // Fresh random WPA2 password + 6-digit code each session. Uses
  // ckRandomBytes() (the same HW-RNG wrapper used for every other secret
  // in this project — crypto_core.cpp) rather than calling esp_random()
  // directly, so there is exactly one RNG code path to audit.
  static const char *AZ = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";  // no confusing chars
  uint8_t rb[8];
  ckRandomBytes(rb, sizeof(rb));
  for (int i = 0; i < 8; i++)  portalPass[i] = AZ[rb[i] % 31];
  portalPass[8] = 0;
  ckRandomBytes(rb, 6);
  for (int i = 0; i < 6; i++)  portalCode[i] = '0' + (rb[i] % 10);
  portalCode[6] = 0;
  ckSecureZero(rb, sizeof(rb));
  portalImported = 0; portalNeedReload = false;

  // ── Restart-bug mitigation ──────────────────────────────────────────
  // The Wi-Fi AP is the highest-current thing this device does. Two things
  // used to make it reset (esp. on a small battery):
  //   1. BLE was left running — WiFi + BLE share ONE 2.4 GHz radio, so the
  //      peak TX current and coexistence arbitration both spiked.
  //   2. The AP came up at full TX power (~19.5 dBm).
  // So: drop BLE first (restored in wifiPortalStop), and cap AP TX power —
  // the phone is inches away for a captive portal, it doesn't need full blast.
  SK_LOG("[WIFI] pre-start heap: free=%u minfree=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap());
  portalBleWasOn = settings.bleEnabled && hidBleCompiled() && hidBleStarted();
  if (portalBleWasOn) {
    SK_LOGLN("[WIFI] stopping BLE before AP (shared radio)");
    hidBleEnd();
    bleAuthorized = false;
    btConnected = false;
    delay(60);
  }

  WiFi.mode(WIFI_AP);
  // channel 1, not hidden, MAX 1 client
  WiFi.softAP(portalSsid, portalPass, 1, 0, 1);
  WiFi.setTxPower(WIFI_POWER_8_5dBm);            // cut the current spike
  delay(100);
  SK_LOG("[WIFI] post-start heap: free=%u minfree=%u\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap());
  portalDns.start(53, "*", WiFi.softAPIP());     // all domains → us

  portalSrv.on("/",       HTTP_GET,  portalSendHtml);
  portalSrv.on("/save",   HTTP_POST, portalHandleSave);
  portalSrv.on("/list",   HTTP_GET,  portalHandleList);
  portalSrv.on("/edit",   HTTP_POST, portalHandleEdit);
  portalSrv.on("/delete", HTTP_POST, portalHandleDelete);
  portalSrv.on("/export", HTTP_GET,  portalHandleExport);
  portalSrv.onNotFound(portalHandleNotFound);
  portalSrv.begin();

  portalActive = true; portalLastSeen = millis(); portalStartedAt = millis();
  // NEVER log the WPA2 password or the 6-digit access code — they are
  // shown ONLY on the device's own display (screen_wifi.ino). Logging
  // them here would defeat the "shown only on-device" security property
  // documented at the top of this file.
  SK_LOG("[WIFI] portal up: SSID=%s IP=%s (password/code shown on-device only)\n",
         portalSsid, WiFi.softAPIP().toString().c_str());
}

void wifiPortalStop() {
  if (!portalActive) return;
  portalSrv.stop();
  portalDns.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  portalActive = false;
  SK_LOGLN("[WIFI] portal stopped");

  // Bring BLE back if we shut it down for the AP.
  if (portalBleWasOn && settings.bleEnabled && hidBleCompiled()) {
    SK_LOGLN("[WIFI] resuming BLE after AP");
    hidBleBegin();
  }
  portalBleWasOn = false;
}

// Call every loop(). Services the portal and auto-stops after idle OR if
// the vault has been locked from under it (auto-lock, idle timeout,
// screen-off) — the portal must never keep running against a locked vault.
void wifiPortalLoop() {
  if (!portalActive) return;

  if (!vaultUnlocked) {
    SK_LOGLN("[WIFI] vault locked — stopping portal");
    wifiPortalStop();
    return;
  }

  portalDns.processNextRequest();
  portalSrv.handleClient();

  if (portalNeedReload) {           // a save happened — refresh the index
    portalNeedReload = false;
    dbLoadIndex();
    SK_LOG("[WIFI] index reloaded (%u total)\n", passwordCount);
  }

  // Auto-off after 3 min of no requests (safety), or after the hard
  // session cap regardless of activity (bounds an unattended-and-poked
  // session to a fixed window — see PORTAL_MAX_SESSION_MS above).
  if (millis() - portalLastSeen > 180000UL) {
    SK_LOGLN("[WIFI] idle timeout — stopping portal");
    wifiPortalStop();
  } else if (millis() - portalStartedAt > PORTAL_MAX_SESSION_MS) {
    SK_LOGLN("[WIFI] session cap reached — stopping portal");
    wifiPortalStop();
  }
}
