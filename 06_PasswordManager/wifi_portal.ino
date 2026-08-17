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
//  ── Bitwarden import mode ─────────────────────────────────────────────
//  A SECOND mode of the SAME portal instance/SoftAP session (not a second
//  radio/server — see wifiPortalStartCommon()), reached via Settings ->
//  Import -> Bitwarden (screen_import.ino), gated behind an explicit
//  on-device plaintext-data warning the user must accept BEFORE the AP
//  even comes up. Registers a DELIBERATELY RESTRICTED route set — NOT
//  /save, /list, /edit, /delete, /export — so an import session's web page
//  has no path to browse or export the existing vault (least privilege;
//  see wifiPortalStartImportMode()). The upload itself uses a REAL
//  multipart file upload (ESP32 WebServer's HTTPUpload chunked callback,
//  ~1436 bytes/call) fed directly into the streaming Bitwarden JSON parser
//  (bw_json_parser.h/bw_import.ino) — the raw JSON is never buffered
//  whole, never written to flash; only already-parsed/normalized fields
//  are staged (see bw_import.ino's own header comment for the full
//  security model of that staging file).
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
static bool       portalImportMode = false;   // false = general manager, true = Bitwarden import

// ── Diagnostic WiFi event logging ─────────────────────────────────────
// Registered ONCE (idempotent — see wifiPortalStartCommon()) so a station
// (phone/laptop) actually reaching the radio at all — even if the join
// then fails — is visible on serial. This is what lets "stuck on the WiFi
// wait screen" be distinguished between: (a) the AP never came up, (b) a
// station never even attempts to associate (radio/RF issue), (c) a station
// associates then is kicked (auth/handshake issue), (d) association
// succeeds but the browser/DNS/HTTP layer above never gets exercised.
// Only counts/reason codes are logged — no SSID/password/MAC-adjacent
// secrets beyond what's already inherent to "a station connected".
static bool s_wifiEventHandlerRegistered = false;
static void wifiPortalOnEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_AP_START:
      SK_LOGLN("[WIFI] event: AP_START (radio up, advertising)");
      break;
    case ARDUINO_EVENT_WIFI_AP_STOP:
      SK_LOGLN("[WIFI] event: AP_STOP");
      break;
    case ARDUINO_EVENT_WIFI_AP_PROBEREQRECVED:
      // A nearby device is scanning/asking about us — proves the radio link
      // is physically working even before any join attempt.
      SK_LOGLN("[WIFI] event: AP_PROBEREQRECVED (a device is scanning nearby)");
      break;
    case ARDUINO_EVENT_WIFI_AP_STACONNECTED:
      SK_LOGLN("[WIFI] event: AP_STACONNECTED (a station associated)");
      break;
    case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED:
      // NOTE: this IDF version's wifi_event_ap_stadisconnected_t has no
      // `reason` field (added in a later IDF release) — just the fact of
      // disconnection is still useful: "associated then immediately
      // disconnected" points at an auth/handshake problem even without a
      // numeric reason code.
      SK_LOGLN("[WIFI] event: AP_STADISCONNECTED (a station left/was dropped)");
      break;
    case ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED:
      SK_LOGLN("[WIFI] event: AP_STAIPASSIGNED (station got a DHCP lease)");
      break;
    default:
      break;
  }
}

// Hard cap on how long the portal can stay up in one session REGARDLESS of
// request activity — bounds "device left unattended with the import screen
// open and someone keeps poking it" to a fixed window, on top of the
// idle-no-requests timeout below. Not adjustable at runtime.
#define PORTAL_MAX_SESSION_MS   600000UL   // 10 minutes

// ── Accessors for the Settings screen ────────────────────────────────
// SSID/password/code/IP accessors are mode-agnostic — both the general
// manager (screen_wifi.ino) and the Bitwarden-import "waiting" screen
// (screen_import.ino) read the SAME live session credentials.
bool        wifiPortalActive()   { return portalActive; }
bool        wifiPortalImportModeActive() { return portalActive && portalImportMode; }
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

// ── Bitwarden import routes (import mode only) ───────────────────────
// Serves the SEPARATE minimal upload page (portal_html.h's PORTAL_IMPORT_HTML,
// not the general-manager PORTAL_HTML) — repeats the plaintext-data warning
// at the point of action (choosing/uploading the file), on top of the
// mandatory on-device confirm the user already passed through before the
// AP even came up (screen_import.ino).
static void portalSendImportHtml() {
  portalLastSeen = millis();
  portalSrv.send_P(200, "text/html", PORTAL_IMPORT_HTML);
}

// The CSRF/session code for this multipart upload travels as a QUERY
// STRING param (?code=123456), NOT a form field — WebServer::arg() reads
// query args regardless of body content-type, same mechanism the existing
// GET /list and /export routes already rely on. A multipart BODY's fields
// are not parsed into arg() at all by this WebServer version, only exposed
// via the HTTPUpload struct below.
static bool portalImportCodeOk() {
  return vaultUnlocked && portalImportMode &&
         portalSrv.arg("code") == String(portalCode);
}

// Streaming upload callback — called repeatedly as the multipart body
// arrives, ~1436 bytes per call (HTTP_UPLOAD_BUFLEN). Feeds bytes DIRECTLY
// into the Bitwarden JSON parser (bw_import.ino) with no intermediate
// copy — the raw upload buffer is owned/reused by the WebServer library
// between calls, so there is nothing here for THIS code to separately wipe.
static bool     s_importUploadOk = false;   // set false on any failure; UPLOAD_FILE_WRITE
                                            // keeps draining bytes either way so the
                                            // connection doesn't hang, but stops staging.
static uint32_t s_importChunkCount = 0;     // diagnostic only — reset per upload

// ── Watchdog note — READ THIS BEFORE TOUCHING THE delay(1) BELOW ─────────
// WebServer::_parseForm() (Parsing.cpp, this project's pinned ESP32 core
// 2.0.16) copies the ENTIRE multipart body one byte at a time inside a
// SINGLE synchronous call, calling back into portalImportUploadChunk() only
// once per HTTP_UPLOAD_BUFLEN (1436-byte) chunk. That whole per-request copy
// loop runs inside one call to WebServer::handleClient() (wifiPortalLoop()),
// with no yield anywhere in the library's own loop except a delay(2) that
// only fires when the socket has momentarily no data — i.e. NOT during a
// normal, actively-flowing transfer.
//
// This project's sdkconfig has CONFIG_ESP_TASK_WDT_TIMEOUT_S=5 and
// CONFIG_ESP_TASK_WDT_PANIC=y: the FreeRTOS idle task must run within 5s or
// the Task Watchdog panics (reboots) — and per ESP-IDF's scheduler, only an
// actual delay()/vTaskDelay() call (not taskYIELD()) blocks the current task
// long enough for the idle task to run and feed that watchdog. Confirmed via
// direct source read of Parsing.cpp plus ESP-IDF/arduino-esp32 documentation.
//
// Net effect (this was the confirmed cause of "device reboots when a file is
// uploaded" — not heap/stack corruption, not the JSON parser, which is
// already correctly bounded/streaming): ANY upload whose total transfer time
// exceeds ~5s wall-clock (slow/bursty WiFi, or per-chunk processing cost
// inside bwImportFeed() below) starves the idle task for the WHOLE upload
// and panics. The fix is a delay(1) called HERE, on every WRITE chunk — the
// library invokes this callback every ~1436 bytes, i.e. many times over the
// course of one upload, so a yield placed at this exact point fires
// regularly throughout the transfer. This mirrors the same "yield
// periodically inside a long blocking operation" idiom already used
// elsewhere in this codebase (bwImportCommit() in bw_import.ino,
// screen_migrate.ino) — not a new pattern, and not a blind "add a delay
// somewhere and hope" — it targets the exact call site that was starving
// the watchdog.
static void portalImportUploadChunk() {
  HTTPUpload &upload = portalSrv.upload();
  portalLastSeen = millis();   // bump on EVERY chunk — a slow-but-active upload
                               // must not trip the 3-minute idle timeout mid-transfer

  switch (upload.status) {
    case UPLOAD_FILE_START:
      s_importUploadOk = portalImportCodeOk();
      s_importChunkCount = 0;
      if (!s_importUploadOk) {
        SK_LOGLN("[BWIMPORT] upload rejected: bad code or vault locked");
        return;
      }
      // bwImportBegin() already ran when the portal entered import mode
      // (wifiPortalStartImportMode()) — nothing further to initialize here.
      // Counts/sizes/memory only — never filename/content.
      SK_LOG("[BWIMPORT] upload started  freeHeap=%u minFreeHeap=%u freePsram=%u\n",
             ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram());
      break;

    case UPLOAD_FILE_WRITE:
      if (!s_importUploadOk) { delay(1); return; }   // still yield while draining
      if (!bwImportFeed(upload.buf, upload.currentSize)) {
        s_importUploadOk = false;      // parser errored — stop staging, keep draining
      }
      s_importChunkCount++;
      // Snapshot memory every ~32 chunks (~45 KB) rather than every chunk —
      // enough resolution to see a real leak/exhaustion trend during a large
      // upload without flooding serial on every 1436-byte packet.
      if ((s_importChunkCount % 32) == 0) {
        SK_LOG("[BWIMPORT] chunk %u  freeHeap=%u minFreeHeap=%u freePsram=%u\n",
               s_importChunkCount, ESP.getFreeHeap(), ESP.getMinFreeHeap(), ESP.getFreePsram());
      }
      // THE ACTUAL FIX for the reboot-on-upload bug — see the file comment
      // above this function for the full mechanism. Must run on every
      // chunk, unconditionally, success or parser-error alike (a slow
      // upload that's already failed parsing still needs to keep draining
      // bytes off the socket without starving the watchdog).
      delay(1);
      break;

    case UPLOAD_FILE_END:
      // Finalization happens in portalImportUploadDone() (the `fn` callback,
      // called once after the whole request completes) — nothing to do here.
      SK_LOG("[BWIMPORT] upload received: %u chunks, %u bytes total\n",
             s_importChunkCount, (unsigned)upload.totalSize);
      break;

    case UPLOAD_FILE_ABORTED:
      SK_LOGLN("[BWIMPORT] upload aborted by client");
      bwImportDiscard();
      s_importUploadOk = false;
      break;
  }
}

// GET /import/bitwarden/verify?code=XXX — side-effect-free auth check the
// upload page calls BEFORE ever revealing the file-picker/upload UI. Reuses
// the SAME 6-digit portalCode gate every other route already enforces (no
// new auth mechanism, no session token, no cookie — see this file's header
// comment on the security model). Returns 200 with no body on a correct
// code, 401 otherwise, so the page can gate its own UI state accordingly
// (see PORTAL_IMPORT_HTML in portal_html.h) — the server-side routes below
// (upload/cancel) independently re-check the same code on every request
// regardless of what this endpoint said, so a client can never bypass
// authentication by skipping this call.
static void portalImportVerifyCode() {
  portalLastSeen = millis();
  if (!portalImportCodeOk()) {
    // 401 specifically for "wrong/missing code" — distinct from 403, which
    // is reserved for "the vault is locked out from under an otherwise-
    // valid session" (see below). Lets the page show the right message.
    portalSrv.send(401, "text/plain", "invalid code");
    return;
  }
  portalSrv.send(200, "text/plain", "ok");
}

// Called once after the full multipart request completes (success or the
// client disconnected — WebServer still invokes this). Sends the actual
// HTTP response.
static void portalImportUploadDone() {
  if (!vaultUnlocked || !portalImportMode) {
    // The SESSION itself is no longer valid (vault locked / portal left
    // import mode) — distinct from "code was simply wrong", which a retry
    // can fix; this can't be fixed by re-entering the code.
    portalSrv.send(403, "text/plain", "session no longer valid");
    return;
  }
  if (!portalImportCodeOk()) {
    portalSrv.send(401, "text/plain", "invalid code");
    return;
  }
  if (!s_importUploadOk) {
    portalSrv.send(400, "text/plain", "upload failed");
    return;
  }
  bool ok = bwImportEnd();
  if (!ok) {
    portalSrv.send(400, "text/plain", bwImportErrorMsg());
    return;
  }
  // Success — the device screen (SCR_IMPORT_WAIT, polled ~1 Hz) will notice
  // BwImportCtx reached AWAITING_PREVIEW and auto-advance to the preview
  // screen on its own; this HTTP response just confirms upload success to
  // the browser.
  portalSrv.send(200, "text/plain", "ok");
}

// POST /import/bitwarden/cancel?code=XXX — user cancelled from the phone's
// browser instead of the device (both paths are supported; the on-device
// CANCEL button on SCR_IMPORT_WAIT/SCR_IMPORT_PREVIEW calls bwImportDiscard()
// directly without going through HTTP).
static void portalImportCancel() {
  if (!portalImportCodeOk()) { portalSrv.send(401, "text/plain", "invalid code"); return; }
  bwImportDiscard();
  SK_LOGLN("[BWIMPORT] import cancelled by user (web)");
  portalSrv.send(200, "text/plain", "ok");
}

// ── Public control ───────────────────────────────────────────────────
// Shared setup for BOTH modes: fresh random WPA2 password + 6-digit code,
// the BLE-coexistence restart-bug mitigation, and bringing up the SoftAP +
// DNS. Does NOT register any HTTP routes or call portalSrv.begin() —
// callers (wifiPortalStart()/wifiPortalStartImportMode()) register their
// own mode-specific route set afterward. Returns false (leaving the caller
// to bail out) if the vault isn't unlocked or the AP is already active.
static bool wifiPortalStartCommon() {
  if (portalActive) return false;
  // Fail closed: never start the portal (and never expose vault routes)
  // if the device somehow isn't unlocked. Settings is only reachable
  // post-PIN, so this should be unreachable in normal use — defense in
  // depth against a future navigation bug.
  if (!vaultUnlocked) return false;

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

  // Diagnostic event log — registered once, never removed (harmless no-op
  // logging for the life of the sketch). Lets a failed join be diagnosed
  // from serial: AP never starting, a station never reaching the radio at
  // all (RF/power issue), a station associating then being kicked
  // (auth/handshake issue, logged with its reason code), or association
  // succeeding but nothing above that layer working.
  if (!s_wifiEventHandlerRegistered) {
    WiFi.onEvent(wifiPortalOnEvent);
    s_wifiEventHandlerRegistered = true;
  }

  WiFi.mode(WIFI_AP);
  // channel 1, not hidden, up to 2 clients. This used to be capped at 1 —
  // that starved the join itself on phones (esp. iOS) that open a silent
  // background probe connection for captive-portal detection BEFORE the
  // connection the user actually sees completes. With max_connection=1 that
  // probe could occupy the only slot, so the real join failed or hung even
  // standing right next to the device (not a range/power issue — reported
  // as "can't get past the WiFi wait screen"). The portal's actual security
  // boundary is unchanged: every state-changing route still requires the
  // single per-session 6-digit code, so a second raw association slot does
  // not let a second party do anything.
  bool apOk = WiFi.softAP(portalSsid, portalPass, 1, 0, 2);
  if (!apOk) {
    // Fail LOUDLY instead of marching on with portalActive=true over a
    // radio that never actually came up — this alone could produce exactly
    // "SSID/password/code shown on-device, but nothing ever joins",
    // because the screen doesn't know the softAP() call itself failed.
    SK_LOGLN("[WIFI] softAP() FAILED — AP did not start");
    WiFi.mode(WIFI_OFF);
    if (portalBleWasOn && settings.bleEnabled && hidBleCompiled()) hidBleBegin();
    portalBleWasOn = false;
    return false;
  }
  // TX power: was WIFI_POWER_8_5dBm (~7 mW) — genuinely weak, and on some
  // hardware/enclosures that's marginal even at point-blank range, not just
  // "cutting a current spike". WIFI_POWER_13dBm (~20 mW) keeps meaningful
  // headroom below the old full-power default (WIFI_POWER_19_5dBm, the
  // documented brownout trigger) while giving the radio enough margin to
  // actually complete a WPA2 handshake reliably.
  WiFi.setTxPower(WIFI_POWER_13dBm);
  delay(100);
  SK_LOG("[WIFI] post-start heap: free=%u minfree=%u  apIP=%s  txPower=%d\n",
         ESP.getFreeHeap(), ESP.getMinFreeHeap(),
         WiFi.softAPIP().toString().c_str(), (int)WiFi.getTxPower());
  portalDns.start(53, "*", WiFi.softAPIP());     // all domains → us
  return true;
}

void wifiPortalStart() {
  portalImportMode = false;
  if (!wifiPortalStartCommon()) return;

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

// Bitwarden import mode: SAME portal instance/SoftAP session as above (no
// second radio/server), but a DELIBERATELY RESTRICTED route set — no
// /save, /list, /edit, /delete, /export, so an import session's web page
// has no path to browse or export the existing vault. See
// portalImportUploadChunk()/portalImportUploadDone() below.
void wifiPortalStartImportMode() {
  portalImportMode = true;
  if (!wifiPortalStartCommon()) return;

  bwImportBegin();   // resets BwImportCtx, opens the staging files

  portalSrv.on("/", HTTP_GET, portalSendImportHtml);
  portalSrv.on("/import/bitwarden/verify", HTTP_GET, portalImportVerifyCode);
  portalSrv.on("/import/bitwarden/upload", HTTP_POST,
              portalImportUploadDone, portalImportUploadChunk);
  portalSrv.on("/import/bitwarden/cancel", HTTP_POST, portalImportCancel);
  portalSrv.onNotFound(portalHandleNotFound);
  portalSrv.begin();

  portalActive = true; portalLastSeen = millis(); portalStartedAt = millis();
  SK_LOG("[WIFI] import portal up: SSID=%s IP=%s (password/code shown on-device only)\n",
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

  // If a Bitwarden import was in-flight when the portal was torn down
  // (device locked, idle timeout, nav-away, hard session cap), discard any
  // staged plaintext immediately — the portal must never leave orphaned
  // staging data behind just because it stopped mid-transfer.
  if (portalImportMode && bwImportStage() != BWI_IDLE &&
      bwImportStage() != BWI_DONE) {
    bwImportDiscard();
  }
  portalImportMode = false;

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
