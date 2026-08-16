// =============================================================
//  media_control.ino  —  Transport-agnostic Consumer Control (media key)
//  abstraction: mediaVolumeUp() / mediaVolumeDown() / mediaMute() /
//  mediaPlayPause() / mediaPrevious() / mediaNext()
//
//  Mirrors the existing typeViaHID()/quickFillViaHID() pattern (same "pick
//  BLE if connected+enabled, else USB, else nothing" transport choice) but
//  is DELIBERATELY independent of bleAuthorized/vaultUnlocked: a media
//  remote (this device, in Media mode) works whether or not the password
//  vault is unlocked — exactly like pressing the volume keys on any
//  standalone Bluetooth/USB media remote. See hid_ble.cpp's and
//  hid_usb.cpp's file-header notes, written specifically to flag this
//  design constraint before this file existed.
//
//  Sends REAL HID Consumer Control usages (Volume Increment 0x00E9, Mute
//  0x00E2, Play/Pause 0x00CD, Scan Next/Previous 0x00B5/0x00B6, ...) — never
//  keyboard-shortcut simulation (no Fn combos, no F7/F8/F9 substitution).
//
//  ── Local volume state — READ THIS BEFORE TRUSTING THE PERCENTAGE ──
//  USB/BLE Consumer Control is a ONE-WAY, edit-only protocol: the host OS
//  applies "increment/decrement/mute" to whatever its current volume is,
//  but never reports that value back to an external HID device — there is
//  no "get system volume" usage in the Consumer Control page, and neither
//  BleKeyboard nor USBHIDConsumerControl exposes an inbound-report/feature
//  path SecureKey could use to ask. So `mediaVolumeLocal` below is a LOCAL
//  ESTIMATE only: it starts at 50%, moves by MEDIA_VOL_STEP per tap, and
//  clamps to [0,100] — it can and will drift out of sync with the host's
//  actual volume (host-side app volume, a hardware volume knob, another
//  input device, an OS volume limit, etc. are all invisible to us). The UI
//  must present it as "your estimate", not "the real volume" — see
//  screen_media.ino's subtitle text. If a future transport/library exposes
//  real host-volume feedback, that should replace this estimate; nothing
//  else in this file's public API would need to change.
// =============================================================

// ── Consumer-key codes — MUST match the MEDIA_KEY_* enum in hid_ble.cpp and
// hid_consumer_usb.cpp exactly (kept as parallel local enums there rather
// than a shared header, since both are tiny extern "C" leaf files that
// otherwise pull in zero project headers beyond theme.h).
enum {
  MK_VOLUME_UP = 0,
  MK_VOLUME_DOWN,
  MK_MUTE,
  MK_PLAY_PAUSE,
  MK_PREV_TRACK,
  MK_NEXT_TRACK,
};

#define MEDIA_VOL_STEP   5      // % moved per Volume +/- tap (local estimate only)
#define MEDIA_VOL_INIT   50     // reasonable starting guess — see file header

// ── Local UI state (estimate only — see file header) ───────────────────
int8_t  mediaVolumeLocal = MEDIA_VOL_INIT;   // 0..100
bool    mediaMuted       = false;
bool    mediaPlaying     = false;   // best-effort local toggle — see mediaPlayPause()

// True if EITHER transport is currently able to carry a media key. Lets the
// UI show a "not connected" hint without needing to know which transport.
bool mediaTransportReady() {
  if (settings.bleEnabled && hidBleCompiled() && hidBleMediaReady()) return true;
  if (settings.usbHidEnabled && hidConsumerUsbCompiled() && hidConsumerUsbReady()) return true;
  return false;
}

// One place that actually dispatches a Consumer Control usage over
// whichever transport is live. Same "BLE first, then USB" precedence as
// typeViaHID() for consistency, but with NO bleAuthorized/vaultUnlocked
// gate — see file header.
static void mediaSend(int code) {
  if (settings.bleEnabled && hidBleCompiled() && hidBleMediaReady()) {
    hidBleMediaKey(code);
    ledSet(0x0000FF, 120);
    return;
  }
  if (settings.usbHidEnabled && hidConsumerUsbCompiled() && hidConsumerUsbReady()) {
    hidConsumerUsbMediaKey(code);
    ledSet(0x00FF00, 120);
    return;
  }
  // No transport ready — silently a no-op (screen_media.ino shows a
  // persistent "not connected" hint instead of an interrupting modal, since
  // media controls are meant to be tapped quickly/repeatedly).
}

static int8_t clampVol(int v) {
  if (v < 0)   return 0;
  if (v > 100) return 100;
  return (int8_t)v;
}

void mediaVolumeUp() {
  mediaVolumeLocal = clampVol(mediaVolumeLocal + MEDIA_VOL_STEP);
  if (mediaVolumeLocal > 0) mediaMuted = false;   // raising volume implies unmuted
  mediaSend(MK_VOLUME_UP);
}

void mediaVolumeDown() {
  mediaVolumeLocal = clampVol(mediaVolumeLocal - MEDIA_VOL_STEP);
  mediaSend(MK_VOLUME_DOWN);
}

void mediaMute() {
  mediaMuted = !mediaMuted;
  mediaSend(MK_MUTE);
}

void mediaPlayPause() {
  // Best-effort local toggle for the icon only — we have no way to know the
  // host's actual playback state (same one-way-protocol limitation as
  // volume). Good enough for "does the icon look right most of the time";
  // never treat this as ground truth.
  mediaPlaying = !mediaPlaying;
  mediaSend(MK_PLAY_PAUSE);
}

void mediaPrevious() {
  mediaSend(MK_PREV_TRACK);
}

void mediaNext() {
  mediaSend(MK_NEXT_TRACK);
}
