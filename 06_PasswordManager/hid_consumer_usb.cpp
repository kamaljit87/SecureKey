// =============================================================
//  hid_consumer_usb.cpp  —  Isolated USB HID Consumer Control wrapper
//
//  Companion to hid_usb.cpp (which owns USBHIDKeyboard). Kept in its own
//  translation unit purely for symmetry/isolation with the rest of the HID
//  code (hid_usb.cpp / hid_ble.cpp) — USBHIDConsumerControl doesn't actually
//  collide with USBHIDKeyboard's macros, but keeping each HID class's begin/
//  press/release calls behind their own tiny extern "C" surface keeps the
//  main .ino free of any USB/TinyUSB headers.
//
//  USBHIDConsumerControl is a SEPARATE composite-HID report (Consumer Page,
//  usage ids like Volume Increment 0x00E9 / Play-Pause 0x00CD / Scan Next
//  0x00B5) from USBHIDKeyboard's boot-keyboard report — both register with
//  the same shared TinyUSB HID interface (USBHID::addDevice), so they can
//  both be active at once with zero interference. This is NOT a keyboard
//  shortcut simulation (no Fn combos) — it's a proper Consumer Control
//  report, which is what OS media-key handling actually listens for.
//
//  Independent of vault lock state by design: media keys must work whether
//  or not the password vault is unlocked, exactly like a normal USB media
//  keyboard would. See media_control.ino for the transport-agnostic
//  mediaVolumeUp()/etc. wrappers that call into this file.
//
//  To disable at compile time, set HID_CONSUMER_USB_ENABLE to 0 below.
// =============================================================
#define HID_CONSUMER_USB_ENABLE 1

#include <Arduino.h>
#include "theme.h"   // SK_LOG/SK_LOGLN (debug-gated logging)

#if HID_CONSUMER_USB_ENABLE
  #include <USB.h>
  #include <USBHIDConsumerControl.h>
  static USBHIDConsumerControl cc;
  static bool started = false;
  extern "C" bool tud_mounted(void);
#endif

// Must match the MEDIA_KEY_* ordering in hid_ble.cpp / media_control.ino.
enum {
  MEDIA_KEY_VOLUME_UP = 0,
  MEDIA_KEY_VOLUME_DOWN,
  MEDIA_KEY_MUTE,
  MEDIA_KEY_PLAY_PAUSE,
  MEDIA_KEY_PREV_TRACK,
  MEDIA_KEY_NEXT_TRACK,
};

extern "C" {

// Safe to call even if hidUsbBegin() (the keyboard) already ran — both
// classes share the same underlying USBHID composite device and each
// registers its own report descriptor once.
void hidConsumerUsbBegin() {
#if HID_CONSUMER_USB_ENABLE
  if (!started) {
    SK_LOGLN("[USB-CC] ConsumerControl.begin()");
    cc.begin();
    started = true;
  }
#endif
}

int hidConsumerUsbReady() {
#if HID_CONSUMER_USB_ENABLE
  if (!started) hidConsumerUsbBegin();
  return tud_mounted() ? 1 : 0;
#else
  return 0;
#endif
}

void hidConsumerUsbMediaKey(int code) {
#if HID_CONSUMER_USB_ENABLE
  if (!started) hidConsumerUsbBegin();
  if (!tud_mounted()) return;

  uint16_t usage;
  switch (code) {
    case MEDIA_KEY_VOLUME_UP:   usage = CONSUMER_CONTROL_VOLUME_INCREMENT; break;
    case MEDIA_KEY_VOLUME_DOWN: usage = CONSUMER_CONTROL_VOLUME_DECREMENT; break;
    case MEDIA_KEY_MUTE:        usage = CONSUMER_CONTROL_MUTE;             break;
    case MEDIA_KEY_PLAY_PAUSE:  usage = CONSUMER_CONTROL_PLAY_PAUSE;       break;
    case MEDIA_KEY_PREV_TRACK:  usage = CONSUMER_CONTROL_SCAN_PREVIOUS;    break;
    case MEDIA_KEY_NEXT_TRACK:  usage = CONSUMER_CONTROL_SCAN_NEXT;        break;
    default: return;
  }
  // Proper HID press/release: send the usage, hold briefly, then send the
  // "no key" (0) report so the host sees a clean key-up (a held-forever
  // report would auto-repeat volume/track-skip on some hosts).
  cc.press(usage);
  delay(20);
  cc.release();
#else
  (void)code;
#endif
}

int hidConsumerUsbCompiled() {
#if HID_CONSUMER_USB_ENABLE
  return 1;
#else
  return 0;
#endif
}

}  // extern "C"
