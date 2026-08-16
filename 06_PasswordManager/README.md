# SecureKey — firmware

This folder is the **SecureKey** password‑manager firmware (Arduino sketch).
Open `06_PasswordManager.ino` in the Arduino IDE and Upload.

👉 Full documentation, build settings, and feature explanations are in the
[**project README**](../README.md) and [**docs/ARCHITECTURE.md**](../docs/ARCHITECTURE.md).

## TL;DR build settings

```
Board:            ESP32S3 Dev Module
PSRAM:            OPI PSRAM
Partition:        16M Flash (3MB APP/9.9MB FATFS)
USB CDC On Boot:  Enabled
USB Mode:         USB-OTG (TinyUSB)
```

Requires: esp32 core **2.0.16**, NimBLE‑Arduino **1.4.3**, GFX Library for Arduino **1.3.7**,
Adafruit NeoPixel, and the patched ESP32 BLE Keyboard (see the project README).

There is no default PIN. First boot walks you through choosing your own PIN
(4/6/8 digits, 6+ recommended) — it's never stored anywhere, only used to
derive the key that unlocks your vault. See
[docs/SECURITY.md](../docs/SECURITY.md) for the full design.
