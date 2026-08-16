// =============================================================
//  screen_media.ino  —  Media / Volume Controller screen
//
//  The device's default "resting" screen once a vault exists (see setup()'s
//  boot routing and popToLock()/screenSleep() in 06_PasswordManager.ino).
//  The vault stays LOCKED the entire time this screen is shown — nothing
//  here reads/decrypts/displays any password data. Tapping "Passwords"
//  hands off to the existing, unmodified PIN-unlock flow (pushNav(SCR_PIN)).
//
//  All button actions call the transport-agnostic mediaVolumeUp()/
//  mediaVolumeDown()/mediaMute()/mediaPlayPause()/mediaPrevious()/
//  mediaNext() wrappers in media_control.ino — this file owns ONLY layout,
//  touch hit-testing and the pressed-state visual feedback, no HID/transport
//  logic of its own (single source of truth, no duplicated dispatch).
// =============================================================

// ── Layout ───────────────────────────────────────────────────
// Big circular volume dial up top, mute/±, then a transport row
// (prev/play-pause/next), then the Passwords entry button at the bottom.
// Every constant below was solved bottom-up against the actual 368x448
// panel (LCD_WIDTH/LCD_HEIGHT, pin_config.h) so nothing clips or overlaps —
// see the block comment at the end of this section for the arithmetic.
#define MC_HEADER_BOTTOM (STATUS_H + 42 + 12)   // below the "Media" subtitle line
#define MC_DIAL_R        44
#define MC_DIAL_CY       (MC_HEADER_BOTTOM + MC_DIAL_R + 14)
#define MC_SLIDER_Y       (MC_DIAL_CY + MC_DIAL_R + 14 + 12)
#define MC_SLIDER_H       8
#define MC_VOLBTN_Y       (MC_SLIDER_Y + MC_SLIDER_H + 14)
#define MC_VOLBTN_H       46
#define MC_TRANSPORT_Y    (MC_VOLBTN_Y + MC_VOLBTN_H + 14)
#define MC_TRANSPORT_H    58
#define MC_PW_BTN_H       50
#define MC_PW_BTN_Y       (LCD_HEIGHT - SAFE_PAD - MC_PW_BTN_H)
// On the 368x448 panel this yields (header 98) -> dial cy 156 (halo top 98,
// ring bottom 214) -> slider y 226 -> vol buttons y 248 (bottom 294) ->
// transport y 308 (bottom 366) -> passwords button y 382 (bottom 432),
// leaving a clean 16px gap before the button and 16px before SAFE_PAD at
// the very bottom. Verified with a standalone arithmetic check against
// these exact constants before being written into this file.

// Pressed-state feedback: which control is currently held down (cleared on
// release/redraw). -1 = none. Kept as small ints, not a struct, to match
// the rest of the codebase's style (see homeDragSlot etc. in screen_home.ino).
static int8_t mcPressed = -1;   // 0=voldown 1=volup 2=mute 3=prev 4=playpause 5=next
#define MC_PRESS_NONE   -1
#define MC_PRESS_VOLDN   0
#define MC_PRESS_VOLUP   1
#define MC_PRESS_MUTE    2
#define MC_PRESS_PREV    3
#define MC_PRESS_PLAY    4
#define MC_PRESS_NEXT    5

// ── Volume dial (arc gauge + big percentage) ────────────────────────────
// Drawn as a ring of short radial tick-segments (cheap, no trig-heavy
// anti-aliased arc needed) lit up to the current volume fraction — reads
// like a premium hardware volume knob rather than a plain progress bar.
static void drawVolumeDial() {
  int16_t cx = LCD_WIDTH / 2;
  int16_t cy = MC_DIAL_CY;

  // Soft halo behind the dial, same "breathing glow on black AMOLED" trick
  // used on the lock screen (glowCircle in gfx_lib.ino) — but STATIC here
  // (no per-frame phase) since the media screen intentionally avoids
  // continuous animation to keep CPU/flicker low (see file header).
  uint16_t haloCol = mediaMuted ? C_GRAY_3 : C_BLUE;
  glowCircle(cx, cy, MC_DIAL_R + 26, MC_DIAL_R - 6, lerp565(C_BLACK, haloCol, 70));

  gfx->fillCircle(cx, cy, MC_DIAL_R, C_GRAY_1);

  // Tick ring: 44 segments around the dial, lit proportionally to volume.
  // Starts at the top (12 o'clock) and goes clockwise, gap at the bottom
  // (270°..~290°) so it reads as an open gauge, not a closed circle.
  const int TICKS = 40;
  const float startDeg = -125.0f, sweepDeg = 250.0f;   // open at the bottom
  int litTicks = mediaMuted ? 0 : (int)((int32_t)mediaVolumeLocal * TICKS / 100);
  for (int i = 0; i < TICKS; i++) {
    float a = (startDeg + sweepDeg * i / (TICKS - 1)) * 0.017453f;  // deg→rad
    int16_t x0 = cx + (int16_t)(cosf(a) * (MC_DIAL_R + 6));
    int16_t y0 = cy + (int16_t)(sinf(a) * (MC_DIAL_R + 6));
    int16_t x1 = cx + (int16_t)(cosf(a) * (MC_DIAL_R + 14));
    int16_t y1 = cy + (int16_t)(sinf(a) * (MC_DIAL_R + 14));
    uint16_t col = (i < litTicks) ? C_BLUE : C_GRAY_2;
    gfx->drawLine(x0, y0, x1, y1, col);
  }

  // Speaker glyph + big percentage, centered in the dial.
  int16_t gx = cx - 38, gy = cy - 8;
  if (mediaMuted) {
    // Muted glyph: speaker body + an "X" instead of sound arcs.
    gfx->fillTriangle(gx, gy - 10, gx, gy + 10, gx + 12, gy, C_GRAY_4);
    gfx->fillRect(gx - 10, gy - 6, 10, 12, C_GRAY_4);
    gfx->drawLine(gx + 18, gy - 9, gx + 32, gy + 9, C_RED);
    gfx->drawLine(gx + 18, gy + 9, gx + 32, gy - 9, C_RED);
    gfx->drawLine(gx + 19, gy - 9, gx + 33, gy + 9, C_RED);
    gfx->drawLine(gx + 19, gy + 9, gx + 33, gy - 9, C_RED);
  } else {
    gfx->fillTriangle(gx, gy - 10, gx, gy + 10, gx + 12, gy, C_WHITE);
    gfx->fillRect(gx - 10, gy - 6, 10, 12, C_WHITE);
    // Sound arcs, count scales with volume (0–3 arcs)
    int arcs = mediaVolumeLocal >= 66 ? 3 : mediaVolumeLocal >= 33 ? 2 : mediaVolumeLocal > 0 ? 1 : 0;
    for (int i = 0; i < arcs; i++) {
      int16_t r = 7 + i * 6;
      // quarter-arc via drawCircle + mask trick would be overkill; use
      // three short diagonal strokes to suggest sound waves instead.
      gfx->drawLine(gx + 16, gy - r, gx + 16 + r/2, gy - r/2, C_WHITE);
      gfx->drawLine(gx + 16, gy + r, gx + 16 + r/2, gy + r/2, C_WHITE);
    }
  }

  char pct[8];
  snprintf(pct, sizeof(pct), "%u%%", mediaMuted ? 0 : (unsigned)mediaVolumeLocal);
  textCenter(cy + 34, pct, 3, C_WHITE, cx);
}

// ── Volume slider (thin bar under the dial, matches Settings' style) ────
static void drawVolumeSlider() {
  int16_t x = SAFE_PAD + 20, w = LCD_WIDTH - 2 * (SAFE_PAD + 20);
  int16_t y = MC_SLIDER_Y;
  gfx->fillRoundRect(x, y, w, MC_SLIDER_H, MC_SLIDER_H/2, C_GRAY_1);
  gfx->drawRoundRect(x, y, w, MC_SLIDER_H, MC_SLIDER_H/2, C_GRAY_3);
  int16_t fillW = mediaMuted ? 0 : (int16_t)((int32_t)mediaVolumeLocal * w / 100);
  if (fillW > 0) gfx->fillRoundRect(x, y, fillW, MC_SLIDER_H, MC_SLIDER_H/2, C_BLUE);
  // Knob
  int16_t kx = x + fillW;
  gfx->fillCircle(kx, y + MC_SLIDER_H/2, 9, C_WHITE);
  gfx->drawCircle(kx, y + MC_SLIDER_H/2, 9, C_BLUE);
}

// ── Buttons ──────────────────────────────────────────────────
// McRect itself lives in shared_types.h — see that file's comment for why
// (Arduino's auto-prototype hoisting needs the struct visible from a header,
// not from this .ino, since these helpers return it by value).

static McRect mcVolDownRect() {
  int16_t w = 88, h = MC_VOLBTN_H;
  return McRect{ SAFE_PAD, MC_VOLBTN_Y, w, h };
}
static McRect mcMuteRect() {
  int16_t w = LCD_WIDTH - 2*SAFE_PAD - 2*88 - 2*12, h = MC_VOLBTN_H;
  return McRect{ SAFE_PAD + 88 + 12, MC_VOLBTN_Y, w, h };
}
static McRect mcVolUpRect() {
  int16_t w = 88, h = MC_VOLBTN_H;
  return McRect{ LCD_WIDTH - SAFE_PAD - w, MC_VOLBTN_Y, w, h };
}

static void drawVolButtons() {
  McRect dn = mcVolDownRect(), mu = mcMuteRect(), up = mcVolUpRect();

  // Volume down (−)
  uint16_t dnBg = (mcPressed == MC_PRESS_VOLDN) ? C_GRAY_3 : C_GRAY_1;
  gfx->fillRoundRect(dn.x, dn.y, dn.w, dn.h, 14, dnBg);
  gfx->drawRoundRect(dn.x, dn.y, dn.w, dn.h, 14, C_GRAY_3);
  gfx->fillRoundRect(dn.x + dn.w/2 - 12, dn.y + dn.h/2 - 2, 24, 4, 2, C_WHITE);

  // Mute — clearly different visual state when active (filled red-tinted
  // pill instead of the neutral dark pill).
  uint16_t muBg = mediaMuted ? C_RED : ((mcPressed == MC_PRESS_MUTE) ? C_GRAY_3 : C_GRAY_1);
  uint16_t muFg = mediaMuted ? C_WHITE : C_WHITE;
  gfx->fillRoundRect(mu.x, mu.y, mu.w, mu.h, 14, muBg);
  if (!mediaMuted) gfx->drawRoundRect(mu.x, mu.y, mu.w, mu.h, 14, C_GRAY_3);
  textCenter(mu.y + mu.h/2 - 8, mediaMuted ? "MUTED" : "MUTE", 2, muFg, mu.x + mu.w/2);

  // Volume up (+)
  uint16_t upBg = (mcPressed == MC_PRESS_VOLUP) ? C_GRAY_3 : C_GRAY_1;
  gfx->fillRoundRect(up.x, up.y, up.w, up.h, 14, upBg);
  gfx->drawRoundRect(up.x, up.y, up.w, up.h, 14, C_GRAY_3);
  gfx->fillRoundRect(up.x + up.w/2 - 12, up.y + up.h/2 - 2, 24, 4, 2, C_WHITE);
  gfx->fillRoundRect(up.x + up.w/2 - 2, up.y + up.h/2 - 12, 4, 24, 2, C_WHITE);
}

static McRect mcPrevRect() {
  int16_t w = (LCD_WIDTH - 2*SAFE_PAD - 2*16) / 3, h = MC_TRANSPORT_H;
  return McRect{ SAFE_PAD, MC_TRANSPORT_Y, w, h };
}
static McRect mcPlayRect() {
  int16_t w = (LCD_WIDTH - 2*SAFE_PAD - 2*16) / 3, h = MC_TRANSPORT_H;
  return McRect{ SAFE_PAD + w + 16, MC_TRANSPORT_Y, w, h };
}
static McRect mcNextRect() {
  int16_t w = (LCD_WIDTH - 2*SAFE_PAD - 2*16) / 3, h = MC_TRANSPORT_H;
  return McRect{ SAFE_PAD + 2*(w + 16), MC_TRANSPORT_Y, w, h };
}

// Filled triangle "previous" glyph (two stacked triangles + bar)
static void drawPrevGlyph(int16_t cx, int16_t cy, uint16_t col) {
  gfx->fillRect(cx - 12, cy - 11, 3, 22, col);
  gfx->fillTriangle(cx - 8, cy, cx + 10, cy - 11, cx + 10, cy + 11, col);
}
static void drawNextGlyph(int16_t cx, int16_t cy, uint16_t col) {
  gfx->fillRect(cx + 9, cy - 11, 3, 22, col);
  gfx->fillTriangle(cx + 8, cy, cx - 10, cy - 11, cx - 10, cy + 11, col);
}
static void drawPlayGlyph(int16_t cx, int16_t cy, uint16_t col) {
  gfx->fillTriangle(cx - 9, cy - 13, cx - 9, cy + 13, cx + 12, cy, col);
}
static void drawPauseGlyph(int16_t cx, int16_t cy, uint16_t col) {
  gfx->fillRoundRect(cx - 11, cy - 13, 8, 26, 2, col);
  gfx->fillRoundRect(cx + 3,  cy - 13, 8, 26, 2, col);
}

static void drawTransportButtons() {
  McRect pv = mcPrevRect(), pp = mcPlayRect(), nx = mcNextRect();

  uint16_t pvBg = (mcPressed == MC_PRESS_PREV) ? C_GRAY_3 : C_GRAY_1;
  gfx->fillRoundRect(pv.x, pv.y, pv.w, pv.h, 16, pvBg);
  gfx->drawRoundRect(pv.x, pv.y, pv.w, pv.h, 16, C_GRAY_3);
  drawPrevGlyph(pv.x + pv.w/2, pv.y + pv.h/2 - 6, C_WHITE);
  textCenter(pv.y + pv.h - 20, "Previous", 1, C_GRAY_4, pv.x + pv.w/2);

  // Play/Pause — the visually dominant control (blue fill), swaps glyph by
  // the best-effort local mediaPlaying state (see media_control.ino).
  uint16_t ppBg = (mcPressed == MC_PRESS_PLAY) ? lerp565(C_BLUE, C_BLACK, 60) : C_BLUE;
  gfx->fillRoundRect(pp.x, pp.y, pp.w, pp.h, 16, ppBg);
  if (mediaPlaying) drawPauseGlyph(pp.x + pp.w/2, pp.y + pp.h/2 - 6, C_BLACK);
  else              drawPlayGlyph(pp.x + pp.w/2,  pp.y + pp.h/2 - 6, C_BLACK);
  textCenter(pp.y + pp.h - 20, mediaPlaying ? "Pause" : "Play", 1, C_BLACK, pp.x + pp.w/2);

  uint16_t nxBg = (mcPressed == MC_PRESS_NEXT) ? C_GRAY_3 : C_GRAY_1;
  gfx->fillRoundRect(nx.x, nx.y, nx.w, nx.h, 16, nxBg);
  gfx->drawRoundRect(nx.x, nx.y, nx.w, nx.h, 16, C_GRAY_3);
  drawNextGlyph(nx.x + nx.w/2, nx.y + nx.h/2 - 6, C_WHITE);
  textCenter(nx.y + nx.h - 20, "Next", 1, C_GRAY_4, nx.x + nx.w/2);
}

static McRect mcPasswordsRect() {
  return McRect{ SAFE_PAD, MC_PW_BTN_Y, LCD_WIDTH - 2*SAFE_PAD, MC_PW_BTN_H };
}

static void drawPasswordsButton() {
  McRect r = mcPasswordsRect();
  gfx->fillRoundRect(r.x, r.y, r.w, r.h, 14, C_WHITE);
  // Small padlock glyph to the left of the label
  int16_t lx = r.x + 30, ly = r.y + r.h/2;
  for (int t = 0; t < 3; t++) gfx->drawCircle(lx, ly - 8, 8 - t, C_BLACK);
  gfx->fillRect(lx - 6, ly - 8, 12, 8, C_WHITE);   // mask lower half of shackle
  gfx->fillRoundRect(lx - 10, ly - 2, 20, 15, 3, C_BLACK);
  textCenter(r.y + r.h/2 - 8, "Passwords", 2, C_BLACK, r.x + r.w/2 + 14);
}

// ── Transport status hint (small, non-intrusive) ────────────────────────
// Sits in the gap between the volume-button row and the transport row —
// that gap is exactly tall enough for one size-1 text line (see the layout
// arithmetic in the constants block above: MC_TRANSPORT_Y - (MC_VOLBTN_Y +
// MC_VOLBTN_H) == 14px, and a size-1 glyph is 8px tall).
static void drawTransportHint() {
  bool ready = mediaTransportReady();
  const char *msg = ready ? nullptr
                  : (settings.bleEnabled || settings.usbHidEnabled)
                    ? "waiting for USB/Bluetooth connection"
                    : "enable USB or Bluetooth in Settings";
  if (msg) {
    int16_t midY = MC_VOLBTN_Y + MC_VOLBTN_H + (MC_TRANSPORT_Y - (MC_VOLBTN_Y + MC_VOLBTN_H) - 8) / 2;
    textCenter(midY, msg, 1, C_GRAY_4);
  }
}

// ── Full draw ────────────────────────────────────────────────
void drawMedia() {
  gfx->fillScreen(C_BLACK);
  drawStatusBar();

  textAt(SAFE_PAD, STATUS_H + 14, "Media", 3, C_WHITE);
  // The header explicitly frames the percentage as an on-device ESTIMATE,
  // not a confirmed host readout — see media_control.ino's file header for
  // why the ESP32 cannot know the host's real volume over Consumer Control.
  textAt(SAFE_PAD, STATUS_H + 42, "estimated volume  \xB7  no vault access", 1, C_GRAY_4);

  drawVolumeDial();
  drawVolumeSlider();
  drawVolButtons();
  drawTransportButtons();
  drawTransportHint();
  drawPasswordsButton();

  flushScreen();
}

// ── Touch dispatch ───────────────────────────────────────────
static bool mcHit(const McRect &r, int16_t tx, int16_t ty) {
  return tx >= r.x && tx < r.x + r.w && ty >= r.y && ty < r.y + r.h;
}

// Brief pressed-state flash then the actual action — mirrors the pattern
// used elsewhere in the app (e.g. onTapHome's drawHomeTileSlot(...,true)).
static void mcFlashAndRun(int8_t which, void (*action)()) {
  mcPressed = which;
  drawMedia();
  flushScreen();
  action();
  delay(50);
  mcPressed = MC_PRESS_NONE;
  drawMedia();
}

void onTapMedia(int16_t tx, int16_t ty) {
  if (mcHit(mcVolDownRect(), tx, ty))  { mcFlashAndRun(MC_PRESS_VOLDN, mediaVolumeDown); return; }
  if (mcHit(mcMuteRect(), tx, ty))     { mcFlashAndRun(MC_PRESS_MUTE,  mediaMute);       return; }
  if (mcHit(mcVolUpRect(), tx, ty))    { mcFlashAndRun(MC_PRESS_VOLUP, mediaVolumeUp);   return; }
  if (mcHit(mcPrevRect(), tx, ty))     { mcFlashAndRun(MC_PRESS_PREV,  mediaPrevious);   return; }
  if (mcHit(mcPlayRect(), tx, ty))     { mcFlashAndRun(MC_PRESS_PLAY,  mediaPlayPause);  return; }
  if (mcHit(mcNextRect(), tx, ty))     { mcFlashAndRun(MC_PRESS_NEXT,  mediaNext);       return; }

  // Tap the volume slider track directly → jump to that level (nice-to-have,
  // still just moves the LOCAL estimate + sends the nearest number of
  // increment/decrement steps, since Consumer Control has no "set volume").
  {
    int16_t sx = SAFE_PAD + 20, sw = LCD_WIDTH - 2 * (SAFE_PAD + 20);
    int16_t sy = MC_SLIDER_Y;
    if (tx >= sx && tx < sx + sw && ty >= sy - 14 && ty < sy + MC_SLIDER_H + 14) {
      int target = (int)((int32_t)(tx - sx) * 100 / sw);
      if (target < 0) target = 0;
      if (target > 100) target = 100;
      // Step toward the tapped point with real HID events (never fabricate
      // the host's volume directly — only nudge it), capped so a wild tap
      // can't fire dozens of HID reports at once.
      int steps = (target - mediaVolumeLocal) / MEDIA_VOL_STEP;
      if (steps > 10) steps = 10;
      if (steps < -10) steps = -10;
      for (int i = 0; i < steps; i++) mediaVolumeUp();
      for (int i = 0; i > steps; i--) mediaVolumeDown();
      drawMedia();
      return;
    }
  }

  if (mcHit(mcPasswordsRect(), tx, ty)) {
    // Hand off to the EXISTING, unmodified PIN flow — matches the spec's
    // navigation diagram exactly (Media -> tap Passwords -> PIN screen).
    // The vault is still locked at this point; pushNav(SCR_PIN) plays its
    // usual slide-up entrance and screen_pin.ino takes over from here.
    pushNav(SCR_PIN);
    return;
  }
}
