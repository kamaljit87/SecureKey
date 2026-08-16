// =============================================================
//  pwgen.ino  —  Cryptographically-secure password generator
//
//  Used by the Add/Edit screen's GENERATE button (password field only).
//  Randomness comes exclusively from ckRandomBytes() (crypto_core.cpp),
//  which wraps the ESP32-S3 hardware RNG (esp_fill_random) — the same
//  source used for salts/nonces/keys elsewhere in this project. This
//  file NEVER calls rand()/random() or seeds anything itself: there is
//  no seed to manage, the HW RNG is continuously entropy-fed by the
//  silicon per Espressif's documentation.
//
//  Rejection sampling (not modulo) is used to pick characters so the
//  output distribution over the charset is exactly uniform — a naive
//  `esp_random() % N` has a small bias whenever N doesn't evenly divide
//  the RNG's range, which is exactly the kind of subtle cryptographic
//  mistake this project avoids.
// =============================================================
#include "shared_types.h"   // PwGenOptions

#define PWGEN_MIN_LEN   8
#define PWGEN_MAX_LEN   32
#define PWGEN_DEFAULT_LEN 16

// (PwGenOptions is defined in shared_types.h — see its comment for why.)

// Not static: screen_add.ino (Add/Edit screen) reads/writes this directly
// for the GENERATE button's length-cycle control.
PwGenOptions pwgenOpts = { PWGEN_DEFAULT_LEN, true, true, true, true };

static const char *PWGEN_UPPER   = "ABCDEFGHJKLMNPQRSTUVWXYZ";   // no I/O (ambiguous)
static const char *PWGEN_LOWER   = "abcdefghijkmnpqrstuvwxyz";   // no l (ambiguous)
static const char *PWGEN_DIGITS  = "23456789";                   // no 0/1 (ambiguous)
static const char *PWGEN_SYMBOLS = "!@#$%^&*-_=+?";

// Uniform random index in [0, n) using rejection sampling over a random
// byte, so every value in range is equally likely (no modulo bias).
static uint8_t pwgenUniformIndex(uint8_t n) {
  if (n == 0) return 0;
  uint8_t limit = (uint8_t)(256 - (256 % n));   // largest multiple of n that fits a byte
  uint8_t r;
  do {
    ckRandomBytes(&r, 1);
  } while (r >= limit);
  return (uint8_t)(r % n);
}

// Fisher-Yates shuffle using the same uniform sampler — avoids the
// generated password's character-class order being predictable (e.g.
// always "one upper, then lowers, then a digit, then symbols").
static void pwgenShuffle(char *buf, uint8_t len) {
  for (int i = len - 1; i > 0; i--) {
    uint8_t j = pwgenUniformIndex((uint8_t)(i + 1));
    char t = buf[i]; buf[i] = buf[j]; buf[j] = t;
  }
}

// Generates a password into `out` (must be at least opts.length+1 bytes).
// Guarantees at least one character from each ENABLED class (so "include
// symbols" can't silently produce a symbol-free password by chance on a
// short length), then fills the rest uniformly from the combined charset,
// then shuffles. If every class is disabled, falls back to lower+digits
// so the field is never left empty. Not static — called from
// screen_add.ino's GENERATE button.
void pwgenGenerate(char *out, const PwGenOptions &opts) {
  uint8_t len = opts.length;
  if (len < PWGEN_MIN_LEN) len = PWGEN_MIN_LEN;
  if (len > PWGEN_MAX_LEN) len = PWGEN_MAX_LEN;

  char charset[96]; int csLen = 0;
  bool useUpper = opts.upper, useLower = opts.lower,
       useDigits = opts.digits, useSymbols = opts.symbols;
  if (!useUpper && !useLower && !useDigits && !useSymbols) {
    useLower = true; useDigits = true;   // never generate from an empty set
  }
  if (useUpper)   for (const char *p = PWGEN_UPPER;   *p; p++) charset[csLen++] = *p;
  if (useLower)   for (const char *p = PWGEN_LOWER;   *p; p++) charset[csLen++] = *p;
  if (useDigits)  for (const char *p = PWGEN_DIGITS;  *p; p++) charset[csLen++] = *p;
  if (useSymbols) for (const char *p = PWGEN_SYMBOLS; *p; p++) charset[csLen++] = *p;

  uint8_t pos = 0;
  // One guaranteed char per enabled class (bounded by len so a very short
  // requested length still can't overflow `out`).
  if (useUpper   && pos < len) out[pos++] = PWGEN_UPPER[pwgenUniformIndex((uint8_t)strlen(PWGEN_UPPER))];
  if (useLower   && pos < len) out[pos++] = PWGEN_LOWER[pwgenUniformIndex((uint8_t)strlen(PWGEN_LOWER))];
  if (useDigits  && pos < len) out[pos++] = PWGEN_DIGITS[pwgenUniformIndex((uint8_t)strlen(PWGEN_DIGITS))];
  if (useSymbols && pos < len) out[pos++] = PWGEN_SYMBOLS[pwgenUniformIndex((uint8_t)strlen(PWGEN_SYMBOLS))];

  for (; pos < len; pos++) out[pos] = charset[pwgenUniformIndex((uint8_t)csLen)];
  out[len] = 0;

  pwgenShuffle(out, len);
  ckSecureZero(charset, sizeof(charset));
}
