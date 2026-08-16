// =============================================================
//  crypto_core.h  —  Public interface to SecureKey's crypto module
//
//  Everything here is a thin wrapper around mbedTLS primitives that
//  ship with the ESP32 Arduino core (esp32:esp32@2.0.16). No custom
//  cryptography is implemented anywhere in this project:
//
//    • Random bytes  → esp_fill_random()          (HW RNG on ESP32-S3)
//    • KDF           → mbedtls_pkcs5_pbkdf2_hmac() (PBKDF2-HMAC-SHA256)
//    • AEAD          → mbedtls_gcm_*()             (AES-256-GCM)
//    • Secure wipe   → mbedtls_platform_zeroize()  (won't be optimized out)
//
//  See docs/SECURITY.md for the full design rationale and threat model.
// =============================================================
#pragma once
#include <Arduino.h>

// ---- Sizes (bytes) --------------------------------------------------
#define CK_SALT_LEN     16   // PBKDF2 salt
#define CK_KEY_LEN      32   // AES-256 key / KEK / master key
#define CK_GCM_IV_LEN   12   // AES-GCM standard nonce size
#define CK_GCM_TAG_LEN  16   // AES-GCM authentication tag

// PBKDF2-HMAC-SHA256 iteration count.
//   Chosen to keep PIN unlock under ~1s on the ESP32-S3 (Xtensa LX7 @240MHz)
//   while being far beyond what plain SHA256(PIN) would cost an attacker.
//   This is a KDF applied to a *low-entropy* PIN, so the honest cost of a
//   single legitimate unlock (~150-300ms measured on S3) is the price paid
//   for making offline brute force meaningfully slower per guess.
#define CK_PBKDF2_ITERATIONS   50000

// ---- Cryptographically-secure random ---------------------------------
// Fills `out` with `len` random bytes from the ESP32-S3 hardware RNG
// (via esp_fill_random — continuously re-seeded from thermal/RF noise
// per Espressif's TRNG documentation). NEVER use rand()/random() for
// anything security-relevant in this project.
void ckRandomBytes(uint8_t *out, size_t len);

// ---- Secure memory wipe ------------------------------------------------
// Zeroes `len` bytes at `buf` using mbedtls_platform_zeroize(), which is
// specifically designed to survive compiler dead-store elimination (unlike
// a plain memset, which an optimizer is permitted to remove if `buf` is
// not read again). Use this for PIN buffers, derived keys, and decrypted
// password buffers once they are no longer needed.
void ckSecureZero(void *buf, size_t len);

// ---- PBKDF2-HMAC-SHA256 -------------------------------------------------
// Derives a `CK_KEY_LEN`-byte key from `pin` (a short numeric secret) and
// `salt` (CK_SALT_LEN random bytes, unique per device). `iterations` is
// stored alongside the salt so the KDF cost can be raised in a future
// firmware/security version without breaking older vaults.
// Returns true on success.
bool ckDeriveKey(const char *pin, const uint8_t *salt, size_t saltLen,
                 uint32_t iterations, uint8_t *outKey, size_t outKeyLen);

// ---- AES-256-GCM authenticated encryption -------------------------------
// Encrypts `plainLen` bytes of `plaintext` with `key` (CK_KEY_LEN bytes)
// under a caller-supplied `iv` (CK_GCM_IV_LEN bytes — MUST be unique per
// key; generate with ckRandomBytes() for every call). `aad`/`aadLen` are
// optional additional authenticated data (not encrypted, but tamper-
// checked) — e.g. a record id, so a ciphertext can't be silently swapped
// onto a different record. Writes ciphertext (same length as plaintext)
// and a CK_GCM_TAG_LEN-byte authentication tag. Returns true on success.
bool ckAesGcmEncrypt(const uint8_t *key,
                     const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen,
                     const uint8_t *plaintext, size_t plainLen,
                     uint8_t *ciphertext, uint8_t *tag);

// Decrypts + verifies. Returns false (and does NOT write partial plaintext
// beyond what mbedTLS already wrote internally — caller must discard the
// output buffer) if the authentication tag does not match, i.e. the
// ciphertext, AAD, IV, or key is wrong/corrupted/tampered.
bool ckAesGcmDecrypt(const uint8_t *key,
                     const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen,
                     const uint8_t *ciphertext, size_t cipherLen,
                     const uint8_t *tag,
                     uint8_t *plaintext);
