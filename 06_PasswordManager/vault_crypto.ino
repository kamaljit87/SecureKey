// =============================================================
//  vault_crypto.ino  —  PIN → KEK → Master Key lifecycle
//
//  This file is the ONLY place that ever holds the master encryption
//  key or a PIN-derived key in memory. Nothing here is persisted:
//
//      NVS ("skcrypt" namespace) stores ONLY:
//          salt          16 random bytes, generated once at setup
//          iterations    PBKDF2 iteration count (versioned, so a future
//                        firmware can raise cost without breaking old
//                        vaults — see kdfver)
//          kdfver        KDF/security parameter version
//          wrap_iv       12-byte nonce used to wrap the master key
//          wrapped_mk    master key encrypted (AES-256-GCM) under the
//                        PIN-derived KEK
//          wrap_tag      16-byte GCM authentication tag for wrapped_mk
//
//      The PIN itself is NEVER stored, in any form.
//      The master key is NEVER stored in plaintext, anywhere.
//
//  Unlock flow:
//      PIN (typed) --PBKDF2(salt,iterations)--> KEK (RAM only)
//      KEK --AES-GCM-decrypt(wrapped_mk, wrap_iv, wrap_tag)--> master key
//      GCM tag verification IS the PIN check: a wrong PIN derives a wrong
//      KEK, which fails to authenticate wrapped_mk, so decryption fails
//      closed. There is no separate stored "PIN hash" to check first —
//      one less place for a plaintext-equivalent secret to leak from.
//
//  Lock:
//      master key and KEK buffers are securely wiped (ckSecureZero) and
//      vaultUnlocked is cleared. See vaultLock().
// =============================================================
#include "crypto_core.h"
#include "shared_types.h"    // SECURITY_VERSION + VaultCryptoParams live here — see its comment for why

#define VAULT_NVS_NS      "skcrypt"

// ── RAM-only key material ─────────────────────────────────────
// Master key: exists in RAM ONLY while the vault is unlocked. Wiped by
// vaultLock() and on any path back to the lock screen.
uint8_t  vaultMasterKey[CK_KEY_LEN];
bool     vaultUnlocked = false;

// (VaultCryptoParams — the on-disk NVS crypto parameter bundle — is
// defined in shared_types.h, not here.)

static bool vaultParamsLoad(VaultCryptoParams &p) {
  prefs.begin(VAULT_NVS_NS, true);
  size_t n1 = prefs.getBytes("salt", p.salt, sizeof(p.salt));
  p.iterations = prefs.getUInt("iter", 0);
  p.kdfVersion = prefs.getUShort("kdfver", 0);
  size_t n2 = prefs.getBytes("wiv", p.wrapIv, sizeof(p.wrapIv));
  size_t n3 = prefs.getBytes("wmk", p.wrappedKey, sizeof(p.wrappedKey));
  size_t n4 = prefs.getBytes("wtag", p.wrapTag, sizeof(p.wrapTag));
  prefs.end();
  return n1 == sizeof(p.salt) && n2 == sizeof(p.wrapIv) &&
         n3 == sizeof(p.wrappedKey) && n4 == sizeof(p.wrapTag) &&
         p.iterations > 0;
}

static void vaultParamsSave(const VaultCryptoParams &p) {
  prefs.begin(VAULT_NVS_NS, false);
  prefs.putBytes("salt", p.salt, sizeof(p.salt));
  prefs.putUInt ("iter", p.iterations);
  prefs.putUShort("kdfver", p.kdfVersion);
  prefs.putBytes("wiv",  p.wrapIv,     sizeof(p.wrapIv));
  prefs.putBytes("wmk",  p.wrappedKey, sizeof(p.wrappedKey));
  prefs.putBytes("wtag", p.wrapTag,    sizeof(p.wrapTag));
  prefs.end();
}

// True once initial crypto setup (first boot / post-factory-reset) has run.
bool vaultCryptoProvisioned() {
  prefs.begin(VAULT_NVS_NS, true);
  bool has = prefs.isKey("wmk");
  prefs.end();
  return has;
}

// ── Configured PIN length (metadata, NOT the PIN) ───────────────────────
// The PIN's LENGTH is not a secret (the keypad UI already reveals it —
// one dot per digit) so it's fine to store as plain NVS metadata. This is
// what lets the unlock/PIN-change screens know how many digits to collect
// without guessing. Defaults to PIN_MIN_LEN (4) so a device that somehow
// reaches vaultUnlock() before this was ever set still behaves sanely.
uint8_t vaultPinLength() {
  prefs.begin(VAULT_NVS_NS, true);
  uint8_t len = prefs.getUChar("pinlen", PIN_MIN_LEN);
  prefs.end();
  if (len < PIN_MIN_LEN || len > PIN_MAX_LEN) len = PIN_MIN_LEN;
  return len;
}
void vaultSetPinLength(uint8_t len) {
  if (len < PIN_MIN_LEN) len = PIN_MIN_LEN;
  if (len > PIN_MAX_LEN) len = PIN_MAX_LEN;
  prefs.begin(VAULT_NVS_NS, false);
  prefs.putUChar("pinlen", len);
  prefs.end();
}

// ── First-time provisioning ────────────────────────────────────────────
// Generates a brand-new random 256-bit master key and wraps it under a
// KEK derived from `pin`. Called on very first boot and after factory
// reset. Overwrites any existing crypto material — callers MUST have
// already wiped/migrated the old encrypted database before calling this
// on a non-empty vault (see storage.ino migration + factory reset).
bool vaultCryptoProvision(const char *pin) {
  VaultCryptoParams p;
  memset(&p, 0, sizeof(p));
  ckRandomBytes(p.salt, sizeof(p.salt));
  p.iterations = CK_PBKDF2_ITERATIONS;
  p.kdfVersion = SECURITY_VERSION;
  ckRandomBytes(p.wrapIv, sizeof(p.wrapIv));

  uint8_t kek[CK_KEY_LEN];
  if (!ckDeriveKey(pin, p.salt, sizeof(p.salt), p.iterations, kek, sizeof(kek))) {
    return false;
  }

  uint8_t newMk[CK_KEY_LEN];
  ckRandomBytes(newMk, sizeof(newMk));

  bool ok = ckAesGcmEncrypt(kek, p.wrapIv, sizeof(p.wrapIv),
                            nullptr, 0,
                            newMk, sizeof(newMk),
                            p.wrappedKey, p.wrapTag);
  if (ok) {
    vaultParamsSave(p);
    vaultSetPinLength((uint8_t)strlen(pin));
    memcpy(vaultMasterKey, newMk, sizeof(vaultMasterKey));
    vaultUnlocked = true;
  }
  ckSecureZero(kek, sizeof(kek));
  ckSecureZero(newMk, sizeof(newMk));
  return ok;
}

// ── Unlock: derive KEK from the entered PIN, recover the master key ─────
// Returns true and leaves vaultMasterKey populated + vaultUnlocked=true
// only if `pin` is correct. On failure, vaultMasterKey is left zeroed.
bool vaultUnlock(const char *pin) {
  VaultCryptoParams p;
  if (!vaultParamsLoad(p)) return false;

  uint8_t kek[CK_KEY_LEN];
  if (!ckDeriveKey(pin, p.salt, sizeof(p.salt), p.iterations, kek, sizeof(kek))) {
    return false;
  }

  uint8_t mk[CK_KEY_LEN];
  bool ok = ckAesGcmDecrypt(kek, p.wrapIv, sizeof(p.wrapIv),
                            nullptr, 0,
                            p.wrappedKey, sizeof(p.wrappedKey),
                            p.wrapTag, mk);
  ckSecureZero(kek, sizeof(kek));

  if (ok) {
    memcpy(vaultMasterKey, mk, sizeof(vaultMasterKey));
    vaultUnlocked = true;
  } else {
    memset(vaultMasterKey, 0, sizeof(vaultMasterKey));
    vaultUnlocked = false;
  }
  ckSecureZero(mk, sizeof(mk));
  return ok;
}

// ── Verify a PIN WITHOUT disturbing the current unlocked session ────────
// Used by the change-PIN flow's "enter current PIN" step: the device is
// already unlocked (vaultMasterKey is live in RAM) at that point, and a
// WRONG re-entry of the "current" PIN here must NOT lock the user out of
// their already-authenticated session or clobber vaultMasterKey — it
// should just fail that one verification step. Recovers the master key
// into a scratch buffer, compares it against the live vaultMasterKey
// (constant-time), and always wipes the scratch buffer before returning.
bool vaultVerifyPin(const char *pin) {
  if (!vaultUnlocked) return false;   // nothing to verify against

  VaultCryptoParams p;
  if (!vaultParamsLoad(p)) return false;

  uint8_t kek[CK_KEY_LEN];
  if (!ckDeriveKey(pin, p.salt, sizeof(p.salt), p.iterations, kek, sizeof(kek))) {
    return false;
  }

  uint8_t mk[CK_KEY_LEN];
  bool ok = ckAesGcmDecrypt(kek, p.wrapIv, sizeof(p.wrapIv),
                            nullptr, 0,
                            p.wrappedKey, sizeof(p.wrappedKey),
                            p.wrapTag, mk);
  ckSecureZero(kek, sizeof(kek));

  if (ok) {
    // Extra belt-and-braces check: the recovered key must match the one
    // already held live in RAM (constant-time compare — this is a secret
    // comparison, not a length/format check).
    uint8_t diff = 0;
    for (size_t i = 0; i < CK_KEY_LEN; i++) diff |= mk[i] ^ vaultMasterKey[i];
    ok = (diff == 0);
  }
  ckSecureZero(mk, sizeof(mk));
  return ok;
}

// ── Re-wrap the master key under a NEW PIN (PIN change) ────────────────
// Requires the vault to already be unlocked (caller has verified the OLD
// PIN via vaultVerifyPin() as part of the change-PIN flow — see
// screen_chgpin.ino) — this re-wraps the SAME master key so existing
// encrypted records stay valid; it does NOT re-encrypt the database.
bool vaultRewrapKey(const char *newPin) {
  if (!vaultUnlocked) return false;

  VaultCryptoParams p;
  memset(&p, 0, sizeof(p));
  ckRandomBytes(p.salt, sizeof(p.salt));       // fresh salt on every PIN change
  p.iterations = CK_PBKDF2_ITERATIONS;
  p.kdfVersion = SECURITY_VERSION;
  ckRandomBytes(p.wrapIv, sizeof(p.wrapIv));   // fresh nonce — never reused

  uint8_t kek[CK_KEY_LEN];
  bool ok = ckDeriveKey(newPin, p.salt, sizeof(p.salt), p.iterations, kek, sizeof(kek));
  if (ok) {
    ok = ckAesGcmEncrypt(kek, p.wrapIv, sizeof(p.wrapIv),
                         nullptr, 0,
                         vaultMasterKey, sizeof(vaultMasterKey),
                         p.wrappedKey, p.wrapTag);
  }
  if (ok) {
    vaultParamsSave(p);
    vaultSetPinLength((uint8_t)strlen(newPin));
  }
  ckSecureZero(kek, sizeof(kek));
  return ok;
}

// ── Lock: wipe all key material from RAM ────────────────────────────────
void vaultLock() {
  ckSecureZero(vaultMasterKey, sizeof(vaultMasterKey));
  vaultUnlocked = false;
}

// ── Factory reset: destroy the crypto identity entirely ─────────────────
// Wipes the NVS crypto namespace (salt/wrapped key/params) so nothing about
// the old master key survives — a fresh vaultCryptoProvision() afterward
// creates an unrelated random master key. Does NOT touch the encrypted
// database file itself; callers must also erase /db.bin (see factory
// reset in screen_settings.ino).
void vaultCryptoErase() {
  vaultLock();
  prefs.begin(VAULT_NVS_NS, false);
  prefs.clear();
  prefs.end();
}
