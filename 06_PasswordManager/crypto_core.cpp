// =============================================================
//  crypto_core.cpp  —  mbedTLS wrappers (see crypto_core.h)
//
//  Isolated in its own translation unit (like hid_usb.cpp / hid_ble.cpp)
//  so the mbedTLS headers stay out of the .ino build units and there is
//  exactly one place in the whole project that talks to mbedTLS directly.
// =============================================================
#include "crypto_core.h"
#include <esp_random.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/platform_util.h>

void ckRandomBytes(uint8_t *out, size_t len) {
  // esp_fill_random() draws from the ESP32-S3's hardware RNG, which
  // Espressif documents as continuously seeded from internal thermal/RF
  // noise — safe for keys, salts, nonces. Not a "seeded rand()".
  esp_fill_random(out, len);
}

void ckSecureZero(void *buf, size_t len) {
  mbedtls_platform_zeroize(buf, len);
}

bool ckDeriveKey(const char *pin, const uint8_t *salt, size_t saltLen,
                 uint32_t iterations, uint8_t *outKey, size_t outKeyLen) {
  if (!pin || !salt || !outKey) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  bool ok = false;
  if (info && mbedtls_md_setup(&ctx, info, 1 /* HMAC */) == 0) {
    int rc = mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                                       (const unsigned char *)pin, strlen(pin),
                                       salt, saltLen,
                                       iterations,
                                       (uint32_t)outKeyLen, outKey);
    ok = (rc == 0);
  }
  mbedtls_md_free(&ctx);
  return ok;
}

bool ckAesGcmEncrypt(const uint8_t *key,
                     const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen,
                     const uint8_t *plaintext, size_t plainLen,
                     uint8_t *ciphertext, uint8_t *tag) {
  if (!key || !iv || !tag) return false;
  if (plainLen > 0 && (!plaintext || !ciphertext)) return false;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  bool ok = false;
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, CK_KEY_LEN * 8) == 0) {
    int rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plainLen,
                                       iv, ivLen, aad, aadLen,
                                       plaintext, ciphertext,
                                       CK_GCM_TAG_LEN, tag);
    ok = (rc == 0);
  }
  mbedtls_gcm_free(&gcm);
  return ok;
}

bool ckAesGcmDecrypt(const uint8_t *key,
                     const uint8_t *iv, size_t ivLen,
                     const uint8_t *aad, size_t aadLen,
                     const uint8_t *ciphertext, size_t cipherLen,
                     const uint8_t *tag,
                     uint8_t *plaintext) {
  if (!key || !iv || !tag) return false;
  if (cipherLen > 0 && (!ciphertext || !plaintext)) return false;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  bool ok = false;
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, CK_KEY_LEN * 8) == 0) {
    int rc = mbedtls_gcm_auth_decrypt(&gcm, cipherLen,
                                      iv, ivLen, aad, aadLen,
                                      tag, CK_GCM_TAG_LEN,
                                      ciphertext, plaintext);
    ok = (rc == 0);   // rc == MBEDTLS_ERR_GCM_AUTH_FAILED on tamper/wrong key
  }
  mbedtls_gcm_free(&gcm);
  // On failure, wipe whatever partial plaintext mbedTLS may have written —
  // never let a caller accidentally trust/display it.
  if (!ok && cipherLen > 0 && plaintext) ckSecureZero(plaintext, cipherLen);
  return ok;
}
