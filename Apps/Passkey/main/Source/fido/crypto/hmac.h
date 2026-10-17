// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    Sha256Ctx inner;
    Sha256Ctx outer;
} HmacSha256Ctx;

void hmac_sha256_init(HmacSha256Ctx* ctx, const uint8_t* key, size_t key_len);
void hmac_sha256_update(HmacSha256Ctx* ctx, const void* data, size_t len);
void hmac_sha256_final(HmacSha256Ctx* ctx, uint8_t out[SHA256_DIGEST_SIZE]);
void hmac_sha256(const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

/** HKDF-SHA256 (RFC 5869). @a salt may be NULL (treated as 32 zero bytes). @a okm_len is at most 255 * 32. */
void hkdf_sha256(
    const uint8_t* salt, size_t salt_len,
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* info, size_t info_len,
    uint8_t* okm, size_t okm_len
);

#ifdef __cplusplus
}
#endif
