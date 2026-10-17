// SPDX-License-Identifier: Apache-2.0
#include "hmac.h"

#include <string.h>

void hmac_sha256_init(HmacSha256Ctx* ctx, const uint8_t* key, size_t key_len) {
    uint8_t block[SHA256_BLOCK_SIZE];
    memset(block, 0, sizeof(block));
    if (key_len > SHA256_BLOCK_SIZE) {
        sha256(key, key_len, block);
    } else {
        memcpy(block, key, key_len);
    }

    uint8_t pad[SHA256_BLOCK_SIZE];
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        pad[i] = block[i] ^ 0x36;
    }
    sha256_init(&ctx->inner);
    sha256_update(&ctx->inner, pad, sizeof(pad));

    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        pad[i] = block[i] ^ 0x5c;
    }
    sha256_init(&ctx->outer);
    sha256_update(&ctx->outer, pad, sizeof(pad));

    memset(block, 0, sizeof(block));
    memset(pad, 0, sizeof(pad));
}

void hmac_sha256_update(HmacSha256Ctx* ctx, const void* data, size_t len) {
    sha256_update(&ctx->inner, data, len);
}

void hmac_sha256_final(HmacSha256Ctx* ctx, uint8_t out[SHA256_DIGEST_SIZE]) {
    uint8_t inner_digest[SHA256_DIGEST_SIZE];
    sha256_final(&ctx->inner, inner_digest);
    sha256_update(&ctx->outer, inner_digest, sizeof(inner_digest));
    sha256_final(&ctx->outer, out);
    memset(inner_digest, 0, sizeof(inner_digest));
}

void hmac_sha256(const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]) {
    HmacSha256Ctx ctx;
    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, len);
    hmac_sha256_final(&ctx, out);
}

void hkdf_sha256(
    const uint8_t* salt, size_t salt_len,
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* info, size_t info_len,
    uint8_t* okm, size_t okm_len
) {
    static const uint8_t zero_salt[SHA256_DIGEST_SIZE] = { 0 };
    if (salt == NULL) {
        salt = zero_salt;
        salt_len = sizeof(zero_salt);
    }

    uint8_t prk[SHA256_DIGEST_SIZE];
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    uint8_t t[SHA256_DIGEST_SIZE];
    size_t t_len = 0;
    uint8_t counter = 1;
    size_t written = 0;
    while (written < okm_len) {
        HmacSha256Ctx ctx;
        hmac_sha256_init(&ctx, prk, sizeof(prk));
        hmac_sha256_update(&ctx, t, t_len);
        hmac_sha256_update(&ctx, info, info_len);
        hmac_sha256_update(&ctx, &counter, 1);
        hmac_sha256_final(&ctx, t);
        t_len = sizeof(t);
        size_t take = okm_len - written;
        if (take > sizeof(t)) {
            take = sizeof(t);
        }
        memcpy(okm + written, t, take);
        written += take;
        counter++;
    }
    memset(prk, 0, sizeof(prk));
    memset(t, 0, sizeof(t));
}
