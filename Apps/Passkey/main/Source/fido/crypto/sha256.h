// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[SHA256_BLOCK_SIZE];
    size_t buffer_len;
} Sha256Ctx;

void sha256_init(Sha256Ctx* ctx);
void sha256_update(Sha256Ctx* ctx, const void* data, size_t len);
void sha256_final(Sha256Ctx* ctx, uint8_t out[SHA256_DIGEST_SIZE]);
void sha256(const void* data, size_t len, uint8_t out[SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif
