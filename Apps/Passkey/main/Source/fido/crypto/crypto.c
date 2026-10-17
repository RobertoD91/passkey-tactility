// SPDX-License-Identifier: Apache-2.0
#include "crypto.h"

#include "../fido_hal.h"
#include "micro-ecc/uECC.h"
#include "tiny-aes/aes.h"

#include <string.h>

static int uecc_rng(uint8_t* dest, unsigned size) {
    fido_hal_random(dest, size);
    return 1;
}

void crypto_init(void) {
    uECC_set_rng(uecc_rng);
}

void crypto_random(uint8_t* out, size_t len) {
    fido_hal_random(out, len);
}

bool crypto_p256_keygen(uint8_t private_key[P256_PRIVATE_KEY_SIZE], uint8_t public_key[P256_PUBLIC_KEY_SIZE]) {
    return uECC_make_key(public_key, private_key, uECC_secp256r1()) == 1;
}

bool crypto_p256_public_key(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], uint8_t public_key[P256_PUBLIC_KEY_SIZE]) {
    return uECC_compute_public_key(private_key, public_key, uECC_secp256r1()) == 1;
}

bool crypto_p256_valid_public_key(const uint8_t public_key[P256_PUBLIC_KEY_SIZE]) {
    return uECC_valid_public_key(public_key, uECC_secp256r1()) == 1;
}

bool crypto_p256_ecdh(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], const uint8_t peer_public_key[P256_PUBLIC_KEY_SIZE], uint8_t shared_x[32]) {
    return uECC_shared_secret(peer_public_key, private_key, shared_x, uECC_secp256r1()) == 1;
}

// ---- Deterministic ECDSA: micro-ecc needs a hash context for its HMAC-DRBG ----

typedef struct {
    uECC_HashContext base;
    Sha256Ctx ctx;
    uint8_t tmp[2 * SHA256_DIGEST_SIZE + SHA256_BLOCK_SIZE];
} Sha256HashContext;

static void hash_init(const uECC_HashContext* base) {
    Sha256HashContext* context = (Sha256HashContext*)base;
    sha256_init(&context->ctx);
}

static void hash_update(const uECC_HashContext* base, const uint8_t* message, unsigned message_size) {
    Sha256HashContext* context = (Sha256HashContext*)base;
    sha256_update(&context->ctx, message, message_size);
}

static void hash_finish(const uECC_HashContext* base, uint8_t* hash_result) {
    Sha256HashContext* context = (Sha256HashContext*)base;
    sha256_final(&context->ctx, hash_result);
}

bool crypto_p256_sign_hash(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], const uint8_t hash[SHA256_DIGEST_SIZE], uint8_t signature[P256_SIGNATURE_SIZE]) {
    Sha256HashContext context;
    context.base.init_hash = hash_init;
    context.base.update_hash = hash_update;
    context.base.finish_hash = hash_finish;
    context.base.block_size = SHA256_BLOCK_SIZE;
    context.base.result_size = SHA256_DIGEST_SIZE;
    context.base.tmp = context.tmp;
    int result = uECC_sign_deterministic(private_key, hash, SHA256_DIGEST_SIZE, &context.base, signature, uECC_secp256r1());
    crypto_zeroize(&context, sizeof(context));
    return result == 1;
}

bool crypto_p256_verify_hash(const uint8_t public_key[P256_PUBLIC_KEY_SIZE], const uint8_t hash[SHA256_DIGEST_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE]) {
    return uECC_verify(public_key, hash, SHA256_DIGEST_SIZE, signature, uECC_secp256r1()) == 1;
}

// Writes one DER INTEGER for a 32-byte big-endian unsigned value. Returns the bytes written.
static size_t der_write_integer(const uint8_t value[32], uint8_t* out) {
    size_t skip = 0;
    while (skip < 31 && value[skip] == 0) {
        skip++;
    }
    const uint8_t* digits = value + skip;
    size_t digits_len = 32 - skip;
    bool needs_pad = (digits[0] & 0x80) != 0;
    size_t content_len = digits_len + (needs_pad ? 1 : 0);
    size_t pos = 0;
    out[pos++] = 0x02;
    out[pos++] = (uint8_t)content_len;
    if (needs_pad) {
        out[pos++] = 0x00;
    }
    memcpy(out + pos, digits, digits_len);
    return pos + digits_len;
}

size_t crypto_ecdsa_signature_to_der(const uint8_t signature[P256_SIGNATURE_SIZE], uint8_t der[ECDSA_DER_MAX_SIZE]) {
    uint8_t body[ECDSA_DER_MAX_SIZE];
    size_t body_len = der_write_integer(signature, body);
    body_len += der_write_integer(signature + 32, body + body_len);
    der[0] = 0x30;
    der[1] = (uint8_t)body_len;
    memcpy(der + 2, body, body_len);
    return body_len + 2;
}

bool crypto_p256_sign_der(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], const void* message, size_t message_len, uint8_t* der, size_t* der_len) {
    uint8_t hash[SHA256_DIGEST_SIZE];
    uint8_t raw[P256_SIGNATURE_SIZE];
    sha256(message, message_len, hash);
    if (!crypto_p256_sign_hash(private_key, hash, raw)) {
        return false;
    }
    *der_len = crypto_ecdsa_signature_to_der(raw, der);
    crypto_zeroize(raw, sizeof(raw));
    return true;
}

void crypto_aes256_cbc_encrypt(const uint8_t key[AES256_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* in, uint8_t* out, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    if (out != in) {
        memcpy(out, in, len);
    }
    AES_CBC_encrypt_buffer(&ctx, out, len);
    crypto_zeroize(&ctx, sizeof(ctx));
}

void crypto_aes256_cbc_decrypt(const uint8_t key[AES256_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* in, uint8_t* out, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    if (out != in) {
        memcpy(out, in, len);
    }
    AES_CBC_decrypt_buffer(&ctx, out, len);
    crypto_zeroize(&ctx, sizeof(ctx));
}

bool crypto_equal(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = (const volatile uint8_t*)a;
    const volatile uint8_t* pb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

void crypto_zeroize(void* buf, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while (len--) {
        *p++ = 0;
    }
}
