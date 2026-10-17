// SPDX-License-Identifier: Apache-2.0
/**
 * The cryptographic primitives the authenticator uses: P-256 ECDSA/ECDH (micro-ecc), AES-256-CBC
 * (tiny-AES), SHA-256 and HMAC/HKDF, plus the small helpers around them.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hmac.h"
#include "sha256.h"

#ifdef __cplusplus
extern "C" {
#endif

#define P256_PRIVATE_KEY_SIZE 32
#define P256_PUBLIC_KEY_SIZE 64 /* X || Y */
#define P256_SIGNATURE_SIZE 64  /* r || s */
#define ECDSA_DER_MAX_SIZE 72
#define AES_BLOCK_SIZE 16
#define AES256_KEY_SIZE 32

/** Must be called once before any other function. Registers the random source with micro-ecc. */
void crypto_init(void);

void crypto_random(uint8_t* out, size_t len);

bool crypto_p256_keygen(uint8_t private_key[P256_PRIVATE_KEY_SIZE], uint8_t public_key[P256_PUBLIC_KEY_SIZE]);

/** @return false when @a private_key is not a valid scalar (zero or >= the group order). */
bool crypto_p256_public_key(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], uint8_t public_key[P256_PUBLIC_KEY_SIZE]);

bool crypto_p256_valid_public_key(const uint8_t public_key[P256_PUBLIC_KEY_SIZE]);

/** ECDH: writes the X coordinate of the shared point to @a shared_x. */
bool crypto_p256_ecdh(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], const uint8_t peer_public_key[P256_PUBLIC_KEY_SIZE], uint8_t shared_x[32]);

/** Deterministic (RFC 6979 style) ECDSA over a SHA-256 digest; raw r || s output. */
bool crypto_p256_sign_hash(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], const uint8_t hash[SHA256_DIGEST_SIZE], uint8_t signature[P256_SIGNATURE_SIZE]);

bool crypto_p256_verify_hash(const uint8_t public_key[P256_PUBLIC_KEY_SIZE], const uint8_t hash[SHA256_DIGEST_SIZE], const uint8_t signature[P256_SIGNATURE_SIZE]);

/** Converts a raw r || s signature to the DER SEQUENCE CTAP and X.509 expect. @return the DER length. */
size_t crypto_ecdsa_signature_to_der(const uint8_t signature[P256_SIGNATURE_SIZE], uint8_t der[ECDSA_DER_MAX_SIZE]);

/**
 * SHA-256 hashes @a message and signs the digest, producing a DER signature.
 * @param[out] der at least ECDSA_DER_MAX_SIZE bytes
 * @param[out] der_len the DER length
 */
bool crypto_p256_sign_der(const uint8_t private_key[P256_PRIVATE_KEY_SIZE], const void* message, size_t message_len, uint8_t* der, size_t* der_len);

/** AES-256-CBC without padding: @a len must be a multiple of 16. In-place operation is allowed. */
void crypto_aes256_cbc_encrypt(const uint8_t key[AES256_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* in, uint8_t* out, size_t len);
void crypto_aes256_cbc_decrypt(const uint8_t key[AES256_KEY_SIZE], const uint8_t iv[AES_BLOCK_SIZE], const uint8_t* in, uint8_t* out, size_t len);

/** Constant-time comparison. @return true when equal. */
bool crypto_equal(const void* a, const void* b, size_t len);

/** Clears sensitive memory in a way the compiler doesn't optimize away. */
void crypto_zeroize(void* buf, size_t len);

#ifdef __cplusplus
}
#endif
