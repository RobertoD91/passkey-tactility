// SPDX-License-Identifier: Apache-2.0
/**
 * CTAP2 PIN/UV auth protocols 1 and 2: ECDH key agreement, encryption and authentication of PIN
 * material and pinUvAuthTokens.
 */
#pragma once

#include "crypto/crypto.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PIN_PROTOCOL_V1 1
#define PIN_PROTOCOL_V2 2

typedef struct {
    uint8_t protocol;
    /** Protocol 1: SHA-256 of the ECDH X coordinate (32 bytes, used for HMAC and AES).
     *  Protocol 2: HKDF-derived HMAC key (bytes 0..31) and AES key (bytes 32..63). */
    uint8_t key[64];
} PinSharedSecret;

bool pin_protocol_is_supported(uint64_t protocol);

/** Derives the shared secret from the platform's key agreement key and the authenticator's private key. */
bool pin_protocol_shared_secret(uint8_t protocol, const uint8_t authenticator_private_key[32], const uint8_t platform_public_key[64], PinSharedSecret* out);

/** Largest ciphertext for a plaintext of @a plaintext_len bytes. */
#define PIN_PROTOCOL_ENCRYPTED_SIZE(plaintext_len) ((plaintext_len) + AES_BLOCK_SIZE)

/**
 * Encrypts @a plaintext (a multiple of 16 bytes). Protocol 2 prepends a random IV.
 * @return the ciphertext length
 */
size_t pin_protocol_encrypt(const PinSharedSecret* secret, const uint8_t* plaintext, size_t plaintext_len, uint8_t* ciphertext);

/**
 * Decrypts into @a plaintext (at least @a ciphertext_len bytes).
 * @return false when the length is invalid for the protocol
 */
bool pin_protocol_decrypt(const PinSharedSecret* secret, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, size_t* plaintext_len);

/** HMAC-SHA256 authentication: protocol 1 uses the first 16 bytes, protocol 2 all 32. */
size_t pin_protocol_authenticate(uint8_t protocol, const uint8_t* key, size_t key_len, const uint8_t* message, size_t message_len, uint8_t out[32]);

bool pin_protocol_verify(uint8_t protocol, const uint8_t* key, size_t key_len, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len);

/** The key to authenticate with when the shared secret is the key (protocol 2 uses only its HMAC half). */
static inline const uint8_t* pin_protocol_hmac_key(const PinSharedSecret* secret) {
    return secret->key;
}

#ifdef __cplusplus
}
#endif
