// SPDX-License-Identifier: Apache-2.0
#include "pin_protocol.h"

#include <string.h>

bool pin_protocol_is_supported(uint64_t protocol) {
    return protocol == PIN_PROTOCOL_V1 || protocol == PIN_PROTOCOL_V2;
}

bool pin_protocol_shared_secret(uint8_t protocol, const uint8_t authenticator_private_key[32], const uint8_t platform_public_key[64], PinSharedSecret* out) {
    uint8_t z[32];
    if (!crypto_p256_valid_public_key(platform_public_key) || !crypto_p256_ecdh(authenticator_private_key, platform_public_key, z)) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    out->protocol = protocol;
    if (protocol == PIN_PROTOCOL_V1) {
        sha256(z, sizeof(z), out->key);
    } else {
        hkdf_sha256(NULL, 0, z, sizeof(z), (const uint8_t*)"CTAP2 HMAC key", 14, out->key, 32);
        hkdf_sha256(NULL, 0, z, sizeof(z), (const uint8_t*)"CTAP2 AES key", 13, out->key + 32, 32);
    }
    crypto_zeroize(z, sizeof(z));
    return true;
}

size_t pin_protocol_encrypt(const PinSharedSecret* secret, const uint8_t* plaintext, size_t plaintext_len, uint8_t* ciphertext) {
    static const uint8_t zero_iv[AES_BLOCK_SIZE] = { 0 };
    if (secret->protocol == PIN_PROTOCOL_V1) {
        crypto_aes256_cbc_encrypt(secret->key, zero_iv, plaintext, ciphertext, plaintext_len);
        return plaintext_len;
    }
    crypto_random(ciphertext, AES_BLOCK_SIZE);
    crypto_aes256_cbc_encrypt(secret->key + 32, ciphertext, plaintext, ciphertext + AES_BLOCK_SIZE, plaintext_len);
    return plaintext_len + AES_BLOCK_SIZE;
}

bool pin_protocol_decrypt(const PinSharedSecret* secret, const uint8_t* ciphertext, size_t ciphertext_len, uint8_t* plaintext, size_t* plaintext_len) {
    static const uint8_t zero_iv[AES_BLOCK_SIZE] = { 0 };
    if (secret->protocol == PIN_PROTOCOL_V1) {
        if (ciphertext_len == 0 || ciphertext_len % AES_BLOCK_SIZE != 0) {
            return false;
        }
        crypto_aes256_cbc_decrypt(secret->key, zero_iv, ciphertext, plaintext, ciphertext_len);
        *plaintext_len = ciphertext_len;
        return true;
    }
    if (ciphertext_len <= AES_BLOCK_SIZE || ciphertext_len % AES_BLOCK_SIZE != 0) {
        return false;
    }
    crypto_aes256_cbc_decrypt(secret->key + 32, ciphertext, ciphertext + AES_BLOCK_SIZE, plaintext, ciphertext_len - AES_BLOCK_SIZE);
    *plaintext_len = ciphertext_len - AES_BLOCK_SIZE;
    return true;
}

size_t pin_protocol_authenticate(uint8_t protocol, const uint8_t* key, size_t key_len, const uint8_t* message, size_t message_len, uint8_t out[32]) {
    hmac_sha256(key, key_len, message, message_len, out);
    return protocol == PIN_PROTOCOL_V1 ? 16 : 32;
}

bool pin_protocol_verify(uint8_t protocol, const uint8_t* key, size_t key_len, const uint8_t* message, size_t message_len, const uint8_t* signature, size_t signature_len) {
    uint8_t expected[32];
    size_t expected_len = pin_protocol_authenticate(protocol, key, key_len, message, message_len, expected);
    bool ok = signature_len == expected_len && crypto_equal(expected, signature, expected_len);
    crypto_zeroize(expected, sizeof(expected));
    return ok;
}
