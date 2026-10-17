// SPDX-License-Identifier: Apache-2.0
#include "credential.h"

#include "ctap_defs.h"

#include <string.h>

#define CRED_ID_VERSION 0x01
#define CRED_FLAG_HMAC_SECRET 0x01
#define CRED_FLAG_PROTECT_SHIFT 1
#define CRED_FLAG_PROTECT_MASK 0x06
#define CRED_FLAG_RESIDENT 0x08

#define OFFSET_VERSION 0
#define OFFSET_FLAGS 1
#define OFFSET_NONCE 2
#define OFFSET_TAG 34
#define NONCE_LEN 32
#define TAG_LEN 16

static void derive_subkey(const char* label, uint8_t out[32]) {
    hmac_sha256(fido_store.master_secret, sizeof(fido_store.master_secret), label, strlen(label), out);
}

static void compute_tag(const uint8_t* id, const uint8_t rp_id_hash[32], uint8_t tag[32]) {
    uint8_t k_mac[32];
    derive_subkey("tactility-passkey cred mac", k_mac);
    HmacSha256Ctx ctx;
    hmac_sha256_init(&ctx, k_mac, sizeof(k_mac));
    hmac_sha256_update(&ctx, id, OFFSET_TAG);
    hmac_sha256_update(&ctx, rp_id_hash, 32);
    hmac_sha256_final(&ctx, tag);
    crypto_zeroize(k_mac, sizeof(k_mac));
}

// Derives the private key and, as a by-product of validating it, the public key.
static void derive_keys(FidoCredential* credential) {
    uint8_t k_key[32];
    derive_subkey("tactility-passkey cred key", k_key);
    for (uint8_t retry = 0;; retry++) {
        HmacSha256Ctx ctx;
        hmac_sha256_init(&ctx, k_key, sizeof(k_key));
        hmac_sha256_update(&ctx, credential->id + OFFSET_NONCE, NONCE_LEN);
        hmac_sha256_update(&ctx, credential->rp_id_hash, 32);
        hmac_sha256_update(&ctx, &retry, 1);
        hmac_sha256_final(&ctx, credential->private_key);
        // Rejects the negligible fraction of candidates that aren't valid scalars, deterministically.
        if (crypto_p256_public_key(credential->private_key, credential->public_key)) {
            credential->public_key_valid = true;
            break;
        }
    }
    crypto_zeroize(k_key, sizeof(k_key));
}

static void fill_from_id(FidoCredential* credential) {
    uint8_t flags = credential->id[OFFSET_FLAGS];
    credential->hmac_secret = (flags & CRED_FLAG_HMAC_SECRET) != 0;
    credential->resident = (flags & CRED_FLAG_RESIDENT) != 0;
    credential->cred_protect = (flags & CRED_FLAG_PROTECT_MASK) >> CRED_FLAG_PROTECT_SHIFT;
    if (credential->cred_protect == 0) {
        credential->cred_protect = CRED_PROTECT_UV_OPTIONAL;
    }
}

bool credential_create(const uint8_t rp_id_hash[32], uint8_t cred_protect, bool hmac_secret, bool resident, FidoCredential* out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->rp_id_hash, rp_id_hash, 32);
    out->id[OFFSET_VERSION] = CRED_ID_VERSION;
    out->id[OFFSET_FLAGS] = (uint8_t)((hmac_secret ? CRED_FLAG_HMAC_SECRET : 0) | (resident ? CRED_FLAG_RESIDENT : 0) | ((cred_protect << CRED_FLAG_PROTECT_SHIFT) & CRED_FLAG_PROTECT_MASK));
    crypto_random(out->id + OFFSET_NONCE, NONCE_LEN);
    uint8_t tag[32];
    compute_tag(out->id, rp_id_hash, tag);
    memcpy(out->id + OFFSET_TAG, tag, TAG_LEN);
    fill_from_id(out);
    derive_keys(out);
    return out->public_key_valid;
}

bool credential_unwrap(const uint8_t* id, size_t id_len, const uint8_t rp_id_hash[32], FidoCredential* out) {
    if (id_len != FIDO_CRED_ID_LEN || id[OFFSET_VERSION] != CRED_ID_VERSION) {
        return false;
    }
    uint8_t tag[32];
    compute_tag(id, rp_id_hash, tag);
    if (!crypto_equal(tag, id + OFFSET_TAG, TAG_LEN)) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    memcpy(out->id, id, FIDO_CRED_ID_LEN);
    memcpy(out->rp_id_hash, rp_id_hash, 32);
    fill_from_id(out);
    if (out->resident && store_find_resident_by_id(id, id_len) < 0) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    derive_keys(out);
    return true;
}

bool credential_compute_public_key(FidoCredential* credential) {
    if (!credential->public_key_valid) {
        credential->public_key_valid = crypto_p256_public_key(credential->private_key, credential->public_key);
    }
    return credential->public_key_valid;
}

void credential_cred_random(const FidoCredential* credential, bool uv, uint8_t out[32]) {
    uint8_t k_hmac[32];
    derive_subkey("tactility-passkey hmac-secret", k_hmac);
    uint8_t uv_byte = uv ? 1 : 0;
    HmacSha256Ctx ctx;
    hmac_sha256_init(&ctx, k_hmac, sizeof(k_hmac));
    hmac_sha256_update(&ctx, credential->id + OFFSET_NONCE, NONCE_LEN);
    hmac_sha256_update(&ctx, &uv_byte, 1);
    hmac_sha256_final(&ctx, out);
    crypto_zeroize(k_hmac, sizeof(k_hmac));
}

void credential_clear(FidoCredential* credential) {
    crypto_zeroize(credential, sizeof(*credential));
}
