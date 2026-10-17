// SPDX-License-Identifier: Apache-2.0
/**
 * Credential IDs and the keys derived from them.
 *
 * A credential ID (also the U2F key handle) is 50 bytes:
 *   version (1) | flags (1) | nonce (32) | tag (16)
 * where tag = HMAC-SHA256(K_mac, version | flags | nonce | rpIdHash)[0..16). The private key is
 * HMAC-SHA256(K_key, nonce | rpIdHash | retry) and the hmac-secret credRandom values are
 * HMAC-SHA256(K_hmac, nonce | uv). K_mac, K_key and K_hmac derive from the store's master secret.
 * Nothing but the master secret needs to be stored for a non-discoverable credential, and an ID
 * presented with the wrong RP fails the tag check without revealing anything.
 */
#pragma once

#include "crypto/crypto.h"
#include "store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t id[FIDO_CRED_ID_LEN];
    uint8_t rp_id_hash[32];
    uint8_t private_key[P256_PRIVATE_KEY_SIZE];
    uint8_t public_key[P256_PUBLIC_KEY_SIZE];
    bool public_key_valid;
    uint8_t cred_protect;
    bool hmac_secret;
    /** Created as a discoverable credential: only valid while its resident record exists, so
     *  deleting the record revokes it even though the keys derive from the master secret. */
    bool resident;
} FidoCredential;

/** Creates a new credential for the RP. Computes the public key. */
bool credential_create(const uint8_t rp_id_hash[32], uint8_t cred_protect, bool hmac_secret, bool resident, FidoCredential* out);

/**
 * Checks that @a id is a credential ID of this authenticator for the RP and derives its private
 * key. A discoverable credential whose resident record was deleted is reported as not ours.
 * The public key is not computed; see credential_compute_public_key().
 * @return false when the ID is not ours or doesn't belong to the RP
 */
bool credential_unwrap(const uint8_t* id, size_t id_len, const uint8_t rp_id_hash[32], FidoCredential* out);

bool credential_compute_public_key(FidoCredential* credential);

/** hmac-secret extension: the per-credential secret, one for UV and one for non-UV assertions. */
void credential_cred_random(const FidoCredential* credential, bool uv, uint8_t out[32]);

/** Wipes the key material. */
void credential_clear(FidoCredential* credential);

#ifdef __cplusplus
}
#endif
