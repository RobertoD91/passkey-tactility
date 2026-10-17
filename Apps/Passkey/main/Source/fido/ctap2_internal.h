// SPDX-License-Identifier: Apache-2.0
/** Shared between the ctap2_*.c files. */
#pragma once

#include "cbor.h"
#include "credential.h"
#include "ctap_defs.h"
#include "fido.h"
#include "fido_config.h"
#include "pin_protocol.h"
#include "store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** pinUvAuthTokens expire this long after they were issued. */
#define PIN_TOKEN_LIFETIME_MS (10u * 60u * 1000u)

typedef struct {
    bool in_use;
    uint8_t value[32];
    uint8_t permissions;
    bool has_rp_id;
    uint8_t rp_id_hash[32];
    uint32_t issued_at;
} PinToken;

typedef struct {
    PinSharedSecret shared_secret;
    uint8_t salt[64];
    size_t salt_len;
} HmacSecretRequest;

typedef struct {
    uint8_t key_agreement_private[P256_PRIVATE_KEY_SIZE];
    uint8_t key_agreement_public[P256_PUBLIC_KEY_SIZE];
    PinToken token;
    uint8_t pin_consecutive_mismatches;

    struct {
        bool valid;
        uint32_t started_at;
        uint8_t rp_id_hash[32];
        uint8_t client_data_hash[32];
        uint8_t flags;
        bool uv;
        uint8_t indices[FIDO_MAX_RESIDENT_CREDENTIALS];
        uint8_t count;
        uint8_t next;
        bool hmac_secret;
        HmacSecretRequest hmac_secret_request;
    } next_assertion;

    struct {
        uint8_t rp_indices[FIDO_MAX_RESIDENT_CREDENTIALS];
        uint8_t rp_count;
        uint8_t rp_next;
        uint8_t rp_id_hash[32];
        uint8_t cred_indices[FIDO_MAX_RESIDENT_CREDENTIALS];
        uint8_t cred_count;
        uint8_t cred_next;
    } enumeration;
} Ctap2Session;

extern Ctap2Session ctap2_session;

void ctap2_regenerate_key_agreement(void);
void ctap2_invalidate_token(void);

/** Parses a COSE_Key map into an uncompressed P-256 point (X || Y). */
uint8_t ctap2_read_cose_key(CborReader* r, uint8_t public_key[P256_PUBLIC_KEY_SIZE]);

/** Writes a COSE_Key map for a P-256 key with the given algorithm. */
void ctap2_write_cose_key(CborWriter* w, int alg, const uint8_t public_key[P256_PUBLIC_KEY_SIZE]);

/**
 * Verifies pinUvAuthParam against the current pinUvAuthToken.
 * @param[in] rp_id_hash when non-NULL, the token must be unrestricted or bound to this RP
 * @return CTAP2_OK, or the status to return
 */
uint8_t ctap2_verify_pin_uv_auth(uint64_t protocol, const uint8_t* param, size_t param_len, const uint8_t* message, size_t message_len, uint8_t permission, const uint8_t* rp_id_hash);

/** Writes a user entity map: "id" always, "name"/"displayName" only when @a include_names. */
void ctap2_write_user(CborWriter* w, const FidoResidentCredential* c, bool include_names);

uint8_t ctap2_client_pin(CborReader* r, size_t map_count, CborWriter* w);
uint8_t ctap2_credential_management(CborReader* r, size_t map_count, CborWriter* w);

#ifdef __cplusplus
}
#endif
