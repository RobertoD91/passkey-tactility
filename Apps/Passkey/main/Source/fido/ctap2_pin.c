// SPDX-License-Identifier: Apache-2.0
// authenticatorClientPIN (CTAP 2.1 section 6.5).
#include "ctap2_internal.h"
#include "fido_hal.h"

#include <string.h>

#define SUBCOMMAND_GET_PIN_RETRIES 0x01
#define SUBCOMMAND_GET_KEY_AGREEMENT 0x02
#define SUBCOMMAND_SET_PIN 0x03
#define SUBCOMMAND_CHANGE_PIN 0x04
#define SUBCOMMAND_GET_PIN_TOKEN 0x05
#define SUBCOMMAND_GET_UV_RETRIES 0x07
#define SUBCOMMAND_GET_PIN_TOKEN_WITH_PERMISSIONS 0x09

#define PADDED_PIN_LEN 64

typedef struct {
    bool has_protocol;
    uint64_t protocol;
    bool has_subcommand;
    uint64_t subcommand;
    bool has_key_agreement;
    uint8_t key_agreement[P256_PUBLIC_KEY_SIZE];
    const uint8_t* pin_uv_auth_param;
    size_t pin_uv_auth_param_len;
    const uint8_t* new_pin_enc;
    size_t new_pin_enc_len;
    const uint8_t* pin_hash_enc;
    size_t pin_hash_enc_len;
    bool has_permissions;
    uint64_t permissions;
    const char* rp_id;
    size_t rp_id_len;
} PinRequest;

static uint8_t parse(CborReader* r, size_t count, PinRequest* req) {
    memset(req, 0, sizeof(*req));
    for (size_t i = 0; i < count; i++) {
        uint64_t key;
        int err = cbor_read_uint(r, &key);
        if (err != CBOR_OK) return (uint8_t)err;
        switch (key) {
            case 1: err = cbor_read_uint(r, &req->protocol); req->has_protocol = true; break;
            case 2: err = cbor_read_uint(r, &req->subcommand); req->has_subcommand = true; break;
            case 3: {
                uint8_t status = ctap2_read_cose_key(r, req->key_agreement);
                if (status != CTAP2_OK) return status;
                req->has_key_agreement = true;
                break;
            }
            case 4: err = cbor_read_bytes(r, &req->pin_uv_auth_param, &req->pin_uv_auth_param_len); break;
            case 5: err = cbor_read_bytes(r, &req->new_pin_enc, &req->new_pin_enc_len); break;
            case 6: err = cbor_read_bytes(r, &req->pin_hash_enc, &req->pin_hash_enc_len); break;
            case 9: err = cbor_read_uint(r, &req->permissions); req->has_permissions = true; break;
            case 10: err = cbor_read_text(r, &req->rp_id, &req->rp_id_len); break;
            default: err = cbor_skip_value(r); break;
        }
        if (err != CBOR_OK) return (uint8_t)err;
    }
    return CTAP2_OK;
}

static void store_pin_hash(const uint8_t* pin, size_t pin_len) {
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(pin, pin_len, digest);
    memcpy(fido_store.pin_hash, digest, sizeof(fido_store.pin_hash));
    crypto_zeroize(digest, sizeof(digest));
    fido_store.pin_set = true;
    fido_store.pin_retries = FIDO_PIN_MAX_RETRIES;
}

/** Decrypts newPinEnc and validates the PIN policy. @a pin receives the PIN, @a pin_len its length. */
static uint8_t decrypt_new_pin(const PinSharedSecret* secret, const PinRequest* req, uint8_t pin[PADDED_PIN_LEN], size_t* pin_len) {
    uint8_t padded[PADDED_PIN_LEN + AES_BLOCK_SIZE];
    size_t padded_len;
    if (!pin_protocol_decrypt(secret, req->new_pin_enc, req->new_pin_enc_len, padded, &padded_len) || padded_len != PADDED_PIN_LEN) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    size_t len = 0;
    while (len < PADDED_PIN_LEN && padded[len] != 0) {
        len++;
    }
    size_t code_points = 0;
    for (size_t i = 0; i < len; i++) {
        if ((padded[i] & 0xC0) != 0x80) {
            code_points++;
        }
    }
    if (code_points < fido_store.min_pin_length || code_points > FIDO_PIN_MAX_LENGTH || len == PADDED_PIN_LEN) {
        crypto_zeroize(padded, sizeof(padded));
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    memcpy(pin, padded, len);
    *pin_len = len;
    crypto_zeroize(padded, sizeof(padded));
    return CTAP2_OK;
}

static uint8_t pin_mismatch(void) {
    ctap2_regenerate_key_agreement();
    ctap2_session.pin_consecutive_mismatches++;
    if (fido_store.pin_retries == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }
    if (ctap2_session.pin_consecutive_mismatches >= FIDO_PIN_MAX_CONSECUTIVE_RETRIES) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    return CTAP2_ERR_PIN_INVALID;
}

/**
 * Shared by changePIN and the token subcommands: charges a retry, decrypts pinHashEnc and
 * compares it. On success the retry counter is restored.
 */
static uint8_t verify_pin_hash(const PinSharedSecret* secret, const PinRequest* req) {
    if (!fido_store.pin_set) {
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if (fido_store.pin_retries == 0) {
        return CTAP2_ERR_PIN_BLOCKED;
    }
    if (ctap2_session.pin_consecutive_mismatches >= FIDO_PIN_MAX_CONSECUTIVE_RETRIES) {
        return CTAP2_ERR_PIN_AUTH_BLOCKED;
    }
    if (req->pin_hash_enc == NULL) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    fido_store.pin_retries--;
    store_save();

    uint8_t pin_hash[AES_BLOCK_SIZE + 16];
    size_t pin_hash_len;
    bool decrypted = pin_protocol_decrypt(secret, req->pin_hash_enc, req->pin_hash_enc_len, pin_hash, &pin_hash_len);
    if (!decrypted || pin_hash_len != 16) {
        return pin_mismatch();
    }
    bool match = crypto_equal(pin_hash, fido_store.pin_hash, 16);
    crypto_zeroize(pin_hash, sizeof(pin_hash));
    if (!match) {
        return pin_mismatch();
    }
    fido_store.pin_retries = FIDO_PIN_MAX_RETRIES;
    ctap2_session.pin_consecutive_mismatches = 0;
    store_save();
    return CTAP2_OK;
}

static uint8_t issue_token(const PinSharedSecret* secret, uint8_t permissions, const char* rp_id, size_t rp_id_len, CborWriter* w) {
    PinToken* token = &ctap2_session.token;
    crypto_zeroize(token, sizeof(*token));
    crypto_random(token->value, sizeof(token->value));
    token->in_use = true;
    token->permissions = permissions;
    token->issued_at = fido_hal_millis();
    if (rp_id != NULL) {
        token->has_rp_id = true;
        sha256(rp_id, rp_id_len, token->rp_id_hash);
    }
    uint8_t encrypted[PIN_PROTOCOL_ENCRYPTED_SIZE(32)];
    size_t encrypted_len = pin_protocol_encrypt(secret, token->value, sizeof(token->value), encrypted);
    cbor_write_map(w, 1);
    cbor_write_uint(w, 0x02);
    cbor_write_bytes(w, encrypted, encrypted_len);
    return CTAP2_OK;
}

uint8_t ctap2_client_pin(CborReader* r, size_t map_count, CborWriter* w) {
    PinRequest req;
    uint8_t status = parse(r, map_count, &req);
    if (status != CTAP2_OK) {
        return status;
    }
    if (!req.has_subcommand) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    switch (req.subcommand) {
        case SUBCOMMAND_GET_PIN_RETRIES:
            cbor_write_map(w, 2);
            cbor_write_uint(w, 0x03);
            cbor_write_uint(w, fido_store.pin_retries);
            cbor_write_uint(w, 0x04);
            cbor_write_bool(w, ctap2_session.pin_consecutive_mismatches >= FIDO_PIN_MAX_CONSECUTIVE_RETRIES);
            return CTAP2_OK;

        case SUBCOMMAND_GET_UV_RETRIES:
            return CTAP2_ERR_INVALID_SUBCOMMAND;

        case SUBCOMMAND_GET_KEY_AGREEMENT:
            if (!req.has_protocol) return CTAP2_ERR_MISSING_PARAMETER;
            if (!pin_protocol_is_supported(req.protocol)) return CTAP1_ERR_INVALID_PARAMETER;
            cbor_write_map(w, 1);
            cbor_write_uint(w, 0x01);
            ctap2_write_cose_key(w, COSE_ALG_ECDH_ES_HKDF_256, ctap2_session.key_agreement_public);
            return CTAP2_OK;

        case SUBCOMMAND_SET_PIN:
        case SUBCOMMAND_CHANGE_PIN:
        case SUBCOMMAND_GET_PIN_TOKEN:
        case SUBCOMMAND_GET_PIN_TOKEN_WITH_PERMISSIONS:
            break;

        default:
            return CTAP2_ERR_INVALID_SUBCOMMAND;
    }

    // The remaining subcommands all need a protocol and a key agreement.
    if (!req.has_protocol || !req.has_key_agreement) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!pin_protocol_is_supported(req.protocol)) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    PinSharedSecret secret;
    if (!pin_protocol_shared_secret((uint8_t)req.protocol, ctap2_session.key_agreement_private, req.key_agreement, &secret)) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }

    uint8_t result;
    switch (req.subcommand) {
        case SUBCOMMAND_SET_PIN: {
            if (req.pin_uv_auth_param == NULL || req.new_pin_enc == NULL) {
                result = CTAP2_ERR_MISSING_PARAMETER;
                break;
            }
            if (fido_store.pin_set) {
                result = CTAP2_ERR_PIN_AUTH_INVALID;
                break;
            }
            if (!pin_protocol_verify((uint8_t)req.protocol, pin_protocol_hmac_key(&secret), 32, req.new_pin_enc, req.new_pin_enc_len, req.pin_uv_auth_param, req.pin_uv_auth_param_len)) {
                result = CTAP2_ERR_PIN_AUTH_INVALID;
                break;
            }
            uint8_t pin[PADDED_PIN_LEN];
            size_t pin_len;
            result = decrypt_new_pin(&secret, &req, pin, &pin_len);
            if (result != CTAP2_OK) break;
            store_pin_hash(pin, pin_len);
            crypto_zeroize(pin, sizeof(pin));
            result = store_save() ? CTAP2_OK : CTAP1_ERR_OTHER;
            fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
            break;
        }

        case SUBCOMMAND_CHANGE_PIN: {
            if (req.pin_uv_auth_param == NULL || req.new_pin_enc == NULL || req.pin_hash_enc == NULL) {
                result = CTAP2_ERR_MISSING_PARAMETER;
                break;
            }
            if (!fido_store.pin_set) {
                result = CTAP2_ERR_PIN_NOT_SET;
                break;
            }
            // pinUvAuthParam covers newPinEnc || pinHashEnc.
            uint8_t message[PIN_PROTOCOL_ENCRYPTED_SIZE(PADDED_PIN_LEN) + PIN_PROTOCOL_ENCRYPTED_SIZE(16)];
            if (req.new_pin_enc_len + req.pin_hash_enc_len > sizeof(message)) {
                result = CTAP1_ERR_INVALID_LENGTH;
                break;
            }
            memcpy(message, req.new_pin_enc, req.new_pin_enc_len);
            memcpy(message + req.new_pin_enc_len, req.pin_hash_enc, req.pin_hash_enc_len);
            if (!pin_protocol_verify((uint8_t)req.protocol, pin_protocol_hmac_key(&secret), 32, message, req.new_pin_enc_len + req.pin_hash_enc_len, req.pin_uv_auth_param, req.pin_uv_auth_param_len)) {
                result = CTAP2_ERR_PIN_AUTH_INVALID;
                break;
            }
            result = verify_pin_hash(&secret, &req);
            if (result != CTAP2_OK) break;
            uint8_t pin[PADDED_PIN_LEN];
            size_t pin_len;
            result = decrypt_new_pin(&secret, &req, pin, &pin_len);
            if (result != CTAP2_OK) break;
            store_pin_hash(pin, pin_len);
            crypto_zeroize(pin, sizeof(pin));
            ctap2_invalidate_token();
            result = store_save() ? CTAP2_OK : CTAP1_ERR_OTHER;
            fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
            break;
        }

        case SUBCOMMAND_GET_PIN_TOKEN: {
            if (req.has_permissions || req.rp_id != NULL) {
                result = CTAP1_ERR_INVALID_PARAMETER;
                break;
            }
            result = verify_pin_hash(&secret, &req);
            if (result != CTAP2_OK) break;
            result = issue_token(&secret, CTAP_PERMISSION_MC | CTAP_PERMISSION_GA, NULL, 0, w);
            break;
        }

        case SUBCOMMAND_GET_PIN_TOKEN_WITH_PERMISSIONS: {
            if (!req.has_permissions) {
                result = CTAP2_ERR_MISSING_PARAMETER;
                break;
            }
            if (req.permissions == 0 || req.permissions > 0xFF) {
                result = CTAP1_ERR_INVALID_PARAMETER;
                break;
            }
            uint8_t supported = CTAP_PERMISSION_MC | CTAP_PERMISSION_GA | CTAP_PERMISSION_CM;
            if ((req.permissions & ~supported) != 0) {
                result = CTAP2_ERR_UNAUTHORIZED_PERMISSION;
                break;
            }
            result = verify_pin_hash(&secret, &req);
            if (result != CTAP2_OK) break;
            result = issue_token(&secret, (uint8_t)req.permissions, req.rp_id, req.rp_id_len, w);
            break;
        }

        default:
            result = CTAP2_ERR_INVALID_SUBCOMMAND;
            break;
    }
    crypto_zeroize(&secret, sizeof(secret));
    return result;
}
