// SPDX-License-Identifier: Apache-2.0
#include "ctap2.h"

#include "ctap2_internal.h"
#include "ctaphid.h"
#include "fido_hal.h"

#include <string.h>

Ctap2Session ctap2_session;

static const uint8_t AAGUID[16] = FIDO_AAGUID;

// ---- Session ----

void ctap2_regenerate_key_agreement(void) {
    crypto_p256_keygen(ctap2_session.key_agreement_private, ctap2_session.key_agreement_public);
}

void ctap2_invalidate_token(void) {
    crypto_zeroize(&ctap2_session.token, sizeof(ctap2_session.token));
}

void ctap2_init(void) {
    crypto_zeroize(&ctap2_session, sizeof(ctap2_session));
    ctap2_regenerate_key_agreement();
}

void ctap2_tick(void) {
    uint32_t now = fido_hal_millis();
    if (ctap2_session.token.in_use && now - ctap2_session.token.issued_at > PIN_TOKEN_LIFETIME_MS) {
        ctap2_invalidate_token();
    }
    if (ctap2_session.next_assertion.valid && now - ctap2_session.next_assertion.started_at > FIDO_NEXT_ASSERTION_TIMEOUT_MS) {
        crypto_zeroize(&ctap2_session.next_assertion, sizeof(ctap2_session.next_assertion));
    }
}

// ---- Shared helpers ----

uint8_t ctap2_read_cose_key(CborReader* r, uint8_t public_key[P256_PUBLIC_KEY_SIZE]) {
    size_t count;
    int err = cbor_read_map(r, &count);
    if (err != CBOR_OK) return (uint8_t)err;
    bool have_x = false, have_y = false;
    for (size_t i = 0; i < count; i++) {
        int64_t key;
        err = cbor_read_int(r, &key);
        if (err != CBOR_OK) return (uint8_t)err;
        if (key == -2 || key == -3) {
            const uint8_t* data;
            size_t len;
            err = cbor_read_bytes(r, &data, &len);
            if (err != CBOR_OK) return (uint8_t)err;
            if (len != 32) return CTAP1_ERR_INVALID_PARAMETER;
            memcpy(public_key + (key == -2 ? 0 : 32), data, 32);
            if (key == -2) have_x = true; else have_y = true;
        } else if (key == 1 || key == -1) {
            int64_t value;
            err = cbor_read_int(r, &value);
            if (err != CBOR_OK) return (uint8_t)err;
            if ((key == 1 && value != COSE_KEY_TYPE_EC2) || (key == -1 && value != COSE_CURVE_P256)) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
        } else {
            err = cbor_skip_value(r);
            if (err != CBOR_OK) return (uint8_t)err;
        }
    }
    if (!have_x || !have_y) return CTAP2_ERR_MISSING_PARAMETER;
    return CTAP2_OK;
}

void ctap2_write_cose_key(CborWriter* w, int alg, const uint8_t public_key[P256_PUBLIC_KEY_SIZE]) {
    cbor_write_map(w, 5);
    cbor_write_int(w, 1);
    cbor_write_int(w, COSE_KEY_TYPE_EC2);
    cbor_write_int(w, 3);
    cbor_write_int(w, alg);
    cbor_write_int(w, -1);
    cbor_write_int(w, COSE_CURVE_P256);
    cbor_write_int(w, -2);
    cbor_write_bytes(w, public_key, 32);
    cbor_write_int(w, -3);
    cbor_write_bytes(w, public_key + 32, 32);
}

uint8_t ctap2_verify_pin_uv_auth(uint64_t protocol, const uint8_t* param, size_t param_len, const uint8_t* message, size_t message_len, uint8_t permission, const uint8_t* rp_id_hash) {
    if (!pin_protocol_is_supported(protocol)) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    PinToken* token = &ctap2_session.token;
    if (!token->in_use) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (!pin_protocol_verify((uint8_t)protocol, token->value, sizeof(token->value), message, message_len, param, param_len)) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if ((token->permissions & permission) == 0) {
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }
    if (rp_id_hash != NULL) {
        if (token->has_rp_id) {
            if (memcmp(token->rp_id_hash, rp_id_hash, 32) != 0) {
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
        } else if (permission == CTAP_PERMISSION_MC || permission == CTAP_PERMISSION_GA) {
            // A token without an RP binding becomes bound to the first RP that uses it.
            token->has_rp_id = true;
            memcpy(token->rp_id_hash, rp_id_hash, 32);
        }
    }
    return CTAP2_OK;
}

void ctap2_write_user(CborWriter* w, const FidoResidentCredential* c, bool include_names) {
    bool has_name = include_names && c->user_name[0] != '\0';
    bool has_display_name = include_names && c->display_name[0] != '\0';
    cbor_write_map(w, 1 + (has_name ? 1 : 0) + (has_display_name ? 1 : 0));
    cbor_write_text(w, "id");
    cbor_write_bytes(w, c->user_id, c->user_id_len);
    if (has_name) {
        cbor_write_text(w, "name");
        cbor_write_text(w, c->user_name);
    }
    if (has_display_name) {
        cbor_write_text(w, "displayName");
        cbor_write_text(w, c->display_name);
    }
}

// Copies a text item into a NUL-terminated buffer, truncating on a UTF-8 boundary.
static void copy_text(char* out, size_t out_size, const char* text, size_t len) {
    size_t max = out_size - 1;
    if (len > max) {
        len = max;
        while (len > 0 && (((uint8_t)text[len]) & 0xC0) == 0x80) {
            len--;
        }
    }
    memcpy(out, text, len);
    out[len] = '\0';
}

// ---- Request parsing ----

typedef struct {
    const uint8_t* client_data_hash;
    size_t client_data_hash_len;

    const char* rp_id;
    size_t rp_id_len;
    const char* rp_name;
    size_t rp_name_len;

    const uint8_t* user_id;
    size_t user_id_len;
    const char* user_name;
    size_t user_name_len;
    const char* display_name;
    size_t display_name_len;

    bool has_pub_key_cred_params;
    bool supports_es256;

    bool has_list; // excludeList (MC) or allowList (GA)
    CborReader list;
    size_t list_count;

    bool has_extensions;
    CborReader extensions;
    size_t extensions_count;

    bool has_rk, rk;
    bool has_up, up;
    bool has_uv, uv;

    bool has_pin_uv_auth_param;
    const uint8_t* pin_uv_auth_param;
    size_t pin_uv_auth_param_len;
    bool has_pin_uv_auth_protocol;
    uint64_t pin_uv_auth_protocol;
} CtapRequest;

static int parse_entity(CborReader* r, CtapRequest* req, bool is_user) {
    size_t count;
    int err = cbor_read_map(r, &count);
    if (err != CBOR_OK) return err;
    for (size_t i = 0; i < count; i++) {
        const char* key;
        size_t key_len;
        err = cbor_read_text(r, &key, &key_len);
        if (err != CBOR_OK) return err;
        if (cbor_text_equals(key, key_len, "id")) {
            if (is_user) {
                err = cbor_read_bytes(r, &req->user_id, &req->user_id_len);
            } else {
                err = cbor_read_text(r, &req->rp_id, &req->rp_id_len);
            }
        } else if (cbor_text_equals(key, key_len, "name")) {
            if (is_user) {
                err = cbor_read_text(r, &req->user_name, &req->user_name_len);
            } else {
                err = cbor_read_text(r, &req->rp_name, &req->rp_name_len);
            }
        } else if (is_user && cbor_text_equals(key, key_len, "displayName")) {
            err = cbor_read_text(r, &req->display_name, &req->display_name_len);
        } else {
            err = cbor_skip_value(r);
        }
        if (err != CBOR_OK) return err;
    }
    return CBOR_OK;
}

static int parse_pub_key_cred_params(CborReader* r, CtapRequest* req) {
    size_t count;
    int err = cbor_read_array(r, &count);
    if (err != CBOR_OK) return err;
    req->has_pub_key_cred_params = true;
    for (size_t i = 0; i < count; i++) {
        size_t fields;
        err = cbor_read_map(r, &fields);
        if (err != CBOR_OK) return err;
        bool has_alg = false, has_type = false, is_public_key = false;
        int64_t alg = 0;
        for (size_t f = 0; f < fields; f++) {
            const char* key;
            size_t key_len;
            err = cbor_read_text(r, &key, &key_len);
            if (err != CBOR_OK) return err;
            if (cbor_text_equals(key, key_len, "alg")) {
                err = cbor_read_int(r, &alg);
                has_alg = true;
            } else if (cbor_text_equals(key, key_len, "type")) {
                const char* type;
                size_t type_len;
                err = cbor_read_text(r, &type, &type_len);
                has_type = true;
                is_public_key = err == CBOR_OK && cbor_text_equals(type, type_len, "public-key");
            } else {
                err = cbor_skip_value(r);
            }
            if (err != CBOR_OK) return err;
        }
        if (!has_alg || !has_type) return CTAP2_ERR_MISSING_PARAMETER;
        if (is_public_key && alg == COSE_ALG_ES256) {
            req->supports_es256 = true;
        }
    }
    return CBOR_OK;
}

static int parse_options(CborReader* r, CtapRequest* req) {
    size_t count;
    int err = cbor_read_map(r, &count);
    if (err != CBOR_OK) return err;
    for (size_t i = 0; i < count; i++) {
        const char* key;
        size_t key_len;
        err = cbor_read_text(r, &key, &key_len);
        if (err != CBOR_OK) return err;
        bool value;
        if (cbor_text_equals(key, key_len, "rk")) {
            err = cbor_read_bool(r, &value);
            req->has_rk = true;
            req->rk = value;
        } else if (cbor_text_equals(key, key_len, "up")) {
            err = cbor_read_bool(r, &value);
            req->has_up = true;
            req->up = value;
        } else if (cbor_text_equals(key, key_len, "uv")) {
            err = cbor_read_bool(r, &value);
            req->has_uv = true;
            req->uv = value;
        } else {
            err = cbor_skip_value(r);
        }
        if (err != CBOR_OK) return err;
    }
    return CBOR_OK;
}

static int parse_request(const uint8_t* data, size_t len, bool is_make_credential, CtapRequest* req) {
    memset(req, 0, sizeof(*req));
    CborReader r;
    cbor_reader_init(&r, data, len);
    size_t count;
    int err = cbor_read_map(&r, &count);
    if (err != CBOR_OK) return err;
    for (size_t i = 0; i < count; i++) {
        uint64_t key;
        err = cbor_read_uint(&r, &key);
        if (err != CBOR_OK) return err;
        if (is_make_credential) {
            switch (key) {
                case 1: err = cbor_read_bytes(&r, &req->client_data_hash, &req->client_data_hash_len); break;
                case 2: err = parse_entity(&r, req, false); break;
                case 3: err = parse_entity(&r, req, true); break;
                case 4: err = parse_pub_key_cred_params(&r, req); break;
                case 5:
                    req->list = r;
                    err = cbor_read_array(&r, &req->list_count);
                    req->has_list = true;
                    if (err == CBOR_OK) err = cbor_skip_values(&r, req->list_count);
                    break;
                case 6:
                    req->extensions = r;
                    err = cbor_read_map(&r, &req->extensions_count);
                    req->has_extensions = true;
                    if (err == CBOR_OK) err = cbor_skip_values(&r, req->extensions_count * 2);
                    break;
                case 7: err = parse_options(&r, req); break;
                case 8:
                    err = cbor_read_bytes(&r, &req->pin_uv_auth_param, &req->pin_uv_auth_param_len);
                    req->has_pin_uv_auth_param = true;
                    break;
                case 9:
                    err = cbor_read_uint(&r, &req->pin_uv_auth_protocol);
                    req->has_pin_uv_auth_protocol = true;
                    break;
                default: err = cbor_skip_value(&r); break;
            }
        } else {
            switch (key) {
                case 1: err = cbor_read_text(&r, &req->rp_id, &req->rp_id_len); break;
                case 2: err = cbor_read_bytes(&r, &req->client_data_hash, &req->client_data_hash_len); break;
                case 3:
                    req->list = r;
                    err = cbor_read_array(&r, &req->list_count);
                    req->has_list = true;
                    if (err == CBOR_OK) err = cbor_skip_values(&r, req->list_count);
                    break;
                case 4:
                    req->extensions = r;
                    err = cbor_read_map(&r, &req->extensions_count);
                    req->has_extensions = true;
                    if (err == CBOR_OK) err = cbor_skip_values(&r, req->extensions_count * 2);
                    break;
                case 5: err = parse_options(&r, req); break;
                case 6:
                    err = cbor_read_bytes(&r, &req->pin_uv_auth_param, &req->pin_uv_auth_param_len);
                    req->has_pin_uv_auth_param = true;
                    break;
                case 7:
                    err = cbor_read_uint(&r, &req->pin_uv_auth_protocol);
                    req->has_pin_uv_auth_protocol = true;
                    break;
                default: err = cbor_skip_value(&r); break;
            }
        }
        if (err != CBOR_OK) return err;
    }
    return CBOR_OK;
}

/** Reads the next PublicKeyCredentialDescriptor of a list. Entries of other types yield id == NULL. */
static int read_descriptor(CborReader* r, const uint8_t** id, size_t* id_len) {
    *id = NULL;
    *id_len = 0;
    size_t fields;
    int err = cbor_read_map(r, &fields);
    if (err != CBOR_OK) return err;
    const uint8_t* found_id = NULL;
    size_t found_len = 0;
    bool has_type = false, is_public_key = false;
    for (size_t f = 0; f < fields; f++) {
        const char* key;
        size_t key_len;
        err = cbor_read_text(r, &key, &key_len);
        if (err != CBOR_OK) return err;
        if (cbor_text_equals(key, key_len, "id")) {
            err = cbor_read_bytes(r, &found_id, &found_len);
        } else if (cbor_text_equals(key, key_len, "type")) {
            const char* type;
            size_t type_len;
            err = cbor_read_text(r, &type, &type_len);
            has_type = true;
            is_public_key = err == CBOR_OK && cbor_text_equals(type, type_len, "public-key");
        } else {
            err = cbor_skip_value(r);
        }
        if (err != CBOR_OK) return err;
    }
    if (found_id == NULL || !has_type) return CTAP2_ERR_MISSING_PARAMETER;
    if (is_public_key) {
        *id = found_id;
        *id_len = found_len;
    }
    return CBOR_OK;
}

// ---- Authenticator data ----

static void put_counter(uint8_t* out, uint32_t counter) {
    out[0] = (uint8_t)(counter >> 24);
    out[1] = (uint8_t)(counter >> 16);
    out[2] = (uint8_t)(counter >> 8);
    out[3] = (uint8_t)counter;
}

static size_t build_auth_data(uint8_t* out, size_t cap, const uint8_t rp_id_hash[32], uint8_t flags, uint32_t counter, const FidoCredential* attested, const uint8_t* extensions, size_t extensions_len) {
    CborWriter w;
    cbor_writer_init(&w, out, cap);
    cbor_write_raw(&w, rp_id_hash, 32);
    cbor_write_raw(&w, &flags, 1);
    uint8_t counter_bytes[4];
    put_counter(counter_bytes, counter);
    cbor_write_raw(&w, counter_bytes, 4);
    if (attested != NULL) {
        cbor_write_raw(&w, AAGUID, sizeof(AAGUID));
        uint8_t id_len[2] = { 0, FIDO_CRED_ID_LEN };
        cbor_write_raw(&w, id_len, 2);
        cbor_write_raw(&w, attested->id, FIDO_CRED_ID_LEN);
        ctap2_write_cose_key(&w, COSE_ALG_ES256, attested->public_key);
    }
    if (extensions_len > 0) {
        cbor_write_raw(&w, extensions, extensions_len);
    }
    return cbor_writer_ok(&w) ? w.len : 0;
}

// ---- Pre-checks shared by makeCredential and getAssertion ----

/**
 * Handles pinUvAuthParam/pinUvAuthProtocol: the zero-length probe, protocol support, and when a
 * PIN is set, verification of the token. Sets *uv when the token was verified.
 */
static uint8_t check_pin_uv_auth(const CtapRequest* req, uint8_t permission, const uint8_t rp_id_hash[32], const char* rp_id, enum FidoUpReason probe_reason, bool* uv) {
    *uv = false;
    if (!req->has_pin_uv_auth_param) {
        return CTAP2_OK;
    }
    if (req->pin_uv_auth_param_len == 0) {
        // A platform probing whether the authenticator has a PIN: answer after user presence.
        enum FidoUpResult result = fido_request_user_presence(probe_reason, rp_id, NULL);
        if (result != FIDO_UP_RESULT_CONFIRMED) {
            return fido_up_result_to_status(result);
        }
        return fido_store.pin_set ? CTAP2_ERR_PIN_INVALID : CTAP2_ERR_PIN_NOT_SET;
    }
    if (!req->has_pin_uv_auth_protocol) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (!pin_protocol_is_supported(req->pin_uv_auth_protocol)) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!fido_store.pin_set) {
        return CTAP2_ERR_PIN_NOT_SET;
    }
    uint8_t status = ctap2_verify_pin_uv_auth(req->pin_uv_auth_protocol, req->pin_uv_auth_param, req->pin_uv_auth_param_len, req->client_data_hash, req->client_data_hash_len, permission, rp_id_hash);
    if (status != CTAP2_OK) {
        return status;
    }
    *uv = true;
    return CTAP2_OK;
}

// ---- getInfo ----

static uint8_t handle_get_info(CborWriter* w) {
    cbor_write_map(w, 13);

    cbor_write_uint(w, 0x01); // versions
    cbor_write_array(w, 3);
    cbor_write_text(w, "U2F_V2");
    cbor_write_text(w, "FIDO_2_0");
    cbor_write_text(w, "FIDO_2_1");

    cbor_write_uint(w, 0x02); // extensions
    cbor_write_array(w, 2);
    cbor_write_text(w, "credProtect");
    cbor_write_text(w, "hmac-secret");

    cbor_write_uint(w, 0x03); // aaguid
    cbor_write_bytes(w, AAGUID, sizeof(AAGUID));

    cbor_write_uint(w, 0x04); // options, in canonical key order (length, then bytewise)
    cbor_write_map(w, 9);
    cbor_write_text(w, "rk");
    cbor_write_bool(w, true);
    cbor_write_text(w, "up");
    cbor_write_bool(w, true);
    cbor_write_text(w, "plat");
    cbor_write_bool(w, false);
    cbor_write_text(w, "alwaysUv");
    cbor_write_bool(w, false);
    cbor_write_text(w, "credMgmt");
    cbor_write_bool(w, true);
    cbor_write_text(w, "clientPin");
    cbor_write_bool(w, fido_store.pin_set);
    cbor_write_text(w, "pinUvAuthToken");
    cbor_write_bool(w, true);
    cbor_write_text(w, "makeCredUvNotRqd");
    cbor_write_bool(w, true);
    cbor_write_text(w, "credentialMgmtPreview");
    cbor_write_bool(w, true);

    cbor_write_uint(w, 0x05); // maxMsgSize
    cbor_write_uint(w, FIDO_MAX_MSG_SIZE);

    cbor_write_uint(w, 0x06); // pinUvAuthProtocols, most preferred first
    cbor_write_array(w, 2);
    cbor_write_uint(w, PIN_PROTOCOL_V2);
    cbor_write_uint(w, PIN_PROTOCOL_V1);

    cbor_write_uint(w, 0x07); // maxCredentialCountInList
    cbor_write_uint(w, FIDO_MAX_CREDENTIAL_COUNT_IN_LIST);

    cbor_write_uint(w, 0x08); // maxCredentialIdLength
    cbor_write_uint(w, FIDO_MAX_CREDENTIAL_ID_LENGTH);

    cbor_write_uint(w, 0x09); // transports
    cbor_write_array(w, 1);
    cbor_write_text(w, "usb");

    cbor_write_uint(w, 0x0A); // algorithms
    cbor_write_array(w, 1);
    cbor_write_map(w, 2);
    cbor_write_text(w, "alg");
    cbor_write_int(w, COSE_ALG_ES256);
    cbor_write_text(w, "type");
    cbor_write_text(w, "public-key");

    cbor_write_uint(w, 0x0D); // minPINLength
    cbor_write_uint(w, fido_store.min_pin_length);

    cbor_write_uint(w, 0x0E); // firmwareVersion
    cbor_write_uint(w, FIDO_FIRMWARE_VERSION);

    cbor_write_uint(w, 0x14); // remainingDiscoverableCredentials
    cbor_write_uint(w, FIDO_MAX_RESIDENT_CREDENTIALS - fido_store.resident_count);

    return CTAP2_OK;
}

// ---- makeCredential ----

static uint8_t handle_make_credential(const uint8_t* data, size_t len, CborWriter* w) {
    CtapRequest req;
    int err = parse_request(data, len, true, &req);
    if (err != CBOR_OK) {
        return (uint8_t)err;
    }
    if (req.client_data_hash == NULL || req.rp_id == NULL || req.user_id == NULL || !req.has_pub_key_cred_params) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (req.client_data_hash_len != 32 || req.user_id_len == 0 || req.user_id_len > FIDO_MAX_USER_ID_LEN) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    char rp_id[FIDO_MAX_RP_ID_LEN + 1];
    copy_text(rp_id, sizeof(rp_id), req.rp_id, req.rp_id_len);
    uint8_t rp_id_hash[32];
    sha256(req.rp_id, req.rp_id_len, rp_id_hash);

    bool uv;
    uint8_t status = check_pin_uv_auth(&req, CTAP_PERMISSION_MC, rp_id_hash, rp_id, FIDO_UP_REASON_PIN_PROBE, &uv);
    if (status != CTAP2_OK) {
        return status;
    }
    if (!req.supports_es256) {
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
    }
    if (req.has_up && !req.up) {
        return CTAP2_ERR_INVALID_OPTION;
    }
    bool rk = req.has_rk && req.rk;
    if (req.has_uv && req.uv && !uv) {
        // No built-in user verification: "uv" is only satisfied through a pinUvAuthToken.
        return CTAP2_ERR_INVALID_OPTION;
    }
    if (fido_store.pin_set && !uv && rk) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }

    // Extensions
    bool want_hmac_secret = false;
    uint8_t cred_protect = CRED_PROTECT_UV_OPTIONAL;
    bool has_cred_protect = false;
    if (req.has_extensions) {
        CborReader r = req.extensions;
        size_t count;
        if (cbor_read_map(&r, &count) != CBOR_OK) return CTAP2_ERR_INVALID_CBOR;
        for (size_t i = 0; i < count; i++) {
            const char* key;
            size_t key_len;
            err = cbor_read_text(&r, &key, &key_len);
            if (err != CBOR_OK) return (uint8_t)err;
            if (cbor_text_equals(key, key_len, "hmac-secret")) {
                err = cbor_read_bool(&r, &want_hmac_secret);
            } else if (cbor_text_equals(key, key_len, "credProtect")) {
                uint64_t level;
                err = cbor_read_uint(&r, &level);
                if (err == CBOR_OK) {
                    if (level < CRED_PROTECT_UV_OPTIONAL || level > CRED_PROTECT_UV_REQUIRED) {
                        return CTAP1_ERR_INVALID_PARAMETER;
                    }
                    cred_protect = (uint8_t)level;
                    has_cred_protect = true;
                }
            } else {
                err = cbor_skip_value(&r);
            }
            if (err != CBOR_OK) return (uint8_t)err;
        }
    }

    // excludeList: a credential of ours for this RP means the user already registered here.
    if (req.has_list) {
        CborReader r = req.list;
        size_t count;
        if (cbor_read_array(&r, &count) != CBOR_OK) return CTAP2_ERR_INVALID_CBOR;
        for (size_t i = 0; i < count; i++) {
            const uint8_t* id;
            size_t id_len;
            err = read_descriptor(&r, &id, &id_len);
            if (err != CBOR_OK) return (uint8_t)err;
            if (id == NULL) continue;
            FidoCredential existing;
            if (credential_unwrap(id, id_len, rp_id_hash, &existing)) {
                bool visible = existing.cred_protect != CRED_PROTECT_UV_REQUIRED || uv;
                credential_clear(&existing);
                if (visible) {
                    enum FidoUpResult result = fido_request_user_presence(FIDO_UP_REASON_CREDENTIAL_EXCLUDED, rp_id, NULL);
                    if (result != FIDO_UP_RESULT_CONFIRMED) {
                        return fido_up_result_to_status(result);
                    }
                    return CTAP2_ERR_CREDENTIAL_EXCLUDED;
                }
            }
        }
    }

    char user_name[FIDO_MAX_USER_NAME_LEN + 1] = "";
    if (req.user_name != NULL) {
        copy_text(user_name, sizeof(user_name), req.user_name, req.user_name_len);
    }
    enum FidoUpResult up = fido_request_user_presence(FIDO_UP_REASON_MAKE_CREDENTIAL, rp_id, user_name[0] ? user_name : NULL);
    if (up != FIDO_UP_RESULT_CONFIRMED) {
        return fido_up_result_to_status(up);
    }

    FidoCredential credential;
    if (!credential_create(rp_id_hash, cred_protect, want_hmac_secret, rk, &credential)) {
        return CTAP2_ERR_PROCESSING;
    }

    if (rk) {
        FidoResidentCredential record;
        memset(&record, 0, sizeof(record));
        memcpy(record.cred_id, credential.id, FIDO_CRED_ID_LEN);
        memcpy(record.rp_id_hash, rp_id_hash, 32);
        copy_text(record.rp_id, sizeof(record.rp_id), req.rp_id, req.rp_id_len);
        if (req.rp_name != NULL) {
            copy_text(record.rp_name, sizeof(record.rp_name), req.rp_name, req.rp_name_len);
        }
        memcpy(record.user_id, req.user_id, req.user_id_len);
        record.user_id_len = (uint8_t)req.user_id_len;
        memcpy(record.user_name, user_name, sizeof(user_name));
        if (req.display_name != NULL) {
            copy_text(record.display_name, sizeof(record.display_name), req.display_name, req.display_name_len);
        }
        record.cred_protect = cred_protect;
        record.hmac_secret = want_hmac_secret;
        if (store_add_resident(&record) < 0) {
            credential_clear(&credential);
            return CTAP2_ERR_KEY_STORE_FULL;
        }
        crypto_zeroize(&record, sizeof(record));
    }

    uint32_t counter = fido_increment_counter();

    // Extension outputs, in canonical order (both keys are 11 bytes: 'c' < 'h').
    uint8_t ext_buf[32];
    size_t ext_len = 0;
    if (has_cred_protect || want_hmac_secret) {
        CborWriter ew;
        cbor_writer_init(&ew, ext_buf, sizeof(ext_buf));
        cbor_write_map(&ew, (has_cred_protect ? 1 : 0) + (want_hmac_secret ? 1 : 0));
        if (has_cred_protect) {
            cbor_write_text(&ew, "credProtect");
            cbor_write_uint(&ew, cred_protect);
        }
        if (want_hmac_secret) {
            cbor_write_text(&ew, "hmac-secret");
            cbor_write_bool(&ew, true);
        }
        ext_len = ew.len;
    }

    uint8_t flags = AUTHDATA_FLAG_UP | AUTHDATA_FLAG_AT | (uv ? AUTHDATA_FLAG_UV : 0) | (ext_len > 0 ? AUTHDATA_FLAG_ED : 0);
    uint8_t auth_data[256];
    size_t auth_data_len = build_auth_data(auth_data, sizeof(auth_data), rp_id_hash, flags, counter, &credential, ext_buf, ext_len);
    if (auth_data_len == 0) {
        credential_clear(&credential);
        return CTAP2_ERR_PROCESSING;
    }

    // Self attestation: the signature over authData || clientDataHash uses the credential key.
    uint8_t to_sign[sizeof(auth_data) + 32];
    memcpy(to_sign, auth_data, auth_data_len);
    memcpy(to_sign + auth_data_len, req.client_data_hash, 32);
    uint8_t signature[ECDSA_DER_MAX_SIZE];
    size_t signature_len;
    bool signed_ok = crypto_p256_sign_der(credential.private_key, to_sign, auth_data_len + 32, signature, &signature_len);
    credential_clear(&credential);
    if (!signed_ok) {
        return CTAP2_ERR_PROCESSING;
    }

    cbor_write_map(w, 3);
    cbor_write_uint(w, 0x01);
    cbor_write_text(w, "packed");
    cbor_write_uint(w, 0x02);
    cbor_write_bytes(w, auth_data, auth_data_len);
    cbor_write_uint(w, 0x03);
    cbor_write_map(w, 2);
    cbor_write_text(w, "alg");
    cbor_write_int(w, COSE_ALG_ES256);
    cbor_write_text(w, "sig");
    cbor_write_bytes(w, signature, signature_len);
    return CTAP2_OK;
}

// ---- getAssertion ----

static uint8_t parse_hmac_secret_request(CborReader* r, HmacSecretRequest* out) {
    size_t count;
    int err = cbor_read_map(r, &count);
    if (err != CBOR_OK) return (uint8_t)err;
    uint8_t platform_key[P256_PUBLIC_KEY_SIZE];
    bool has_key = false;
    const uint8_t* salt_enc = NULL;
    size_t salt_enc_len = 0;
    const uint8_t* salt_auth = NULL;
    size_t salt_auth_len = 0;
    uint64_t protocol = PIN_PROTOCOL_V1;
    for (size_t i = 0; i < count; i++) {
        uint64_t key;
        err = cbor_read_uint(r, &key);
        if (err != CBOR_OK) return (uint8_t)err;
        switch (key) {
            case 1: {
                uint8_t status = ctap2_read_cose_key(r, platform_key);
                if (status != CTAP2_OK) return status;
                has_key = true;
                break;
            }
            case 2: err = cbor_read_bytes(r, &salt_enc, &salt_enc_len); break;
            case 3: err = cbor_read_bytes(r, &salt_auth, &salt_auth_len); break;
            case 4: err = cbor_read_uint(r, &protocol); break;
            default: err = cbor_skip_value(r); break;
        }
        if (err != CBOR_OK) return (uint8_t)err;
    }
    if (!has_key || salt_enc == NULL || salt_auth == NULL) return CTAP2_ERR_MISSING_PARAMETER;
    if (!pin_protocol_is_supported(protocol)) return CTAP1_ERR_INVALID_PARAMETER;
    if (!pin_protocol_shared_secret((uint8_t)protocol, ctap2_session.key_agreement_private, platform_key, &out->shared_secret)) {
        return CTAP1_ERR_INVALID_PARAMETER;
    }
    if (!pin_protocol_verify((uint8_t)protocol, pin_protocol_hmac_key(&out->shared_secret), 32, salt_enc, salt_enc_len, salt_auth, salt_auth_len)) {
        return CTAP2_ERR_EXTENSION_FIRST;
    }
    uint8_t salt[64 + AES_BLOCK_SIZE];
    size_t salt_len;
    if (!pin_protocol_decrypt(&out->shared_secret, salt_enc, salt_enc_len, salt, &salt_len) || (salt_len != 32 && salt_len != 64)) {
        return CTAP1_ERR_INVALID_LENGTH;
    }
    memcpy(out->salt, salt, salt_len);
    out->salt_len = salt_len;
    crypto_zeroize(salt, sizeof(salt));
    return CTAP2_OK;
}

static size_t build_hmac_secret_output(const HmacSecretRequest* hs, const FidoCredential* credential, bool uv, uint8_t* out, size_t cap) {
    uint8_t cred_random[32];
    credential_cred_random(credential, uv, cred_random);
    uint8_t outputs[64];
    hmac_sha256(cred_random, sizeof(cred_random), hs->salt, 32, outputs);
    if (hs->salt_len == 64) {
        hmac_sha256(cred_random, sizeof(cred_random), hs->salt + 32, 32, outputs + 32);
    }
    crypto_zeroize(cred_random, sizeof(cred_random));
    uint8_t encrypted[64 + AES_BLOCK_SIZE];
    size_t encrypted_len = pin_protocol_encrypt(&hs->shared_secret, outputs, hs->salt_len, encrypted);
    crypto_zeroize(outputs, sizeof(outputs));

    CborWriter w;
    cbor_writer_init(&w, out, cap);
    cbor_write_map(&w, 1);
    cbor_write_text(&w, "hmac-secret");
    cbor_write_bytes(&w, encrypted, encrypted_len);
    return cbor_writer_ok(&w) ? w.len : 0;
}

/** Signs with @a credential and writes the assertion response map. */
static uint8_t write_assertion(CborWriter* w, const FidoCredential* credential, const FidoResidentCredential* resident, const uint8_t rp_id_hash[32], const uint8_t client_data_hash[32], uint8_t flags, bool uv, const HmacSecretRequest* hmac_secret, size_t number_of_credentials) {
    uint8_t ext_buf[96];
    size_t ext_len = 0;
    if (hmac_secret != NULL && credential->hmac_secret) {
        ext_len = build_hmac_secret_output(hmac_secret, credential, uv, ext_buf, sizeof(ext_buf));
        if (ext_len == 0) {
            return CTAP2_ERR_PROCESSING;
        }
        flags |= AUTHDATA_FLAG_ED;
    }

    uint32_t counter = fido_increment_counter();
    uint8_t auth_data[37 + sizeof(ext_buf)];
    size_t auth_data_len = build_auth_data(auth_data, sizeof(auth_data), rp_id_hash, flags, counter, NULL, ext_buf, ext_len);
    if (auth_data_len == 0) {
        return CTAP2_ERR_PROCESSING;
    }

    uint8_t to_sign[sizeof(auth_data) + 32];
    memcpy(to_sign, auth_data, auth_data_len);
    memcpy(to_sign + auth_data_len, client_data_hash, 32);
    uint8_t signature[ECDSA_DER_MAX_SIZE];
    size_t signature_len;
    if (!crypto_p256_sign_der(credential->private_key, to_sign, auth_data_len + 32, signature, &signature_len)) {
        return CTAP2_ERR_PROCESSING;
    }

    cbor_write_map(w, 3 + (resident != NULL ? 1 : 0) + (number_of_credentials > 1 ? 1 : 0));
    cbor_write_uint(w, 0x01);
    cbor_write_map(w, 2);
    cbor_write_text(w, "id");
    cbor_write_bytes(w, credential->id, FIDO_CRED_ID_LEN);
    cbor_write_text(w, "type");
    cbor_write_text(w, "public-key");
    cbor_write_uint(w, 0x02);
    cbor_write_bytes(w, auth_data, auth_data_len);
    cbor_write_uint(w, 0x03);
    cbor_write_bytes(w, signature, signature_len);
    if (resident != NULL) {
        cbor_write_uint(w, 0x04);
        // Names identify the user: only disclosed after user verification (or when there is a
        // single account, the platform shows it anyway).
        ctap2_write_user(w, resident, uv || number_of_credentials <= 1);
    }
    if (number_of_credentials > 1) {
        cbor_write_uint(w, 0x05);
        cbor_write_uint(w, number_of_credentials);
    }
    return CTAP2_OK;
}

static uint8_t handle_get_assertion(const uint8_t* data, size_t len, CborWriter* w) {
    CtapRequest req;
    int err = parse_request(data, len, false, &req);
    if (err != CBOR_OK) {
        return (uint8_t)err;
    }
    if (req.client_data_hash == NULL || req.rp_id == NULL) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (req.client_data_hash_len != 32) {
        return CTAP1_ERR_INVALID_LENGTH;
    }

    char rp_id[FIDO_MAX_RP_ID_LEN + 1];
    copy_text(rp_id, sizeof(rp_id), req.rp_id, req.rp_id_len);
    uint8_t rp_id_hash[32];
    sha256(req.rp_id, req.rp_id_len, rp_id_hash);

    bool uv;
    uint8_t status = check_pin_uv_auth(&req, CTAP_PERMISSION_GA, rp_id_hash, rp_id, FIDO_UP_REASON_PIN_PROBE, &uv);
    if (status != CTAP2_OK) {
        return status;
    }
    bool up = !req.has_up || req.up;
    if (req.has_uv && req.uv && !uv) {
        return CTAP2_ERR_INVALID_OPTION;
    }

    crypto_zeroize(&ctap2_session.next_assertion, sizeof(ctap2_session.next_assertion));

    // Extensions
    bool has_hmac_secret = false;
    HmacSecretRequest hmac_secret;
    memset(&hmac_secret, 0, sizeof(hmac_secret));
    if (req.has_extensions) {
        CborReader r = req.extensions;
        size_t count;
        if (cbor_read_map(&r, &count) != CBOR_OK) return CTAP2_ERR_INVALID_CBOR;
        for (size_t i = 0; i < count; i++) {
            const char* key;
            size_t key_len;
            err = cbor_read_text(&r, &key, &key_len);
            if (err != CBOR_OK) return (uint8_t)err;
            if (cbor_text_equals(key, key_len, "hmac-secret")) {
                status = parse_hmac_secret_request(&r, &hmac_secret);
                if (status != CTAP2_OK) return status;
                has_hmac_secret = true;
            } else {
                err = cbor_skip_value(&r);
                if (err != CBOR_OK) return (uint8_t)err;
            }
        }
    }

    // Locate credentials
    FidoCredential credential;
    bool found = false;
    const FidoResidentCredential* resident = NULL;
    size_t number_of_credentials = 0;

    if (req.has_list && req.list_count > 0) {
        CborReader r = req.list;
        size_t count;
        if (cbor_read_array(&r, &count) != CBOR_OK) return CTAP2_ERR_INVALID_CBOR;
        for (size_t i = 0; i < count && !found; i++) {
            const uint8_t* id;
            size_t id_len;
            err = read_descriptor(&r, &id, &id_len);
            if (err != CBOR_OK) return (uint8_t)err;
            if (id == NULL) continue;
            if (credential_unwrap(id, id_len, rp_id_hash, &credential)) {
                if (credential.cred_protect == CRED_PROTECT_UV_REQUIRED && !uv) {
                    credential_clear(&credential);
                    continue;
                }
                int index = store_find_resident_by_id(id, id_len);
                resident = index >= 0 ? &fido_store.resident[index] : NULL;
                found = true;
                number_of_credentials = 1;
            }
        }
    } else {
        // Discoverable credentials for this RP, newest first.
        uint8_t* indices = ctap2_session.next_assertion.indices;
        uint8_t count = 0;
        for (size_t i = 0; i < fido_store.resident_count; i++) {
            const FidoResidentCredential* c = &fido_store.resident[i];
            if (memcmp(c->rp_id_hash, rp_id_hash, 32) != 0) continue;
            if (c->cred_protect != CRED_PROTECT_UV_OPTIONAL && !uv) continue;
            uint8_t pos = count;
            while (pos > 0 && fido_store.resident[indices[pos - 1]].sequence < c->sequence) {
                indices[pos] = indices[pos - 1];
                pos--;
            }
            indices[pos] = (uint8_t)i;
            count++;
        }
        if (count > 0) {
            resident = &fido_store.resident[indices[0]];
            if (!credential_unwrap(resident->cred_id, FIDO_CRED_ID_LEN, rp_id_hash, &credential)) {
                return CTAP2_ERR_PROCESSING;
            }
            found = true;
            number_of_credentials = count;
            ctap2_session.next_assertion.count = count;
            ctap2_session.next_assertion.next = 1;
        }
    }

    if (!found) {
        if (up) {
            enum FidoUpResult result = fido_request_user_presence(FIDO_UP_REASON_NO_CREDENTIALS, rp_id, NULL);
            if (result != FIDO_UP_RESULT_CONFIRMED) {
                return fido_up_result_to_status(result);
            }
        }
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    uint8_t flags = uv ? AUTHDATA_FLAG_UV : 0;
    if (up) {
        enum FidoUpResult result = fido_request_user_presence(FIDO_UP_REASON_GET_ASSERTION, rp_id, resident != NULL ? resident->user_name : NULL);
        if (result != FIDO_UP_RESULT_CONFIRMED) {
            credential_clear(&credential);
            return fido_up_result_to_status(result);
        }
        flags |= AUTHDATA_FLAG_UP;
    }

    if (number_of_credentials > 1) {
        ctap2_session.next_assertion.valid = true;
        ctap2_session.next_assertion.started_at = fido_hal_millis();
        memcpy(ctap2_session.next_assertion.rp_id_hash, rp_id_hash, 32);
        memcpy(ctap2_session.next_assertion.client_data_hash, req.client_data_hash, 32);
        ctap2_session.next_assertion.flags = flags;
        ctap2_session.next_assertion.uv = uv;
        ctap2_session.next_assertion.hmac_secret = has_hmac_secret;
        if (has_hmac_secret) {
            ctap2_session.next_assertion.hmac_secret_request = hmac_secret;
        }
    }

    status = write_assertion(w, &credential, resident, rp_id_hash, req.client_data_hash, flags, uv, has_hmac_secret ? &hmac_secret : NULL, number_of_credentials);
    credential_clear(&credential);
    crypto_zeroize(&hmac_secret, sizeof(hmac_secret));
    return status;
}

static uint8_t handle_get_next_assertion(CborWriter* w) {
    typeof(ctap2_session.next_assertion)* na = &ctap2_session.next_assertion;
    if (!na->valid || na->next >= na->count || fido_hal_millis() - na->started_at > FIDO_NEXT_ASSERTION_TIMEOUT_MS) {
        crypto_zeroize(na, sizeof(*na));
        return CTAP2_ERR_NOT_ALLOWED;
    }
    const FidoResidentCredential* resident = &fido_store.resident[na->indices[na->next]];
    na->next++;
    FidoCredential credential;
    if (!credential_unwrap(resident->cred_id, FIDO_CRED_ID_LEN, na->rp_id_hash, &credential)) {
        return CTAP2_ERR_PROCESSING;
    }
    na->started_at = fido_hal_millis();
    uint8_t status = write_assertion(w, &credential, resident, na->rp_id_hash, na->client_data_hash, na->flags, na->uv, na->hmac_secret ? &na->hmac_secret_request : NULL, na->count);
    credential_clear(&credential);
    if (na->next >= na->count) {
        crypto_zeroize(na, sizeof(*na));
    }
    return status;
}

// ---- reset, selection ----

static uint8_t handle_reset(void) {
    enum FidoUpResult result = fido_request_user_presence(FIDO_UP_REASON_RESET, NULL, NULL);
    if (result != FIDO_UP_RESULT_CONFIRMED) {
        return fido_up_result_to_status(result);
    }
    if (!store_reset()) {
        return CTAP2_ERR_PROCESSING;
    }
    fido_on_state_reset();
    return CTAP2_OK;
}

static uint8_t handle_selection(void) {
    return fido_up_result_to_status(fido_request_user_presence(FIDO_UP_REASON_SELECTION, NULL, NULL));
}

// ---- Dispatcher ----

uint8_t ctap2_handle(const uint8_t* request, size_t request_len, uint8_t* response, size_t response_cap, size_t* response_len) {
    CborWriter w;
    cbor_writer_init(&w, response, response_cap);
    *response_len = 0;
    uint8_t command = request[0];
    const uint8_t* params = request + 1;
    size_t params_len = request_len - 1;
    uint8_t status;

    switch (command) {
        case CTAP2_CMD_GET_INFO:
            status = handle_get_info(&w);
            break;
        case CTAP2_CMD_MAKE_CREDENTIAL:
            ctaphid_send_keepalive(ctaphid_get_active_cid(), CTAPHID_STATUS_PROCESSING);
            status = handle_make_credential(params, params_len, &w);
            break;
        case CTAP2_CMD_GET_ASSERTION:
            ctaphid_send_keepalive(ctaphid_get_active_cid(), CTAPHID_STATUS_PROCESSING);
            status = handle_get_assertion(params, params_len, &w);
            break;
        case CTAP2_CMD_GET_NEXT_ASSERTION:
            status = handle_get_next_assertion(&w);
            break;
        case CTAP2_CMD_CLIENT_PIN: {
            CborReader r;
            cbor_reader_init(&r, params, params_len);
            size_t count;
            int err = cbor_read_map(&r, &count);
            status = err != CBOR_OK ? (uint8_t)err : ctap2_client_pin(&r, count, &w);
            break;
        }
        case CTAP2_CMD_RESET:
            status = handle_reset();
            break;
        case CTAP2_CMD_CREDENTIAL_MANAGEMENT:
        case CTAP2_CMD_CREDENTIAL_MANAGEMENT_PREVIEW: {
            CborReader r;
            cbor_reader_init(&r, params, params_len);
            size_t count;
            int err = cbor_read_map(&r, &count);
            status = err != CBOR_OK ? (uint8_t)err : ctap2_credential_management(&r, count, &w);
            break;
        }
        case CTAP2_CMD_SELECTION:
            status = handle_selection();
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            break;
    }

    if (status == CTAP2_OK && !cbor_writer_ok(&w)) {
        status = CTAP2_ERR_REQUEST_TOO_LARGE;
    }
    *response_len = status == CTAP2_OK ? w.len : 0;
    return status;
}
