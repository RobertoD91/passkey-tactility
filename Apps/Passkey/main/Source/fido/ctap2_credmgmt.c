// SPDX-License-Identifier: Apache-2.0
// authenticatorCredentialManagement (CTAP 2.1 section 6.8) and its preview (0x41).
#include "ctap2_internal.h"
#include "fido_hal.h"

#include <string.h>

#define SUBCOMMAND_GET_CREDS_METADATA 0x01
#define SUBCOMMAND_ENUMERATE_RPS_BEGIN 0x02
#define SUBCOMMAND_ENUMERATE_RPS_NEXT 0x03
#define SUBCOMMAND_ENUMERATE_CREDENTIALS_BEGIN 0x04
#define SUBCOMMAND_ENUMERATE_CREDENTIALS_NEXT 0x05
#define SUBCOMMAND_DELETE_CREDENTIAL 0x06
#define SUBCOMMAND_UPDATE_USER_INFORMATION 0x07

typedef struct {
    bool has_subcommand;
    uint64_t subcommand;
    bool has_params;
    const uint8_t* params_raw;
    size_t params_raw_len;
    bool has_protocol;
    uint64_t protocol;
    const uint8_t* pin_uv_auth_param;
    size_t pin_uv_auth_param_len;
} CmRequest;

typedef struct {
    const uint8_t* rp_id_hash;
    size_t rp_id_hash_len;
    const uint8_t* cred_id;
    size_t cred_id_len;
    const uint8_t* user_id;
    size_t user_id_len;
    const char* user_name;
    size_t user_name_len;
    const char* display_name;
    size_t display_name_len;
    bool has_user;
} CmParams;

static uint8_t parse(CborReader* r, size_t count, CmRequest* req) {
    memset(req, 0, sizeof(*req));
    for (size_t i = 0; i < count; i++) {
        uint64_t key;
        int err = cbor_read_uint(r, &key);
        if (err != CBOR_OK) return (uint8_t)err;
        switch (key) {
            case 1: err = cbor_read_uint(r, &req->subcommand); req->has_subcommand = true; break;
            case 2: {
                size_t size = cbor_value_size(r);
                if (size == 0) return CTAP2_ERR_INVALID_CBOR;
                req->params_raw = r->buf + r->pos;
                req->params_raw_len = size;
                req->has_params = true;
                err = cbor_skip_value(r);
                break;
            }
            case 3: err = cbor_read_uint(r, &req->protocol); req->has_protocol = true; break;
            case 4: err = cbor_read_bytes(r, &req->pin_uv_auth_param, &req->pin_uv_auth_param_len); break;
            default: err = cbor_skip_value(r); break;
        }
        if (err != CBOR_OK) return (uint8_t)err;
    }
    return CTAP2_OK;
}

static int parse_user(CborReader* r, CmParams* params) {
    size_t count;
    int err = cbor_read_map(r, &count);
    if (err != CBOR_OK) return err;
    params->has_user = true;
    for (size_t i = 0; i < count; i++) {
        const char* key;
        size_t key_len;
        err = cbor_read_text(r, &key, &key_len);
        if (err != CBOR_OK) return err;
        if (cbor_text_equals(key, key_len, "id")) {
            err = cbor_read_bytes(r, &params->user_id, &params->user_id_len);
        } else if (cbor_text_equals(key, key_len, "name")) {
            err = cbor_read_text(r, &params->user_name, &params->user_name_len);
        } else if (cbor_text_equals(key, key_len, "displayName")) {
            err = cbor_read_text(r, &params->display_name, &params->display_name_len);
        } else {
            err = cbor_skip_value(r);
        }
        if (err != CBOR_OK) return err;
    }
    return CBOR_OK;
}

static int parse_descriptor(CborReader* r, CmParams* params) {
    size_t count;
    int err = cbor_read_map(r, &count);
    if (err != CBOR_OK) return err;
    for (size_t i = 0; i < count; i++) {
        const char* key;
        size_t key_len;
        err = cbor_read_text(r, &key, &key_len);
        if (err != CBOR_OK) return err;
        if (cbor_text_equals(key, key_len, "id")) {
            err = cbor_read_bytes(r, &params->cred_id, &params->cred_id_len);
        } else {
            err = cbor_skip_value(r);
        }
        if (err != CBOR_OK) return err;
    }
    return CBOR_OK;
}

static uint8_t parse_params(const CmRequest* req, CmParams* params) {
    memset(params, 0, sizeof(*params));
    if (!req->has_params) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    CborReader r;
    cbor_reader_init(&r, req->params_raw, req->params_raw_len);
    size_t count;
    int err = cbor_read_map(&r, &count);
    if (err != CBOR_OK) return (uint8_t)err;
    for (size_t i = 0; i < count; i++) {
        uint64_t key;
        err = cbor_read_uint(&r, &key);
        if (err != CBOR_OK) return (uint8_t)err;
        switch (key) {
            case 1: err = cbor_read_bytes(&r, &params->rp_id_hash, &params->rp_id_hash_len); break;
            case 2: err = parse_descriptor(&r, params); break;
            case 3: err = parse_user(&r, params); break;
            default: err = cbor_skip_value(&r); break;
        }
        if (err != CBOR_OK) return (uint8_t)err;
    }
    return CTAP2_OK;
}

static uint8_t authenticate(const CmRequest* req) {
    if (req->pin_uv_auth_param == NULL || !req->has_protocol) {
        return CTAP2_ERR_PUAT_REQUIRED;
    }
    // The message is the subCommand byte followed by the raw subCommandParams, if any.
    uint8_t message[1 + FIDO_MAX_MSG_SIZE];
    message[0] = (uint8_t)req->subcommand;
    size_t message_len = 1;
    if (req->has_params) {
        if (req->params_raw_len > FIDO_MAX_MSG_SIZE) return CTAP2_ERR_REQUEST_TOO_LARGE;
        memcpy(message + 1, req->params_raw, req->params_raw_len);
        message_len += req->params_raw_len;
    }
    return ctap2_verify_pin_uv_auth(req->protocol, req->pin_uv_auth_param, req->pin_uv_auth_param_len, message, message_len, CTAP_PERMISSION_CM, NULL);
}

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

static void write_rp(CborWriter* w, const FidoResidentCredential* c, size_t total_rps) {
    bool has_name = c->rp_name[0] != '\0';
    cbor_write_map(w, total_rps > 0 ? 3 : 2);
    cbor_write_uint(w, 0x03);
    cbor_write_map(w, has_name ? 2 : 1);
    cbor_write_text(w, "id");
    cbor_write_text(w, c->rp_id);
    if (has_name) {
        cbor_write_text(w, "name");
        cbor_write_text(w, c->rp_name);
    }
    cbor_write_uint(w, 0x04);
    cbor_write_bytes(w, c->rp_id_hash, 32);
    if (total_rps > 0) {
        cbor_write_uint(w, 0x05);
        cbor_write_uint(w, total_rps);
    }
}

static uint8_t write_credential(CborWriter* w, const FidoResidentCredential* c, size_t total_credentials) {
    FidoCredential credential;
    if (!credential_unwrap(c->cred_id, FIDO_CRED_ID_LEN, c->rp_id_hash, &credential)) {
        return CTAP2_ERR_PROCESSING;
    }
    cbor_write_map(w, total_credentials > 0 ? 5 : 4);
    cbor_write_uint(w, 0x06);
    ctap2_write_user(w, c, true);
    cbor_write_uint(w, 0x07);
    cbor_write_map(w, 2);
    cbor_write_text(w, "id");
    cbor_write_bytes(w, c->cred_id, FIDO_CRED_ID_LEN);
    cbor_write_text(w, "type");
    cbor_write_text(w, "public-key");
    cbor_write_uint(w, 0x08);
    ctap2_write_cose_key(w, COSE_ALG_ES256, credential.public_key);
    if (total_credentials > 0) {
        cbor_write_uint(w, 0x09);
        cbor_write_uint(w, total_credentials);
    }
    cbor_write_uint(w, 0x0A);
    cbor_write_uint(w, c->cred_protect);
    credential_clear(&credential);
    return CTAP2_OK;
}

uint8_t ctap2_credential_management(CborReader* r, size_t map_count, CborWriter* w) {
    CmRequest req;
    uint8_t status = parse(r, map_count, &req);
    if (status != CTAP2_OK) {
        return status;
    }
    if (!req.has_subcommand) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    typeof(ctap2_session.enumeration)* e = &ctap2_session.enumeration;

    switch (req.subcommand) {
        case SUBCOMMAND_GET_CREDS_METADATA:
            status = authenticate(&req);
            if (status != CTAP2_OK) return status;
            cbor_write_map(w, 2);
            cbor_write_uint(w, 0x01);
            cbor_write_uint(w, fido_store.resident_count);
            cbor_write_uint(w, 0x02);
            cbor_write_uint(w, FIDO_MAX_RESIDENT_CREDENTIALS - fido_store.resident_count);
            return CTAP2_OK;

        case SUBCOMMAND_ENUMERATE_RPS_BEGIN: {
            status = authenticate(&req);
            if (status != CTAP2_OK) return status;
            e->rp_count = 0;
            for (size_t i = 0; i < fido_store.resident_count; i++) {
                bool seen = false;
                for (size_t j = 0; j < e->rp_count; j++) {
                    if (memcmp(fido_store.resident[e->rp_indices[j]].rp_id_hash, fido_store.resident[i].rp_id_hash, 32) == 0) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    e->rp_indices[e->rp_count++] = (uint8_t)i;
                }
            }
            if (e->rp_count == 0) return CTAP2_ERR_NO_CREDENTIALS;
            e->rp_next = 1;
            write_rp(w, &fido_store.resident[e->rp_indices[0]], e->rp_count);
            return CTAP2_OK;
        }

        case SUBCOMMAND_ENUMERATE_RPS_NEXT:
            if (e->rp_count == 0 || e->rp_next >= e->rp_count) return CTAP2_ERR_NOT_ALLOWED;
            write_rp(w, &fido_store.resident[e->rp_indices[e->rp_next++]], 0);
            return CTAP2_OK;

        case SUBCOMMAND_ENUMERATE_CREDENTIALS_BEGIN: {
            status = authenticate(&req);
            if (status != CTAP2_OK) return status;
            CmParams params;
            status = parse_params(&req, &params);
            if (status != CTAP2_OK) return status;
            if (params.rp_id_hash == NULL) return CTAP2_ERR_MISSING_PARAMETER;
            if (params.rp_id_hash_len != 32) return CTAP1_ERR_INVALID_LENGTH;
            memcpy(e->rp_id_hash, params.rp_id_hash, 32);
            e->cred_count = 0;
            for (size_t i = 0; i < fido_store.resident_count; i++) {
                if (memcmp(fido_store.resident[i].rp_id_hash, e->rp_id_hash, 32) == 0) {
                    e->cred_indices[e->cred_count++] = (uint8_t)i;
                }
            }
            if (e->cred_count == 0) return CTAP2_ERR_NO_CREDENTIALS;
            e->cred_next = 1;
            return write_credential(w, &fido_store.resident[e->cred_indices[0]], e->cred_count);
        }

        case SUBCOMMAND_ENUMERATE_CREDENTIALS_NEXT:
            if (e->cred_count == 0 || e->cred_next >= e->cred_count) return CTAP2_ERR_NOT_ALLOWED;
            return write_credential(w, &fido_store.resident[e->cred_indices[e->cred_next++]], 0);

        case SUBCOMMAND_DELETE_CREDENTIAL: {
            status = authenticate(&req);
            if (status != CTAP2_OK) return status;
            CmParams params;
            status = parse_params(&req, &params);
            if (status != CTAP2_OK) return status;
            if (params.cred_id == NULL) return CTAP2_ERR_MISSING_PARAMETER;
            int index = store_find_resident_by_id(params.cred_id, params.cred_id_len);
            if (index < 0) return CTAP2_ERR_NO_CREDENTIALS;
            store_delete_resident(index);
            // Indices into the resident list moved: stop any running enumeration.
            e->rp_count = 0;
            e->cred_count = 0;
            if (!store_save()) return CTAP1_ERR_OTHER;
            fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
            return CTAP2_OK;
        }

        case SUBCOMMAND_UPDATE_USER_INFORMATION: {
            status = authenticate(&req);
            if (status != CTAP2_OK) return status;
            CmParams params;
            status = parse_params(&req, &params);
            if (status != CTAP2_OK) return status;
            if (params.cred_id == NULL || !params.has_user || params.user_id == NULL) return CTAP2_ERR_MISSING_PARAMETER;
            int index = store_find_resident_by_id(params.cred_id, params.cred_id_len);
            if (index < 0) return CTAP2_ERR_NO_CREDENTIALS;
            FidoResidentCredential* c = &fido_store.resident[index];
            if (params.user_id_len != c->user_id_len || memcmp(params.user_id, c->user_id, c->user_id_len) != 0) {
                return CTAP1_ERR_INVALID_PARAMETER;
            }
            c->user_name[0] = '\0';
            c->display_name[0] = '\0';
            if (params.user_name != NULL) copy_text(c->user_name, sizeof(c->user_name), params.user_name, params.user_name_len);
            if (params.display_name != NULL) copy_text(c->display_name, sizeof(c->display_name), params.display_name, params.display_name_len);
            if (!store_save()) return CTAP1_ERR_OTHER;
            fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
            return CTAP2_OK;
        }

        default:
            return CTAP2_ERR_INVALID_SUBCOMMAND;
    }
}
