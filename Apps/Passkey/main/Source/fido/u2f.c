// SPDX-License-Identifier: Apache-2.0
#include "u2f.h"

#include "credential.h"
#include "ctap_defs.h"
#include "fido.h"
#include "fido_hal.h"

#include <string.h>

typedef struct {
    uint8_t* buf;
    size_t cap;
    size_t len;
    bool overflow;
} Response;

static void append(Response* r, const void* data, size_t len) {
    if (r->len + len > r->cap) {
        r->overflow = true;
        return;
    }
    memcpy(r->buf + r->len, data, len);
    r->len += len;
}

static void append_byte(Response* r, uint8_t byte) {
    append(r, &byte, 1);
}

static void finish(Response* r, uint16_t sw) {
    if (r->overflow) {
        r->len = 0;
        sw = CTAP1_ERR_OTHER; // never a valid SW; replaced below
    }
    if (sw == CTAP1_ERR_OTHER) {
        sw = U2F_SW_WRONG_LENGTH;
    }
    uint8_t status[2] = { (uint8_t)(sw >> 8), (uint8_t)sw };
    r->overflow = false;
    append(r, status, 2);
}

static uint16_t handle_register(const uint8_t* data, size_t len, Response* r) {
    if (len != 64) {
        return U2F_SW_WRONG_LENGTH;
    }
    const uint8_t* challenge = data;
    const uint8_t* application = data + 32;

    if (!fido_u2f_test_user_presence(FIDO_UP_REASON_U2F_REGISTER)) {
        return U2F_SW_CONDITIONS_NOT_SATISFIED;
    }

    FidoCredential credential;
    if (!credential_create(application, CRED_PROTECT_UV_OPTIONAL, false, false, &credential)) {
        return U2F_SW_WRONG_DATA;
    }

    size_t certificate_len;
    const uint8_t* certificate = fido_attestation_certificate(&certificate_len);
    if (certificate_len == 0) {
        credential_clear(&credential);
        return U2F_SW_WRONG_DATA;
    }

    // Signed: 0x00 | application | challenge | key handle | 0x04 | public key
    uint8_t to_sign[1 + 32 + 32 + FIDO_CRED_ID_LEN + 1 + P256_PUBLIC_KEY_SIZE];
    size_t pos = 0;
    to_sign[pos++] = 0x00;
    memcpy(to_sign + pos, application, 32);
    pos += 32;
    memcpy(to_sign + pos, challenge, 32);
    pos += 32;
    memcpy(to_sign + pos, credential.id, FIDO_CRED_ID_LEN);
    pos += FIDO_CRED_ID_LEN;
    to_sign[pos++] = 0x04;
    memcpy(to_sign + pos, credential.public_key, P256_PUBLIC_KEY_SIZE);
    pos += P256_PUBLIC_KEY_SIZE;

    uint8_t signature[ECDSA_DER_MAX_SIZE];
    size_t signature_len;
    bool signed_ok = crypto_p256_sign_der(fido_attestation_private_key(), to_sign, pos, signature, &signature_len);
    if (!signed_ok) {
        credential_clear(&credential);
        return U2F_SW_WRONG_DATA;
    }

    append_byte(r, 0x05);
    append_byte(r, 0x04);
    append(r, credential.public_key, P256_PUBLIC_KEY_SIZE);
    append_byte(r, FIDO_CRED_ID_LEN);
    append(r, credential.id, FIDO_CRED_ID_LEN);
    append(r, certificate, certificate_len);
    append(r, signature, signature_len);
    credential_clear(&credential);
    return U2F_SW_NO_ERROR;
}

static uint16_t handle_authenticate(uint8_t control, const uint8_t* data, size_t len, Response* r) {
    if (len < 65) {
        return U2F_SW_WRONG_LENGTH;
    }
    const uint8_t* challenge = data;
    const uint8_t* application = data + 32;
    size_t handle_len = data[64];
    if (len != 65 + handle_len) {
        return U2F_SW_WRONG_LENGTH;
    }
    const uint8_t* handle = data + 65;

    FidoCredential credential;
    if (!credential_unwrap(handle, handle_len, application, &credential)) {
        return U2F_SW_WRONG_DATA;
    }
    // A credential that requires user verification can't be used over U2F, which has none.
    if (credential.cred_protect == CRED_PROTECT_UV_REQUIRED) {
        credential_clear(&credential);
        return U2F_SW_WRONG_DATA;
    }

    uint8_t flags;
    switch (control) {
        case U2F_AUTH_CHECK_ONLY:
            credential_clear(&credential);
            return U2F_SW_CONDITIONS_NOT_SATISFIED;
        case U2F_AUTH_ENFORCE:
            if (!fido_u2f_test_user_presence(FIDO_UP_REASON_U2F_AUTHENTICATE)) {
                credential_clear(&credential);
                return U2F_SW_CONDITIONS_NOT_SATISFIED;
            }
            flags = AUTHDATA_FLAG_UP;
            break;
        case U2F_AUTH_DONT_ENFORCE:
            flags = 0;
            break;
        default:
            credential_clear(&credential);
            return U2F_SW_WRONG_DATA;
    }

    uint32_t counter = fido_increment_counter();
    uint8_t counter_bytes[4] = { (uint8_t)(counter >> 24), (uint8_t)(counter >> 16), (uint8_t)(counter >> 8), (uint8_t)counter };

    // Signed: application | flags | counter | challenge
    uint8_t to_sign[32 + 1 + 4 + 32];
    memcpy(to_sign, application, 32);
    to_sign[32] = flags;
    memcpy(to_sign + 33, counter_bytes, 4);
    memcpy(to_sign + 37, challenge, 32);

    uint8_t signature[ECDSA_DER_MAX_SIZE];
    size_t signature_len;
    bool signed_ok = crypto_p256_sign_der(credential.private_key, to_sign, sizeof(to_sign), signature, &signature_len);
    credential_clear(&credential);
    if (!signed_ok) {
        return U2F_SW_WRONG_DATA;
    }

    append_byte(r, flags);
    append(r, counter_bytes, 4);
    append(r, signature, signature_len);
    return U2F_SW_NO_ERROR;
}

void u2f_handle_apdu(const uint8_t* apdu, size_t len, uint8_t* response, size_t cap, size_t* response_len) {
    Response r = { response, cap, 0, false };
    uint16_t sw;

    if (len < 4) {
        sw = U2F_SW_WRONG_LENGTH;
    } else {
        uint8_t cla = apdu[0];
        uint8_t ins = apdu[1];
        uint8_t p1 = apdu[2];
        const uint8_t* data = NULL;
        size_t data_len = 0;
        bool length_ok = true;

        if (len > 4) {
            if (apdu[4] != 0 || len < 7) {
                // Short APDU: Lc in one byte, optional Le after the data.
                data_len = apdu[4];
                data = apdu + 5;
                length_ok = len >= 5 + data_len;
            } else {
                // Extended APDU: 0x00 then a two-byte Lc, optional two-byte Le after the data.
                data_len = (size_t)((apdu[5] << 8) | apdu[6]);
                data = apdu + 7;
                length_ok = len >= 7 + data_len;
            }
        }

        if (!length_ok) {
            sw = U2F_SW_WRONG_LENGTH;
        } else if (cla != 0x00) {
            sw = U2F_SW_CLA_NOT_SUPPORTED;
        } else {
            switch (ins) {
                case U2F_INS_REGISTER:
                    sw = handle_register(data, data_len, &r);
                    break;
                case U2F_INS_AUTHENTICATE:
                    sw = handle_authenticate(p1, data, data_len, &r);
                    break;
                case U2F_INS_VERSION:
                    if (data_len != 0) {
                        sw = U2F_SW_WRONG_LENGTH;
                    } else {
                        append(&r, "U2F_V2", 6);
                        sw = U2F_SW_NO_ERROR;
                    }
                    break;
                default:
                    sw = U2F_SW_INS_NOT_SUPPORTED;
                    break;
            }
        }
    }

    if (sw != U2F_SW_NO_ERROR) {
        r.len = 0;
    }
    finish(&r, sw);
    *response_len = r.len;
}
