// SPDX-License-Identifier: Apache-2.0
#include "x509.h"

#include "crypto/crypto.h"

#include <string.h>

// DER length for the sizes used here (< 65536).
static size_t der_length(size_t len, uint8_t* out) {
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        return 1;
    }
    if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    out[0] = 0x82;
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)len;
    return 3;
}

/** Wraps @a content (already in @a buf at offset content_offset) into tag + length, shifting as needed.
 *  Returns the total size of the wrapped element written at @a out_offset... simplified: builds into a scratch. */
static size_t der_wrap(uint8_t tag, const uint8_t* content, size_t content_len, uint8_t* out, size_t cap) {
    uint8_t length_bytes[3];
    size_t length_len = der_length(content_len, length_bytes);
    size_t total = 1 + length_len + content_len;
    if (total > cap) {
        return 0;
    }
    out[0] = tag;
    memcpy(out + 1, length_bytes, length_len);
    memmove(out + 1 + length_len, content, content_len);
    return total;
}

static const uint8_t OID_ECDSA_WITH_SHA256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
static const uint8_t OID_EC_PUBLIC_KEY[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OID_PRIME256V1[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_COMMON_NAME[] = { 0x06, 0x03, 0x55, 0x04, 0x03 };
static const char COMMON_NAME[] = "Tactility Passkey";

static size_t build_name(uint8_t* out, size_t cap) {
    uint8_t attribute[64];
    size_t pos = 0;
    memcpy(attribute + pos, OID_COMMON_NAME, sizeof(OID_COMMON_NAME));
    pos += sizeof(OID_COMMON_NAME);
    attribute[pos++] = 0x0C; // UTF8String
    attribute[pos++] = (uint8_t)(sizeof(COMMON_NAME) - 1);
    memcpy(attribute + pos, COMMON_NAME, sizeof(COMMON_NAME) - 1);
    pos += sizeof(COMMON_NAME) - 1;

    uint8_t sequence[64];
    size_t sequence_len = der_wrap(0x30, attribute, pos, sequence, sizeof(sequence));
    uint8_t set[64];
    size_t set_len = der_wrap(0x31, sequence, sequence_len, set, sizeof(set));
    return der_wrap(0x30, set, set_len, out, cap);
}

static size_t build_tbs(const uint8_t public_key[64], uint8_t* out, size_t cap) {
    uint8_t tbs[320];
    size_t pos = 0;

    // version [0] EXPLICIT INTEGER 2 (v3)
    static const uint8_t version[] = { 0xA0, 0x03, 0x02, 0x01, 0x02 };
    memcpy(tbs + pos, version, sizeof(version));
    pos += sizeof(version);

    // serialNumber: derived from the public key so every device has its own. The first byte is
    // kept positive and non-zero so the INTEGER is minimal DER without a leading zero.
    tbs[pos++] = 0x02;
    tbs[pos++] = 0x08;
    memcpy(tbs + pos, public_key, 8);
    tbs[pos] = (uint8_t)((tbs[pos] & 0x7F) | 0x01);
    pos += 8;

    // signature AlgorithmIdentifier
    tbs[pos++] = 0x30;
    tbs[pos++] = sizeof(OID_ECDSA_WITH_SHA256);
    memcpy(tbs + pos, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    pos += sizeof(OID_ECDSA_WITH_SHA256);

    // issuer
    pos += build_name(tbs + pos, sizeof(tbs) - pos);

    // validity: UTCTime 2026-01-01 .. 2049-12-31
    static const uint8_t validity[] = {
        0x30, 0x1E,
        0x17, 0x0D, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z',
        0x17, 0x0D, '4', '9', '1', '2', '3', '1', '2', '3', '5', '9', '5', '9', 'Z',
    };
    memcpy(tbs + pos, validity, sizeof(validity));
    pos += sizeof(validity);

    // subject (same as issuer)
    pos += build_name(tbs + pos, sizeof(tbs) - pos);

    // subjectPublicKeyInfo
    static const uint8_t spki_header[] = {
        0x30, 0x59,
        0x30, 0x13,
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04,
    };
    (void)OID_EC_PUBLIC_KEY;
    (void)OID_PRIME256V1;
    memcpy(tbs + pos, spki_header, sizeof(spki_header));
    pos += sizeof(spki_header);
    memcpy(tbs + pos, public_key, 64);
    pos += 64;

    return der_wrap(0x30, tbs, pos, out, cap);
}

size_t x509_build_self_signed(const uint8_t private_key[32], const uint8_t public_key[64], uint8_t* out, size_t cap) {
    uint8_t body[X509_MAX_SIZE];
    size_t pos = build_tbs(public_key, body, sizeof(body));
    if (pos == 0) {
        return 0;
    }

    uint8_t signature[ECDSA_DER_MAX_SIZE];
    size_t signature_len;
    if (!crypto_p256_sign_der(private_key, body, pos, signature, &signature_len)) {
        return 0;
    }

    body[pos++] = 0x30;
    body[pos++] = sizeof(OID_ECDSA_WITH_SHA256);
    memcpy(body + pos, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    pos += sizeof(OID_ECDSA_WITH_SHA256);

    body[pos++] = 0x03; // BIT STRING
    body[pos++] = (uint8_t)(signature_len + 1);
    body[pos++] = 0x00;
    memcpy(body + pos, signature, signature_len);
    pos += signature_len;

    return der_wrap(0x30, body, pos, out, cap);
}
