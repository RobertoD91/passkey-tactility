// SPDX-License-Identifier: Apache-2.0
/**
 * Minimal self-signed X.509 certificate for the U2F attestation key. U2F registration responses
 * must carry a certificate; CTAP2 uses self attestation and never needs one.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define X509_MAX_SIZE 400

/** @return the DER length, or 0 when @a out is too small or signing failed */
size_t x509_build_self_signed(const uint8_t private_key[32], const uint8_t public_key[64], uint8_t* out, size_t cap);

#ifdef __cplusplus
}
#endif
