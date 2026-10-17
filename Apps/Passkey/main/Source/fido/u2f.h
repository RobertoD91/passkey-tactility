// SPDX-License-Identifier: Apache-2.0
/**
 * U2F (CTAP1) over CTAPHID_MSG: register, authenticate and version APDUs.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Handles one APDU; writes the response data followed by the two status bytes. */
void u2f_handle_apdu(const uint8_t* apdu, size_t len, uint8_t* response, size_t cap, size_t* response_len);

#ifdef __cplusplus
}
#endif
