// SPDX-License-Identifier: Apache-2.0
/**
 * CTAP2 command processing (authenticatorMakeCredential, GetAssertion, GetInfo, ClientPIN,
 * Reset, GetNextAssertion, CredentialManagement, Selection).
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Resets the transient session state (key agreement key, pinUvAuthToken, enumerations). */
void ctap2_init(void);

/** Expires stale transient state. Called periodically. */
void ctap2_tick(void);

/**
 * Handles a CTAPHID_CBOR payload (command byte followed by CBOR parameters).
 * @param[out] response the CBOR response (without the status byte)
 * @return the CTAP2 status code
 */
uint8_t ctap2_handle(const uint8_t* request, size_t request_len, uint8_t* response, size_t response_cap, size_t* response_len);

#ifdef __cplusplus
}
#endif
