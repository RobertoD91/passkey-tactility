// SPDX-License-Identifier: Apache-2.0
/**
 * The FIDO2/U2F authenticator core. Platform independent: everything it needs from the outside
 * goes through fido_hal.h.
 *
 * Worker side: fido_init() once, then fido_poll() in a loop. UI side: the fido_get_*,
 * fido_delete_* and fido_factory_reset() functions, which take the HAL lock themselves.
 */
#pragma once

#include "fido_config.h"
#include "fido_hal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void fido_init(void);

/** Waits up to @a timeout_ms for a packet, processes it and runs housekeeping. */
void fido_poll(uint32_t timeout_ms);

/** Overrides FIDO_UP_TIMEOUT_MS (tests). */
void fido_set_up_timeout_ms(uint32_t timeout_ms);

// ---- Used by the command handlers ----

enum FidoUpResult {
    FIDO_UP_RESULT_CONFIRMED,
    FIDO_UP_RESULT_DENIED,
    FIDO_UP_RESULT_TIMEOUT,
    FIDO_UP_RESULT_CANCELLED,
};

/** Blocks until the user confirms, denies, the prompt times out or the host cancels. Sends keepalives. */
enum FidoUpResult fido_request_user_presence(enum FidoUpReason reason, const char* rp_id, const char* user_name);

/** Maps a non-confirmed user presence result to its CTAP2 status code. */
uint8_t fido_up_result_to_status(enum FidoUpResult result);

/**
 * U2F test of user presence: non-blocking, as U2F clients poll. Opens the prompt on the first
 * call and reports true once the user has confirmed (the confirmation is cached briefly for the
 * client's retry).
 */
bool fido_u2f_test_user_presence(enum FidoUpReason reason);

/** Increments and persists the signature counter. @return the new value */
uint32_t fido_increment_counter(void);

const uint8_t* fido_attestation_certificate(size_t* out_len);
const uint8_t* fido_attestation_private_key(void);

/** Called after a factory reset or PIN change, so transient state (tokens, keys) is renewed. */
void fido_on_state_reset(void);

// ---- UI API (takes the HAL lock; returns false when the core is busy) ----

typedef struct {
    bool pin_set;
    uint8_t pin_retries;
    uint8_t resident_count;
    uint32_t counter;
} FidoStatus;

typedef struct {
    char rp_id[FIDO_MAX_RP_ID_LEN + 1];
    char user_name[FIDO_MAX_USER_NAME_LEN + 1];
    char display_name[FIDO_MAX_USER_NAME_LEN + 1];
} FidoCredentialInfo;

bool fido_get_status(FidoStatus* out);
bool fido_get_resident_credential(size_t index, FidoCredentialInfo* out);
bool fido_delete_resident_credential(size_t index);
bool fido_factory_reset(void);

#ifdef __cplusplus
}
#endif
