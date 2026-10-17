// SPDX-License-Identifier: Apache-2.0
/**
 * Hardware/OS abstraction the FIDO core needs. Implemented once for Tactility (hal_tactility.c)
 * and once for the host test harness (tests/host/hal_host.c).
 *
 * Threading model: the core runs on one worker task that calls fido_poll(). The HAL's user
 * presence functions are the only ones called from the core while another task (the UI) may act
 * on them concurrently, so an implementation keeps the user presence state in atomics.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Fills @a out with cryptographically secure random bytes. */
void fido_hal_random(uint8_t* out, size_t len);

/** Milliseconds since boot. Wraps after 49 days; the core only computes differences. */
uint32_t fido_hal_millis(void);

/**
 * Reads the persisted authenticator state.
 * @return false when nothing was stored yet or the data could not be read
 */
bool fido_hal_storage_read(uint8_t* buf, size_t cap, size_t* out_len);

/** Persists the authenticator state atomically (the previous state survives a failed write). */
bool fido_hal_storage_write(const uint8_t* buf, size_t len);

/** Removes the persisted state. Used by a factory reset before writing the new state. */
void fido_hal_storage_erase(void);

/** Sends one 64-byte CTAPHID packet to the host. Blocks until the packet is queued for transfer. */
bool fido_hal_hid_send(const uint8_t* packet);

/**
 * Waits up to @a timeout_ms for one 64-byte CTAPHID packet from the host.
 * @return false on timeout
 */
bool fido_hal_hid_recv(uint8_t* packet, uint32_t timeout_ms);

enum FidoUpReason {
    FIDO_UP_REASON_MAKE_CREDENTIAL,
    FIDO_UP_REASON_GET_ASSERTION,
    FIDO_UP_REASON_U2F_REGISTER,
    FIDO_UP_REASON_U2F_AUTHENTICATE,
    FIDO_UP_REASON_RESET,
    FIDO_UP_REASON_SELECTION,
    /** The relying party asked to exclude an existing credential; confirming only reports that. */
    FIDO_UP_REASON_CREDENTIAL_EXCLUDED,
    /** No credential matched; confirming only reports that (keeps timing uniform). */
    FIDO_UP_REASON_NO_CREDENTIALS,
    /** A client probes whether a PIN is set; confirming only reports that. */
    FIDO_UP_REASON_PIN_PROBE,
};

enum FidoUpState {
    FIDO_UP_STATE_PENDING,
    FIDO_UP_STATE_CONFIRMED,
    FIDO_UP_STATE_DENIED,
};

/**
 * Asks the user to confirm their presence (show a prompt). The core then calls fido_hal_up_poll()
 * repeatedly until the user answers or FIDO_UP_TIMEOUT_MS pass, and fido_hal_up_end() afterwards.
 * @param[in] rp_id relying party id, or NULL when unknown (U2F only has the application hash)
 * @param[in] user_name user name shown to the user, or NULL
 */
void fido_hal_up_begin(enum FidoUpReason reason, const char* rp_id, const char* user_name);
enum FidoUpState fido_hal_up_poll(void);
void fido_hal_up_end(void);

enum FidoHalEvent {
    /** Persistent state changed (PIN, credentials, counter): the UI may refresh. */
    FIDO_HAL_EVENT_STATE_CHANGED,
    /** The host asked the authenticator to identify itself (CTAPHID_WINK). */
    FIDO_HAL_EVENT_WINK,
    /** A host started talking to the authenticator. */
    FIDO_HAL_EVENT_ACTIVITY,
};

/** Called from the worker task. Implementations must not block. */
void fido_hal_notify(enum FidoHalEvent event);

/**
 * Serializes access to the core between the worker task and the UI.
 * @return false when the lock could not be taken within @a timeout_ms
 */
bool fido_hal_lock(uint32_t timeout_ms);
void fido_hal_unlock(void);

void fido_hal_log(const char* format, ...);

#ifdef __cplusplus
}
#endif
