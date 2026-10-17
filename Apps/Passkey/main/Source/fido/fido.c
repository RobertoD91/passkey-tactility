// SPDX-License-Identifier: Apache-2.0
#include "fido.h"

#include "crypto/crypto.h"
#include "ctap2.h"
#include "ctap_defs.h"
#include "ctaphid.h"
#include "store.h"
#include "x509.h"

#include <string.h>

#define LOCK_FOREVER 0xFFFFFFFFu

static uint8_t attestation_certificate[X509_MAX_SIZE];
static size_t attestation_certificate_len = 0;
static uint32_t up_timeout_ms = FIDO_UP_TIMEOUT_MS;

static struct {
    bool prompt_open;
    uint32_t opened_at;
    bool confirmed;
    uint32_t confirmed_at;
} u2f_up;

static void rebuild_attestation_certificate(void) {
    uint8_t public_key[P256_PUBLIC_KEY_SIZE];
    if (!crypto_p256_public_key(fido_store.attestation_key, public_key)) {
        attestation_certificate_len = 0;
        return;
    }
    attestation_certificate_len = x509_build_self_signed(fido_store.attestation_key, public_key, attestation_certificate, sizeof(attestation_certificate));
    if (attestation_certificate_len == 0) {
        fido_hal_log("fido: building the attestation certificate failed");
    }
}

void fido_init(void) {
    crypto_init();
    store_init();
    ctaphid_init();
    ctap2_init();
    rebuild_attestation_certificate();
    memset(&u2f_up, 0, sizeof(u2f_up));
    fido_hal_log("fido: ready (version %d.%d.%d)", FIDO_VERSION_MAJOR, FIDO_VERSION_MINOR, FIDO_VERSION_BUILD);
}

void fido_set_up_timeout_ms(uint32_t timeout_ms) {
    up_timeout_ms = timeout_ms;
}

static void close_u2f_prompt(void) {
    if (u2f_up.prompt_open) {
        fido_hal_up_end();
        u2f_up.prompt_open = false;
    }
}

static void u2f_up_housekeeping(void) {
    if (!u2f_up.prompt_open) {
        return;
    }
    uint32_t now = fido_hal_millis();
    enum FidoUpState state = fido_hal_up_poll();
    if (state == FIDO_UP_STATE_CONFIRMED) {
        u2f_up.confirmed = true;
        u2f_up.confirmed_at = now;
        close_u2f_prompt();
    } else if (state == FIDO_UP_STATE_DENIED || now - u2f_up.opened_at > up_timeout_ms) {
        close_u2f_prompt();
    }
}

void fido_poll(uint32_t timeout_ms) {
    uint8_t packet[FIDO_HID_PACKET_SIZE];
    bool received = fido_hal_hid_recv(packet, timeout_ms);
    fido_hal_lock(LOCK_FOREVER);
    if (received) {
        ctaphid_handle_packet(packet);
    }
    ctaphid_tick();
    u2f_up_housekeeping();
    ctap2_tick();
    fido_hal_unlock();
}

enum FidoUpResult fido_request_user_presence(enum FidoUpReason reason, const char* rp_id, const char* user_name) {
    close_u2f_prompt();
    u2f_up.confirmed = false;

    uint32_t cid = ctaphid_get_active_cid();
    fido_hal_up_begin(reason, rp_id, user_name);
    uint32_t started_at = fido_hal_millis();
    uint32_t last_keepalive = 0;
    bool first = true;
    enum FidoUpResult result = FIDO_UP_RESULT_TIMEOUT;
    for (;;) {
        enum FidoUpState state = fido_hal_up_poll();
        if (state == FIDO_UP_STATE_CONFIRMED) {
            result = FIDO_UP_RESULT_CONFIRMED;
            break;
        }
        if (state == FIDO_UP_STATE_DENIED) {
            result = FIDO_UP_RESULT_DENIED;
            break;
        }
        uint32_t now = fido_hal_millis();
        if (now - started_at >= up_timeout_ms) {
            result = FIDO_UP_RESULT_TIMEOUT;
            break;
        }
        if (first || now - last_keepalive >= FIDO_KEEPALIVE_INTERVAL_MS) {
            ctaphid_send_keepalive(cid, CTAPHID_STATUS_UPNEEDED);
            last_keepalive = now;
            first = false;
        }
        uint8_t packet[FIDO_HID_PACKET_SIZE];
        if (fido_hal_hid_recv(packet, 20) && ctaphid_handle_packet_while_busy(packet)) {
            result = FIDO_UP_RESULT_CANCELLED;
            break;
        }
    }
    fido_hal_up_end();
    return result;
}

uint8_t fido_up_result_to_status(enum FidoUpResult result) {
    switch (result) {
        case FIDO_UP_RESULT_CONFIRMED: return CTAP2_OK;
        case FIDO_UP_RESULT_DENIED: return CTAP2_ERR_OPERATION_DENIED;
        case FIDO_UP_RESULT_CANCELLED: return CTAP2_ERR_KEEPALIVE_CANCEL;
        default: return CTAP2_ERR_USER_ACTION_TIMEOUT;
    }
}

bool fido_u2f_test_user_presence(enum FidoUpReason reason) {
    uint32_t now = fido_hal_millis();
    if (u2f_up.confirmed) {
        u2f_up.confirmed = false;
        if (now - u2f_up.confirmed_at <= FIDO_U2F_UP_CACHE_MS) {
            close_u2f_prompt();
            return true;
        }
    }
    if (!u2f_up.prompt_open) {
        fido_hal_up_begin(reason, NULL, NULL);
        u2f_up.prompt_open = true;
        u2f_up.opened_at = now;
        return false;
    }
    enum FidoUpState state = fido_hal_up_poll();
    if (state == FIDO_UP_STATE_CONFIRMED) {
        close_u2f_prompt();
        return true;
    }
    if (state == FIDO_UP_STATE_DENIED || now - u2f_up.opened_at > up_timeout_ms) {
        close_u2f_prompt();
    }
    return false;
}

uint32_t fido_increment_counter(void) {
    fido_store.counter++;
    store_save();
    fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
    return fido_store.counter;
}

const uint8_t* fido_attestation_certificate(size_t* out_len) {
    *out_len = attestation_certificate_len;
    return attestation_certificate;
}

const uint8_t* fido_attestation_private_key(void) {
    return fido_store.attestation_key;
}

void fido_on_state_reset(void) {
    ctap2_init();
    rebuild_attestation_certificate();
    memset(&u2f_up, 0, sizeof(u2f_up));
    fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
}

// ---- UI API ----

// Reads come from the UI task and must not stall it while the worker waits for the user; writes
// come from the app's own task and can afford to wait a little.
#define UI_READ_LOCK_TIMEOUT_MS 20
#define UI_WRITE_LOCK_TIMEOUT_MS 500

bool fido_get_status(FidoStatus* out) {
    if (!fido_hal_lock(UI_READ_LOCK_TIMEOUT_MS)) {
        return false;
    }
    out->pin_set = fido_store.pin_set;
    out->pin_retries = fido_store.pin_retries;
    out->resident_count = fido_store.resident_count;
    out->counter = fido_store.counter;
    fido_hal_unlock();
    return true;
}

bool fido_get_resident_credential(size_t index, FidoCredentialInfo* out) {
    if (!fido_hal_lock(UI_READ_LOCK_TIMEOUT_MS)) {
        return false;
    }
    bool ok = index < fido_store.resident_count;
    if (ok) {
        const FidoResidentCredential* c = &fido_store.resident[index];
        strncpy(out->rp_id, c->rp_id, sizeof(out->rp_id) - 1);
        out->rp_id[sizeof(out->rp_id) - 1] = '\0';
        strncpy(out->user_name, c->user_name, sizeof(out->user_name) - 1);
        out->user_name[sizeof(out->user_name) - 1] = '\0';
        strncpy(out->display_name, c->display_name, sizeof(out->display_name) - 1);
        out->display_name[sizeof(out->display_name) - 1] = '\0';
    }
    fido_hal_unlock();
    return ok;
}

bool fido_delete_resident_credential(size_t index) {
    if (!fido_hal_lock(UI_WRITE_LOCK_TIMEOUT_MS)) {
        return false;
    }
    bool ok = index < fido_store.resident_count;
    if (ok) {
        store_delete_resident((int)index);
        ok = store_save();
    }
    fido_hal_unlock();
    if (ok) {
        fido_hal_notify(FIDO_HAL_EVENT_STATE_CHANGED);
    }
    return ok;
}

bool fido_factory_reset(void) {
    if (!fido_hal_lock(UI_WRITE_LOCK_TIMEOUT_MS)) {
        return false;
    }
    bool ok = store_reset();
    fido_on_state_reset();
    fido_hal_unlock();
    return ok;
}
