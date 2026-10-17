// SPDX-License-Identifier: Apache-2.0
#include "ctaphid.h"

#include "ctap2.h"
#include "ctap_defs.h"
#include "fido_config.h"
#include "fido_hal.h"
#include "u2f.h"

#include <string.h>

#define PACKET_SIZE FIDO_HID_PACKET_SIZE

static struct {
    bool active;
    uint32_t cid;
    uint8_t cmd;
    uint16_t length;
    uint16_t received;
    uint8_t next_seq;
    uint32_t started_at;
} rx;

static uint8_t rx_buf[FIDO_MAX_MSG_SIZE];
static uint8_t tx_buf[FIDO_MAX_MSG_SIZE + 1];
static uint32_t next_cid = 1;
static uint32_t active_cid = 0;

static uint32_t read_cid(const uint8_t* packet) {
    return ((uint32_t)packet[0] << 24) | ((uint32_t)packet[1] << 16) | ((uint32_t)packet[2] << 8) | (uint32_t)packet[3];
}

static void write_cid(uint8_t* packet, uint32_t cid) {
    packet[0] = (uint8_t)(cid >> 24);
    packet[1] = (uint8_t)(cid >> 16);
    packet[2] = (uint8_t)(cid >> 8);
    packet[3] = (uint8_t)cid;
}

static void reset_rx(void) {
    memset(&rx, 0, sizeof(rx));
}

void ctaphid_init(void) {
    reset_rx();
    next_cid = 1;
    active_cid = 0;
}

uint32_t ctaphid_get_active_cid(void) {
    return active_cid;
}

// ---- Sending ----

static void send_message(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t len) {
    uint8_t packet[PACKET_SIZE];
    memset(packet, 0, sizeof(packet));
    write_cid(packet, cid);
    packet[4] = (uint8_t)(CTAPHID_TYPE_INIT | cmd);
    packet[5] = (uint8_t)(len >> 8);
    packet[6] = (uint8_t)len;
    size_t chunk = len < CTAPHID_INIT_PAYLOAD_SIZE ? len : CTAPHID_INIT_PAYLOAD_SIZE;
    memcpy(packet + 7, data, chunk);
    if (!fido_hal_hid_send(packet)) {
        return;
    }
    size_t offset = chunk;
    uint8_t seq = 0;
    while (offset < len) {
        memset(packet, 0, sizeof(packet));
        write_cid(packet, cid);
        packet[4] = seq++;
        chunk = len - offset < CTAPHID_CONT_PAYLOAD_SIZE ? len - offset : CTAPHID_CONT_PAYLOAD_SIZE;
        memcpy(packet + 5, data + offset, chunk);
        if (!fido_hal_hid_send(packet)) {
            return;
        }
        offset += chunk;
    }
}

static void send_error(uint32_t cid, uint8_t code) {
    send_message(cid, CTAPHID_ERROR, &code, 1);
}

void ctaphid_send_keepalive(uint32_t cid, uint8_t status) {
    send_message(cid, CTAPHID_KEEPALIVE, &status, 1);
}

// ---- Commands ----

static void handle_init(uint32_t cid, const uint8_t* data, size_t len) {
    if (len != 8) {
        send_error(cid, CTAP1_ERR_INVALID_LENGTH);
        return;
    }
    uint32_t assigned = cid;
    if (cid == CTAPHID_BROADCAST_CID) {
        assigned = next_cid++;
        if (next_cid == CTAPHID_BROADCAST_CID || next_cid == 0) {
            next_cid = 1;
        }
    }
    uint8_t response[17];
    memcpy(response, data, 8);
    write_cid(response + 8, assigned);
    response[12] = CTAPHID_PROTOCOL_VERSION;
    response[13] = FIDO_VERSION_MAJOR;
    response[14] = FIDO_VERSION_MINOR;
    response[15] = FIDO_VERSION_BUILD;
    response[16] = CTAPHID_CAPABILITY_WINK | CTAPHID_CAPABILITY_CBOR;
    send_message(cid, CTAPHID_INIT, response, sizeof(response));
}

static void dispatch(uint32_t cid, uint8_t cmd, const uint8_t* data, size_t len) {
    switch (cmd) {
        case CTAPHID_INIT:
            handle_init(cid, data, len);
            return;
        case CTAPHID_PING:
            send_message(cid, CTAPHID_PING, data, len);
            return;
        case CTAPHID_WINK:
            if (len != 0) {
                send_error(cid, CTAP1_ERR_INVALID_LENGTH);
                return;
            }
            fido_hal_notify(FIDO_HAL_EVENT_WINK);
            send_message(cid, CTAPHID_WINK, NULL, 0);
            return;
        case CTAPHID_LOCK:
            if (len != 1) {
                send_error(cid, CTAP1_ERR_INVALID_LENGTH);
                return;
            }
            // Only one host at a time talks to a USB device: the lock is accepted without effect.
            send_message(cid, CTAPHID_LOCK, NULL, 0);
            return;
        case CTAPHID_CANCEL:
        case CTAPHID_KEEPALIVE:
        case CTAPHID_ERROR:
            // Nothing is pending on this channel.
            return;
        case CTAPHID_CBOR: {
            if (len == 0) {
                send_error(cid, CTAP1_ERR_INVALID_LENGTH);
                return;
            }
            fido_hal_notify(FIDO_HAL_EVENT_ACTIVITY);
            active_cid = cid;
            size_t response_len = 0;
            uint8_t status = ctap2_handle(data, len, tx_buf + 1, sizeof(tx_buf) - 1, &response_len);
            active_cid = 0;
            tx_buf[0] = status;
            send_message(cid, CTAPHID_CBOR, tx_buf, status == CTAP2_OK ? response_len + 1 : 1);
            return;
        }
        case CTAPHID_MSG: {
            fido_hal_notify(FIDO_HAL_EVENT_ACTIVITY);
            active_cid = cid;
            size_t response_len = 0;
            u2f_handle_apdu(data, len, tx_buf, sizeof(tx_buf), &response_len);
            active_cid = 0;
            send_message(cid, CTAPHID_MSG, tx_buf, response_len);
            return;
        }
        default:
            send_error(cid, CTAP1_ERR_INVALID_COMMAND);
            return;
    }
}

// ---- Receiving ----

void ctaphid_handle_packet(const uint8_t* packet) {
    uint32_t cid = read_cid(packet);
    bool is_init = (packet[4] & CTAPHID_TYPE_INIT) != 0;

    if (cid == 0) {
        send_error(cid, CTAP1_ERR_INVALID_CHANNEL);
        return;
    }

    if (is_init) {
        uint8_t cmd = packet[4] & 0x7F;
        uint16_t length = (uint16_t)((packet[5] << 8) | packet[6]);

        if (rx.active && rx.cid != cid) {
            if (cmd == CTAPHID_INIT && cid == CTAPHID_BROADCAST_CID) {
                handle_init(cid, packet + 7, length == 8 ? 8 : 0);
            } else {
                send_error(cid, CTAP1_ERR_CHANNEL_BUSY);
            }
            return;
        }
        if (rx.active && rx.cid == cid && cmd != CTAPHID_INIT) {
            // A new command before the previous message completed: abort that message.
            reset_rx();
            send_error(cid, CTAP1_ERR_INVALID_SEQ);
            return;
        }
        reset_rx();
        if (cmd != CTAPHID_INIT && cid == CTAPHID_BROADCAST_CID) {
            send_error(cid, CTAP1_ERR_INVALID_CHANNEL);
            return;
        }
        if (length > sizeof(rx_buf)) {
            send_error(cid, CTAP1_ERR_INVALID_LENGTH);
            return;
        }
        size_t chunk = length < CTAPHID_INIT_PAYLOAD_SIZE ? length : CTAPHID_INIT_PAYLOAD_SIZE;
        memcpy(rx_buf, packet + 7, chunk);
        if (chunk == length) {
            dispatch(cid, cmd, rx_buf, length);
            return;
        }
        rx.active = true;
        rx.cid = cid;
        rx.cmd = cmd;
        rx.length = length;
        rx.received = (uint16_t)chunk;
        rx.next_seq = 0;
        rx.started_at = fido_hal_millis();
        return;
    }

    // Continuation packet
    if (!rx.active) {
        // Spurious continuation (e.g. the tail of a message that timed out): nothing to answer.
        return;
    }
    if (rx.cid != cid) {
        send_error(cid, CTAP1_ERR_CHANNEL_BUSY);
        return;
    }
    uint8_t seq = packet[4];
    if (seq != rx.next_seq) {
        reset_rx();
        send_error(cid, CTAP1_ERR_INVALID_SEQ);
        return;
    }
    rx.next_seq++;
    size_t remaining = rx.length - rx.received;
    size_t chunk = remaining < CTAPHID_CONT_PAYLOAD_SIZE ? remaining : CTAPHID_CONT_PAYLOAD_SIZE;
    memcpy(rx_buf + rx.received, packet + 5, chunk);
    rx.received = (uint16_t)(rx.received + chunk);
    if (rx.received == rx.length) {
        uint8_t cmd = rx.cmd;
        uint16_t length = rx.length;
        reset_rx();
        dispatch(cid, cmd, rx_buf, length);
    }
}

void ctaphid_tick(void) {
    if (rx.active && fido_hal_millis() - rx.started_at > FIDO_HID_TRANSACTION_TIMEOUT_MS) {
        uint32_t cid = rx.cid;
        reset_rx();
        send_error(cid, CTAP1_ERR_TIMEOUT);
    }
}

bool ctaphid_handle_packet_while_busy(const uint8_t* packet) {
    uint32_t cid = read_cid(packet);
    bool is_init = (packet[4] & CTAPHID_TYPE_INIT) != 0;
    if (!is_init) {
        if (cid != active_cid) {
            send_error(cid, CTAP1_ERR_CHANNEL_BUSY);
        }
        return false;
    }
    uint8_t cmd = packet[4] & 0x7F;
    uint16_t length = (uint16_t)((packet[5] << 8) | packet[6]);
    if (cid == active_cid && cmd == CTAPHID_CANCEL) {
        return true;
    }
    if (cid == CTAPHID_BROADCAST_CID && cmd == CTAPHID_INIT) {
        handle_init(cid, packet + 7, length == 8 ? 8 : 0);
        return false;
    }
    if (cid == 0) {
        send_error(cid, CTAP1_ERR_INVALID_CHANNEL);
        return false;
    }
    send_error(cid, CTAP1_ERR_CHANNEL_BUSY);
    return false;
}
