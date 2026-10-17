// SPDX-License-Identifier: Apache-2.0
/**
 * CTAPHID transport: channels, message (de)fragmentation and the transport-level commands
 * (INIT, PING, WINK, CANCEL, ...). CBOR and MSG payloads are handed to ctap2 and u2f.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void ctaphid_init(void);

/** Processes one 64-byte packet from the host, running the command when a message is complete. */
void ctaphid_handle_packet(const uint8_t* packet);

/** Fails a message whose continuation packets stopped arriving. Call periodically. */
void ctaphid_tick(void);

/** The channel of the command being executed (valid inside a command handler). */
uint32_t ctaphid_get_active_cid(void);

/**
 * Handles a packet that arrives while a command is being executed (e.g. while waiting for the
 * user): answers CTAPHID_INIT on the broadcast channel, reports every other channel as busy.
 * @return true when the packet was a CTAPHID_CANCEL for the active channel
 */
bool ctaphid_handle_packet_while_busy(const uint8_t* packet);

void ctaphid_send_keepalive(uint32_t cid, uint8_t status);

#ifdef __cplusplus
}
#endif
