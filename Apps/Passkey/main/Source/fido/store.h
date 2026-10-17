// SPDX-License-Identifier: Apache-2.0
/**
 * Persistent authenticator state: secrets, PIN, signature counter and resident credentials.
 * Serialized to a single blob through the HAL's storage functions.
 */
#pragma once

#include "fido_config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIDO_CRED_ID_LEN 50

typedef struct {
    uint8_t cred_id[FIDO_CRED_ID_LEN];
    uint8_t rp_id_hash[32];
    char rp_id[FIDO_MAX_RP_ID_LEN + 1];
    char rp_name[FIDO_MAX_RP_NAME_LEN + 1];
    uint8_t user_id[FIDO_MAX_USER_ID_LEN];
    uint8_t user_id_len;
    char user_name[FIDO_MAX_USER_NAME_LEN + 1];
    char display_name[FIDO_MAX_USER_NAME_LEN + 1];
    uint8_t cred_protect;
    bool hmac_secret;
    /** Creation order: a higher value is a newer credential. */
    uint32_t sequence;
} FidoResidentCredential;

typedef struct {
    uint8_t master_secret[32];
    uint8_t attestation_key[32];
    bool pin_set;
    uint8_t pin_hash[16];
    uint8_t pin_retries;
    uint8_t min_pin_length;
    uint32_t counter;
    uint32_t next_sequence;
    uint8_t resident_count;
    FidoResidentCredential resident[FIDO_MAX_RESIDENT_CREDENTIALS];
} FidoStore;

extern FidoStore fido_store;

/** Loads the persisted state, or creates and persists a fresh one when none exists. */
void store_init(void);
bool store_save(void);
/** Factory reset: new secrets, no PIN, no credentials, counter 0. Persists the new state. */
bool store_reset(void);

int store_find_resident_by_id(const uint8_t* id, size_t id_len);
int store_find_resident_by_user(const uint8_t rp_id_hash[32], const uint8_t* user_id, size_t user_id_len);
/**
 * Adds a credential, replacing the one with the same RP and user id if present.
 * @return the index, or -1 when the store is full
 */
int store_add_resident(const FidoResidentCredential* credential);
void store_delete_resident(int index);
/** Number of distinct relying parties among the resident credentials. */
size_t store_count_rps(void);

#ifdef __cplusplus
}
#endif
