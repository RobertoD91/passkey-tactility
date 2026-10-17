// SPDX-License-Identifier: Apache-2.0
/**
 * Compile-time limits and identity of the authenticator.
 */
#pragma once

/** Authenticator version reported in CTAPHID_INIT and getInfo's firmwareVersion. */
#define FIDO_VERSION_MAJOR 1
#define FIDO_VERSION_MINOR 0
#define FIDO_VERSION_BUILD 0
#define FIDO_FIRMWARE_VERSION ((FIDO_VERSION_MAJOR << 16) | (FIDO_VERSION_MINOR << 8) | FIDO_VERSION_BUILD)

/** AAGUID: the ASCII bytes of "tact-passkey-1.0", so it's recognizable in authenticator metadata. */
#define FIDO_AAGUID { 0x74, 0x61, 0x63, 0x74, 0x2d, 0x70, 0x61, 0x73, 0x73, 0x6b, 0x65, 0x79, 0x2d, 0x31, 0x2e, 0x30 }

/** Largest CTAP message accepted or produced (getInfo maxMsgSize). The spec's minimum is 1024. */
#define FIDO_MAX_MSG_SIZE 1200

/** CTAPHID packet size (HID report size). Fixed by the CTAP specification for USB. */
#define FIDO_HID_PACKET_SIZE 64

/** Resident (discoverable) credentials kept in the store. Each record is about 450 bytes on disk. */
#define FIDO_MAX_RESIDENT_CREDENTIALS 32

#define FIDO_MAX_RP_ID_LEN 128
#define FIDO_MAX_RP_NAME_LEN 32
#define FIDO_MAX_USER_ID_LEN 64
#define FIDO_MAX_USER_NAME_LEN 64

/** getInfo maxCredentialCountInList / maxCredentialIdLength. */
#define FIDO_MAX_CREDENTIAL_COUNT_IN_LIST 8
#define FIDO_MAX_CREDENTIAL_ID_LENGTH 128

#define FIDO_PIN_MAX_RETRIES 8
/** Consecutive PIN failures within one power cycle before the authenticator must be power cycled. */
#define FIDO_PIN_MAX_CONSECUTIVE_RETRIES 3
#define FIDO_PIN_MIN_LENGTH 4
#define FIDO_PIN_MAX_LENGTH 63

/** How long a user presence prompt stays open before the operation fails. */
#define FIDO_UP_TIMEOUT_MS 30000
/** A U2F test-of-user-presence confirmation is kept for this long, for the client's next retry. */
#define FIDO_U2F_UP_CACHE_MS 10000
#define FIDO_KEEPALIVE_INTERVAL_MS 100
/** Timeout between the packets of one CTAPHID message. */
#define FIDO_HID_TRANSACTION_TIMEOUT_MS 3000
/** getNextAssertion must follow the previous assertion within this time. */
#define FIDO_NEXT_ASSERTION_TIMEOUT_MS 30000
