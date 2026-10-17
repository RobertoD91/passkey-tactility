// SPDX-License-Identifier: Apache-2.0
/**
 * Minimal CBOR (RFC 8949) codec for CTAP2: integers, byte and text strings, arrays, maps and
 * booleans. Indefinite-length items and floats are rejected on input (CTAP2 uses the canonical
 * subset) and never produced.
 *
 * Decoder return codes are CTAP2 status codes, so handlers can return them directly.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CBOR_OK 0x00
#define CBOR_ERR_UNEXPECTED_TYPE 0x11 /* CTAP2_ERR_CBOR_UNEXPECTED_TYPE */
#define CBOR_ERR_INVALID 0x12         /* CTAP2_ERR_INVALID_CBOR */

// ---- Encoder ----

typedef struct {
    uint8_t* buf;
    size_t cap;
    size_t len;
    bool overflow;
} CborWriter;

void cbor_writer_init(CborWriter* w, uint8_t* buf, size_t cap);
/** @return false when any write didn't fit. The writer keeps counting lengths after an overflow. */
bool cbor_writer_ok(const CborWriter* w);

void cbor_write_uint(CborWriter* w, uint64_t value);
void cbor_write_int(CborWriter* w, int64_t value);
void cbor_write_bytes(CborWriter* w, const void* data, size_t len);
void cbor_write_text(CborWriter* w, const char* text);
void cbor_write_text_len(CborWriter* w, const char* text, size_t len);
void cbor_write_bool(CborWriter* w, bool value);
void cbor_write_array(CborWriter* w, size_t count);
void cbor_write_map(CborWriter* w, size_t count);
/** Appends already-encoded CBOR. */
void cbor_write_raw(CborWriter* w, const void* data, size_t len);

// ---- Decoder ----

typedef enum {
    CBOR_TYPE_UINT,
    CBOR_TYPE_NEGINT, /* value holds n, the item is -1 - n */
    CBOR_TYPE_BYTES,
    CBOR_TYPE_TEXT,
    CBOR_TYPE_ARRAY,
    CBOR_TYPE_MAP,
    CBOR_TYPE_TAG,
    CBOR_TYPE_FALSE,
    CBOR_TYPE_TRUE,
    CBOR_TYPE_NULL,
    CBOR_TYPE_UNDEFINED,
    CBOR_TYPE_SIMPLE,
    CBOR_TYPE_FLOAT,
} CborType;

typedef struct {
    CborType type;
    /** Integer value, string length, container count, tag number or simple value. */
    uint64_t value;
    /** Payload of byte and text strings. */
    const uint8_t* data;
} CborItem;

typedef struct {
    const uint8_t* buf;
    size_t len;
    size_t pos;
} CborReader;

void cbor_reader_init(CborReader* r, const uint8_t* buf, size_t len);
bool cbor_reader_at_end(const CborReader* r);

/**
 * Reads the next item. Byte and text strings are consumed whole (payload pointed to by
 * item->data); arrays and maps only have their header consumed, the elements follow.
 */
int cbor_read_item(CborReader* r, CborItem* item);
/** Skips one complete value, including nested containers. */
int cbor_skip_value(CborReader* r);
int cbor_skip_values(CborReader* r, size_t count);

int cbor_read_uint(CborReader* r, uint64_t* value);
int cbor_read_int(CborReader* r, int64_t* value);
int cbor_read_bool(CborReader* r, bool* value);
int cbor_read_bytes(CborReader* r, const uint8_t** data, size_t* len);
int cbor_read_text(CborReader* r, const char** text, size_t* len);
int cbor_read_map(CborReader* r, size_t* count);
int cbor_read_array(CborReader* r, size_t* count);

/** @return the number of bytes a value occupies from the reader's position, or 0 on error. */
size_t cbor_value_size(const CborReader* r);

/** Compares a text item (not NUL-terminated) with a C string. */
bool cbor_text_equals(const char* text, size_t len, const char* expected);

#ifdef __cplusplus
}
#endif
