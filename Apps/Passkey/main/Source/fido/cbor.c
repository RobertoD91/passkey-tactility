// SPDX-License-Identifier: Apache-2.0
#include "cbor.h"

#include <string.h>

#define MAJOR_UINT 0
#define MAJOR_NEGINT 1
#define MAJOR_BYTES 2
#define MAJOR_TEXT 3
#define MAJOR_ARRAY 4
#define MAJOR_MAP 5
#define MAJOR_TAG 6
#define MAJOR_SIMPLE 7

#define MAX_NESTING 8

// ---- Encoder ----

void cbor_writer_init(CborWriter* w, uint8_t* buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->overflow = false;
}

bool cbor_writer_ok(const CborWriter* w) {
    return !w->overflow;
}

static void put_byte(CborWriter* w, uint8_t byte) {
    if (w->len < w->cap) {
        w->buf[w->len] = byte;
    } else {
        w->overflow = true;
    }
    w->len++;
}

static void write_head(CborWriter* w, uint8_t major, uint64_t value) {
    uint8_t type = (uint8_t)(major << 5);
    if (value < 24) {
        put_byte(w, type | (uint8_t)value);
    } else if (value <= 0xFF) {
        put_byte(w, type | 24);
        put_byte(w, (uint8_t)value);
    } else if (value <= 0xFFFF) {
        put_byte(w, type | 25);
        put_byte(w, (uint8_t)(value >> 8));
        put_byte(w, (uint8_t)value);
    } else if (value <= 0xFFFFFFFFu) {
        put_byte(w, type | 26);
        for (int shift = 24; shift >= 0; shift -= 8) {
            put_byte(w, (uint8_t)(value >> shift));
        }
    } else {
        put_byte(w, type | 27);
        for (int shift = 56; shift >= 0; shift -= 8) {
            put_byte(w, (uint8_t)(value >> shift));
        }
    }
}

void cbor_write_uint(CborWriter* w, uint64_t value) {
    write_head(w, MAJOR_UINT, value);
}

void cbor_write_int(CborWriter* w, int64_t value) {
    if (value >= 0) {
        write_head(w, MAJOR_UINT, (uint64_t)value);
    } else {
        write_head(w, MAJOR_NEGINT, (uint64_t)(-1 - value));
    }
}

void cbor_write_raw(CborWriter* w, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        put_byte(w, p[i]);
    }
}

void cbor_write_bytes(CborWriter* w, const void* data, size_t len) {
    write_head(w, MAJOR_BYTES, len);
    cbor_write_raw(w, data, len);
}

void cbor_write_text_len(CborWriter* w, const char* text, size_t len) {
    write_head(w, MAJOR_TEXT, len);
    cbor_write_raw(w, text, len);
}

void cbor_write_text(CborWriter* w, const char* text) {
    cbor_write_text_len(w, text, strlen(text));
}

void cbor_write_bool(CborWriter* w, bool value) {
    put_byte(w, (uint8_t)(0xE0 | (value ? 21 : 20)));
}

void cbor_write_array(CborWriter* w, size_t count) {
    write_head(w, MAJOR_ARRAY, count);
}

void cbor_write_map(CborWriter* w, size_t count) {
    write_head(w, MAJOR_MAP, count);
}

// ---- Decoder ----

void cbor_reader_init(CborReader* r, const uint8_t* buf, size_t len) {
    r->buf = buf;
    r->len = len;
    r->pos = 0;
}

bool cbor_reader_at_end(const CborReader* r) {
    return r->pos >= r->len;
}

static int read_argument(CborReader* r, uint8_t additional, uint64_t* value, bool* is_indefinite) {
    *is_indefinite = false;
    if (additional < 24) {
        *value = additional;
        return CBOR_OK;
    }
    size_t width;
    switch (additional) {
        case 24: width = 1; break;
        case 25: width = 2; break;
        case 26: width = 4; break;
        case 27: width = 8; break;
        case 31: *is_indefinite = true; *value = 0; return CBOR_OK;
        default: return CBOR_ERR_INVALID;
    }
    if (r->len - r->pos < width) {
        return CBOR_ERR_INVALID;
    }
    uint64_t v = 0;
    for (size_t i = 0; i < width; i++) {
        v = (v << 8) | r->buf[r->pos++];
    }
    *value = v;
    return CBOR_OK;
}

int cbor_read_item(CborReader* r, CborItem* item) {
    if (r->pos >= r->len) {
        return CBOR_ERR_INVALID;
    }
    uint8_t initial = r->buf[r->pos++];
    uint8_t major = initial >> 5;
    uint8_t additional = initial & 0x1F;
    item->data = NULL;

    if (major == MAJOR_SIMPLE) {
        switch (additional) {
            case 20: item->type = CBOR_TYPE_FALSE; item->value = 0; return CBOR_OK;
            case 21: item->type = CBOR_TYPE_TRUE; item->value = 1; return CBOR_OK;
            case 22: item->type = CBOR_TYPE_NULL; item->value = 0; return CBOR_OK;
            case 23: item->type = CBOR_TYPE_UNDEFINED; item->value = 0; return CBOR_OK;
            case 24:
                if (r->pos >= r->len) return CBOR_ERR_INVALID;
                item->type = CBOR_TYPE_SIMPLE;
                item->value = r->buf[r->pos++];
                return CBOR_OK;
            case 25: case 26: case 27: {
                size_t width = additional == 25 ? 2 : (additional == 26 ? 4 : 8);
                if (r->len - r->pos < width) return CBOR_ERR_INVALID;
                r->pos += width;
                item->type = CBOR_TYPE_FLOAT;
                item->value = 0;
                return CBOR_OK;
            }
            default:
                return CBOR_ERR_INVALID;
        }
    }

    bool indefinite;
    uint64_t value;
    int err = read_argument(r, additional, &value, &indefinite);
    if (err != CBOR_OK) {
        return err;
    }
    if (indefinite) {
        return CBOR_ERR_INVALID;
    }
    item->value = value;

    switch (major) {
        case MAJOR_UINT: item->type = CBOR_TYPE_UINT; return CBOR_OK;
        case MAJOR_NEGINT: item->type = CBOR_TYPE_NEGINT; return CBOR_OK;
        case MAJOR_BYTES:
        case MAJOR_TEXT:
            if (value > r->len - r->pos) {
                return CBOR_ERR_INVALID;
            }
            item->type = major == MAJOR_BYTES ? CBOR_TYPE_BYTES : CBOR_TYPE_TEXT;
            item->data = r->buf + r->pos;
            r->pos += (size_t)value;
            return CBOR_OK;
        case MAJOR_ARRAY: item->type = CBOR_TYPE_ARRAY; return CBOR_OK;
        case MAJOR_MAP: item->type = CBOR_TYPE_MAP; return CBOR_OK;
        case MAJOR_TAG: item->type = CBOR_TYPE_TAG; return CBOR_OK;
        default: return CBOR_ERR_INVALID;
    }
}

static int skip_value(CborReader* r, int depth) {
    if (depth > MAX_NESTING) {
        return CBOR_ERR_INVALID;
    }
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) {
        return err;
    }
    switch (item.type) {
        case CBOR_TYPE_ARRAY:
            for (uint64_t i = 0; i < item.value; i++) {
                err = skip_value(r, depth + 1);
                if (err != CBOR_OK) return err;
            }
            return CBOR_OK;
        case CBOR_TYPE_MAP:
            for (uint64_t i = 0; i < item.value; i++) {
                err = skip_value(r, depth + 1);
                if (err != CBOR_OK) return err;
                err = skip_value(r, depth + 1);
                if (err != CBOR_OK) return err;
            }
            return CBOR_OK;
        case CBOR_TYPE_TAG:
            return skip_value(r, depth + 1);
        default:
            return CBOR_OK;
    }
}

int cbor_skip_value(CborReader* r) {
    return skip_value(r, 0);
}

int cbor_skip_values(CborReader* r, size_t count) {
    for (size_t i = 0; i < count; i++) {
        int err = skip_value(r, 0);
        if (err != CBOR_OK) {
            return err;
        }
    }
    return CBOR_OK;
}

int cbor_read_uint(CborReader* r, uint64_t* value) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type != CBOR_TYPE_UINT) return CBOR_ERR_UNEXPECTED_TYPE;
    *value = item.value;
    return CBOR_OK;
}

int cbor_read_int(CborReader* r, int64_t* value) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type == CBOR_TYPE_UINT) {
        if (item.value > INT64_MAX) return CBOR_ERR_INVALID;
        *value = (int64_t)item.value;
        return CBOR_OK;
    }
    if (item.type == CBOR_TYPE_NEGINT) {
        if (item.value > INT64_MAX) return CBOR_ERR_INVALID;
        *value = -1 - (int64_t)item.value;
        return CBOR_OK;
    }
    return CBOR_ERR_UNEXPECTED_TYPE;
}

int cbor_read_bool(CborReader* r, bool* value) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type == CBOR_TYPE_TRUE) { *value = true; return CBOR_OK; }
    if (item.type == CBOR_TYPE_FALSE) { *value = false; return CBOR_OK; }
    return CBOR_ERR_UNEXPECTED_TYPE;
}

int cbor_read_bytes(CborReader* r, const uint8_t** data, size_t* len) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type != CBOR_TYPE_BYTES) return CBOR_ERR_UNEXPECTED_TYPE;
    *data = item.data;
    *len = (size_t)item.value;
    return CBOR_OK;
}

int cbor_read_text(CborReader* r, const char** text, size_t* len) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type != CBOR_TYPE_TEXT) return CBOR_ERR_UNEXPECTED_TYPE;
    *text = (const char*)item.data;
    *len = (size_t)item.value;
    return CBOR_OK;
}

int cbor_read_map(CborReader* r, size_t* count) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type != CBOR_TYPE_MAP) return CBOR_ERR_UNEXPECTED_TYPE;
    // A map can't have more pairs than remaining bytes: rejects absurd counts early.
    if (item.value > r->len - r->pos) return CBOR_ERR_INVALID;
    *count = (size_t)item.value;
    return CBOR_OK;
}

int cbor_read_array(CborReader* r, size_t* count) {
    CborItem item;
    int err = cbor_read_item(r, &item);
    if (err != CBOR_OK) return err;
    if (item.type != CBOR_TYPE_ARRAY) return CBOR_ERR_UNEXPECTED_TYPE;
    if (item.value > r->len - r->pos) return CBOR_ERR_INVALID;
    *count = (size_t)item.value;
    return CBOR_OK;
}

size_t cbor_value_size(const CborReader* r) {
    CborReader copy = *r;
    if (cbor_skip_value(&copy) != CBOR_OK) {
        return 0;
    }
    return copy.pos - r->pos;
}

bool cbor_text_equals(const char* text, size_t len, const char* expected) {
    size_t expected_len = strlen(expected);
    return len == expected_len && memcmp(text, expected, len) == 0;
}
