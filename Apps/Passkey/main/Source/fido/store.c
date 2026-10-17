// SPDX-License-Identifier: Apache-2.0
#include "store.h"

#include "crypto/crypto.h"
#include "fido_hal.h"

#include <stdlib.h>
#include <string.h>

#define STORE_MAGIC "TPK1"
#define STORE_VERSION 1

#define HEADER_SIZE (4 + 1 + 32 + 32 + 1 + 16 + 1 + 1 + 4 + 4 + 1)
#define RECORD_SIZE (FIDO_CRED_ID_LEN + 32 + 1 + FIDO_MAX_RP_ID_LEN + 1 + FIDO_MAX_RP_NAME_LEN + 1 + FIDO_MAX_USER_ID_LEN + 1 + FIDO_MAX_USER_NAME_LEN + 1 + FIDO_MAX_USER_NAME_LEN + 1 + 1 + 4)
#define STORE_MAX_SIZE (HEADER_SIZE + FIDO_MAX_RESIDENT_CREDENTIALS * RECORD_SIZE + SHA256_DIGEST_SIZE)

FidoStore fido_store;

// ---- Serialization ----

typedef struct {
    uint8_t* buf;
    size_t pos;
} Writer;

static void put(Writer* w, const void* data, size_t len) {
    memcpy(w->buf + w->pos, data, len);
    w->pos += len;
}

static void put_u8(Writer* w, uint8_t value) {
    w->buf[w->pos++] = value;
}

static void put_u32(Writer* w, uint32_t value) {
    for (int i = 0; i < 4; i++) {
        w->buf[w->pos++] = (uint8_t)(value >> (8 * i));
    }
}

/** Length-prefixed string in a fixed-size field, so records keep a constant size. */
static void put_string(Writer* w, const char* text, size_t field_size) {
    size_t len = strlen(text);
    if (len > field_size) {
        len = field_size;
    }
    put_u8(w, (uint8_t)len);
    memcpy(w->buf + w->pos, text, len);
    memset(w->buf + w->pos + len, 0, field_size - len);
    w->pos += field_size;
}

typedef struct {
    const uint8_t* buf;
    size_t len;
    size_t pos;
} Reader;

static bool get(Reader* r, void* out, size_t len) {
    if (r->len - r->pos < len) {
        return false;
    }
    memcpy(out, r->buf + r->pos, len);
    r->pos += len;
    return true;
}

static bool get_u8(Reader* r, uint8_t* out) {
    return get(r, out, 1);
}

static bool get_u32(Reader* r, uint32_t* out) {
    uint8_t bytes[4];
    if (!get(r, bytes, 4)) {
        return false;
    }
    *out = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
    return true;
}

static bool get_string(Reader* r, char* out, size_t field_size) {
    uint8_t len;
    if (!get_u8(r, &len) || len > field_size || r->len - r->pos < field_size) {
        return false;
    }
    memcpy(out, r->buf + r->pos, len);
    out[len] = '\0';
    r->pos += field_size;
    return true;
}

static size_t serialize(uint8_t* buf) {
    Writer w = { buf, 0 };
    put(&w, STORE_MAGIC, 4);
    put_u8(&w, STORE_VERSION);
    put(&w, fido_store.master_secret, 32);
    put(&w, fido_store.attestation_key, 32);
    put_u8(&w, fido_store.pin_set ? 1 : 0);
    put(&w, fido_store.pin_hash, 16);
    put_u8(&w, fido_store.pin_retries);
    put_u8(&w, fido_store.min_pin_length);
    put_u32(&w, fido_store.counter);
    put_u32(&w, fido_store.next_sequence);
    put_u8(&w, fido_store.resident_count);
    for (size_t i = 0; i < fido_store.resident_count; i++) {
        const FidoResidentCredential* c = &fido_store.resident[i];
        put(&w, c->cred_id, FIDO_CRED_ID_LEN);
        put(&w, c->rp_id_hash, 32);
        put_string(&w, c->rp_id, FIDO_MAX_RP_ID_LEN);
        put_string(&w, c->rp_name, FIDO_MAX_RP_NAME_LEN);
        put_u8(&w, c->user_id_len);
        put(&w, c->user_id, FIDO_MAX_USER_ID_LEN);
        put_string(&w, c->user_name, FIDO_MAX_USER_NAME_LEN);
        put_string(&w, c->display_name, FIDO_MAX_USER_NAME_LEN);
        put_u8(&w, c->cred_protect);
        put_u8(&w, c->hmac_secret ? 1 : 0);
        put_u32(&w, c->sequence);
    }
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(buf, w.pos, digest);
    put(&w, digest, sizeof(digest));
    return w.pos;
}

static bool deserialize(const uint8_t* buf, size_t len) {
    if (len < HEADER_SIZE + SHA256_DIGEST_SIZE) {
        return false;
    }
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256(buf, len - SHA256_DIGEST_SIZE, digest);
    if (!crypto_equal(digest, buf + len - SHA256_DIGEST_SIZE, SHA256_DIGEST_SIZE)) {
        return false;
    }

    Reader r = { buf, len - SHA256_DIGEST_SIZE, 0 };
    char magic[4];
    uint8_t version;
    FidoStore s;
    memset(&s, 0, sizeof(s));
    if (!get(&r, magic, 4) || memcmp(magic, STORE_MAGIC, 4) != 0 || !get_u8(&r, &version) || version != STORE_VERSION) {
        return false;
    }
    uint8_t pin_set;
    if (!get(&r, s.master_secret, 32) || !get(&r, s.attestation_key, 32) || !get_u8(&r, &pin_set) ||
        !get(&r, s.pin_hash, 16) || !get_u8(&r, &s.pin_retries) || !get_u8(&r, &s.min_pin_length) ||
        !get_u32(&r, &s.counter) || !get_u32(&r, &s.next_sequence) || !get_u8(&r, &s.resident_count)) {
        return false;
    }
    s.pin_set = pin_set != 0;
    if (s.resident_count > FIDO_MAX_RESIDENT_CREDENTIALS) {
        return false;
    }
    for (size_t i = 0; i < s.resident_count; i++) {
        FidoResidentCredential* c = &s.resident[i];
        uint8_t hmac_secret;
        if (!get(&r, c->cred_id, FIDO_CRED_ID_LEN) || !get(&r, c->rp_id_hash, 32) ||
            !get_string(&r, c->rp_id, FIDO_MAX_RP_ID_LEN) || !get_string(&r, c->rp_name, FIDO_MAX_RP_NAME_LEN) ||
            !get_u8(&r, &c->user_id_len) || !get(&r, c->user_id, FIDO_MAX_USER_ID_LEN) ||
            !get_string(&r, c->user_name, FIDO_MAX_USER_NAME_LEN) || !get_string(&r, c->display_name, FIDO_MAX_USER_NAME_LEN) ||
            !get_u8(&r, &c->cred_protect) || !get_u8(&r, &hmac_secret) || !get_u32(&r, &c->sequence)) {
            return false;
        }
        if (c->user_id_len > FIDO_MAX_USER_ID_LEN) {
            return false;
        }
        c->hmac_secret = hmac_secret != 0;
    }
    fido_store = s;
    crypto_zeroize(&s, sizeof(s));
    return true;
}

// ---- Lifecycle ----

static void init_fresh(void) {
    memset(&fido_store, 0, sizeof(fido_store));
    crypto_random(fido_store.master_secret, sizeof(fido_store.master_secret));
    uint8_t public_key[P256_PUBLIC_KEY_SIZE];
    do {
        crypto_random(fido_store.attestation_key, sizeof(fido_store.attestation_key));
    } while (!crypto_p256_public_key(fido_store.attestation_key, public_key));
    fido_store.pin_set = false;
    fido_store.pin_retries = FIDO_PIN_MAX_RETRIES;
    fido_store.min_pin_length = FIDO_PIN_MIN_LENGTH;
    fido_store.counter = 0;
    fido_store.next_sequence = 1;
    fido_store.resident_count = 0;
}

bool store_save(void) {
    uint8_t* buf = (uint8_t*)malloc(STORE_MAX_SIZE);
    if (buf == NULL) {
        fido_hal_log("store: out of memory");
        return false;
    }
    size_t len = serialize(buf);
    bool ok = fido_hal_storage_write(buf, len);
    crypto_zeroize(buf, len);
    free(buf);
    if (!ok) {
        fido_hal_log("store: write failed");
    }
    return ok;
}

void store_init(void) {
    uint8_t* buf = (uint8_t*)malloc(STORE_MAX_SIZE);
    size_t len = 0;
    bool loaded = false;
    if (buf != NULL) {
        if (fido_hal_storage_read(buf, STORE_MAX_SIZE, &len)) {
            loaded = deserialize(buf, len);
            if (!loaded) {
                fido_hal_log("store: stored state is invalid, starting fresh");
            }
        }
        crypto_zeroize(buf, STORE_MAX_SIZE);
        free(buf);
    }
    if (!loaded) {
        init_fresh();
        store_save();
    }
    fido_hal_log("store: %u resident credential(s), PIN %s", (unsigned)fido_store.resident_count, fido_store.pin_set ? "set" : "not set");
}

bool store_reset(void) {
    crypto_zeroize(&fido_store, sizeof(fido_store));
    fido_hal_storage_erase();
    init_fresh();
    return store_save();
}

// ---- Resident credentials ----

int store_find_resident_by_id(const uint8_t* id, size_t id_len) {
    if (id_len != FIDO_CRED_ID_LEN) {
        return -1;
    }
    for (size_t i = 0; i < fido_store.resident_count; i++) {
        if (crypto_equal(fido_store.resident[i].cred_id, id, FIDO_CRED_ID_LEN)) {
            return (int)i;
        }
    }
    return -1;
}

int store_find_resident_by_user(const uint8_t rp_id_hash[32], const uint8_t* user_id, size_t user_id_len) {
    for (size_t i = 0; i < fido_store.resident_count; i++) {
        const FidoResidentCredential* c = &fido_store.resident[i];
        if (memcmp(c->rp_id_hash, rp_id_hash, 32) == 0 && c->user_id_len == user_id_len && memcmp(c->user_id, user_id, user_id_len) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int store_add_resident(const FidoResidentCredential* credential) {
    int index = store_find_resident_by_user(credential->rp_id_hash, credential->user_id, credential->user_id_len);
    if (index < 0) {
        if (fido_store.resident_count >= FIDO_MAX_RESIDENT_CREDENTIALS) {
            return -1;
        }
        index = fido_store.resident_count++;
    }
    fido_store.resident[index] = *credential;
    fido_store.resident[index].sequence = fido_store.next_sequence++;
    return index;
}

void store_delete_resident(int index) {
    if (index < 0 || index >= fido_store.resident_count) {
        return;
    }
    crypto_zeroize(&fido_store.resident[index], sizeof(FidoResidentCredential));
    for (size_t i = (size_t)index + 1; i < fido_store.resident_count; i++) {
        fido_store.resident[i - 1] = fido_store.resident[i];
    }
    fido_store.resident_count--;
    crypto_zeroize(&fido_store.resident[fido_store.resident_count], sizeof(FidoResidentCredential));
}

size_t store_count_rps(void) {
    size_t count = 0;
    for (size_t i = 0; i < fido_store.resident_count; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++) {
            if (memcmp(fido_store.resident[i].rp_id_hash, fido_store.resident[j].rp_id_hash, 32) == 0) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            count++;
        }
    }
    return count;
}
