// SPDX-License-Identifier: Apache-2.0
/**
 * HAL for the host test harness: CTAPHID packets travel over stdin/stdout, the state lives in a
 * file, and user presence is decided by environment variables:
 *   PASSKEY_STORE        state file (default ./passkey-store.bin)
 *   PASSKEY_UP           confirm (default) | deny | timeout
 *   PASSKEY_UP_DELAY_MS  delay before the simulated user answers (default 50)
 */
#define _GNU_SOURCE
#include "fido_hal.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool eof = false;

static struct {
    bool open;
    uint32_t opened_at;
} up;

bool hal_host_eof(void) {
    return eof;
}

static const char* store_path(void) {
    const char* path = getenv("PASSKEY_STORE");
    return path != NULL ? path : "passkey-store.bin";
}

void fido_hal_random(uint8_t* out, size_t len) {
    while (len > 0) {
        ssize_t n = getrandom(out, len, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("getrandom");
            abort();
        }
        out += n;
        len -= (size_t)n;
    }
}

uint32_t fido_hal_millis(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

bool fido_hal_storage_read(uint8_t* buf, size_t cap, size_t* out_len) {
    FILE* file = fopen(store_path(), "rb");
    if (file == NULL) {
        return false;
    }
    size_t len = fread(buf, 1, cap, file);
    fclose(file);
    *out_len = len;
    return len > 0;
}

bool fido_hal_storage_write(const uint8_t* buf, size_t len) {
    char temp[1024];
    snprintf(temp, sizeof(temp), "%s.tmp", store_path());
    FILE* file = fopen(temp, "wb");
    if (file == NULL) {
        return false;
    }
    bool ok = fwrite(buf, 1, len, file) == len;
    ok = fclose(file) == 0 && ok;
    if (ok) {
        ok = rename(temp, store_path()) == 0;
    }
    return ok;
}

void fido_hal_storage_erase(void) {
    unlink(store_path());
}

bool fido_hal_hid_send(const uint8_t* packet) {
    size_t written = 0;
    while (written < 64) {
        ssize_t n = write(STDOUT_FILENO, packet + written, 64 - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        written += (size_t)n;
    }
    return true;
}

bool fido_hal_hid_recv(uint8_t* packet, uint32_t timeout_ms) {
    if (eof) {
        usleep(timeout_ms * 1000);
        return false;
    }
    struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
    int ready = poll(&pfd, 1, (int)timeout_ms);
    if (ready <= 0) {
        return false;
    }
    size_t received = 0;
    while (received < 64) {
        ssize_t n = read(STDIN_FILENO, packet + received, 64 - received);
        if (n == 0) {
            eof = true;
            return false;
        }
        if (n < 0) {
            if (errno == EINTR) continue;
            eof = true;
            return false;
        }
        received += (size_t)n;
    }
    return true;
}

void fido_hal_up_begin(enum FidoUpReason reason, const char* rp_id, const char* user_name) {
    fido_hal_log("UP prompt: reason=%d rp=%s user=%s", (int)reason, rp_id ? rp_id : "-", user_name ? user_name : "-");
    up.open = true;
    up.opened_at = fido_hal_millis();
}

enum FidoUpState fido_hal_up_poll(void) {
    if (!up.open) {
        return FIDO_UP_STATE_PENDING;
    }
    const char* mode = getenv("PASSKEY_UP");
    const char* delay_text = getenv("PASSKEY_UP_DELAY_MS");
    uint32_t delay = delay_text != NULL ? (uint32_t)atoi(delay_text) : 50;
    if (fido_hal_millis() - up.opened_at < delay) {
        return FIDO_UP_STATE_PENDING;
    }
    if (mode != NULL && strcmp(mode, "deny") == 0) {
        return FIDO_UP_STATE_DENIED;
    }
    if (mode != NULL && strcmp(mode, "timeout") == 0) {
        return FIDO_UP_STATE_PENDING;
    }
    return FIDO_UP_STATE_CONFIRMED;
}

void fido_hal_up_end(void) {
    up.open = false;
}

void fido_hal_notify(enum FidoHalEvent event) {
    static const char* names[] = { "state-changed", "wink", "activity" };
    fido_hal_log("event: %s", names[event]);
}

bool fido_hal_lock(uint32_t timeout_ms) {
    (void)timeout_ms;
    return pthread_mutex_lock(&lock) == 0;
}

void fido_hal_unlock(void) {
    pthread_mutex_unlock(&lock);
}

void fido_hal_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[passkey] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}
