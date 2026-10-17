// SPDX-License-Identifier: Apache-2.0
/**
 * fido_hal.h for Tactility: random bytes and the storage encryption come from crypt-module, the
 * state file lives in the app's user data folder, packets travel through the USB transport's
 * queue, and user presence is answered by the UI.
 *
 * The state file is AES-256-CBC encrypted with crypt-module's device-bound key, so a copy of the
 * file (e.g. from the SD card) can't be used on another device.
 */
#include "fido/fido_hal.h"
#include "passkey_app.h"
#include "usb_transport.h"

#include <app/paths.h>
#include <crypt/crypt.h>
#include <tactility/drivers/usb_hid_device.h>
#include <tactility/log.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define STORE_FILE "passkey.bin"
#define STORE_MAGIC "TPKE"
#define STORE_HEADER_SIZE (4 + 16 + 4)

static bool get_store_path(char* path, size_t size) {
    return app_paths_get_user_data_path(PASSKEY_APP_ID, STORE_FILE, path, size) == ERROR_NONE;
}

static void ensure_directory(void) {
    char directory[256];
    if (app_paths_get_user_data_directory(PASSKEY_APP_ID, directory, sizeof(directory)) != ERROR_NONE) {
        return;
    }
    // mkdir -p: create each missing component in turn.
    for (char* p = directory + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(directory, 0777);
            *p = '/';
        }
    }
    mkdir(directory, 0777);
}

void fido_hal_random(uint8_t* out, size_t len) {
    while (len > 0) {
        uint8_t block[16];
        crypt_generate_iv(block);
        size_t take = len < sizeof(block) ? len : sizeof(block);
        memcpy(out, block, take);
        out += take;
        len -= take;
    }
}

uint32_t fido_hal_millis(void) {
    return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

bool fido_hal_storage_read(uint8_t* buf, size_t cap, size_t* out_len) {
    char path[256];
    if (!get_store_path(path, sizeof(path))) {
        passkey_app->storage_ok = false;
        return false;
    }
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        return false;
    }
    uint8_t header[STORE_HEADER_SIZE];
    bool ok = fread(header, 1, sizeof(header), file) == sizeof(header) && memcmp(header, STORE_MAGIC, 4) == 0;
    size_t plain_len = 0;
    size_t cipher_len = 0;
    uint8_t* cipher = NULL;
    if (ok) {
        plain_len = (size_t)header[20] | ((size_t)header[21] << 8) | ((size_t)header[22] << 16) | ((size_t)header[23] << 24);
        cipher_len = (plain_len + 15) & ~(size_t)15;
        ok = plain_len <= cap && cipher_len > 0;
    }
    if (ok) {
        cipher = (uint8_t*)malloc(cipher_len);
        ok = cipher != NULL && fread(cipher, 1, cipher_len, file) == cipher_len;
    }
    fclose(file);
    if (ok) {
        uint8_t* plain = (uint8_t*)malloc(cipher_len);
        ok = plain != NULL && crypt_decrypt(header + 4, cipher, plain, cipher_len) == 0;
        if (ok) {
            memcpy(buf, plain, plain_len);
            *out_len = plain_len;
        }
        if (plain != NULL) {
            memset(plain, 0, cipher_len);
            free(plain);
        }
    }
    free(cipher);
    if (!ok) {
        LOG_W(PASSKEY_TAG, "State file unreadable: %s", path);
    }
    return ok;
}

bool fido_hal_storage_write(const uint8_t* buf, size_t len) {
    char path[256];
    if (!get_store_path(path, sizeof(path))) {
        passkey_app->storage_ok = false;
        return false;
    }
    ensure_directory();

    size_t cipher_len = (len + 15) & ~(size_t)15;
    uint8_t* plain = (uint8_t*)calloc(1, cipher_len);
    uint8_t* cipher = (uint8_t*)malloc(cipher_len);
    bool ok = plain != NULL && cipher != NULL;
    uint8_t header[STORE_HEADER_SIZE];
    if (ok) {
        memcpy(plain, buf, len);
        memcpy(header, STORE_MAGIC, 4);
        crypt_generate_iv(header + 4);
        header[20] = (uint8_t)len;
        header[21] = (uint8_t)(len >> 8);
        header[22] = (uint8_t)(len >> 16);
        header[23] = (uint8_t)(len >> 24);
        ok = crypt_encrypt(header + 4, plain, cipher, cipher_len) == 0;
    }
    if (plain != NULL) {
        memset(plain, 0, cipher_len);
        free(plain);
    }

    char temp[256 + 4];
    if (ok) {
        snprintf(temp, sizeof(temp), "%s.tmp", path);
        FILE* file = fopen(temp, "wb");
        ok = file != NULL;
        if (ok) {
            ok = fwrite(header, 1, sizeof(header), file) == sizeof(header) && fwrite(cipher, 1, cipher_len, file) == cipher_len;
            ok = (fclose(file) == 0) && ok;
        }
        if (ok) {
            remove(path);
            ok = rename(temp, path) == 0;
        }
    }
    free(cipher);
    passkey_app->storage_ok = ok;
    if (!ok) {
        LOG_E(PASSKEY_TAG, "Writing the state file failed: %s", path);
    }
    return ok;
}

void fido_hal_storage_erase(void) {
    char path[256];
    if (get_store_path(path, sizeof(path))) {
        remove(path);
    }
}

bool fido_hal_hid_send(const uint8_t* packet) {
    struct PasskeyApp* app = passkey_app;
    if (!app->usb_started || app->hid_device == NULL) {
        return false;
    }
    // The driver already retries a busy endpoint for about 50 ms; a long response of many packets
    // can still find the endpoint busy, so retry a few more times before giving up.
    for (int attempt = 0; attempt < 20; attempt++) {
        error_t result = usb_hid_device_send_raw(app->hid_device, packet, FIDO_HID_PACKET_SIZE);
        if (result == ERROR_NONE) {
            return true;
        }
        if (result != ERROR_RESOURCE) {
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    return false;
}

bool fido_hal_hid_recv(uint8_t* packet, uint32_t timeout_ms) {
    struct PasskeyApp* app = passkey_app;
    if (app->rx_queue == NULL) {
        vTaskDelay(pdMS_TO_TICKS(timeout_ms));
        return false;
    }
    return xQueueReceive(app->rx_queue, packet, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void fido_hal_up_begin(enum FidoUpReason reason, const char* rp_id, const char* user_name) {
    struct PasskeyApp* app = passkey_app;
    app->up_reason = reason;
    strncpy(app->up_rp_id, rp_id != NULL ? rp_id : "", sizeof(app->up_rp_id) - 1);
    app->up_rp_id[sizeof(app->up_rp_id) - 1] = '\0';
    strncpy(app->up_user_name, user_name != NULL ? user_name : "", sizeof(app->up_user_name) - 1);
    app->up_user_name[sizeof(app->up_user_name) - 1] = '\0';
    app->up_state = FIDO_UP_STATE_PENDING;
    app->prompt = PASSKEY_PROMPT_USER_PRESENCE;
    passkey_signal_ui(app);
}

enum FidoUpState fido_hal_up_poll(void) {
    int state = passkey_app->up_state;
    return state < 0 ? FIDO_UP_STATE_PENDING : (enum FidoUpState)state;
}

void fido_hal_up_end(void) {
    struct PasskeyApp* app = passkey_app;
    app->up_state = -1;
    if (app->prompt == PASSKEY_PROMPT_USER_PRESENCE) {
        app->prompt = PASSKEY_PROMPT_NONE;
    }
    passkey_signal_ui(app);
}

void fido_hal_notify(enum FidoHalEvent event) {
    struct PasskeyApp* app = passkey_app;
    if (event == FIDO_HAL_EVENT_WINK) {
        app->wink = true;
    } else if (event == FIDO_HAL_EVENT_STATE_CHANGED) {
        app->credentials_dirty = true;
    }
    passkey_signal_ui(app);
}

bool fido_hal_lock(uint32_t timeout_ms) {
    TickType_t ticks = timeout_ms == 0xFFFFFFFFu ? portMAX_DELAY : pdMS_TO_TICKS(timeout_ms);
    return xSemaphoreTake(passkey_app->core_mutex, ticks) == pdTRUE;
}

void fido_hal_unlock(void) {
    xSemaphoreGive(passkey_app->core_mutex);
}

void fido_hal_log(const char* format, ...) {
    char message[160];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    LOG_I(PASSKEY_TAG, "%s", message);
}
