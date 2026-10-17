// SPDX-License-Identifier: Apache-2.0
/** State shared by the app's main task, its UI (LVGL task) and the FIDO worker task. */
#pragma once

#include "fido/fido.h"

#include <app/instance.h>
#include <lvgl.h>
#include <lvgl_window_manager/window_manager.h>
#include <tactility/concurrent/task_event_group.h>
#include <tactility/concurrent/thread.h>
#include <tactility/device.h>
#include <tactility/freertos/freertos.h>
#include <tactility/freertos/queue.h>
#include <tactility/freertos/semphr.h>

#include <stdbool.h>
#include <stdint.h>

#define PASSKEY_APP_ID "robertod.passkey"
#define PASSKEY_TAG "Passkey"

/** The UI asks the main task to do something; the main task owns USB start/stop. */
enum PasskeyUiRequest {
    PASSKEY_REQUEST_NONE,
    PASSKEY_REQUEST_USB_ON,
    PASSKEY_REQUEST_USB_OFF,
    PASSKEY_REQUEST_DELETE_CREDENTIAL,
    PASSKEY_REQUEST_FACTORY_RESET,
};

/** What the prompt card is asking the user, if anything. */
enum PasskeyPrompt {
    PASSKEY_PROMPT_NONE,
    /** The FIDO core waits for user presence (fido_hal_up_begin). */
    PASSKEY_PROMPT_USER_PRESENCE,
    PASSKEY_PROMPT_DELETE_CREDENTIAL,
    PASSKEY_PROMPT_FACTORY_RESET,
};

struct PasskeyApp {
    AppInstanceId app_instance_id;
    WindowId window;
    struct TaskEventGroup* event_group;
    /** Bit of event_group signalled when the UI must refresh or a request is pending. */
    uint32_t ui_bit;

    // USB transport (owned by the main task)
    struct Device* hid_device;
    QueueHandle_t rx_queue;
    bool usb_started;
    char usb_error[64];

    // FIDO worker
    Thread* worker;
    volatile bool worker_running;
    SemaphoreHandle_t core_mutex;
    volatile bool storage_ok;

    // User presence (written by the worker and the LVGL task)
    volatile int up_state; // enum FidoUpState, or -1 when no prompt is open
    enum FidoUpReason up_reason;
    char up_rp_id[FIDO_MAX_RP_ID_LEN + 1];
    char up_user_name[FIDO_MAX_USER_NAME_LEN + 1];

    // UI requests and local prompts
    volatile enum PasskeyUiRequest request;
    volatile enum PasskeyPrompt prompt;
    size_t selected_credential;
    volatile bool wink;
    /** The credential list must be rebuilt (state changed since it was last drawn). */
    volatile bool credentials_dirty;

    // Widgets (only valid while the window is topmost; NULL otherwise)
    lv_obj_t* usb_switch;
    lv_obj_t* status_label;
    lv_obj_t* prompt_card;
    lv_obj_t* prompt_label;
    lv_obj_t* confirm_button;
    lv_obj_t* deny_button;
    lv_obj_t* credential_list;
    lv_timer_t* status_timer;
};

/** The single instance, for the HAL functions that have no context argument. */
extern struct PasskeyApp* passkey_app;

void passkey_signal_ui(struct PasskeyApp* app);
