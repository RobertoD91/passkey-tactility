// SPDX-License-Identifier: Apache-2.0
/**
 * Passkey: a FIDO2/U2F security key for Tactility.
 *
 * Tasks:
 *  - this app's main task: event loop, USB start/stop, credential deletion and reset requests
 *  - the FIDO worker thread: runs the authenticator core (fido_poll)
 *  - the LVGL task: the UI, which answers user presence prompts
 */
#include "passkey_app.h"
#include "ui.h"
#include "usb_transport.h"

#include <app/event.h>
#include <app/manager.h>
#include <app/scheduler.h>
#include <lvgl/lvgl.h>
#include <lvgl_window_manager/window_manager.h>
#include <tactility/check.h>
#include <tactility/log.h>

#include <stdlib.h>
#include <string.h>

#define WORKER_STACK_SIZE (20 * 1024)

struct PasskeyApp* passkey_app = NULL;

void passkey_signal_ui(struct PasskeyApp* app) {
    if (app->event_group != NULL) {
        task_event_group_signal(app->event_group, app->ui_bit);
    }
}

static int32_t worker_main(void* context) {
    struct PasskeyApp* app = (struct PasskeyApp*)context;
    fido_init();
    app->credentials_dirty = true;
    passkey_signal_ui(app);
    while (app->worker_running) {
        fido_poll(100);
    }
    return 0;
}

static void refresh_ui(struct PasskeyApp* app) {
    if (lvgl_try_lock(200)) {
        passkey_ui_refresh(app);
        app->wink = false;
        lvgl_unlock();
    }
}

static void handle_request(struct PasskeyApp* app) {
    enum PasskeyUiRequest request = app->request;
    app->request = PASSKEY_REQUEST_NONE;
    switch (request) {
        case PASSKEY_REQUEST_USB_ON:
            usb_transport_start(app);
            break;
        case PASSKEY_REQUEST_USB_OFF:
            usb_transport_stop(app);
            break;
        case PASSKEY_REQUEST_DELETE_CREDENTIAL:
            fido_delete_resident_credential(app->selected_credential);
            break;
        case PASSKEY_REQUEST_FACTORY_RESET:
            fido_factory_reset();
            break;
        default:
            break;
    }
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    struct PasskeyApp* app = (struct PasskeyApp*)calloc(1, sizeof(struct PasskeyApp));
    check(app != NULL);
    passkey_app = app;
    app->app_instance_id = app_scheduler_current_app_id();
    app->up_state = -1;
    app->storage_ok = true;
    app->core_mutex = xSemaphoreCreateMutex();
    check(app->core_mutex != NULL);

    struct TaskEventGroup event_group = {0};
    task_event_group_construct(&event_group);
    app->event_group = &event_group;
    check(task_event_group_claim_bit(&event_group, &app->ui_bit) == ERROR_NONE);

    struct AppEventSubscription sub = {0};
    check(app_event_subscribe(&sub, &event_group) == ERROR_NONE);

    // The worker loads the state and then serves the host; the UI reads through fido_get_*.
    app->worker_running = true;
    app->worker = thread_alloc_full("passkey", WORKER_STACK_SIZE, worker_main, app, tskNO_AFFINITY);
    check(app->worker != NULL);
    thread_set_priority(app->worker, THREAD_PRIORITY_NORMAL);
    check(thread_start(app->worker) == ERROR_NONE);

    app->window = window_manager_create_ext(app->app_instance_id, passkey_ui_create, passkey_ui_destroy, app);

    // Present the key to the host right away: that's what the app is for.
    usb_transport_start(app);
    refresh_ui(app);

    bool should_close = false;
    while (!should_close) {
        task_event_group_wait_any(&event_group, NULL, portMAX_DELAY);

        struct AppEvent event;
        while (app_event_poll(&sub, &event) == ERROR_NONE) {
            if (event.type == APP_EVENT_CLOSE) {
                should_close = true;
            }
        }
        if (should_close) {
            break;
        }
        handle_request(app);
        refresh_ui(app);
    }

    // Any prompt still open is answered "denied" so the worker doesn't wait on the vanished UI.
    app->up_state = FIDO_UP_STATE_DENIED;
    usb_transport_stop(app);
    app->worker_running = false;
    thread_join(app->worker, portMAX_DELAY, pdMS_TO_TICKS(20));
    thread_free(app->worker);

    window_manager_remove(app->window);
    check(app_event_unsubscribe(&sub) == ERROR_NONE);
    task_event_group_release_bit(&event_group, app->ui_bit);
    app->event_group = NULL;
    task_event_group_destruct(&event_group);

    if (app->rx_queue != NULL) {
        vQueueDelete(app->rx_queue);
    }
    vSemaphoreDelete(app->core_mutex);
    passkey_app = NULL;
    free(app);
    return 0;
}
