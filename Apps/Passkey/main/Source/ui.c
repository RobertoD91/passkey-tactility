// SPDX-License-Identifier: Apache-2.0
#include "ui.h"

#include "usb_transport.h"

// Only widgets that every Tactility 0.8.0-dev build exports are used (plain LVGL plus the toolbar),
// so the app also runs on derived firmwares such as the RomHack Camp 2026 badge.
#include <lvgl/fonts.h>
#include <lvgl/lvgl.h>
#include <lvgl/widgets/toolbar.h>
#include <tactility/log.h>

#include <stdio.h>
#include <string.h>

#define MAX_LISTED_CREDENTIALS 16

static bool widgets_alive(struct PasskeyApp* app) {
    return app->status_label != NULL && window_manager_get_state(app->window) == WINDOW_STATE_GRANTED;
}

// ---- Event handlers (LVGL task) ----

static void on_usb_switch(lv_event_t* event) {
    struct PasskeyApp* app = (struct PasskeyApp*)lv_event_get_user_data(event);
    bool on = lv_obj_has_state(lv_event_get_target_obj(event), LV_STATE_CHECKED);
    app->request = on ? PASSKEY_REQUEST_USB_ON : PASSKEY_REQUEST_USB_OFF;
    passkey_signal_ui(app);
}

static void on_confirm(lv_event_t* event) {
    struct PasskeyApp* app = (struct PasskeyApp*)lv_event_get_user_data(event);
    switch (app->prompt) {
        case PASSKEY_PROMPT_USER_PRESENCE:
            app->up_state = FIDO_UP_STATE_CONFIRMED;
            break;
        case PASSKEY_PROMPT_DELETE_CREDENTIAL:
            app->prompt = PASSKEY_PROMPT_NONE;
            app->request = PASSKEY_REQUEST_DELETE_CREDENTIAL;
            break;
        case PASSKEY_PROMPT_FACTORY_RESET:
            app->prompt = PASSKEY_PROMPT_NONE;
            app->request = PASSKEY_REQUEST_FACTORY_RESET;
            break;
        default:
            break;
    }
    passkey_signal_ui(app);
}

static void on_deny(lv_event_t* event) {
    struct PasskeyApp* app = (struct PasskeyApp*)lv_event_get_user_data(event);
    if (app->prompt == PASSKEY_PROMPT_USER_PRESENCE) {
        app->up_state = FIDO_UP_STATE_DENIED;
    } else {
        app->prompt = PASSKEY_PROMPT_NONE;
    }
    passkey_signal_ui(app);
}

static void on_credential_clicked(lv_event_t* event) {
    struct PasskeyApp* app = (struct PasskeyApp*)lv_event_get_user_data(event);
    if (app->prompt != PASSKEY_PROMPT_NONE) {
        return;
    }
    app->selected_credential = (size_t)(uintptr_t)lv_obj_get_user_data(lv_event_get_target_obj(event));
    app->prompt = PASSKEY_PROMPT_DELETE_CREDENTIAL;
    passkey_signal_ui(app);
}

static void on_reset_clicked(lv_event_t* event) {
    struct PasskeyApp* app = (struct PasskeyApp*)lv_event_get_user_data(event);
    if (app->prompt != PASSKEY_PROMPT_NONE) {
        return;
    }
    app->prompt = PASSKEY_PROMPT_FACTORY_RESET;
    passkey_signal_ui(app);
}

// The host connection state has no event: poll it while the window is visible.
static void on_status_timer(lv_timer_t* timer) {
    struct PasskeyApp* app = (struct PasskeyApp*)lv_timer_get_user_data(timer);
    if (widgets_alive(app)) {
        passkey_ui_refresh(app);
    }
}

// ---- Building ----

static lv_obj_t* add_button(lv_obj_t* parent, const char* text, lv_event_cb_t callback, void* user_data) {
    lv_obj_t* button = lv_button_create(parent);
    lv_obj_t* label = lv_label_create(button);
    lv_label_set_text(label, text);
    lv_obj_center(label);
    lv_obj_add_event_cb(button, callback, LV_EVENT_SHORT_CLICKED, user_data);
    return button;
}

void passkey_ui_create(lv_obj_t* parent, void* user_data) {
    struct PasskeyApp* app = (struct PasskeyApp*)user_data;
    // Small displays (240x240 rounds, the 80x160 dongle) get tighter spacing and a smaller status font.
    bool compact = lv_display_get_horizontal_resolution(NULL) <= 240 && lv_display_get_vertical_resolution(NULL) <= 240;

    lv_obj_remove_flag(parent, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(parent, LV_FLEX_FLOW_COLUMN);

    lv_obj_t* toolbar = lvgl_toolbar_create(parent, "Passkey");
    app->usb_switch = lvgl_toolbar_add_switch_action(toolbar);
    if (app->usb_started) {
        lv_obj_add_state(app->usb_switch, LV_STATE_CHECKED);
    }
    lv_obj_add_event_cb(app->usb_switch, on_usb_switch, LV_EVENT_VALUE_CHANGED, app);

    lv_obj_t* content = lv_obj_create(parent);
    lv_obj_set_width(content, LV_PCT(100));
    lv_obj_set_flex_grow(content, 1);
    lv_obj_set_flex_flow(content, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(content, compact ? 2 : 6, LV_PART_MAIN);
    lv_obj_set_style_pad_row(content, compact ? 2 : 6, LV_PART_MAIN);
    lv_obj_set_style_border_width(content, 0, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(content, LV_OPA_TRANSP, LV_PART_MAIN);

    app->status_label = lv_label_create(content);
    lv_obj_set_width(app->status_label, LV_PCT(100));
    lv_label_set_long_mode(app->status_label, LV_LABEL_LONG_WRAP);
    if (compact) {
        lv_obj_set_style_text_font(app->status_label, lvgl_get_text_font(FONT_SIZE_SMALL), LV_STATE_DEFAULT);
    }

    app->prompt_card = lv_obj_create(content);
    lv_obj_set_size(app->prompt_card, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(app->prompt_card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_all(app->prompt_card, compact ? 4 : 8, LV_PART_MAIN);
    lv_obj_remove_flag(app->prompt_card, LV_OBJ_FLAG_SCROLLABLE);
    app->prompt_label = lv_label_create(app->prompt_card);
    lv_obj_set_width(app->prompt_label, LV_PCT(100));
    lv_label_set_long_mode(app->prompt_label, LV_LABEL_LONG_WRAP);
    lv_obj_t* buttons = lv_obj_create(app->prompt_card);
    lv_obj_set_size(buttons, LV_PCT(100), LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(buttons, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(buttons, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_all(buttons, 0, LV_PART_MAIN);
    lv_obj_set_style_border_width(buttons, 0, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(buttons, LV_OPA_TRANSP, LV_PART_MAIN);
    lv_obj_remove_flag(buttons, LV_OBJ_FLAG_SCROLLABLE);
    app->confirm_button = add_button(buttons, LV_SYMBOL_OK " Confirm", on_confirm, app);
    app->deny_button = add_button(buttons, LV_SYMBOL_CLOSE " Deny", on_deny, app);
    lv_obj_add_flag(app->prompt_card, LV_OBJ_FLAG_HIDDEN);

    app->credential_list = lv_list_create(content);
    lv_obj_set_width(app->credential_list, LV_PCT(100));
    lv_obj_set_flex_grow(app->credential_list, 1);

    app->status_timer = lv_timer_create(on_status_timer, 1000, app);

    app->credentials_dirty = true;
    passkey_ui_refresh(app);
}

void passkey_ui_destroy(void* user_data) {
    struct PasskeyApp* app = (struct PasskeyApp*)user_data;
    if (app->status_timer != NULL) {
        lv_timer_delete(app->status_timer);
        app->status_timer = NULL;
    }
    app->usb_switch = NULL;
    app->status_label = NULL;
    app->prompt_card = NULL;
    app->prompt_label = NULL;
    app->confirm_button = NULL;
    app->deny_button = NULL;
    app->credential_list = NULL;
}

// ---- Refreshing ----

static const char* up_reason_text(enum FidoUpReason reason) {
    switch (reason) {
        case FIDO_UP_REASON_MAKE_CREDENTIAL: return "Register passkey for";
        case FIDO_UP_REASON_GET_ASSERTION: return "Sign in to";
        case FIDO_UP_REASON_U2F_REGISTER: return "Register security key (U2F)";
        case FIDO_UP_REASON_U2F_AUTHENTICATE: return "Sign in with security key (U2F)";
        case FIDO_UP_REASON_RESET: return "The computer asks to RESET this key: all passkeys and the PIN will be erased";
        case FIDO_UP_REASON_SELECTION: return "The computer asks you to touch this key";
        case FIDO_UP_REASON_CREDENTIAL_EXCLUDED: return "Already registered at";
        case FIDO_UP_REASON_NO_CREDENTIALS: return "No passkey found for";
        case FIDO_UP_REASON_PIN_PROBE: return "The computer checks this key for";
        default: return "Confirm";
    }
}

static void refresh_prompt(struct PasskeyApp* app) {
    char text[256];
    switch (app->prompt) {
        case PASSKEY_PROMPT_USER_PRESENCE: {
            const char* reason = up_reason_text(app->up_reason);
            if (app->up_rp_id[0] != '\0' && app->up_user_name[0] != '\0') {
                snprintf(text, sizeof(text), "%s\n%s\nas %s", reason, app->up_rp_id, app->up_user_name);
            } else if (app->up_rp_id[0] != '\0') {
                snprintf(text, sizeof(text), "%s\n%s", reason, app->up_rp_id);
            } else {
                snprintf(text, sizeof(text), "%s", reason);
            }
            break;
        }
        case PASSKEY_PROMPT_DELETE_CREDENTIAL: {
            FidoCredentialInfo info;
            if (fido_get_resident_credential(app->selected_credential, &info)) {
                snprintf(text, sizeof(text), "Delete the passkey for\n%s\n%s?", info.rp_id, info.user_name);
            } else {
                snprintf(text, sizeof(text), "Delete this passkey?");
            }
            break;
        }
        case PASSKEY_PROMPT_FACTORY_RESET:
            snprintf(text, sizeof(text), "Erase ALL passkeys and the PIN?\nThis cannot be undone.");
            break;
        default:
            lv_obj_add_flag(app->prompt_card, LV_OBJ_FLAG_HIDDEN);
            return;
    }
    lv_label_set_text(app->prompt_label, text);
    bool was_hidden = lv_obj_has_flag(app->prompt_card, LV_OBJ_FLAG_HIDDEN);
    lv_obj_remove_flag(app->prompt_card, LV_OBJ_FLAG_HIDDEN);
    if (was_hidden) {
        // Devices without touch confirm with Enter: put the focus on the button right away.
        lv_group_t* group = lv_group_get_default();
        if (group != NULL) {
            lv_group_focus_obj(app->confirm_button);
        }
    }
}

static void refresh_status(struct PasskeyApp* app) {
    // While the worker waits for the user it holds the core lock: show the last known status then.
    static FidoStatus status;
    static bool have_status = false;
    if (fido_get_status(&status)) {
        have_status = true;
    }
    const char* usb;
    if (!app->usb_started) {
        usb = app->usb_error[0] != '\0' ? app->usb_error : "off (use the switch)";
    } else if (usb_transport_is_connected(app)) {
        usb = "connected to host";
    } else {
        usb = "waiting for host";
    }
    char text[256];
    if (have_status) {
        char pin[32];
        if (status.pin_set) {
            snprintf(pin, sizeof(pin), "set, %u tries left", (unsigned)status.pin_retries);
        } else {
            snprintf(pin, sizeof(pin), "not set");
        }
        snprintf(text, sizeof(text), "USB: %s\nPIN: %s\nPasskeys stored: %u%s%s",
                 usb, pin, (unsigned)status.resident_count,
                 app->storage_ok ? "" : "\nStorage: WRITE FAILED, check the SD card",
                 app->wink ? "\nThe host is looking for this key!" : "");
    } else {
        snprintf(text, sizeof(text), "USB: %s\nStarting...", usb);
    }
    lv_label_set_text(app->status_label, text);
    if (app->usb_switch != NULL) {
        if (app->usb_started) {
            lv_obj_add_state(app->usb_switch, LV_STATE_CHECKED);
        } else {
            lv_obj_remove_state(app->usb_switch, LV_STATE_CHECKED);
        }
    }
}

static void refresh_credentials(struct PasskeyApp* app) {
    // Rebuilt only when the state changed, so a visible list keeps its scroll position and focus.
    FidoStatus status;
    if (!app->credentials_dirty || !fido_get_status(&status)) {
        return;
    }
    app->credentials_dirty = false;
    lv_obj_clean(app->credential_list);
    if (status.resident_count == 0) {
        lv_list_add_text(app->credential_list, "No passkeys stored on this key");
    } else {
        lv_list_add_text(app->credential_list, "Passkeys (tap to delete)");
    }
    for (size_t i = 0; i < status.resident_count && i < MAX_LISTED_CREDENTIALS; i++) {
        FidoCredentialInfo info;
        if (!fido_get_resident_credential(i, &info)) {
            break;
        }
        char text[FIDO_MAX_RP_ID_LEN + FIDO_MAX_USER_NAME_LEN + 4];
        snprintf(text, sizeof(text), "%s\n%s", info.rp_id, info.user_name[0] ? info.user_name : "(no user name)");
        lv_obj_t* button = lv_list_add_button(app->credential_list, LV_SYMBOL_KEYBOARD, text);
        lv_obj_set_user_data(button, (void*)(uintptr_t)i);
        lv_obj_add_event_cb(button, on_credential_clicked, LV_EVENT_SHORT_CLICKED, app);
    }
    if (status.resident_count > MAX_LISTED_CREDENTIALS) {
        lv_list_add_text(app->credential_list, "...");
    }
    lv_obj_t* reset = lv_list_add_button(app->credential_list, LV_SYMBOL_TRASH, "Factory reset");
    lv_obj_add_event_cb(reset, on_reset_clicked, LV_EVENT_SHORT_CLICKED, app);
}

void passkey_ui_refresh(struct PasskeyApp* app) {
    if (!widgets_alive(app)) {
        return;
    }
    refresh_status(app);
    refresh_prompt(app);
    refresh_credentials(app);
}
