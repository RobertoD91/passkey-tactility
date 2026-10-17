// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "passkey_app.h"

/** window_manager_create_ext() callbacks */
void passkey_ui_create(lv_obj_t* parent, void* user_data);
void passkey_ui_destroy(void* user_data);

/** Updates the widgets from the app state. Call with the LVGL lock held. */
void passkey_ui_refresh(struct PasskeyApp* app);
