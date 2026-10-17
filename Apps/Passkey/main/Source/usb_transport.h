// SPDX-License-Identifier: Apache-2.0
/** Presents the device as a FIDO security key over USB and queues the host's packets. */
#pragma once

#include "passkey_app.h"

/** @return false when the firmware has no USB HID device or the USB slot is busy; app->usb_error says why. */
bool usb_transport_start(struct PasskeyApp* app);
void usb_transport_stop(struct PasskeyApp* app);
bool usb_transport_is_connected(struct PasskeyApp* app);
