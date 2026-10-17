// SPDX-License-Identifier: Apache-2.0
#include "usb_transport.h"

#include <tactility/drivers/usb_hid_device.h>
#include <tactility/log.h>

#include <stdio.h>
#include <string.h>

#define RX_QUEUE_LENGTH 16

// Runs on the USB stack's task: only copies the packet into the queue the worker drains.
static void on_raw_report(const uint8_t* report, size_t len, void* context) {
    struct PasskeyApp* app = (struct PasskeyApp*)context;
    if (len != FIDO_HID_PACKET_SIZE || app->rx_queue == NULL) {
        return;
    }
    if (xQueueSend(app->rx_queue, report, 0) != pdTRUE) {
        LOG_W(PASSKEY_TAG, "USB packet dropped: queue full");
    }
}

bool usb_transport_start(struct PasskeyApp* app) {
    app->usb_error[0] = '\0';
    if (app->usb_started) {
        return true;
    }
    struct Device* device = usb_hid_device_get();
    if (device == NULL) {
        snprintf(app->usb_error, sizeof(app->usb_error), "No USB HID device (needs the FIDO patch)");
        return false;
    }
    if (app->rx_queue == NULL) {
        app->rx_queue = xQueueCreate(RX_QUEUE_LENGTH, FIDO_HID_PACKET_SIZE);
        if (app->rx_queue == NULL) {
            device_put(device);
            snprintf(app->usb_error, sizeof(app->usb_error), "Out of memory");
            return false;
        }
    }
    usb_hid_device_set_name(device, "Tactility Passkey");
    usb_hid_device_set_raw_report_callback(device, on_raw_report, app);
    error_t result = usb_hid_device_start(device, USB_HID_DEVICE_MODE_FIDO);
    if (result != ERROR_NONE) {
        usb_hid_device_set_raw_report_callback(device, NULL, NULL);
        device_put(device);
        if (result == ERROR_RESOURCE_BUSY) {
            snprintf(app->usb_error, sizeof(app->usb_error), "USB is in use (mass storage?)");
        } else if (result == ERROR_NOT_SUPPORTED) {
            snprintf(app->usb_error, sizeof(app->usb_error), "Firmware lacks the FIDO HID mode");
        } else {
            snprintf(app->usb_error, sizeof(app->usb_error), "USB start failed (%d)", (int)result);
        }
        LOG_E(PASSKEY_TAG, "%s", app->usb_error);
        return false;
    }
    app->hid_device = device;
    app->usb_started = true;
    LOG_I(PASSKEY_TAG, "USB FIDO interface started");
    return true;
}

void usb_transport_stop(struct PasskeyApp* app) {
    if (!app->usb_started) {
        return;
    }
    usb_hid_device_stop(app->hid_device);
    usb_hid_device_set_raw_report_callback(app->hid_device, NULL, NULL);
    device_put(app->hid_device);
    app->hid_device = NULL;
    app->usb_started = false;
    if (app->rx_queue != NULL) {
        xQueueReset(app->rx_queue);
    }
    LOG_I(PASSKEY_TAG, "USB FIDO interface stopped");
}

bool usb_transport_is_connected(struct PasskeyApp* app) {
    return app->usb_started && app->hid_device != NULL && usb_hid_device_is_connected(app->hid_device);
}
