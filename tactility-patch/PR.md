# Pull request text for TactilityProject/Tactility

Branch: `RobertoD91/Tactility:usb-hid-fido-mode` → `TactilityProject/Tactility:main`

Compare link: https://github.com/TactilityProject/Tactility/compare/main...RobertoD91:Tactility:usb-hid-fido-mode

---

**Title:** Add USB HID FIDO mode for CTAPHID authenticators

**Body:**

This adds `USB_HID_DEVICE_MODE_FIDO` to the USB HID device driver so an app can present the device to a host as a FIDO2/U2F security key (CTAPHID transport):

- `hid_report_map_fido`: the FIDO Alliance report map (usage page `0xF1D0`, 64-byte IN and OUT reports, no report IDs), the same bytes as TinyUSB's `TUD_HID_REPORT_DESC_FIDO_U2F`.
- The FIDO mode allocates an interrupt OUT endpoint and installs a `TUD_HID_INOUT_DESCRIPTOR` (the other modes keep their IN-only descriptor).
- `usb_hid_device_send_raw()` sends a raw 64-byte IN report; `usb_hid_device_set_raw_report_callback()` registers the receiver of OUT reports, which `tud_hid_set_report_cb()` forwards in FIDO mode. Both are exported to apps.
- Product name "Tactility FIDO" and its own PID (`0x4009`), following the per-mode PID scheme.
- `usbdevicehid0` is enabled (devicetree node + `hardware.tinyUsbHid=true`) on the ESP32-S3 devices that already have a `usbdevice0` node, so the HID class driver is built for them. Happy to trim this list if you prefer to enable it per board.

Motivation: a passkey/security-key app ([passkey-tactility](https://github.com/RobertoD91/passkey-tactility)). Apps only see the USB classes the kernel exports, and the existing modes (keyboard, mouse, gamepad) have fixed report maps and no OUT endpoint, so CTAPHID can't be done from an app without this.

Testing:
- Firmware builds with ESP-IDF 6.1 for `lilygo-tdongle-s3`.
- The app that uses the new API builds against the SDK for esp32s3 and esp32p4, and its CTAP2/U2F core is tested against python-fido2 on Linux.
- Tested on an ESP32-S3 board, the RomHack Camp 2026 badge. Its firmware carries a copy of Tactility with the same USB HID device driver (ESP-IDF 5.5.2), and this patch was applied to it. With Chrome on macOS: passkey registration and sign-in on webauthn.io, and sign-in on passkeys.io, where Chrome set a PIN on first use. Not yet tested on a board running `main`.

Disclosure: the patch was written with AI assistance (Claude) and reviewed by the submitter.
