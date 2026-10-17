# Third-party notices

The app's own code is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
It bundles the following third-party code:

## micro-ecc

- Path: `Apps/Passkey/main/Source/fido/crypto/micro-ecc/`
- Source: https://github.com/kmackay/micro-ecc (commit `541b3a78026420a3e369c4c9281c396b5e531113`)
- License: BSD 2-Clause, Copyright (c) 2014 Kenneth MacKay. See `LICENSE.txt` in that folder.
- Modifications: none (only P-256 is compiled in, through `uECC_SUPPORTS_*` definitions).

## tiny-AES-c

- Path: `Apps/Passkey/main/Source/fido/crypto/tiny-aes/`
- Source: https://github.com/kokke/tiny-AES-c (commit `23856752fbd139da0b8ca6e471a13d5bcc99a08d`)
- License: The Unlicense (public domain). See `unlicense.txt` in that folder.
- Modifications: `aes.h` selects AES-256 and disables the ECB and CTR modes.

## Tactility SDK headers

- Path: `Apps/Passkey/main/sdk-overlay/tactility/drivers/usb_hid_device.h`
- Source: https://github.com/TactilityProject/Tactility, `TactilityKernel/include/tactility/drivers/usb_hid_device.h`
- License: Apache License 2.0.
- Modifications: the additions of `tactility-patch/0001-Add-USB-HID-FIDO-mode-for-CTAPHID-authenticators.patch`.
