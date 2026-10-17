# Patch per Tactility: modalità USB HID FIDO

Il driver USB HID device di Tactility (`usb_hid_device`) espone solo le modalità tastiera,
mouse, tastiera+mouse e gamepad. Un autenticatore FIDO2/U2F ha bisogno di:

- un report descriptor con usage page FIDO Alliance (`0xF1D0`), report IN e OUT da 64 byte senza report ID;
- un endpoint interrupt **OUT** (le modalità esistenti hanno solo l'endpoint IN);
- la consegna all'app dei report OUT ricevuti dall'host (`tud_hid_set_report_cb`) e l'invio di report IN grezzi.

La patch [`0001-Add-USB-HID-FIDO-mode-for-CTAPHID-authenticators.patch`](0001-Add-USB-HID-FIDO-mode-for-CTAPHID-authenticators.patch)
aggiunge questo al kernel e al driver ESP32, senza toccare le modalità esistenti:

| File | Modifica |
|---|---|
| `TactilityKernel/include/tactility/drivers/usb_hid_device.h` | `USB_HID_DEVICE_MODE_FIDO`, `UsbHidDeviceRawReportCallback`, `send_raw()`, `set_raw_report_callback()` |
| `TactilityKernel/source/drivers/usb_hid_device.cpp` | wrapper `usb_hid_device_send_raw()` / `usb_hid_device_set_raw_report_callback()` |
| `TactilityKernel/source/symbols.c` | esporta i due nuovi simboli alle app esterne |
| `Platforms/platform-esp32/.../hid_report_descriptors.{h,cpp}` | report map `hid_report_map_fido` |
| `Platforms/platform-esp32/source/drivers/usb/esp32_usb_hid_device.cpp` | descrittore `TUD_HID_INOUT_DESCRIPTOR`, allocazione dell'endpoint OUT, PID `0x4009`, nome "Tactility FIDO", inoltro dei report OUT, `send_raw()` |
| `Devices/*/` (ESP32-S3 con `usbdevice0`) | nodo `usbdevicehid0` nel devicetree e `hardware.tinyUsbHid=true` in `device.properties` |

La patch è stata generata contro il commit `76434d5bcd6246def97f16f153a0ae159d7145e4` di
[TactilityProject/Tactility](https://github.com/TactilityProject/Tactility) (ramo `main`, SDK `0.8.0-dev`).

## Applicarla

```sh
git clone --recurse-submodules https://github.com/TactilityProject/Tactility.git
cd Tactility
git am /percorso/di/passkey-tactility/tactility-patch/0001-Add-USB-HID-FIDO-mode-for-CTAPHID-authenticators.patch
python device.py lilygo-tdeck      # o un altro dispositivo ESP32-S3 / ESP32-P4
idf.py build flash
```

Poi genera l'SDK locale con `python Buildscripts/release-current.py` e compila l'app con
`TACTILITY_SDK_PATH=/percorso/Tactility/release ./tt app build -a esp32s3` (vedi il README principale).

## Note di progettazione

- Il buffer dell'endpoint OUT di TinyUSB (`CFG_TUD_HID_EP_BUFSIZE`) vale 64 byte con la
  configurazione di `esp_tinyusb`, esattamente la dimensione di un pacchetto CTAPHID.
- Il callback dei report OUT viene chiamato sul task di TinyUSB: l'app copia il pacchetto in una
  coda e lo elabora sul proprio task (è quello che fa `usb_transport.c` in questo repository).
- Il report descriptor è quello standard del trasporto HID di CTAP (identico a
  `TUD_HID_REPORT_DESC_FIDO_U2F` di TinyUSB), così Windows, macOS, Linux e i browser riconoscono
  il dispositivo come security key senza driver.
- Sul `m5stack-tab5` (ESP32-P4) il nodo `usbdevicehid0` esiste già: la patch ai device riguarda
  solo le schede ESP32-S3 che hanno già `usbdevice0`.
