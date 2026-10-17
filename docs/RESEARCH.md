# Ricerca: passkey hardware su ESP32 e Tactility

Questa nota riassume cosa esiste già (ottobre 2026) e perché l'app è strutturata com'è.

## Progetti esistenti

| Progetto | Hardware | Cosa offre | Riutilizzabile per Tactility? |
|---|---|---|---|
| [pico-fido](https://github.com/polhenarejos/pico-fido) (pico-keys-sdk) | RP2040/RP2350 **e ESP32-S3** | CTAP 2.1/2.3, U2F, hmac-secret, credProtect, PIN, credential management, large blobs, OATH/OTP via CCID, Secure Boot su S3. Il più completo. Licenza AGPL-3.0. | Solo come firmware a sé stante: `main.c` possiede `app_main`, TinyUSB (`tinyusb_driver_install`, descrittori propri), una partizione flash dedicata, efuse/OTP e un file system interno. Non è una libreria che un'app ELF possa caricare. |
| [jocover/esp32_u2f](https://github.com/jocover/esp32_u2f) | ESP32-S2/S3 (Arduino) | FIDO2/U2F token, derivato da pico-fido. | Stessa architettura monolitica. |
| [quicknet-lab/quick-key](https://github.com/quicknet-lab/quick-key) | LilyGO T-Dongle S3 | FIDO2/U2F, OpenPGP, PIV, TOTP, password manager. | Firmware completo per una sola scheda. |
| [Felix3322/esp32-yubikey5c](https://github.com/Felix3322/esp32-yubikey5c) ("LibreFido 2") | ESP32-S3 | FIDO2, OATH, OTP, OpenPGP, PIV, con tool host. | Firmware completo. |
| [wychlw/canokey-ESP32-S2](https://github.com/wychlw/canokey-ESP32-S2), [canokey-esp32](https://github.com/ZenithalHourlyRate/canokey-esp32) | ESP32-S2 | Port di canokey-core (U2F, FIDO2, OpenPGP, PIV, OATH). Il secondo è incompleto e fermo dal 2023. | canokey-core è portabile ma ha un proprio livello device/USB, da reimplementare. |
| [itres-labs/esp32-fido2-lab](https://github.com/itres-labs/esp32-fido2-lab) | ESP32-S3 | CTAP2 sperimentale, senza U2F. | Firmware completo. |
| Zephyr `samples/subsys/authentication/fido2` | ESP32-S3 (Zephyr) | CTAP 2.1 su USB HID. | Dipende da Zephyr. |

Conclusione: non esiste un'app Tactility né una libreria FIDO "a innesto" per Tactility.
Tutti i progetti sopra sostituiscono il firmware e parlano direttamente con TinyUSB.

## Il vincolo di Tactility

Le app esterne di Tactility sono file ELF caricati dalla SD/flash e collegati a runtime **solo**
ai simboli che il firmware esporta esplicitamente (`DEFINE_MODULE_SYMBOL` nel kernel e nei
moduli). Guardando il sorgente di Tactility `0.8.0-dev` (commit `76434d5`):

- TinyUSB non è esportato alle app.
- Il kernel esporta `usb_device_controller_*` (claim della porta USB device, allocazione di
  interfacce ed endpoint) e `usb_hid_device_*`, ma il driver HID device conosce solo le modalità
  tastiera, mouse, tastiera+mouse e gamepad, tutte con il solo endpoint IN.
- I callback TinyUSB `tud_hid_descriptor_report_cb` e `tud_hid_set_report_cb` sono definiti una
  volta nel firmware (`esp32_usb_hid_device.cpp`) e restituiscono sempre la mappa della modalità
  attiva: un'app non può né pubblicare l'usage page FIDO (`0xF1D0`) né ricevere i report OUT.
- Il BLE HID ha le stesse modalità fisse, e comunque i browser non supportano più le security key
  BLE (resta solo il trasporto "hybrid"/caBLE, che richiede un tunnel in rete).

Per questo serve una piccola estensione del kernel, [tactility-patch/](../tactility-patch/):
una modalità `USB_HID_DEVICE_MODE_FIDO` con `send_raw()` e un callback per i report OUT. È il
tipo di modifica proponibile upstream: dopo l'unione l'app funziona su firmware stock.

## Scelte progettuali dell'app

- **Core FIDO scritto da zero, in C portabile**, con una HAL minima (`fido_hal.h`): si compila
  e si testa su Linux con python-fido2, la libreria di riferimento di Yubico, prima ancora di
  toccare l'hardware. Integrare pico-fido avrebbe richiesto di riscrivere il suo livello
  APDU/file system/flash/OTP: più lavoro e più rischio di un'implementazione mirata.
- **Crittografia in-app**: alle app Tactility sono esportate solo le funzioni di hashing di
  mbedtls (`mbedtls_md_*`) e AES-CBC con chiave di dispositivo (`crypt_*`). ECDSA P-256 ed ECDH
  arrivano da [micro-ecc](https://github.com/kmackay/micro-ecc) (BSD-2), AES-256 da
  [tiny-AES-c](https://github.com/kokke/tiny-AES-c) (Unlicense), SHA-256/HMAC/HKDF sono
  implementati nel progetto. La casualità viene da `crypt_generate_iv()` (`esp_fill_random`).
- **Credenziali derivate**: l'ID credenziale contiene un nonce e un tag HMAC; la chiave privata
  si deriva dal segreto master. Le credenziali non discoverable non occupano spazio; quelle
  discoverable aggiungono un record (RP, utente) nel file di stato, che su dispositivo è cifrato
  con la chiave di dispositivo di `crypt-module`.
- **Attestazione**: self attestation ("packed", senza certificato) per CTAP2, certificato X.509
  autofirmato generato sul dispositivo per U2F, che lo richiede. Nessuna chiave di attestazione
  condivisa fra dispositivi, quindi nessuna tracciabilità fra RP.
- **Presenza utente**: la UI mostra la richiesta (RP, utente) con due pulsanti; funziona anche
  senza touch (il pulsante Conferma riceve il focus). I client U2F ricevono `6985` e ripetono la
  richiesta finché l'utente non conferma, come da specifica.
