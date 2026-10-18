# CLAUDE.md

App Passkey per [Tactility](https://github.com/TactilityProject/Tactility): una security key FIDO2/U2F via
USB su ESP32-S3/P4. Rispondi all'utente in italiano.

## Repository pubblico

Dal 2026-10-18 il repository è **pubblico**: tutto ciò che viene committato, inclusa la storia, è visibile
a chiunque.

- Non committare mai segreti: token, chiavi, password, certificati, file `.env`.
- Non committare dati personali. I commit usano l'email `RobertoD91@users.noreply.github.com`.
- Non committare file di stato o di build: `passkey-store.bin`, `.tactility/` (host di `tt`), `build/`,
  `sdkconfig` delle app, cache di pytest. Sono già in `.gitignore`: controlla `git status` prima di ogni commit.
- I workflow non usano `secrets` e hanno permessi `contents: read`: mantienili così.

## Branch

- Lavora e pusha direttamente su `master`, su richiesta dell'utente.
- Non creare branch `claude/*`. Il vecchio branch di sessione `claude/adoring-fermi-8kri5u` è stato
  cancellato e non va ricreato.
- La cancellazione di un branch di sessione via `git push --delete` viene rifiutata dal proxy git della
  sessione: se serve, va fatta dall'utente dal web.

## Struttura

| Percorso | Contenuto |
|---|---|
| `Apps/Passkey/main/Source/fido/` | core FIDO portabile in C (CTAPHID, CTAP2, U2F, store, crypto); tutto passa da `fido_hal.h` |
| `Apps/Passkey/main/Source/*.c` | integrazione Tactility: HAL, trasporto USB, UI LVGL, `main` |
| `Apps/Passkey/main/sdk-overlay/` | `usb_hid_device.h` con l'API della patch FIDO, per compilare con l'SDK ufficiale |
| `Apps/Passkey/targets/rhc2026-badge/` | manifest `0.2` e `sdkconfig` per il badge RomHack Camp 2026 |
| `tactility-patch/` | patch per il firmware Tactility, testo della PR (`PR.md`), patch del device del badge |
| `tests/host/`, `tests/python/` | build Linux del core e test con python-fido2 |
| `Scripts/build-rhc2026-badge-app.sh` | build e pacchetto dell'app per il badge |

## Build e test

```sh
# test del core (vanno tenuti verdi a ogni modifica di fido/)
cmake -S tests/host -B tests/host/build -G Ninja -DPASSKEY_SANITIZE=ON && ninja -C tests/host/build
python -m pytest -q tests/python

# app per Tactility upstream (SDK 0.8.0-dev, ESP-IDF 6.1)
./tt app build -a esp32s3        # oppure esp32p4
```

L'app può usare solo i simboli che il firmware esporta (`DEFINE_MODULE_SYMBOL`). Dopo modifiche all'app,
verifica con `nm -D -u` sull'ELF che ogni simbolo importato sia esportato da Tactility, e per il badge anche
dal suo firmware. Per questo la UI usa solo LVGL di base e la toolbar.

## Patch per Tactility e repository collegati

- La patch `tactility-patch/0001-...patch` aggiunge `USB_HID_DEVICE_MODE_FIDO` al driver USB HID. Senza di
  essa l'app non si carica (`usb_hid_device_send_raw` mancante).
- Fork [RobertoD91/Tactility](https://github.com/RobertoD91/Tactility):
  - `usb-hid-fido-mode`: solo la patch, è il branch della PR verso `TactilityProject/Tactility` (non ancora
    aperta, testo in `tactility-patch/PR.md`);
  - `ci/usb-hid-fido-mode`: patch più il workflow manuale "Build Device Firmware";
  - `rhc2026-badge-fido`: workflow che compila il firmware del badge con le patch (immagine completa e SDK).
- Le patch esistono in due copie: `tactility-patch/` qui e `rhc2026-badge/` nel branch `rhc2026-badge-fido`
  del fork. Se ne cambi una, aggiorna anche l'altra.
- Issue di riferimento: [#1](https://github.com/RobertoD91/passkey-tactility/issues/1).

## Badge RomHack Camp 2026

Il firmware del [badge](https://github.com/CyberSaiyanIT/rhc2026-badge) contiene una copia più vecchia di
Tactility in `firmware/tactility`:

- ESP-IDF 5.5.2, app con manifest formato `0.2` e pacchetto `manifest.properties` + `elf/esp32s3.elf`,
  nessuno strumento `tt`;
- la patch `0001` si applica escludendo `Devices/*`; la `0002` abilita `usbdevicehid0` sul device
  `romhack2026-badge` (serve anche l'include `esp32_usbdevice.h` nel devicetree);
- lo script SDK del badge salta LVGL senza errori: va copiato `build/esp-idf/lvgl/liblvgl.a`;
- il link di `passkey.elf` fallisce sempre con quell'SDK: conta solo `passkey.app.elf`.

## Stato

Core verificato con python-fido2, app e firmware compilati per upstream e per il badge. Nessun test
ancora su hardware reale: dillo sempre quando riporti lo stato.
