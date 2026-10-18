# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

App Passkey per [Tactility](https://github.com/TactilityProject/Tactility): una security key FIDO2/U2F
(CTAP 2.1 e CTAP1) via USB su ESP32-S3/P4. Rispondi all'utente in italiano. README e `docs/` sono in
italiano. Commenti nel codice, messaggi di commit e testi per upstream (patch, `tactility-patch/PR.md`)
sono in inglese.

## Repository pubblico e branch

Dal 2026-10-18 il repository è **pubblico**: ogni commit, storia inclusa, è visibile a chiunque.

- Niente dati personali: i commit usano l'email `RobertoD91@users.noreply.github.com`.
- Niente file di stato o di build (`passkey-store.bin`, `.tactility/`, `build/`, `Apps/*/sdkconfig`): sono
  in `.gitignore`, ma controlla `git status` prima di ogni commit.
- I workflow non usano `secrets` e hanno solo `contents: read`: mantienili così.
- Lavora e pusha direttamente su `master`. Non creare branch `claude/*`: il vecchio branch di sessione
  `claude/adoring-fermi-8kri5u` è stato cancellato e non va ricreato. Il proxy git della sessione rifiuta
  `git push --delete` su quel tipo di branch, quindi una cancellazione la fa l'utente dal web.

## Comandi

```sh
# core FIDO come processo Linux + test python-fido2 (pip install fido2 pytest)
cmake -S tests/host -B tests/host/build -G Ninja -DPASSKEY_SANITIZE=ON
ninja -C tests/host/build        # pytest non ricompila: rilancia ninja dopo ogni modifica al core
python -m pytest -q tests/python
python -m pytest -q "tests/python/test_pin.py::test_change_pin[protocol2]"   # un solo test
python -m pytest -q tests/python -k hmac                                     # per nome

# app per Tactility upstream (ESP-IDF 6.1 attivo, scarica l'SDK 0.8.0-dev in ~/.tactility)
./tt app build -p Apps/Passkey -a esp32s3    # oppure esp32p4 → Apps/Passkey/build/robertod.passkey.app

# app per il badge RHC2026 (ESP-IDF 5.5 attivo, SDK generato dal firmware del badge, vedi sotto)
Scripts/build-rhc2026-badge-app.sh <cartella TactilitySDK>   # → build/rhc2026-badge/robertod.passkey.app
```

- `tt app` lavora sulla cartella corrente: dalla radice serve `-p Apps/Passkey`, altrimenti fallisce con
  `manifest.properties not found`. La CI svuota `IDF_TARGET` prima di chiamarlo, perché tt sceglie il
  target da sé.
- Entrambi i `CMakeLists.txt` raccolgono i sorgenti con `file(GLOB)`: un nuovo `.c` in `fido/` entra in
  tutte e due le build, ma per la build host va rilanciato `cmake`.
- La build host usa `-Wall -Wextra` e oggi compila senza warning. Non ci sono linter o formatter.
- Fixture dei test (`tests/python/conftest.py`): `make_authenticator(up="deny"|"timeout", up_delay_ms=…,
  up_timeout_ms=…)` avvia `passkey-host` su un file di stato nella `tmp_path` del test. Una seconda
  chiamata nello stesso test riusa quel file e simula un ciclo di alimentazione. Il log del core finisce in
  `authenticator.log` nella `tmp_path`. `PASSKEY_HOST_BINARY` sceglie un altro binario.

## Architettura

**Core portabile e due HAL.** `Apps/Passkey/main/Source/fido/` è C11 senza dipendenze di piattaforma.
Tutto ciò che gli serve passa da `fido_hal.h`, implementato due volte:

- `Source/hal_tactility.c` per il dispositivo;
- `tests/host/hal_host.c` per Linux: CTAPHID su stdin/stdout, stato nel file di `PASSKEY_STORE`, presenza
  utente simulata da `PASSKEY_UP`.

Le modifiche al core si verificano con i test host. Il resto di `Source/` si può solo compilare per ESP32,
non eseguire.

**Percorso di un pacchetto.**

1. Il callback dei report OUT di `usb_transport.c` gira sul task di TinyUSB e copia il pacchetto in una
   coda FreeRTOS da 16.
2. Il worker la svuota in `fido_poll()`.
3. `ctaphid.c` riassembla i messaggi e gestisce canali e CANCEL.
4. I messaggi CTAP2 vanno a `ctap2.c` (dispatch CBOR), i messaggi CTAP1 a `u2f.c`. `ctap2_pin.c` e
   `ctap2_credmgmt.c` condividono lo stato di sessione `Ctap2Session` tramite `ctap2_internal.h`.

**Task, lock e segnali** (`main.c`, `passkey_app.h`):

- **Task principale dell'app.** È l'unico che avvia e ferma l'USB, ed esegue le richieste della UI scritte
  in `app->request`: USB on/off, cancellazione di una passkey, reset di fabbrica.
- **Worker.** Esegue tutto il core tenendo `fido_hal_lock`, anche mentre `fido_request_user_presence()`
  aspetta l'utente: in quell'attesa invia i keepalive e accetta il CANCEL dell'host.
- **Codice UI (`ui.c`).** Gira sia sul task LVGL (callback, timer di stato) sia sul task principale
  (`refresh_ui()` sotto `lvgl_try_lock`). Legge il core con `fido_get_*`, che prendono il lock con un
  timeout di 20 ms e restituiscono `false` se il core è occupato. Risponde ai prompt scrivendo
  `app->up_state`.
- **Segnali.** Le HAL e la UI comunicano tramite i campi `volatile` di `struct PasskeyApp` e svegliano il
  task principale con il bit `ui_bit` del suo event group.
- **Widget.** I puntatori valgono solo mentre la finestra è in primo piano: `passkey_ui_destroy` li azzera.
  Alla chiusura il prompt aperto viene risposto "denied" prima di fermare il worker.
- **Presenza utente U2F.** Non blocca, perché i client U2F ripetono la richiesta: la conferma resta valida
  `FIDO_U2F_UP_CACHE_MS`. Limiti e timeout sono in `fido_config.h`.

**Stato persistente.** `store.c` serializza tutto `FidoStore` in un unico blob (magic, versione e
SHA-256) e lo riscrive a ogni modifica. `hal_tactility.c` lo cifra con `crypt-module` (header `TPKE`, IV
e lunghezza) e lo scrive in modo atomico con `.tmp` e `rename`.

**Credenziali derivate.** Gli ID di credenziale, che sono anche i key handle U2F, contengono un nonce e un
tag HMAC legato al `rpIdHash` (formato in `credential.h`). Le chiavi private si derivano dal master secret
e si salvano solo le credenziali discoverable. Il flag `resident` nell'ID fa fallire `credential_unwrap`
quando il record della credenziale è stato cancellato.

> [!WARNING]
> Se `deserialize()` fallisce, `store_init()` riparte da uno stato nuovo e perde tutte le passkey del
> dispositivo. Lo stesso succede alle credenziali già registrate se cambi la derivazione o il formato degli
> ID. Una modifica al formato del blob richiede quindi `STORE_VERSION` e una migrazione.

**Simboli.** L'app è un ELF condiviso caricato da Tactility e può usare solo i simboli che il firmware
esporta (`DEFINE_MODULE_SYMBOL`). Dopo modifiche all'app controlla con `nm -D -u` sull'ELF che ogni
simbolo importato sia esportato da Tactility, e per il badge anche dal suo firmware. Per questo la UI usa
solo LVGL di base e la toolbar. `main/sdk-overlay/` contiene l'`usb_hid_device.h` della patch FIDO, così
l'app compila contro l'SDK ufficiale.

## Patch per Tactility e repository collegati

- `tactility-patch/0001-...patch` aggiunge `USB_HID_DEVICE_MODE_FIDO` al driver USB HID. È necessaria
  perché le app non vedono TinyUSB. Senza la patch l'app non si carica (`usb_hid_device_send_raw` mancante).
- Fork [RobertoD91/Tactility](https://github.com/RobertoD91/Tactility):
  - `usb-hid-fido-mode`: contiene solo la patch ed è il branch della PR verso `TactilityProject/Tactility`.
    La PR non è ancora aperta e il suo testo è in `tactility-patch/PR.md`.
  - `ci/usb-hid-fido-mode`: la patch più il workflow manuale "Build Device Firmware".
  - `rhc2026-badge-fido`: il workflow che compila il firmware del badge con le patch (immagine completa e
    SDK).
- Le patch esistono in due copie, in `tactility-patch/` qui e in `rhc2026-badge/` nel branch
  `rhc2026-badge-fido` del fork: se ne cambi una, aggiorna anche l'altra.
- Issue di riferimento: [#1](https://github.com/RobertoD91/passkey-tactility/issues/1).

## Badge RomHack Camp 2026

Il firmware del [badge](https://github.com/CyberSaiyanIT/rhc2026-badge) contiene una copia più vecchia di
Tactility in `firmware/tactility`. Il workflow `rhc2026-badge-app.yml` ne fissa il commit in `BADGE_REF`.

- Usa ESP-IDF 5.5.2 e non ha lo strumento `tt`. Le app hanno un manifest in formato `0.2`
  (`Apps/Passkey/targets/rhc2026-badge/`) e il pacchetto contiene `manifest.properties` più
  `elf/esp32s3.elf`.
- La patch `0001` si applica escludendo `Devices/*`. La `0002` abilita `usbdevicehid0` sul device
  `romhack2026-badge` e serve anche l'include `esp32_usbdevice.h` nel devicetree.
- Lo script SDK del badge salta LVGL senza dare errori, quindi `build/esp-idf/lvgl/liblvgl.a` va copiato a
  mano.
- Con quell'SDK il link di `passkey.elf` fallisce sempre e conta solo `passkey.app.elf`.

## Stato

Il core è verificato con python-fido2 (50 test). App e firmware compilano sia per upstream sia per il
badge. Non c'è ancora nessun test su hardware reale: dillo sempre quando riporti lo stato.
