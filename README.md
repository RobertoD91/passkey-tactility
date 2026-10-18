# Passkey per Tactility

Un'app per [Tactility](https://github.com/TactilityProject/Tactility) (il sistema operativo per
ESP32) che trasforma il dispositivo in una **security key FIDO2/U2F via USB**, nello spirito di
[pico-fido](https://github.com/polhenarejos/pico-fido): registrazione e accesso con passkey da
browser e sistemi operativi, con conferma della presenza utente sullo schermo del dispositivo.

> **Stato**: software sperimentale, non certificato FIDO e non sottoposto ad audit di sicurezza.
> Il core è verificato su Linux contro [python-fido2](https://github.com/Yubico/python-fido2)
> (libreria di riferimento di Yubico) con 50 test automatici; l'app compila per ESP32-S3 ed
> ESP32-P4 con l'SDK ufficiale 0.8.0-dev e tutti i simboli che importa sono esportati dal
> firmware patchato, che a sua volta compila (ESP-IDF 6.1, T-Dongle S3). Su hardware è stata
> provata sul badge RomHack Camp 2026 (ESP32-S3) con Chrome su macOS: registrazione e accesso su
> [webauthn.io](https://webauthn.io), accesso su [passkeys.io](https://www.passkeys.io) con il PIN
> impostato da Chrome al primo uso. Il firmware Tactility upstream, le altre schede e gli altri
> sistemi e browser non sono ancora stati provati: le segnalazioni sono benvenute.

## Cosa fa

- **CTAP 2.1 su USB HID**: `authenticatorMakeCredential`, `GetAssertion`/`GetNextAssertion`,
  `GetInfo`, `ClientPIN` (protocolli 1 e 2, `pinUvAuthToken` con permessi), `Reset`,
  `CredentialManagement` (anche il "preview" 0x41), `Selection`.
- **Estensioni** `hmac-secret` (quindi WebAuthn PRF) e `credProtect`.
- **Passkey discoverable** (resident key, fino a 32) con nome utente e RP memorizzati, oltre alle
  credenziali non discoverable, illimitate perché derivate dal segreto master.
- **U2F / CTAP1** (`U2F_V2`) con certificato di attestazione autofirmato generato sul dispositivo;
  gli handle U2F e gli ID CTAP2 sono intercambiabili.
- **Presenza utente** con pulsanti Conferma/Rifiuta sul display (anche da tastiera), keepalive
  CTAPHID, annullamento da host, timeout.
- **PIN** con 8 tentativi (3 consecutivi per ciclo di alimentazione), policy di lunghezza, hash
  conservato come da specifica.
- **UI**: stato USB/PIN, elenco delle passkey memorizzate con cancellazione, reset di fabbrica.
- Lo stato (segreti, PIN, passkey, contatore) è un file nella cartella dati dell'app, **cifrato
  con la chiave di dispositivo** di Tactility (`crypt-module`, AES-256-CBC): copiato altrove non è
  leggibile.

## Come funziona

```
browser / OS  ──USB HID (CTAPHID, 64 byte)──▶  Tactility: driver usb_hid_device (modalità FIDO)
                                                      │  callback report OUT → coda FreeRTOS
                                                      ▼
                                       Apps/Passkey: task worker → core FIDO (ctaphid → ctap2/u2f)
                                                      │  fido_hal.h
                                                      ▼
                                       UI LVGL (presenza utente)   file di stato cifrato
```

Il core (`Apps/Passkey/main/Source/fido/`) è C portabile senza dipendenze dalla piattaforma:
tutto ciò che gli serve passa da `fido_hal.h` (random, orologio, storage, pacchetti HID,
presenza utente, lock). Per questo lo stesso codice gira anche come processo Linux nei test.

La crittografia è in-app: P-256 ECDSA/ECDH da [micro-ecc](https://github.com/kmackay/micro-ecc),
AES-256 da [tiny-AES-c](https://github.com/kokke/tiny-AES-c), SHA-256/HMAC/HKDF proprie. Vedi
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Perché serve una patch a Tactility

A differenza del Flipper Zero, dove un'app può installare un proprio descrittore USB, le app
Tactility sono ELF che vedono solo i simboli esportati dal firmware. Il driver USB HID device di
Tactility conosce solo tastiera, mouse e gamepad (solo endpoint IN) e i callback TinyUSB sono
fissi nel firmware: nessuna app può pubblicare l'usage page FIDO né ricevere i report OUT.

La cartella [`tactility-patch/`](tactility-patch/) contiene una patch piccola e autonoma che
aggiunge la modalità `USB_HID_DEVICE_MODE_FIDO` (descrittore FIDO, endpoint OUT, `send_raw()`,
callback per i report in ingresso) e abilita il nodo `usbdevicehid0` sulle schede ESP32-S3 che
hanno già la porta USB device. È pensata per essere proposta upstream. L'analisi completa è in
[docs/RESEARCH.md](docs/RESEARCH.md), insieme al confronto con i progetti esistenti.

## Dispositivi

Serve un SoC con USB OTG: **ESP32-S3** (T-Deck, Cardputer, CoreS3, T-Dongle S3, T-Display S3,
...) o **ESP32-P4** (M5Stack Tab5). ESP32 classico e ESP32-C6 non hanno USB device. La porta USB
deve essere quella OTG collegata al PHY nativo (la stessa usata da Tactility per la mass storage).

**Badge RomHack Camp 2026**: il suo firmware contiene una copia più vecchia di Tactility (ESP-IDF 5.5,
formato app `0.2`), quindi ha una build dedicata. Il firmware con la patch esce dal workflow del
branch [`rhc2026-badge-fido`](https://github.com/RobertoD91/Tactility/tree/rhc2026-badge-fido) del
fork di Tactility, l'app dal workflow "Passkey for the RHC2026 badge" di questo repository (oppure
in locale con `Scripts/build-rhc2026-badge-app.sh`). Dettagli in [tactility-patch/README.md](tactility-patch/README.md).

## Compilare e installare

### 1. Firmware Tactility con la patch

```sh
git clone --recurse-submodules https://github.com/TactilityProject/Tactility.git
cd Tactility
git am /percorso/passkey-tactility/tactility-patch/0001-Add-USB-HID-FIDO-mode-for-CTAPHID-authenticators.patch
python device.py lilygo-tdeck        # il tuo dispositivo
idf.py build flash
```

Richiede ESP-IDF 6.1 (vedi i [requisiti di Tactility](https://github.com/TactilityProject/TactilityDocs)).

### 2. L'app

```sh
cd passkey-tactility
./tt app build -p Apps/Passkey -a esp32s3   # scarica l'SDK 0.8.0-dev dal CDN di Tactility
./tt host 192.168.1.50                      # IP del dispositivo (app Development → server di sviluppo acceso)
./tt app install -p Apps/Passkey
./tt app run -p Apps/Passkey
```

`tt app` lavora sulla cartella dell'app: dalla radice del repository serve `-p Apps/Passkey`, senza
fallisce con `manifest.properties not found`.

Il pacchetto `Apps/Passkey/build/robertod.passkey.app` si può anche copiare sulla SD e installare
dall'app Files. L'app compila contro l'SDK ufficiale grazie alla copia dell'header patchato in
`Apps/Passkey/main/sdk-overlay/`; a runtime però il firmware deve contenere la patch, altrimenti il
caricamento fallisce con `Can't find symbol usb_hid_device_send_raw`.

### 3. Uso

1. Apri **Passkey**: l'interruttore nella toolbar accende l'interfaccia USB FIDO (si accende da
   sola all'avvio). Sull'ESP32-S3 la porta smette di fare da console seriale finché l'app è aperta.
2. Collega il dispositivo al computer: compare come "Tactility Passkey" (VID `303A`, PID `4009`).
3. Da un sito con passkey (o da `chrome://settings/securityKeys`, `ykman`, `fido2-token`) avvia
   la registrazione: sul display appare la richiesta con il nome del sito e l'utente, premi
   **Conferma**. Lo stesso per l'accesso.
4. Il PIN si imposta dal computer (Chrome, Windows, `ykman fido access change-pin`); l'app mostra se
   è impostato e i tentativi rimasti.
5. Le passkey memorizzate sono elencate nell'app: un tocco permette di cancellarle; in fondo c'è il
   reset di fabbrica.

Tieni l'app aperta mentre usi la chiave: la richiesta di conferma è nella sua finestra.

## Test su PC

Il core si compila come processo Linux che parla CTAPHID su stdin/stdout, e python-fido2 lo
pilota con il suo stesso framing HID (`CtapHidDevice`), quindi i test esercitano anche il
trasporto:

```sh
pip install fido2 pytest
cmake -S tests/host -B tests/host/build -G Ninja -DPASSKEY_SANITIZE=ON
ninja -C tests/host/build
python -m pytest -q tests/python
```

I test coprono getInfo, make/getAssertion con verifica delle firme, exclude list, credenziali
discoverable e `getNextAssertion`, persistenza fra riavvii, reset, presenza utente (conferma,
rifiuto, timeout, cancel), hmac-secret, credProtect, PIN (entrambi i protocolli, tentativi,
blocco, cambio, policy, permessi e binding al RP), credential management, U2F (registrazione,
autenticazione, check-only, interoperabilità con CTAP2) e due flussi WebAuthn completi con
`Fido2Client`/`Fido2Server` (incluso PRF). La CI li esegue a ogni push e compila l'app per
ESP32-S3 e ESP32-P4.

## Struttura del repository

```
Apps/Passkey/                app Tactility (manifest, CMake, sorgenti)
  main/Source/fido/          core FIDO portabile (CTAPHID, CTAP2, U2F, store, crypto)
  main/Source/*.c            integrazione Tactility: HAL, trasporto USB, UI LVGL, main
  main/sdk-overlay/          header usb_hid_device.h con l'API della patch
tactility-patch/             patch per il firmware Tactility + istruzioni
tests/host/                  build Linux del core (hal_host.c, main_host.c)
tests/python/                test con python-fido2
docs/RESEARCH.md             progetti esistenti e scelte progettuali
tt, tt.py                    strumento di build ufficiale di Tactility
```

## Note di sicurezza e limiti

- Senza **Secure Boot e flash encryption** chi ha accesso fisico al dispositivo può estrarre la
  chiave di dispositivo e quindi il segreto master; su ESP32-S3 abilitarli in Tactility rende il
  file di stato inutilizzabile fuori dal chip. Non c'è elemento sicuro: la protezione è software.
- Il contatore delle firme è globale (come nelle chiavi U2F semplici).
- Un solo trasporto (USB); niente NFC, BLE o `largeBlobs`, niente attestazione con certificato
  del produttore (self attestation, come Solo e simili).
- La richiesta di presenza utente è visibile solo quando la finestra dell'app è in primo piano.
- Su hardware è stata provata solo sul badge RomHack Camp 2026 con Chrome su macOS (vedi lo stato
  in cima).

## Licenza

Apache License 2.0 per il codice del progetto (vedi [LICENSE](LICENSE)); le librerie incluse
hanno le licenze indicate in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). La patch per
Tactility segue le licenze dei file che modifica.

---

**English summary**: a FIDO2/U2F USB security key app for the Tactility ESP32 OS, similar in
scope to pico-fido. It ships a portable C CTAP2.1/U2F core tested against python-fido2, a
Tactility app (LVGL UI for user presence, encrypted credential store) and a small patch for the
Tactility firmware that adds a FIDO HID mode to its USB HID device driver, which is required
because Tactility apps can only use the USB classes the kernel exports.
