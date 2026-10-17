#!/usr/bin/env bash
#
# Builds the Passkey app for the RomHack Camp 2026 badge firmware.
#
# The badge ships its own Tactility copy, older than the SDK that ./tt targets: apps are packaged
# with a format 0.2 manifest and the binary at elf/<platform>.elf, and are built against the
# TactilitySDK made from that firmware (ESP-IDF 5.5). This script does what the badge's own
# tactility.py does for one platform.
#
# Usage: Scripts/build-rhc2026-badge-app.sh <TactilitySDK folder built from the badge firmware>
# Needs an activated ESP-IDF 5.5 environment. Output: build/rhc2026-badge/robertod.passkey.app

set -euo pipefail

if [ $# -ne 1 ] || [ ! -f "$1/TactilitySDK.cmake" ]; then
    echo "Usage: $0 <path to TactilitySDK>" >&2
    exit 1
fi
if ! command -v idf.py >/dev/null 2>&1; then
    echo "ERROR: idf.py not found: activate ESP-IDF 5.5 first (. \$IDF_PATH/export.sh)" >&2
    exit 1
fi

SDK="$(cd "$1" && pwd)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/Apps/Passkey"
TARGET="$APP/targets/rhc2026-badge"
WORK="$ROOT/build/rhc2026-badge"
PLATFORM=esp32s3

rm -rf "$WORK"
mkdir -p "$WORK/app" "$WORK/package/elf"
cp -r "$APP/CMakeLists.txt" "$APP/main" "$WORK/app/"
cp "$TARGET/manifest.properties" "$WORK/app/manifest.properties"
cp "$TARGET/sdkconfig.app.$PLATFORM" "$WORK/app/sdkconfig"

cd "$WORK/app"
export TACTILITY_SDK_PATH="$SDK"
ELF="build/cmake-build-$PLATFORM/passkey.app.elf"
# elf_loader's CMake script can make idf.py report a failure after the ELF was written, so success
# is judged by the ELF, as tactility.py does. The log is kept for when it really failed.
if ! idf.py -B "build/cmake-build-$PLATFORM" build > "$WORK/idf-build.log" 2>&1; then
    if [ ! -f "$ELF" ]; then
        tail -n 60 "$WORK/idf-build.log" >&2
        echo "ERROR: the build failed, see $WORK/idf-build.log" >&2
        exit 1
    fi
fi

cp manifest.properties "$WORK/package/manifest.properties"
cp "$ELF" "$WORK/package/elf/$PLATFORM.elf"

python3 - "$WORK/package" "$WORK/robertod.passkey.app" <<'PY'
import sys
import tarfile

source, target = sys.argv[1], sys.argv[2]
with tarfile.open(target, mode="w", format=tarfile.USTAR_FORMAT) as tar:
    tar.add(source, arcname="")
PY

echo "Package: $WORK/robertod.passkey.app"
