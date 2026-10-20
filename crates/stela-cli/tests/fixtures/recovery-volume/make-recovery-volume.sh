#!/bin/sh
# Make recovery-volume.img.gz: the recoveryOS volume `stela boot prepare
# --recovery` builds (boot/recovery_volume.rs, the same hdiutil arguments),
# holding a 4096-byte synthetic file in place of the BaseSystem image.
# Needs macOS (hdiutil); no root.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/stage/usr/standalone/firmware"
head -c 4096 /dev/zero | tr '\0' 'S' > "$work/stage/usr/standalone/firmware/arm64eBaseSystem.dmg"
hdiutil create -quiet -fs APFS -layout NONE -format UDRW -volname "Stela recoveryOS" \
    -srcfolder "$work/stage" "$work/volume.dmg"
gzip -9 -n -c "$work/volume.dmg" > "$here/recovery-volume.img.gz"
