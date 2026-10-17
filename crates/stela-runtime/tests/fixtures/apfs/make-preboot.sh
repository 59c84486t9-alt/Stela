#!/bin/sh
# Make preboot.img.gz: an 8 MiB raw APFS container with one Preboot-role
# volume "Stela" laid out like an Apple-silicon Preboot volume. Synthetic
# content only. Needs macOS (hdiutil, diskutil, xattr) and Python 3.
set -eu
out="$(cd "$(dirname "$0")" && pwd)/preboot.img.gz"
work="$(mktemp -d)"
trap 'hdiutil detach "$disk" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
hdiutil create -size 8m -fs APFS -volname Stela -layout NONE -type UDIF "$work/preboot.dmg" >/dev/null
attached="$(hdiutil attach -nomount -noverify "$work/preboot.dmg")"
disk="$(echo "$attached" | awk 'NR==1 {print $1}')"
# The volume's partition type is the 'APFS' volume GUID 41504653-...
volume="$(echo "$attached" | awk '$2 ~ /^41504653/ {print $1; exit}')"
diskutil apfs changeVolumeRole "$volume" B >/dev/null
mkdir "$work/mount"
diskutil mount -mountPoint "$work/mount" "$volume" >/dev/null
m="$work/mount"
mkdir -p "$m/AAAA-UUID/boot/HASH01/System/Library/Caches/com.apple.kernelcaches" \
    "$m/AAAA-UUID/boot/HASH01/usr/standalone/firmware"
echo HASH01 > "$m/AAAA-UUID/boot/active"
python3 -I -c 'import sys; open(sys.argv[1], "wb").write(bytes((i * 7 + i // 251) & 0xff for i in range(300000)))' \
    "$m/AAAA-UUID/boot/HASH01/System/Library/Caches/com.apple.kernelcaches/kernelcache"
printf 'device tree bytes' > "$m/AAAA-UUID/boot/HASH01/usr/standalone/firmware/devicetree.img4"
ln -s boot/HASH01 "$m/AAAA-UUID/current"
: > "$m/empty"
xattr -w com.stela.test hello "$m/empty"
dd if=/dev/zero of="$m/sparse" bs=1 count=0 seek=200000 2>/dev/null
printf tail >> "$m/sparse"
sync
hdiutil detach "$disk" >/dev/null
gzip -9 -n -c "$work/preboot.dmg" > "$out"
