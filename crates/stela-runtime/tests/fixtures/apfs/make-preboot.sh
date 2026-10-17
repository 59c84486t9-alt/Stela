#!/bin/sh
# Make preboot.img.gz: an 8 MiB raw APFS container with one Preboot-role
# volume "Stela" laid out like an Apple-silicon Preboot volume, holding
# synthetic Image4 objects only. Needs macOS (hdiutil, diskutil, xattr) and
# Python 3.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/preboot.img.gz"
work="$(mktemp -d)"
disk=""
trap '[ -n "$disk" ] && hdiutil detach "$disk" >/dev/null 2>&1; rm -rf "$work"' EXIT
hdiutil create -size 8m -fs APFS -volname Stela -layout NONE -type UDIF "$work/preboot.dmg" >/dev/null
attached="$(hdiutil attach -nomount -noverify "$work/preboot.dmg")"
disk="$(echo "$attached" | awk 'NR==1 {print $1}')"
# The volume's partition type is the 'APFS' volume GUID 41504653-...
volume="$(echo "$attached" | awk '$2 ~ /^41504653/ {print $1; exit}')"
diskutil apfs changeVolumeRole "$volume" B >/dev/null
mkdir "$work/mount"
diskutil mount -mountPoint "$work/mount" "$volume" >/dev/null
python3 -I "$here/make-preboot-tree.py" "$work/mount"
xattr -w com.stela.test hello "$work/mount/empty"
dd if=/dev/zero of="$work/mount/sparse" bs=1 count=0 seek=200000 2>/dev/null
printf tail >> "$work/mount/sparse"
sync
hdiutil detach "$disk" >/dev/null
disk=""
gzip -9 -n -c "$work/preboot.dmg" > "$out"
