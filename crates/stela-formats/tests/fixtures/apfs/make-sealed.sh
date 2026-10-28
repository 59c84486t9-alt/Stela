#!/bin/sh
# Make sealed.img.gz: a raw APFS container whose one volume is sealed by
# Apple's own sealer (apfs_prepare_cryptex), and sealed.root_hash, the
# 208-byte metadata-hash record the sealer wrote for it. Synthetic files
# only. Needs macOS (hdiutil, diskutil); no root.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
sealer=/System/Library/Filesystems/apfs.fs/Contents/Resources/apfs_prepare_cryptex
work="$(mktemp -d)"
disk=""
trap '[ -n "$disk" ] && hdiutil detach "$disk" >/dev/null 2>&1; rm -rf "$work"' EXIT
hdiutil create -size 8m -fs APFS -volname Sealed -layout NONE -type UDIF "$work/sealed.dmg" >/dev/null
attached="$(hdiutil attach -nomount -noverify "$work/sealed.dmg")"
disk="$(echo "$attached" | awk 'NR==1 {print $1}')"
volume="$(echo "$attached" | awk '$2 ~ /^41504653/ {print $1; exit}')"
mkdir "$work/mount"
diskutil mount -mountPoint "$work/mount" "$volume" >/dev/null
mkdir -p "$work/mount/System/Library/CoreServices"
printf 'sealed by apfs_prepare_cryptex\n' > "$work/mount/System/Library/CoreServices/stela.txt"
sync
diskutil unmount "$volume" >/dev/null
"$sealer" -M "$here/sealed.root_hash" "$volume" >/dev/null
hdiutil detach "$disk" >/dev/null
disk=""
gzip -9 -n -c "$work/sealed.dmg" > "$here/sealed.img.gz"
