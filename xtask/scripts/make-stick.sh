#!/bin/zsh
# Build Stela's standalone host-check boot stick: GPT, the 200 MB EFI system
# partition diskutil creates (s1, FAT32) holding \EFI\BOOT\BOOTX64.EFI =
# stela.efi and \EFI\stela\stela.cfg, and one FAT32 data partition STELA (s2,
# the rest of the disk) holding \EFI\stela\STELALOG.BIN, the preallocated
# --nor-file log, and room for later bundles and the macOS install medium.
#
#   make-stick.sh --image FILE [CFG-OPTIONS]   a 4 GiB raw image, for QEMU
#   make-stick.sh --disk DISK [CFG-OPTIONS]    an external USB disk; WIPES IT
#
# CFG-OPTIONS go after `--host-check --nor-file GUID:/EFI/stela/STELALOG.BIN`
# in stela.cfg (default: --key-seconds 120 --deadline 1800). STELA_EFI names
# the stela.efi to install; the default is `cargo xtask boot build --release`'s.
set -euo pipefail

EFI=${STELA_EFI:-${0:A:h:h:h}/target/boot/x86_64-unknown-uefi/release/stela.efi}
IMAGE_BYTES=$((4 * 1024 * 1024 * 1024))
LOG_MIB=6   # >= boot_log::PARTITION_BYTES (0x510000)

die() { print -u2 "make-stick: $*"; exit 1; }
field() { # field PLIST KEY: one value of `diskutil info -plist`
  plutil -extract "$2" raw -o - "$1" 2>/dev/null || print -n "?"
}

(( $# >= 2 )) || die "usage: make-stick.sh --image FILE | --disk DISK [CFG-OPTIONS]"
mode=$1 target=$2
shift 2
extra=${*:---key-seconds 120 --deadline 1800}
[[ -f $EFI ]] || die "no stela.efi at $EFI"
# macOS mounts a physical disk's EFI system partition only for root.
esp_root=()
info=$(mktemp -t make-stick)
trap 'rm -f $info' EXIT

case $mode in
  --image)
    [[ -e $target ]] && die "$target exists"
    python3 -I -c "open('$target','wb').truncate($IMAGE_BYTES)"
    dev=$(hdiutil attach -nomount -imagekey diskimage-class=CRawDiskImage "$target" | awk 'NR==1 {print $1}')
    dev=${dev#/dev/}
    [[ $dev =~ '^disk[0-9]+$' ]] || die "hdiutil gave no device for $target"
    trap 'rm -f $info; hdiutil detach $dev > /dev/null 2>&1 || true' EXIT
    diskutil info -plist $dev > $info
    [[ $(field $info VirtualOrPhysical) == Virtual && $(field $info BusProtocol) == "Disk Image" \
       && $(field $info TotalSize) == $IMAGE_BYTES ]] || die "$dev is not $target"
    ;;
  --disk)
    [[ $target =~ '^disk[0-9]+$' ]] || die "$target is not a whole-disk identifier such as disk5"
    dev=$target
    expect() { [[ $(field $info $1) == "$2" ]] || die "$dev: $1 is '$(field $info $1)', expected '$2'"; }
    diskutil info -plist $dev > $info
    expect DeviceIdentifier $dev
    expect WholeDisk true
    expect Internal false
    expect VirtualOrPhysical Physical
    expect BusProtocol USB
    media=$(field $info MediaName) bytes=$(field $info TotalSize)
    diskutil info -plist / > $info
    [[ $(field $info ParentWholeDisk) != $dev ]] || die "$dev holds the running system"
    diskutil list $dev
    print "$dev: \"$media\", $bytes bytes, external USB."
    print -n "This erases every byte of $dev. Type $dev to continue: "
    read -r answer
    [[ $answer == $dev ]] || die "not confirmed"
    esp_root=(sudo)
    ;;
  *) die "unknown mode $mode" ;;
esac

diskutil partitionDisk $dev GPT "MS-DOS FAT32" STELA R
mount_point() { diskutil info -plist $1 > $info; field $info MountPoint; }
diskutil info -plist ${dev}s1 > $info
[[ $(field $info Content) == EFI ]] || die "${dev}s1 is not an EFI system partition"
$esp_root diskutil mount ${dev}s1
esp=$(mount_point ${dev}s1)
data=$(mount_point ${dev}s2)
[[ -d $esp && -d $data ]] || die "partitions not mounted (esp=$esp data=$data)"
diskutil info -plist ${dev}s2 > $info
guid=$(field $info DiskUUID)
[[ $guid == ????????-????-????-????-???????????? ]] || die "no partition GUID for ${dev}s2"

$esp_root mkdir -p "$esp/EFI/BOOT" "$esp/EFI/stela"
mkdir -p "$data/EFI/stela"
$esp_root cp "$EFI" "$esp/EFI/BOOT/BOOTX64.EFI"
print -n -- "--host-check --nor-file $guid:/EFI/stela/STELALOG.BIN $extra" | $esp_root tee "$esp/EFI/stela/stela.cfg" > /dev/null
# dd, not mkfile -n: every cluster is allocated, contiguous on a fresh volume.
dd if=/dev/zero of="$data/EFI/stela/STELALOG.BIN" bs=1m count=$LOG_MIB
sync
print "stela.cfg: $(cat "$esp/EFI/stela/stela.cfg")"
print "BOOTX64.EFI sha256: $(shasum -a 256 "$EFI" | cut -d' ' -f1)"
$esp_root diskutil unmountDisk $dev
print "make-stick: done"
