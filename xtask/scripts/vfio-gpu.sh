#!/bin/bash
# Lend a host's GPU to one `cargo xtask boot run --kvm --vfio-gpu` and take it
# back. Linux keeps no VFIO configuration between runs: the card is bound to
# vfio-pci for the command's life and returned to its driver afterwards.
#
#   vfio-gpu.sh status
#   sudo vfio-gpu.sh run [--stop-desktop] [--seconds N] -- COMMAND...
#
# COMMAND runs as the sudo caller, with memory locking unlimited so VFIO can
# pin guest RAM. --stop-desktop stops the display manager first and restarts
# it afterwards: a card that drives the only display cannot be unbound, and
# every graphical session on it ends. Start such a run detached so it survives
# them; it always gives the desktop back, within --seconds at the latest:
#
#   sudo systemd-run --unit=stela-vfio --collect xtask/scripts/vfio-gpu.sh \
#     run --stop-desktop --seconds 1800 -- COMMAND...
#
# STELA_VFIO_GPU names the card, by default the first NVIDIA display function.
set -euo pipefail

die() { echo "vfio-gpu: $*" >&2; exit 1; }
devices=/sys/bus/pci/devices

gpu() {
  if [[ -n ${STELA_VFIO_GPU:-} ]]; then
    echo "$STELA_VFIO_GPU"
    return
  fi
  local device
  for device in "$devices"/*; do
    [[ $(<"$device/vendor") == 0x10de && $(<"$device/class") == 0x03* ]] || continue
    basename "$device"
    return
  done
  die "no NVIDIA display function"
}

# The functions of the card's slot, which go to the guest together.
functions() {
  local device
  for device in "$devices/${1%.*}".*; do basename "$device"; done
}

driver() {
  local link="$devices/$1/driver"
  if [[ -e $link ]]; then basename "$(readlink -f "$link")"; else echo none; fi
}

status() {
  local card function device
  card=$(gpu)
  echo "card $card: $(lspci -s "$card" | cut -d' ' -f2-)"
  echo "boot VGA: $(<"$devices/$card/boot_vga")"
  for function in $(functions "$card"); do
    echo "$function: driver $(driver "$function"), IOMMU group $(basename "$(readlink "$devices/$function/iommu_group")")"
  done
  for device in "$devices/$card/iommu_group/devices"/*; do
    [[ $(basename "$device") == "${card%.*}".* ]] && continue
    echo "WARNING: $(basename "$device") shares the card's IOMMU group"
  done
  local displays=()
  for device in "$devices"/*; do
    [[ $(<"$device/class") == 0x03* && $(basename "$device") != "${card%.*}".* ]] || continue
    displays+=("$(basename "$device")")
  done
  if ((${#displays[@]})); then
    echo "other display functions: ${displays[*]}: this desktop can stay up"
  else
    echo "no other display function: a run needs --stop-desktop and ends this desktop"
  fi
}

bind() {
  local function=$1
  local current
  current=$(driver "$function")
  if [[ $current != none ]]; then
    echo "$function" >"$devices/$function/driver/unbind"
  fi
  echo vfio-pci >"$devices/$function/driver_override"
  echo "$function" >/sys/bus/pci/drivers_probe
  [[ $(driver "$function") == vfio-pci ]] || die "$function did not bind to vfio-pci"
  # An FLR of a card whose GSP has served work never completes and takes the
  # link with it. Without it QEMU resets the slot, which does bring it back.
  if [[ -e $devices/$function/reset_method ]]; then
    echo >"$devices/$function/reset_method"
  fi
}

release() {
  local function=$1
  if [[ $(driver "$function") == vfio-pci ]]; then
    echo "$function" >"$devices/$function/driver/unbind"
  fi
  echo >"$devices/$function/driver_override"
}

# Stop what holds an NVIDIA card: its services, consoles and modules.
unload_nvidia() {
  local console
  systemctl stop nvidia-persistenced.service 2>/dev/null || true
  for console in /sys/class/vtconsole/vtcon*; do
    if grep -q 'frame buffer' "$console/name"; then
      echo 0 >"$console/bind"
    fi
  done
  local module
  for module in nvidia_uvm nvidia_drm nvidia_modeset nvidia; do
    if [[ -d /sys/module/$module ]]; then
      modprobe -r "$module" || die "cannot unload $module: something still holds the card"
    fi
  done
}

restore() {
  local function console
  set +e
  for function in "${members[@]}"; do release "$function"; done
  [[ -e /dev/vfio/$group ]] && chown root:root "/dev/vfio/$group"
  if ((nvidia)); then
    modprobe nvidia_drm
    modprobe nvidia_uvm
    systemctl start nvidia-persistenced.service 2>/dev/null
  fi
  for function in "${members[@]}"; do
    echo "$function" >/sys/bus/pci/drivers_probe
  done
  for console in /sys/class/vtconsole/vtcon*; do
    echo 1 >"$console/bind" 2>/dev/null
  done
  ((stopped)) && systemctl start display-manager.service
  set -e
}

run() {
  local stop_desktop=0 seconds=3600
  while (($#)); do
    case $1 in
      --stop-desktop) stop_desktop=1 ;;
      --seconds) seconds=$2; shift ;;
      --) shift; break ;;
      *) die "unknown option $1" ;;
    esac
    shift
  done
  (($#)) || die "no command"
  ((EUID == 0)) || die "run needs root"
  local owner=${SUDO_USER:-${STELA_VFIO_USER:-}}
  [[ -n $owner && $owner != root ]] || die "set STELA_VFIO_USER to the user who runs the command"

  local card
  card=$(gpu)
  mapfile -t members < <(functions "$card")
  group=$(basename "$(readlink "$devices/$card/iommu_group")")
  stopped=0
  nvidia=0
  trap restore EXIT
  modprobe vfio-pci
  if ((stop_desktop)); then
    systemctl stop display-manager.service
    stopped=1
    sleep 3
  fi
  if [[ $(driver "$card") == nvidia ]]; then
    nvidia=1
    unload_nvidia
  fi
  local function
  for function in "${members[@]}"; do bind "$function"; done
  chown "$owner" "/dev/vfio/$group"
  ulimit -l unlimited
  local code=0
  # Stopping the service ends the command too: first let the card write no
  # more to memory QEMU is about to unmap.
  trap 'for function in "${members[@]}"; do setpci -s "$function" COMMAND=0:4; done; kill "$child" 2>/dev/null' TERM
  timeout --kill-after=30 "$seconds" runuser -u "$owner" -- "$@" &
  child=$!
  wait "$child" || code=$?
  wait "$child" 2>/dev/null || true
  return "$code"
}

case ${1:-} in
  status) status ;;
  run) shift; run "$@" ;;
  *) die "usage: vfio-gpu.sh status | run [--stop-desktop] [--seconds N] -- COMMAND..." ;;
esac
