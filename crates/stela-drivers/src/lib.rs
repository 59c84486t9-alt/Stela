//! Stela's native PC drivers, organized by device class. The UEFI mount runs
//! them after ExitBootServices, when firmware drivers no longer own the devices.
//!
//! Native backends supply physical operations for Apple-compatible guest
//! devices and the mount's own clients. macOS keeps its guest drivers. Backend
//! attachment, guest integration and physical validation are separate facts.
//! Native C/C++ ports use explicit ABI wrappers and the driver requirements
//! determine their allocation, DMA, interrupt and lifecycle services.
//!
//! This crate holds the USB, Bluetooth and input stacks and [`probe`], and
//! re-exports the driver crates it builds on: the foundation
//! ([`bus`], [`block`], [`platform`], [`Clock`], [`Handoff`]) and the
//! [`net`], [`storage`], [`audio`] and [`gpu`] device classes.
//!
//! The mount passes PCI windows, mappings, firmware, clocks and owned native
//! services through [`Handoff`] and [`probe::NativeServices`]. [`probe::probe`]
//! records devices, refusals and kept owners. [`firmware`] supplies its
//! device image catalog.
//!
//! The generated [hardware route table](https://github.com/tylertms/Stela/blob/main/docs/design/hardware.md)
//! is the shared inventory of attached, check-only and planned routes. It is
//! derived from probe admission and dispatch, with per-route limits;
//! an ID match or library implementation grants no operational support claim.
#![no_std]
#[macro_use]
extern crate alloc;

pub use stela_driver_audio as audio;
pub use stela_driver_base::{
    Clock, ClockError, Deadline, Handoff, block, bus, entropy, on_wait, on_work, platform,
};
pub use stela_driver_core::firmware;
pub use stela_driver_gpu as gpu;
pub use stela_driver_net as net;
pub use stela_driver_storage as storage;

pub mod bluetooth;
pub mod input;
pub mod probe;
pub mod usb;

#[cfg(test)]
mod model_test_process;
#[cfg(test)]
use stela_driver_base::test_clock;
use stela_driver_base::{registers, waiting, working};
use stela_driver_core::bytes;

/// The UEFI variables `stela.efi` reads for the drivers before it leaves
/// boot services; copies only, no firmware service or heap borrow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlatformCaptures {
    /// Intel Bluetooth's DSBR board variable, with its diagnostics.
    pub bluetooth: usb::bluetooth::intel::DsbrCapture,
    /// Intel Wi-Fi's variables' status; their bytes belong to the firmware
    /// catalog.
    pub wifi: net::wifi::intel::platform::Observations,
}
