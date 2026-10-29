//! Stateful Apple SoC models: register-level models of the Apple T8112 (M2)
//! devices that an unchanged XNU kernel programs before its first userspace
//! process, the native USB bus peers they serve, and their composition as the
//! engine's devices ([`machine`]).
//!
//! Each model is placed at its DeviceTree `reg` address on a [`bus::Bus`] and
//! reports interrupt-wire changes through
//! [`InterruptSink`](stela_contracts::interrupt::InterruptSink). Every
//! register the model does not implement is an explicit [`bus::MmioError`];
//! nothing reads as a silent zero. Doc comments mark what the cited sources
//! document and what the model infers.
#![cfg_attr(not(feature = "std"), no_std)]
#[macro_use]
extern crate alloc;

pub use stela_contracts::Refusal;
use stela_contracts::bus;
#[cfg(test)]
use stela_contracts::interrupt;

/// A refused request names the values that decided it.
pub type Result<T, E = Refusal> = core::result::Result<T, E>;

mod checksum;
pub mod machine;
#[cfg(test)]
mod research;
pub mod usb;

pub mod aes;
pub mod agx;
pub mod aic;
pub mod aic1;
pub mod amcc;
pub mod ans;
pub mod asc;
pub mod atc_phy;
pub mod bridge;
pub mod cluster;
pub mod core_counters;
pub mod coresight;
pub mod counter;
pub mod cpm;
pub mod cpustart;
pub mod dart;
pub mod dcp;
pub mod dcs;
pub mod display;
pub mod dpe;
pub mod dwc3;
pub mod energy;
pub mod fuse;
pub mod gpio;
pub mod hpm;
pub mod i2c;
pub mod ipi;
pub mod lockdown;
pub mod mcc;
pub mod nor;
pub mod perf;
pub mod pmgr;
pub mod pmp;
pub mod pmu;
pub mod power;
pub mod ptd;
pub mod regfile;
pub mod rtkit;
pub mod sart;
pub mod scanout;
pub mod sep;
pub mod smc;
pub mod spi;
pub mod spmi;
pub mod typec;
pub mod uart;
pub mod wake;
pub mod wdt;
