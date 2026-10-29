//! Apple SoC topology, register geometry and initial image contracts.
//!
//! These data contracts carry no device execution, JIT, native mapping or
//! controller-effect permission. Device models and bundle preparation consume
//! the same validated descriptions.
#![cfg_attr(not(any(test, feature = "std")), no_std)]
extern crate alloc;

pub use stela_contracts::Refusal;

/// A description that is refused names the values that decided it.
pub type Result<T, E = Refusal> = core::result::Result<T, E>;

pub mod aes;
pub mod aic;
pub mod amcc;
pub mod ans;
pub mod core_counters;
pub mod cpm;
pub mod cpustart;
pub mod dart;
pub mod dpe;
pub mod gpio;
pub mod nor;
pub mod pmgr;
pub mod pmu;
pub mod power;
pub mod ptd;
pub mod spmi;

pub mod bridge;

pub mod sart;

pub mod smc;

pub mod sep;

pub mod dcp;

pub mod asc;

pub mod atc_phy;

pub mod coresight;

pub mod energy;

pub mod fuse;

pub mod i2c;

pub mod spi;

pub mod wake;

pub mod agx;
pub mod cluster;

pub mod board;

pub mod lockdown;
pub mod mcc;
pub mod perf;
