//! Apple SoC topology, register geometry and initial image contracts.
//!
//! These data contracts carry no device execution, JIT, native mapping or
//! controller-effect authority. Device models and bundle preparation consume
//! the same validated descriptions.
#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

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
