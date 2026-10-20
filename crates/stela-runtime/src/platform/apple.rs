//! Register-level models of the Apple T8112 (M2) devices that an unchanged
//! XNU kernel programs before its first userspace process, backed by x86 PC
//! resources: a console sink, a host monotonic counter and the system engine's
//! interrupt wiring.
//!
//! Each model is placed at its DeviceTree `reg` address on a [`bus::Bus`] and
//! reports interrupt-wire changes through [`interrupt::InterruptSink`]. Every
//! register the model does not implement is an explicit [`bus::MmioError`];
//! nothing reads as a silent zero. Doc comments mark what the cited sources
//! document and what the model infers.
pub mod aes;
pub mod agx;
pub mod aic;
pub mod aic1;
pub mod amcc;
pub mod ans;
pub mod asc;
pub mod atc_phy;
pub mod bridge;
pub mod bus;
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
pub mod interrupt;
pub mod ipi;
pub mod lockdown;
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
pub mod timer;
pub mod typec;
pub mod uart;
pub mod wake;
pub mod wdt;
