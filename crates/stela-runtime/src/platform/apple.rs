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
pub mod bus;
pub mod counter;
pub mod interrupt;
