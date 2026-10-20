//! System-mode execution: one ARM PE with EL0, EL1 and EL2 running native
//! blocks from the shared compiler, with the MMU, exceptions, generic timers
//! and System registers implemented here and the x86 mechanisms supplied by a
//! [`Host`].
//! The design is in `docs/design/system.md#system-mode-execution`.
pub mod adt;
pub mod amu;
pub mod amx;
pub mod apple;
pub mod caches;
pub mod chip;
pub mod cpu;
pub mod ctrr;
pub mod debug;
pub mod engine;
pub mod exception;
pub mod hacr;
pub mod identification;
pub mod impdef;
pub mod mmu;
pub mod pmu;
pub mod registers;
pub mod soc;
pub mod streaming;
pub mod system;
pub mod tags;
pub mod timer;
pub mod vgic;

pub use chip::Chip;
#[cfg(test)]
pub(crate) use chip::test_chip;
pub use cpu::{Cpu, Exception};
pub use engine::{
    DeviceError, Devices, Event, FaultCause, Host, InstallError, Machine, NativeCode, NativeExit,
    NativeFault, NoDevices, Offer, PeerState, Regime, Requirement, RequirementKind, Reset,
    StaleCode, Statistics, Stop, Transition, Translations, compile_input,
};
pub use registers::{CpuProfile, Identity, Lines};
