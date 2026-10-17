//! System-mode execution: one ARM PE with EL0, EL1 and EL2 running native
//! blocks from the shared compiler, with the MMU, exceptions, generic timers
//! and System registers implemented here and the x86 mechanisms supplied by a
//! [`Host`].
//! The design is in `docs/design/system.md#system-mode-execution`.
pub mod amx;
pub mod apple;
pub mod cpu;
pub mod engine;
pub mod exception;
pub mod identification;
pub mod impdef;
pub mod mmu;
pub mod registers;
pub mod system;
pub mod timer;

pub use cpu::{Cpu, Exception};
pub use engine::{
    DeviceError, Devices, Event, FaultCause, Host, InstallError, Machine, NativeCode, NativeExit,
    NativeFault, NoDevices, Regime, Requirement, RequirementKind, Statistics, Stop,
};
pub use registers::{CpuProfile, Lines};
