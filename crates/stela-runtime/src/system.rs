//! Shared A64 system decisions, authoritative state and checked effect dispatch.

pub mod access;
pub mod debug;
pub mod events;
pub mod exception;
pub mod execution;
pub mod fixed_controls;
pub mod fixed_execution;
pub mod identification;
pub mod identification_snapshot;
pub mod interrupt;
pub mod process_memory;
pub mod profile;
pub mod pstate;
pub mod scalable_controls;
pub mod state;
pub mod timer;
pub mod translation;
