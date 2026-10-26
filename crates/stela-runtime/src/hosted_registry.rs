//! Platform-independent metadata shared with the Darwin hosted dispatchers.
//!
//! The live selectors below are also the requirement matrix's source of truth;
//! they do not execute host services or imply hosted execution on this platform.
pub(crate) mod bsd;
pub(crate) mod mach;
#[path = "hosted/requirements.rs"]
pub mod requirements;
#[path = "hosted/kernel/services.rs"]
pub mod services;
