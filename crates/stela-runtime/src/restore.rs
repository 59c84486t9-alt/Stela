//! Request-driven restore host, independent of USB and guest execution.
//!
//! Wire evidence: pinned libimobiledevice property_list_service.c/restore.c
//! and idevicerestore restore.c/asr.c, revisions in
//! `docs/research/restore-transport.md`. No signing-service access exists here.
//! An adapter supplies mux streams; each call performs bounded work so the
//! caller can schedule control, ASR and independent DataPort jobs fairly.
pub mod answers;
pub mod asr;
pub mod plist;
pub mod proxy;
pub mod session;
pub mod store;
pub mod stream;
pub mod ticket;

use alloc::{boxed::Box, string::String};
use plist::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Limit(&'static str),
    Transport(String),
    Payload(String),
    /// Preserve the entire bounded message, including updater, arguments,
    /// DataPort and asynchronous context. Never a blank successful response.
    Refused {
        reason: String,
        request: Box<Value>,
    },
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
pub type Result<T> = core::result::Result<T, Error>;
pub fn refuse(reason: impl Into<String>, request: &Value) -> Error {
    Error::Refused {
        reason: reason.into(),
        request: Box::new(request.clone()),
    }
}
