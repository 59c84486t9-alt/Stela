//! Common context memory emission. The callback body has exactly one owner.
//!
//! Parent registration is brokered separately. Scalable callers reexport this
//! module as `scalable::memory`; ordinary callers use this canonical name.
mod callback;
pub(crate) use callback::{begin, branch_failed, call, fault, patch_branch, request};
pub(crate) mod address;
