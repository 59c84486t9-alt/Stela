//! Common context memory emission. The callback body has exactly one owner.
//!
//! Parent registration is brokered separately. Scalable callers reexport this
//! module as `scalable::memory`; ordinary callers use this canonical name.
#[path = "scalable/memory.rs"]
mod callback;
pub(crate) use callback::{begin, branch_failed, call, fault, patch_branch, request};
#[path = "memory_context/address.rs"]
pub(crate) mod address;
