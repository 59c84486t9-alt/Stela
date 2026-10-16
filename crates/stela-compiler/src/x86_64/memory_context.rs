//! Calls into the memory service for context-backed accesses.
mod callback;
pub(crate) use callback::{begin, branch_failed, call, fault, patch_branch, request};
pub(crate) mod address;
