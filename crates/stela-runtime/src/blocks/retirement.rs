//! The canonical checked process consumer and its retained actual owners.
use super::ThreadState;
use crate::system::{
    execution::{
        authority::PeExecutionAuthority,
        owner::{OwnerKey, SystemExecutionLoan},
    },
    state::SystemState,
};
/// Only this canonical module constructs the consumer key.
pub(crate) struct ConsumerKey(());

/// Opaque producer loan. This type/its constructor must be private to the
/// retained owner; only this canonical blocks consumer may extract its fields.
/// A production join uses the reviewed SystemExecutionOwner constructor rather
/// than adding a second actual-PE allocator in this module.
pub(crate) struct RetainedResources<'pe, B> {
    authority: &'pe mut PeExecutionAuthority,
    thread: &'pe mut ThreadState,
    system: &'pe mut SystemState,
    backend: &'pe mut B,
}

impl<'pe, B> RetainedResources<'pe, B> {
    pub(crate) fn from_owner(
        _key: OwnerKey,
        authority: &'pe mut PeExecutionAuthority,
        thread: &'pe mut ThreadState,
        system: &'pe mut SystemState,
        backend: &'pe mut B,
    ) -> Self {
        Self {
            authority,
            thread,
            system,
            backend,
        }
    }
}

fn accept_retained_loan<B>(loan: SystemExecutionLoan<'_, B>) -> RetainedResources<'_, B> {
    loan.into_retirement(ConsumerKey(()))
}

pub(crate) mod checked;
mod process;
mod software_async;
pub(crate) use process::run_protected_services;
