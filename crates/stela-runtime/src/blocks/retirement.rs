//! Checked block execution: running native blocks and retiring their effects.
use super::ThreadState;
use crate::system::{
    execution::{
        authority::PeExecutionAuthority,
        owner::{OwnerKey, SystemExecutionLoan},
    },
    state::SystemState,
};
/// Only this module constructs the consumer key.
pub(crate) struct ConsumerKey(());

/// Resources lent to the consumer. Only this module may take their fields.
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
#[cfg(feature = "std")]
mod process;
#[cfg(feature = "std")]
pub(crate) use process::run_protected_services;
