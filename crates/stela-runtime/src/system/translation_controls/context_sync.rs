//! Control generation for exception context synchronization.
use super::{
    ContextSynchronizationCause, ContextSynchronizationRequest, ControlError, FetchedInstruction,
    PreparedPublication, TranslationControls, TranslationServices, check_execution_state,
};
use crate::system::state::SystemState;

impl TranslationControls {
    /// The post-native consumer holds the state, source, outer object and PE.
    /// This only reserves the context synchronization; the exception plan
    /// validates and commits the CPU state.
    pub(crate) fn prepare_exception_context<'a, S: TranslationServices>(
        &'a mut self,
        fetched: &FetchedInstruction,
        state: &SystemState,
        cause: ContextSynchronizationCause,
        services: &'a mut S,
    ) -> Result<PreparedContextSynchronization<'a, S::Prepared<'a>>, ControlError> {
        check_execution_state(state)?;
        self.check_services(services)?;
        self.check_site(fetched)?;
        if !cause.matches_source(fetched.word()) {
            // An authenticated return or failure needs the PAuth service before
            // it can be a synchronization cause.
            return Err(ControlError::Unavailable(
                "exception source needs another actual context service",
            ));
        }
        services
            .validate_source(&self.current_snapshot(), fetched.source, state)
            .map_err(ControlError::Unavailable)?;
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(ControlError::GenerationExhausted)?;
        let before = self.current_snapshot();
        let mut after = before.clone();
        after.generation = next_generation;
        let prepared = services
            .prepare_context_synchronization(ContextSynchronizationRequest {
                before,
                after,
                source: fetched.source,
                cpu: self.profile.cpu,
                state,
                cause,
            })
            .map_err(ControlError::Unavailable)?;
        Ok(PreparedContextSynchronization {
            owner: self,
            prepared,
            next_generation,
        })
    }
}

/// The controls and the prepared source and publication gates; no PC, return
/// target or copied system state.
pub(crate) struct PreparedContextSynchronization<'a, P: PreparedPublication> {
    owner: &'a mut TranslationControls,
    prepared: P,
    next_generation: u64,
}
impl<'a, P: PreparedPublication> PreparedContextSynchronization<'a, P> {
    /// Return the controls after the publication attempt. A failed bank stays
    /// failed.
    #[must_use = "recover the original controls and inspect exact publication outcome"]
    pub(crate) fn commit(self) -> (&'a mut TranslationControls, Result<(), ControlError>) {
        let Self {
            owner,
            prepared,
            next_generation,
        } = self;
        if let Err(error) = prepared.commit() {
            owner.poisoned = true;
            return (
                owner,
                Err(ControlError::Publication {
                    register_committed: false,
                    progress: error.progress,
                    reason: error.reason,
                }),
            );
        }
        owner.generation = next_generation;
        (owner, Ok(()))
    }
}
