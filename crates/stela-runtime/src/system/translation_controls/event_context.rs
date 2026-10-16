//! Event inputs (SCTLR, identification, debug) for WFx and SEV.
use super::{ControlError, TranslationControls, fields::sctlr};
use crate::system::{
    access::{Profile, SecurityState},
    debug::DebugControls,
    events::{Context, ContextError},
    identification::Register,
    identification_snapshot::{Snapshot, Unsupported},
    state::SystemState,
};

const WFXT_FIELD_MASK: u64 = 0xf;
const WFXT_ABSENT: u64 = 0;
const WFXT_REGISTER_SYNDROME: u64 = 2;

#[derive(Debug)]
pub(crate) enum EventContextError {
    Controls(ControlError),
    Identification(Unsupported),
    ReservedWfxt(u64),
    Context(ContextError),
}

impl core::fmt::Display for EventContextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Controls(error) => write!(f, "translation controls: {error:?}"),
            Self::Identification(error) => write!(f, "identification snapshot: {error:?}"),
            Self::ReservedWfxt(value) => {
                write!(f, "reserved ID_AA64ISAR2_EL1.WFxT value {value:#x}")
            }
            Self::Context(error) => write!(f, "architectural wait context: {error:?}"),
        }
    }
}

impl TranslationControls {
    /// The fixed profile keeps the PE's identification snapshot and debug
    /// owner, and entry and re-check validate them. This adds no feature flag
    /// or control bank; TranslationControls already admits only the NonSecure
    /// EL0/EL1 regime without EL2 or EL3.
    pub(crate) fn event_context(
        &self,
        identification: &Snapshot,
        system: &SystemState,
        debug: &DebugControls,
    ) -> Result<Context, EventContextError> {
        let wfxt = match identification
            .read(Register::IdAa64Isar2El1)
            .map_err(EventContextError::Identification)?
            & WFXT_FIELD_MASK
        {
            WFXT_ABSENT => false,
            WFXT_REGISTER_SYNDROME => true,
            reserved => return Err(EventContextError::ReservedWfxt(reserved)),
        };
        // Read SCTLR now: an earlier copy would not survive a wake re-check,
        // and feature-dependent RES0 bits must not become effects.
        let snapshot = self.snapshot().map_err(EventContextError::Controls)?;
        let effective = snapshot.consumer_inputs().sctlr_el1;
        Context::new(
            Profile {
                current_el: system.current_el(),
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            wfxt,
            effective & sctlr::TWED_EN != 0,
            debug.halted,
            effective & sctlr::NTWE != 0,
            effective & sctlr::NTWI != 0,
        )
        .map_err(EventContextError::Context)
    }
}
