//! Test backend for event delivery.
use crate::memory::{domain::MemoryThread, policy::MemoryControls};
use crate::system::{
    access::{ExceptionLevel, Profile, SecurityState},
    events::{EventDomain, EventEndpoint, SendAttachment},
    exception::{Completion, EffectFailure, ExceptionServices, ServiceRequest},
    execution::{Backend, Boundary, EntryBoundary, EntrySnapshot, SendEventServices, TagSnapshot},
    state::{PSTATE_SS_MASK, SystemState},
};
use std::sync::Arc;
use stela_compiler::{
    GuestAddress, GuestState,
    block::{BlockProfile, analyze_with_profile},
};

const INSTRUCTION_BYTES: usize = size_of::<u32>();

pub(super) const NOP: u32 = 0xd503_201f;
pub(super) const SEV: u32 = 0xd503_209f;
pub(super) const SEVL: u32 = 0xd503_20bf;
pub(super) const ADD_X0: u32 = 0x9100_0400;

pub(super) struct EventBackend {
    pub domain: Arc<EventDomain>,
    pub endpoint: EventEndpoint,
    pub service_available: bool,
    expected_pc: GuestAddress,
    expected_word: u32,
    admitted_source: Option<(u64, u64, GuestAddress, GuestAddress, usize)>,
}

impl EventBackend {
    pub fn new(domain: Arc<EventDomain>, endpoint: EventEndpoint) -> Self {
        Self {
            domain,
            endpoint,
            service_available: true,
            expected_pc: GuestAddress(0),
            expected_word: 0,
            admitted_source: None,
        }
    }
    pub fn expect(&mut self, pc: GuestAddress, word: u32) {
        self.expected_pc = pc;
        self.expected_word = word;
    }
}

fn unavailable() -> EffectFailure<String> {
    EffectFailure {
        error: "event corpus has no exception service".into(),
        completion: Completion::None,
    }
}

impl ExceptionServices for EventBackend {
    type Permit = ();
    type Error = String;
    fn preflight(&mut self, _: ServiceRequest) -> Result<(), String> {
        Err("event corpus has no exception service".into())
    }
    fn synchronize_context(
        &mut self,
        _: &mut (),
        _: ExceptionLevel,
    ) -> Result<(), EffectFailure<String>> {
        Err(unavailable())
    }
    fn clear_exclusive_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
        Err(unavailable())
    }
    fn send_event_local(&mut self, _: &mut ()) -> Result<(), EffectFailure<String>> {
        Err(unavailable())
    }
    fn branch_address(
        &mut self,
        _: &mut (),
        _: u64,
        _: ExceptionLevel,
    ) -> Result<u64, EffectFailure<String>> {
        Err(unavailable())
    }
}

impl Backend for EventBackend {
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        system: &SystemState,
        registers: &GuestState,
    ) -> Result<(), String> {
        if system.current_el() != ExceptionLevel::El0 {
            return Err("event corpus source profile requires own EL0".into());
        }
        if system.pstate(registers) & PSTATE_SS_MASK != 0 {
            return Err("event corpus fixture does not support PSTATE.SS=1".into());
        }
        if source
            .first_chunk::<INSTRUCTION_BYTES>()
            .map(|x| u32::from_le_bytes(*x))
            != Some(boundary.word())
        {
            return Err("entry source word mismatch".into());
        }
        let analysis = analyze_with_profile(source, boundary.entry(), BlockProfile::SystemV1)
            .map_err(|error| error.to_string())?;
        let consumed = source
            .get(..analysis.source_bytes)
            .ok_or("invalid consumed extent")?;
        for (index, bytes) in consumed
            .as_chunks::<INSTRUCTION_BYTES>()
            .0
            .iter()
            .enumerate()
        {
            let word = u32::from_le_bytes(*bytes);
            if !matches!(word, NOP | ADD_X0 | SEV | SEVL) {
                return Err("outside event corpus register/send source profile".into());
            }
            if matches!(word, SEV | SEVL) && (index + 1) * INSTRUCTION_BYTES != consumed.len() {
                return Err("send must be the terminal".into());
            }
        }
        self.admitted_source = Some((
            boundary.address_space(),
            boundary.generation(),
            boundary.entry(),
            boundary.region_base(),
            boundary.source_bytes(),
        ));
        Ok(())
    }
    fn entry_snapshot(
        &mut self,
        _: &Boundary,
        _: &SystemState,
        _: &GuestState,
    ) -> Result<EntrySnapshot, String> {
        Err("event corpus has no exception entry snapshot".into())
    }
    fn tag_snapshot(
        &mut self,
        _: &Boundary,
        _: &SystemState,
        _: &GuestState,
    ) -> Result<TagSnapshot, String> {
        Err("event corpus has no tag service".into())
    }
    fn tag_memory(&mut self) -> Result<&mut MemoryThread<MemoryControls>, String> {
        Err("event corpus has no memory service".into())
    }
    fn send_event_services(
        &mut self,
        boundary: &Boundary,
        system: &SystemState,
        _: &GuestState,
    ) -> Result<SendEventServices<'_>, String> {
        let source = boundary.source();
        let identity = (
            source.address_space(),
            source.generation(),
            source.entry(),
            source.region_base(),
            source.source_bytes(),
        );
        let instruction = boundary.instruction();
        if self.admitted_source != Some(identity)
            || instruction.instruction_pc != self.expected_pc
            || !instruction.matches_source(self.expected_pc, self.expected_word)
        {
            return Err("post-prefix event source identity differs".into());
        }
        if !self.service_available {
            return Err(
                "event publication service explicitly unavailable after source validation".into(),
            );
        }
        if system.current_el() != ExceptionLevel::El0 {
            return Err("current event source level differs".into());
        }
        let attachment = SendAttachment::new(&self.domain, &mut self.endpoint)
            .map_err(|error| format!("{error:?}"))?;
        Ok(SendEventServices {
            profile: Profile {
                current_el: ExceptionLevel::El0,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            attachment,
        })
    }
}
