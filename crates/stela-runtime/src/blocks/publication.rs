//! Exclusive access to registered source and native code while an EL1 exception
//! completes, so neither can be replaced or reclaimed meanwhile.

use super::{BlockRuntime, serialize_instruction_execution, validate_terminal_word};
use crate::system::{
    exception::{Completion, EffectFailure, RequiredEffects, ServiceRequest},
    execution::Boundary,
    fixed_controls::FixedEl1Controls,
};
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use stela_compiler::{
    GuestAddress,
    aarch64::system::exception::Operation,
    block::system::{SystemInstruction, SystemOperation},
};

struct SourceSite {
    address_space: u64,
    generation: u64,
    entry: GuestAddress,
    instruction: SystemInstruction,
    region_base: GuestAddress,
    registered_bytes: usize,
    consumed_bytes: usize,
}

/// A non-cloneable borrow of the registered code, taken after native return. It
/// exposes neither mutable source nor executable pointers.
pub struct CodePublicationScope<'run> {
    runtime: &'run BlockRuntime,
    site: SourceSite,
}

impl<'run> CodePublicationScope<'run> {
    pub(crate) fn new(runtime: &'run BlockRuntime, boundary: &Boundary) -> Self {
        let source = boundary.source();
        Self {
            runtime,
            site: SourceSite {
                address_space: source.address_space(),
                generation: source.generation(),
                entry: source.entry(),
                instruction: boundary.instruction(),
                region_base: source.region_base(),
                registered_bytes: source.source_bytes(),
                consumed_bytes: boundary.consumed_bytes(),
            },
        }
    }

    /// Match the exact typed runtime boundary, rather than public PC/word
    /// metadata, and revalidate against the still-borrowed source owner.
    pub(crate) fn check_boundary(&self, boundary: &Boundary) -> Result<(), String> {
        let source = boundary.source();
        if source.address_space() != self.site.address_space
            || source.generation() != self.site.generation
            || source.entry() != self.site.entry
            || source.region_base() != self.site.region_base
            || source.source_bytes() != self.site.registered_bytes
            || boundary.consumed_bytes() != self.site.consumed_bytes
            || boundary.instruction() != self.site.instruction
        {
            return Err("code publication scope belongs to another boundary".into());
        }
        self.check_source()
    }

    pub(crate) fn check_exception_request(
        &self,
        controls: &FixedEl1Controls,
        request: &ServiceRequest,
    ) -> Result<(), String> {
        controls
            .check_exception_request(request)
            .map_err(|error| format!("fixed controls: {error:?}"))?;
        self.check_source()?;
        let matches_operation = matches!(
            (request.effects, self.site.instruction.operation),
            (
                RequiredEffects::Entry { irq: false },
                SystemOperation::Exception(
                    Operation::Undefined { .. } | Operation::SupervisorCall { .. }
                )
            ) | (
                RequiredEffects::Return,
                SystemOperation::Exception(Operation::ExceptionReturn { key: None })
            )
        );
        if request.source_pc != self.site.instruction.instruction_pc.0 || !matches_operation {
            return Err("fixed synchronization request differs from typed source".into());
        }
        Ok(())
    }

    /// Perform the host serialization once the controls and the source
    /// instruction are validated. Control, cache, TLBI, data, device and IRQ
    /// effects are not handled here.
    pub(crate) fn synchronize_fixed_el1(
        &mut self,
        controls: &FixedEl1Controls,
        request: &ServiceRequest,
    ) -> Result<(), EffectFailure<String>> {
        self.check_exception_request(controls, request)
            .map_err(no_effect)?;
        // The supported helper has no fallible work after CPUID. An unsupported
        // host is declined before the host effect; no queued work is inferred.
        serialize_instruction_execution().map_err(|error| no_effect(error.to_string()))
    }

    fn check_source(&self) -> Result<(), String> {
        let (base, region) = self
            .runtime
            .region(self.site.entry)
            .ok_or("code publication source disappeared")?;
        if self.runtime.address_space() != self.site.address_space
            || base != self.site.region_base.0
            || region.generation != self.site.generation
            || region.source.len() != self.site.registered_bytes
        {
            return Err("code publication source identity changed".into());
        }
        let word = validate_terminal_word(
            self.site.entry,
            self.site.instruction.instruction_pc,
            self.site.consumed_bytes,
            base,
            &region.source,
        )
        .map_err(|error| error.to_string())?;
        if !self
            .site
            .instruction
            .matches_source(self.site.instruction.instruction_pc, word)
        {
            return Err("code publication original instruction changed".into());
        }
        Ok(())
    }
}

fn no_effect(error: String) -> EffectFailure<String> {
    EffectFailure {
        error,
        completion: Completion::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{
        debug::DebugControls,
        exception::{EntryControls, RequiredEffects},
        execution::EntryBoundary,
        profile::{EntryProfile, ScalableEntryAbsence, SystemEntryFeatures},
        state::{El1Registers, PSTATE_EL1H, SystemState},
    };
    use stela_compiler::{
        GuestState,
        block::{BlockProfile, system::decode_system_instruction},
    };

    const ADDRESS_SPACE: u64 = 7;
    const ENTRY: GuestAddress = GuestAddress(0x1000);
    const SVC: u32 = 0xd400_0001;
    const ERET: u32 = 0xd69f_03e0;
    const INSTRUCTION_BYTES: usize = size_of::<u32>();

    fn controls() -> FixedEl1Controls {
        FixedEl1Controls::new(
            EntryProfile::base(
                SystemEntryFeatures::declared_absent(),
                ScalableEntryAbsence::from_id_registers(0, 0).unwrap(),
            )
            .unwrap(),
            crate::system::profile::BaseSpeAbsence::from_id_aa64dfr0_el1(0).unwrap(),
            0,
            EntryControls {
                tcr_el1: 0,
                mdscr_el1: 0,
                debug: DebugControls::default(),
            },
        )
        .unwrap()
    }

    fn boundary(runtime: &BlockRuntime, word: u32) -> Boundary {
        let (base, region) = runtime.region(ENTRY).unwrap();
        Boundary::new(
            EntryBoundary::new(
                runtime.address_space(),
                region.generation,
                ENTRY,
                GuestAddress(base),
                region.source.len(),
                word,
            ),
            INSTRUCTION_BYTES,
            decode_system_instruction(ENTRY, word).unwrap().unwrap(),
        )
    }

    fn request(controls: &FixedEl1Controls, effects: RequiredEffects) -> ServiceRequest {
        let system = SystemState::new(PSTATE_EL1H, 0, El1Registers::new(0, 0, 0, 0, 0)).unwrap();
        let snapshot = controls
            .entry_snapshot(&system, &GuestState::default())
            .unwrap();
        ServiceRequest {
            effects,
            profile: snapshot.profile,
            source_el: snapshot.profile.current_el,
            source_pstate: PSTATE_EL1H,
            source_pc: ENTRY.0,
            controls: snapshot.controls,
        }
    }

    fn registered_runtime(word: u32) -> BlockRuntime {
        let mut runtime = BlockRuntime::new_with_profile(
            ADDRESS_SPACE,
            std::path::PathBuf::new(),
            BlockProfile::SystemV1,
        );
        runtime
            .register_code(ENTRY, word.to_le_bytes().to_vec())
            .unwrap();
        runtime
    }

    #[test]
    fn publication_scope_checks_typed_boundary_and_request_before_serialization() {
        let runtime = registered_runtime(SVC);
        let boundary = boundary(&runtime, SVC);
        let mut scope = CodePublicationScope::new(&runtime, &boundary);
        let controls = controls();
        let request = request(&controls, RequiredEffects::Entry { irq: false });
        assert_eq!(scope.check_boundary(&boundary), Ok(()));
        assert_eq!(scope.check_exception_request(&controls, &request), Ok(()));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(scope.synchronize_fixed_el1(&controls, &request), Ok(()));
        let mut wrong = request;
        wrong.source_pc += INSTRUCTION_BYTES as u64;
        assert_eq!(
            scope
                .synchronize_fixed_el1(&controls, &wrong)
                .unwrap_err()
                .completion,
            Completion::None
        );
        wrong = request;
        wrong.effects = RequiredEffects::Return;
        assert_eq!(
            scope
                .synchronize_fixed_el1(&controls, &wrong)
                .unwrap_err()
                .completion,
            Completion::None
        );
        wrong = request;
        wrong.controls.tcr_el1 = 1;
        assert_eq!(
            scope
                .synchronize_fixed_el1(&controls, &wrong)
                .unwrap_err()
                .completion,
            Completion::None
        );
    }

    #[test]
    fn publication_scope_rejects_stale_generation_and_changed_original_word() {
        let mut runtime = registered_runtime(SVC);
        let stale = boundary(&runtime, SVC);
        runtime
            .register_code(ENTRY, SVC.to_le_bytes().to_vec())
            .unwrap();
        let scope = CodePublicationScope::new(&runtime, &stale);
        assert!(scope.check_boundary(&stale).is_err());
        let forged = boundary(&runtime, ERET);
        let scope = CodePublicationScope::new(&runtime, &forged);
        assert!(scope.check_boundary(&forged).is_err());
    }

    #[test]
    fn publication_scope_rejects_other_source_identity_and_forged_typed_operands() {
        let runtime = registered_runtime(SVC);
        let current = boundary(&runtime, SVC);
        let scope = CodePublicationScope::new(&runtime, &current);
        let mut other = registered_runtime(SVC);
        other.address_space += 1;
        assert!(scope.check_boundary(&boundary(&other, SVC)).is_err());
        let mut instruction = current.instruction();
        instruction.next_pc = ENTRY;
        let source = current.source();
        let forged = Boundary::new(
            EntryBoundary::new(
                source.address_space(),
                source.generation(),
                source.entry(),
                source.region_base(),
                source.source_bytes(),
                source.word(),
            ),
            current.consumed_bytes(),
            instruction,
        );
        assert!(scope.check_boundary(&forged).is_err());
    }

    #[test]
    fn publication_scope_additive_default_preserves_legacy_completion() {
        use crate::system::execution::{Dispatcher, Failure};
        struct Legacy(usize);
        impl Dispatcher for Legacy {
            fn address_space(&self) -> u64 {
                ADDRESS_SPACE
            }
            fn validate_entry(
                &mut self,
                _: &EntryBoundary,
                _: &[u8],
                _: &GuestState,
            ) -> Result<(), Failure> {
                Ok(())
            }
            fn complete(
                &mut self,
                _: Boundary,
                _: &mut GuestState,
            ) -> Result<GuestAddress, Failure> {
                self.0 += 1;
                Ok(ENTRY)
            }
        }
        let runtime = registered_runtime(SVC);
        let boundary = boundary(&runtime, SVC);
        let mut scope = CodePublicationScope::new(&runtime, &boundary);
        let mut legacy = Legacy(0);
        assert_eq!(
            legacy.complete_with_code_scope(boundary, &mut GuestState::default(), &mut scope),
            Ok(ENTRY)
        );
        assert_eq!(legacy.0, 1);
        // The default performs only the provider's existing completion.
    }
}
