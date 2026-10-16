use super::*;
use crate::system::execution::{Boundary, Dispatcher, EntryBoundary, Failure};

const ADDRESS_SPACE: u64 = 7;
const BASE: GuestAddress = GuestAddress(0x1000);
const ADD: u32 = 0x9100_0400;
const SVC: u32 = 0xd400_0001;
const UDF: u32 = 0x0000_0042;

struct Recorder {
    seen: Vec<(u64, u32)>,
}
impl Dispatcher for Recorder {
    fn address_space(&self) -> u64 {
        ADDRESS_SPACE
    }
    fn validate_entry(
        &mut self,
        boundary: &EntryBoundary,
        source: &[u8],
        _: &GuestState,
    ) -> Result<(), Failure> {
        assert_eq!(boundary.entry(), BASE);
        assert!(source.len().is_multiple_of(INSTRUCTION_BYTES));
        assert!(source.len() <= MAX_BLOCK_INSTRUCTIONS * INSTRUCTION_BYTES);
        assert_eq!(
            u32::from_le_bytes(source[..INSTRUCTION_BYTES].try_into().unwrap()),
            boundary.word()
        );
        Ok(())
    }
    fn complete(
        &mut self,
        boundary: Boundary,
        _: &mut GuestState,
    ) -> Result<GuestAddress, Failure> {
        self.seen
            .push((boundary.source().generation(), boundary.instruction().word));
        Ok(boundary.instruction().next_pc)
    }
}

#[test]
fn replacement_uses_new_registered_generation_and_original_word() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime =
        BlockRuntime::new_with_profile(ADDRESS_SPACE, cache.path().into(), BlockProfile::SystemV1);
    let mut state = ThreadState {
        registers: GuestState::default(),
        pc: BASE,
    };
    let mut recorder = Recorder { seen: Vec::new() };
    let first = runtime.register_code(BASE, SVC.to_le_bytes().to_vec())?;
    // SAFETY: exact trusted fixture; the service boundary performs no RAM access.
    let outcome = unsafe {
        runtime.run_with_system(&mut state, Some(GuestAddress(BASE.0 + 4)), 1, &mut recorder)?
    };
    assert!(matches!(outcome.reason, StopReason::StopAddress));
    let second = runtime.register_code(BASE, UDF.to_le_bytes().to_vec())?;
    assert!(second > first);
    state.pc = BASE;
    // SAFETY: replacement is serialized; the immutable original is revalidated.
    unsafe {
        runtime.run_with_system(&mut state, Some(GuestAddress(BASE.0 + 4)), 1, &mut recorder)?
    };
    assert_eq!(recorder.seen, [(first, SVC), (second, UDF)]);
    Ok(())
}

#[test]
fn missing_system_context_stops_before_native_prefix() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut runtime =
        BlockRuntime::new_with_profile(ADDRESS_SPACE, cache.path().into(), BlockProfile::SystemV1);
    runtime.register_code(
        BASE,
        [ADD, SVC].into_iter().flat_map(u32::to_le_bytes).collect(),
    )?;
    let mut state = ThreadState {
        registers: GuestState::default(),
        pc: BASE,
    };
    let original = state.registers.clone();
    // SAFETY: trusted pure prefix; missing context must prevent invocation.
    let outcome = unsafe { runtime.run(&mut state, None, 1)? };
    assert!(matches!(
        outcome.reason,
        StopReason::SystemContextRequired {
            instruction_pc: BASE
        }
    ));
    assert_eq!(outcome.blocks_executed, 0);
    assert_eq!(state.registers, original);
    assert_eq!(state.pc, BASE);
    Ok(())
}

#[test]
fn terminal_recovery_rejects_forged_pc_extent_and_non_system_word() {
    let source: Vec<_> = [ADD, SVC].into_iter().flat_map(u32::to_le_bytes).collect();
    let terminal = GuestAddress(BASE.0 + 4);
    assert!(validate_system_exit(BASE, terminal, source.len(), BASE.0, &source).is_ok());
    assert!(validate_system_exit(BASE, BASE, source.len(), BASE.0, &source).is_err());
    assert!(validate_system_exit(BASE, terminal, source.len() + 4, BASE.0, &source).is_err());
    assert!(validate_system_exit(BASE, BASE, 4, BASE.0, &source).is_err());
    assert!(validate_system_exit(BASE, terminal, source.len(), BASE.0, &source[..4]).is_err());
}
