//! Actual generated-leaf consumers of the provider's test-only late failure.
use super::*;

const ACTIVE_LOAD_BYTES: u64 = 2;
const REENTRY_X0_SENTINEL: u64 = 0x9abc_def0_1234_5678;

#[derive(Clone, Copy)]
enum LateFailure {
    Returned,
    CallbackFault,
    StackFault,
    InvalidFaultPc,
    Reentry,
}

fn mxcsr() -> u32 {
    let mut value = 0_u32;
    // SAFETY: STMXCSR writes exactly this live aligned u32 on x86-64.
    unsafe {
        std::arch::asm!("stmxcsr [{pointer}]", pointer = in(reg) &mut value,
                        options(nostack, preserves_flags));
    }
    value
}

struct HostMxcsr(u32);
impl HostMxcsr {
    fn seeded() -> Self {
        let previous = mxcsr();
        const PRECISION_STICKY: u32 = 1 << 5;
        // SAFETY: preserve every effective mask/control and set one legal sticky bit.
        unsafe { Self::write(previous | PRECISION_STICKY) };
        Self(previous)
    }

    unsafe fn write(value: u32) {
        // SAFETY: the caller supplies an already valid host MXCSR value.
        unsafe {
            std::arch::asm!("ldmxcsr [{pointer}]", pointer = in(reg) &value,
                            options(nostack, preserves_flags));
        }
    }
}
impl Drop for HostMxcsr {
    fn drop(&mut self) {
        // SAFETY: restore the exact legal value captured on this test thread.
        unsafe { Self::write(self.0) };
    }
}

fn assert_scalable_storage(actual: &ScalableState, before: &ScalableState) {
    assert_eq!(actual.length, before.length);
    assert_eq!(actual.sme2, before.sme2);
    assert_eq!(actual.mode, before.mode);
    assert_eq!(actual.tpidr2_el0, before.tpidr2_el0);
    assert_eq!(actual.fpmr, before.fpmr);
    assert_eq!(actual.vectors, before.vectors);
    assert_eq!(actual.matrices, before.matrices);
}

fn late_failure(case: LateFailure) {
    let stack_fault = matches!(case, LateFailure::StackFault);
    let callback_fault = matches!(
        case,
        LateFailure::CallbackFault | LateFailure::InvalidFaultPc | LateFailure::Reentry
    );
    let load = if stack_fault {
        LD1B_Z1_P0_SP
    } else {
        LD1B_Z1_P0_X5
    };
    let mut leaf = PreparedScalableLeaf::prepare(
        &words(&[MOV_X0_SEVEN, load, RET_X30]),
        GuestAddress(GUEST_BASE),
        profile(),
        TargetCpu::Baseline,
    )
    .unwrap();
    if matches!(case, LateFailure::InvalidFaultPc) {
        // Deliberately corrupt only test metadata so PC validation itself fails.
        leaf.source_map = leaf
            .source_map
            .iter()
            .copied()
            .filter(|(pc, _)| pc.0 != GUEST_BASE + size_of::<u32>() as u64)
            .collect::<Vec<_>>()
            .into_boxed_slice();
    }
    let (storage, mut memory) = owner(false, callback_fault);
    let ram_before = storage.bytes();
    let (mut registers, mut scalable) = state();
    scalable
        .apply_mode(&mut registers, ScalableMode::new(true, true))
        .unwrap();
    scalable.matrices.as_mut().unwrap().fill(0x6d);
    scalable
        .apply_mode(&mut registers, profile().mode())
        .unwrap();
    scalable.set_tpidr2_el0(0x1234_5678_9abc_def0);
    scalable.set_fpmr(0x2468_ace0);
    if stack_fault {
        registers.sp = RAM_BASE + 1;
        scalable.write_predicate(0, &[0, 0]).unwrap();
    }
    let scalable_before = scalable.clone();
    let mut expected = registers.clone();
    expected.x[0] = 7;
    if !stack_fault && !callback_fault {
        expected.v[DESTINATION as usize] = [u64::from_le_bytes([0, 1, 0, 0, 0, 0, 0, 0]), 0];
    }
    let original_fault = if stack_fault {
        Some(MemoryFault {
            status: MemoryStatus::StackAlignment,
            address: GuestAddress(RAM_BASE + 1),
            pc: GuestAddress(GUEST_BASE + size_of::<u32>() as u64),
            completed_bytes: 0,
        })
    } else if callback_fault {
        Some(MemoryFault {
            status: MemoryStatus::Permission,
            address: GuestAddress(RAM_BASE + 1),
            pc: GuestAddress(GUEST_BASE + size_of::<u32>() as u64),
            completed_bytes: 1,
        })
    } else {
        None
    };
    let mut context = context();
    let pointers = (context.memory, context.scalable, context.system);
    let _mxcsr_guard = HostMxcsr::seeded();
    let mxcsr_before = mxcsr();
    memory.inject_post_body_failure_once_for_test();
    // SAFETY: finite real generated leaf, explicit CPU controls and disjoint
    // pinned owners. Provider injection runs only after the actual body returns.
    let exit =
        unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }.unwrap();
    assert_eq!(
        exit,
        ScalableLeafExit::FinalizationFailed {
            status: MemoryStatus::Domain,
            native_executed: true,
            completed_bytes: original_fault
                .map_or(ACTIVE_LOAD_BYTES, |fault| fault.completed_bytes),
            original_fault,
        }
    );
    assert_eq!(registers, expected);
    assert_scalable_storage(&scalable, &scalable_before);
    assert_eq!(storage.bytes(), ram_before);
    assert_eq!((context.memory, context.scalable, context.system), pointers);
    assert_eq!(mxcsr(), mxcsr_before);
    if matches!(case, LateFailure::Reentry) {
        registers.x[0] = REENTRY_X0_SENTINEL;
        expected.x[0] = REENTRY_X0_SENTINEL;
        // SAFETY: same finite source and owners; failed real domain must decline
        // before executing another prefix or modifying any architectural state.
        let exit =
            unsafe { leaf.execute(&mut registers, &mut scalable, &mut memory, &mut context) }
                .unwrap();
        assert_eq!(exit, ScalableLeafExit::EntryDeclined(MemoryStatus::Domain));
        assert_eq!(registers, expected);
        assert_scalable_storage(&scalable, &scalable_before);
        assert_eq!(storage.bytes(), ram_before);
        assert_eq!((context.memory, context.scalable, context.system), pointers);
        assert_eq!(mxcsr(), mxcsr_before);
    }
}

#[test]
fn returned_native_body_cannot_escape_failed_health_finalization() {
    late_failure(LateFailure::Returned);
}
#[test]
fn callback_fault_keeps_original_prefix_after_failed_finalization() {
    late_failure(LateFailure::CallbackFault);
}
#[test]
fn emitted_inactive_sp_fault_keeps_original_provenance_after_failed_finalization() {
    late_failure(LateFailure::StackFault);
}
#[test]
fn pc_validation_error_cannot_discard_fault_during_failed_finalization() {
    late_failure(LateFailure::InvalidFaultPc);
}
#[test]
fn failed_finalization_restores_owners_and_blocks_next_entry() {
    late_failure(LateFailure::Reentry);
}
