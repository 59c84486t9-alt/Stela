//! SEV/SEVL event delivery.
mod backend;

use crate::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    system::{
        events::EventDomain,
        execution::{Execution, Failure},
    },
};
use anyhow::Result;
use backend::{ADD_X0, EventBackend, SEVL};
use std::sync::Arc;
use stela_compiler::{GuestAddress, TargetCpu, block::BlockProfile};

const ADDRESS_SPACE: u64 = 7;
const INSTRUCTION_BYTES: u64 = size_of::<u32>() as u64;
const TEST_PREFIX_PC: GuestAddress = GuestAddress(0x1000);

fn backends() -> Result<[EventBackend; 2]> {
    let domain = Arc::new(EventDomain::new());
    let first = domain
        .register(false, None)
        .map_err(|e| anyhow::anyhow!("event register: {e:?}"))?;
    let second = domain
        .register(false, None)
        .map_err(|e| anyhow::anyhow!("event register: {e:?}"))?;
    Ok([
        EventBackend::new(Arc::clone(&domain), first),
        EventBackend::new(domain, second),
    ])
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn fixture_single_step_refusal_precedes_native_prefix_and_publication() -> Result<()> {
    use crate::system::state::{El1Registers, PSTATE_EL0T, PSTATE_SS_MASK, SystemState};
    use stela_compiler::GuestState;

    let cache = tempfile::tempdir()?;
    let mut runtime = BlockRuntime::new_for_target(
        ADDRESS_SPACE,
        cache.path().into(),
        BlockProfile::SystemV1,
        TargetCpu::Baseline,
    );
    runtime.register_code(
        TEST_PREFIX_PC,
        [ADD_X0, SEVL]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect(),
    )?;
    let mut owners = backends()?;
    owners[0].expect(GuestAddress(TEST_PREFIX_PC.0 + INSTRUCTION_BYTES), SEVL);
    let mut thread = ThreadState {
        registers: GuestState {
            x: std::array::from_fn(|index| 0x1000 + index as u64),
            sp: 0x4000,
            nzcv: 0xa000_0000,
            reserved: 0x1234_5678,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0,
            fpsr: 0x0800_0001,
        },
        pc: TEST_PREFIX_PC,
    };
    let mut system = SystemState::new(
        PSTATE_EL0T | PSTATE_SS_MASK,
        0x5000,
        El1Registers::new(0x2000, PSTATE_EL0T, 0, 0, 0x8000),
    )
    .map_err(|error| anyhow::anyhow!("single-step fixture state: {error:?}"))?;
    assert_ne!(system.pstate(&thread.registers) & PSTATE_SS_MASK, 0);
    assert!(owners[0].service_available);
    let original_registers = thread.registers.clone();
    let original_system = system.clone();
    let original_pc = thread.pc;
    let original_events = [owners[0].endpoint.is_set(), owners[1].endpoint.is_set()];
    // SAFETY: the fixture's SS check refuses before this code runs; no guest
    // RAM access is possible.
    let outcome = unsafe {
        runtime.run_with_system(
            &mut thread,
            None,
            1,
            &mut Execution::new(ADDRESS_SPACE, &mut system, &mut owners[0]),
        )?
    };
    assert!(matches!(
        outcome.reason,
        StopReason::SystemEntryFailure {
            instruction_pc: TEST_PREFIX_PC,
            word: ADD_X0,
            failure: Failure::Backend(_),
        }
    ));
    assert_eq!(outcome.blocks_executed, 0);
    assert_eq!(thread.registers, original_registers);
    assert_eq!(system, original_system);
    assert_eq!(thread.pc, original_pc);
    assert_eq!(
        [owners[0].endpoint.is_set(), owners[1].endpoint.is_set()],
        original_events
    );
    assert_eq!(original_events, [false, false]);
    Ok(())
}
