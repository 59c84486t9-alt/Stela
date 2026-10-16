use super::*;
use crate::clock::{ReplaySource, Snapshot};

const BASE: GuestAddress = GuestAddress(0x1000);
const STOP: GuestAddress = GuestAddress(0x1400);
const PROFILE: BlockProfile = BlockProfile::AppleArm64eSoftwarePauthClockV1;

fn runtime(path: &std::path::Path, words: &[u32]) -> Result<BlockRuntime> {
    let mut runtime = BlockRuntime::new_with_profile(1, path.to_path_buf(), PROFILE);
    runtime.register_code(
        BASE,
        words.iter().flat_map(|word| word.to_le_bytes()).collect(),
    )?;
    Ok(runtime)
}
fn keys(address_space: u64) -> pauth::Context {
    pauth::Context::new(address_space, pauth::Keys::from_ib_words(1, 2))
}
fn initial_thread(flags: u32) -> ThreadState {
    let mut registers = GuestState {
        x: core::array::from_fn(|i| 0x0123456789abcdefu64.rotate_left(i as u32)),
        sp: 0x2000,
        nzcv: flags << 28,
        reserved: 0xa5c39e71,
        v: core::array::from_fn(|i| {
            [
                0x123456789abcdef0u64.rotate_left(i as u32),
                0xfedcba9876543210u64.rotate_right(i as u32),
            ]
        }),
        fpcr: 0x03c00000,
        fpsr: 0x0800001f,
    };
    registers.x[30] = STOP.0;
    ThreadState {
        registers,
        pc: BASE,
    }
}

#[test]
fn all_counter_destinations_preserve_full_state_and_share_preparation_cache() -> Result<()> {
    let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
    let samples = (0..=512)
        .map(|i| Snapshot {
            counter: 1000 + i,
            sleep_ticks: 100,
        })
        .collect();
    let mut clock = clock::Context::new(1, Box::new(ReplaySource::new(samples)?))?;
    let keys = keys(1);
    let cache = tempfile::tempdir()?;
    for destination in 0..32 {
        let mut vm = runtime(cache.path(), &[0xd2800547, 0xd53be040 | destination])?;
        let prepared = vm.prepare(BASE)?;
        assert!(!prepared.prepared.cache_hit);
        for flags in 0..16 {
            let mut state = initial_thread(flags);
            let mut expected = state.registers.clone();
            expected.x[7] = 42;
            let counter = 1001 + u64::from(destination * 16 + flags);
            if destination != 31 {
                expected.x[destination as usize] = counter;
            }
            // SAFETY: register prefix and checked service only, no guest RAM accesses.
            let result = unsafe {
                vm.run_with_clock(
                    &mut state,
                    Some(GuestAddress(BASE.0 + 8)),
                    1,
                    &keys,
                    &mut clock,
                )?
            };
            assert_eq!(state.registers, expected);
            assert_eq!(state.pc, GuestAddress(BASE.0 + 8));
            assert_eq!(result.reason, StopReason::StopAddress);
            assert_eq!(result.blocks_executed, 1);
            assert_eq!(result.compiled_blocks, 0);
            assert_eq!(result.disk_cache_hits, usize::from(flags == 0));
            assert_eq!(result.clock_events.len(), 1);
            assert_eq!(result.clock_events[0].counter, Some(counter));
            assert_eq!(
                result.clock_events[0].instruction.operation,
                ClockOperation::ReadVirtualCounter {
                    destination: destination as u8
                }
            );
        }
    }
    assert_eq!(clock.events().len(), 513);
    Ok(())
}

#[test]
fn isb_serializes_without_sampling_and_counter_xzr_discards_only_destination() -> Result<()> {
    let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
    let mut clock = clock::Context::new(
        1,
        Box::new(ReplaySource::new(vec![
            Snapshot {
                counter: 100,
                sleep_ticks: 10,
            },
            Snapshot {
                counter: 150,
                sleep_ticks: 20,
            },
        ])?),
    )?;
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[0xd5033fdf, 0xd53be05f, 0xd65f03c0])?;
    let mut state = initial_thread(15);
    let before = state.registers.clone();
    let result = unsafe { vm.run_with_clock(&mut state, Some(STOP), 3, &keys(1), &mut clock)? };
    assert_eq!(result.reason, StopReason::StopAddress);
    assert_eq!(result.blocks_executed, 3);
    assert_eq!(state.registers, before);
    assert_eq!(result.clock_events.len(), 2);
    assert_eq!(result.clock_events[0].counter, None);
    assert_eq!(result.clock_events[1].counter, Some(150));
    assert_eq!(clock.events().len(), 2);
    Ok(())
}

#[test]
fn unavailable_clock_preserves_destination_page_and_exact_resume_after_prefix() -> Result<()> {
    let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
    let mut clock = clock::Context::new(
        1,
        Box::new(ReplaySource::new(vec![Snapshot {
            counter: 100,
            sleep_ticks: 10,
        }])?),
    )?;
    let page = clock.snapshot_bytes(0, clock::GUEST_BYTES)?;
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[0x91000400, 0xd53be048])?;
    let mut state = initial_thread(5);
    let mut expected = state.registers.clone();
    expected.x[0] = expected.x[0].wrapping_add(1);
    for _ in 0..2 {
        let result = unsafe {
            vm.run_with_clock(
                &mut state,
                Some(GuestAddress(BASE.0 + 8)),
                1,
                &keys(1),
                &mut clock,
            )?
        };
        assert!(matches!(result.reason, StopReason::ClockUnavailable { .. }));
        assert_eq!(state.registers, expected);
        assert_eq!(state.pc, GuestAddress(BASE.0 + 4));
        assert_eq!(result.last_exit, Some((BASE.0 + 4, ExitKind::Clock as u64)));
        assert!(result.clock_events.is_empty());
        assert_eq!(clock.snapshot_bytes(0, clock::GUEST_BYTES)?, page);
        assert_eq!(clock.events().len(), 1);
    }
    Ok(())
}

#[test]
fn missing_clock_and_foreign_services_decline_without_helper_effects() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut vm = runtime(cache.path(), &[0x91000400, 0xd5033fdf])?;
    let mut state = initial_thread(7);
    let mut expected = state.registers.clone();
    expected.x[0] = expected.x[0].wrapping_add(1);
    let result = unsafe { vm.run_with_pauth(&mut state, None, 1, &keys(1))? };
    assert!(matches!(result.reason, StopReason::ClockRequired { .. }));
    assert_eq!(state.registers, expected);
    assert_eq!(state.pc, GuestAddress(BASE.0 + 4));
    assert!(result.clock_events.is_empty());
    let _lock = clock::TEST_CONTEXT_LOCK.lock().unwrap();
    for address_space in [1, 2] {
        let mut clock = clock::Context::new(
            address_space,
            Box::new(ReplaySource::new(vec![Snapshot {
                counter: 100,
                sleep_ticks: 10,
            }])?),
        )?;
        let empty = tempfile::tempdir()?;
        let mut vm = runtime(empty.path(), &[0xd53be048])?;
        let mut state = initial_thread(0);
        let before = state.registers.clone();
        let pauth = keys(if address_space == 1 { 2 } else { 1 });
        assert!(unsafe { vm.run_with_clock(&mut state, None, 1, &pauth, &mut clock) }.is_err());
        assert_eq!(state.pc, BASE);
        assert_eq!(state.registers, before);
        assert_eq!(clock.events().len(), 1);
        assert_eq!(std::fs::read_dir(empty.path())?.count(), 0);
    }
    Ok(())
}
