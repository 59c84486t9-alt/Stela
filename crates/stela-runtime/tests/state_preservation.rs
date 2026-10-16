//! Guest state survives scalar native execution and block reuse.
#![cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
use anyhow::Result;
use stela_compiler::{GuestAddress, GuestState};
use stela_runtime::{
    blocks::{BlockRuntime, StopReason, ThreadState},
    dispatch::LeafDispatcher,
    execution::ExecutableLeaf,
};

const ENTRY: GuestAddress = GuestAddress(0x1000);
const STOP: GuestAddress = GuestAddress(0xdead0000);

fn source() -> Vec<u8> {
    // ADD X0,#1; SUBS X1,X0,#2; B.NE RET; unreachable MOV X2,#0; RET X30.
    [
        0x91000400u32,
        0xf1000801,
        0x54000041,
        0xd2800002,
        0xd65f03c0,
    ]
    .into_iter()
    .flat_map(u32::to_le_bytes)
    .collect()
}

fn state(flags: u32) -> GuestState {
    let mut state = GuestState {
        x: std::array::from_fn(|index| 0x123456789abcdef0u64.rotate_left(index as u32)),
        sp: 0x12340000,
        nzcv: flags << 28,
        reserved: 0xa5c39e71,
        v: std::array::from_fn(|index| {
            [
                0x0123456789abcdefu64.rotate_left(index as u32) ^ u64::from(flags),
                0xfedcba9876543210u64.rotate_right(index as u32) ^ u64::from(flags),
            ]
        }),
        fpcr: 0xa5c39e71 ^ flags,
        fpsr: 0x5a3c618e ^ flags,
    };
    state.x[0] = 3;
    state.x[30] = STOP.0;
    state
}

fn expected(initial: &GuestState) -> GuestState {
    let mut expected = initial.clone();
    expected.x[0] = 4;
    expected.x[1] = 2;
    expected.nzcv = 0x20000000;
    expected
}

#[test]
fn scalar_leaf_preserves_all_vector_bits_and_opaque_fp_control_status() -> Result<()> {
    let cache = tempfile::tempdir()?;
    let mut leaves = LeafDispatcher::new(1, cache.path().into());
    leaves.register(ENTRY, source())?;
    let leaf = ExecutableLeaf::load(&leaves, &leaves.resolve(ENTRY)?)?;
    for flags in 0..16 {
        let initial = state(flags);
        let mut actual = initial.clone();
        // SAFETY: owned finite register-only code has no guest RAM or host calls.
        unsafe { leaf.execute(&leaves, &mut actual)? };
        assert_eq!(actual, expected(&initial));
    }
    Ok(())
}

#[test]
fn scalar_aot_disk_hot_and_fresh_runtime_paths_preserve_the_enlarged_state() -> Result<()> {
    let cache = tempfile::tempdir()?;
    for fresh in 0..2 {
        let mut runtime = BlockRuntime::new(2, cache.path().into());
        runtime.register_code(ENTRY, source())?;
        let discovery = runtime.discover(&[ENTRY], 8)?;
        assert!(discovery.issues.is_empty());
        assert!(!discovery.native_executed && !discovery.native_pages_loaded);
        assert_eq!(discovery.blocks.len(), 3);
        assert_eq!(discovery.compiled_blocks, if fresh == 0 { 3 } else { 0 });
        for flags in 0..16 {
            let initial = state(flags);
            let mut thread = ThreadState {
                registers: initial.clone(),
                pc: ENTRY,
            };
            // SAFETY: all paths are finite owned scalar register instructions,
            // both branch arms are registered, and the actual RET names STOP.
            let outcome = unsafe { runtime.run(&mut thread, Some(STOP), 4)? };
            assert_eq!(outcome.reason, StopReason::StopAddress);
            assert_eq!(outcome.blocks_executed, 2);
            assert_eq!(outcome.compiled_blocks, 0);
            assert_eq!(outcome.disk_cache_hits, if flags == 0 { 2 } else { 0 });
            assert_eq!(outcome.memory_cache_hits, if flags == 0 { 0 } else { 2 });
            assert_eq!(thread.pc, STOP);
            assert_eq!(thread.registers, expected(&initial));
        }
    }
    Ok(())
}
