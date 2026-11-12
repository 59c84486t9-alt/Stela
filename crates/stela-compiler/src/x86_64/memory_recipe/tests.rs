use super::*;

const LOAD: MemoryTransfer = MemoryTransfer::Load {
    signed: false,
    width: Width::X64,
};
/// MOVDQA XMM0,[RAX] and MOVDQA [RAX],XMM0.
const MOVDQA_LOAD: [u8; 4] = [0x66, 0x0f, 0x6f, 0x00];
const MOVDQA_STORE: [u8; 4] = [0x66, 0x0f, 0x7f, 0x00];
/// TEST AL,15.
const TEST_ALIGNMENT: [u8; 3] = [0xf6, 0xc0, 0x0f];

fn pair_of(transfer: MemoryTransfer, bytes: u8, base: Register, displacement: i32) -> Pair {
    Pair {
        transfer,
        bytes,
        data: [Register::X(16), Register::X(17)],
        address: ImmediateAddress {
            base,
            displacement,
            mode: AddressMode::Offset,
        },
    }
}

fn contains(code: &Code, bytes: &[u8]) -> bool {
    code.as_slice()
        .windows(bytes.len())
        .any(|window| window == bytes)
}

/// FEAT_LSE2: a 16-byte-aligned X pair is one 16-byte access, which is
/// single-copy atomic on `TargetCpu::AtomicLoad16` hosts. An address not
/// known aligned tests RAX and takes the element accesses otherwise.
#[test]
fn aligned_x_pairs_are_one_16_byte_access() {
    for (transfer, movdqa) in [(LOAD, MOVDQA_LOAD), (MemoryTransfer::Store, MOVDQA_STORE)] {
        let (code, recipe) = pair_recipe(
            MemoryChecks::DEFAULT,
            pair_of(transfer, 8, Register::X(15), -8),
        );
        assert!(recipe.complete(&code));
        assert!(contains(&code, &TEST_ALIGNMENT) && contains(&code, &movdqa));
        if transfer == LOAD {
            // The region recipes find both results where they always were.
            assert_eq!(
                [recipe.result(0), recipe.result(1)],
                [Some(Gpr::Rcx), Some(Gpr::R8)]
            );
            assert_ne!(recipe.clobbers() & mask(Gpr::R8), 0);
        }
        // A checked SP is 16-byte aligned: at a multiple of 16 the access
        // is the 16-byte one alone, 8 bytes on two element accesses.
        let (aligned, recipe) = pair_recipe(
            MemoryChecks::DEFAULT,
            pair_of(transfer, 8, Register::Sp, 16),
        );
        assert!(recipe.complete(&aligned));
        assert!(contains(&aligned, &movdqa) && !contains(&aligned, &TEST_ALIGNMENT));
        let (split, _) = pair_recipe(MemoryChecks::DEFAULT, pair_of(transfer, 8, Register::Sp, 8));
        assert!(!contains(&split, &movdqa) && !contains(&split, &TEST_ALIGNMENT));
        // An unchecked SP is tested like any other base.
        let unchecked = MemoryChecks {
            stack_alignment: false,
            ..MemoryChecks::DEFAULT
        };
        let (tested, _) = pair_recipe(unchecked, pair_of(transfer, 8, Register::Sp, 8));
        assert!(contains(&tested, &TEST_ALIGNMENT) && contains(&tested, &movdqa));
    }
}

/// W pairs and LDPSW have no 16-byte access to make atomic.
#[test]
fn other_pairs_keep_their_element_accesses() {
    let signed = MemoryTransfer::Load {
        signed: true,
        width: Width::X64,
    };
    let word = MemoryTransfer::Load {
        signed: false,
        width: Width::W32,
    };
    for (transfer, bytes) in [(word, 4), (MemoryTransfer::Store, 4), (signed, 4)] {
        let (code, _) = pair_recipe(
            MemoryChecks::DEFAULT,
            pair_of(transfer, bytes, Register::X(15), 0),
        );
        assert!(!contains(&code, &TEST_ALIGNMENT));
        assert!(!contains(&code, &MOVDQA_LOAD) && !contains(&code, &MOVDQA_STORE));
    }
}

/// Pinned code tests the base's own host register where the pair starts a
/// multiple of 16 bytes past it, and its address in RAX otherwise.
#[test]
fn pinned_pairs_test_the_register_that_holds_the_address() {
    for displacement in [0, 16, 8] {
        let mut code = Code::pinned();
        pair(
            &mut code,
            MemoryChecks::DEFAULT,
            pair_of(LOAD, 8, Register::X(1), displacement),
            None,
        );
        let host = code.host(Register::X(1)).expect("X1 is pinned");
        let mut expected = Code::new();
        let tested = if displacement % 16 == 0 {
            host
        } else {
            Gpr::Rax
        };
        expected.asm().test_imm(Size::Byte, tested, 15);
        assert!(contains(&code, expected.as_slice()), "{displacement}");
    }
}

/// Aligned X pairs at SP move each register straight from or to where it
/// lives (its host register, its frame slot, XZR) through one 16-byte
/// access, in pinned and frame code alike: the state and memory a plain
/// model gives, at an offset and with pre- and post-index writeback.
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[test]
fn aligned_sp_pairs_move_each_register_from_where_it_lives() {
    use crate::{
        GuestAddress, GuestState, Options, TargetCpu,
        block::{BlockProfile, Features},
    };
    const BASE: GuestAddress = GuestAddress(0x4000_0000);
    // Pinned (X0, X1, X8, X16, X19), frame slots and XZR.
    const REGISTERS: [u32; 8] = [0, 1, 8, 16, 19, 22, 30, 31];
    let mut memory = alloc::vec![0u8; 1 << 12];
    let middle = (memory.as_mut_ptr() as u64 + (1 << 11)) & !15;
    let target = TargetCpu::detect();
    let mut compared = 0;
    for (profile, pinned) in [
        (BlockProfile::new(Features::SYSTEM_MODE), true),
        (BlockProfile::ORDINARY, false),
    ] {
        let options = Options::new(profile, target);
        // Offset #16, pre-index #-32 and post-index #32.
        for (form, offset, writeback) in [
            (0xa900_0000_u32 | 2 << 15, 16_i64, false),
            (0xa980_0000 | 0x7c << 15, -32, true),
            (0xa880_0000 | 4 << 15, 32, true),
        ] {
            let post = form & 0x0180_0000 == 0x0080_0000;
            for load in [false, true] {
                for &first in &REGISTERS {
                    for &second in &REGISTERS {
                        if load && first == second {
                            continue;
                        }
                        let word = form | u32::from(load) << 22 | second << 10 | 31 << 5 | first;
                        let block = crate::compile(&word.to_le_bytes(), BASE, &options)
                            .unwrap_or_else(|error| panic!("{word:08x}: {error:?}"));
                        assert_eq!(block.source_bytes, 4, "{word:08x}");
                        let code = if pinned {
                            crate::x86_64::pinned::entered(&block.native.x86_64_code)
                        } else {
                            block.native.x86_64_code.clone()
                        };
                        let mut state = GuestState::default();
                        for (index, slot) in state.x.iter_mut().enumerate() {
                            *slot = 0x0101_0101_0101_0101 * (index as u64 + 1);
                        }
                        state.sp = middle;
                        for (index, byte) in memory.iter_mut().enumerate() {
                            *byte = (index * 7 + 3) as u8;
                        }
                        let mut expected = state.clone();
                        let mut expected_memory = memory.clone();
                        let at = middle.wrapping_add_signed(if post { 0 } else { offset });
                        let index = (at - memory.as_ptr() as u64) as usize;
                        let read = |register: u32| match register {
                            31 => 0,
                            _ => expected.x[register as usize],
                        };
                        if load {
                            for (element, register) in [first, second].into_iter().enumerate() {
                                let bytes = &expected_memory[index + 8 * element..][..8];
                                let value = u64::from_le_bytes(bytes.try_into().unwrap());
                                if register != 31 {
                                    expected.x[register as usize] = value;
                                }
                            }
                        } else {
                            let values = [read(first), read(second)];
                            for (element, value) in values.into_iter().enumerate() {
                                expected_memory[index + 8 * element..][..8]
                                    .copy_from_slice(&value.to_le_bytes());
                            }
                        }
                        if writeback {
                            expected.sp = middle.wrapping_add_signed(offset);
                        }
                        let next = crate::x86_64::native::run(&code, &mut state);
                        assert_eq!(next, BASE.0 + 4, "{word:08x}");
                        assert_eq!(state, expected, "{word:08x} pinned {pinned}");
                        assert!(memory == expected_memory, "{word:08x} pinned {pinned}");
                        compared += 1;
                    }
                }
            }
        }
    }
    assert_eq!(compared, 2 * 3 * (64 + 56));
}
