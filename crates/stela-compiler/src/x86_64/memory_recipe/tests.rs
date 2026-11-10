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
