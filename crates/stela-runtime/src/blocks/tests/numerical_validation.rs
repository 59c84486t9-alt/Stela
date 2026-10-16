use super::*;

const BASE: u64 = 0x1000;
const NOP: u32 = 0xd503201f;
const FADD_S: u32 = 0x1e222820;
const RET: u32 = 0xd65f03c0;

fn source(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[test]
fn interior_numerical_exit_keeps_terminal_helpers_strict() {
    let bytes = source(&[NOP, FADD_S, RET]);
    let (operand, continuation) = validate_numerical_exit(
        GuestAddress(BASE),
        GuestAddress(BASE + 4),
        bytes.len(),
        BASE,
        &bytes,
    )
    .unwrap();
    let stela_compiler::aarch64::FloatingPointOperation::Binary(operand) = operand else {
        panic!("binary instruction decoded as another numerical family");
    };
    assert_eq!(operand.destination, 0);
    assert_eq!(
        operand.inputs,
        stela_compiler::aarch64::simd::arithmetic::Inputs::Elementwise { left: 1, right: 2 }
    );
    assert_eq!(continuation, GuestAddress(BASE + 8));
    assert!(
        validate_terminal_word(
            GuestAddress(BASE),
            GuestAddress(BASE + 4),
            bytes.len(),
            BASE,
            &bytes
        )
        .is_err()
    );
}

#[test]
fn metadata_cannot_authorize_outside_reserved_or_nonnumerical_words() {
    let bytes = source(&[NOP, FADD_S, RET]);
    for (entry, exit, count, region) in [
        (BASE, BASE - 4, 12, BASE),
        (BASE, BASE + 12, 12, BASE),
        (BASE, BASE + 5, 12, BASE),
        (BASE + 1, BASE + 4, 12, BASE),
        (BASE, BASE + 4, 0, BASE),
        (BASE, BASE + 4, 10, BASE),
        (BASE, BASE + 4, 16, BASE),
        (BASE, BASE + 4, 12, BASE + 4),
        (BASE, BASE, 12, BASE),
        (BASE, BASE + 8, 12, BASE),
    ] {
        assert!(
            validate_numerical_exit(
                GuestAddress(entry),
                GuestAddress(exit),
                count,
                region,
                &bytes
            )
            .is_err()
        );
    }
    let reserved = source(&[FADD_S | (2 << 22)]);
    assert!(
        validate_numerical_exit(GuestAddress(BASE), GuestAddress(BASE), 4, BASE, &reserved)
            .is_err()
    );
    assert!(
        validate_numerical_exit(
            GuestAddress(u64::MAX - 3),
            GuestAddress(u64::MAX - 3),
            4,
            u64::MAX - 3,
            &source(&[FADD_S])
        )
        .is_err()
    );
}
