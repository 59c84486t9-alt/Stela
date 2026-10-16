use super::*;

mod fp8_matrix_scope;
mod numerical22_scope;
mod sme_matrix;

const FADD_Z0_S_P0_Z0_Z0: u32 = 0x6580_8000;
const NOP: u32 = 0xd503_201f;

#[test]
fn numerical_boundary_keeps_exact_source_identity() {
    let pc = GuestAddress(0x1000);
    let instruction = decode_scalable_numerical_instruction(pc, FADD_Z0_S_P0_Z0_Z0)
        .unwrap()
        .expect("allocated floating add");
    assert_eq!(instruction.instruction_pc, pc);
    assert_eq!(instruction.next_pc, GuestAddress(0x1004));
    assert_eq!(instruction.word, FADD_Z0_S_P0_Z0_Z0);
    assert!(matches!(
        instruction.operation,
        ScalableNumericalOperation::Sve(_)
    ));
    assert!(
        decode_scalable_numerical_instruction(pc, NOP)
            .unwrap()
            .is_none()
    );
    assert!(decode_scalable_numerical_instruction(GuestAddress(2), NOP).is_err());
    assert!(
        decode_scalable_numerical_instruction(GuestAddress(u64::MAX - 3), FADD_Z0_S_P0_Z0_Z0)
            .is_err()
    );
}
