use super::*;
use alloc::vec::Vec;

#[test]
fn scoped_qword_encodings_keep_rex_operand_roles_and_state_base() {
    let mut code = Vec::new();
    QwordOpcode::Move.emit(&mut code, Gpr::R10, Gpr::Rdx);
    QwordOpcode::And.emit(&mut code, Gpr::R10, Gpr::R9);
    rotate(&mut code, Gpr::R11, 23);
    state_qword(&mut code, 31, HIGH, Gpr::R9, true);
    state_qword(&mut code, 31, LOW, Gpr::R10, false);
    let high = (vector_offset(31) + QWORD_BYTES).to_le_bytes();
    let low = vector_offset(31).to_le_bytes();
    assert_eq!(
        code,
        [
            &[0x49, 0x89, 0xd2][..], // mov r10,rdx
            &[0x4d, 0x21, 0xca],     // and r10,r9
            &[0x49, 0xc1, 0xcb, 23], // ror r11,23
            &[0x4c, 0x8b, 0x8f],
            &high,
            &[0x4c, 0x89, 0x97],
            &low,
        ]
        .concat()
    );
}
