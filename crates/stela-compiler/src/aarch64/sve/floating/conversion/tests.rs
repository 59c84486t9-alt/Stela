use super::*;

#[test]
fn selected_integer_forms_use_complete_max_width_slots() {
    for (opcode, source_bits, destination_bits) in [
        (SCVTF_Z_P_Z_W2S, 32, 32),
        (SCVTF_Z_P_Z_W2D, 32, 64),
        (SCVTF_Z_P_Z_X2S, 64, 32),
        (SCVTF_Z_P_Z_X2D, 64, 64),
        (UCVTF_Z_P_Z_W2S, 32, 32),
        (UCVTF_Z_P_Z_W2D, 32, 64),
        (FCVTZS_Z_P_Z_S2W, 32, 32),
        (FCVTZS_Z_P_Z_S2X, 32, 64),
        (FCVTZS_Z_P_Z_D2W, 64, 32),
        (FCVTZS_Z_P_Z_D2X, 64, 64),
        (FCVTZU_Z_P_Z_S2W, 32, 32),
        (FCVTZU_Z_P_Z_D2W, 64, 32),
    ] {
        let word = opcode
            | REGISTER_MASK
            | (REGISTER_MASK << SOURCE_SHIFT)
            | (GOVERNING_MASK << GOVERNING_SHIFT);
        let operand = decode(word).unwrap().unwrap();
        assert_eq!(
            (operand.destination, operand.source, operand.governing),
            (31, 31, 7)
        );
        assert_eq!(operand.kind.source_bits(), source_bits);
        assert_eq!(operand.kind.destination_bits(), destination_bits);
        let slot_bytes = (source_bits.max(destination_bits) / BITS_PER_BYTE) as u8;
        assert_eq!(operand.kind.slot_bytes(), slot_bytes);
        assert_eq!(operand.kind.written_bytes(), slot_bytes);
        assert_eq!(operand.kind.source_offset(), 0);
        assert_eq!(operand.kind.destination_offset(), 0);
    }
}
