use super::*;

#[test]
fn all_fixed_arrangements_and_register_aliases_decode() {
    for base in [BF1CVTL, BF2CVTL, F1CVTL, F2CVTL, FCVTN_HALF, FCVTN_SINGLE] {
        for q in [0, Q] {
            for register in 0..32 {
                let fields = register
                    | register << SOURCE_SHIFT
                    | if matches!(base, FCVTN_HALF | FCVTN_SINGLE) {
                        register << SECOND_SOURCE_SHIFT
                    } else {
                        0
                    };
                let operand = decode(base | q | fields).unwrap();
                assert_eq!(operand.destination, register as u8);
                assert_eq!(operand.source, register as u8);
            }
        }
    }
}

#[test]
fn allocated_neighbors_are_not_claimed() {
    for word in [
        0x0e21_6800,
        0x0ea1_6800,
        0x1e63_4000,
        0x0fc0_0000,
        0x2e21_7000,
    ] {
        assert_eq!(decode(word), None);
    }
}
