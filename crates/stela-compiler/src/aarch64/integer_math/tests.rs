use super::*;

#[test]
fn scalar_shifts_and_extract_validate_width_immediates_and_zero_roles() {
    for (sf, width) in [(0, Width::W32), (1u32 << 31, Width::X64)] {
        for (op, shift) in [Shift::Lsl, Shift::Lsr, Shift::Asr, Shift::Ror]
            .into_iter()
            .enumerate()
        {
            let base = sf | 0x1ac02000 | ((op as u32) << 10);
            let operand = decode(base | (31 << 16) | (31 << 5) | 31).unwrap().unwrap();
            assert_eq!(operand.kind, Kind::VariableShift { width, shift });
            assert_eq!(
                (operand.destination, operand.left, operand.right),
                (Register::Zero, Register::Zero, Register::Zero)
            );
            for bit in 0..32 {
                if 0x7fe0f000 & (1 << bit) != 0 {
                    assert!(!matches!(
                        decode(base ^ (1 << bit)),
                        Some(Ok(Operand {
                            kind: Kind::VariableShift { .. },
                            ..
                        }))
                    ));
                }
            }
        }
        let base = if width == Width::X64 {
            0x93c00000
        } else {
            0x13800000
        };
        for amount in 0..64 {
            let decoded = decode(base | (amount << 10) | (31 << 16) | (31 << 5) | 31).unwrap();
            if width == Width::W32 && amount >= 32 {
                assert_eq!(decoded, Err(()));
            } else {
                let operand = decoded.unwrap();
                assert_eq!(
                    operand.kind,
                    Kind::Extract {
                        width,
                        amount: amount as u8
                    }
                );
                assert_eq!(
                    (operand.destination, operand.left, operand.right),
                    (Register::Zero, Register::Zero, Register::Zero)
                );
            }
        }
        assert_eq!(decode(base ^ (1 << 22)), Some(Err(()))); // N must match sf.
        assert!(decode(base | (1 << 21)).is_none()); // fixed o0
    }
}

#[test]
fn unary_forms_use_exact_fixed_bits_and_zero_register_roles() {
    let forms = [
        (0x5ac01000, Kind::LeadingZeros { width: Width::W32 }),
        (0xdac01000, Kind::LeadingZeros { width: Width::X64 }),
        (0x5ac01400, Kind::LeadingSignBits { width: Width::W32 }),
        (0xdac01400, Kind::LeadingSignBits { width: Width::X64 }),
        (0x5ac00000, Kind::ReverseBits { width: Width::W32 }),
        (0xdac00000, Kind::ReverseBits { width: Width::X64 }),
        (
            0x5ac00800,
            Kind::ReverseBytes {
                width: Width::W32,
                group_bytes: 4,
            },
        ),
        (
            0x5ac00400,
            Kind::ReverseBytes {
                width: Width::W32,
                group_bytes: 2,
            },
        ),
        (
            0xdac00c00,
            Kind::ReverseBytes {
                width: Width::X64,
                group_bytes: 8,
            },
        ),
        (
            0xdac00800,
            Kind::ReverseBytes {
                width: Width::X64,
                group_bytes: 4,
            },
        ),
        (
            0xdac00400,
            Kind::ReverseBytes {
                width: Width::X64,
                group_bytes: 2,
            },
        ),
    ];
    for (base, kind) in forms {
        for destination in 0..32 {
            for source in 0..32 {
                let operand = decode(base | (source << 5) | destination).unwrap().unwrap();
                assert_eq!(operand.kind, kind);
                assert_eq!(operand.destination, register(destination, false));
                assert_eq!(operand.left, register(source, false));
                assert_eq!(operand.right, Register::Zero);
                assert_eq!(operand.accumulator, Register::Zero);
            }
        }
        for bit in 10..32 {
            if let Some(Ok(neighbor)) = decode(base ^ (1 << bit)) {
                assert_ne!(neighbor.kind, kind, "{base:08x} bit {bit}");
            }
        }
    }
    // W32 REV with the X64-only opcode and reserved one-source neighbors.
    for word in [0x5ac00c00, 0x5ac01800, 0xdac01800, 0x5ac02000, 0xdac02000] {
        assert!(decode(word).is_none(), "{word:08x}");
    }
}

#[test]
fn division_fixed_bits_width_and_zero_roles_are_exact() {
    for (base, signed) in [(0x1ac00800, false), (0x1ac00c00, true)] {
        for (sf, width) in [(0, Width::W32), (1u32 << 31, Width::X64)] {
            let word = base | sf | (31 << 16) | (31 << 5) | 31;
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(operand.kind, Kind::Divide { signed, width });
            assert_eq!(operand.destination, Register::Zero);
            assert_eq!(operand.left, Register::Zero);
            assert_eq!(operand.right, Register::Zero);
            assert_eq!(operand.accumulator, Register::Zero);
            for bit in [11, 12, 13, 14, 15, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30] {
                // A neighboring encoding can be a different valid integer
                // operation (for example UMULH), but never another divide.
                if let Some(Ok(neighbor)) = decode(word ^ (1 << bit)) {
                    assert!(
                        !matches!(neighbor.kind, Kind::Divide { .. }),
                        "{word:08x} bit {bit}"
                    );
                }
            }
        }
    }
}

#[test]
fn opcode_space_and_reserved_neighbors_are_explicit() {
    for sf in 0..2 {
        for opcode in 0..8 {
            for subtract in 0..2 {
                let word = 0x1b000000 | (sf << 31) | (opcode << 21) | (subtract << 15);
                let valid = opcode == 0
                    || (sf == 1
                        && (opcode == 1
                            || opcode == 5
                            || (subtract == 0 && (opcode == 2 || opcode == 6))));
                assert_eq!(decode(word).unwrap().is_ok(), valid, "{word:08x}");
            }
        }
    }
    for bit in 24..31 {
        assert!(decode(0x9b007c00 ^ (1 << bit)).is_none());
    }
}

#[test]
fn every_operand_uses_zero_instead_of_sp() {
    let operand = decode(0x9b000000 | (31 << 16) | (31 << 10) | (31 << 5) | 31)
        .unwrap()
        .unwrap();
    assert_eq!(operand.destination, Register::Zero);
    assert_eq!(operand.left, Register::Zero);
    assert_eq!(operand.right, Register::Zero);
    assert_eq!(operand.accumulator, Register::Zero);
}

#[test]
fn high_product_ignores_all_accumulator_encodings() {
    for signed in [false, true] {
        for accumulator in 0..32 {
            let word = (if signed { 0x9b400000 } else { 0x9bc00000 }) | (accumulator << 10);
            let operand = decode(word).unwrap().unwrap();
            assert_eq!(operand.kind, Kind::High { signed });
            assert_eq!(operand.accumulator, Register::Zero);
        }
    }
}
