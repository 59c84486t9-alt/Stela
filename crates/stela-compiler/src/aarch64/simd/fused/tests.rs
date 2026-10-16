use super::*;

const FORMAT_RESERVED: u32 = 2;
const INDEXED_REGISTER_HIGH_SHIFT: u32 = 4;
const SCALAR_OPERATION_MASK: u32 = 0x00208000;
const INDEXED_HALF_SINGLE_BIT: u32 = 1 << 23;
const INDEXED_SCALAR_VECTOR_BIT: u32 = 1 << 28;
const VECTOR_OPERATION_MASK: u32 = 1 << 23;
const SCALAR_OPERATIONS: [(u32, FusedOperation); 4] = [
    (FMADD, FusedOperation::Add),
    (FMSUB, FusedOperation::Subtract),
    (FNMADD, FusedOperation::NegatedAdd),
    (FNMSUB, FusedOperation::NegatedSubtract),
];

#[test]
fn scalar_formats_and_all_register_roles_are_explicit() {
    for (encoding, operation) in SCALAR_OPERATIONS {
        for (format_field, format) in [
            (FORMAT_SINGLE, Some(Format::Single)),
            (FORMAT_DOUBLE, Some(Format::Double)),
            (FORMAT_HALF, Some(Format::Half)),
            (FORMAT_RESERVED, None),
        ] {
            for destination in 0..=REGISTER_MASK {
                for left in 0..=REGISTER_MASK {
                    for right in 0..=REGISTER_MASK {
                        // Every addend value and alias occurs across the field matrix.
                        let addend = destination ^ left ^ right;
                        let word = encoding
                            | (format_field << FORMAT_SHIFT)
                            | (right << RIGHT_SHIFT)
                            | (addend << ADDEND_SHIFT)
                            | (left << LEFT_SHIFT)
                            | destination;
                        let expected = format.map_or(Err(()), |format| {
                            Ok(Operand {
                                operation,
                                format,
                                shape: Shape::Scalar,
                                destination: destination as u8,
                                addend: addend as u8,
                                left: left as u8,
                                right: right as u8,
                                right_lane: None,
                            })
                        });
                        assert_eq!(decode(word), Some(expected));
                    }
                }
            }
        }
    }
}

#[test]
fn vector_formats_shapes_and_registers_are_explicit() {
    for (ordinary, half, operation) in [
        (VECTOR_FMLA, VECTOR_HALF_FMLA, FusedOperation::Add),
        (VECTOR_FMLS, VECTOR_HALF_FMLS, FusedOperation::Subtract),
    ] {
        for (encoding, format, size) in [
            (ordinary, Format::Single, 0),
            (ordinary, Format::Double, VECTOR_DOUBLE),
            (half, Format::Half, 0),
        ] {
            for (q, shape) in [(0, Shape::Vector64), (VECTOR_Q, Shape::Vector128)] {
                for destination in 0..=REGISTER_MASK {
                    for left in 0..=REGISTER_MASK {
                        for right in 0..=REGISTER_MASK {
                            let word = encoding
                                | size
                                | q
                                | (right << RIGHT_SHIFT)
                                | (left << LEFT_SHIFT)
                                | destination;
                            let expected = if format == Format::Double && shape == Shape::Vector64 {
                                Err(())
                            } else {
                                Ok(Operand {
                                    operation,
                                    format,
                                    shape,
                                    destination: destination as u8,
                                    addend: destination as u8,
                                    left: left as u8,
                                    right: right as u8,
                                    right_lane: None,
                                })
                            };
                            assert_eq!(decode(word), Some(expected));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn indexed_lanes_register_widths_and_reserved_fields_are_explicit() {
    for (scalar, half, encoding) in [
        (true, true, INDEXED_SCALAR_HALF),
        (true, false, INDEXED_SCALAR),
        (false, true, INDEXED_VECTOR_HALF),
        (false, false, INDEXED_VECTOR),
    ] {
        for (subtract, operation) in [
            (0, FusedOperation::Add),
            (INDEXED_SUBTRACT, FusedOperation::Subtract),
        ] {
            for q in [0, VECTOR_Q] {
                if scalar && q == 0 {
                    continue;
                }
                let shape = if scalar {
                    Shape::Scalar
                } else if q == 0 {
                    Shape::Vector64
                } else {
                    Shape::Vector128
                };
                for double in [0, VECTOR_DOUBLE] {
                    if half && double != 0 {
                        continue;
                    }
                    let format = if half {
                        Format::Half
                    } else if double == 0 {
                        Format::Single
                    } else {
                        Format::Double
                    };
                    for h in 0..=INDEX_BIT_MASK {
                        for l in 0..=INDEX_BIT_MASK {
                            for m in 0..=INDEX_BIT_MASK {
                                for rm in 0..=INDEXED_HALF_REGISTER_MASK {
                                    for destination in 0..=REGISTER_MASK {
                                        for left in 0..=REGISTER_MASK {
                                            let word = encoding
                                                | subtract
                                                | q
                                                | double
                                                | (h << INDEX_H_SHIFT)
                                                | (l << INDEX_L_SHIFT)
                                                | (m << INDEX_M_SHIFT)
                                                | (rm << RIGHT_SHIFT)
                                                | (left << LEFT_SHIFT)
                                                | destination;
                                            let expected = if format == Format::Double
                                                && (l != 0 || shape == Shape::Vector64)
                                            {
                                                Err(())
                                            } else {
                                                Ok(Operand {
                                                    operation,
                                                    format,
                                                    shape,
                                                    destination: destination as u8,
                                                    addend: destination as u8,
                                                    left: left as u8,
                                                    right: if half {
                                                        rm
                                                    } else {
                                                        (m << INDEXED_REGISTER_HIGH_SHIFT) | rm
                                                    }
                                                        as u8,
                                                    right_lane: Some(match format {
                                                        Format::Half => {
                                                            (h << HALF_LANE_HIGH_SHIFT)
                                                                | (l << HALF_LANE_LOW_SHIFT)
                                                                | m
                                                        }
                                                        Format::Single => {
                                                            (h << SINGLE_LANE_HIGH_SHIFT) | l
                                                        }
                                                        Format::Double => h,
                                                    }
                                                        as u8),
                                                })
                                            };
                                            assert_eq!(decode(word), Some(expected));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn fixed_bits_and_neighboring_families_do_not_alias() {
    for (encoding, mask) in [
        (FMADD, SCALAR_MASK & !SCALAR_OPERATION_MASK),
        (VECTOR_FMLA, VECTOR_MASK & !VECTOR_OPERATION_MASK),
        (VECTOR_HALF_FMLA, VECTOR_HALF_MASK & !VECTOR_OPERATION_MASK),
        (INDEXED_SCALAR_HALF, INDEXED_SCALAR_HALF_MASK),
        (INDEXED_SCALAR, INDEXED_SCALAR_MASK),
        (INDEXED_VECTOR_HALF, INDEXED_VECTOR_HALF_MASK),
        (INDEXED_VECTOR, INDEXED_VECTOR_MASK),
    ] {
        for bit in 0..u32::BITS {
            let changed_bit = 1 << bit;
            if mask & changed_bit != 0 {
                let changed = encoding ^ changed_bit;
                let indexed = matches!(
                    encoding,
                    INDEXED_SCALAR_HALF | INDEXED_SCALAR | INDEXED_VECTOR_HALF | INDEXED_VECTOR
                );
                let scalar_indexed = matches!(encoding, INDEXED_SCALAR_HALF | INDEXED_SCALAR);
                let crosses_family = indexed
                    && (changed_bit == INDEXED_HALF_SINGLE_BIT
                        || changed_bit == INDEXED_SCALAR_VECTOR_BIT
                        || (scalar_indexed && changed_bit == VECTOR_Q));
                if crosses_family {
                    // These changes enter another fused encoding or reserved ftype.
                    assert!(decode(changed).is_some(), "{changed:08x}");
                } else {
                    assert_eq!(decode(changed), None, "{changed:08x}");
                }
            }
        }
    }
    for neighbor in [
        0x1e200800, // FMUL S
        0x1e208800, // FNMUL S
        0x0e20d400, // FADD vector
        0x2e20dc00, // FMUL vector
        0x0e20ec00, // FMLAL vector
        0x0f800000, // FMLAL indexed
        0x0f809000, // FMUL indexed
        0x2f809000, // FMULX indexed
        0x0f00c000, // SQDMULH indexed
    ] {
        assert_eq!(decode(neighbor), None, "{neighbor:08x}");
    }
}
