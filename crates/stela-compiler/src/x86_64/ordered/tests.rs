use super::*;

#[test]
fn only_potentially_crossing_loads_require_atomic_load16() {
    for kind in [Kind::Acquire, Kind::Release, Kind::AcquirePc] {
        for bytes in [BYTE_BYTES, HALFWORD_BYTES, DWORD_BYTES, QWORD_BYTES] {
            for base in [Register::X(0), Register::X(30), Register::Sp] {
                let operand = Operand::Transfer {
                    kind,
                    bytes,
                    data: Register::Zero,
                    base,
                    displacement: 0,
                    extension: LoadExtension::Zero,
                };
                assert_eq!(
                    requires_atomic_load16(&operand),
                    kind != Kind::Release && bytes != BYTE_BYTES && base != Register::Sp
                );
            }
        }
    }
    for bytes in [HALFWORD_BYTES, DWORD_BYTES, QWORD_BYTES] {
        for displacement in -256..=255 {
            let operand = Operand::Transfer {
                kind: Kind::AcquirePc,
                bytes,
                data: Register::X(0),
                base: Register::Sp,
                displacement,
                extension: LoadExtension::Sign(Width::X64),
            };
            let effective = (256 + displacement) as usize;
            let last = effective + usize::from(bytes) - 1;
            let inside_quantity = effective / 16 == last / 16;
            let crosses_baseline = effective / 8 != last / 8;
            assert_eq!(
                requires_atomic_load16(&operand),
                inside_quantity && crosses_baseline
            );
        }
    }
    assert!(!requires_atomic_load16(&Operand::Barrier {
        option: 15,
        requirement: Barrier::All,
    }));
}
