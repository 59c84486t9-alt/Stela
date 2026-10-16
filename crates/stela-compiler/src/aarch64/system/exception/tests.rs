use super::*;

#[test]
fn immediate_operations_preserve_all_comment_bits() {
    for immediate in [0, 1, 0x80, 0x8000, u16::MAX] {
        let encoded = u32::from(immediate) << COMMENT_SHIFT;
        for (encoding, expected) in [
            (SVC_ENCODING, Operation::SupervisorCall { immediate }),
            (HVC_ENCODING, Operation::HypervisorCall { immediate }),
            (SMC_ENCODING, Operation::SecureMonitorCall { immediate }),
            (BRK_ENCODING, Operation::SoftwareBreakpoint { immediate }),
            (HLT_ENCODING, Operation::Halt { immediate }),
            (
                DCPS1_ENCODING,
                Operation::DebugChange {
                    target: DebugTarget::El1,
                    immediate,
                },
            ),
            (
                DCPS2_ENCODING,
                Operation::DebugChange {
                    target: DebugTarget::El2,
                    immediate,
                },
            ),
            (
                DCPS3_ENCODING,
                Operation::DebugChange {
                    target: DebugTarget::El3,
                    immediate,
                },
            ),
        ] {
            assert_eq!(decode(encoding | encoded), Some(expected));
        }
        assert_eq!(
            decode(u32::from(immediate)),
            Some(Operation::Undefined { immediate })
        );
    }
}

#[test]
fn returns_require_exact_fixed_operands() {
    for (encoding, expected) in [
        (ERET_ENCODING, Operation::ExceptionReturn { key: None }),
        (
            ERETAA_ENCODING,
            Operation::ExceptionReturn {
                key: Some(AuthenticationKey::A),
            },
        ),
        (
            ERETAB_ENCODING,
            Operation::ExceptionReturn {
                key: Some(AuthenticationKey::B),
            },
        ),
        (DRPS_ENCODING, Operation::DebugReturn),
    ] {
        assert_eq!(decode(encoding), Some(expected));
        for bit in 0..u32::BITS {
            let changed = encoding ^ (1 << bit);
            if ![
                ERET_ENCODING,
                ERETAA_ENCODING,
                ERETAB_ENCODING,
                DRPS_ENCODING,
            ]
            .contains(&changed)
            {
                assert_eq!(decode(changed), None, "reserved neighbor {changed:#010x}");
            }
        }
    }
}

#[test]
fn unrelated_system_and_reserved_exception_classes_decline() {
    for word in [
        0xd400_0000,
        0xd400_0004,
        0xd420_0001,
        0xd440_0001,
        0xd4a0_0000,
        0xd4a0_0004,
        0xd503_201f,
        0xd503_3fdf,
        0xd53b_4200,
        0x0001_0000,
    ] {
        assert_eq!(decode(word), None, "neighbor {word:#010x}");
    }
}
