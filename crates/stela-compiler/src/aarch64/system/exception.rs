//! Exception generation and return: SVC, HVC, SMC, BRK, HLT, ERET and variants.

const EXCEPTION_CLASS_MASK: u32 = 0xffe0_001f;
const SVC_ENCODING: u32 = 0xd400_0001;
const HVC_ENCODING: u32 = 0xd400_0002;
const SMC_ENCODING: u32 = 0xd400_0003;
const BRK_ENCODING: u32 = 0xd420_0000;
const HLT_ENCODING: u32 = 0xd440_0000;
const DCPS1_ENCODING: u32 = 0xd4a0_0001;
const DCPS2_ENCODING: u32 = 0xd4a0_0002;
const DCPS3_ENCODING: u32 = 0xd4a0_0003;
const ERET_ENCODING: u32 = 0xd69f_03e0;
const ERETAA_ENCODING: u32 = 0xd69f_0bff;
const ERETAB_ENCODING: u32 = 0xd69f_0fff;
const DRPS_ENCODING: u32 = 0xd6bf_03e0;
const UDF_CLASS_MASK: u32 = 0xffff_0000;
const UDF_ENCODING: u32 = 0x0000_0000;
const COMMENT_SHIFT: u32 = 5;
const COMMENT_MASK: u32 = u16::MAX as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugTarget {
    El1,
    El2,
    El3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationKey {
    A,
    B,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    SupervisorCall {
        immediate: u16,
    },
    HypervisorCall {
        immediate: u16,
    },
    SecureMonitorCall {
        immediate: u16,
    },
    SoftwareBreakpoint {
        immediate: u16,
    },
    Halt {
        immediate: u16,
    },
    DebugChange {
        target: DebugTarget,
        immediate: u16,
    },
    DebugReturn,
    ExceptionReturn {
        key: Option<AuthenticationKey>,
    },
    /// Hardware ignores the immediate; retaining it identifies the source.
    Undefined {
        immediate: u16,
    },
}

pub fn decode(word: u32) -> Option<Operation> {
    let immediate = ((word >> COMMENT_SHIFT) & COMMENT_MASK) as u16;
    let exception = match word & EXCEPTION_CLASS_MASK {
        SVC_ENCODING => Operation::SupervisorCall { immediate },
        HVC_ENCODING => Operation::HypervisorCall { immediate },
        SMC_ENCODING => Operation::SecureMonitorCall { immediate },
        BRK_ENCODING => Operation::SoftwareBreakpoint { immediate },
        HLT_ENCODING => Operation::Halt { immediate },
        DCPS1_ENCODING => Operation::DebugChange {
            target: DebugTarget::El1,
            immediate,
        },
        DCPS2_ENCODING => Operation::DebugChange {
            target: DebugTarget::El2,
            immediate,
        },
        DCPS3_ENCODING => Operation::DebugChange {
            target: DebugTarget::El3,
            immediate,
        },
        _ => {
            return match word {
                ERET_ENCODING => Some(Operation::ExceptionReturn { key: None }),
                ERETAA_ENCODING => Some(Operation::ExceptionReturn {
                    key: Some(AuthenticationKey::A),
                }),
                ERETAB_ENCODING => Some(Operation::ExceptionReturn {
                    key: Some(AuthenticationKey::B),
                }),
                DRPS_ENCODING => Some(Operation::DebugReturn),
                _ if word & UDF_CLASS_MASK == UDF_ENCODING => Some(Operation::Undefined {
                    immediate: (word & COMMENT_MASK) as u16,
                }),
                _ => None,
            };
        }
    };
    Some(exception)
}

#[cfg(test)]
mod tests {
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
}
