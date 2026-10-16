//! Translation-control system-register access decisions, before backend effects.
//!
//! Source: Arm A-profile SysReg June 2026 SCTLR_EL1, TCR_EL1, TTBR0/1_EL1,
//! MAIR_EL1, AMAIR_EL1, PAR_EL1, CONTEXTIDR_EL1 and VBAR_EL1 pages.
//! Readbacks belong to the architectural backend. This module does not invent
//! reset values, interpret RES0/RES1 as write-ignore, or simulate an MMU with a
//! register bank. TCR/TTBR field interpretation needs the selected CPU profile.

use super::access::{
    AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, SecurityState,
};

const SYSTEM_REGISTER_OP0: u8 = 0b11;
const EL1_REGISTER_OP1: u8 = 0b000;
const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    SctlrEl1,
    TcrEl1,
    Ttbr0El1,
    Ttbr1El1,
    MairEl1,
    AmairEl1,
    ParEl1,
    ContextidrEl1,
    VbarEl1,
}

impl Register {
    pub const ALL: [Self; 9] = [
        Self::SctlrEl1,
        Self::TcrEl1,
        Self::Ttbr0El1,
        Self::Ttbr1El1,
        Self::MairEl1,
        Self::AmairEl1,
        Self::ParEl1,
        Self::ContextidrEl1,
        Self::VbarEl1,
    ];

    pub const fn encoding(self) -> Encoding {
        let (crn, crm, op2) = match self {
            Self::SctlrEl1 => return stela_compiler::aarch64::system::registers::SCTLR_EL1,
            Self::TcrEl1 => return stela_compiler::aarch64::system::registers::TCR_EL1,
            Self::Ttbr0El1 => return stela_compiler::aarch64::system::registers::TTBR0_EL1,
            Self::Ttbr1El1 => return stela_compiler::aarch64::system::registers::TTBR1_EL1,
            Self::MairEl1 => return stela_compiler::aarch64::system::registers::MAIR_EL1,
            Self::AmairEl1 => (0b1010, 0b0011, 0b000),
            Self::ParEl1 => (0b0111, 0b0100, 0b000),
            Self::ContextidrEl1 => (0b1101, 0b0000, 0b001),
            Self::VbarEl1 => (0b1100, 0b0000, 0b000),
        };
        Encoding::new(SYSTEM_REGISTER_OP0, EL1_REGISTER_OP1, crn, crm, op2)
    }

    pub fn decode(encoding: Encoding) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|register| register.encoding() == encoding)
    }

    pub const fn effect(self) -> Effect {
        match self {
            Self::SctlrEl1 => Effect::ExecutionAndTranslationControl,
            Self::TcrEl1 => Effect::TranslationConfiguration,
            Self::Ttbr0El1 | Self::Ttbr1El1 => Effect::TranslationTableAndAsid,
            Self::MairEl1 => Effect::MemoryAttributes,
            Self::AmairEl1 => Effect::ImplementationDefinedMemoryAttributes,
            Self::ParEl1 => Effect::AddressTranslationResult,
            Self::ContextidrEl1 => Effect::TraceContext,
            Self::VbarEl1 => Effect::ExceptionVectorBase,
        }
    }
}

/// Exact backend-provided architectural readbacks, not reset defaults.
/// None means that this decision layer cannot supply a truthful value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readbacks {
    pub sctlr_el1: Option<u64>,
    pub tcr_el1: Option<u64>,
    pub ttbr0_el1: Option<u64>,
    pub ttbr1_el1: Option<u64>,
    pub mair_el1: Option<u64>,
    pub amair_el1: Option<u64>,
    pub par_el1: Option<u64>,
    pub contextidr_el1: Option<u64>,
    pub vbar_el1: Option<u64>,
}

impl Readbacks {
    pub const fn get(self, register: Register) -> Option<u64> {
        match register {
            Register::SctlrEl1 => self.sctlr_el1,
            Register::TcrEl1 => self.tcr_el1,
            Register::Ttbr0El1 => self.ttbr0_el1,
            Register::Ttbr1El1 => self.ttbr1_el1,
            Register::MairEl1 => self.mair_el1,
            Register::AmairEl1 => self.amair_el1,
            Register::ParEl1 => self.par_el1,
            Register::ContextidrEl1 => self.contextidr_el1,
            Register::VbarEl1 => self.vbar_el1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub aa64: bool,
    pub readbacks: Readbacks,
}

/// A responsibility classification, not an instruction to flush every TLB.
/// The backend must apply the actual architectural synchronization rules and
/// may retain stale cached translations exactly where the architecture permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    ExecutionAndTranslationControl,
    TranslationConfiguration,
    TranslationTableAndAsid,
    MemoryAttributes,
    ImplementationDefinedMemoryAttributes,
    AddressTranslationResult,
    TraceContext,
    ExceptionVectorBase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    /// Raw Xt. Feature-dependent reserved fields and implementation choices are
    /// backend policy; no blanket RES0/RES1 normalization occurs here.
    Write {
        value: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendRequest {
    pub register: Register,
    pub operation: Operation,
    pub effect: Effect,
}

/// `NotHandled` is a family dispatch miss. The full allocation owner decides
/// whether the selector is unsupported or architecturally unallocated.
/// No state changes occur here. Even same-value control writes require the
/// owning backend. MRS Xt==XZR still performs access checks and obtains the
/// register value; destination discard belongs to the shared instruction owner.
pub fn resolve(request: Request, context: &Context) -> Resolution<BackendRequest> {
    let Some(register) = Register::decode(request.encoding) else {
        return Resolution::NotHandled;
    };
    if request.rt > ZERO_REGISTER {
        return Resolution::Unsupported("system-register Rt exceeds five-bit encoding");
    }
    if !context.aa64 || context.profile.current_el == ExceptionLevel::El0 {
        return Resolution::Undefined;
    }
    if context.profile.security != SecurityState::NonSecure {
        return Resolution::Unsupported("translation-register security-state access path");
    }
    if context.profile.current_el != ExceptionLevel::El1 {
        return Resolution::Unsupported("translation-register EL2/EL3 access path");
    }
    if context.profile.el2_enabled || context.profile.el3_present {
        return Resolution::Unsupported(
            "translation-register EL2 traps, nested redirection and EL3 controls",
        );
    }
    let operation = match request.kind {
        AccessKind::Read => {
            if let Some(value) = context.readbacks.get(register) {
                return Resolution::Read(value);
            }
            Operation::Read
        }
        AccessKind::Write { .. } => Operation::Write {
            value: request
                .write_value()
                .expect("write request has a source value"),
        },
    };
    Resolution::BackendRequired(BackendRequest {
        register,
        operation,
        effect: register.effect(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::access::*;
    use super::*;

    fn context() -> Context {
        Context {
            profile: Profile {
                current_el: ExceptionLevel::El1,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            aa64: true,
            readbacks: Readbacks {
                sctlr_el1: Some(0x3060_0981),
                tcr_el1: Some(0x5008_03519),
                ttbr0_el1: Some(0x4001_0000),
                ttbr1_el1: Some(0xabcd_0000_4010_0000),
                mair_el1: Some(0xff),
                amair_el1: Some(0x0123_4567_89ab_cdef),
                par_el1: Some(0x800),
                contextidr_el1: Some(0xfedc_ba98),
                vbar_el1: Some(0x4008_1000),
            },
        }
    }

    #[test]
    fn exact_selectors_match_official_pages_and_do_not_alias() {
        let official = [
            (3, 0, 1, 0, 0),
            (3, 0, 2, 0, 2),
            (3, 0, 2, 0, 0),
            (3, 0, 2, 0, 1),
            (3, 0, 10, 2, 0),
            (3, 0, 10, 3, 0),
            (3, 0, 7, 4, 0),
            (3, 0, 13, 0, 1),
            (3, 0, 12, 0, 0),
        ];
        for (register, (op0, op1, crn, crm, op2)) in Register::ALL.into_iter().zip(official) {
            let encoding = Encoding::new(op0, op1, crn, crm, op2);
            assert_eq!(register.encoding(), encoding);
            assert_eq!(Register::decode(encoding), Some(register));
        }
        let mut recognized = 0;
        for op0 in 0..4 {
            for op1 in 0..8 {
                for crn in 0..16 {
                    for crm in 0..16 {
                        for op2 in 0..8 {
                            let encoding = Encoding::new(op0, op1, crn, crm, op2);
                            if Register::decode(encoding).is_some() {
                                recognized += 1;
                            } else {
                                assert_eq!(
                                    resolve(Request::read(encoding, 0), &context()),
                                    Resolution::NotHandled
                                );
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(recognized, Register::ALL.len());
    }

    #[test]
    fn reads_preserve_explicit_values_for_every_destination_including_xzr() {
        let original = context();
        for register in Register::ALL {
            for rt in 0..32 {
                assert_eq!(
                    resolve(Request::read(register.encoding(), rt), &original),
                    Resolution::Read(original.readbacks.get(register).unwrap())
                );
            }
        }
        assert_eq!(original, context());
    }

    #[test]
    fn every_write_requires_backend_without_mutation_or_reserved_bit_masking() {
        let context = context();
        let before = context;
        for register in Register::ALL {
            for rt in 0..32 {
                for value in [0, 1, u64::MAX, 0x0123_4567_89ab_cdef] {
                    let expected = if rt == 31 { 0 } else { value };
                    assert_eq!(
                        resolve(Request::write(register.encoding(), rt, value), &context),
                        Resolution::BackendRequired(BackendRequest {
                            register,
                            operation: Operation::Write { value: expected },
                            effect: register.effect(),
                        })
                    );
                }
            }
        }
        assert_eq!(context, before);
    }

    #[test]
    fn absent_readbacks_request_real_backend_even_for_xzr() {
        let mut context = context();
        context.readbacks = Readbacks {
            sctlr_el1: None,
            tcr_el1: None,
            ttbr0_el1: None,
            ttbr1_el1: None,
            mair_el1: None,
            amair_el1: None,
            par_el1: None,
            contextidr_el1: None,
            vbar_el1: None,
        };
        for register in Register::ALL {
            for rt in [0, 31] {
                assert_eq!(
                    resolve(Request::read(register.encoding(), rt), &context),
                    Resolution::BackendRequired(BackendRequest {
                        register,
                        operation: Operation::Read,
                        effect: register.effect(),
                    })
                );
            }
        }
    }

    #[test]
    fn el0_is_undefined_before_hypervisor_controls_for_both_directions() {
        for register in Register::ALL {
            for el2_enabled in [false, true] {
                for el3_present in [false, true] {
                    let mut context = context();
                    context.profile.current_el = ExceptionLevel::El0;
                    context.profile.el2_enabled = el2_enabled;
                    context.profile.el3_present = el3_present;
                    for rt in 0..32 {
                        assert_eq!(
                            resolve(Request::read(register.encoding(), rt), &context),
                            Resolution::Undefined
                        );
                        assert_eq!(
                            resolve(Request::write(register.encoding(), rt, u64::MAX), &context),
                            Resolution::Undefined
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn missing_aa64_is_architectural_undefined() {
        let mut context = context();
        context.aa64 = false;
        for register in Register::ALL {
            for el in [
                ExceptionLevel::El0,
                ExceptionLevel::El1,
                ExceptionLevel::El2,
                ExceptionLevel::El3,
            ] {
                context.profile.current_el = el;
                assert_eq!(
                    resolve(Request::read(register.encoding(), 0), &context),
                    Resolution::Undefined
                );
                assert_eq!(
                    resolve(Request::write(register.encoding(), 0, 1), &context),
                    Resolution::Undefined
                );
            }
        }
    }

    #[test]
    fn unmodeled_control_paths_are_not_architectural_undefined_or_success() {
        for register in Register::ALL {
            for mode in 0..6 {
                let mut context = context();
                match mode {
                    0 => context.profile.el2_enabled = true,
                    1 => context.profile.el3_present = true,
                    2 => context.profile.security = SecurityState::Secure,
                    3 => context.profile.security = SecurityState::Realm,
                    4 => context.profile.current_el = ExceptionLevel::El2,
                    5 => context.profile.current_el = ExceptionLevel::El3,
                    _ => unreachable!(),
                }
                assert!(matches!(
                    resolve(Request::read(register.encoding(), 0), &context),
                    Resolution::Unsupported(_)
                ));
                assert!(matches!(
                    resolve(Request::write(register.encoding(), 0, 0), &context),
                    Resolution::Unsupported(_)
                ));
            }
        }
    }

    #[test]
    fn forged_public_write_request_cannot_make_xzr_nonzero() {
        for register in Register::ALL {
            let request = Request {
                encoding: register.encoding(),
                kind: AccessKind::Write { value: u64::MAX },
                rt: 31,
            };
            assert!(matches!(
                resolve(request, &context()),
                Resolution::BackendRequired(BackendRequest {
                    operation: Operation::Write { value: 0 },
                    ..
                })
            ));
        }
    }
}
