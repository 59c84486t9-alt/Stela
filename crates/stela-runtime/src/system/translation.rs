//! Access decisions for the translation-control registers: SCTLR_EL1, TCR_EL1,
//! TTBR0/1_EL1, MAIR_EL1, AMAIR_EL1, PAR_EL1, CONTEXTIDR_EL1 and VBAR_EL1.

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
mod tests;
