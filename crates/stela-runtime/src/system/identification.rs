//! Identification-register (ID_*) reads. Values come from the guest CPU profile.

use super::access::{
    AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, StateWrite, Trap,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    IdAa64Afr0El1,
    IdAa64Afr1El1,
    IdAa64Dfr0El1,
    IdAa64Dfr1El1,
    IdAa64Dfr2El1,
    IdAa64Fpfr0El1,
    IdAa64Isar0El1,
    IdAa64Isar1El1,
    IdAa64Isar2El1,
    IdAa64Isar3El1,
    IdAa64Mmfr0El1,
    IdAa64Mmfr1El1,
    IdAa64Mmfr2El1,
    IdAa64Mmfr3El1,
    IdAa64Mmfr4El1,
    IdAa64Pfr0El1,
    IdAa64Pfr1El1,
    IdAa64Pfr2El1,
    IdAa64Smfr0El1,
    IdAa64Zfr0El1,
    MidrEl1,
    MpidrEl1,
    RevidrEl1,
    AidrEl1,
    CtrEl0,
    DczidEl0,
    ClidrEl1,
    CcsidrEl1,
    Ccsidr2El1,
    CsselrEl1,
}

pub const ALL_REGISTERS: [Register; 30] = [
    Register::IdAa64Afr0El1,
    Register::IdAa64Afr1El1,
    Register::IdAa64Dfr0El1,
    Register::IdAa64Dfr1El1,
    Register::IdAa64Dfr2El1,
    Register::IdAa64Fpfr0El1,
    Register::IdAa64Isar0El1,
    Register::IdAa64Isar1El1,
    Register::IdAa64Isar2El1,
    Register::IdAa64Isar3El1,
    Register::IdAa64Mmfr0El1,
    Register::IdAa64Mmfr1El1,
    Register::IdAa64Mmfr2El1,
    Register::IdAa64Mmfr3El1,
    Register::IdAa64Mmfr4El1,
    Register::IdAa64Pfr0El1,
    Register::IdAa64Pfr1El1,
    Register::IdAa64Pfr2El1,
    Register::IdAa64Smfr0El1,
    Register::IdAa64Zfr0El1,
    Register::MidrEl1,
    Register::MpidrEl1,
    Register::RevidrEl1,
    Register::AidrEl1,
    Register::CtrEl0,
    Register::DczidEl0,
    Register::ClidrEl1,
    Register::CcsidrEl1,
    Register::Ccsidr2El1,
    Register::CsselrEl1,
];

impl Register {
    pub const fn encoding(self) -> Encoding {
        let (op1, crm, op2) = match self {
            Self::IdAa64Afr0El1 => (0, 5, 4),
            Self::IdAa64Afr1El1 => (0, 5, 5),
            Self::IdAa64Dfr0El1 => (0, 5, 0),
            Self::IdAa64Dfr1El1 => (0, 5, 1),
            Self::IdAa64Dfr2El1 => (0, 5, 2),
            Self::IdAa64Fpfr0El1 => (0, 4, 7),
            Self::IdAa64Isar0El1 => (0, 6, 0),
            Self::IdAa64Isar1El1 => (0, 6, 1),
            Self::IdAa64Isar2El1 => (0, 6, 2),
            Self::IdAa64Isar3El1 => (0, 6, 3),
            Self::IdAa64Mmfr0El1 => (0, 7, 0),
            Self::IdAa64Mmfr1El1 => (0, 7, 1),
            Self::IdAa64Mmfr2El1 => (0, 7, 2),
            Self::IdAa64Mmfr3El1 => (0, 7, 3),
            Self::IdAa64Mmfr4El1 => (0, 7, 4),
            Self::IdAa64Pfr0El1 => (0, 4, 0),
            Self::IdAa64Pfr1El1 => (0, 4, 1),
            Self::IdAa64Pfr2El1 => (0, 4, 2),
            Self::IdAa64Smfr0El1 => (0, 4, 5),
            Self::IdAa64Zfr0El1 => (0, 4, 4),
            Self::MidrEl1 => (0, 0, 0),
            Self::MpidrEl1 => (0, 0, 5),
            Self::RevidrEl1 => (0, 0, 6),
            Self::AidrEl1 => (1, 0, 7),
            Self::CtrEl0 => (3, 0, 1),
            Self::DczidEl0 => (3, 0, 7),
            Self::ClidrEl1 => (1, 0, 1),
            Self::CcsidrEl1 => (1, 0, 0),
            Self::Ccsidr2El1 => (1, 0, 2),
            Self::CsselrEl1 => (2, 0, 0),
        };
        Encoding::new(SYSTEM_REGISTER_OP0, op1, IDENTIFICATION_CRN, crm, op2)
    }

    pub fn decode(selector: Encoding) -> Option<Self> {
        ALL_REGISTERS
            .into_iter()
            .find(|register| register.encoding() == selector)
    }

    pub const fn is_aa64_feature(self) -> bool {
        !matches!(
            self,
            Self::MidrEl1
                | Self::MpidrEl1
                | Self::RevidrEl1
                | Self::AidrEl1
                | Self::CtrEl0
                | Self::DczidEl0
                | Self::ClidrEl1
                | Self::CcsidrEl1
                | Self::Ccsidr2El1
                | Self::CsselrEl1
        )
    }

    const fn has_conditional_tid3(self) -> bool {
        matches!(
            self,
            Self::IdAa64Dfr2El1
                | Self::IdAa64Fpfr0El1
                | Self::IdAa64Isar2El1
                | Self::IdAa64Isar3El1
                | Self::IdAa64Mmfr2El1
                | Self::IdAa64Mmfr3El1
                | Self::IdAa64Mmfr4El1
                | Self::IdAa64Pfr2El1
                | Self::IdAa64Smfr0El1
                | Self::IdAa64Zfr0El1
        )
    }
}

pub const SYSTEM_REGISTER_OP0: u8 = 3;
pub const IDENTIFICATION_CRN: u8 = 0;
pub const CACHE_SELECTOR_INSTRUCTION_BIT: u64 = 1;
pub const CACHE_SELECTOR_LEVEL_MASK: u64 = 0b1110;
pub const CACHE_SELECTOR_TAG_BIT: u64 = 1 << 4;
pub const CACHE_SELECTOR_BASE_MASK: u64 =
    CACHE_SELECTOR_INSTRUCTION_BIT | CACHE_SELECTOR_LEVEL_MASK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readback {
    Register(Register),
    VirtualMidr,
    VirtualMpidr,
    /// Already resolves DCZID.DZP from effective TDZ/DZE and current EL.
    DynamicDczid,
    /// Reflects the selected cache; invalid selections need an explicit
    /// CONSTRAINED UNPREDICTABLE policy from the backend.
    SelectedCache(Register),
}

pub trait Readbacks {
    fn readback(&self, readback: Readback) -> Option<u64>;
    /// Only queried for late ID registers if FGT is absent and the readback is zero.
    fn conditional_tid3(&self, register: Register) -> Option<bool>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub aa64: bool,
    pub idst: bool,
    pub idte3: bool,
    pub fgt: bool,
    pub evt: bool,
    pub ccidx: bool,
    pub mte2: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub features: Features,
    pub el0_in_host: bool,
    pub hcr_tge: bool,
    pub hcr_tid1: bool,
    pub hcr_tid2: bool,
    pub hcr_tid3: bool,
    pub hcr_tid4: bool,
    pub scr_tid3: bool,
    pub scr_fgt_enabled: bool,
    pub el3_sdd_undef_priority: bool,
    pub el3_sdd_undef: bool,
    pub sctlr_el1_uct: bool,
    pub sctlr_el2_uct: bool,
    /// The selected register's HFGRTR bit; never substitutes for HFGWTR.
    pub fgt_read: bool,
    /// The selected register's HFGWTR bit; used only for CSSELR writes.
    pub fgt_write: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRequest {
    Readback(Readback),
    ConditionalTid3(Register),
}

fn trap(target: ExceptionLevel) -> Resolution<BackendRequest> {
    Resolution::Trap(Trap::system_access(target))
}

fn trap_el0(context: &Context) -> Resolution<BackendRequest> {
    trap(if context.profile.el2_enabled && context.hcr_tge {
        ExceptionLevel::El2
    } else {
        ExceptionLevel::El1
    })
}

fn unimplemented_id(context: &Context) -> Resolution<BackendRequest> {
    if context.features.idst {
        if context.profile.current_el == ExceptionLevel::El0 {
            trap_el0(context)
        } else {
            trap(context.profile.current_el)
        }
    } else {
        Resolution::Undefined
    }
}

fn fgt_enabled(context: &Context) -> bool {
    context.profile.el2_enabled
        && context.features.fgt
        && (!context.profile.el3_present || context.scr_fgt_enabled)
}

fn read(readbacks: &impl Readbacks, key: Readback) -> Resolution<BackendRequest> {
    readbacks
        .readback(key)
        .map(Resolution::Read)
        .unwrap_or(Resolution::BackendRequired(BackendRequest::Readback(key)))
}

/// Resolve an identification access without mutating state or invoking a backend.
///
/// `Resolution::NotHandled` means this direction/selector is not handled by this
/// leaf. The root allocation table must distinguish another family, a known but
/// unsupported register, and architectural unallocated/default feature-ID behavior.
/// In particular, a leaf miss does not itself authorize architectural UNDEF.
pub fn resolve(
    request: Request,
    context: &Context,
    readbacks: &impl Readbacks,
) -> Resolution<BackendRequest> {
    let kind = match request.kind {
        AccessKind::Read => AccessKind::Read,
        AccessKind::Write { .. } => AccessKind::Write {
            value: request.write_value().expect("write request"),
        },
    };
    resolve_kind(request.encoding, kind, context, readbacks)
}

fn resolve_kind(
    selector: Encoding,
    kind: AccessKind,
    context: &Context,
    readbacks: &impl Readbacks,
) -> Resolution<BackendRequest> {
    let Some(register) = Register::decode(selector) else {
        return Resolution::NotHandled;
    };
    if matches!(kind, AccessKind::Write { .. }) && register != Register::CsselrEl1 {
        // The corpus has no MSR allocation for these read-only selectors.
        return Resolution::NotHandled;
    }
    if register.is_aa64_feature() {
        return feature_id(register, context, readbacks);
    }
    if !context.features.aa64 || register == Register::Ccsidr2El1 && !context.features.ccidx {
        return if register == Register::CsselrEl1 {
            Resolution::Undefined
        } else {
            unimplemented_id(context)
        };
    }
    if register == Register::CtrEl0 {
        return ctr(context, readbacks);
    }
    if register == Register::DczidEl0 {
        if (context.profile.current_el == ExceptionLevel::El1
            || context.profile.current_el == ExceptionLevel::El0 && !context.el0_in_host)
            && fgt_enabled(context)
            && context.fgt_read
        {
            return trap(ExceptionLevel::El2);
        }
        return read(readbacks, Readback::DynamicDczid);
    }
    if context.profile.current_el == ExceptionLevel::El0 {
        return if register != Register::CsselrEl1 && context.features.idst {
            trap_el0(context)
        } else {
            Resolution::Undefined
        };
    }
    if context.profile.current_el == ExceptionLevel::El1 {
        let tid = match register {
            Register::RevidrEl1 | Register::AidrEl1 => context.hcr_tid1,
            Register::ClidrEl1
            | Register::CcsidrEl1
            | Register::Ccsidr2El1
            | Register::CsselrEl1 => context.hcr_tid2 || context.features.evt && context.hcr_tid4,
            _ => false,
        };
        if context.profile.el2_enabled && tid {
            return trap(ExceptionLevel::El2);
        }
        let fine = match kind {
            AccessKind::Read => context.fgt_read,
            AccessKind::Write { .. } => context.fgt_write,
        };
        // CCSIDR2 has no FGT branch in the pinned access pseudocode.
        if register != Register::Ccsidr2El1 && fgt_enabled(context) && fine {
            return trap(ExceptionLevel::El2);
        }
        if context.profile.el2_enabled {
            match register {
                Register::MidrEl1 => return read(readbacks, Readback::VirtualMidr),
                Register::MpidrEl1 => return read(readbacks, Readback::VirtualMpidr),
                _ => (),
            }
        }
    }
    match (register, kind) {
        (Register::CsselrEl1, AccessKind::Write { value }) => {
            let tag_mask = if context.features.mte2 && value & CACHE_SELECTOR_INSTRUCTION_BIT == 0 {
                CACHE_SELECTOR_TAG_BIT
            } else {
                0
            };
            Resolution::Write(StateWrite {
                encoding: register.encoding(),
                value: value & (CACHE_SELECTOR_BASE_MASK | tag_mask),
            })
        }
        (Register::CsselrEl1 | Register::CcsidrEl1 | Register::Ccsidr2El1, AccessKind::Read) => {
            read(readbacks, Readback::SelectedCache(register))
        }
        (_, AccessKind::Read) => read(readbacks, Readback::Register(register)),
        (_, AccessKind::Write { .. }) => Resolution::NotHandled,
    }
}

fn feature_id(
    register: Register,
    context: &Context,
    readbacks: &impl Readbacks,
) -> Resolution<BackendRequest> {
    // SMFR0 and ZFR0 lack the AA64 presence guard in the pinned source.
    if !context.features.aa64
        && !matches!(register, Register::IdAa64Smfr0El1 | Register::IdAa64Zfr0El1)
    {
        return unimplemented_id(context);
    }
    let el3_trap = context.profile.el3_present && context.features.idte3 && context.scr_tid3;
    if !matches!(
        context.profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El3
    ) && context.el3_sdd_undef_priority
        && el3_trap
    {
        return Resolution::Undefined;
    }
    if context.profile.current_el == ExceptionLevel::El0 {
        return if context.features.idst {
            trap_el0(context)
        } else {
            Resolution::Undefined
        };
    }
    if context.profile.current_el == ExceptionLevel::El1
        && context.profile.el2_enabled
        && context.hcr_tid3
    {
        let traps = if !register.has_conditional_tid3() || context.features.fgt {
            true
        } else {
            let key = Readback::Register(register);
            let Some(value) = readbacks.readback(key) else {
                return Resolution::BackendRequired(BackendRequest::Readback(key));
            };
            if value != 0 {
                true
            } else {
                let Some(choice) = readbacks.conditional_tid3(register) else {
                    return Resolution::BackendRequired(BackendRequest::ConditionalTid3(register));
                };
                choice
            }
        };
        if traps {
            return trap(ExceptionLevel::El2);
        }
    }
    if matches!(
        context.profile.current_el,
        ExceptionLevel::El1 | ExceptionLevel::El2
    ) && el3_trap
    {
        return if context.el3_sdd_undef {
            Resolution::Undefined
        } else {
            trap(ExceptionLevel::El3)
        };
    }
    read(readbacks, Readback::Register(register))
}

fn ctr(context: &Context, readbacks: &impl Readbacks) -> Resolution<BackendRequest> {
    if context.profile.current_el == ExceptionLevel::El0 {
        if context.el0_in_host {
            if !context.sctlr_el2_uct {
                return trap(ExceptionLevel::El2);
            }
            return read(readbacks, Readback::Register(Register::CtrEl0));
        }
        if !context.sctlr_el1_uct {
            return trap_el0(context);
        }
    }
    if matches!(
        context.profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) && context.profile.el2_enabled
        && (context.hcr_tid2 || fgt_enabled(context) && context.fgt_read)
    {
        return trap(ExceptionLevel::El2);
    }
    read(readbacks, Readback::Register(Register::CtrEl0))
}

#[cfg(test)]
mod tests;
