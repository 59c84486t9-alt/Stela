//! Direct-state AArch64 system register access checks and unapplied effects.
//! June 2026 SysReg XML plus MSR-immediate/CheckDAIFAccess are the source contract.

use super::access::{
    AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, StateWrite, Trap,
};

pub const NZCV_MASK: u64 = 0xf << 28;
pub const DAIF_SHIFT: u32 = 6;
pub const DAIF_MASK: u64 = 0xf << DAIF_SHIFT;
pub const SP_SELECT_MASK: u64 = 1;
pub const PAN_MASK: u64 = 1 << 22;
pub const UAO_MASK: u64 = 1 << 23;
pub const DIT_MASK: u64 = 1 << 24;
pub const SSBS_MASK: u64 = 1 << 12;
pub const TCO_MASK: u64 = 1 << 25;
const EL1_READBACK: u64 = 1 << 2;
const EL2_READBACK: u64 = 2 << 2;
const HCR_NV_BIT: u8 = 1;
const IMMEDIATE_LOW_BIT: u8 = 1;
const ZERO_REGISTER: u8 = 31;

const fn encoding(op1: u8, crn: u8, crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, op1, crn, crm, op2)
}
pub const NZCV: Encoding = encoding(3, 4, 2, 0);
pub const DAIF: Encoding = encoding(3, 4, 2, 1);
pub const CURRENT_EL: Encoding = encoding(0, 4, 2, 2);
pub const SPSEL: Encoding = encoding(0, 4, 2, 0);
pub const PAN: Encoding = encoding(0, 4, 2, 3);
pub const UAO: Encoding = encoding(0, 4, 2, 4);
pub const DIT: Encoding = encoding(3, 4, 2, 5);
pub const SSBS: Encoding = encoding(3, 4, 2, 6);
pub const TCO: Encoding = encoding(3, 4, 2, 7);
pub const TPIDR_EL0: Encoding = encoding(3, 13, 0, 2);
pub const TPIDRRO_EL0: Encoding = encoding(3, 13, 0, 3);
pub const TPIDR_EL1: Encoding = encoding(0, 13, 0, 4);
pub const SP_EL0: Encoding = encoding(0, 4, 1, 0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsbsFeature {
    Absent,
    ImmediateOnly,
    ReadWrite,
}

/// MTE1's two implementation-defined choices are independent. MTE2+ requires
/// PSTATE.TCO storage for both register and immediate forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MteFeature {
    Absent,
    One {
        register_raz_wi: bool,
        immediate_ignored: bool,
    },
    TwoOrLater,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub aa64: bool,
    pub pan: bool,
    pub uao: bool,
    pub dit: bool,
    pub ssbs: SsbsFeature,
    pub mte: MteFeature,
    pub fine_grained_traps: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadIdTrapBits {
    pub el0: bool,
    pub read_only_el0: bool,
    pub el1: bool,
}

/// Evaluated architectural controls, never host CPU flags. The profile owner
/// derives host status and EffectiveHCR_EL2_NVx from current security/EL state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Controls {
    pub el0_in_host: bool,
    pub sctlr_el1_uma: bool,
    pub hcr_el2_tge: bool,
    pub effective_hcr_el2_nvx: u8,
    pub scr_el3_fgt_enable: bool,
    pub thread_id_read_traps: ThreadIdTrapBits,
    pub thread_id_write_traps: ThreadIdTrapBits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub features: Features,
    pub controls: Controls,
}

/// Borrowed architectural values; this type proposes no runtime layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub pstate: Option<u64>,
    pub thread_id_el0: Option<u64>,
    pub thread_id_read_only_el0: Option<u64>,
    pub thread_id_el1: Option<u64>,
    pub stack_pointer_el0: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PstateField {
    Daif,
    SpSelect,
    Pan,
    Uao,
    Dit,
    Ssbs,
    Tco,
}

/// These typed operations require a real backend before state commitment.
/// DIT includes data-independent timing/exception response; SSBS includes the
/// prohibited speculation behavior. A stored bit alone satisfies neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRequest {
    Pstate {
        field: PstateField,
        mask: u64,
        value: u64,
    },
    /// Only the documented MTE1 implementation-defined ignored write choice.
    IgnoreTcoWrite,
}

fn is_el0(context: &Context) -> bool {
    context.profile.current_el == ExceptionLevel::El0
}

fn daif_check(context: &Context) -> Option<Resolution<BackendRequest>> {
    if is_el0(context) && (context.controls.el0_in_host || !context.controls.sctlr_el1_uma) {
        let target = if context.profile.el2_enabled && context.controls.hcr_el2_tge {
            ExceptionLevel::El2
        } else {
            ExceptionLevel::El1
        };
        Some(Resolution::Trap(Trap::system_access(target)))
    } else {
        None
    }
}

fn thread_id_check(request: Request, context: &Context) -> Option<Resolution<BackendRequest>> {
    if is_el0(context)
        && (request.encoding == TPIDR_EL1
            || request.encoding == TPIDRRO_EL0 && request.write_value().is_some())
    {
        return Some(Resolution::Undefined);
    }
    let bits = match request.kind {
        AccessKind::Read => context.controls.thread_id_read_traps,
        AccessKind::Write { .. } => context.controls.thread_id_write_traps,
    };
    let selected = match request.encoding {
        TPIDR_EL0 => bits.el0,
        TPIDRRO_EL0 => bits.read_only_el0,
        TPIDR_EL1 => bits.el1,
        _ => unreachable!("private helper accepts only thread ID registers"),
    };
    let fine_grained_enabled = context.profile.el2_enabled
        && context.features.fine_grained_traps
        && (!context.profile.el3_present || context.controls.scr_el3_fgt_enable);
    if fine_grained_enabled && (!is_el0(context) || !context.controls.el0_in_host) && selected {
        Some(Resolution::Trap(Trap::system_access(ExceptionLevel::El2)))
    } else {
        None
    }
}

fn field(selected: Encoding) -> Option<(PstateField, u64)> {
    Some(match selected {
        DAIF => (PstateField::Daif, DAIF_MASK),
        SPSEL => (PstateField::SpSelect, SP_SELECT_MASK),
        PAN => (PstateField::Pan, PAN_MASK),
        UAO => (PstateField::Uao, UAO_MASK),
        DIT => (PstateField::Dit, DIT_MASK),
        SSBS => (PstateField::Ssbs, SSBS_MASK),
        TCO => (PstateField::Tco, TCO_MASK),
        _ => return None,
    })
}

fn implemented(selected: Encoding, features: &Features) -> bool {
    features.aa64
        && match selected {
            PAN => features.pan,
            UAO => features.uao,
            DIT => features.dit,
            SSBS => features.ssbs == SsbsFeature::ReadWrite,
            TCO => features.mte != MteFeature::Absent,
            _ => true,
        }
}

fn state_access(
    request: Request,
    readback: Option<u64>,
    write_mask: u64,
) -> Resolution<BackendRequest> {
    match request.write_value() {
        Some(value) => Resolution::Write(StateWrite {
            encoding: request.encoding,
            value: value & write_mask,
        }),
        None => match readback {
            Some(value) => Resolution::Read(value),
            None => Resolution::Unsupported("architectural register storage is unavailable"),
        },
    }
}

/// Request allocation, feature/access checks, then a read or unapplied effect.
/// XZR reads still run all checks. Only the terminal owner discards their value.
/// `NotHandled` is a family dispatch miss; the root allocation table determines
/// whether an unhandled selector is architecturally unallocated or another family.
pub fn resolve(
    request: Request,
    context: &Context,
    state: &Snapshot,
) -> Resolution<BackendRequest> {
    if request.encoding.op0() == 0 {
        return immediate(request, context);
    }
    if !matches!(
        request.encoding,
        NZCV | DAIF
            | CURRENT_EL
            | SPSEL
            | PAN
            | UAO
            | DIT
            | SSBS
            | TCO
            | TPIDR_EL0
            | TPIDRRO_EL0
            | TPIDR_EL1
            | SP_EL0
    ) {
        return Resolution::NotHandled;
    }
    if request.encoding == CURRENT_EL && request.write_value().is_some() {
        return Resolution::NotHandled;
    }
    if !implemented(request.encoding, &context.features) {
        return Resolution::Undefined;
    }
    if !matches!(
        context.profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Resolution::Unsupported("direct-state model requires an EL0 or EL1 profile");
    }
    match request.encoding {
        CURRENT_EL | SPSEL | PAN | UAO | SP_EL0 if is_el0(context) => {
            return Resolution::Undefined;
        }
        CURRENT_EL => {
            return Resolution::Read(
                if context.controls.effective_hcr_el2_nvx & HCR_NV_BIT != 0 {
                    EL2_READBACK
                } else {
                    EL1_READBACK
                },
            );
        }
        NZCV => {
            return state_access(
                request,
                state.pstate.map(|value| value & NZCV_MASK),
                NZCV_MASK,
            );
        }
        DAIF => {
            if let Some(fault) = daif_check(context) {
                return fault;
            }
        }
        TPIDR_EL0 | TPIDRRO_EL0 | TPIDR_EL1 => {
            if let Some(fault) = thread_id_check(request, context) {
                return fault;
            }
            let value = match request.encoding {
                TPIDR_EL0 => state.thread_id_el0,
                TPIDRRO_EL0 => state.thread_id_read_only_el0,
                TPIDR_EL1 => state.thread_id_el1,
                _ => unreachable!(),
            };
            return state_access(request, value, u64::MAX);
        }
        SP_EL0 => {
            let Some(pstate) = state.pstate else {
                return Resolution::Unsupported(
                    "SP_EL0 access requires architectural PSTATE.SP storage",
                );
            };
            if pstate & SP_SELECT_MASK == 0 {
                return Resolution::Undefined;
            }
            return state_access(request, state.stack_pointer_el0, u64::MAX);
        }
        TCO if matches!(
            context.features.mte,
            MteFeature::One {
                register_raz_wi: true,
                ..
            }
        ) =>
        {
            return if request.write_value().is_some() {
                Resolution::BackendRequired(BackendRequest::IgnoreTcoWrite)
            } else {
                Resolution::Read(0)
            };
        }
        _ => {}
    }
    let (field, mask) = field(request.encoding).expect("all non-PSTATE registers return above");
    match request.write_value() {
        None => match state.pstate {
            Some(value) => Resolution::Read(value & mask),
            None => Resolution::Unsupported("architectural PSTATE storage is unavailable"),
        },
        Some(value) => Resolution::BackendRequired(BackendRequest::Pstate {
            field,
            mask,
            value: value & mask,
        }),
    }
}

/// The upper three immediate bits of one-bit fields are accepted and ignored;
/// DAIF uses all four. Other immediate subfamilies remain with their own owners.
fn immediate(request: Request, context: &Context) -> Resolution<BackendRequest> {
    let selected = request.encoding;
    if selected.crn() != 4
        || selected.crm() > 15
        || request.rt != ZERO_REGISTER
        || !matches!(request.kind, AccessKind::Write { .. })
    {
        return Resolution::NotHandled;
    }
    let (register, privileged, present) = match (selected.op1(), selected.op2()) {
        (0, 3) => (UAO, true, context.features.uao),
        (0, 4) => (PAN, true, context.features.pan),
        (0, 5) => (SPSEL, true, true),
        (3, 1) => (SSBS, false, context.features.ssbs != SsbsFeature::Absent),
        (3, 2) => (DIT, false, context.features.dit),
        (3, 4) => (TCO, false, context.features.mte != MteFeature::Absent),
        (3, 6 | 7) => (DAIF, false, true),
        _ => return Resolution::NotHandled,
    };
    if !context.features.aa64 || !present {
        return Resolution::Undefined;
    }
    if !matches!(
        context.profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Resolution::Unsupported("direct-state model requires an EL0 or EL1 profile");
    }
    if privileged && is_el0(context) {
        return Resolution::Undefined;
    }
    let (field, mask) = field(register).expect("immediates identify only PSTATE fields");
    if register == DAIF {
        if let Some(fault) = daif_check(context) {
            return fault;
        }
        let selected_mask = u64::from(selected.crm()) << DAIF_SHIFT;
        return Resolution::BackendRequired(BackendRequest::Pstate {
            field,
            mask: selected_mask,
            value: if selected.op2() == 6 {
                selected_mask
            } else {
                0
            },
        });
    }
    if register == TCO
        && matches!(
            context.features.mte,
            MteFeature::One {
                immediate_ignored: true,
                ..
            }
        )
    {
        return Resolution::BackendRequired(BackendRequest::IgnoreTcoWrite);
    }
    Resolution::BackendRequired(BackendRequest::Pstate {
        field,
        mask,
        value: if selected.crm() & IMMEDIATE_LOW_BIT != 0 {
            mask
        } else {
            0
        },
    })
}

#[cfg(test)]
mod tests;
