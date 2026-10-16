//! Access routing for the EL0/EL1 debug registers. A backend implements
//! breakpoints, DCC transfers, power transitions and halting.

pub(crate) mod drps;
pub(crate) mod halted;
pub(crate) mod halting;

const DEBUG_OP0: u8 = 2;
const DEBUG_EL1_OP1: u8 = 0;
const BANK_SIZE: u8 = 16;
const BANK_COUNT: u8 = 4;
const MDSCR_NV_OFFSET: u16 = 0x158;
const NV_MONITOR_REDIRECT_MASK: u8 = 0b101;
const BREAKPOINT_VALUE_OP2: u8 = 4;
const BREAKPOINT_CONTROL_OP2: u8 = 5;
const WATCHPOINT_VALUE_OP2: u8 = 6;
const WATCHPOINT_CONTROL_OP2: u8 = 7;

use super::access::{
    AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, SecurityState, Trap,
};

pub const MDSCR_EL1: Encoding = Encoding::new(DEBUG_OP0, 0, 0, 2, 2);
pub const MDCCINT_EL1: Encoding = Encoding::new(DEBUG_OP0, 0, 0, 2, 0);
pub const OSLAR_EL1: Encoding = Encoding::new(DEBUG_OP0, 0, 1, 0, 4);
pub const OSLSR_EL1: Encoding = Encoding::new(DEBUG_OP0, 0, 1, 1, 4);
pub const DBGPRCR_EL1: Encoding = Encoding::new(DEBUG_OP0, 0, 1, 4, 4);
pub const MDCCSR_EL0: Encoding = Encoding::new(DEBUG_OP0, 3, 0, 1, 0);
pub const DBGDTR_RX_TX_EL0: Encoding = Encoding::new(DEBUG_OP0, 3, 0, 5, 0);
pub const DBGDTR_EL0: Encoding = Encoding::new(DEBUG_OP0, 3, 0, 4, 0);
pub const MDSELR_EL1: Encoding = Encoding::new(DEBUG_OP0, 0, 0, 4, 2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    DbgbvrEl1(u8),
    DbgbcrEl1(u8),
    DbgwvrEl1(u8),
    DbgwcrEl1(u8),
    MdscrEl1,
    MdccintEl1,
    OslarEl1,
    OslsrEl1,
    DbgprcrEl1,
    MdccsrEl0,
    DbgdtrrxEl0,
    DbgdtrtxEl0,
    DbgdtrEl0,
    MdselrEl1,
}

impl Register {
    /// The selector for this destination. An indexed destination uses its low
    /// four index bits; the bank stays in the context.
    pub const fn encoding(self) -> Encoding {
        match self {
            Self::DbgbvrEl1(index) => bank_encoding(index, BREAKPOINT_VALUE_OP2),
            Self::DbgbcrEl1(index) => bank_encoding(index, BREAKPOINT_CONTROL_OP2),
            Self::DbgwvrEl1(index) => bank_encoding(index, WATCHPOINT_VALUE_OP2),
            Self::DbgwcrEl1(index) => bank_encoding(index, WATCHPOINT_CONTROL_OP2),
            Self::MdscrEl1 => MDSCR_EL1,
            Self::MdccintEl1 => MDCCINT_EL1,
            Self::OslarEl1 => OSLAR_EL1,
            Self::OslsrEl1 => OSLSR_EL1,
            Self::DbgprcrEl1 => DBGPRCR_EL1,
            Self::MdccsrEl0 => MDCCSR_EL0,
            Self::DbgdtrrxEl0 | Self::DbgdtrtxEl0 => DBGDTR_RX_TX_EL0,
            Self::DbgdtrEl0 => DBGDTR_EL0,
            Self::MdselrEl1 => MDSELR_EL1,
        }
    }

    // One bit per non-indexed family, shared by all members of each bank.
    pub const fn fine_grained_bit(self) -> u16 {
        let shift = match self {
            Self::DbgbvrEl1(_) => 0,
            Self::DbgbcrEl1(_) => 1,
            Self::DbgwvrEl1(_) => 2,
            Self::DbgwcrEl1(_) => 3,
            Self::MdscrEl1 => 4,
            Self::OslarEl1 => 5,
            Self::OslsrEl1 => 6,
            Self::DbgprcrEl1 => 7,
            _ => return 0,
        };
        1 << shift
    }

    const fn is_dcc(self) -> bool {
        matches!(
            self,
            Self::MdccintEl1
                | Self::MdccsrEl0
                | Self::DbgdtrrxEl0
                | Self::DbgdtrtxEl0
                | Self::DbgdtrEl0
        )
    }

    const fn is_transfer(self) -> bool {
        matches!(
            self,
            Self::DbgdtrrxEl0 | Self::DbgdtrtxEl0 | Self::DbgdtrEl0
        )
    }

    const fn is_os_control(self) -> bool {
        matches!(self, Self::OslarEl1 | Self::OslsrEl1 | Self::DbgprcrEl1)
    }

    const fn is_banked(self) -> bool {
        matches!(
            self,
            Self::DbgbvrEl1(_) | Self::DbgbcrEl1(_) | Self::DbgwvrEl1(_) | Self::DbgwcrEl1(_)
        )
    }
}

const fn bank_encoding(index: u8, op2: u8) -> Encoding {
    assert!(index < BANK_SIZE * BANK_COUNT, "physical debug index");
    Encoding::new(DEBUG_OP0, DEBUG_EL1_OP1, 0, index % BANK_SIZE, op2)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Default))]
pub struct Features {
    pub aa64: bool,
    pub debug_v8p9: bool,
    pub fgt: bool,
    pub fgt2: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Default))]
pub struct TrapControls {
    pub mdcr_el2_tde: bool,
    pub mdcr_el2_tda: bool,
    pub mdcr_el2_tdosa: bool,
    pub mdcr_el2_tdcc: bool,
    pub hcr_el2_tge: bool,
    pub effective_tge: bool,
    pub mdscr_el1_tdcc: bool,
    pub fine_grained_read_traps: u16,
    pub fine_grained_write_traps: u16,
    pub mdselr_read_allowed: bool,
    pub mdselr_write_allowed: bool,
    /// EffectiveHCR_EL2_NVx, bit order NV2:NV1:NV.
    pub effective_nvx: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Default))]
pub struct DebugControls {
    pub halted: bool,
    /// The selected permitted CONSTRAINED UNPREDICTABLE ignore-trap outcome.
    pub ignore_traps_in_debug: bool,
    pub halting_allowed: bool,
    pub edscr_tda: bool,
    pub os_locked: bool,
    pub breakpoint_count: u8,
    pub watchpoint_count: u8,
    /// Raw MDSELR_EL1.BANK; distinct from the effective bank by architecture.
    pub raw_bank: u8,
    /// EffectiveMDSELR_EL1_BANK(), including enable and reserved-value rules.
    pub effective_bank: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub profile: Profile,
    pub features: Features,
    pub traps: TrapControls,
    pub debug: DebugControls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferWidth {
    Word,
    Doubleword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRequest {
    Register {
        register: Register,
        request: Request,
        width: TransferWidth,
    },
    NestedMonitorControl {
        offset: u16,
        request: Request,
    },
    HaltSoftwareAccess {
        register: Register,
        request: Request,
    },
}

pub fn decode(selector: Encoding, direction: AccessKind) -> Option<Register> {
    if selector.op0() != DEBUG_OP0 || selector.crm() >= BANK_SIZE {
        return None;
    }
    let read = matches!(direction, AccessKind::Read);
    if selector.op1() == DEBUG_EL1_OP1 && selector.crn() == 0 {
        let bank = match selector.op2() {
            BREAKPOINT_VALUE_OP2 => Some(Register::DbgbvrEl1(selector.crm())),
            BREAKPOINT_CONTROL_OP2 => Some(Register::DbgbcrEl1(selector.crm())),
            WATCHPOINT_VALUE_OP2 => Some(Register::DbgwvrEl1(selector.crm())),
            WATCHPOINT_CONTROL_OP2 => Some(Register::DbgwcrEl1(selector.crm())),
            _ => None,
        };
        if bank.is_some() {
            return bank;
        }
    }
    match selector {
        MDSCR_EL1 => Some(Register::MdscrEl1),
        MDCCINT_EL1 => Some(Register::MdccintEl1),
        OSLAR_EL1 if !read => Some(Register::OslarEl1),
        OSLSR_EL1 if read => Some(Register::OslsrEl1),
        DBGPRCR_EL1 => Some(Register::DbgprcrEl1),
        MDCCSR_EL0 if read => Some(Register::MdccsrEl0),
        DBGDTR_RX_TX_EL0 if read => Some(Register::DbgdtrrxEl0),
        DBGDTR_RX_TX_EL0 => Some(Register::DbgdtrtxEl0),
        DBGDTR_EL0 => Some(Register::DbgdtrEl0),
        MDSELR_EL1 => Some(Register::MdselrEl1),
        _ => None,
    }
}

pub fn resolve(request: Request, context: &Context) -> Resolution<BackendRequest> {
    let selector = request.encoding;
    let direction = request.kind;
    let profile = context.profile;
    let features = context.features;
    let traps = context.traps;
    let debug = context.debug;
    let Some(mut register) = decode(selector, direction) else {
        return Resolution::NotHandled;
    };
    if !features.aa64 || (register == Register::MdselrEl1 && !features.debug_v8p9) {
        return Resolution::Undefined;
    }
    if profile.security != SecurityState::NonSecure
        || profile.el3_present
        || !matches!(
            profile.current_el,
            ExceptionLevel::El0 | ExceptionLevel::El1
        )
    {
        return Resolution::Unsupported("requires nonsecure EL0/EL1 with EL3 absent");
    }
    if traps.effective_nvx > 7
        || debug.raw_bank >= BANK_COUNT
        || debug.effective_bank >= BANK_COUNT
        || debug.breakpoint_count > BANK_SIZE * BANK_COUNT
        || debug.watchpoint_count > BANK_SIZE * BANK_COUNT
    {
        return Resolution::Unsupported("invalid effective debug context");
    }
    if register.is_banked() {
        let (encoded_index, count, range_bank) = match register {
            Register::DbgbvrEl1(index) | Register::DbgbcrEl1(index) => {
                (index, debug.breakpoint_count, debug.effective_bank)
            }
            Register::DbgwvrEl1(index) | Register::DbgwcrEl1(index) => {
                (index, debug.watchpoint_count, debug.raw_bank)
            }
            _ => unreachable!(),
        };
        let range_index = encoded_index
            + if features.debug_v8p9 {
                range_bank * BANK_SIZE
            } else {
                0
            };
        if range_index >= count {
            return Resolution::Undefined;
        }
        let effective_index = encoded_index
            + if features.debug_v8p9 {
                debug.effective_bank * BANK_SIZE
            } else {
                0
            };
        register = match register {
            Register::DbgbvrEl1(_) => Register::DbgbvrEl1(effective_index),
            Register::DbgbcrEl1(_) => Register::DbgbcrEl1(effective_index),
            Register::DbgwvrEl1(_) => Register::DbgwvrEl1(effective_index),
            Register::DbgwcrEl1(_) => Register::DbgwcrEl1(effective_index),
            _ => unreachable!(),
        };
    }
    let backend = register_request(register, request);
    // DTR accesses bypass every trap when halted. MDCCSR and MDCCINT have a
    // selected permitted ignore-trap choice; MDCCINT still excludes EL0.
    if debug.halted
        && (register.is_transfer()
            || (debug.ignore_traps_in_debug
                && (register == Register::MdccsrEl0
                    || (register == Register::MdccintEl1
                        && profile.current_el != ExceptionLevel::El0))))
    {
        return Resolution::BackendRequired(backend);
    }
    if profile.current_el == ExceptionLevel::El0 && !register.is_dcc() {
        return Resolution::Undefined;
    }
    if profile.current_el == ExceptionLevel::El0 && register == Register::MdccintEl1 {
        return Resolution::Undefined;
    }
    let trap_el2 = || Resolution::Trap(Trap::system_access(ExceptionLevel::El2));
    if register.is_dcc() {
        if profile.current_el == ExceptionLevel::El0 && traps.mdscr_el1_tdcc {
            return Resolution::Trap(Trap::system_access(
                if profile.el2_enabled && traps.hcr_el2_tge {
                    ExceptionLevel::El2
                } else {
                    ExceptionLevel::El1
                },
            ));
        }
        if profile.el2_enabled
            && ((features.fgt && traps.mdcr_el2_tdcc)
                || traps.mdcr_el2_tde
                || traps.mdcr_el2_tda
                || (profile.current_el == ExceptionLevel::El0 && traps.effective_tge))
        {
            return trap_el2();
        }
        return Resolution::BackendRequired(backend);
    }
    if profile.el2_enabled {
        let selected_traps = match direction {
            AccessKind::Read => traps.fine_grained_read_traps,
            AccessKind::Write { .. } => traps.fine_grained_write_traps,
        };
        if features.fgt && selected_traps & register.fine_grained_bit() != 0 {
            return trap_el2();
        }
        if register == Register::MdselrEl1 && features.fgt2 {
            let allowed = match direction {
                AccessKind::Read => traps.mdselr_read_allowed,
                AccessKind::Write { .. } => traps.mdselr_write_allowed,
            };
            if !allowed {
                return trap_el2();
            }
        }
        if traps.mdcr_el2_tde
            || if register.is_os_control() {
                traps.mdcr_el2_tdosa
            } else {
                traps.mdcr_el2_tda
            }
        {
            return trap_el2();
        }
    }
    if register.is_banked() && !debug.os_locked && debug.halting_allowed && debug.edscr_tda {
        return Resolution::BackendRequired(BackendRequest::HaltSoftwareAccess {
            register,
            request,
        });
    }
    if register == Register::MdscrEl1
        && traps.effective_nvx & NV_MONITOR_REDIRECT_MASK == NV_MONITOR_REDIRECT_MASK
    {
        return Resolution::BackendRequired(BackendRequest::NestedMonitorControl {
            offset: MDSCR_NV_OFFSET,
            request: normalize_request(request, TransferWidth::Doubleword),
        });
    }
    Resolution::BackendRequired(backend)
}

fn register_request(register: Register, request: Request) -> BackendRequest {
    let width = if matches!(register, Register::DbgdtrrxEl0 | Register::DbgdtrtxEl0) {
        TransferWidth::Word
    } else {
        TransferWidth::Doubleword
    };
    BackendRequest::Register {
        register,
        request: normalize_request(request, width),
        width,
    }
}

fn normalize_request(mut request: Request, width: TransferWidth) -> Request {
    if let Some(value) = request.write_value() {
        request.kind = AccessKind::Write {
            value: match width {
                TransferWidth::Word => u64::from(value as u32),
                TransferWidth::Doubleword => value,
            },
        };
    }
    request
}

#[cfg(test)]
mod tests;
