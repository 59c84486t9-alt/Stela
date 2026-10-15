//! Pure access routing for the selected nonsecure AArch64 EL0/EL1 debug profile.
//! No debug state is represented as ordinary register storage here. A backend
//! must implement matching, DCC transfers, lock/power transitions, and halts.
//! `Resolution::NotHandled` is only a family dispatch miss. The caller's complete
//! allocation table owns the final unallocated versus unsupported distinction.

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
    /// Canonical selector for this backend destination. An indexed destination
    /// uses its low four index bits; its physical bank remains in the context.
    /// The original request is retained separately in every backend request.
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
mod tests {
    use super::*;

    fn context(el: ExceptionLevel) -> Context {
        Context {
            profile: Profile {
                current_el: el,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            features: Features {
                aa64: true,
                ..Features::default()
            },
            traps: TrapControls::default(),
            debug: DebugControls {
                breakpoint_count: BANK_SIZE,
                watchpoint_count: BANK_SIZE,
                ..DebugControls::default()
            },
        }
    }

    fn bank(op2: u8, index: u8) -> Encoding {
        Encoding::new(DEBUG_OP0, DEBUG_EL1_OP1, 0, index, op2)
    }

    fn is_backend(result: Resolution<BackendRequest>) -> bool {
        matches!(result, Resolution::BackendRequired(_))
    }

    #[test]
    fn selector_space_has_exact_direction_sensitive_allocations() {
        let mut reads = 0;
        let mut writes = 0;
        for op0 in 0..4 {
            for op1 in 0..8 {
                for crn in 0..16 {
                    for crm in 0..16 {
                        for op2 in 0..8 {
                            let encoding = Encoding::new(op0, op1, crn, crm, op2);
                            reads += u32::from(decode(encoding, AccessKind::Read).is_some());
                            writes += u32::from(
                                decode(encoding, AccessKind::Write { value: 0 }).is_some(),
                            );
                        }
                    }
                }
            }
        }
        assert_eq!((reads, writes), (72, 71));
        assert_eq!(decode(OSLAR_EL1, AccessKind::Read), None);
        let ctx = context(ExceptionLevel::El1);
        for request in [
            Request::read(OSLAR_EL1, 0),
            Request::write(OSLSR_EL1, 0, 0),
            Request::write(MDCCSR_EL0, 0, 0),
            Request::read(Encoding::new(3, 7, 15, 15, 7), 0),
        ] {
            assert_eq!(resolve(request, &ctx), Resolution::NotHandled);
        }
        assert_eq!(decode(OSLSR_EL1, AccessKind::Write { value: 0 }), None);
        assert_eq!(decode(MDCCSR_EL0, AccessKind::Write { value: 0 }), None);
        assert_eq!(
            decode(DBGDTR_RX_TX_EL0, AccessKind::Read),
            Some(Register::DbgdtrrxEl0)
        );
        assert_eq!(
            decode(DBGDTR_RX_TX_EL0, AccessKind::Write { value: 0 }),
            Some(Register::DbgdtrtxEl0)
        );
    }

    #[test]
    fn descriptor_selectors_preserve_request_identity() {
        for index in 0..BANK_SIZE * BANK_COUNT {
            for register in [
                Register::DbgbvrEl1(index),
                Register::DbgbcrEl1(index),
                Register::DbgwvrEl1(index),
                Register::DbgwcrEl1(index),
            ] {
                assert_eq!(register.encoding().crm(), index % BANK_SIZE);
            }
        }
        for encoding in [
            MDSCR_EL1,
            MDCCINT_EL1,
            OSLSR_EL1,
            DBGPRCR_EL1,
            MDCCSR_EL0,
            DBGDTR_RX_TX_EL0,
            DBGDTR_EL0,
            MDSELR_EL1,
        ] {
            assert_eq!(
                decode(encoding, AccessKind::Read).unwrap().encoding(),
                encoding
            );
        }
        assert_eq!(
            decode(OSLAR_EL1, AccessKind::Write { value: 0 })
                .unwrap()
                .encoding(),
            OSLAR_EL1
        );
    }

    #[test]
    fn all_indexed_members_obey_count_and_feature_priority() {
        let mut ctx = context(ExceptionLevel::El1);
        for op2 in BREAKPOINT_VALUE_OP2..=WATCHPOINT_CONTROL_OP2 {
            for index in 0..BANK_SIZE {
                for count in 0..=BANK_SIZE {
                    ctx.debug.breakpoint_count = count;
                    ctx.debug.watchpoint_count = count;
                    for kind in [AccessKind::Read, AccessKind::Write { value: u64::MAX }] {
                        let request = Request {
                            encoding: bank(op2, index),
                            kind,
                            rt: 0,
                        };
                        assert_eq!(
                            resolve(request, &ctx) == Resolution::Undefined,
                            index >= count
                        );
                    }
                }
            }
        }
        ctx.features.aa64 = false;
        ctx.profile.el2_enabled = true;
        ctx.traps.mdcr_el2_tde = true;
        assert_eq!(
            resolve(Request::read(bank(BREAKPOINT_VALUE_OP2, 0), 0), &ctx),
            Resolution::Undefined
        );
    }

    #[test]
    fn bank_selection_preserves_raw_watchpoint_guard_and_effective_index() {
        let mut ctx = context(ExceptionLevel::El1);
        ctx.features.debug_v8p9 = true;
        ctx.debug.breakpoint_count = BANK_SIZE * BANK_COUNT;
        ctx.debug.watchpoint_count = BANK_SIZE * BANK_COUNT;
        for raw in 0..BANK_COUNT {
            for effective in 0..BANK_COUNT {
                ctx.debug.raw_bank = raw;
                ctx.debug.effective_bank = effective;
                for index in 0..BANK_SIZE {
                    for op2 in BREAKPOINT_VALUE_OP2..=WATCHPOINT_CONTROL_OP2 {
                        for count in 0..=BANK_SIZE * BANK_COUNT {
                            ctx.debug.breakpoint_count = count;
                            ctx.debug.watchpoint_count = count;
                            let encoded = bank(op2, index);
                            let request = Request::read(encoded, 0);
                            let range_bank = if op2 < WATCHPOINT_VALUE_OP2 {
                                effective
                            } else {
                                raw
                            };
                            let result = resolve(request, &ctx);
                            if index + range_bank * BANK_SIZE >= count {
                                assert_eq!(result, Resolution::Undefined);
                            } else {
                                let register = match op2 {
                                    BREAKPOINT_VALUE_OP2 => {
                                        Register::DbgbvrEl1(index + effective * BANK_SIZE)
                                    }
                                    BREAKPOINT_CONTROL_OP2 => {
                                        Register::DbgbcrEl1(index + effective * BANK_SIZE)
                                    }
                                    WATCHPOINT_VALUE_OP2 => {
                                        Register::DbgwvrEl1(index + effective * BANK_SIZE)
                                    }
                                    WATCHPOINT_CONTROL_OP2 => {
                                        Register::DbgwcrEl1(index + effective * BANK_SIZE)
                                    }
                                    _ => unreachable!(),
                                };
                                assert_eq!(
                                    result,
                                    Resolution::BackendRequired(register_request(
                                        register, request
                                    ))
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn el0_privilege_and_halted_dcc_priority_are_distinct() {
        let mut ctx = context(ExceptionLevel::El0);
        ctx.features.debug_v8p9 = true;
        ctx.debug.halted = true;
        ctx.debug.ignore_traps_in_debug = true;
        ctx.traps.mdscr_el1_tdcc = true;
        for encoding in [
            MDSCR_EL1,
            MDCCINT_EL1,
            OSLSR_EL1,
            DBGPRCR_EL1,
            MDSELR_EL1,
            bank(BREAKPOINT_VALUE_OP2, 0),
        ] {
            assert_eq!(
                resolve(Request::read(encoding, 0), &ctx),
                Resolution::Undefined
            );
        }
        assert!(is_backend(resolve(
            Request::write(OSLAR_EL1, 0, 1),
            &context(ExceptionLevel::El1)
        )));
        assert_eq!(
            resolve(Request::write(OSLAR_EL1, 0, 1), &ctx),
            Resolution::Undefined
        );
        for encoding in [MDCCSR_EL0, DBGDTR_RX_TX_EL0, DBGDTR_EL0] {
            assert!(is_backend(resolve(Request::read(encoding, 31), &ctx)));
        }
        ctx.debug.ignore_traps_in_debug = false;
        assert!(matches!(
            resolve(Request::read(MDCCSR_EL0, 0), &ctx),
            Resolution::Trap(_)
        ));
        assert!(is_backend(resolve(Request::read(DBGDTR_EL0, 0), &ctx)));
    }

    #[test]
    fn dcc_el0_trap_routing_uses_raw_tge_before_later_effective_tge() {
        let mut ctx = context(ExceptionLevel::El0);
        ctx.profile.el2_enabled = true;
        ctx.traps.mdscr_el1_tdcc = true;
        ctx.traps.effective_tge = true;
        let request = Request::read(MDCCSR_EL0, 7);
        assert_eq!(
            resolve(request, &ctx),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El1))
        );
        ctx.traps.hcr_el2_tge = true;
        assert_eq!(
            resolve(request, &ctx),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
        ctx.traps.mdscr_el1_tdcc = false;
        ctx.traps.hcr_el2_tge = false;
        assert_eq!(
            resolve(request, &ctx),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
        ctx.profile.el2_enabled = false;
        assert!(is_backend(resolve(request, &ctx)));
    }

    #[test]
    fn dcc_tdcc_requires_fgt_but_tda_and_tde_do_not() {
        let mut ctx = context(ExceptionLevel::El1);
        ctx.profile.el2_enabled = true;
        let request = Request::read(MDCCINT_EL1, 0);
        ctx.traps.mdcr_el2_tdcc = true;
        assert!(is_backend(resolve(request, &ctx)));
        ctx.features.fgt = true;
        assert_eq!(
            resolve(request, &ctx),
            Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
        );
        ctx.features.fgt = false;
        ctx.traps.mdcr_el2_tdcc = false;
        ctx.traps.mdcr_el2_tda = true;
        assert!(matches!(resolve(request, &ctx), Resolution::Trap(_)));
        ctx.traps.mdcr_el2_tda = false;
        ctx.traps.mdcr_el2_tde = true;
        assert!(matches!(resolve(request, &ctx), Resolution::Trap(_)));
        ctx.debug.halted = true;
        ctx.debug.ignore_traps_in_debug = true;
        assert!(is_backend(resolve(request, &ctx)));
    }

    #[test]
    fn os_control_uses_tdosa_and_ignores_tda() {
        let mut ctx = context(ExceptionLevel::El1);
        ctx.profile.el2_enabled = true;
        ctx.traps.mdcr_el2_tda = true;
        for request in [
            Request::write(OSLAR_EL1, 0, 1),
            Request::read(OSLSR_EL1, 0),
            Request::read(DBGPRCR_EL1, 0),
        ] {
            assert!(is_backend(resolve(request, &ctx)));
            let mut trapped = ctx;
            trapped.traps.mdcr_el2_tdosa = true;
            assert_eq!(
                resolve(request, &trapped),
                Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
            );
        }
    }

    #[test]
    fn fine_grained_read_write_traps_are_independent() {
        let mut ctx = context(ExceptionLevel::El1);
        ctx.profile.el2_enabled = true;
        ctx.features.fgt = true;
        for encoding in [
            bank(BREAKPOINT_VALUE_OP2, 0),
            bank(BREAKPOINT_CONTROL_OP2, 0),
            bank(WATCHPOINT_VALUE_OP2, 0),
            bank(WATCHPOINT_CONTROL_OP2, 0),
            MDSCR_EL1,
            DBGPRCR_EL1,
        ] {
            let bit = decode(encoding, AccessKind::Read)
                .unwrap()
                .fine_grained_bit();
            ctx.traps.fine_grained_read_traps = bit;
            ctx.traps.fine_grained_write_traps = 0;
            assert!(matches!(
                resolve(Request::read(encoding, 0), &ctx),
                Resolution::Trap(_)
            ));
            assert!(is_backend(resolve(Request::write(encoding, 0, 0), &ctx)));
            ctx.traps.fine_grained_read_traps = 0;
            ctx.traps.fine_grained_write_traps = bit;
            assert!(is_backend(resolve(Request::read(encoding, 0), &ctx)));
            assert!(matches!(
                resolve(Request::write(encoding, 0, 0), &ctx),
                Resolution::Trap(_)
            ));
        }
    }

    #[test]
    fn software_access_halt_requires_unlocked_enabled_bank_and_loses_to_trap() {
        let mut ctx = context(ExceptionLevel::El1);
        ctx.debug.halting_allowed = true;
        ctx.debug.edscr_tda = true;
        let request = Request::read(bank(BREAKPOINT_VALUE_OP2, 0), 0);
        assert!(matches!(
            resolve(request, &ctx),
            Resolution::BackendRequired(BackendRequest::HaltSoftwareAccess { .. })
        ));
        for changed in [
            DebugControls {
                os_locked: true,
                ..ctx.debug
            },
            DebugControls {
                halting_allowed: false,
                ..ctx.debug
            },
            DebugControls {
                edscr_tda: false,
                ..ctx.debug
            },
        ] {
            let no_halt = Context {
                debug: changed,
                ..ctx
            };
            assert!(matches!(
                resolve(request, &no_halt),
                Resolution::BackendRequired(BackendRequest::Register { .. })
            ));
        }
        assert!(matches!(
            resolve(Request::read(MDSCR_EL1, 0), &ctx),
            Resolution::BackendRequired(BackendRequest::Register { .. })
        ));
        ctx.profile.el2_enabled = true;
        ctx.traps.mdcr_el2_tda = true;
        assert!(matches!(resolve(request, &ctx), Resolution::Trap(_)));
    }

    #[test]
    fn nested_monitor_redirect_and_bank_select_have_exact_gate() {
        let mut ctx = context(ExceptionLevel::El1);
        for nvx in 0..8 {
            ctx.traps.effective_nvx = nvx;
            assert_eq!(
                matches!(
                    resolve(Request::read(MDSCR_EL1, 0), &ctx),
                    Resolution::BackendRequired(BackendRequest::NestedMonitorControl {
                        offset: MDSCR_NV_OFFSET,
                        ..
                    })
                ),
                nvx == 5 || nvx == 7
            );
        }
        assert_eq!(
            resolve(Request::read(MDSELR_EL1, 0), &ctx),
            Resolution::Undefined
        );
        ctx.features.debug_v8p9 = true;
        ctx.features.fgt2 = true;
        ctx.profile.el2_enabled = true;
        ctx.traps.mdselr_read_allowed = true;
        assert!(is_backend(resolve(Request::read(MDSELR_EL1, 0), &ctx)));
        assert!(matches!(
            resolve(Request::write(MDSELR_EL1, 0, 0), &ctx),
            Resolution::Trap(_)
        ));
    }

    #[test]
    fn dcc_width_and_xzr_keep_side_effecting_requests() {
        let ctx = context(ExceptionLevel::El0);
        let request = Request::write(DBGDTR_RX_TX_EL0, 5, 0xaabb_ccdd_1122_3344);
        let Resolution::BackendRequired(BackendRequest::Register { request, width, .. }) =
            resolve(request, &ctx)
        else {
            panic!("DCC transmit request expected")
        };
        assert_eq!(width, TransferWidth::Word);
        assert_eq!(request.write_value(), Some(0x1122_3344));
        for encoding in [DBGDTR_RX_TX_EL0, DBGDTR_EL0] {
            let raw = Request {
                encoding,
                kind: AccessKind::Write { value: u64::MAX },
                rt: 31,
            };
            let Resolution::BackendRequired(BackendRequest::Register { request, .. }) =
                resolve(raw, &ctx)
            else {
                panic!("DCC XZR transmit request expected")
            };
            assert_eq!(request.write_value(), Some(0));
            assert!(is_backend(resolve(Request::read(encoding, 31), &ctx)));
        }
    }

    #[test]
    fn out_of_profile_states_are_explicit_and_resolution_is_pure() {
        let ctx = context(ExceptionLevel::El1);
        let request = Request::read(MDSCR_EL1, 0);
        for profile in [
            Profile {
                security: SecurityState::Secure,
                ..ctx.profile
            },
            Profile {
                security: SecurityState::Realm,
                ..ctx.profile
            },
            Profile {
                el3_present: true,
                ..ctx.profile
            },
            Profile {
                current_el: ExceptionLevel::El2,
                ..ctx.profile
            },
            Profile {
                current_el: ExceptionLevel::El3,
                ..ctx.profile
            },
        ] {
            assert!(matches!(
                resolve(request, &Context { profile, ..ctx }),
                Resolution::Unsupported(_)
            ));
        }
        let before = ctx;
        assert!(is_backend(resolve(request, &ctx)));
        assert_eq!(ctx, before);
    }
}
