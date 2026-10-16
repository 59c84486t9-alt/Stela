//! Generic-timer register access decisions for EL0/EL1.

use super::access::{
    AccessKind, Encoding, ExceptionLevel, Profile, Request, Resolution, SecurityState, Trap,
};

const SYSTEM_REGISTER_TRAP_EC: u8 = 0x18;
pub const TIMER_ENABLE: u64 = 1;
pub const TIMER_IMASK: u64 = 1 << 1;
pub const TIMER_ISTATUS: u64 = 1 << 2;
pub const TIMER_WRITABLE_MASK: u64 = TIMER_ENABLE | TIMER_IMASK;
pub const CNTP_NVMEM_CVAL: u16 = 0x178;
pub const CNTP_NVMEM_CTL: u16 = 0x180;
pub const CNTV_NVMEM_CVAL: u16 = 0x168;
pub const CNTV_NVMEM_CTL: u16 = 0x170;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    CntfrqEl0,
    CntpctEl0,
    CntvctEl0,
    CntpctssEl0,
    CntvctssEl0,
    CntkctlEl1,
    TimerEl0 { kind: TimerKind, field: TimerField },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKind {
    Physical,
    Virtual,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerField {
    Control,
    CompareValue,
    TimerValue,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrapReason {
    El0PhysicalCount,
    El0VirtualCount,
    El0Frequency,
    El1PhysicalCount,
    El0HostPhysicalCount,
    El0HostVirtualCount,
    El1VirtualCount,
    El0PhysicalTimer,
    El1PhysicalTimer,
    El0HostPhysicalTimer,
    El0VirtualTimer,
    El0HostVirtualTimer,
    El1VirtualTimer,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Undefined,
    SystemRegisterTrap {
        target: ExceptionLevel,
        ec: u8,
        reason: TrapReason,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Requirement {
    CurrentEl2OrEl3,
    Aarch32El2CounterOffset,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Fault(Fault),
    Backend(BackendRequest),
    Unsupported(Requirement),
}

/// Effective architectural inputs, evaluated by the common system context.
/// `el0_in_host` is EffectivelyAtEL0InHost; it is not simply HCR.E2H.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    pub aa64: bool,
    pub ecv: bool,
    pub ecv_physical_offset: bool,
    pub secure_el2: bool,
    pub profile: Profile,
    pub highest_el: ExceptionLevel,
    pub have_el2: bool,
    pub el2_aarch64: bool,
    pub el2_in_host: bool,
    pub el0_in_host: bool,
    pub effective_tge: bool,
    pub scr_ecv_enable: bool,
    pub nested_all: bool,
    pub kernel: KernelControl,
    pub hypervisor: HypervisorControl,
}
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(Default))]
pub struct KernelControl {
    pub el0_physical_count: bool,
    pub el0_virtual_count: bool,
    pub el0_physical_timer: bool,
    pub el0_virtual_timer: bool,
}
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(Default))]
pub struct HypervisorControl {
    pub el0_physical_count: bool,
    pub el0_virtual_count: bool,
    pub el1_physical_count: bool,
    pub el1_virtual_count_trap: bool,
    pub el0_physical_timer: bool,
    pub el0_virtual_timer: bool,
    pub el1_physical_timer: bool,
    pub el1_physical_timer_host: bool,
    pub el1_virtual_timer_trap: bool,
    pub ecv: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterOffset {
    None,
    PhysicalEl2,
    VirtualEl2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterOrdering {
    /// Program order relative to physical/virtual counter reads as specified.
    CounterReads,
    /// FEAT_ECV self-synchronized read, not an ordinary host load or raw RDTSC.
    SelfSynchronized,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerBank {
    PhysicalEl1,
    VirtualEl1,
    HostPhysical,
    HostSecurePhysical,
    HostVirtual,
    HostSecureVirtual,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRequest {
    Frequency(AccessKind),
    /// Reads/writes must honor implemented CNTKCTL field masks, event-stream
    /// generation, and register synchronization; not just store an integer.
    KernelControl(AccessKind),
    Counter {
        kind: TimerKind,
        offset: CounterOffset,
        ordering: CounterOrdering,
    },
    /// The backend owns compare/control state, unknown disabled read fields,
    /// current counter sampling, and interrupt re-evaluation after writes.
    Timer {
        bank: TimerBank,
        field: TimerField,
        access: AccessKind,
        offset: CounterOffset,
    },
    /// NV2 redirection is memory access and can fault; no direct timer effect.
    NestedMemory {
        offset: u16,
        access: AccessKind,
    },
}

const TIMER_OP0: u8 = 0b11;
const TIMER_CRN: u8 = 0b1110;
const EL0_TIMER_OP1: u8 = 0b011;
const EL1_TIMER_OP1: u8 = 0;
const COUNTER_CRM: u8 = 0;
const KERNEL_CONTROL_CRM: u8 = 1;
const KERNEL_CONTROL_OP2: u8 = 0;
const PHYSICAL_TIMER_CRM: u8 = 2;
const VIRTUAL_TIMER_CRM: u8 = 3;
const FREQUENCY_OP2: u8 = 0;
const PHYSICAL_COUNT_OP2: u8 = 1;
const VIRTUAL_COUNT_OP2: u8 = 2;
const PHYSICAL_COUNT_SS_OP2: u8 = 5;
const VIRTUAL_COUNT_SS_OP2: u8 = 6;
const TIMER_VALUE_OP2: u8 = 0;
const TIMER_CONTROL_OP2: u8 = 1;
const TIMER_COMPARE_OP2: u8 = 2;

impl Register {
    /// The register selector; not a profile or access permission.
    pub const fn encoding(self) -> Encoding {
        use stela_compiler::aarch64::system::registers::{CNTFRQ_EL0, CNTPCT_EL0, CNTVCT_EL0};
        match self {
            Self::CntfrqEl0 => CNTFRQ_EL0,
            Self::CntpctEl0 => CNTPCT_EL0,
            Self::CntvctEl0 => CNTVCT_EL0,
            Self::CntpctssEl0 => Encoding::new(
                TIMER_OP0,
                EL0_TIMER_OP1,
                TIMER_CRN,
                COUNTER_CRM,
                PHYSICAL_COUNT_SS_OP2,
            ),
            Self::CntvctssEl0 => Encoding::new(
                TIMER_OP0,
                EL0_TIMER_OP1,
                TIMER_CRN,
                COUNTER_CRM,
                VIRTUAL_COUNT_SS_OP2,
            ),
            Self::CntkctlEl1 => Encoding::new(
                TIMER_OP0,
                EL1_TIMER_OP1,
                TIMER_CRN,
                KERNEL_CONTROL_CRM,
                KERNEL_CONTROL_OP2,
            ),
            Self::TimerEl0 { kind, field } => Encoding::new(
                TIMER_OP0,
                EL0_TIMER_OP1,
                TIMER_CRN,
                match kind {
                    TimerKind::Physical => PHYSICAL_TIMER_CRM,
                    TimerKind::Virtual => VIRTUAL_TIMER_CRM,
                },
                match field {
                    TimerField::Control => TIMER_CONTROL_OP2,
                    TimerField::CompareValue => TIMER_COMPARE_OP2,
                    TimerField::TimerValue => TIMER_VALUE_OP2,
                },
            ),
        }
    }
}

pub fn decode(encoding: Encoding) -> Option<Register> {
    if encoding.op0() != TIMER_OP0 || encoding.crn() != TIMER_CRN {
        return None;
    }
    if encoding.op1() == EL1_TIMER_OP1
        && encoding.crm() == KERNEL_CONTROL_CRM
        && encoding.op2() == KERNEL_CONTROL_OP2
    {
        return Some(Register::CntkctlEl1);
    }
    if encoding.op1() != EL0_TIMER_OP1 {
        return None;
    }
    if encoding.crm() == COUNTER_CRM {
        return match encoding.op2() {
            FREQUENCY_OP2 => Some(Register::CntfrqEl0),
            PHYSICAL_COUNT_OP2 => Some(Register::CntpctEl0),
            VIRTUAL_COUNT_OP2 => Some(Register::CntvctEl0),
            PHYSICAL_COUNT_SS_OP2 => Some(Register::CntpctssEl0),
            VIRTUAL_COUNT_SS_OP2 => Some(Register::CntvctssEl0),
            _ => None,
        };
    }
    let kind = match encoding.crm() {
        PHYSICAL_TIMER_CRM => TimerKind::Physical,
        VIRTUAL_TIMER_CRM => TimerKind::Virtual,
        _ => return None,
    };
    let field = match encoding.op2() {
        TIMER_VALUE_OP2 => TimerField::TimerValue,
        TIMER_CONTROL_OP2 => TimerField::Control,
        TIMER_COMPARE_OP2 => TimerField::CompareValue,
        _ => return None,
    };
    Some(Register::TimerEl0 { kind, field })
}

/// Access decisions precede backend sampling/mutation, including Rt==XZR.
/// `Resolution::NotHandled` is a leaf dispatch miss: another family may own the
/// selector. Architectural allocation belongs to the complete CPU-profile owner.
pub fn resolve(request: Request, context: &Context) -> Resolution<BackendRequest> {
    let Some(register) = decode(request.encoding) else {
        return Resolution::NotHandled;
    };
    if matches!(
        register,
        Register::CntpctEl0 | Register::CntvctEl0 | Register::CntpctssEl0 | Register::CntvctssEl0
    ) && matches!(request.kind, AccessKind::Write { .. })
    {
        return Resolution::NotHandled;
    }
    let access = match request.kind {
        AccessKind::Read => AccessKind::Read,
        AccessKind::Write { .. } => AccessKind::Write {
            value: request.write_value().expect("write request"),
        },
    };
    match plan(register, access, context) {
        Outcome::Fault(Fault::Undefined) => Resolution::Undefined,
        Outcome::Fault(Fault::SystemRegisterTrap { target, .. }) => {
            Resolution::Trap(Trap::system_access(target))
        }
        Outcome::Backend(request) => Resolution::BackendRequired(request),
        Outcome::Unsupported(Requirement::CurrentEl2OrEl3) => {
            Resolution::Unsupported("timer current EL2/EL3 access model")
        }
        Outcome::Unsupported(Requirement::Aarch32El2CounterOffset) => {
            Resolution::Unsupported("AArch32 EL2 counter offset model")
        }
    }
}

fn plan(register: Register, access: AccessKind, c: &Context) -> Outcome {
    if !c.aa64 {
        return Outcome::Fault(Fault::Undefined);
    }
    if matches!(register, Register::CntpctssEl0 | Register::CntvctssEl0) && !c.ecv {
        return Outcome::Fault(Fault::Undefined);
    }
    // Defensive private boundary; resolve has already excluded these unowned
    // directions. A write must never reach or sample the counter backend.
    if matches!(
        register,
        Register::CntpctEl0 | Register::CntvctEl0 | Register::CntpctssEl0 | Register::CntvctssEl0
    ) && matches!(access, AccessKind::Write { .. })
    {
        return Outcome::Fault(Fault::Undefined);
    }
    if !matches!(
        c.profile.current_el,
        ExceptionLevel::El0 | ExceptionLevel::El1
    ) {
        return Outcome::Unsupported(Requirement::CurrentEl2OrEl3);
    }
    match register {
        Register::CntfrqEl0 => frequency(access, c),
        Register::CntkctlEl1 => {
            if c.profile.current_el == ExceptionLevel::El0 {
                Outcome::Fault(Fault::Undefined)
            } else {
                Outcome::Backend(BackendRequest::KernelControl(access))
            }
        }
        Register::CntpctEl0 | Register::CntpctssEl0 => counter(TimerKind::Physical, register, c),
        Register::CntvctEl0 | Register::CntvctssEl0 => counter(TimerKind::Virtual, register, c),
        Register::TimerEl0 { kind, field } => timer(kind, field, access, c),
    }
}
fn trap(target: ExceptionLevel, reason: TrapReason) -> Outcome {
    Outcome::Fault(Fault::SystemRegisterTrap {
        target,
        ec: SYSTEM_REGISTER_TRAP_EC,
        reason,
    })
}
fn el0_trap(c: &Context, reason: TrapReason) -> Outcome {
    trap(
        if c.profile.el2_enabled && c.effective_tge {
            ExceptionLevel::El2
        } else {
            ExceptionLevel::El1
        },
        reason,
    )
}
fn frequency(access: AccessKind, c: &Context) -> Outcome {
    if matches!(access, AccessKind::Write { .. }) {
        return if c.profile.current_el == c.highest_el {
            Outcome::Backend(BackendRequest::Frequency(access))
        } else {
            Outcome::Fault(Fault::Undefined)
        };
    }
    if c.profile.current_el == ExceptionLevel::El0 {
        if !c.el0_in_host && !c.kernel.el0_physical_count && !c.kernel.el0_virtual_count {
            return el0_trap(c, TrapReason::El0Frequency);
        }
        if c.el0_in_host && !c.hypervisor.el0_physical_count && !c.hypervisor.el0_virtual_count {
            return trap(ExceptionLevel::El2, TrapReason::El0Frequency);
        }
    }
    Outcome::Backend(BackendRequest::Frequency(access))
}
fn physical_offset(c: &Context) -> CounterOffset {
    if c.ecv_physical_offset
        && c.profile.el2_enabled
        && (!c.profile.el3_present || c.scr_ecv_enable)
        && c.hypervisor.ecv
        && (c.profile.current_el == ExceptionLevel::El1 || !c.el0_in_host)
    {
        CounterOffset::PhysicalEl2
    } else {
        CounterOffset::None
    }
}
fn counter(kind: TimerKind, register: Register, c: &Context) -> Outcome {
    let offset = match kind {
        TimerKind::Physical => {
            if c.profile.current_el == ExceptionLevel::El0 {
                if !c.el0_in_host && !c.kernel.el0_physical_count {
                    return el0_trap(c, TrapReason::El0PhysicalCount);
                }
                if (c.profile.el2_enabled && !c.el2_in_host && !c.hypervisor.el1_physical_count)
                    || (c.el2_in_host && !c.effective_tge && !c.hypervisor.el1_physical_count)
                {
                    return trap(ExceptionLevel::El2, TrapReason::El1PhysicalCount);
                }
                if c.el0_in_host && !c.hypervisor.el0_physical_count {
                    return trap(ExceptionLevel::El2, TrapReason::El0HostPhysicalCount);
                }
            } else if c.profile.el2_enabled && !c.hypervisor.el1_physical_count {
                return trap(ExceptionLevel::El2, TrapReason::El1PhysicalCount);
            }
            physical_offset(c)
        }
        TimerKind::Virtual => {
            if c.profile.current_el == ExceptionLevel::El0 {
                if !c.el0_in_host && !c.kernel.el0_virtual_count {
                    return el0_trap(c, TrapReason::El0VirtualCount);
                }
                if c.el0_in_host && !c.hypervisor.el0_virtual_count {
                    return trap(ExceptionLevel::El2, TrapReason::El0HostVirtualCount);
                }
                if c.profile.el2_enabled && !c.el0_in_host && c.hypervisor.el1_virtual_count_trap {
                    return trap(ExceptionLevel::El2, TrapReason::El1VirtualCount);
                }
            } else if c.profile.el2_enabled && c.hypervisor.el1_virtual_count_trap {
                return trap(ExceptionLevel::El2, TrapReason::El1VirtualCount);
            }
            if c.have_el2
                && (!c.profile.el2_enabled
                    || c.profile.current_el == ExceptionLevel::El1
                    || !c.el0_in_host)
            {
                if !c.el2_aarch64 {
                    return Outcome::Unsupported(Requirement::Aarch32El2CounterOffset);
                }
                CounterOffset::VirtualEl2
            } else {
                CounterOffset::None
            }
        }
    };
    let ordering = if matches!(register, Register::CntpctssEl0 | Register::CntvctssEl0) {
        CounterOrdering::SelfSynchronized
    } else {
        CounterOrdering::CounterReads
    };
    Outcome::Backend(BackendRequest::Counter {
        kind,
        offset,
        ordering,
    })
}
fn timer(kind: TimerKind, field: TimerField, access: AccessKind, c: &Context) -> Outcome {
    let bank = match kind {
        TimerKind::Physical => {
            if c.profile.current_el == ExceptionLevel::El0 {
                if !c.el0_in_host && !c.kernel.el0_physical_timer {
                    return el0_trap(c, TrapReason::El0PhysicalTimer);
                }
                if c.profile.el2_enabled && !c.el2_in_host && !c.hypervisor.el1_physical_timer {
                    return trap(ExceptionLevel::El2, TrapReason::El1PhysicalTimer);
                }
                if c.el2_in_host && !c.effective_tge && !c.hypervisor.el1_physical_timer_host {
                    return trap(ExceptionLevel::El2, TrapReason::El1PhysicalTimer);
                }
                if c.el0_in_host && !c.hypervisor.el0_physical_timer {
                    return trap(ExceptionLevel::El2, TrapReason::El0HostPhysicalTimer);
                }
                if c.el0_in_host && c.profile.security == SecurityState::Secure && c.secure_el2 {
                    TimerBank::HostSecurePhysical
                } else if c.el0_in_host && c.profile.security != SecurityState::Secure {
                    TimerBank::HostPhysical
                } else {
                    TimerBank::PhysicalEl1
                }
            } else {
                if (c.profile.el2_enabled && !c.el2_in_host && !c.hypervisor.el1_physical_timer)
                    || (c.el2_in_host && !c.hypervisor.el1_physical_timer_host)
                {
                    return trap(ExceptionLevel::El2, TrapReason::El1PhysicalTimer);
                }
                TimerBank::PhysicalEl1
            }
        }
        TimerKind::Virtual => {
            if c.profile.current_el == ExceptionLevel::El0 {
                if !c.el0_in_host {
                    if !c.kernel.el0_virtual_timer {
                        return el0_trap(c, TrapReason::El0VirtualTimer);
                    }
                    if c.profile.el2_enabled && c.ecv && c.hypervisor.el1_virtual_timer_trap {
                        return trap(ExceptionLevel::El2, TrapReason::El1VirtualTimer);
                    }
                    TimerBank::VirtualEl1
                } else {
                    if !c.hypervisor.el0_virtual_timer {
                        return trap(ExceptionLevel::El2, TrapReason::El0HostVirtualTimer);
                    }
                    if c.profile.security == SecurityState::Secure {
                        TimerBank::HostSecureVirtual
                    } else {
                        TimerBank::HostVirtual
                    }
                }
            } else {
                if c.profile.el2_enabled && c.ecv && c.hypervisor.el1_virtual_timer_trap {
                    return trap(ExceptionLevel::El2, TrapReason::El1VirtualTimer);
                }
                TimerBank::VirtualEl1
            }
        }
    };
    // CTL/CVAL have NV2 '111' redirection; TVAL deliberately does not.
    if c.profile.current_el == ExceptionLevel::El1
        && c.nested_all
        && field != TimerField::TimerValue
    {
        let offset = match (kind, field) {
            (TimerKind::Physical, TimerField::Control) => CNTP_NVMEM_CTL,
            (TimerKind::Physical, TimerField::CompareValue) => CNTP_NVMEM_CVAL,
            (TimerKind::Virtual, TimerField::Control) => CNTV_NVMEM_CTL,
            (TimerKind::Virtual, TimerField::CompareValue) => CNTV_NVMEM_CVAL,
            (_, TimerField::TimerValue) => unreachable!(),
        };
        return Outcome::Backend(BackendRequest::NestedMemory { offset, access });
    }
    let offset = match bank {
        TimerBank::PhysicalEl1 => physical_offset(c),
        TimerBank::VirtualEl1 if c.have_el2 => {
            if !c.el2_aarch64 {
                return Outcome::Unsupported(Requirement::Aarch32El2CounterOffset);
            }
            CounterOffset::VirtualEl2
        }
        _ => CounterOffset::None,
    };
    Outcome::Backend(BackendRequest::Timer {
        bank,
        field,
        access,
        offset,
    })
}

/// TVAL writes sign-extend only the low 32 bits before modular addition.
pub fn compare_from_timer_value(value: u64, physical_count: u64, offset: u64) -> u64 {
    physical_count
        .wrapping_sub(offset)
        .wrapping_add(value as u32 as i32 as i64 as u64)
}
/// Disabled TVAL reads are architecturally ARBITRARY; ask the backend to choose
/// and record a permitted value rather than inventing a successful zero here.
pub fn timer_value(compare: u64, physical_count: u64, offset: u64, enabled: bool) -> Option<u64> {
    enabled.then(|| u64::from(compare.wrapping_sub(physical_count.wrapping_sub(offset)) as u32))
}
/// Return a value plus an exact known-bit mask. ISTATUS is UNKNOWN when disabled.
pub fn control_value(enable_and_mask: u64, condition_met: bool) -> (u64, u64) {
    let control = enable_and_mask & TIMER_WRITABLE_MASK;
    if control & TIMER_ENABLE == 0 {
        (control, !TIMER_ISTATUS)
    } else {
        (
            control | if condition_met { TIMER_ISTATUS } else { 0 },
            u64::MAX,
        )
    }
}
pub fn interrupt_asserted(control: u64, condition_met: bool) -> bool {
    control & TIMER_WRITABLE_MASK == TIMER_ENABLE && condition_met
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(el: ExceptionLevel) -> Context {
        Context {
            aa64: true,
            ecv: true,
            ecv_physical_offset: true,
            secure_el2: false,
            profile: Profile {
                current_el: el,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            highest_el: ExceptionLevel::El1,
            have_el2: false,
            el2_aarch64: true,
            el2_in_host: false,
            el0_in_host: false,
            effective_tge: false,
            scr_ecv_enable: false,
            nested_all: false,
            kernel: KernelControl {
                el0_physical_count: true,
                el0_virtual_count: true,
                el0_physical_timer: true,
                el0_virtual_timer: true,
            },
            hypervisor: HypervisorControl {
                el0_physical_count: true,
                el0_virtual_count: true,
                el1_physical_count: true,
                el1_physical_timer: true,
                el1_physical_timer_host: true,
                el0_physical_timer: true,
                el0_virtual_timer: true,
                ..Default::default()
            },
        }
    }
    fn denied(outcome: Outcome, level: ExceptionLevel, reason: TrapReason) {
        assert_eq!(outcome, trap(level, reason));
    }
    fn timer_register(kind: TimerKind, field: TimerField) -> Register {
        Register::TimerEl0 { kind, field }
    }
    #[test]
    fn canonical_selectors_and_xzr_are_not_access_bypasses() {
        let mut allocated = 0;
        for op0 in 0..4 {
            for op1 in 0..8 {
                for crn in 0..16 {
                    for crm in 0..16 {
                        for op2 in 0..8 {
                            let encoding = Encoding::new(op0, op1, crn, crm, op2);
                            if let Some(register) = decode(encoding) {
                                assert_eq!(register.encoding(), encoding);
                                allocated += 1;
                            }
                        }
                    }
                }
            }
        }
        assert_eq!(allocated, 12);
        let frequency = Encoding::new(
            TIMER_OP0,
            EL0_TIMER_OP1,
            TIMER_CRN,
            COUNTER_CRM,
            FREQUENCY_OP2,
        );
        let mut c = context(ExceptionLevel::El1);
        let request = Request::write(frequency, 31, u64::MAX);
        assert_eq!(
            resolve(request, &c),
            Resolution::BackendRequired(BackendRequest::Frequency(AccessKind::Write { value: 0 }))
        );
        c.profile.current_el = ExceptionLevel::El0;
        c.kernel.el0_physical_count = false;
        c.kernel.el0_virtual_count = false;
        assert!(matches!(
            resolve(Request::read(frequency, 31), &c),
            Resolution::Trap(_)
        ));
        c.kernel.el0_virtual_count = true;
        assert_eq!(
            resolve(Request::read(frequency, 31), &c),
            Resolution::BackendRequired(BackendRequest::Frequency(AccessKind::Read))
        );
        let unowned = Encoding::new(0, 0, 0, 0, 0);
        assert_eq!(
            resolve(Request::read(unowned, 0), &c),
            Resolution::NotHandled
        );
    }
    #[test]
    fn read_only_counter_write_directions_belong_to_allocation_owner() {
        let mut c = context(ExceptionLevel::El0);
        c.aa64 = false;
        c.ecv = false;
        for op2 in [
            PHYSICAL_COUNT_OP2,
            VIRTUAL_COUNT_OP2,
            PHYSICAL_COUNT_SS_OP2,
            VIRTUAL_COUNT_SS_OP2,
        ] {
            let encoding = Encoding::new(TIMER_OP0, EL0_TIMER_OP1, TIMER_CRN, COUNTER_CRM, op2);
            for rt in [0, 31] {
                let request = Request::write(encoding, rt, u64::MAX);
                assert_eq!(resolve(request, &c), Resolution::NotHandled);
            }
        }
    }
    #[test]
    fn feature_and_direction_checks_precede_access_controls() {
        let mut c = context(ExceptionLevel::El0);
        c.aa64 = false;
        c.kernel.el0_physical_count = false;
        assert_eq!(
            plan(Register::CntpctEl0, AccessKind::Read, &c),
            Outcome::Fault(Fault::Undefined)
        );
        c.aa64 = true;
        c.ecv = false;
        for r in [Register::CntpctssEl0, Register::CntvctssEl0] {
            assert_eq!(
                plan(r, AccessKind::Read, &c),
                Outcome::Fault(Fault::Undefined)
            );
        }
        for r in [
            Register::CntpctEl0,
            Register::CntvctEl0,
            Register::CntpctssEl0,
            Register::CntvctssEl0,
        ] {
            assert_eq!(
                plan(r, AccessKind::Write { value: u64::MAX }, &c),
                Outcome::Fault(Fault::Undefined)
            );
        }
    }
    #[test]
    fn frequency_read_gate_is_either_counter_enable_not_both() {
        for p in [false, true] {
            for v in [false, true] {
                for host in [false, true] {
                    let mut c = context(ExceptionLevel::El0);
                    c.el0_in_host = host;
                    c.kernel.el0_physical_count = p;
                    c.kernel.el0_virtual_count = v;
                    c.hypervisor.el0_physical_count = p;
                    c.hypervisor.el0_virtual_count = v;
                    let result = plan(Register::CntfrqEl0, AccessKind::Read, &c);
                    if p || v {
                        assert_eq!(
                            result,
                            Outcome::Backend(BackendRequest::Frequency(AccessKind::Read))
                        );
                    } else {
                        denied(
                            result,
                            if host {
                                ExceptionLevel::El2
                            } else {
                                ExceptionLevel::El1
                            },
                            TrapReason::El0Frequency,
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn frequency_writes_require_highest_implemented_el() {
        let mut c = context(ExceptionLevel::El1);
        assert_eq!(
            plan(
                Register::CntfrqEl0,
                AccessKind::Write { value: 24_000_000 },
                &c
            ),
            Outcome::Backend(BackendRequest::Frequency(AccessKind::Write {
                value: 24_000_000
            }))
        );
        c.highest_el = ExceptionLevel::El2;
        assert_eq!(
            plan(Register::CntfrqEl0, AccessKind::Write { value: 1 }, &c),
            Outcome::Fault(Fault::Undefined)
        );
        c.profile.current_el = ExceptionLevel::El0;
        assert_eq!(
            plan(Register::CntkctlEl1, AccessKind::Write { value: 0 }, &c),
            Outcome::Fault(Fault::Undefined)
        );
    }
    #[test]
    fn physical_count_trap_priority_and_tge_routing() {
        for tge in [false, true] {
            for k in [false, true] {
                for h in [false, true] {
                    let mut c = context(ExceptionLevel::El0);
                    c.profile.el2_enabled = true;
                    c.effective_tge = tge;
                    c.kernel.el0_physical_count = k;
                    c.hypervisor.el1_physical_count = h;
                    let actual = plan(Register::CntpctEl0, AccessKind::Read, &c);
                    if !k {
                        denied(
                            actual,
                            if tge {
                                ExceptionLevel::El2
                            } else {
                                ExceptionLevel::El1
                            },
                            TrapReason::El0PhysicalCount,
                        );
                    } else if !h {
                        denied(actual, ExceptionLevel::El2, TrapReason::El1PhysicalCount);
                    } else {
                        assert!(matches!(
                            actual,
                            Outcome::Backend(BackendRequest::Counter { .. })
                        ));
                    }
                }
            }
        }
        let mut c = context(ExceptionLevel::El0);
        c.el2_in_host = true;
        c.el0_in_host = true;
        c.hypervisor.el1_physical_count = false;
        c.hypervisor.el0_physical_count = false;
        denied(
            plan(Register::CntpctEl0, AccessKind::Read, &c),
            ExceptionLevel::El2,
            TrapReason::El1PhysicalCount,
        );
        c.effective_tge = true;
        denied(
            plan(Register::CntpctEl0, AccessKind::Read, &c),
            ExceptionLevel::El2,
            TrapReason::El0HostPhysicalCount,
        );
    }
    #[test]
    fn virtual_count_host_and_nonhost_gates_are_distinct() {
        let mut c = context(ExceptionLevel::El0);
        c.profile.el2_enabled = true;
        c.kernel.el0_virtual_count = false;
        c.hypervisor.el1_virtual_count_trap = true;
        denied(
            plan(Register::CntvctEl0, AccessKind::Read, &c),
            ExceptionLevel::El1,
            TrapReason::El0VirtualCount,
        );
        c.kernel.el0_virtual_count = true;
        denied(
            plan(Register::CntvctEl0, AccessKind::Read, &c),
            ExceptionLevel::El2,
            TrapReason::El1VirtualCount,
        );
        c.el0_in_host = true;
        c.hypervisor.el0_virtual_count = false;
        denied(
            plan(Register::CntvctEl0, AccessKind::Read, &c),
            ExceptionLevel::El2,
            TrapReason::El0HostVirtualCount,
        );
        c.hypervisor.el0_virtual_count = true;
        assert_eq!(
            plan(Register::CntvctEl0, AccessKind::Read, &c),
            Outcome::Backend(BackendRequest::Counter {
                kind: TimerKind::Virtual,
                offset: CounterOffset::None,
                ordering: CounterOrdering::CounterReads
            })
        );
    }
    #[test]
    fn virtual_offset_survives_el2_disabled_but_present() {
        let mut c = context(ExceptionLevel::El0);
        c.have_el2 = true;
        assert_eq!(
            plan(Register::CntvctssEl0, AccessKind::Read, &c),
            Outcome::Backend(BackendRequest::Counter {
                kind: TimerKind::Virtual,
                offset: CounterOffset::VirtualEl2,
                ordering: CounterOrdering::SelfSynchronized
            })
        );
        c.el2_aarch64 = false;
        assert_eq!(
            plan(Register::CntvctEl0, AccessKind::Read, &c),
            Outcome::Unsupported(Requirement::Aarch32El2CounterOffset)
        );
    }
    #[test]
    fn physical_offset_requires_every_feature_and_enable() {
        for bits in 0u8..32 {
            let mut c = context(ExceptionLevel::El1);
            c.ecv_physical_offset = bits & 1 != 0;
            c.profile.el2_enabled = bits & 2 != 0;
            c.profile.el3_present = bits & 4 != 0;
            c.scr_ecv_enable = bits & 8 != 0;
            c.hypervisor.ecv = bits & 16 != 0;
            let expected = c.ecv_physical_offset
                && c.profile.el2_enabled
                && (!c.profile.el3_present || c.scr_ecv_enable)
                && c.hypervisor.ecv;
            assert_eq!(
                physical_offset(&c),
                if expected {
                    CounterOffset::PhysicalEl2
                } else {
                    CounterOffset::None
                }
            );
        }
    }
    #[test]
    fn all_physical_timer_fields_and_directions_share_ordered_gates() {
        for field in [
            TimerField::Control,
            TimerField::CompareValue,
            TimerField::TimerValue,
        ] {
            for access in [AccessKind::Read, AccessKind::Write { value: u64::MAX }] {
                let mut c = context(ExceptionLevel::El0);
                c.profile.el2_enabled = true;
                c.kernel.el0_physical_timer = false;
                c.hypervisor.el1_physical_timer = false;
                denied(
                    plan(timer_register(TimerKind::Physical, field), access, &c),
                    ExceptionLevel::El1,
                    TrapReason::El0PhysicalTimer,
                );
                c.kernel.el0_physical_timer = true;
                denied(
                    plan(timer_register(TimerKind::Physical, field), access, &c),
                    ExceptionLevel::El2,
                    TrapReason::El1PhysicalTimer,
                );
                c.profile.current_el = ExceptionLevel::El1;
                c.nested_all = true;
                denied(
                    plan(timer_register(TimerKind::Physical, field), access, &c),
                    ExceptionLevel::El2,
                    TrapReason::El1PhysicalTimer,
                );
            }
        }
    }
    #[test]
    fn virtual_timer_trap_requires_ecv_and_precedes_nested_memory() {
        let mut c = context(ExceptionLevel::El1);
        c.nested_all = true;
        c.profile.el2_enabled = true;
        c.hypervisor.el1_virtual_timer_trap = true;
        let r = timer_register(TimerKind::Virtual, TimerField::Control);
        denied(
            plan(r, AccessKind::Read, &c),
            ExceptionLevel::El2,
            TrapReason::El1VirtualTimer,
        );
        c.ecv = false;
        assert_eq!(
            plan(r, AccessKind::Read, &c),
            Outcome::Backend(BackendRequest::NestedMemory {
                offset: CNTV_NVMEM_CTL,
                access: AccessKind::Read
            })
        );
    }
    #[test]
    fn nested_all_redirects_only_control_and_compare() {
        let mut c = context(ExceptionLevel::El1);
        c.nested_all = true;
        for (kind, field, offset) in [
            (TimerKind::Physical, TimerField::Control, CNTP_NVMEM_CTL),
            (
                TimerKind::Physical,
                TimerField::CompareValue,
                CNTP_NVMEM_CVAL,
            ),
            (TimerKind::Virtual, TimerField::Control, CNTV_NVMEM_CTL),
            (
                TimerKind::Virtual,
                TimerField::CompareValue,
                CNTV_NVMEM_CVAL,
            ),
        ] {
            assert_eq!(
                plan(
                    timer_register(kind, field),
                    AccessKind::Write { value: 99 },
                    &c
                ),
                Outcome::Backend(BackendRequest::NestedMemory {
                    offset,
                    access: AccessKind::Write { value: 99 }
                })
            );
        }
        for kind in [TimerKind::Physical, TimerKind::Virtual] {
            assert!(matches!(
                plan(
                    timer_register(kind, TimerField::TimerValue),
                    AccessKind::Read,
                    &c
                ),
                Outcome::Backend(BackendRequest::Timer {
                    field: TimerField::TimerValue,
                    ..
                })
            ));
        }
    }
    #[test]
    fn host_bank_aliases_match_security_rules() {
        let mut c = context(ExceptionLevel::El0);
        c.el0_in_host = true;
        for (secure, sel2, physical, virtual_bank) in [
            (
                false,
                false,
                TimerBank::HostPhysical,
                TimerBank::HostVirtual,
            ),
            (
                true,
                true,
                TimerBank::HostSecurePhysical,
                TimerBank::HostSecureVirtual,
            ),
            (
                true,
                false,
                TimerBank::PhysicalEl1,
                TimerBank::HostSecureVirtual,
            ),
        ] {
            c.profile.security = if secure {
                SecurityState::Secure
            } else {
                SecurityState::NonSecure
            };
            c.secure_el2 = sel2;
            for (kind, bank) in [
                (TimerKind::Physical, physical),
                (TimerKind::Virtual, virtual_bank),
            ] {
                assert!(
                    matches!(plan(timer_register(kind, TimerField::TimerValue), AccessKind::Read, &c), Outcome::Backend(BackendRequest::Timer { bank: b, .. }) if b == bank)
                );
            }
        }
    }
    #[test]
    fn timer_value_signed_low_word_and_modular_arithmetic() {
        let values = [
            0,
            1,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_ffff,
            0x1234_5678_8000_0001,
            u64::MAX,
        ];
        for input in values {
            for count in [0, 1, u64::MAX] {
                for offset in [0, 7, u64::MAX] {
                    let compare = compare_from_timer_value(input, count, offset);
                    assert_eq!(
                        timer_value(compare, count, offset, true),
                        Some(u64::from(input as u32))
                    );
                    assert_eq!(timer_value(compare, count, offset, false), None);
                }
            }
        }
    }
    #[test]
    fn control_read_known_bits_and_interrupt_mask_are_independent() {
        for control in 0..16 {
            for condition in [false, true] {
                let (value, known) = control_value(control, condition);
                assert_eq!(value & TIMER_WRITABLE_MASK, control & TIMER_WRITABLE_MASK);
                assert_eq!(value & !(TIMER_WRITABLE_MASK | TIMER_ISTATUS), 0);
                if control & TIMER_ENABLE != 0 {
                    assert_eq!(known, u64::MAX);
                    assert_eq!(value & TIMER_ISTATUS != 0, condition);
                } else {
                    assert_eq!(known, !TIMER_ISTATUS);
                }
                assert_eq!(
                    interrupt_asserted(control, condition),
                    control & TIMER_ENABLE != 0 && control & TIMER_IMASK == 0 && condition
                );
            }
        }
    }
    #[test]
    fn current_el2_or_el3_never_falls_through_to_success() {
        for el in [ExceptionLevel::El2, ExceptionLevel::El3] {
            let c = context(el);
            assert_eq!(
                plan(Register::CntfrqEl0, AccessKind::Read, &c),
                Outcome::Unsupported(Requirement::CurrentEl2OrEl3)
            );
        }
    }
}
