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
mod tests;
