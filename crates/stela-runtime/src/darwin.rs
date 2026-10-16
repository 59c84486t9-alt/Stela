//! Darwin BSD system-call ABI and native service dispatch.
//!
//! Follows XNU `bsd/dev/arm/systemcalls.c`, `bsd/sys/user.h` and
//! `osfmk/arm64/sleh.c`. Only `SVC #0x80` is accepted. Each service is enabled
//! separately; a declined request leaves its pending state unchanged.
use crate::blocks::ThreadState;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use core::error::Error;
use core::fmt;
use serde::{Serialize, ser::SerializeStruct};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{SynchronousTrap, TrapKind},
};
mod copyout;
pub mod crossarch;
pub mod csr;
#[cfg(feature = "std")]
pub mod entropy;
pub mod mach_vm;
pub mod platform;
pub mod process;
pub mod shared_region;

pub const MAX_BSD_ARGUMENTS: usize = 8;
pub(crate) const SYSCALL_SELECTOR_REGISTER: usize = 16;
const CARRY: u32 = 0x20000000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BsdReturnType {
    Int,
    UnsignedInt,
    Offset,
    Address,
    Size,
    SignedSize,
    Unsigned64,
    None,
}

/// System-call table entry supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BsdPrototype {
    pub argument_count: usize,
    pub return_type: BsdReturnType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BsdSelector {
    pub number: u16,
    pub indirect: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BsdRequest {
    pub number: u16,
    pub indirect: bool,
    arguments: [u64; MAX_BSD_ARGUMENTS],
    prototype: BsdPrototype,
}

impl BsdRequest {
    /// The argument slots declared by the call's prototype.
    pub fn arguments(&self) -> &[u64] {
        &self.arguments[..self.prototype.argument_count]
    }

    pub fn prototype(&self) -> BsdPrototype {
        self.prototype
    }
}

impl Serialize for BsdRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut request = serializer.serialize_struct("BsdRequest", 4)?;
        request.serialize_field("number", &self.number)?;
        request.serialize_field("indirect", &self.indirect)?;
        request.serialize_field("arguments", self.arguments())?;
        request.serialize_field("prototype", &self.prototype)?;
        request.end()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BsdCompletion {
    /// The two 32-bit uthread return slots, before ABI normalization.
    Success {
        values: [u32; 2],
    },
    /// A positive Darwin errno supplied by the service; never a host errno cast.
    Error {
        errno: u32,
    },
    Restart,
    /// Requires external context restoration and is deliberately declined.
    JustReturn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbiError {
    UnsupportedTrap { trap_kind: TrapKind, immediate: u16 },
    InvalidTrapState { detail: &'static str },
    PlatformCall { raw_x16: u64 },
    MachCall { number: i32, raw_x16: u64 },
    InvalidPrototype { argument_count: usize },
    StateChanged,
    InvalidErrno { errno: u32 },
    UnsupportedJustReturn,
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTrap { trap_kind, immediate } => write!(f, "Darwin BSD profile requires SVC #0x80, received {trap_kind:?} #{immediate:#x}"),
            Self::InvalidTrapState { detail } => write!(f, "incoherent stopped Darwin call: {detail}"),
            Self::PlatformCall { raw_x16 } => write!(f, "Darwin platform call selector {raw_x16:#x} is unsupported"),
            Self::MachCall { number, .. } => write!(f, "Darwin Mach call selector {number} is unsupported"),
            Self::InvalidPrototype { argument_count } => write!(f, "Darwin LP64 prototype has {argument_count} arguments, maximum is {MAX_BSD_ARGUMENTS}"),
            Self::StateChanged => f.write_str("stopped thread changed after Darwin call capture"),
            Self::InvalidErrno { errno } => write!(f, "Darwin completion requires a positive signed32 errno, received {errno}"),
            Self::UnsupportedJustReturn => f.write_str("EJUSTRETURN requires externally restored thread context; adapter context restoration is unsupported"),
        }
    }
}

impl Error for AbiError {}

pub(crate) fn validate_trap(state: &ThreadState, trap: &SynchronousTrap) -> Result<(), AbiError> {
    validate_trap_parts(state.pc, &state.registers, trap)
}

/// Validate the borrowed registers.
pub(crate) fn validate_trap_parts(
    pc: GuestAddress,
    registers: &GuestState,
    trap: &SynchronousTrap,
) -> Result<(), AbiError> {
    if trap.kind != TrapKind::SupervisorCall || trap.immediate != 0x80 {
        return Err(AbiError::UnsupportedTrap {
            trap_kind: trap.kind,
            immediate: trap.immediate,
        });
    }
    if pc != trap.instruction_pc || !trap.instruction_pc.0.is_multiple_of(4) {
        return Err(AbiError::InvalidTrapState {
            detail: "thread PC must identify the aligned SVC instruction",
        });
    }
    if trap.instruction_pc.0.checked_add(4) != Some(trap.exception_return_pc.0) {
        return Err(AbiError::InvalidTrapState {
            detail: "SVC preferred return PC must be instruction PC plus four",
        });
    }
    if registers.nzcv & !0xf0000000 != 0 {
        return Err(AbiError::InvalidTrapState {
            detail: "state contains unsupported NZCV bits",
        });
    }
    Ok(())
}

/// Classify without mutating state, allowing the caller to select its prototype.
/// XNU first converts X16 to signed32 for dispatch. BSD number/argument selection
/// separately tests the full saved X16 for zero and truncates the number to u16.
pub fn classify_bsd_call(
    state: &ThreadState,
    trap: &SynchronousTrap,
) -> Result<BsdSelector, AbiError> {
    classify_bsd_call_parts(state.pc, &state.registers, trap)
}

pub(crate) fn classify_bsd_call_parts(
    pc: GuestAddress,
    registers: &GuestState,
    trap: &SynchronousTrap,
) -> Result<BsdSelector, AbiError> {
    validate_trap_parts(pc, registers, trap)?;
    let raw_x16 = registers.x[SYSCALL_SELECTOR_REGISTER];
    let dispatch = raw_x16 as u32 as i32;
    if dispatch == i32::MIN {
        return Err(AbiError::PlatformCall { raw_x16 });
    }
    if dispatch < 0 {
        return Err(AbiError::MachCall {
            number: dispatch,
            raw_x16,
        });
    }
    let indirect = raw_x16 == 0;
    Ok(BsdSelector {
        number: if indirect {
            registers.x[0] as u16
        } else {
            raw_x16 as u16
        },
        indirect,
    })
}

/// A trapped request and the full thread state before the service. The service
/// has not run yet.
#[derive(Debug)]
pub struct PendingBsdCall {
    request: BsdRequest,
    issued: ThreadState,
    trap: SynchronousTrap,
}

impl PendingBsdCall {
    pub fn from_trap(
        state: &ThreadState,
        trap: &SynchronousTrap,
        prototype: BsdPrototype,
    ) -> Result<Self, AbiError> {
        Self::from_registers(state.pc, &state.registers, trap, prototype)
    }

    pub(crate) fn from_registers(
        pc: GuestAddress,
        registers: &GuestState,
        trap: &SynchronousTrap,
        prototype: BsdPrototype,
    ) -> Result<Self, AbiError> {
        let selector = classify_bsd_call_parts(pc, registers, trap)?;
        if prototype.argument_count > MAX_BSD_ARGUMENTS {
            return Err(AbiError::InvalidPrototype {
                argument_count: prototype.argument_count,
            });
        }
        // The pinned LP64 C implementation copies up to eight u64 values from
        // x[0] for direct calls or x[1] for indirect calls: no guest-stack read.
        let start = usize::from(selector.indirect);
        let mut arguments = [0; MAX_BSD_ARGUMENTS];
        arguments[..prototype.argument_count]
            .copy_from_slice(&registers.x[start..start + prototype.argument_count]);
        Ok(Self {
            request: BsdRequest {
                number: selector.number,
                indirect: selector.indirect,
                arguments,
                prototype,
            },
            issued: ThreadState {
                pc,
                registers: registers.clone(),
            },
            trap: *trap,
        })
    }

    pub fn request(&self) -> &BsdRequest {
        &self.request
    }

    /// Apply a backend result after checking that the stopped state is
    /// unchanged. Declined services must not call this. An invalid reply, or a
    /// context restoration that is declined, leaves all state unchanged. BSD
    /// completion writes only the return registers, carry and PC.
    pub fn complete(
        self,
        state: &mut ThreadState,
        completion: BsdCompletion,
    ) -> Result<(), AbiError> {
        if state.pc != self.issued.pc {
            return Err(AbiError::StateChanged);
        }
        state.pc = self.complete_registers(&mut state.registers, completion)?;
        Ok(())
    }

    /// Apply a backend result to the register bank. The issued copy is only
    /// used for validation; the caller sets PC.
    pub(crate) fn complete_registers(
        self,
        registers: &mut GuestState,
        completion: BsdCompletion,
    ) -> Result<GuestAddress, AbiError> {
        if *registers != self.issued.registers {
            return Err(AbiError::StateChanged);
        }
        match completion {
            BsdCompletion::JustReturn => return Err(AbiError::UnsupportedJustReturn),
            BsdCompletion::Error { errno } if errno == 0 || errno > i32::MAX as u32 => {
                return Err(AbiError::InvalidErrno { errno });
            }
            _ => {}
        }
        registers.nzcv &= !CARRY;
        let mut next_pc = self.trap.exception_return_pc;
        match completion {
            BsdCompletion::Success { values } => match self.request.prototype.return_type {
                BsdReturnType::Int => {
                    registers.x[0] = values[0] as i32 as i64 as u64;
                    registers.x[1] = values[1] as i32 as i64 as u64;
                }
                BsdReturnType::UnsignedInt => {
                    registers.x[0] = u64::from(values[0]);
                    registers.x[1] = u64::from(values[1]);
                }
                BsdReturnType::Offset
                | BsdReturnType::Address
                | BsdReturnType::Size
                | BsdReturnType::SignedSize
                | BsdReturnType::Unsigned64 => {
                    registers.x[0] = u64::from(values[0]) | (u64::from(values[1]) << u32::BITS);
                    registers.x[1] = 0;
                }
                BsdReturnType::None => {}
            },
            BsdCompletion::Error { errno } => {
                registers.x[0] = u64::from(errno);
                registers.x[1] = 0;
                registers.nzcv |= CARRY;
            }
            BsdCompletion::Restart => next_pc = self.trap.instruction_pc,
            BsdCompletion::JustReturn => {
                unreachable!("context restoration declined before mutation")
            }
        }
        Ok(next_pc)
    }
}

/// The captured request and the backend's completion or decline.
#[derive(Debug, Serialize)]
pub struct BsdServiceEvent {
    pub trap: SynchronousTrap,
    pub request: Option<BsdRequest>,
    pub completion: Option<BsdCompletion>,
    pub declined: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ServiceRunOutcome {
    /// Diagnostics from the retained owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_observation: Option<serde_json::Value>,
    pub execution: crate::blocks::RunOutcome,
    pub services: Vec<BsdServiceEvent>,
    pub mach_services: Vec<crate::mach::Event>,
    pub thread_services: Vec<crate::thread::Event>,
    pub crossarch_services: Vec<BsdServiceEvent>,
    pub shared_region_services: Vec<BsdServiceEvent>,
    pub csr_services: Vec<BsdServiceEvent>,
    pub entropy_services: Vec<BsdServiceEvent>,
    pub process_services: Vec<BsdServiceEvent>,
    pub mach_vm_services: Vec<crate::mach::Event>,
    pub mach_vm_map_services: Vec<mach_vm::map::Event>,
}
impl ServiceRunOutcome {
    /// Preserve the common report shape when no OS service backend is selected.
    pub fn unserviced(execution: crate::blocks::RunOutcome) -> Self {
        Self {
            execution,
            protected_observation: None,
            services: Vec::new(),
            mach_services: Vec::new(),
            thread_services: Vec::new(),
            crossarch_services: Vec::new(),
            shared_region_services: Vec::new(),
            csr_services: Vec::new(),
            entropy_services: Vec::new(),
            process_services: Vec::new(),
            mach_vm_services: Vec::new(),
            mach_vm_map_services: Vec::new(),
        }
    }
}
#[derive(Default)]
pub struct ExecutionServices<'a> {
    pub protected_system: Option<&'a mut crate::system::state::SystemState>,
    pub protected_controls:
        Option<&'a mut crate::system::process_memory::FixedProcessMemoryControls>,
    pub protected_memory:
        Option<&'a mut crate::memory::domain::MemoryThread<crate::memory::policy::MemoryControls>>,
    pub protected_context: Option<&'a mut stela_compiler::context::ExecutionContext>,
    pub protected_event: Option<&'a crate::system::events::EventEndpoint>,
    pub protected_fp: Option<&'a crate::system::scalable_controls::fp::FpControlOwner<'a>>,
    pub mach_ports: Option<&'a mut crate::mach::HostPorts>,
    pub thread: Option<&'a mut crate::thread::Context>,
    pub data_vm: bool,
    pub mach_vm: bool,
    pub mach_vm_map: bool,
    pub crossarch: bool,
    /// The caller has established that the guest has no shared-region
    /// attachment.
    pub absent_shared_region: bool,
    pub csr: Option<&'a csr::ArmSecurityPolicy>,
    pub entropy: bool,
    pub pauth: Option<&'a crate::pauth::Context>,
    pub clock: Option<&'a mut crate::clock::Context>,
}

/// Explicit ARM process VM profile; ordinary data protections only. Executable
/// transitions, trusted/TPRO flags and MAC/code-sign policy remain unsupported.
pub const DATA_VM_PROFILE: &str = "darwin-arm64-va47-page16k-data-mprotect-v1";
pub const GUEST_PAGE_BYTES: u64 = 16 * 1024;

/// Service BSD call 74 (mprotect) on owned guest pages; guest pointers are
/// never used directly. Unsupported requests stay pending. Follows XNU
/// `bsd/kern/kern_mman.c`: W implies R, and guest pages are 16 KiB whatever the
/// host page size.
#[cfg(feature = "std")]
pub fn service_data_mprotect(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    memory: &mut crate::memory::OwnedMemory,
    runtime: &crate::blocks::BlockRuntime,
) -> BsdServiceEvent {
    let mut event = BsdServiceEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> anyhow::Result<BsdCompletion> {
        anyhow::ensure!(memory.is_usable(), "guest address space is unusable");
        let selector = classify_bsd_call(state, trap)?;
        anyhow::ensure!(
            selector.number == 74,
            "BSD service {} is not implemented by the data VM profile",
            selector.number
        );
        let pending = PendingBsdCall::from_trap(
            state,
            trap,
            BsdPrototype {
                argument_count: 3,
                return_type: BsdReturnType::Int,
            },
        )?;
        let request = *pending.request();
        event.request = Some(request);
        let [address, length, raw_prot]: [u64; 3] = request.arguments().try_into()?;
        let prot = raw_prot as u32;
        anyhow::ensure!(
            prot & !7 == 0,
            "special/unknown mprotect flags require a reviewed platform policy"
        );
        anyhow::ensure!(
            prot & 4 == 0,
            "executable protection requires source publication/invalidation"
        );
        let completion = if !address.is_multiple_of(GUEST_PAGE_BYTES) {
            BsdCompletion::Error { errno: 22 }
        } else if let Some(end) = address
            .checked_add(length)
            .and_then(|e| e.checked_add(GUEST_PAGE_BYTES - 1))
            .map(|e| e & !(GUEST_PAGE_BYTES - 1))
        {
            if address >= (1 << 47) || end > (1 << 47) {
                BsdCompletion::Error { errno: 12 }
            } else if length == 0 {
                BsdCompletion::Success { values: [0, 0] }
            } else {
                anyhow::ensure!(
                    !runtime.source_overlaps(address, end - address),
                    "data protection overlaps a registered code snapshot"
                );
                let writable = prot & 2 != 0;
                let readable = prot & 3 != 0;
                match memory.protect_data(address, end - address, readable, writable) {
                    Ok(()) => BsdCompletion::Success { values: [0, 0] },
                    Err(crate::memory::ProtectionError::MaximumProtection) => {
                        BsdCompletion::Error { errno: 13 }
                    }
                    Err(crate::memory::ProtectionError::UnmappedRange) => {
                        BsdCompletion::Error { errno: 12 }
                    }
                    Err(crate::memory::ProtectionError::InvalidRange) => {
                        BsdCompletion::Error { errno: 22 }
                    }
                    Err(crate::memory::ProtectionError::HostFailure {
                        errno: Some(e),
                        rollback_succeeded: true,
                    }) if e == libc::ENOMEM => BsdCompletion::Error { errno: 12 },
                    Err(crate::memory::ProtectionError::HostFailure {
                        errno: Some(e),
                        rollback_succeeded: true,
                    }) if e == libc::EACCES => BsdCompletion::Error { errno: 13 },
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            BsdCompletion::Error { errno: 22 }
        };
        // Exclusive thread/owner borrows exclude mutation between capture and
        // completion; service code does not otherwise touch architectural state.
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

/// Run native dispatch with the selected data-VM, cross-architecture and
/// thread/Mach services. Unknown services stop at their trap, and one budget
/// counts every block across resumptions.
///
/// # Safety
/// All `BlockRuntime` direct-RAM requirements apply, and `memory` must cover
/// the data the trusted code uses. No concurrent guest execution or code or
/// data mutation is allowed; executable transitions are declined.
/// `absent_shared_region` requires that the process has no shared-region
/// attachment (file and anonymous RAM do not create one). For a checked profile
/// this call is the whole run of a new software PE: its protected resources and
/// every asynchronous producer are uniquely borrowed, and nothing may resume
/// the PE afterwards.
#[cfg(feature = "std")]
pub unsafe fn run_services(
    runtime: &mut crate::blocks::BlockRuntime,
    state: &mut ThreadState,
    stop: Option<GuestAddress>,
    budget: usize,
    memory: &mut crate::memory::OwnedMemory,
    mut services: ExecutionServices<'_>,
) -> anyhow::Result<ServiceRunOutcome> {
    use crate::blocks::{RunOutcome, StopReason};
    if runtime.profile().checked_memory().is_some() {
        // SAFETY: this route inherits the fresh, uniquely retained software-PE
        // contract below and never falls back to an unowned entry.
        return unsafe {
            crate::blocks::retirement::run_protected_services(
                runtime, state, stop, budget, memory, services,
            )
        };
    }
    anyhow::ensure!(
        services.protected_system.is_none()
            && services.protected_controls.is_none()
            && services.protected_memory.is_none()
            && services.protected_context.is_none()
            && services.protected_event.is_none()
            && services.protected_fp.is_none(),
        "protected owners require a checked block profile"
    );
    let mut aggregate: Option<RunOutcome> = None;
    let mut events = Vec::new();
    let mut mach_events = Vec::new();
    let mut thread_events = Vec::new();
    let mut crossarch_events = Vec::new();
    let mut shared_region_events = Vec::new();
    let mut csr_events = Vec::new();
    let mut entropy_events = Vec::new();
    let mut process_events = Vec::new();
    let mut mach_vm_events = Vec::new();
    let mut mach_vm_map_events = Vec::new();
    anyhow::ensure!(
        services.mach_ports.is_none() || services.thread.is_none(),
        "thread services and independent Mach ports cannot have different owners"
    );
    if let Some(thread) = services.thread.as_ref() {
        anyhow::ensure!(
            thread.address_space() == runtime.address_space(),
            "thread context belongs to another guest address space"
        );
    }
    if let Some(ports) = services.mach_ports.as_ref() {
        anyhow::ensure!(
            ports.address_space() == runtime.address_space(),
            "Mach ports belong to another guest address space"
        );
    }
    let mut executed = 0;
    loop {
        anyhow::ensure!(
            memory.is_usable(),
            "refusing execution in an unusable guest address space"
        );
        let mut part = unsafe {
            if let Some(thread) = services
                .thread
                .as_deref()
                .filter(|_| runtime.profile().supports_thread_registers())
            {
                runtime.run_with_thread(
                    state,
                    stop,
                    budget - executed,
                    thread,
                    services.pauth,
                    services.clock.as_deref_mut(),
                )?
            } else {
                match (services.pauth, services.clock.as_deref_mut()) {
                    (Some(pauth), Some(clock)) => {
                        runtime.run_with_clock(state, stop, budget - executed, pauth, clock)?
                    }
                    (Some(pauth), None) => {
                        runtime.run_with_pauth(state, stop, budget - executed, pauth)?
                    }
                    (None, None) => runtime.run(state, stop, budget - executed)?,
                    (None, Some(_)) => anyhow::bail!("clock execution requires a PAC context"),
                }
            }
        };
        executed += part.blocks_executed;
        let trap = match &part.reason {
            StopReason::SynchronousTrap { trap } => Some(*trap),
            _ => None,
        };
        if let Some(total) = &mut aggregate {
            total.reason = part.reason;
            total.blocks_executed = executed;
            total.compiled_blocks += part.compiled_blocks;
            total.disk_cache_hits += part.disk_cache_hits;
            total.memory_cache_hits += part.memory_cache_hits;
            total.last_exit = part.last_exit.or(total.last_exit);
            total
                .pointer_authentication_events
                .append(&mut part.pointer_authentication_events);
            total.clock_events.append(&mut part.clock_events);
            total
                .thread_register_events
                .append(&mut part.thread_register_events);
        } else {
            aggregate = Some(part);
        }
        let Some(trap) = trap else {
            break;
        };
        let serviced = if let Some(thread) = services
            .thread
            .as_deref_mut()
            .filter(|_| crate::thread::handles(state, &trap))
        {
            let event = crate::thread::service(state, &trap, thread);
            let serviced = event.completed();
            thread_events.push(event);
            serviced
        } else if services.mach_vm && mach_vm::handles(state, &trap) {
            let ports = services
                .thread
                .as_deref()
                .map(|thread| thread.ports())
                .or(services.mach_ports.as_deref());
            if let Some(ports) = ports {
                let event = mach_vm::service(state, &trap, ports, memory, runtime);
                let serviced = event.result.is_some();
                mach_vm_events.push(event);
                serviced
            } else {
                false
            }
        } else if services.mach_vm_map && mach_vm::map::handles(state, &trap) {
            let ports = services
                .thread
                .as_deref()
                .map(|thread| thread.ports())
                .or(services.mach_ports.as_deref());
            if let Some(ports) = ports {
                let event = mach_vm::map::service(state, &trap, ports, memory, runtime);
                let serviced = event.result.is_some();
                mach_vm_map_events.push(event);
                serviced
            } else {
                false
            }
        } else if (state.registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32) < 0 {
            let ports = if let Some(thread) = services.thread.as_deref_mut() {
                Some(thread.ports_mut())
            } else {
                services.mach_ports.as_deref_mut()
            };
            if let Some(ports) = ports {
                let event = crate::mach::service(state, &trap, ports);
                let serviced = event.result.is_some();
                mach_events.push(event);
                serviced
            } else {
                false
            }
        } else if services.crossarch && crossarch::handles(state, &trap) {
            let event = crossarch::service(state, &trap);
            let serviced = event.completion.is_some();
            crossarch_events.push(event);
            serviced
        } else if services.absent_shared_region && shared_region::handles(state, &trap) {
            let event = shared_region::service_absent(state, &trap);
            let serviced = event.completion.is_some();
            shared_region_events.push(event);
            serviced
        } else if let Some(policy) = services.csr.filter(|_| csr::handles(state, &trap)) {
            let event = csr::service(state, &trap, memory, policy);
            let serviced = event.completion.is_some();
            csr_events.push(event);
            serviced
        } else if let Some(context) = services
            .thread
            .as_deref()
            .and_then(crate::thread::Context::process)
            .filter(|_| process::handles(state, &trap))
        {
            let event = process::service(state, &trap, context);
            let serviced = event.completion.is_some();
            process_events.push(event);
            serviced
        } else if services.entropy && entropy::handles(state, &trap) {
            let event = entropy::service(state, &trap, memory);
            let serviced = event.completion.is_some();
            entropy_events.push(event);
            serviced
        } else if services.data_vm {
            let event = service_data_mprotect(state, &trap, memory, runtime);
            let serviced = event.completion.is_some();
            events.push(event);
            serviced
        } else {
            false
        };
        if !serviced {
            break;
        }
        let total = aggregate.as_mut().expect("one native dispatch outcome");
        if stop == Some(state.pc) {
            total.reason = StopReason::StopAddress;
            break;
        }
        if executed == budget {
            total.reason = StopReason::BudgetExhausted;
            break;
        }
    }
    Ok(ServiceRunOutcome {
        execution: aggregate.expect("one native dispatch outcome"),
        protected_observation: None,
        services: events,
        mach_services: mach_events,
        thread_services: thread_events,
        crossarch_services: crossarch_events,
        shared_region_services: shared_region_events,
        csr_services: csr_events,
        entropy_services: entropy_events,
        process_services: process_events,
        mach_vm_services: mach_vm_events,
        mach_vm_map_services: mach_vm_map_events,
    })
}

/// Data-only compatibility entry; Mach services remain absent unless supplied.
///
/// # Safety
/// The same direct-RAM requirements as `run_services` apply.
#[cfg(feature = "std")]
pub unsafe fn run_data_vm(
    runtime: &mut crate::blocks::BlockRuntime,
    state: &mut ThreadState,
    stop: Option<GuestAddress>,
    budget: usize,
    memory: &mut crate::memory::OwnedMemory,
    mut services: ExecutionServices<'_>,
) -> anyhow::Result<ServiceRunOutcome> {
    services.data_vm = true;
    unsafe { run_services(runtime, state, stop, budget, memory, services) }
}

#[cfg(test)]
mod tests;
