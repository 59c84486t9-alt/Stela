//! Serialized native-thread identity, owned Mach rights and guest ARM TSD.
//!
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea: thread_info.h,
//! machine_routines.c platform_syscall and pcb.c machine_thread_set_tsd_base.
//! One context represents one guest thread on the current host thread. It does
//! not create threads, schedule them or modify host TLS/FS/GS.
use crate::{
    blocks::ThreadState,
    darwin::{
        self, BsdCompletion, BsdPrototype, BsdRequest, BsdReturnType, PendingBsdCall,
        SYSCALL_SELECTOR_REGISTER, platform,
    },
    mach::{self, HostPorts},
    memory::DIRECT_RAM_USER_END,
    process,
};
use alloc::rc::Rc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString};
use anyhow::{Result, ensure};
use serde::Serialize;
use stela_compiler::block::SynchronousTrap;

pub const PROFILE_ID: &str = "darwin-host-thread-arm-tsd-v1";
pub const THREAD_SELFID_SYSCALL: u16 = 372;
const RETURN_WORD_BITS: u32 = u32::BITS;

/// Explicit guest vm_map_max input, independently bounded by the native RAM
/// profile. The host allocation limit is not a substitute for a guest VM contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmMaximum(u64);
impl VmMaximum {
    pub fn new(address: u64) -> Result<Self> {
        ensure!(
            address > 0 && address <= DIRECT_RAM_USER_END,
            "guest VM maximum must be explicit, nonzero and within the direct-RAM user range"
        );
        Ok(Self(address))
    }
    pub fn address(self) -> u64 {
        self.0
    }
    pub fn sanitize_thread_specific_data(self, address: u64) -> u64 {
        if address > self.0 { 0 } else { address }
    }
}

/// HostPorts' Rc marker confines both rights and identity to the same host thread.
pub struct Context {
    ports: HostPorts,
    identity: u64,
    thread_specific_data: u64,
    vm_maximum: VmMaximum,
    process: Option<Rc<process::Context>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Snapshot {
    pub profile_id: &'static str,
    pub address_space: u64,
    pub thread_id: u64,
    pub thread_specific_data: u64,
    pub guest_vm_max_address: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<process::Snapshot>,
}
impl Context {
    pub fn native(address_space: u64, vm_maximum: VmMaximum) -> Result<Self> {
        let ports = HostPorts::new(address_space)?;
        let identity = mach::current_thread_identifier()?;
        Ok(Self {
            ports,
            identity,
            thread_specific_data: 0,
            vm_maximum,
            process: None,
        })
    }
    /// Bind this actual thread/task owner to one explicitly declared process.
    /// Acquires the existing native thread identity and rights exactly once.
    pub fn native_in_process(process: Rc<process::Context>, vm_maximum: VmMaximum) -> Result<Self> {
        let mut thread = Self::native(process.address_space(), vm_maximum)?;
        thread.process = Some(process);
        Ok(thread)
    }
    pub fn process(&self) -> Option<&process::Context> {
        self.process.as_deref()
    }
    pub fn address_space(&self) -> u64 {
        self.ports.address_space()
    }
    pub fn thread_specific_data(&self) -> u64 {
        self.thread_specific_data
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            profile_id: PROFILE_ID,
            address_space: self.address_space(),
            thread_id: self.identity,
            thread_specific_data: self.thread_specific_data,
            guest_vm_max_address: self.vm_maximum.address(),
            process: self.process.as_ref().map(|process| process.snapshot()),
        }
    }
    pub(crate) fn identity_completion(&self, request: &BsdRequest) -> Result<BsdCompletion> {
        ensure!(
            request.number == THREAD_SELFID_SYSCALL
                && request.prototype().argument_count == 0
                && request.prototype().return_type == BsdReturnType::Unsigned64,
            "request is not the thread identity prototype"
        );
        Ok(BsdCompletion::Success {
            values: [
                self.identity as u32,
                (self.identity >> RETURN_WORD_BITS) as u32,
            ],
        })
    }

    /// Complete only the borrowed ABI bank, then commit actual TSD infallibly.
    /// No actual PC, host TLS or guest pointer access is available here.
    pub(crate) fn complete_platform_registers(
        &mut self,
        pending: platform::PendingCall,
        registers: &mut stela_compiler::GuestState,
    ) -> Result<PlatformResult> {
        let before = self.thread_specific_data;
        let (completion, next) = match *pending.request() {
            platform::Request::SetThreadSpecificData { address } => (
                platform::Completion::SetThreadSpecificData,
                self.vm_maximum.sanitize_thread_specific_data(address),
            ),
            platform::Request::GetThreadSpecificData => (
                platform::Completion::GetThreadSpecificData { address: before },
                before,
            ),
        };
        let next_pc = pending.complete_registers(registers, completion)?;
        self.thread_specific_data = next;
        Ok(PlatformResult {
            next_pc,
            completion,
            before,
            after: next,
        })
    }

    pub fn ports(&self) -> &HostPorts {
        &self.ports
    }
    pub fn ports_mut(&mut self) -> &mut HostPorts {
        &mut self.ports
    }
}

// Only hosted thread events read the prior value back.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) struct PlatformResult {
    pub next_pc: stela_compiler::GuestAddress,
    pub completion: platform::Completion,
    pub before: u64,
    pub after: u64,
}

#[derive(Debug, Serialize)]
pub struct IdentityEvent {
    pub trap: SynchronousTrap,
    pub request: Option<BsdRequest>,
    pub completion: Option<BsdCompletion>,
    pub declined: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct PlatformEvent {
    pub trap: SynchronousTrap,
    pub request: Option<platform::Request>,
    pub completion: Option<platform::Completion>,
    pub thread_specific_data_before: u64,
    pub thread_specific_data_after: u64,
    pub declined: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(tag = "kind", content = "event", rename_all = "snake_case")]
pub enum Event {
    Identity(IdentityEvent),
    Platform(PlatformEvent),
}
impl Event {
    pub fn completed(&self) -> bool {
        match self {
            Self::Identity(event) => event.completion.is_some(),
            Self::Platform(event) => event.completion.is_some(),
        }
    }
}

/// Classify only owned services; ordinary BSD calls remain with their backends.
pub fn handles(state: &ThreadState, trap: &SynchronousTrap) -> bool {
    let selector = state.registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32;
    selector == platform::PLATFORM_CALL_SELECTOR
        || darwin::classify_bsd_call(state, trap)
            .is_ok_and(|selector| selector.number == THREAD_SELFID_SYSCALL)
}

pub fn service(state: &mut ThreadState, trap: &SynchronousTrap, context: &mut Context) -> Event {
    if state.registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32
        == platform::PLATFORM_CALL_SELECTOR
    {
        Event::Platform(service_platform(state, trap, context))
    } else {
        Event::Identity(service_identity(state, trap, context))
    }
}

fn service_identity(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    context: &Context,
) -> IdentityEvent {
    let mut event = IdentityEvent {
        trap: *trap,
        request: None,
        completion: None,
        declined: None,
    };
    let result = (|| -> Result<BsdCompletion> {
        let pending = PendingBsdCall::from_trap(
            state,
            trap,
            BsdPrototype {
                argument_count: 0,
                return_type: BsdReturnType::Unsigned64,
            },
        )?;
        event.request = Some(*pending.request());
        ensure!(
            pending.request().number == THREAD_SELFID_SYSCALL,
            "BSD call is not thread_selfid"
        );
        let completion = context.identity_completion(pending.request())?;
        pending.complete(state, completion)?;
        Ok(completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

fn service_platform(
    state: &mut ThreadState,
    trap: &SynchronousTrap,
    context: &mut Context,
) -> PlatformEvent {
    let before = context.thread_specific_data;
    let mut event = PlatformEvent {
        trap: *trap,
        request: None,
        completion: None,
        thread_specific_data_before: before,
        thread_specific_data_after: before,
        declined: None,
    };
    let result = (|| -> Result<platform::Completion> {
        let pending = platform::PendingCall::from_trap(state, trap)?;
        let request = *pending.request();
        event.request = Some(request);
        let result = context.complete_platform_registers(pending, &mut state.registers)?;
        state.pc = result.next_pc;
        event.thread_specific_data_after = result.after;
        Ok(result.completion)
    })();
    match result {
        Ok(completion) => event.completion = Some(completion),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

#[cfg(test)]
mod tests;
