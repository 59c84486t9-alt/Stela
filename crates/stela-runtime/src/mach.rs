//! ARM64 Mach trap ABI and opt-in host-owned bootstrap port rights.
//! Public XNU f6217f891ac0bb64f3d375211650a4c1ff8ca1ea:
//! osfmk/arm64/bsd_arm64.c and osfmk/kern/syscall_sw.c. This is not an IPC bridge.
use crate::{
    blocks::ThreadState,
    darwin::{SYSCALL_SELECTOR_REGISTER, validate_trap},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{marker::PhantomData, rc::Rc};
use stela_compiler::block::SynchronousTrap;

pub const HOST_PORT_PROFILE: &str = "darwin-host-owned-mach-ports-v1";
pub const REPLY_PORT_TRAP: u32 = 26;
pub const THREAD_SELF_TRAP: u32 = 27;
pub const TASK_SELF_TRAP: u32 = 28;
pub const HOST_SELF_TRAP: u32 = 29;
const MAX_PORT_ACQUISITIONS: usize = 4096;
const FIRST_GUEST_PORT: u32 = 0x101;
const GUEST_PORT_STRIDE: u32 = 0x100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Request {
    pub number: u32,
    pub arguments: Vec<u64>,
}

/// Capture a stopped call without touching memory or invoking a backend.
pub struct PendingCall {
    request: Request,
    issued: ThreadState,
    trap: SynchronousTrap,
}
impl PendingCall {
    pub fn from_trap(
        state: &ThreadState,
        trap: &SynchronousTrap,
        argument_count: usize,
    ) -> Result<Self> {
        validate_trap(state, trap)?;
        let selector = state.registers.x[SYSCALL_SELECTOR_REGISTER] as u32 as i32;
        ensure!(
            selector < 0 && selector != i32::MIN && selector != -3 && selector != -4,
            "selector is not an ordinary Mach trap"
        );
        ensure!(
            argument_count <= 9,
            "Mach LP64 prototype exceeds nine register arguments"
        );
        Ok(Self {
            request: Request {
                number: selector.unsigned_abs(),
                arguments: state.registers.x[..argument_count].to_vec(),
            },
            issued: state.clone(),
            trap: *trap,
        })
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn complete(self, state: &mut ThreadState, value: i32) -> Result<()> {
        ensure!(
            state.pc == self.issued.pc && state.registers == self.issued.registers,
            "pending Mach state changed"
        );
        // Unlike BSD returns, Mach completion does not normalize carry or X1.
        state.registers.x[0] = value as i64 as u64;
        state.pc = self.trap.exception_return_pc;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PortKind {
    ReplyReceive,
    ThreadSend,
    TaskSend,
    HostSend,
}

#[derive(Debug, Serialize)]
pub struct PortRight {
    pub guest_name: u32,
    pub kind: PortKind,
    pub references: u32,
    #[serde(skip)]
    host_name: u32,
}

/// Rights belong to this serialized host task/thread and address space. Guest
/// names never directly authorize host IPC; future services must resolve here.
/// Rc marker prevents moving a current-thread service to a different host thread.
pub struct HostPorts {
    address_space: u64,
    rights: Vec<PortRight>,
    acquisitions: usize,
    _thread: PhantomData<Rc<()>>,
}
impl HostPorts {
    pub fn new(address_space: u64) -> Result<Self> {
        ensure!(
            cfg!(target_os = "macos"),
            "host Mach port services require macOS"
        );
        Ok(Self {
            address_space,
            rights: Vec::new(),
            acquisitions: 0,
            _thread: PhantomData,
        })
    }
    pub fn address_space(&self) -> u64 {
        self.address_space
    }
    pub fn rights(&self) -> &[PortRight] {
        &self.rights
    }
    pub fn request(&mut self, request: &Request) -> Result<i32> {
        ensure!(
            request.arguments.is_empty(),
            "bootstrap port traps take no arguments"
        );
        let kind = match request.number {
            REPLY_PORT_TRAP => PortKind::ReplyReceive,
            THREAD_SELF_TRAP => PortKind::ThreadSend,
            TASK_SELF_TRAP => PortKind::TaskSend,
            HOST_SELF_TRAP => PortKind::HostSend,
            _ => anyhow::bail!(
                "Mach trap {} is not implemented by the host port profile",
                request.number
            ),
        };
        ensure!(
            self.acquisitions < MAX_PORT_ACQUISITIONS,
            "host port acquisition budget exhausted"
        );
        let host = acquire(kind)?;
        if host == 0 {
            return Ok(0);
        } // Genuine host allocation failure / MACH_PORT_NULL.
        self.acquisitions += 1;
        if let Some(right) = self
            .rights
            .iter_mut()
            .find(|r| r.host_name == host && r.kind == kind)
        {
            right.references += 1;
            return Ok(right.guest_name as i32);
        }
        let guest_name = FIRST_GUEST_PORT + self.rights.len() as u32 * GUEST_PORT_STRIDE;
        self.rights.push(PortRight {
            guest_name,
            kind,
            references: 1,
            host_name: host,
        });
        Ok(guest_name as i32)
    }

    /// Query only an owned current-thread send right, never an unchecked guest name.
    pub fn thread_identifier(&self, guest_name: u32) -> Result<u64> {
        let right = self
            .rights
            .iter()
            .find(|right| right.guest_name == guest_name && right.kind == PortKind::ThreadSend)
            .context("guest name is not an owned thread send right")?;
        host_thread_identifier(right.host_name)
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_reply_port() -> u32;
    fn thread_self_trap() -> u32;
    fn task_self_trap() -> u32;
    fn host_self_trap() -> u32;
    fn mach_port_destroy(task: u32, port: u32) -> i32;
    fn mach_port_deallocate(task: u32, port: u32) -> i32;
    fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
}

/// The temporary right is released on query success and failure. Guest port
/// accounting stays unchanged because this is host context construction.
pub(crate) fn current_thread_identifier() -> Result<u64> {
    #[cfg(target_os = "macos")]
    {
        let port = acquire(PortKind::ThreadSend)?;
        ensure!(port != 0, "current-thread send right is unavailable");
        let result = host_thread_identifier(port);
        // SAFETY: this right was acquired above in the current task and has not escaped.
        let released = unsafe { mach_port_deallocate(mach_task_self_, port) };
        ensure!(
            released == 0,
            "release current-thread query right failed: {released}"
        );
        result
    }
    #[cfg(not(target_os = "macos"))]
    anyhow::bail!("host thread identity requires macOS")
}

fn host_thread_identifier(port: u32) -> Result<u64> {
    #[cfg(target_os = "macos")]
    {
        // Pinned osfmk/mach/thread_info.h. Pointer-like host fields never escape.
        #[repr(C)]
        #[derive(Default)]
        struct ThreadIdentifierInfo {
            thread_id: u64,
            thread_handle: u64,
            dispatch_qaddr: u64,
        }
        const THREAD_IDENTIFIER_INFO: i32 = 4;
        const THREAD_IDENTIFIER_INFO_COUNT: u32 =
            (size_of::<ThreadIdentifierInfo>() / size_of::<i32>()) as u32;
        let mut info = ThreadIdentifierInfo::default();
        let mut count = THREAD_IDENTIFIER_INFO_COUNT;
        // SAFETY: the caller owns a current-thread send right. The aligned array
        // has the exact public structure extent; count bounds the kernel write.
        let status = unsafe {
            thread_info(
                port,
                THREAD_IDENTIFIER_INFO,
                (&mut info as *mut ThreadIdentifierInfo).cast(),
                &mut count,
            )
        };
        ensure!(
            status == 0 && count == THREAD_IDENTIFIER_INFO_COUNT,
            "host thread identifier query failed: status={status}, count={count}"
        );
        ensure!(info.thread_id != 0, "host thread identifier is zero");
        Ok(info.thread_id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = port;
        anyhow::bail!("host thread identity requires macOS")
    }
}
fn acquire(kind: PortKind) -> Result<u32> {
    #[cfg(target_os = "macos")]
    // SAFETY: zero-argument host traps return an owned receive/send right;
    // no guest pointer or port number reaches the host kernel.
    unsafe {
        Ok(match kind {
            PortKind::ReplyReceive => mach_reply_port(),
            PortKind::ThreadSend => thread_self_trap(),
            PortKind::TaskSend => task_self_trap(),
            PortKind::HostSend => host_self_trap(),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kind;
        anyhow::bail!("host Mach port services require macOS")
    }
}
impl Drop for HostPorts {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        // SAFETY: only rights acquired above are released, in the same host task.
        // The service is thread-confined and these names are never passed to guests.
        unsafe {
            let task = mach_task_self_;
            for right in &self.rights {
                if right.kind == PortKind::ReplyReceive {
                    mach_port_destroy(task, right.host_name);
                } else {
                    for _ in 0..right.references {
                        mach_port_deallocate(task, right.host_name);
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Event {
    pub trap: SynchronousTrap,
    pub request: Option<Request>,
    pub result: Option<i32>,
    pub declined: Option<String>,
}
pub fn service(state: &mut ThreadState, trap: &SynchronousTrap, ports: &mut HostPorts) -> Event {
    let mut event = Event {
        trap: *trap,
        request: None,
        result: None,
        declined: None,
    };
    let result = (|| -> Result<i32> {
        let pending = PendingCall::from_trap(state, trap, 0)?;
        event.request = Some(pending.request().clone());
        let value = ports.request(pending.request())?;
        pending.complete(state, value)?;
        Ok(value)
    })();
    match result {
        Ok(value) => event.result = Some(value),
        Err(error) => event.declined = Some(error.to_string()),
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::{GuestAddress, GuestState, block::TrapKind};
    #[test]
    fn mach_capture_and_completion_preserve_carry_and_other_state() {
        let trap = SynchronousTrap {
            kind: TrapKind::SupervisorCall,
            immediate: 0x80,
            instruction_pc: GuestAddress(0x1000),
            exception_return_pc: GuestAddress(0x1004),
        };
        for flags in 0..16 {
            for value in [0, 1, i32::MAX, i32::MIN, -1] {
                let mut state = ThreadState {
                    pc: trap.instruction_pc,
                    registers: GuestState {
                        x: std::array::from_fn(|i| 0xdeadc0de12340000 + i as u64),
                        nzcv: flags << 28,
                        v: [[123, 456]; 32],
                        fpcr: 17,
                        fpsr: 29,
                        ..GuestState::default()
                    },
                };
                state.registers.x[16] = 0xfeedfaceffffffe4; // signed32 selector -28
                let pending = PendingCall::from_trap(&state, &trap, 9).unwrap();
                assert_eq!(
                    pending.request(),
                    &Request {
                        number: 28,
                        arguments: state.registers.x[..9].to_vec()
                    }
                );
                let mut expected = state.clone();
                expected.pc = trap.exception_return_pc;
                expected.registers.x[0] = value as i64 as u64;
                pending.complete(&mut state, value).unwrap();
                assert_eq!(state.pc, expected.pc);
                assert_eq!(state.registers, expected.registers);
                let pending = PendingCall::from_trap(
                    &ThreadState {
                        pc: trap.instruction_pc,
                        ..state.clone()
                    },
                    &trap,
                    0,
                )
                .unwrap();
                let before = state.clone();
                assert!(pending.complete(&mut state, 0).is_err());
                assert_eq!(state.pc, before.pc);
                assert_eq!(state.registers, before.registers);
            }
        }
        for selector in [
            0,
            28,
            0x80000000,
            (-3i32) as u32 as u64,
            (-4i32) as u32 as u64,
        ] {
            let mut state = ThreadState {
                pc: trap.instruction_pc,
                registers: GuestState::default(),
            };
            state.registers.x[16] = selector;
            assert!(PendingCall::from_trap(&state, &trap, 0).is_err());
        }
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn host_rights_are_owned_and_guest_names_are_stable_and_distinct() {
        unsafe extern "C" {
            fn mach_port_get_refs(task: u32, name: u32, right: u32, refs: *mut u32) -> i32;
        }
        // SAFETY: the borrowed task name is valid and refs points to owned stack storage.
        let task_host = unsafe { mach_task_self_ };
        let mut baseline = 0;
        assert_eq!(
            unsafe { mach_port_get_refs(task_host, task_host, 0, &mut baseline) },
            0
        );
        let mut ports = HostPorts::new(123).unwrap();
        let task = ports
            .request(&Request {
                number: 28,
                arguments: vec![],
            })
            .unwrap();
        assert_eq!(
            task,
            ports
                .request(&Request {
                    number: 28,
                    arguments: vec![]
                })
                .unwrap()
        );
        let first = ports
            .request(&Request {
                number: 26,
                arguments: vec![],
            })
            .unwrap();
        let second = ports
            .request(&Request {
                number: 26,
                arguments: vec![],
            })
            .unwrap();
        assert_ne!(first, second);
        assert_ne!(first, task);
        assert_eq!(ports.rights[0].references, 2);
        for number in [27, 29] {
            assert!(
                ports
                    .request(&Request {
                        number,
                        arguments: vec![]
                    })
                    .unwrap()
                    > 0
            );
        }
        let before = serde_json::to_string(ports.rights()).unwrap();
        assert!(
            ports
                .request(&Request {
                    number: 31,
                    arguments: vec![]
                })
                .is_err()
        );
        assert_eq!(serde_json::to_string(ports.rights()).unwrap(), before);
        let reply_host = ports
            .rights
            .iter()
            .find(|r| r.guest_name == first as u32)
            .unwrap()
            .host_name;
        let mut refs = 0;
        // SAFETY: queried names belong to this service, and refs is writable local storage.
        assert_eq!(
            unsafe { mach_port_get_refs(task_host, reply_host, 1, &mut refs) },
            0
        );
        assert_eq!(refs, 1);
        drop(ports);
        assert_ne!(
            unsafe { mach_port_get_refs(task_host, reply_host, 1, &mut refs) },
            0
        );
        assert_eq!(
            unsafe { mach_port_get_refs(task_host, task_host, 0, &mut refs) },
            0
        );
        assert_eq!(refs, baseline);
    }
}
