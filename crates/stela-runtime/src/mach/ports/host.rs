//! Host Mach calls on privately owned port names.
use super::{KERN_SUCCESS, PortKind, RightKind, RightState};
use anyhow::{Result, bail, ensure};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_reply_port() -> u32;
    fn thread_self_trap() -> u32;
    fn task_self_trap() -> u32;
    fn host_self_trap() -> u32;
    fn mach_port_allocate(task: u32, right: u32, name: *mut u32) -> i32;
    fn mach_port_type(task: u32, name: u32, bits: *mut u32) -> i32;
    fn mach_port_destroy(task: u32, port: u32) -> i32;
    fn mach_port_deallocate(task: u32, port: u32) -> i32;
    fn thread_info(thread: u32, flavor: i32, info: *mut i32, count: *mut u32) -> i32;
}

pub(super) fn acquire(role: PortKind) -> Result<u32> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: zero-argument host acquisition; the returned owned name never
        // escapes to a guest or authorizes a second namespace.
        unsafe {
            match role {
                PortKind::ReplyReceive => Ok(mach_reply_port()),
                PortKind::ThreadSend => Ok(thread_self_trap()),
                PortKind::TaskSend => Ok(task_self_trap()),
                PortKind::HostSend => Ok(host_self_trap()),
                PortKind::Ordinary => bail!("ordinary ports require typed allocation"),
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = role;
        bail!("host Mach port services require macOS")
    }
}

pub(super) fn allocate(right: RightKind) -> Result<(i32, u32)> {
    #[cfg(target_os = "macos")]
    {
        let mut name = 0;
        // SAFETY: target is actual current host task; output is private storage.
        let status = unsafe { mach_port_allocate(mach_task_self_, right as u32, &mut name) };
        Ok((status, name))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = right;
        bail!("host Mach port services require macOS")
    }
}

pub(super) fn port_type(name: u32) -> Result<(i32, u32)> {
    #[cfg(target_os = "macos")]
    {
        let mut bits = 0;
        // SAFETY: name resolved from this owner's ledger; private output word.
        let status = unsafe { mach_port_type(mach_task_self_, name, &mut bits) };
        Ok((status, bits))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        bail!("host Mach port services require macOS")
    }
}

pub(super) fn deallocate(name: u32) -> Result<i32> {
    #[cfg(target_os = "macos")]
    // SAFETY: one actual reference acquired and retained by this owner.
    unsafe {
        Ok(mach_port_deallocate(mach_task_self_, name))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = name;
        bail!("host Mach port services require macOS")
    }
}

pub(super) fn release(name: u32, state: RightState) -> Result<i32> {
    match state {
        RightState::Receive | RightState::SendReceive | RightState::PortSet => {
            #[cfg(target_os = "macos")]
            // SAFETY: dedicated receive/set resource has no external aliases or
            // notifications in this profile. It belongs only to this owner.
            unsafe {
                Ok(mach_port_destroy(mach_task_self_, name))
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = name;
                bail!("host Mach port services require macOS")
            }
        }
        RightState::Send | RightState::SendOnce | RightState::DeadName => deallocate(name),
    }
}

pub(crate) fn current_thread_identifier() -> Result<u64> {
    let port = acquire(PortKind::ThreadSend)?;
    ensure!(port != 0, "current-thread send right is unavailable");
    let result = thread_identifier(port);
    let status = deallocate(port)?;
    ensure!(
        status == KERN_SUCCESS,
        "release current-thread query right failed: {status}"
    );
    result
}

pub(super) fn thread_identifier(port: u32) -> Result<u64> {
    #[cfg(target_os = "macos")]
    {
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
        // SAFETY: actual owned thread send right and correctly sized private
        // output; pointer-like host fields never leave this function.
        let status = unsafe {
            thread_info(
                port,
                THREAD_IDENTIFIER_INFO,
                (&mut info as *mut ThreadIdentifierInfo).cast(),
                &mut count,
            )
        };
        ensure!(
            status == KERN_SUCCESS && count == THREAD_IDENTIFIER_INFO_COUNT,
            "host thread identifier query failed: status={status}, count={count}"
        );
        ensure!(info.thread_id != 0, "host thread identifier is zero");
        Ok(info.thread_id)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = port;
        bail!("host thread identity requires macOS")
    }
}
