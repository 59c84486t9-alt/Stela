//! Run Stela's native translation of a case at the guest's own addresses.
use crate::{CODE_PAGE, CODE_REGION, CODE_REGION_BYTES, Case, DATA_BYTES, DATA_WINDOW, Outcome};
use anyhow::{Context, Result, ensure};
use std::{
    ptr::NonNull,
    sync::{Mutex, OnceLock},
};
use stela_compiler::GuestState;

const PAGE_BYTES: usize = 0x1000;

/// Host mappings at the guest code region and data window. One process-wide
/// instance exists; the lock serializes every native case.
struct Windows {
    code: NonNull<u8>,
    data: NonNull<u8>,
}

// SAFETY: the mappings are owned for the process lifetime and only touched
// while the surrounding mutex is held.
unsafe impl Send for Windows {}

fn windows() -> Result<&'static Mutex<Windows>> {
    static WINDOWS: OnceLock<Mutex<Windows>> = OnceLock::new();
    if let Some(windows) = WINDOWS.get() {
        return Ok(windows);
    }
    let windows = Windows {
        code: map_at(CODE_REGION, CODE_REGION_BYTES)?,
        data: map_at(DATA_WINDOW, DATA_BYTES)?,
    };
    Ok(WINDOWS.get_or_init(|| Mutex::new(windows)))
}

/// Map fresh RW memory at exactly `address`, refusing to replace a mapping.
fn map_at(address: u64, bytes: usize) -> Result<NonNull<u8>> {
    // SAFETY: a hinted anonymous mapping never replaces existing memory; the
    // result is checked against the requested address before use.
    let pointer = unsafe {
        libc::mmap(
            address as *mut libc::c_void,
            bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    ensure!(pointer != libc::MAP_FAILED, "cannot map {address:#x}");
    if pointer as u64 != address {
        // SAFETY: release the mapping the kernel placed elsewhere.
        unsafe { libc::munmap(pointer, bytes) };
        anyhow::bail!("{address:#x} is already mapped in this process");
    }
    NonNull::new(pointer.cast()).context("null mapping")
}

/// Executable copy of native code, unmapped on drop.
struct Executable {
    pointer: NonNull<u8>,
    bytes: usize,
}

impl Executable {
    fn new(code: &[u8]) -> Result<Self> {
        ensure!(!code.is_empty(), "empty native code");
        let bytes = code.len().next_multiple_of(PAGE_BYTES);
        // SAFETY: fresh anonymous RW memory, checked before use.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        ensure!(pointer != libc::MAP_FAILED, "cannot map native code");
        let executable = Self {
            pointer: NonNull::new(pointer.cast()).context("null mapping")?,
            bytes,
        };
        // SAFETY: the mapping holds at least `code.len()` writable bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), executable.pointer.as_ptr(), code.len());
            ensure!(
                libc::mprotect(pointer, bytes, libc::PROT_READ | libc::PROT_EXEC) == 0,
                "cannot make native code executable"
            );
        }
        Ok(executable)
    }
}

impl Drop for Executable {
    fn drop(&mut self) {
        // SAFETY: this object owns the whole mapping.
        unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.bytes) };
    }
}

fn mxcsr() -> u32 {
    let mut value = 0;
    // SAFETY: STMXCSR stores the 32-bit control register to a valid location.
    unsafe { std::arch::asm!("stmxcsr [{}]", in(reg) &mut value, options(nostack)) };
    value
}

fn set_mxcsr(value: u32) {
    // SAFETY: restores a value previously read from MXCSR.
    unsafe { std::arch::asm!("ldmxcsr [{}]", in(reg) &value, options(nostack)) };
}

/// Run `native`, compiled from `case.code` at [`CODE_PAGE`], against the case.
///
/// # Safety
///
/// `native` must be Stela's leaf translation of `case.code`, and the original
/// must have completed on the oracle, so every access stays in the windows.
pub unsafe fn run(native: &[u8], case: &Case) -> Result<Outcome> {
    let windows = windows()?.lock().expect("native windows lock");
    let executable = Executable::new(native)?;
    let mut state = case.state.clone();
    // SAFETY: both windows are owned, writable and sized as copied here.
    unsafe {
        let page = (CODE_PAGE - CODE_REGION) as usize;
        let code = std::slice::from_raw_parts_mut(windows.code.as_ptr().add(page), PAGE_BYTES);
        code.fill(0);
        for (word, bytes) in case.code.iter().zip(code.as_chunks_mut::<4>().0) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
        std::slice::from_raw_parts_mut(windows.data.as_ptr(), DATA_BYTES)
            .copy_from_slice(&case.data);
    }
    let entry: extern "sysv64" fn(*mut GuestState) =
        // SAFETY: the mapping holds a leaf that follows the guest-state ABI.
        unsafe { std::mem::transmute(executable.pointer.as_ptr()) };
    let saved = mxcsr();
    entry(&mut state);
    set_mxcsr(saved);
    // SAFETY: the data window stays mapped and is no longer written.
    let data = unsafe { std::slice::from_raw_parts(windows.data.as_ptr(), DATA_BYTES) }.into();
    Ok(Outcome {
        state,
        data,
        exception: None,
    })
}
