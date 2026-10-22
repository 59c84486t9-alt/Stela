//! Native x86-64 MM-index VRAM reads through the canonical register lease.
//! No mapping, allocator, IRQ/reset guard, TMR ownership or GPU READY is created.
use super::native_mmio::{Error as WindowError, RegisterWindow};
use core::ffi::{c_int, c_void};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Window(WindowError),
    InvalidRange,
    /// Numeric preflight failed before any register or destination effect.
    Preflight(c_int),
}

unsafe extern "C" {
    fn stela_amd_vram_mm_read(
        registers: *mut c_void,
        register_bytes: usize,
        vram_bytes: u64,
        position: u64,
        data: *mut u32,
        size: usize,
    ) -> c_int;
}

/// Read through the exact original synchronous NO_KIQ MM-index protocol.
/// Success means the original void CPU transaction loop returned, not that a
/// device acknowledged the read or that the bytes satisfy discovery integrity.
/// The retained window is borrowed throughout; nothing allocates or escapes.
///
/// # Safety
/// The caller holds the genuine same-device D0/bridge, reset/removal and
/// MM-index/IRQ exclusion for the WHOLE call, including every other firmware,
/// driver and C window user. Execution is on the owner's allowed native CPU and
/// process context. The canonical window must be UC with original ordered
/// MMIO32 semantics; these three original low direct registers must be valid on
/// the actual matched device. This does not permit bypassing indirect PCIe,
/// KIQ, RLCG or XCC routing elsewhere. `vram_bytes` is actual accessible GPU VRAM
/// in this epoch, not domain IOVA/host RAM or a guessed capacity. The caller
/// owns/excludes writes to the requested VRAM region (including actual TMR
/// reservation when reading discovery). Output is distinct exclusive CPU RAM.
/// Unexpected access faults require the platform's real fail-stop/retention
/// policy; neither this call nor Drop invents rollback after index writes.
pub unsafe fn read(
    window: &RegisterWindow<'_>,
    vram_bytes: u64,
    position: u64,
    output: &mut [u32],
) -> Result<(), Error> {
    let size = output
        .len()
        .checked_mul(size_of::<u32>())
        .ok_or(Error::InvalidRange)?;
    // SAFETY: the same borrowed retained lease and all genuine owner conditions
    // are required by this unsafe API; the pointer never escapes this call.
    let registers = unsafe { window.native_base() }.map_err(Error::Window)?;
    // SAFETY: exclusive slice and same live canonical window, original C width
    // and ABI; native code checks all numeric bounds before any register effect.
    let status = unsafe {
        stela_amd_vram_mm_read(
            registers.as_ptr().cast(),
            window.bytes(),
            vram_bytes,
            position,
            output.as_mut_ptr(),
            size,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Preflight(status))
    }
}
