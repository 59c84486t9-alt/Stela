//! Raw single-copy-atomic parts for the coherent Normal-WB memory profile.
//!
//! The caller owns address translation, permission checks, mapping lifetime and
//! reservation tracking. These helpers never create Rust references into guest
//! RAM. They implement one part inside an aligned 16-byte SCA quantity; ordinary
//! accesses split across quantities belong to the caller.

use stela_compiler::TargetCpu;

const BYTE_BYTES: usize = 1;
const HALFWORD_BYTES: usize = 2;
const WORD_BYTES: usize = 4;
const DOUBLEWORD_BYTES: usize = 8;
const QUADWORD_BYTES: usize = 16;
const BITS_PER_BYTE: usize = 8;
const DOUBLEWORD_BITS: usize = DOUBLEWORD_BYTES * BITS_PER_BYTE;
const SCA_BYTES: usize = QUADWORD_BYTES;
const SCA_OFFSET_MASK: usize = SCA_BYTES - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AccessError {
    UnsupportedHost,
    InvalidWidth,
    CrossesScaQuantity,
    MissingAtomicLoad16,
    MissingCx16,
}

fn validate_part(address: usize, bytes: usize) -> Result<(), AccessError> {
    if !cfg!(target_arch = "x86_64") {
        return Err(AccessError::UnsupportedHost);
    }
    if !matches!(
        bytes,
        BYTE_BYTES | HALFWORD_BYTES | WORD_BYTES | DOUBLEWORD_BYTES | QUADWORD_BYTES
    ) {
        return Err(AccessError::InvalidWidth);
    }
    if (address & SCA_OFFSET_MASK) + bytes > SCA_BYTES {
        return Err(AccessError::CrossesScaQuantity);
    }
    Ok(())
}

/// Actual host read footprint, for permission and lifetime preflight.
///
/// The coherent WB profile allows reading the enclosing aligned quantity. It
/// excludes byte-granular permissions, device registers and debug watchpoints.
pub(super) fn read_footprint(
    address: usize,
    bytes: usize,
    target: TargetCpu,
) -> Result<(usize, usize), AccessError> {
    validate_part(address, bytes)?;
    if (address & (DOUBLEWORD_BYTES - 1)) + bytes <= DOUBLEWORD_BYTES {
        return Ok((address, bytes));
    }
    if !target.supports(TargetCpu::AtomicLoad16) {
        return Err(AccessError::MissingAtomicLoad16);
    }
    Ok((address & !SCA_OFFSET_MASK, SCA_BYTES))
}

/// Read one atomic part, returning its zero-extended little-endian value.
///
/// # Safety
/// The complete `read_footprint` must be live, readable coherent Normal-WB RAM
/// throughout this call. No Rust reference may alias concurrently mutated RAM.
/// The selected target's capabilities must have been checked against the actual
/// host. The caller must provide any guest ordering and reservation protocol.
/// Host faults are not resumable through this function without a separate adapter.
pub(super) unsafe fn read_part(
    pointer: *const u8,
    bytes: usize,
    target: TargetCpu,
) -> Result<u128, AccessError> {
    let (address, footprint_bytes) = read_footprint(pointer as usize, bytes, target)?;
    #[cfg(target_arch = "x86_64")]
    {
        if footprint_bytes == SCA_BYTES {
            // SAFETY: the caller prevalidates the entire aligned snapshot and
            // actual host AtomicLoad16 capability. No write permission is used.
            let snapshot = unsafe { read_quadword(address as *const u8) };
            let shifted = snapshot >> ((pointer as usize & SCA_OFFSET_MASK) * BITS_PER_BYTE);
            let mask = u128::MAX >> ((QUADWORD_BYTES - bytes) * BITS_PER_BYTE);
            return Ok(shifted & mask);
        }
        let value: u64;
        // SAFETY: validated exact-width part fits inside eight aligned bytes.
        // Both Intel and AMD guarantee these cached Normal-WB reads atomically.
        unsafe {
            match bytes {
                BYTE_BYTES => core::arch::asm!(
                    "movzx {value:e}, byte ptr [{pointer}]",
                    value = out(reg) value,
                    pointer = in(reg) pointer,
                    options(nostack, preserves_flags),
                ),
                HALFWORD_BYTES => core::arch::asm!(
                    "movzx {value:e}, word ptr [{pointer}]",
                    value = out(reg) value,
                    pointer = in(reg) pointer,
                    options(nostack, preserves_flags),
                ),
                WORD_BYTES => core::arch::asm!(
                    "mov {value:e}, dword ptr [{pointer}]",
                    value = out(reg) value,
                    pointer = in(reg) pointer,
                    options(nostack, preserves_flags),
                ),
                DOUBLEWORD_BYTES => core::arch::asm!(
                    "mov {value}, qword ptr [{pointer}]",
                    value = out(reg) value,
                    pointer = in(reg) pointer,
                    options(nostack, preserves_flags),
                ),
                _ => unreachable!("validated scalar read width"),
            }
        }
        Ok(u128::from(value))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (address, footprint_bytes);
        Err(AccessError::UnsupportedHost)
    }
}

/// Write the low `bytes` of `value` as one atomic little-endian part.
///
/// # Safety
/// The exact part must remain live, readable and writable coherent Normal-WB RAM
/// throughout this call, without aliasing Rust references. The selected target's
/// capabilities must have been checked against the actual host. The caller owns
/// guest ordering, reservation invalidation and preflight before acquiring gates.
/// Host faults need a separate resumable adapter. The 16-byte retry loop can retry
/// under competing writers; it does not provide a wait-free progress guarantee.
pub(super) unsafe fn write_part(
    pointer: *mut u8,
    bytes: usize,
    value: u128,
    target: TargetCpu,
) -> Result<(), AccessError> {
    validate_part(pointer as usize, bytes)?;
    if bytes == QUADWORD_BYTES && !target.supports(TargetCpu::Cx16) {
        return Err(AccessError::MissingCx16);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: caller supplies stable prevalidated coherent RAM and actual host
    // capabilities. Scalar exchange supplies explicit strong WB ordering.
    unsafe {
        if bytes == QUADWORD_BYTES {
            write_quadword(pointer, value);
            Ok(())
        } else {
            exchange_part(pointer, bytes, value).map(|_| ())
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = value;
        Err(AccessError::UnsupportedHost)
    }
}

/// Exchange one exact scalar part with full coherent-WB memory ordering.
/// This strong operation is independent of any future ordinary-store recipe.
///
/// # Safety
/// The exact 1/2/4/8-byte part is live readable/writable coherent Normal-WB RAM,
/// pinned through this call and disjoint from Rust references. Caller owns
/// source permission/tag checks, writer participation and guest ordering intent.
/// Unexpected host faults require a separate resumable adapter.
#[inline]
pub(super) unsafe fn exchange_part(
    pointer: *mut u8,
    bytes: usize,
    value: u128,
) -> Result<u128, AccessError> {
    if !matches!(
        bytes,
        BYTE_BYTES | HALFWORD_BYTES | WORD_BYTES | DOUBLEWORD_BYTES
    ) {
        return Err(AccessError::InvalidWidth);
    }
    validate_part(pointer as usize, bytes)?;
    #[cfg(target_arch = "x86_64")]
    // SAFETY: validated exact-width part; memory XCHG is implicitly locked and
    // its default asm memory clobber also prevents compiler memory reordering.
    unsafe {
        let old = match bytes {
            BYTE_BYTES => {
                let mut old = value as u8;
                core::arch::asm!(
                    "xchg byte ptr [{pointer}], {value}",
                    pointer = in(reg) pointer,
                    value = inout(reg_byte) old,
                    options(nostack, preserves_flags),
                );
                u64::from(old)
            }
            HALFWORD_BYTES => {
                let mut old = value as u64;
                core::arch::asm!(
                    "xchg word ptr [{pointer}], {value:x}",
                    pointer = in(reg) pointer,
                    value = inout(reg) old,
                    options(nostack, preserves_flags),
                );
                old & u64::from(u16::MAX)
            }
            WORD_BYTES => {
                let mut old = value as u64;
                core::arch::asm!(
                    "xchg dword ptr [{pointer}], {value:e}",
                    pointer = in(reg) pointer,
                    value = inout(reg) old,
                    options(nostack, preserves_flags),
                );
                old & u64::from(u32::MAX)
            }
            DOUBLEWORD_BYTES => {
                let mut old = value as u64;
                core::arch::asm!(
                    "xchg qword ptr [{pointer}], {value}",
                    pointer = in(reg) pointer,
                    value = inout(reg) old,
                    options(nostack, preserves_flags),
                );
                old
            }
            _ => unreachable!("validated scalar exchange width"),
        };
        Ok(u128::from(old))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = value;
        Err(AccessError::UnsupportedHost)
    }
}

#[cfg(target_arch = "x86_64")]
unsafe fn read_quadword(pointer: *const u8) -> u128 {
    let low: u64;
    let high: u64;
    // SAFETY: caller guarantees an aligned readable quantity and AtomicLoad16.
    // Legacy SSE2 MOVDQA needs no OS AVX state; the checked AVX hardware bit
    // establishes this load's atomicity independently of usable AVX arithmetic.
    unsafe {
        core::arch::asm!(
            "movdqa xmm0, xmmword ptr [{pointer}]",
            "movq {low}, xmm0",
            "psrldq xmm0, {half_bytes}",
            "movq {high}, xmm0",
            pointer = in(reg) pointer,
            low = out(reg) low,
            high = out(reg) high,
            half_bytes = const DOUBLEWORD_BYTES,
            out("xmm0") _,
            options(nostack, preserves_flags),
        );
    }
    u128::from(low) | (u128::from(high) << DOUBLEWORD_BITS)
}

#[cfg(target_arch = "x86_64")]
unsafe fn write_quadword(pointer: *mut u8, value: u128) {
    // SAFETY: caller guarantees a live aligned readable/writable quantity and
    // Cx16. Each iteration is one actual atomic 16-byte update. A failed first
    // compare acquires the next expected value; no torn initial read is needed.
    // LLVM reserves RBX, so save and restore it inside the assembly statement.
    unsafe {
        core::arch::asm!(
            "mov r9, rbx",
            "mov rbx, r8",
            "2:",
            "lock cmpxchg16b xmmword ptr [rsi]",
            "jnz 2b",
            "mov rbx, r9",
            in("rsi") pointer,
            in("r8") value as u64,
            in("rcx") (value >> DOUBLEWORD_BITS) as u64,
            inout("rax") 0u64 => _,
            inout("rdx") 0u64 => _,
            out("r9") _,
            options(nostack),
        );
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
