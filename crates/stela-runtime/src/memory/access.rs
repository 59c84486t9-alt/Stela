//! Single-copy-atomic access parts within an aligned 16-byte quantity. Callers
//! handle translation, permissions, mapping lifetime and reservations.

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

/// Read one atomic part and return its zero-extended little-endian value.
///
/// # Safety
/// The whole `read_footprint` must be live, readable, coherent write-back RAM
/// for the call, with no Rust reference aliasing concurrently mutated RAM. The
/// target's features must have been checked against the host. The caller
/// provides guest ordering and reservations. Host faults are not recoverable
/// here.
pub(super) unsafe fn read_part(
    pointer: *const u8,
    bytes: usize,
    target: TargetCpu,
) -> Result<u128, AccessError> {
    let (address, footprint_bytes) = read_footprint(pointer as usize, bytes, target)?;
    #[cfg(target_arch = "x86_64")]
    {
        if footprint_bytes == SCA_BYTES {
            // SAFETY: the caller validated the whole aligned snapshot and the
            // host's 16-byte atomic load; nothing is written.
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
/// The part must stay live, readable and writable coherent write-back RAM for
/// the call, with no aliasing Rust references. The target's features must have
/// been checked against the host. The caller provides guest ordering,
/// reservation invalidation and validation before taking any gate. Host faults
/// are not recoverable here. The 16-byte loop may retry under competing
/// writers; it is not wait-free.
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
    // SAFETY: the caller supplies stable, validated, coherent RAM and the host
    // features. The scalar exchange gives strong write-back ordering.
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
    // SAFETY: the caller guarantees a live, aligned, readable and writable
    // quantity and CMPXCHG16B. Each iteration is one atomic 16-byte update; a
    // failed first compare loads the next expected value, so no separate
    // initial read can tear. LLVM reserves RBX, so it is saved and restored
    // inside the asm.
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
mod tests {
    use super::*;

    #[repr(align(16))]
    struct Quantity([u8; SCA_BYTES]);

    #[test]
    fn footprints_decline_unsupported_widths_crossings_and_capabilities() {
        for bytes in [0, 3, 5, 9, 17, usize::MAX] {
            assert_eq!(
                read_footprint(0, bytes, TargetCpu::Baseline),
                Err(AccessError::InvalidWidth)
            );
        }
        assert_eq!(
            read_footprint(SCA_BYTES - 1, HALFWORD_BYTES, TargetCpu::AtomicLoad16),
            Err(AccessError::CrossesScaQuantity)
        );
        assert_eq!(
            read_footprint(DOUBLEWORD_BYTES - 1, HALFWORD_BYTES, TargetCpu::Cx16),
            Err(AccessError::MissingAtomicLoad16)
        );
        assert_eq!(
            read_footprint(0, QUADWORD_BYTES, TargetCpu::AtomicLoad16),
            Ok((0, SCA_BYTES))
        );
        // Declines occur before touching a deliberately inaccessible pointer.
        assert_eq!(
            unsafe {
                write_part(
                    std::ptr::null_mut(),
                    QUADWORD_BYTES,
                    0,
                    TargetCpu::AtomicLoad16,
                )
            },
            Err(AccessError::MissingCx16)
        );
    }

    #[test]
    fn all_valid_offsets_preserve_neighbors_and_zero_extend_reads() {
        let target = TargetCpu::detect();
        let original = std::array::from_fn(|index| index as u8 * 13);
        let value = 0xfedc_ba98_7654_3210_1234_5678_9abc_def0u128;
        for bytes in [
            BYTE_BYTES,
            HALFWORD_BYTES,
            WORD_BYTES,
            DOUBLEWORD_BYTES,
            QUADWORD_BYTES,
        ] {
            for offset in 0..=SCA_BYTES - bytes {
                let mut memory = Quantity(original);
                let pointer = memory.0.as_mut_ptr().wrapping_add(offset);
                let footprint = read_footprint(pointer as usize, bytes, target);
                if footprint.is_ok() {
                    let mut expected = [0u8; QUADWORD_BYTES];
                    expected[..bytes].copy_from_slice(&original[offset..offset + bytes]);
                    assert_eq!(
                        unsafe { read_part(pointer, bytes, target) }.unwrap(),
                        u128::from_le_bytes(expected)
                    );
                } else {
                    assert_eq!(footprint, Err(AccessError::MissingAtomicLoad16));
                }
                if bytes == QUADWORD_BYTES && !target.supports(TargetCpu::Cx16) {
                    continue;
                }
                unsafe { write_part(pointer, bytes, value, target) }.unwrap();
                let mut expected = original;
                expected[offset..offset + bytes].copy_from_slice(&value.to_le_bytes()[..bytes]);
                assert_eq!(memory.0, expected, "width={bytes} offset={offset}");
                if footprint.is_ok() {
                    let mask = u128::MAX >> ((QUADWORD_BYTES - bytes) * BITS_PER_BYTE);
                    assert_eq!(
                        unsafe { read_part(pointer, bytes, target) }.unwrap(),
                        value & mask
                    );
                }
            }
        }
    }
    #[test]
    fn scalar_exchange_declines_invalid_widths_and_sca_crossings_before_access() {
        for bytes in [0, 3, 5, QUADWORD_BYTES, usize::MAX] {
            // Invalid shape must decline without reaching native memory.
            assert_eq!(
                unsafe { exchange_part(std::ptr::null_mut(), bytes, 0) },
                Err(AccessError::InvalidWidth)
            );
        }
        assert_eq!(
            unsafe { exchange_part((SCA_BYTES - 1) as *mut u8, HALFWORD_BYTES, 0) },
            Err(AccessError::CrossesScaQuantity)
        );
    }

    #[test]
    fn scalar_exchange_returns_normalized_old_and_preserves_neighbors() {
        let original = std::array::from_fn(|index| u8::MAX - index as u8);
        let replacement = 0xfedc_ba98_7654_3210_1234_5678_9abc_def0_u128;
        for (bytes, offset) in [
            (BYTE_BYTES, DOUBLEWORD_BYTES - 1),
            (HALFWORD_BYTES, DOUBLEWORD_BYTES - 1),
            (WORD_BYTES, DOUBLEWORD_BYTES - 1),
            (DOUBLEWORD_BYTES, DOUBLEWORD_BYTES - 1),
        ] {
            let mut memory = Quantity(original);
            let pointer = memory.0.as_mut_ptr().wrapping_add(offset);
            let mut expected_old = [0_u8; QUADWORD_BYTES];
            expected_old[..bytes].copy_from_slice(&original[offset..offset + bytes]);
            // SAFETY: exact private live storage, no simultaneous aliases or
            // observers; the scalar part stays within one aligned SCA quantity.
            let old = unsafe { exchange_part(pointer, bytes, replacement) }.unwrap();
            assert_eq!(old, u128::from_le_bytes(expected_old));
            let mut expected = original;
            expected[offset..offset + bytes].copy_from_slice(&replacement.to_le_bytes()[..bytes]);
            assert_eq!(memory.0, expected, "width={bytes} offset={offset}");
        }
    }
}
