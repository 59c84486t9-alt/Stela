//! UEFI RNG discovery and capture into the shared finite entropy pool.
use crate::Result;
pub use stela_boot_core::entropy::{Algorithm, Pool};
use stela_contracts::refuse;

/// Read advertised UEFI RNG output while boot services are active.
/// The parent owns protocol discovery/selection and its source provenance;
/// the borrowed protocol must be closed before ExitBootServices. There are
/// no post-EBS protocol calls, implicit algorithm default or CPU fallback.
///
/// UEFI2.11 37.5 requires exact output length and forbids reuse across calls.
/// Recognized SP800-90 256-bit DRBGs or the explicit raw source are accepted.
/// Other advertised algorithms require separate validation. Protocol
/// failure, including NOT_READY, aborts/clears the entire finite capture.
pub fn prepare<const BYTES: usize, const REQUESTS: usize>(
    rng: &mut uefi::proto::rng::Rng,
    widths: [usize; REQUESTS],
) -> Result<Pool<BYTES, REQUESTS>> {
    use uefi::proto::rng::RngAlgorithmType as Guid;
    let table =
        uefi::table::system_table_raw().ok_or(refuse!("UEFI system table is unavailable"))?;
    // SAFETY: the UEFI crate's initialized system table is valid. This
    // mirrors its boot-services activity check; no EBS may race this call.
    if unsafe { table.as_ref() }.boot_services.is_null() {
        return Err(refuse!("UEFI RNG capture requires active boot services"));
    }
    let mut algorithms = [Guid::EMPTY_ALGORITHM; 32];
    let advertised = rng
        .get_info(&mut algorithms)
        .map_err(|_| refuse!("UEFI RNG algorithm inventory failed or exceeds its bound"))?;
    let (algorithm, guid) = [
        (Algorithm::Hash256, Guid::ALGORITHM_SP800_90_HASH_256),
        (Algorithm::Hmac256, Guid::ALGORITHM_SP800_90_HMAC_256),
        (Algorithm::Ctr256, Guid::ALGORITHM_SP800_90_CTR_256),
        (Algorithm::Raw, Guid::ALGORITHM_RAW),
    ]
    .into_iter()
    .find(|(_, guid)| advertised.contains(guid))
    .ok_or(refuse!("UEFI RNG has no qualified advertised algorithm"))?;
    Pool::capture(widths, algorithm, |_, destination| {
        rng.get_rng(Some(guid), destination)
            .map_err(|error| match error.status() {
                uefi::Status::NOT_READY => {
                    refuse!("UEFI RNG has insufficient entropy for the complete request")
                }
                uefi::Status::UNSUPPORTED => refuse!("UEFI RNG rejected its advertised algorithm"),
                uefi::Status::INVALID_PARAMETER => {
                    refuse!("UEFI RNG rejected the requested output range")
                }
                status => refuse!("UEFI RNG failed to produce entropy", ?status),
            })
    })
}

/// Keep one private ChaCha20 seed before firmware services end. Firmware
/// RNG is preferred; checked architectural hardware randomness is the
/// fallback. Failed sources never publish partial seed material.
pub fn retain_seed() -> Result<(crate::handoff::Region, &'static str)> {
    let mut seed = [0; 32];
    let source = match firmware_seed(&mut seed) {
        Ok(()) => "uefi-rng",
        Err(_) => match hardware_seed(&mut seed) {
            Ok(source) => source,
            Err(error) => {
                erase(&mut seed);
                return Err(error);
            }
        },
    };
    let page = match uefi::boot::allocate_pages(
        uefi::boot::AllocateType::AnyPages,
        uefi::boot::MemoryType::LOADER_DATA,
        1,
    ) {
        Ok(page) => page,
        Err(_) => {
            erase(&mut seed);
            return Err(refuse!("no private page for the host entropy seed"));
        }
    };
    // SAFETY: this fresh loader page is exclusive and holds all 32 bytes.
    unsafe { core::ptr::copy_nonoverlapping(seed.as_ptr(), page.as_ptr(), seed.len()) };
    erase(&mut seed);
    Ok((
        crate::handoff::Region {
            physical: page.as_ptr() as u64,
            bytes: 32,
        },
        source,
    ))
}

fn firmware_seed(seed: &mut [u8; 32]) -> Result<()> {
    use uefi::{boot, proto::rng::Rng};
    let handle = boot::get_handle_for_protocol::<Rng>()
        .map_err(|_| refuse!("UEFI RNG protocol is unavailable"))?;
    let mut rng = boot::open_protocol_exclusive::<Rng>(handle)
        .map_err(|_| refuse!("UEFI RNG protocol could not be opened"))?;
    let mut pool = prepare::<32, 1>(&mut rng, [32])?;
    pool.fill(seed)
}

fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: the byte is exclusively borrowed and clearing must survive
        // dead-store elimination after the source's last ordinary use.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn hardware_seed(seed: &mut [u8; 32]) -> Result<&'static str> {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let maximum = __cpuid(0).eax;
    let rdseed = maximum >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0;
    let rdrand = maximum >= 1 && __cpuid(1).ecx & (1 << 30) != 0;
    if !rdseed && !rdrand {
        return Err(refuse!("no qualified firmware or CPU entropy source"));
    }
    for chunk in seed.chunks_mut(8) {
        let Some(word) = hardware_word(rdseed) else {
            erase(seed);
            return Err(refuse!("CPU entropy source did not complete the seed"));
        };
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(if rdseed { "rdseed" } else { "rdrand" })
}

fn hardware_word(seed: bool) -> Option<u64> {
    for _ in 0..128 {
        let (value, ready): (u64, u8);
        // SAFETY: CPUID checked this instruction before entry. It changes
        // only its destination and flags, and executes before native takeover.
        unsafe {
            if seed {
                core::arch::asm!("rdseed {}", "setc {}", out(reg) value, out(reg_byte) ready,
                    options(nomem, nostack));
            } else {
                core::arch::asm!("rdrand {}", "setc {}", out(reg) value, out(reg_byte) ready,
                    options(nomem, nostack));
            }
        }
        if ready != 0 {
            return Some(value);
        }
        core::hint::spin_loop();
    }
    None
}
