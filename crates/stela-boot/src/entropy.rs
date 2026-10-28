//! UEFI RNG discovery and capture into the shared finite entropy pool.
pub use stela_boot_core::entropy::{Algorithm, Pool};

/// Read actual advertised UEFI RNG output while boot services are active.
/// The parent owns protocol discovery/selection and its source provenance;
/// the borrowed protocol must be closed before ExitBootServices. There are
/// no post-EBS protocol calls, implicit algorithm default or CPU fallback.
///
/// UEFI2.11 37.5 requires exact output length and forbids reuse across calls.
/// Recognized SP800-90 256-bit DRBGs or the explicit raw source are accepted.
/// Other advertised algorithms require separate qualification. Protocol
/// failure, including NOT_READY, aborts/clears the entire finite capture.
pub fn prepare<const BYTES: usize, const REQUESTS: usize>(
    rng: &mut uefi::proto::rng::Rng,
    widths: [usize; REQUESTS],
) -> Result<Pool<BYTES, REQUESTS>, &'static str> {
    use uefi::proto::rng::RngAlgorithmType as Guid;
    let table = uefi::table::system_table_raw().ok_or("UEFI system table is unavailable")?;
    // SAFETY: the UEFI crate's initialized system table is valid. This
    // mirrors its boot-services activity check; no EBS may race this call.
    if unsafe { table.as_ref() }.boot_services.is_null() {
        return Err("UEFI RNG capture requires active boot services");
    }
    let mut algorithms = [Guid::EMPTY_ALGORITHM; 32];
    let advertised = rng
        .get_info(&mut algorithms)
        .map_err(|_| "UEFI RNG algorithm inventory failed or exceeds its bound")?;
    let (algorithm, guid) = [
        (Algorithm::Hash256, Guid::ALGORITHM_SP800_90_HASH_256),
        (Algorithm::Hmac256, Guid::ALGORITHM_SP800_90_HMAC_256),
        (Algorithm::Ctr256, Guid::ALGORITHM_SP800_90_CTR_256),
        (Algorithm::Raw, Guid::ALGORITHM_RAW),
    ]
    .into_iter()
    .find(|(_, guid)| advertised.contains(guid))
    .ok_or("UEFI RNG has no qualified advertised algorithm")?;
    Pool::capture(widths, algorithm, |_, destination| {
        rng.get_rng(Some(guid), destination)
            .map_err(|error| match error.status() {
                uefi::Status::NOT_READY => {
                    "UEFI RNG has insufficient entropy for the complete request"
                }
                uefi::Status::UNSUPPORTED => "UEFI RNG rejected its advertised algorithm",
                uefi::Status::INVALID_PARAMETER => "UEFI RNG rejected the requested output range",
                _ => "UEFI RNG failed to produce entropy",
            })
    })
}
