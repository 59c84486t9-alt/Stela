//! Finite independent RNG requests captured before ExitBootServices.
//!
//! Only the real UEFI RNG protocol can prepare a production pool. It contains
//! no protocol pointer, heap pointer, CPU RNG instruction, refill or seed
//! fallback. The boot owner selects the protocol and retains this non-cloneable
//! value through the actual engine handoff; preparation alone does not perform
//! that handoff or attest firmware entropy quality. Secret bytes are not logged.
use core::sync::atomic::{Ordering, compiler_fence};

/// Selected, advertised standard algorithm. This metadata contains no seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Hash256,
    Hmac256,
    Ctr256,
    Raw,
}

/// Pointer-free, bounded pool, with one successful firmware request per slot.
/// The caller supplies capacities and the exact ordered native request widths.
/// There is intentionally no Clone, Copy, Debug or serialization of its bytes.
pub struct Pool<const BYTES: usize, const REQUESTS: usize> {
    bytes: [u8; BYTES],
    widths: [usize; REQUESTS],
    offset: usize,
    next: usize,
    algorithm: Algorithm,
}

/// Keep clearing observable to the compiler even when the source is dead.
fn clear(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each exclusively borrowed byte is valid for this write.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

impl<const BYTES: usize, const REQUESTS: usize> Pool<BYTES, REQUESTS> {
    #[cfg(any(test, target_os = "uefi"))]
    fn capture(
        widths: [usize; REQUESTS],
        algorithm: Algorithm,
        mut fill: impl FnMut(Algorithm, &mut [u8]) -> Result<(), &'static str>,
    ) -> Result<Self, &'static str> {
        if REQUESTS == 0 || widths.contains(&0) {
            return Err("entropy pool requires nonempty independent requests");
        }
        let total = widths
            .iter()
            .try_fold(0usize, |n, &width| n.checked_add(width))
            .ok_or("entropy pool request sizes overflow")?;
        if total > BYTES {
            return Err("entropy pool capacity is smaller than its complete request plan");
        }
        let mut pool = Self {
            bytes: [0; BYTES],
            widths,
            offset: 0,
            next: 0,
            algorithm,
        };
        let mut offset = 0;
        for &width in &widths {
            // An error drops/clears the complete pool, including any partial
            // failing write. No earlier slot or partially prepared pool escapes.
            fill(algorithm, &mut pool.bytes[offset..offset + width])?;
            offset += width;
        }
        Ok(pool)
    }

    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn remaining_requests(&self) -> usize {
        REQUESTS - self.next
    }

    /// Consume exactly the next independently captured native request. A width
    /// mismatch or exhausted pool leaves both destination and pool unchanged.
    /// The caller owns/clears the output when its actual consumer has finished.
    pub fn fill(&mut self, destination: &mut [u8]) -> Result<(), &'static str> {
        let &width = self
            .widths
            .get(self.next)
            .ok_or("pre-EBS entropy pool is exhausted")?;
        if destination.len() != width {
            return Err("entropy consumer width disagrees with the next captured request");
        }
        let bytes = &mut self.bytes[self.offset..self.offset + width];
        destination.copy_from_slice(bytes);
        clear(bytes);
        self.offset += width;
        self.next += 1;
        Ok(())
    }
}

impl<const BYTES: usize, const REQUESTS: usize> Drop for Pool<BYTES, REQUESTS> {
    fn drop(&mut self) {
        clear(&mut self.bytes);
    }
}

#[cfg(target_os = "uefi")]
impl<const BYTES: usize, const REQUESTS: usize> Pool<BYTES, REQUESTS> {
    /// Read actual advertised UEFI RNG output while boot services are active.
    /// The parent owns protocol discovery/selection and its source provenance;
    /// the borrowed protocol must be closed before ExitBootServices. There are
    /// no post-EBS protocol calls, implicit algorithm default or CPU fallback.
    ///
    /// UEFI2.11 37.5 requires exact output length and forbids reuse across calls.
    /// Recognized SP800-90 256-bit DRBGs or the explicit raw source are accepted.
    /// Other advertised algorithms require separate qualification. Protocol
    /// failure, including NOT_READY, aborts/clears the entire finite capture.
    pub fn prepare(
        rng: &mut uefi::proto::rng::Rng,
        widths: [usize; REQUESTS],
    ) -> Result<Self, &'static str> {
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
        Self::capture(widths, algorithm, |_, destination| {
            rng.get_rng(Some(guid), destination)
                .map_err(|error| match error.status() {
                    uefi::Status::NOT_READY => {
                        "UEFI RNG has insufficient entropy for the complete request"
                    }
                    uefi::Status::UNSUPPORTED => "UEFI RNG rejected its advertised algorithm",
                    uefi::Status::INVALID_PARAMETER => {
                        "UEFI RNG rejected the requested output range"
                    }
                    _ => "UEFI RNG failed to produce entropy",
                })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_requests_are_consumed_once_and_erased() {
        let widths = [8, 1, 8, 8];
        let mut requests = std::vec::Vec::new();
        let mut pool = Pool::<25, 4>::capture(widths, Algorithm::Hmac256, |algorithm, out| {
            assert_eq!(algorithm, Algorithm::Hmac256);
            requests.push(out.len());
            out.fill(requests.len() as u8);
            Ok(())
        })
        .unwrap();
        assert_eq!(requests, widths);
        assert_eq!(pool.algorithm(), Algorithm::Hmac256);
        let mut wrong = [0xa5; 7];
        assert!(pool.fill(&mut wrong).is_err());
        assert_eq!(wrong, [0xa5; 7]);
        assert_eq!(pool.remaining_requests(), 4);
        for (slot, width) in widths.into_iter().enumerate() {
            let mut out = std::vec![0; width];
            pool.fill(&mut out).unwrap();
            assert_eq!(out, std::vec![slot as u8 + 1; width]);
            assert!(pool.bytes[..pool.offset].iter().all(|&b| b == 0));
        }
        let mut out = [0xa5; 8];
        assert!(pool.fill(&mut out).is_err());
        assert_eq!(out, [0xa5; 8]);
        assert_eq!(pool.remaining_requests(), 0);
    }

    #[test]
    fn invalid_plans_fail_before_calling_the_source() {
        let mut source = |_, _: &mut [u8]| -> Result<(), &'static str> {
            panic!("invalid plan must not read entropy")
        };
        assert!(Pool::<1, 0>::capture([], Algorithm::Raw, &mut source).is_err());
        assert!(Pool::<1, 1>::capture([0], Algorithm::Raw, &mut source).is_err());
        assert!(Pool::<1, 1>::capture([2], Algorithm::Raw, &mut source).is_err());
        assert!(Pool::<1, 2>::capture([usize::MAX, 1], Algorithm::Raw, source).is_err());
    }

    #[test]
    fn failed_capture_never_publishes_partial_requests_or_retries() {
        let mut calls = 0;
        let pool = Pool::<16, 2>::capture([8, 8], Algorithm::Ctr256, |_, out| {
            calls += 1;
            out.fill(0x91); // A firmware may alter output before reporting failure.
            if calls == 2 {
                Err("source failed")
            } else {
                Ok(())
            }
        });
        assert_eq!(pool.err(), Some("source failed"));
        assert_eq!(calls, 2);
    }

    #[test]
    fn genuine_zero_output_is_preserved_and_unused_capacity_is_not_a_request() {
        let mut pool = Pool::<64, 1>::capture([8], Algorithm::Raw, |_, out| {
            out.fill(0);
            Ok(())
        })
        .unwrap();
        let mut out = [0xa5; 8];
        pool.fill(&mut out).unwrap();
        assert_eq!(out, [0; 8]);
        assert!(pool.fill(&mut out).is_err());
        let mut scratch = [0xa5; 11];
        clear(&mut scratch);
        assert_eq!(scratch, [0; 11]);
    }
}
