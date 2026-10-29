//! Exact-request, multi-channel scan admission and guarded native publication.
//!
//! Every requested receive channel and active probe profile is checked while
//! one original hardware lease and then one OS lease remain held. This issues
//! no completion, cancellation or retirement proof for firmware-owned work.
use super::{
    Error, HardwarePolicy, NativeContext, Operation, OsLease, OsPolicy, Owner, Purpose, TxProfile,
    check,
};
use crate::net::wifi::{
    Channel,
    scan::{self as protocol, Request, SixGhz},
};
use alloc::vec::Vec;

/// Exact immutable request snapshot and its checked active-probe profile. This
/// is an operation description, never a stand-alone device or radio permit.
#[derive(Clone, Copy, Debug)]
pub struct ScanOperation<'a> {
    request: &'a Request,
    probe: Option<TxProfile>,
}
impl<'a> ScanOperation<'a> {
    pub fn request(self) -> &'a Request {
        self.request
    }
    pub fn probe_profile(self) -> Option<TxProfile> {
        self.probe
    }
}
/// Single-use admission owning the complete immutable request snapshot.
/// Publication takes no replacement request/profile; its callback receives this
/// exact one. The snapshot is input data: original native/OS guards supply the
/// permission. Owning it permits the vendor to mark its Scanner submitted inside
/// the guarded native handoff without aliasing Scanner::request().
///
/// ```compile_fail
/// use stela_drivers::net::wifi::regulatory::ScanAdmission;
/// let admission = ScanAdmission { owner: 1 };
/// ```
#[derive(Debug)]
pub struct ScanAdmission {
    owner: u64,
    native: NativeContext,
    os_revision: u64,
    request: Request,
    probe: Option<TxProfile>,
}
impl ScanAdmission {
    pub fn operation(&self) -> ScanOperation<'_> {
        ScanOperation {
            request: &self.request,
            probe: self.probe,
        }
    }
}
fn validate_lengths(
    channels: &[Channel],
    ssids: &[Vec<u8>],
    elements: &[u8],
    six_ghz: &[SixGhz],
) -> Result<(), Error> {
    if channels.is_empty()
        || channels.len() > protocol::MAX_CHANNELS
        || ssids.len() > protocol::MAX_SSIDS
        || ssids
            .iter()
            .any(|ssid| ssid.len() > protocol::MAX_SSID_BYTES)
        || elements.len() > protocol::MAX_EXTRA_ELEMENTS
        || six_ghz.len() > protocol::MAX_SIX_GHZ
    {
        return Err(Error::Mismatch);
    }
    Ok(())
}
fn snapshot(request: &Request) -> Result<Request, Error> {
    // Bound every nested allocation before allocating even the first channel.
    validate_lengths(
        request.channels(),
        request.ssids(),
        request.extra_elements(),
        request.six_ghz(),
    )?;
    request.try_snapshot().map_err(|_| Error::NoMemory)
}
fn check_request(
    hardware: &mut impl super::HardwareLease,
    os: &mut impl OsLease,
    operation: ScanOperation<'_>,
) -> Result<(), Error> {
    if operation.request.active() != operation.probe.is_some() {
        return Err(if operation.request.active() {
            Error::Unsupported
        } else {
            Error::Mismatch
        });
    }
    for &channel in operation.request.channels() {
        check(hardware, os, Operation::Receive(channel))?;
        if operation.request.active() {
            check(
                hardware,
                os,
                Operation::Transmit {
                    channel,
                    purpose: Purpose::Probe,
                    profile: operation.probe.ok_or(Error::Unsupported)?,
                },
            )?;
        }
    }
    Ok(())
}
impl<H: HardwarePolicy, O: OsPolicy> Owner<H, O> {
    /// Check the complete request under one hardware then OS lease pair.
    /// Individual preflight channel checks cannot replace this admission.
    pub fn admit_scan(
        &mut self,
        request: &Request,
        probe: Option<TxProfile>,
    ) -> Result<ScanAdmission, Error> {
        let request = snapshot(request)?;
        let operation = ScanOperation {
            request: &request,
            probe,
        };
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = super::HardwareLease::context(&hardware);
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        check_request(&mut hardware, &mut os, operation)?;
        Ok(ScanAdmission {
            owner: self.identity,
            native,
            os_revision: os.revision(),
            request,
            probe,
        })
    }
    /// Recheck every operation for the same immutable request and same native
    /// context/OS revision; keep both leases across native submission.
    /// # Safety
    /// The callback must encode the supplied exact request/profile and publish
    /// through this concrete hardware guard's native owner. It may not
    /// target another requester or supply an unchecked firmware rate/power,
    /// active/passive, channel/width or probe-frame variation. Revocation must
    /// enforce the providers' existing pending/autonomous-work stop/drain
    /// contracts after publication; closure return is no terminal completion.
    pub unsafe fn publish_scan<'hardware, T>(
        &'hardware mut self,
        admission: ScanAdmission,
        submit: impl FnOnce(&mut H::Lease<'hardware>, ScanOperation<'_>) -> T,
    ) -> Result<T, Error> {
        if admission.owner != self.identity {
            return Err(Error::Stale);
        }
        let mut hardware = self.hardware.acquire().ok_or(Error::HardwareUnavailable)?;
        let native = super::HardwareLease::context(&hardware);
        if admission.native != native {
            return Err(Error::Stale);
        }
        let mut os = self.os.acquire(native).ok_or(Error::OsUnavailable)?;
        if admission.os_revision != os.revision() {
            return Err(Error::Stale);
        }
        let operation = admission.operation();
        check_request(&mut hardware, &mut os, operation)?;
        let result = submit(&mut hardware, operation);
        drop(os);
        drop(hardware);
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
