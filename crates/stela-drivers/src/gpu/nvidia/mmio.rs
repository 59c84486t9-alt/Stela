//! Original tokenless RM physical mapping ABI over the canonical MMIO authority.
//!
//! This module owns only returned-VA/size -> Mapping lease bookkeeping. Actual
//! resource registration, aliases, effective cache policy, native roots and TLB
//! acknowledgement belong to `bus::mmio::owned` and the real platform adapter.
//! No platform adapter or GPU activation is supplied here. Cached RAM/firmware
//! mapping remains a separate unsupported integration requirement.
use crate::bus::mmio::owned::{
    Authority, CacheAttribute, Error as MappingError, Mapping, PhysicalSpan, Protection,
    Status as AuthorityStatus,
};
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    marker::{PhantomData, PhantomPinned},
    pin::Pin,
    ptr,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering},
};

static INSTALLED: AtomicPtr<MmioServices> = AtomicPtr::new(ptr::null_mut());
// Fail reentry before constructing any Rust reference to the installed object.
// This guard is ownership serialization, never an ISR/context predicate.
static ENTERED: AtomicBool = AtomicBool::new(false);
static REFUSED_CALLS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    AlreadyInstalled,
    NotInstalled,
    Busy,
    LiveMappings,
    UnknownMapping,
    Mapping(MappingError),
}
impl From<MappingError> for Error {
    fn from(error: MappingError) -> Self {
        Self::Mapping(error)
    }
}

/// Historical failures remain visible because the original unmap ABI is void.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    pub live: usize,
    pub pending: usize,
    pub busy_retirements: u64,
    pub failed_maps: u64,
    pub failed_unmaps: u64,
    pub unmap_quarantines: u64,
    pub last_failure: Option<Error>,
    /// Boot-global entry refusals before any service reference is constructed.
    pub refused_calls: u64,
}

struct Lease {
    address: *mut c_void,
    bytes: u64,
    mapping: Mapping,
    pending: bool,
}

/// Pinned native installation for the original global, tokenless mapping hooks.
/// It retains a clone of the one canonical Authority, not a BAR/resource table.
/// No resources are registered here. This handle is neither Send nor Sync.
pub struct MmioServices {
    authority: Authority,
    leases: Vec<Lease>,
    busy_retirements: u64,
    failed_maps: u64,
    failed_unmaps: u64,
    unmap_quarantines: u64,
    last_failure: Option<Error>,
    _owner: PhantomData<*mut ()>,
    _pin: PhantomPinned,
}

struct Entry;
impl Entry {
    fn acquire() -> Result<Self, Error> {
        ENTERED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| Error::Busy)?;
        Ok(Self)
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        ENTERED.store(false, Ordering::Release);
    }
}

impl MmioServices {
    pub fn new(authority: Authority) -> Self {
        Self {
            authority,
            leases: Vec::new(),
            busy_retirements: 0,
            failed_maps: 0,
            failed_unmaps: 0,
            unmap_quarantines: 0,
            last_failure: None,
            _owner: PhantomData,
            _pin: PhantomPinned,
        }
    }

    /// Publish only after the real global heap, registered resources and native
    /// mapping platform are ready. This performs no mapping or initialization.
    ///
    /// # Safety
    /// Keep this pinned object alive until successful uninstall, with the same
    /// native CPU ABI/address space. Serialize all native callers and Rust
    /// service access; exclude interrupts, callback/allocator reentry and final
    /// release outside the providers' process/deferred context. Do not create
    /// Rust references to this object while any C callback can access it.
    /// Stop/drain all callers and retire live/pending leases before uninstall;
    /// they may not outlive installation. The guard rejects reentry but cannot make an
    /// invalid lifetime/context or an interrupted allocator safe.
    pub unsafe fn install(self: Pin<&mut Self>) -> Result<(), Error> {
        let _entry = Entry::acquire()?;
        // SAFETY: pin remains in place through all callbacks and uninstall.
        let pointer = unsafe { self.get_unchecked_mut() as *mut Self };
        INSTALLED
            .compare_exchange(
                ptr::null_mut(),
                pointer,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| Error::AlreadyInstalled)?;
        Ok(())
    }

    /// # Safety
    /// All native callers have stopped/drained and cannot restart, including
    /// callbacks/workers with raw addresses. The install lifetime/context and
    /// serialization contract still applies. Failure leaves the slot installed.
    /// Canonically quarantined leases retain actual platform/resources without
    /// this object; their failure remains a real teardown error in diagnostics.
    /// Live AND pending leases refuse uninstall. Drain pending retirements at
    /// real quiescent points, and before attempting final uninstall.
    pub unsafe fn uninstall(self: Pin<&mut Self>) -> Result<(), Error> {
        let _entry = Entry::acquire()?;
        // SAFETY: caller excludes callbacks and keeps the object pinned.
        let services = unsafe { self.get_unchecked_mut() };
        let pointer = services as *mut Self;
        if INSTALLED.load(Ordering::Acquire) != pointer {
            return Err(Error::NotInstalled);
        }
        if !services.leases.is_empty() {
            return Err(Error::LiveMappings);
        }
        INSTALLED.store(ptr::null_mut(), Ordering::Release);
        Ok(())
    }

    /// Inspect only between serialized callbacks, as required by install.
    pub fn status(&self) -> Status {
        let pending = self.leases.iter().filter(|lease| lease.pending).count();
        Status {
            live: self.leases.len() - pending,
            pending,
            busy_retirements: self.busy_retirements,
            failed_maps: self.failed_maps,
            failed_unmaps: self.failed_unmaps,
            unmap_quarantines: self.unmap_quarantines,
            last_failure: self.last_failure,
            refused_calls: REFUSED_CALLS.load(Ordering::Relaxed),
        }
    }

    /// Actual shared-authority state, including uncertain maps that never
    /// returned a VA and quarantine from every native authority consumer.
    pub fn authority_status(&self) -> Result<AuthorityStatus, MappingError> {
        self.authority.status()
    }

    /// Retry pending exact canonical tokens, using their existing ledger slots.
    /// No adapter allocation, queue or worker is created. Returns the number
    /// retired if all attempts succeed; an error may follow earlier progress,
    /// which remains visible in status. Busy retains the pending Mapping even
    /// if the platform was called and canonical state is already uncertain.
    ///
    /// # Safety
    /// Call only on the installed pinned native owner, serialized with all C
    /// hooks in the real platform/global heap's process/deferred context. Every
    /// pending lease's initial unmap has already proved complete raw CPU/device/
    /// callback/worker and posted/WC drain; no future access may restart. Retry
    /// at actual quiescent points and before uninstall. Never infer that Busy
    /// means a platform callback was not entered or a raw VA is usable again.
    pub unsafe fn drain_pending_retirements(self: Pin<&mut Self>) -> Result<usize, Error> {
        let _entry = Entry::acquire()?;
        // SAFETY: caller excludes native callbacks and preserves pin/lifetime.
        let services = unsafe { self.get_unchecked_mut() };
        if !ptr::eq(INSTALLED.load(Ordering::Acquire), services) {
            return Err(Error::NotInstalled);
        }
        let mut at = 0;
        let mut retired = 0;
        let mut failure = None;
        while at < services.leases.len() {
            if !services.leases[at].pending {
                at += 1;
                continue;
            }
            // SAFETY: initial unmap permanently ended raw access; retry the
            // same retained canonical token in owner-established context.
            match unsafe { services.retire(at) } {
                Ok(()) => retired += 1,
                Err(error) => {
                    services.record_unmap_failure(error);
                    failure.get_or_insert(error);
                    if error == Error::Mapping(MappingError::Busy) {
                        at += 1; // retained in this same slot
                    }
                    // Other failures consumed this slot into quarantine; its
                    // swapped-in neighbor still needs inspection at this index.
                }
            }
        }
        failure.map_or(Ok(retired), Err)
    }

    fn map(&mut self, physical: u64, bytes: u64, mode: u32) -> Result<*mut c_void, Error> {
        let attribute = match mode {
            1 | 6 => CacheAttribute::Uncached,
            2 => CacheAttribute::WriteCombining,
            _ => return Err(MappingError::UnsupportedCache.into()),
        };
        if physical == 0 {
            return Err(MappingError::InvalidRange.into());
        }
        let span = PhysicalSpan::new(physical, bytes)?;
        let size = usize::try_from(bytes).map_err(|_| MappingError::InvalidRange)?;
        // Validate genuine context and complete rounded ownership BEFORE any
        // allocator operation. map_physical repeats lookup and atomically
        // reserves the resource/cache range; no GPU BAR metadata is trusted.
        drop(self.authority.resolve_resource(span)?);
        let authority = &self.authority;
        publish(
            &mut self.leases,
            |leases| {
                leases
                    .try_reserve(1)
                    .map_err(|_| MappingError::Unavailable.into())
            },
            || {
                let mapping = authority.map_physical(span, attribute, Protection::ReadWrite)?;
                // A canonical address failure (e.g. concurrent identity
                // quarantine) drops into canonical quarantine, never unmaps a
                // token or publishes an invalid/partially valid raw pointer.
                let address = mapping.address(0, size)?.as_ptr().cast();
                Ok((
                    Lease {
                        address,
                        bytes,
                        mapping,
                        pending: false,
                    },
                    address,
                ))
            },
        )
    }

    /// # Safety
    /// Original caller has stopped/drained every raw consumer and posted/WC
    /// effect of precisely this mapping. No future access may begin.
    unsafe fn unmap(&mut self, address: *mut c_void, bytes: u64) -> Result<(), Error> {
        let at = self
            .leases
            .iter()
            .position(|lease| !lease.pending && lease.address == address && lease.bytes == bytes)
            .ok_or(Error::UnknownMapping)?;
        // The void ABI ended the caller's raw access regardless of whether
        // canonical retirement can finish now. Never hand this lease out again.
        self.leases[at].pending = true;
        // SAFETY: initial caller proves permanent raw-user/post-write drain.
        unsafe { self.retire(at) }
    }

    /// # Safety
    /// This pending slot has permanently stopped/drained all raw users/effects.
    unsafe fn retire(&mut self, at: usize) -> Result<(), Error> {
        // SAFETY: caller proves complete raw-user drain; Mapping retains the
        // genuine platform/resource and validates exact canonical identity.
        match unsafe { self.leases[at].mapping.retire() } {
            Ok(()) => {
                self.leases.swap_remove(at);
                Ok(())
            }
            Err(MappingError::Busy) => Err(MappingError::Busy.into()),
            Err(error) => {
                self.unmap_quarantines = self.unmap_quarantines.saturating_add(1);
                // Fatal/ambiguous failures consume into canonical permanent
                // quarantine, retaining actual owners and uncertain aliases.
                // Busy instead retains the exact token without guessing if
                // native unmap ran, for explicit native-owner retry above.
                self.leases.swap_remove(at);
                Err(error.into())
            }
        }
    }

    fn record_unmap_failure(&mut self, error: Error) {
        if error == Error::Mapping(MappingError::Busy) {
            self.busy_retirements = self.busy_retirements.saturating_add(1);
        } else {
            self.failed_unmaps = self.failed_unmaps.saturating_add(1);
        }
        self.last_failure = Some(error);
    }
}

// All fallible bookkeeping precedes the real mapping. This internal seam lets
// tests model bounded metadata OOM without exhausting the Rust test harness.
fn publish<T, R>(
    leases: &mut Vec<T>,
    reserve: impl FnOnce(&mut Vec<T>) -> Result<(), Error>,
    map: impl FnOnce() -> Result<(T, R), Error>,
) -> Result<R, Error> {
    reserve(leases)?;
    if leases.len() == leases.capacity() {
        return Err(MappingError::Unavailable.into());
    }
    let (lease, result) = map()?;
    leases.push(lease);
    Ok(result)
}

fn refuse() {
    let _ = REFUSED_CALLS.try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
        Some(count.saturating_add(1))
    });
}

fn with_installed<R>(fallback: R, call: impl FnOnce(&mut MmioServices) -> R) -> R {
    let Ok(_entry) = Entry::acquire() else {
        refuse();
        return fallback;
    };
    let pointer = INSTALLED.load(Ordering::Acquire);
    if pointer.is_null() {
        refuse();
        return fallback;
    }
    // SAFETY: unsafe install retains this pinned native object; global entry
    // ownership excludes all other callbacks before constructing this borrow.
    call(unsafe { &mut *pointer })
}

#[unsafe(no_mangle)]
extern "C" fn stela_nvidia_map_mmio(physical: u64, bytes: u64, mode: u32) -> *mut c_void {
    with_installed(ptr::null_mut(), |services| {
        match services.map(physical, bytes, mode) {
            Ok(address) => address,
            Err(error) => {
                services.failed_maps = services.failed_maps.saturating_add(1);
                services.last_failure = Some(error);
                ptr::null_mut()
            }
        }
    })
}

#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_unmap_mmio(address: *mut c_void, bytes: u64) {
    with_installed((), |services| {
        // SAFETY: original C caller satisfies the installed unmap contract.
        if let Err(error) = unsafe { services.unmap(address, bytes) } {
            services.record_unmap_failure(error);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn failed_metadata_reservation_never_maps_or_publishes() {
        let mut leases = Vec::<u8>::new();
        let calls = Cell::new(0);
        let result = publish(
            &mut leases,
            |_| Err(MappingError::Unavailable.into()),
            || {
                calls.set(calls.get() + 1);
                Ok((1, ()))
            },
        );
        assert_eq!(result, Err(Error::Mapping(MappingError::Unavailable)));
        assert!(leases.is_empty());
        assert_eq!(calls.get(), 0);
        assert_eq!(
            publish(
                &mut leases,
                |_| Ok(()),
                || {
                    calls.set(1);
                    Ok((1, ()))
                }
            ),
            Err(Error::Mapping(MappingError::Unavailable))
        );
        assert_eq!(calls.get(), 0);
        leases.try_reserve(1).unwrap();
        assert_eq!(
            publish(
                &mut leases,
                |_| Ok(()),
                || Err::<(u8, ()), _>(MappingError::MappingFailed.into())
            ),
            Err(Error::Mapping(MappingError::MappingFailed))
        );
        assert!(leases.is_empty());
        assert_eq!(publish(&mut leases, |_| Ok(()), || Ok((7, 3))), Ok(3));
        assert_eq!(leases, [7]);
    }
}
