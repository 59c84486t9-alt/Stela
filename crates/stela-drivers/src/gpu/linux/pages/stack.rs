//! Descriptor reservations for pinned, unpublished Runtime workers.
use super::*;
use crate::platform::work::{EnteredProcess, PinnedColdStackPreparation, WorkError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Work(WorkError),
    Memory(MemoryError),
    Catalog(Error),
    AlreadyAdmitted,
}
impl core::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "stack catalog admission: {self:?}")
    }
}
impl core::error::Error for AdmissionError {}

#[repr(C)]
struct NativeAdmission {
    version: u32,
    bytes: u32,
    generation: u64,
    cpu_base: *mut c_void,
    physical_pages: *const u64,
    page_count: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeTicket {
    version: u32,
    bytes: u32,
    generation: u64,
    record: usize,
    nonce: u64,
}
unsafe extern "C" {
    fn stela_linux_page_stack_admit(
        request: *const NativeAdmission,
        ticket: *mut NativeTicket,
    ) -> c_int;
    fn stela_linux_page_stack_cancel(ticket: *const NativeTicket) -> c_int;
}

/// Owns the cold pin and its optional unpublished catalog marker. The native
/// admission count blocks descriptor retirement independently of this borrow:
/// forgotten values keep both the catalog context and Runtime backing alive.
/// Dropping a live value closes its Runtime; it leaves marker cleanup for
/// permanent quarantine rather than calling C under an expired work scope.
#[must_use = "cancel with fresh matching work authority; dropping retains the owners"]
pub struct StackAdmission<'catalog, 'runtime, P: Provider, const N: usize> {
    catalog: &'catalog Catalog<P>,
    cold: PinnedColdStackPreparation<'runtime, N>,
    ticket: Option<NativeTicket>,
}
impl<P: Provider> Catalog<P> {
    /// Retain the original cold pin for a descriptor admission attempt.
    /// This wrapper alone makes no C call and publishes no marker.
    pub fn prepare_stack<'catalog, 'runtime, const N: usize>(
        &'catalog self,
        cold: PinnedColdStackPreparation<'runtime, N>,
    ) -> StackAdmission<'catalog, 'runtime, P, N> {
        StackAdmission {
            catalog: self,
            cold,
            ticket: None,
        }
    }
}
impl<P: Provider, const N: usize> StackAdmission<'_, '_, P, N> {
    /// Reserve only descriptor markers. Every refusal leaves this same owner
    /// in place, including a marker created before post-call scope failure.
    /// Repeated admission refuses a second marker. This borrows the owning
    /// value only for the call; pages and C stack addresses stay private.
    pub fn admit(&mut self, entered: &dyn EnteredProcess) -> Result<(), AdmissionError> {
        self.cold.check_pin(entered).map_err(AdmissionError::Work)?;
        if self.ticket.is_some() {
            return Err(AdmissionError::AlreadyAdmitted);
        }
        if self.catalog.context.is_none() {
            return Err(AdmissionError::Catalog(Error::InvalidReservation));
        }
        let mut native_ticket = NativeTicket {
            version: 1,
            bytes: size_of::<NativeTicket>() as u32,
            generation: 0,
            record: usize::MAX,
            nonce: 0,
        };
        let result = {
            let _owner = Entered::try_new().map_err(AdmissionError::Catalog)?;
            let result = self.cold.inspect_pin(entered, |pages| {
                let mapping = pages
                    .cpu_mapping(CacheAttribute::WriteBack)
                    .map_err(AdmissionError::Memory)?;
                let cpu = mapping
                    .address(0, pages.bytes())
                    .map_err(AdmissionError::Memory)?;
                let request = NativeAdmission {
                    version: 1,
                    bytes: size_of::<NativeAdmission>() as u32,
                    generation: self.catalog.generation,
                    cpu_base: cpu.as_ptr().cast(),
                    physical_pages: pages.physical_pages().as_ptr(),
                    page_count: pages.physical_pages().len(),
                };
                // SAFETY: this value retains the actual cold pin, physical list
                // and CPU mapping through the synchronous call. Header lengths
                // match their repr(C) objects. C copies only descriptor markers,
                // and returns an opaque generation/index/nonce, never a page.
                Ok::<_, AdmissionError>(unsafe {
                    stela_linux_page_stack_admit(&request, &mut native_ticket)
                })
            });
            match result {
                Ok(Ok(0)) => {
                    // No fallible operation separates marker creation from
                    // retaining its ticket, including C-owner exit callbacks.
                    self.ticket = Some(native_ticket);
                    Ok(())
                }
                Ok(Ok(status)) => Err(AdmissionError::Catalog(Error::Native(status))),
                Ok(Err(error)) => Err(error),
                Err(error) => Err(AdmissionError::Work(error)),
            }
        };
        // C-owner exit may finish other service callbacks. Recheck after that
        // complete boundary while retaining any successfully created marker.
        self.cold.check_pin(entered).map_err(AdmissionError::Work)?;
        result
    }

    /// Remove this unpublished marker under fresh work authority, keeping its
    /// RuntimeStack extent reserved, then restore/cancel the cold frame once.
    /// Refusal retains/quarantines the catalog and Runtime owners.
    pub fn cancel(self, entered: &dyn EnteredProcess) -> Result<(), AdmissionError> {
        self.cold.check_pin(entered).map_err(AdmissionError::Work)?;
        if let Some(ticket) = self.ticket {
            let result = {
                let _owner = Entered::try_new().map_err(AdmissionError::Catalog)?;
                // SAFETY: private ticket belongs to this retained catalog and
                // cold pin. C validates its fixed header/generation/nonce and
                // every unpublished marker before changing any of them.
                unsafe { stela_linux_page_stack_cancel(&ticket) }
            };
            if result != 0 {
                return Err(AdmissionError::Catalog(Error::Native(result)));
            }
        }
        self.cold.check_pin(entered).map_err(AdmissionError::Work)?;
        self.cold.cancel(entered).map_err(AdmissionError::Work)
    }
}

#[cfg(all(test, unix))]
mod tests;
