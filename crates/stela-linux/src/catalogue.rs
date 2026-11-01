//! Exact original-device firmware metadata, backed by real C device references.
//! These leases retain source custody and data; they grant no active I/O or
//! ownership of an original driver's arbitrary callback context.
use alloc::{boxed::Box, rc::Rc, string::String, sync::Arc};
use core::{
    cell::RefCell,
    ffi::c_void,
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use stela_driver_base::bus::pci::{
    owned::{ConfigRetention, OwnedConfig},
    requester::{RequesterId, preparation::Attachment},
};
use stela_driver_core::firmware::{Catalog, Target};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidTarget(&'static str),
    SourceBusy,
    ForeignSource,
    NativeSource(stela_driver_base::bus::dma::mapping::DmaError),
    Config(stela_driver_base::bus::mmio::owned::Error),
    Native(i32),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "device catalogue: {self:?}")
    }
}
impl core::error::Error for Error {}

/// Owned exact label syntax only; these strings grant no source authority.
/// Native enrollment separately proves manifest/observed-device correspondence.
/// None is a board-independent exact target, not an inferred board wildcard.
pub struct FirmwareTarget {
    driver: String,
    hardware: String,
    revision: String,
    board: Option<String>,
}
impl FirmwareTarget {
    pub fn new(
        driver: String,
        hardware: String,
        revision: String,
        board: Option<String>,
    ) -> Result<Self, Error> {
        for (name, value) in [
            ("driver", driver.as_str()),
            ("hardware", hardware.as_str()),
            ("revision", revision.as_str()),
        ]
        .into_iter()
        .chain(board.as_deref().map(|value| ("board", value)))
        {
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(Error::InvalidTarget(name));
            }
        }
        Ok(Self {
            driver,
            hardware,
            revision,
            board,
        })
    }
    pub fn view(&self) -> Target<'_> {
        Target {
            driver: &self.driver,
            hardware: &self.hardware,
            revision: &self.revision,
            board: self.board.as_deref(),
        }
    }
}

/// Shared custody of the actual original attachment allocation. The slot is
/// private: safe callers cannot replace it with another requester's attachment.
pub struct FunctionCustody {
    attachment: RefCell<Attachment>,
    requester: RequesterId,
}
impl FunctionCustody {
    pub fn new(attachment: Attachment) -> Rc<Self> {
        let requester = attachment.requester().clone();
        Rc::new(Self {
            attachment: RefCell::new(attachment),
            requester,
        })
    }
    pub fn requester(&self) -> &RequesterId {
        &self.requester
    }
    /// Native control of this same original allocation, never a catalogue grant.
    ///
    /// # Safety
    /// The original method's actual CPU/context/I/O permissions hold. Do not
    /// replace/retarget the attachment, sleep, reenter or call Linux/driver code
    /// while this short mutable borrow exists. Never detach, consume/release
    /// original ConfigRetention or replace its epoch through this callback:
    /// catalogue/device/request custodians still own that exact allocation.
    /// Final detach uses into_attachment only after the last Rc custodian ends.
    /// Route/wait objects must be moved out before any callback or suspension.
    pub unsafe fn with_native<R>(
        &self,
        operation: impl FnOnce(&mut Attachment) -> R,
    ) -> Result<R, Error> {
        let mut attachment = self
            .attachment
            .try_borrow_mut()
            .map_err(|_| Error::SourceBusy)?;
        Ok(operation(&mut attachment))
    }
    /// Only ownership transfer after all actual catalogue/lease custodians end;
    /// the returned attachment still requires its native IRQ/DMA detach proofs.
    pub fn into_attachment(self: Rc<Self>) -> Result<Attachment, Rc<Self>> {
        Rc::try_unwrap(self).map(|source| source.attachment.into_inner())
    }
}

/// Keeps the actual native attachment/configuration custody, not just its ID.
/// Native control keeps its own Rc; catalogue users cannot borrow the attachment.
pub struct PciAuthority {
    _config: ConfigRetention,
    _execution: super::kernel::ExecutionPin,
    source: Rc<FunctionCustody>,
    requester: RequesterId,
    target: FirmwareTarget,
    catalog: Arc<Catalog>,
}
impl PciAuthority {
    /// Qualify a manifest target against this actual original native function.
    ///
    /// # Safety
    /// The exact driver/hardware/revision/board labels and Catalog resources
    /// are approved for this same observed original OwnedConfig allocation and
    /// retained attachment, including the actual board identity when required.
    /// This is the native source/manifest qualification boundary: syntax,
    /// filename, BDF, driver name or another device's valid image is no proof.
    /// Keep the actual observation/provenance and original source epoch valid;
    /// any requalification follows native removal/retirement, not relabeling.
    pub unsafe fn new<P: super::owner::Platform, const N: usize>(
        kernel: &super::kernel::KernelOwner<P, N>,
        source: Rc<FunctionCustody>,
        original: &OwnedConfig,
        target: FirmwareTarget,
        catalog: Arc<Catalog>,
    ) -> Result<Self, Error> {
        let requester = {
            let source = source
                .attachment
                .try_borrow()
                .map_err(|_| Error::SourceBusy)?;
            if !source
                .matches_config(original)
                .map_err(Error::NativeSource)?
            {
                return Err(Error::ForeignSource);
            }
            source.requester().clone()
        };
        // Actual original mapping/allocation custody, never a cloned writer or
        // permission to access config after its native epoch stops admitting it.
        let config = original.retain_epoch().map_err(Error::Config)?;
        Ok(Self {
            _config: config,
            _execution: kernel.execution(),
            source,
            requester,
            target,
            catalog,
        })
    }
    pub fn requester(&self) -> &RequesterId {
        &self.requester
    }
    pub(crate) fn domain(
        &self,
    ) -> Result<Arc<dyn stela_driver_base::bus::dma::mapping::DmaDomain>, Error> {
        let source = self
            .source
            .attachment
            .try_borrow()
            .map_err(|_| Error::SourceBusy)?;
        if !source.requester().same_requester(&self.requester) {
            return Err(Error::ForeignSource);
        }
        Ok(source.domain())
    }
}

/// Only explicit enrollment of the original regulatory device creates this
/// route. It is never inferred from a resource or faux-device name.
pub struct GlobalAuthority {
    target: FirmwareTarget,
    catalog: Arc<Catalog>,
    _execution: super::kernel::ExecutionPin,
}
pub enum Authority {
    Pci(PciAuthority),
    GlobalRegulatory(GlobalAuthority),
}
impl Authority {
    pub(crate) fn global_regulatory(
        target: FirmwareTarget,
        catalog: Arc<Catalog>,
        execution: super::kernel::ExecutionPin,
    ) -> Self {
        Self::GlobalRegulatory(GlobalAuthority {
            target,
            catalog,
            _execution: execution,
        })
    }
    pub fn target(&self) -> Target<'_> {
        match self {
            Self::Pci(pci) => pci.target.view(),
            Self::GlobalRegulatory(global) => global.target.view(),
        }
    }
    pub fn catalog(&self) -> &Catalog {
        match self {
            Self::Pci(pci) => &pci.catalog,
            Self::GlobalRegulatory(global) => &global.catalog,
        }
    }
    pub fn requester(&self) -> Option<&RequesterId> {
        match self {
            Self::Pci(pci) => Some(pci.requester()),
            Self::GlobalRegulatory(_) => None,
        }
    }
}
#[repr(C)]
struct RawLease {
    device: *mut c_void,
    authority: *const c_void,
}
unsafe extern "C" {
    fn stela_linux_device_bind(
        device: *mut c_void,
        authority: *mut c_void,
        release: unsafe extern "C" fn(*mut c_void),
    ) -> i32;
    fn stela_linux_device_acquire(device: *mut c_void, lease: *mut RawLease) -> i32;
    fn stela_linux_device_release(lease: *mut RawLease) -> i32;
}
unsafe extern "C" fn release_authority(authority: *mut c_void) {
    // SAFETY: bind transferred exactly this Box on success; original final
    // device retirement invokes this once in its canonical process owner.
    drop(unsafe { Box::from_raw(authority.cast::<Authority>()) });
}

/// # Safety
/// Entered canonical process owner; device is the original initialized object
/// still owned by its prepare/global registration. Failure transfers nothing.
pub(crate) unsafe fn bind(
    device: *mut c_void,
    authority: Box<Authority>,
) -> Result<(), (Box<Authority>, Error)> {
    let authority = Box::into_raw(authority);
    // SAFETY: the exact C object and owned authority above obey the caller's contract.
    let status = unsafe { stela_linux_device_bind(device, authority.cast(), release_authority) };
    if status == 0 {
        Ok(())
    } else {
        // SAFETY: failure took no authority ownership and invoked no destructor.
        Err((unsafe { Box::from_raw(authority) }, Error::Native(status)))
    }
}

static RETAINED: AtomicU64 = AtomicU64::new(0);
/// Leases abandoned without the explicit process-owner release remain held.
pub fn retained_leases() -> u64 {
    RETAINED.load(Ordering::Relaxed)
}

/// An actual original C device ref and its source record. This is neither a
/// driver-context reference nor permission to access the requester.
#[must_use = "release explicitly in the canonical process owner or retain the real device reference"]
pub struct DeviceLease {
    raw: RawLease,
    released: bool,
    local: PhantomData<*mut ()>,
}
impl DeviceLease {
    /// # Safety
    /// The caller holds the original Linux API's valid device/reference
    /// contract and is on the canonical owner's checked Linux task/CPU.
    pub unsafe fn acquire(device: *mut c_void) -> Result<Self, Error> {
        let mut raw = RawLease {
            device: core::ptr::null_mut(),
            authority: core::ptr::null(),
        };
        // SAFETY: C checks original enrolled membership before taking its real reference.
        let status = unsafe { stela_linux_device_acquire(device, &raw mut raw) };
        if status != 0 {
            return Err(Error::Native(status));
        }
        assert!(!raw.device.is_null() && !raw.authority.is_null());
        Ok(Self {
            raw,
            released: false,
            local: PhantomData,
        })
    }
    pub fn authority(&self) -> &Authority {
        let authority = NonNull::new(self.raw.authority.cast_mut().cast::<Authority>())
            .expect("live authority");
        // SAFETY: the real C reference keeps the Rust-created enrolled source
        // record alive through original final release; no driver context is borrowed.
        unsafe { authority.as_ref() }
    }
    /// # Safety
    /// Same canonical process owner/CPU, quiescent outside atomic/RCU delivery.
    /// A refusal returns the unchanged real reference for retained retry.
    pub unsafe fn release(mut self) -> Result<(), Self> {
        // SAFETY: caller establishes the process release scope; C refuses before effects otherwise.
        if unsafe { stela_linux_device_release(&raw mut self.raw) } != 0 {
            return Err(self);
        }
        self.released = true;
        Ok(())
    }
}
impl Drop for DeviceLease {
    fn drop(&mut self) {
        if !self.released {
            // No put_device is invented outside the admitted process scope.
            // The actual extra C ref remains, retaining device/native source.
            let _ = RETAINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn target_labels_remain_exact_and_owned() {
        let target = FirmwareTarget::new(
            "original-driver".to_string(),
            "exact-hardware".to_string(),
            "revision-2".to_string(),
            Some("board-a".to_string()),
        )
        .unwrap();
        let view = target.view();
        assert_eq!(view.driver, "original-driver");
        assert_eq!(view.hardware, "exact-hardware");
        assert_eq!(view.revision, "revision-2");
        assert_eq!(view.board, Some("board-a"));
    }

    #[test]
    fn target_refuses_empty_and_control_labels() {
        for (driver, hardware, revision, board, expected) in [
            ("", "hw", "rev", None, "driver"),
            ("drv", "hw\n", "rev", None, "hardware"),
            ("drv", "hw", "", None, "revision"),
            ("drv", "hw", "rev", Some(""), "board"),
        ] {
            let result = FirmwareTarget::new(
                driver.to_string(),
                hardware.to_string(),
                revision.to_string(),
                board.map(ToString::to_string),
            );
            assert!(matches!(result, Err(Error::InvalidTarget(field)) if field == expected));
        }
    }
}
