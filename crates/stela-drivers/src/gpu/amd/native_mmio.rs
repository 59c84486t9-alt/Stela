//! Original AMDGPU BAR policy attached to the canonical native MMIO owner.
//!
//! No register access, doorbell write, firmware load or hardware activation is
//! performed here. Original AMDGPU register routing and device lifecycle remain
//! mandatory; this module only retains their real, bounded CPU windows.
use super::pci::{Admission, IpPath, MatchedFunction};
use crate::bus::{
    mmio::owned::{
        Authority, CacheAttribute, Error as MmioError, Mapping, MappingView, PAGE_BYTES,
        PhysicalSpan, Protection, Resource, ResourceKind,
    },
    pci::{Address, ConfigSpace, Function},
};
use core::{ffi::c_int, marker::PhantomData, ptr::NonNull};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidOwner,
    AdmissionRequired,
    StaticInitializationRequired,
    InvalidRange,
    Policy(c_int),
    Mapping(MmioError),
    IndirectRegisterRequired,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Preflight,
    Registers,
    Doorbells,
}

/// Failure ownership is truthful even when attachment fails after a real map.
/// The canonical authority owns uncertain failed-map reservations internally.
/// `rollback` describes the already-installed, unpublished register window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachError {
    pub stage: Stage,
    pub error: Error,
    pub rollback: Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rollback {
    NotAttempted,
    Retired,
    /// Drop retained the real mapping/resource in canonical quarantine after
    /// this failed retirement. No resource or native table was freed here.
    Quarantined(MmioError),
}

/// The actual resource owner, not a physical BAR tuple or a DMA allocation.
pub struct RegisterBar {
    pub index: u8,
    pub resource: Resource,
}

/// Actual original kernel doorbell reservation within BAR2. The resource's
/// original backing must pin this allocation as well as the whole BAR through
/// acknowledged retirement or permanent canonical quarantine, including Drop.
/// `reserved_bytes` covers complete physical pages; `logical_dwords` is the
/// original post-MES-allocation extent, not the entire BAR's capacity.
pub struct KernelDoorbells {
    pub index: u8,
    pub resource: Resource,
    pub offset: usize,
    pub reserved_bytes: usize,
    pub logical_dwords: u32,
    pub max_assignment: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub address: Address,
    pub device: u16,
    /// Original pciidlist match's driver flags; never a Metal feature mask.
    pub original_flags: u32,
    pub asic_type: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Layout {
    register_bar: u32,
    kernel_doorbells: u32,
    kernel_doorbell_bytes: u64,
}
const _: () = assert!(size_of::<Layout>() == 16);
const _: () = assert!(core::mem::offset_of!(Layout, kernel_doorbell_bytes) == 8);

unsafe extern "C" {
    fn stela_amd_native_register_bar(asic_type: u32, bar: *mut u32) -> c_int;
    fn stela_amd_native_bar_layout(
        asic_type: u32,
        doorbell_bar_bytes: u64,
        max_assignment: u32,
        page_bytes: u64,
        layout: *mut Layout,
    ) -> c_int;
}

/// The lifetime also borrows the actual matched PCI function. ResourceBacking
/// retains the real resource/reset epoch; caller's original owner retains its
/// doorbell BO reservation and all C consumers through this borrow.
pub struct AttachedBars<'a> {
    identity: Identity,
    admission: Option<Admission>,
    registers: Mapping,
    doorbells: Option<Mapping>,
    logical_doorbell_bytes: usize,
    active: bool,
    _function: PhantomData<&'a ()>,
}

fn preflight(error: Error) -> AttachError {
    AttachError {
        stage: Stage::Preflight,
        error,
        rollback: Rollback::NotAttempted,
    }
}

fn whole_pages(resource: &Resource, offset: usize, bytes: usize) -> Result<(), Error> {
    let span = resource.physical_span();
    let offset = u64::try_from(offset).map_err(|_| Error::InvalidRange)?;
    let bytes = u64::try_from(bytes).map_err(|_| Error::InvalidRange)?;
    let start = span
        .start()
        .checked_add(offset)
        .ok_or(Error::InvalidRange)?;
    let end = start.checked_add(bytes).ok_or(Error::InvalidRange)?;
    if bytes == 0
        || !start.is_multiple_of(PAGE_BYTES)
        || !bytes.is_multiple_of(PAGE_BYTES)
        || start < span.start()
        || end > span.end()
    {
        return Err(Error::InvalidRange);
    }
    Ok(())
}

fn query_layout(asic_type: u32, doorbells: Option<&KernelDoorbells>) -> Result<Layout, Error> {
    if doorbells.is_some_and(|d| d.index != 2) {
        return Err(Error::InvalidOwner);
    }
    let mut layout = Layout::default();
    // SAFETY: private C ABI has independent layout assertions and writes only
    // initialized local outputs; original policies are allocation-free.
    let status = unsafe {
        match doorbells {
            None => stela_amd_native_register_bar(asic_type, &mut layout.register_bar),
            Some(d) => stela_amd_native_bar_layout(
                asic_type,
                d.resource.physical_span().bytes(),
                d.max_assignment,
                PAGE_BYTES,
                &mut layout,
            ),
        }
    };
    if status != 0 {
        return Err(Error::Policy(status));
    }
    Ok(layout)
}

fn validate_doorbells(
    registers: PhysicalSpan,
    doorbells: &KernelDoorbells,
    layout: Layout,
) -> Result<usize, Error> {
    let bytes = usize::try_from(layout.kernel_doorbell_bytes).map_err(|_| Error::InvalidRange)?;
    if doorbells.logical_dwords != layout.kernel_doorbells
        || bytes == 0
        || bytes > doorbells.reserved_bytes
    {
        return Err(Error::InvalidRange);
    }
    whole_pages(
        &doorbells.resource,
        doorbells.offset,
        doorbells.reserved_bytes,
    )?;
    let span = doorbells.resource.physical_span();
    if registers.start() < span.end() && span.start() < registers.end() {
        return Err(Error::InvalidOwner);
    }
    Ok(bytes)
}

impl<'a> AttachedBars<'a> {
    /// The register window and admission of an attachment whose matched ASIC
    /// Linux brings up from IP discovery.
    pub(super) fn dynamic(&self) -> Result<(RegisterWindow<'a>, Admission), Error> {
        let admission = self.admission.ok_or(Error::AdmissionRequired)?;
        if admission.path() != IpPath::Dynamic {
            return Err(Error::StaticInitializationRequired);
        }
        Ok((self.registers()?, admission))
    }

    /// Attach from the actual original normal PCI match. The private result is
    /// retained on this exact mapping owner; the legacy manual unsafe path
    /// cannot mint this admission. No firmware/static fallback or activation.
    ///
    /// # Safety
    /// All actual resource/context/exclusion requirements of [`Self::attach`]
    /// hold. The matched function and resources are from this same genuine
    /// owner/reset epoch. Keep its original source/static plan; matching does
    /// not acquire the selected firmware or implement static IP initialization.
    pub unsafe fn attach_matched<C: ConfigSpace>(
        authority: &Authority,
        matched: &'a MatchedFunction<'_, C>,
        registers: RegisterBar,
        doorbells: Option<KernelDoorbells>,
    ) -> Result<Self, AttachError> {
        let admission = matched.admission();
        // SAFETY: actual owner/resource contract above; ASIC/flags are private
        // outputs of original matching, not independently supplied labels.
        let mut bars = unsafe {
            Self::attach(
                authority,
                matched.function(),
                admission.flags(),
                admission.asic(),
                registers,
                doorbells,
            )
        }?;
        bars.admission = Some(admission);
        Ok(bars)
    }

    /// How Linux brings up a matched attachment's IP blocks. None means the
    /// manual attachment has no admission.
    pub fn ip_path(&self) -> Option<IpPath> {
        self.admission.map(Admission::path)
    }

    /// Attach unpublished CPU windows for an actual original AMDGPU PCI match.
    /// The display-only diagnostic inventory is intentionally not consulted.
    ///
    /// # Safety
    /// `function`, `original_flags` and `asic_type` must describe the same real
    /// original pciidlist match and original native device/reset epoch. Both
    /// resources must be that function's assigned BARs, with live exclusive
    /// reservations; no other driver or firmware may use them. `registers`
    /// must be the complete original register BAR. `None` bootstraps registers
    /// before original IP discovery/BO initialization; it never reports doors
    /// or an initialized device. A supplied `doorbells` must describe the
    /// actual original kernel BO reservation in BAR2, actual ASIC
    /// max_assignment and post-allocation logical extent, including paging/MES
    /// pages. The original owner must retain that suballocation and prevent
    /// rebinding/reset/removal or C access after teardown begins, until every
    /// borrowed window is released and retirement is acknowledged. No booleans
    /// supplied here establish firmware, queue, power or device readiness.
    /// Native process/deferred context and the canonical provider's rules apply.
    pub unsafe fn attach<C: ConfigSpace>(
        authority: &Authority,
        function: &'a Function<C>,
        original_flags: u32,
        asic_type: u32,
        registers: RegisterBar,
        doorbells: Option<KernelDoorbells>,
    ) -> Result<Self, AttachError> {
        if function.vendor != 0x1002 || registers.resource.kind() != ResourceKind::Registers {
            return Err(preflight(Error::InvalidOwner));
        }
        let layout = query_layout(asic_type, doorbells.as_ref()).map_err(preflight)?;
        if u32::from(registers.index) != layout.register_bar {
            return Err(preflight(Error::InvalidOwner));
        }
        let register_bytes = usize::try_from(registers.resource.physical_span().bytes())
            .map_err(|_| preflight(Error::InvalidRange))?;
        whole_pages(&registers.resource, 0, register_bytes).map_err(preflight)?;
        let logical_doorbell_bytes = doorbells
            .as_ref()
            .map_or(Ok(0), |d| {
                validate_doorbells(registers.resource.physical_span(), d, layout)
            })
            .map_err(preflight)?;
        let mut registers = authority
            .map(
                registers.resource,
                0,
                register_bytes,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(|error| AttachError {
                stage: Stage::Registers,
                error: Error::Mapping(error),
                rollback: Rollback::NotAttempted,
            })?;
        let doorbell_mapping = match doorbells {
            None => None,
            Some(d) => match authority.map(
                d.resource,
                d.offset,
                d.reserved_bytes,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            ) {
                Ok(mapping) => Some(mapping),
                Err(error) => {
                    // SAFETY: no pointer/view was exposed and no CPU/device
                    // access occurred through this new unpublished mapping.
                    let rollback = match unsafe { registers.retire() } {
                        Ok(()) => Rollback::Retired,
                        Err(error) => Rollback::Quarantined(error),
                    };
                    // Failed retire is retained by canonical Drop quarantine.
                    drop(registers);
                    return Err(AttachError {
                        stage: Stage::Doorbells,
                        error: Error::Mapping(error),
                        rollback,
                    });
                }
            },
        };
        Ok(Self {
            identity: Identity {
                address: function.address,
                device: function.device,
                original_flags,
                asic_type,
            },
            admission: None,
            registers,
            doorbells: doorbell_mapping,
            logical_doorbell_bytes,
            active: true,
            _function: PhantomData,
        })
    }

    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// Retained views may be held by the original native C owner independently
    /// of this container; canonical retirement stays Busy until they drain.
    pub fn registers(&self) -> Result<RegisterWindow<'a>, Error> {
        if !self.active {
            return Err(Error::Retired);
        }
        let bytes = self.registers.bytes().map_err(Error::Mapping)?;
        Ok(RegisterWindow {
            view: self.registers.view(0..bytes).map_err(Error::Mapping)?,
            _owner: PhantomData,
        })
    }

    pub fn doorbells(&self) -> Result<Option<DoorbellWindow<'a>>, Error> {
        if !self.active {
            return Err(Error::Retired);
        }
        self.doorbells
            .as_ref()
            .map(|mapping| {
                Ok(DoorbellWindow {
                    view: mapping
                        .view(0..self.logical_doorbell_bytes)
                        .map_err(Error::Mapping)?,
                    _owner: PhantomData,
                })
            })
            .transpose()
    }

    pub fn register_physical_span(&self) -> Result<PhysicalSpan, Error> {
        self.registers.physical_span().map_err(Error::Mapping)
    }

    /// Attach the real kernel reservation after original discovery/doorbell BO
    /// creation, reusing the existing register mapping. Failure preserves that
    /// published register owner; canonical failed-map quarantine still applies.
    ///
    /// # Safety
    /// The reservation/backing, ASIC assignment and original owner must obey
    /// `attach`'s same-device/reset-epoch and lifetime requirements. The backing
    /// retains the actual BO suballocation even on permanent map quarantine.
    /// Original device initialization remains serialized by its actual owner.
    pub unsafe fn attach_kernel_doorbells(
        &mut self,
        authority: &Authority,
        doorbells: KernelDoorbells,
    ) -> Result<(), AttachError> {
        if !self.active || self.doorbells.is_some() {
            return Err(preflight(Error::InvalidOwner));
        }
        let layout = query_layout(self.identity.asic_type, Some(&doorbells)).map_err(preflight)?;
        let span = self.register_physical_span().map_err(preflight)?;
        let bytes = validate_doorbells(span, &doorbells, layout).map_err(preflight)?;
        let mapping = authority
            .map(
                doorbells.resource,
                doorbells.offset,
                doorbells.reserved_bytes,
                CacheAttribute::Uncached,
                Protection::ReadWrite,
            )
            .map_err(|error| AttachError {
                stage: Stage::Doorbells,
                error: Error::Mapping(error),
                rollback: Rollback::NotAttempted,
            })?;
        self.doorbells = Some(mapping);
        self.logical_doorbell_bytes = bytes;
        Ok(())
    }

    /// Retire only after real original consumers stop and posted accesses drain.
    /// An error disables new windows and retains the exact mappings for retry;
    /// Drop without acknowledged retirement uses canonical quarantine.
    ///
    /// # Safety
    /// Every C/CPU/worker/IRQ consumer and original-owner access through all
    /// obtained raw pointers must be stopped/drained, with no future access.
    /// Caller proves device/reset exclusion, correct process/deferred context
    /// and all canonical retirement requirements. This does not stop hardware.
    pub unsafe fn retire(&mut self) -> Result<(), Error> {
        self.active = false;
        if let Some(mapping) = &mut self.doorbells {
            // SAFETY: the caller supplies the real shared consumer drain.
            unsafe { mapping.retire().map_err(Error::Mapping)? };
            self.doorbells = None;
        }
        // SAFETY: the same actual consumer drain and context proof apply.
        unsafe { self.registers.retire().map_err(Error::Mapping) }
    }
}

/// Bounded register mapping only. Original RREG/WREG dispatch still owns
/// direct versus indirect PCIe/KIQ/RLCG/XCC routing and power/reset rules.
pub struct RegisterWindow<'a> {
    view: MappingView,
    _owner: PhantomData<&'a ()>,
}
impl RegisterWindow<'_> {
    pub fn bytes(&self) -> usize {
        self.view.bytes()
    }

    /// Private native C bootstrap may borrow this exact rmmio pointer/size.
    /// No Rust reference is formed, and no register is read or written.
    ///
    /// # Safety
    /// The pointer must not escape this borrowed window's lifetime. All actual
    /// accesses must use original AMDGPU register routing/width/order/reset
    /// semantics. A pointer is not authority to bypass indirect/KIQ/XCC routes.
    pub unsafe fn native_base(&self) -> Result<NonNull<u8>, Error> {
        self.view.address(0, self.bytes()).map_err(Error::Mapping)
    }

    /// A checked direct DWORD location. An out-of-window register requires
    /// original indirect dispatch, never a wrapped or widened MMIO access.
    pub fn direct_dword(&self, register: u32) -> Result<NonNull<u32>, Error> {
        let offset = usize::try_from(register)
            .ok()
            .and_then(|r| r.checked_mul(4))
            .filter(|offset| offset.checked_add(4).is_some_and(|end| end <= self.bytes()))
            .ok_or(Error::IndirectRegisterRequired)?;
        let address = self.view.address(offset, 4).map_err(Error::Mapping)?;
        if !(address.as_ptr() as usize).is_multiple_of(4) {
            return Err(Error::InvalidRange);
        }
        Ok(address.cast())
    }
}

pub struct DoorbellWindow<'a> {
    view: MappingView,
    _owner: PhantomData<&'a ()>,
}
impl DoorbellWindow<'_> {
    pub fn bytes(&self) -> usize {
        self.view.bytes()
    }

    fn address(&self, index: u32, width: usize) -> Result<NonNull<u8>, Error> {
        let offset = usize::try_from(index)
            .ok()
            .and_then(|i| i.checked_mul(4))
            .ok_or(Error::InvalidRange)?;
        let pointer = self.view.address(offset, width).map_err(Error::Mapping)?;
        if !(pointer.as_ptr() as usize).is_multiple_of(width) {
            return Err(Error::InvalidRange);
        }
        Ok(pointer)
    }

    /// Original doorbell index is measured in DWORDs. Pointer access remains
    /// unsafe and requires the original initialized ring/doorbell owner.
    pub fn dword(&self, index: u32) -> Result<NonNull<u32>, Error> {
        self.address(index, 4).map(NonNull::cast)
    }

    /// Keep the original native atomic 64-bit transaction; never synthesize
    /// two DWORD doorbell writes. Both DWORDs and alignment are checked.
    pub fn qword(&self, index: u32) -> Result<NonNull<u64>, Error> {
        self.address(index, 8).map(NonNull::cast)
    }
}
