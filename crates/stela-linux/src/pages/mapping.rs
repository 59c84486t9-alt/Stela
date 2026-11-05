//! Actual catalogue allocation references for native WB RAM aliases.
//! No PFN, cache override, root mapper or hardware permission is created here.
use super::*;
use crate::{
    kernel::{ExecutionPin, KernelOwner},
    owner::{Platform, RawOwner},
};
use core::mem::ManuallyDrop;

#[repr(C)]
struct NativeMappingPage {
    record: *mut c_void,
    provider_pin: *mut c_void,
    cpu_page: *mut c_void,
}
unsafe extern "C" {
    fn stela_linux_page_mapping_pin(
        generation: u64,
        context: *const c_void,
        owner: *const RawOwner,
        physical: u64,
        out: *mut NativeMappingPage,
    ) -> c_int;
    fn stela_linux_page_mapping_unpin(
        generation: u64,
        context: *const c_void,
        owner: *const RawOwner,
        token: *mut c_void,
    ) -> c_int;
}
static RETAINED: AtomicU64 = AtomicU64::new(0);
pub fn retained_mapping_pins() -> u64 {
    RETAINED.load(Ordering::Relaxed)
}

/// Exact original allocation/page reference, affine to its native release scope.
/// Exporting backing metadata does not replace keeping this object through all
/// Linux page-descriptor, VMA/alias and CPU mapping users. No Drop unpin occurs.
#[must_use = "retain through all alias users; explicitly release only after actual mapping retirement"]
pub struct MappingPagePin {
    pages: ManuallyDrop<PinnedPages>,
    execution: ManuallyDrop<ExecutionPin>,
    context: *const c_void,
    owner: *const RawOwner,
    generation: u64,
    record: NonNull<c_void>,
    physical: u64,
    cpu: NonNull<u8>,
    page_index: usize,
    released: bool,
    local: PhantomData<Rc<()>>,
}
impl MappingPagePin {
    /// The original actual allocation, never a caller-owned PA list.
    pub fn backing(&self) -> &PinnedPages {
        &self.pages
    }
    pub fn physical(&self) -> u64 {
        self.physical
    }
    pub fn cpu_page(&self) -> NonNull<u8> {
        self.cpu
    }
    pub fn page_index(&self) -> usize {
        self.page_index
    }
    /// # Safety
    /// On the original canonical checked CPU/root/process task, already entered
    /// quiescent. Every native root/VMA/alias/CPU user of this claim has actually
    /// retired. No outstanding derived view substitutes for this allocation ref.
    /// Failure changes nothing and returns the complete held graph for retry.
    pub unsafe fn release<K: Platform, const N: usize>(
        mut self,
        kernel: &KernelOwner<K, N>,
    ) -> Result<(), Self> {
        if kernel.raw() != self.owner {
            return Err(self);
        }
        // SAFETY: C validates exact generation/Context/owner/token before any
        // decrement; success performs no callback, allocator or final free.
        let status = unsafe {
            stela_linux_page_mapping_unpin(
                self.generation,
                self.context,
                self.owner,
                self.record.as_ptr(),
            )
        };
        if status != 0 {
            return Err(self);
        }
        self.released = true;
        // SAFETY: the original C Pin still owns these pages until later
        // pages_finish. Clone release cannot free/recycle its actual backing.
        // Actual Context and KernelOwner retain callback/execution code too.
        unsafe {
            ManuallyDrop::drop(&mut self.pages);
            ManuallyDrop::drop(&mut self.execution);
        }
        Ok(())
    }
}
impl Drop for MappingPagePin {
    fn drop(&mut self) {
        if !self.released {
            // Keep the real C ref, original backing and code/root graph. The
            // C ref blocks catalogue unregister; Catalog Drop quarantines its
            // original Provider Context, not a substitute allocation.
            let _ = RETAINED.try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        }
    }
}
impl<P: Provider> Catalog<P> {
    /// Pin one live ordinary WB allocation page for a separately owned mapper.
    ///
    /// # Safety
    /// Already entered/quiescent on the registered canonical owner's real
    /// CPU/root/process task. Caller supplies actual alias/cache/root ownership
    /// separately and keeps the affine result through every such user. This
    /// exports existing original backing only; it supplies no new cache policy,
    /// PFN discovery, native I/O, task-stack or root-mapping permission.
    pub unsafe fn pin_mapping<K: Platform, const N: usize>(
        &self,
        kernel: &KernelOwner<K, N>,
        physical: u64,
    ) -> Result<MappingPagePin, Error> {
        let context = self.context.as_ref().ok_or(Error::InvalidReservation)?;
        context.entry.check(kernel)?;
        let ContextEntry::Canonical { owner, execution } = &context.entry else {
            return Err(Error::InvalidReservation);
        };
        let context_pointer = ptr::from_ref(&**context).cast::<c_void>();
        let mut native = NativeMappingPage {
            record: ptr::null_mut(),
            provider_pin: ptr::null_mut(),
            cpu_page: ptr::null_mut(),
        };
        // SAFETY: actual Context/generation owns this provider ABI. C takes
        // its real allocation ref before returning any original Pin pointer.
        let status = unsafe {
            stela_linux_page_mapping_pin(
                self.generation,
                context_pointer,
                *owner,
                physical,
                &raw mut native,
            )
        };
        if status != 0 {
            return Err(Error::Native(status));
        }
        let record = NonNull::new(native.record).expect("successful allocation ref");
        let provider =
            NonNull::new(native.provider_pin.cast::<Pin>()).expect("original provider Pin");
        let cpu = NonNull::new(native.cpu_page.cast::<u8>()).expect("original CPU page");
        // SAFETY: exact registered Rust Context plus C ref keeps its original
        // Rust-created Pin alive. This clones actual PageBacking ownership,
        // not addresses, a reservation descriptor or an arbitrary caller Arc.
        let pages = unsafe { provider.as_ref() }.pages.clone();
        let mut pin = MappingPagePin {
            pages: ManuallyDrop::new(pages),
            execution: ManuallyDrop::new(execution.clone()),
            context: context_pointer,
            owner: *owner,
            generation: self.generation,
            record,
            physical,
            cpu,
            page_index: 0,
            released: false,
            local: PhantomData,
        };
        let validation = (|| {
            if pin.pages.page_shift() != PAGE_SHIFT as u8
                || pin.pages.cache_attribute() != CacheAttribute::WriteBack
            {
                return Err(Error::InvalidReservation);
            }
            let index = pin
                .pages
                .physical_pages()
                .iter()
                .position(|page| *page == physical)
                .ok_or(Error::InvalidReservation)?;
            let offset = index
                .checked_mul(PAGE_BYTES)
                .ok_or(Error::InvalidReservation)?;
            let mapping = pin
                .pages
                .cpu_mapping(CacheAttribute::WriteBack)
                .map_err(Error::Memory)?;
            let address = mapping.address(offset, PAGE_BYTES).map_err(Error::Memory)?;
            if address != cpu {
                return Err(Error::InvalidReservation);
            }
            pin.page_index = index;
            Ok(())
        })();
        if let Err(error) = validation {
            // SAFETY: no mapping was exposed; the same actual release scope
            // applies. Refusal keeps the complete graph via its default Drop.
            if let Err(retained) = unsafe { pin.release(kernel) } {
                drop(retained);
            }
            return Err(error);
        }
        Ok(pin)
    }
}
