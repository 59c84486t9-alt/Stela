//! Original NVIDIA DMA allocation hooks over canonical attached-domain leases.
//! Opaque dma_dev values are compared with allocation/token provenance before
//! any platform access; they are never cast into an arbitrary C device object.
use super::{
    allocation::Allocation,
    memory,
    services::{MemoryServices, Status},
};
use crate::bus::dma::mapping::{Direction, DmaError, DmaMapping};
use alloc::sync::Arc;
use core::{ffi::c_void, ptr};

struct Token {
    lease: DmaMapping,
    device_key: *mut c_void,
    count: u64,
}

const _: () = assert!(align_of::<Token>() <= memory::ALIGNMENT);

fn dma_error(error: DmaError) -> Status {
    match error {
        DmaError::IommuUnavailable => Status::NotSupported,
        DmaError::InvalidRange => Status::InvalidArgument,
        DmaError::AddressLimit => Status::InvalidAddress,
        DmaError::Unmapped => Status::InvalidState,
        _ => Status::OperatingSystem,
    }
}

/// # Safety
/// The original C caller supplies the live producer Allocation in *private,
/// one writable native address slot for contiguous allocations or count slots
/// otherwise, and serialized process/deferred context. On success *private
/// changes ownership kind to a unique DMA token; the Allocation remains owned
/// separately by its original memory descriptor. No guest pointers are valid.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_dma_map(
    device_key: *mut c_void,
    count: u64,
    addresses: *mut u64,
    contiguous: u8,
    read_only: u8,
    private: *mut *mut c_void,
) -> Status {
    // SAFETY: the C shim checks slots; the caller supplies this live
    // native Allocation kind, not another import or a previous DMA token.
    let allocation = unsafe { &*(*private).cast::<Allocation>() };
    let Some(origin) = allocation.origin.as_ref() else {
        return Status::NotSupported;
    };
    if device_key != origin.device_key
        || count != u64::from(origin.count)
        || contiguous != u8::from(origin.contiguous)
        || read_only > 1
    {
        return Status::InvalidArgument;
    }
    // SAFETY: producer provenance identifies the live pinned service, whose
    // unbind refuses any surviving producer allocation or published DMA token.
    // The arbitrary incoming device key was compared before this dereference.
    let services = unsafe { &*origin.device_key.cast::<MemoryServices<'_>>() };
    if !services.bound_to(origin.state) {
        return Status::InvalidState;
    }
    if let Err(status) = services.can_map() {
        return status;
    }
    let pages = allocation.pages();
    let page_bytes = 1u64 << pages.page_shift();
    let physical = pages.physical_pages();
    let entries = if contiguous != 0 { 1 } else { physical.len() };
    for (index, &expected) in physical.iter().take(entries).enumerate() {
        // SAFETY: count/policy match the original allocation; caller supplies
        // its complete native physical-PTE input/output capacity.
        if unsafe { addresses.add(index).read() } != expected {
            return Status::InvalidArgument;
        }
    }
    // Reserve metadata before creating a live domain mapping. This is the
    // shared global heap, not another mapping registry or DMA allocator.
    let storage = match memory::allocate(size_of::<Token>() as u64) {
        Ok(storage) => storage,
        Err(_) => return Status::NoMemory,
    };
    let prepare = (|| -> Result<DmaMapping, Status> {
        let direction = if read_only != 0 {
            Direction::ToDevice
        } else {
            Direction::Bidirectional
        };
        let mut lease = DmaMapping::map(
            Arc::clone(&origin.domain),
            pages.clone(),
            direction,
            origin.address_limit,
        )
        .map_err(dma_error)?;
        let valid_address = lease
            .address()
            .is_ok_and(|address| address.is_multiple_of(page_bytes));
        let visibility = if valid_address {
            lease.sync_for_device(0..lease.bytes()).map_err(dma_error)
        } else {
            Err(Status::InvalidAddress)
        };
        if let Err(error) = visibility {
            // No IOVA has escaped this API, so this newly installed mapping
            // has never been submitted. Real removal/invalidation still must
            // finish; a failure drops into canonical observable quarantine.
            // SAFETY: no device/worker can know the unpublished address.
            if let Err(removal) = unsafe { lease.unmap() } {
                return Err(dma_error(removal));
            }
            return Err(error);
        }
        Ok(lease)
    })();
    let lease = match prepare {
        Ok(lease) => lease,
        Err(status) => {
            // SAFETY: uninitialized private metadata storage never escaped.
            unsafe { memory::free(storage.as_ptr()) };
            return status;
        }
    };
    // Successful visibility, immutable live address and full bounds were
    // checked before the first caller output is changed.
    let address = match lease.address() {
        Ok(address) => address,
        Err(error) => {
            // This cannot occur for the unmodified lease. Dropping
            // it still quarantines pins rather than assuming teardown.
            // SAFETY: the private metadata storage never escaped.
            unsafe { memory::free(storage.as_ptr()) };
            return dma_error(error);
        }
    };
    // SAFETY: distinct aligned metadata owns this lease through the
    // single original unmap call. It has not been published to the caller.
    unsafe {
        storage.cast::<Token>().as_ptr().write(Token {
            lease,
            device_key,
            count,
        });
    }
    services.mapped();
    for index in 0..entries {
        // SAFETY: output capacity matches the validated allocation policy;
        // canonical mapping bounds cover the complete native page sequence.
        unsafe {
            addresses
                .add(index)
                .write(address + index as u64 * page_bytes)
        };
    }
    // SAFETY: all fallible work/accounting completed before caller publication.
    unsafe { private.write(storage.as_ptr()) };
    Status::Ok
}

/// # Safety
/// Return this device's live DMA token once, with matching count, only after
/// device completion, removed GPU bindings and stopped/drained native
/// submission/IRQ workers. No new device access may start. Context must permit
/// the real domain/backing/global-heap operations and their final release.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_dma_unmap(
    device_key: *mut c_void,
    count: u64,
    private: *mut *mut c_void,
) -> Status {
    // SAFETY: the shim checked slots; the caller returns the live token
    // kind created by dma_map. Never dereference the untrusted device key.
    let token = unsafe { &*(*private).cast::<Token>() };
    if token.device_key != device_key || token.count != count {
        return Status::InvalidArgument;
    }
    // SAFETY: the pinned service/state outlive every published token; unbind
    // refuses this live mapping count. Never dereference the supplied key.
    let services = unsafe { &*token.device_key.cast::<MemoryServices<'_>>() };
    if !services.has_mapping() {
        return Status::InvalidState;
    }
    // SAFETY: validation completed and the caller transfers unique ownership
    // after real quiescence. The metadata is now uninitialized and private.
    let mut token = unsafe { (*private).cast::<Token>().read() };
    // SAFETY: `private` is the caller's valid handle slot, read just above.
    let storage = unsafe { private.replace(ptr::null_mut()) };
    // Match real dma_unmap's CPU visibility before releasing translations.
    // SAFETY: the caller establishes exclusive CPU ownership/completion.
    let result = unsafe { token.lease.sync_for_cpu(0..token.lease.bytes()) }.and_then(|()| {
        // SAFETY: the same caller-supplied complete quiescence applies.
        unsafe { token.lease.unmap() }
    });
    // Official osIovaUnmap logs an error then clears pOsData unconditionally.
    // Consume a failed live lease into canonical observable quarantine here;
    // never rely on that original caller keeping a retry token. Drop keeps
    // the domain/pins on any uncertain sync/removal/invalidation error.
    drop(token);
    services.retired();
    // SAFETY: the token's value was moved out and dropped once; return only
    // this exact private metadata block to the existing shared heap.
    unsafe { memory::free(storage) };
    match result {
        Ok(()) => Status::Ok,
        Err(error) => dma_error(error),
    }
}
