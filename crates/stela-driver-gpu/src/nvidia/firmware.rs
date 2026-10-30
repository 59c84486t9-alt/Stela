//! Original RM firmware lookup over Stela's immutable firmware catalog.
//!
//! This supplies CPU image bytes only. Manifest length/SHA-256 integrity is not
//! vendor authentication. Original RM ELF/version/signature checks, upload,
//! reset, IRQ/context services and device initialization remain required.
use super::{memory, services::MemoryServices, services::ServiceError};
use core::{ffi::CStr, ffi::c_char, ffi::c_void, ptr, ptr::NonNull};
use stela_driver_core::firmware::{Image, Provider, Requirement, Target};

unsafe extern "C" {
    fn stela_nvidia_firmware_family(architecture: u32, implementation: u32) -> u32;
    fn stela_nvidia_firmware_alignment() -> u64;
}

/// A provider bound to one native device's observed NVIDIA chip family. The
/// original vendor helper selects the family; no parallel architecture table.
/// Attach before pinning/binding [`MemoryServices::with_firmware`].
pub struct FirmwareBinding<'a> {
    provider: &'a dyn Provider,
    family: u32,
}

impl<'a> FirmwareBinding<'a> {
    /// # Safety
    /// `architecture` and `implementation` are the device's observed
    /// original NV_ARCH facts (not PCI IDs or a guest's assertions). This binding
    /// and its MemoryServices requester describe the same device/reset epoch.
    /// Keep provider/catalog immutable, CPU-readable and live until all firmware
    /// tokens are returned and the pinned service/state successfully unbinds.
    /// Serialize every lookup/release with the other service operations; exclude
    /// interrupt, allocator and provider reentry. The global heap must be live.
    pub unsafe fn new(
        provider: &'a dyn Provider,
        architecture: u32,
        implementation: u32,
    ) -> Result<Self, ServiceError> {
        // SAFETY: pure original C selector, same native integer ABI.
        let family = unsafe { stela_nvidia_firmware_family(architecture, implementation) };
        if family == 0 {
            return Err(ServiceError::InvalidConfiguration);
        }
        Ok(Self { provider, family })
    }
}

struct Token<'a> {
    image: Image<'a>,
    owner: *const MemoryServices<'a>,
}
const _: () = assert!(align_of::<Token<'_>>() <= memory::ALIGNMENT);

fn native_length(length: usize, address: usize, alignment: usize) -> Option<u32> {
    if length == 0 || alignment == 0 || !address.is_multiple_of(alignment) {
        return None;
    }
    u32::try_from(length).ok()
}

/// All fallible preparation precedes publication/counting. The internal bounded
/// allocator seam exercises real metadata OOM without exhausting the host heap.
fn prepare<'a>(
    owner: &'a MemoryServices<'a>,
    state: *mut c_void,
    family: u32,
    requirement: Requirement<'_>,
    allocate: impl FnOnce() -> Option<NonNull<c_void>>,
) -> Option<(NonNull<Token<'a>>, *const c_void, u32)> {
    if !owner.bound_to(state) {
        return None;
    }
    let binding = owner.firmware.as_ref()?;
    if binding.family != family {
        return None;
    }
    let count = owner.firmware_tokens.get().checked_add(1)?;
    let image = binding.provider.load(requirement).ok()?;
    // A delegating Provider can accidentally return a different valid catalog
    // image. Exact name/target still must match the original vendor request.
    if image.name() != requirement.name || image.target() != requirement.target {
        return None;
    }
    // SAFETY: a pure layout query on the original vendor ELF types.
    let alignment = unsafe { stela_nvidia_firmware_alignment() } as usize;
    let bytes = native_length(
        image.bytes().len(),
        image.bytes().as_ptr() as usize,
        alignment,
    )?;
    let buffer = image.bytes().as_ptr().cast();
    let storage = allocate()?.cast::<Token<'a>>();
    // SAFETY: the common heap returned sufficient/aligned exclusively owned
    // metadata. The token keeps its Image/provider borrow until the unique put.
    unsafe { storage.as_ptr().write(Token { image, owner }) };
    owner.firmware_tokens.set(count);
    Some((storage, buffer, bytes))
}

/// # Safety
/// Only the native C shim supplies this bound state/service and static original
/// selector strings. Output slots are writable, aligned and disjoint. The pinned
/// owner, catalog and original state remain live through every published token;
/// all operations obey the serialized nonreentrant process/heap contract above.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_get_firmware(
    services: *mut c_void,
    state: *mut c_void,
    family: u32,
    name: *const c_char,
    hardware: *const c_char,
    revision: *const c_char,
    buffer: *mut *const c_void,
    bytes: *mut u32,
) -> *const c_void {
    // SAFETY: C only forwards the handle installed in this live original state.
    let owner = unsafe { &*services.cast::<MemoryServices<'_>>() };
    // SAFETY: these are static, terminated ASCII strings from original helpers.
    let labels = unsafe {
        (
            CStr::from_ptr(name).to_str(),
            CStr::from_ptr(hardware).to_str(),
            CStr::from_ptr(revision).to_str(),
        )
    };
    let (Ok(name), Ok(hardware), Ok(revision)) = labels else {
        return ptr::null();
    };
    let result = prepare(
        owner,
        state,
        family,
        Requirement {
            name,
            target: Target {
                driver: "nvidia-rm",
                hardware,
                revision,
                board: None,
            },
            minimum_bytes: 1,
        },
        || memory::allocate(size_of::<Token<'_>>() as u64).ok(),
    );
    let Some((token, data, size)) = result else {
        return ptr::null();
    };
    // SAFETY: caller-owned checked native output slots. No fallible operation
    // follows; publish the one unique token only after both outputs are ready.
    unsafe {
        bytes.write(size);
        buffer.write(data);
    }
    token.as_ptr().cast()
}

/// # Safety
/// Return only a live firmware token from this adapter, once, after all CPU
/// readers stop. Provider/service/state/global heap remain live and operations
/// are serialized, noninterrupt and nonreentrant. No invented completion.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_put_firmware(token: *const c_void) {
    // SAFETY: original nv_put_firmware filters NULL; unique token kind.
    let token = token.cast_mut().cast::<Token<'_>>();
    // SAFETY: the raw ownership contract keeps token and pinned service.
    let value = unsafe { &*token };
    // SAFETY: the token keeps its pinned owner service alive.
    let owner = unsafe { &*value.owner };
    debug_assert!(owner.firmware_tokens.get() > 0);
    // Read the image borrow before release; no image copy or ownership escape.
    let _ = value.image.bytes();
    owner.firmware_tokens.set(owner.firmware_tokens.get() - 1);
    // SAFETY: unique put after all token users stop; exact common-heap free.
    unsafe {
        token.drop_in_place();
        memory::free(token.cast());
    }
}

#[cfg(test)]
mod tests;
