//! Original RM firmware lookup over Stela's immutable firmware catalog.
//!
//! This supplies CPU image bytes only. Manifest length/SHA-256 integrity is not
//! vendor authentication. Original RM ELF/version/signature checks, upload,
//! reset, IRQ/context services and actual device initialization remain required.
use super::{memory, services::MemoryServices, services::ServiceError};
use crate::firmware::{Image, Provider, Requirement, Target};
use core::{ffi::CStr, ffi::c_char, ffi::c_void, ptr, ptr::NonNull};

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
    /// `architecture` and `implementation` are the actual device's observed
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
/// are serialized, noninterrupt and nonreentrant. No fabricated completion.
#[unsafe(no_mangle)]
unsafe extern "C" fn stela_nvidia_put_firmware(token: *const c_void) {
    // SAFETY: original nv_put_firmware filters NULL; unique actual token kind.
    let token = token.cast_mut().cast::<Token<'_>>();
    // SAFETY: the raw ownership contract retains token and pinned service.
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
mod tests {
    use super::*;
    use crate::{
        bus::{
            dma::{
                mapping::{Direction, DmaDomain, DmaError, DomainMapping},
                memory::{CacheAttribute, MemoryError, PageSource, PinnedPages},
            },
            pci::Address,
        },
        firmware::{Catalog, Provenance, Resource},
    };
    use alloc::{alloc::alloc_zeroed, alloc::dealloc, boxed::Box, format, sync::Arc, vec};
    use core::{alloc::Layout, cell::Cell, ops::Range, pin::Pin};
    use sha2::{Digest, Sha256};

    unsafe extern "C" {
        fn stela_nvidia_state_layout(bytes: *mut u64, alignment: *mut u64);
        fn stela_nvidia_firmware_version() -> *const c_char;
        fn nv_get_firmware(
            state: *mut c_void,
            kind: u32,
            family: u32,
            buffer: *mut *const c_void,
            bytes: *mut u32,
        ) -> *const c_void;
        fn nv_put_firmware(token: *const c_void);
    }

    // The explicit CPU model attests only its 4KiB geometry. It never exercises
    // RAM or DMA: unsupported operations are genuine
    // failures so an accidental dependency cannot masquerade as native success.
    struct Unavailable;
    impl PageSource for Unavailable {
        fn page_geometry(&self) -> Result<crate::bus::dma::memory::PageGeometry, MemoryError> {
            crate::bus::dma::memory::PageGeometry::base_only(12)
        }
        fn allocate(
            &self,
            _: usize,
            _: usize,
            _: CacheAttribute,
        ) -> Result<PinnedPages, MemoryError> {
            panic!("firmware lookup must not allocate RAM pins")
        }
    }
    // SAFETY: this model can never publish any device mapping or successful sync.
    unsafe impl DmaDomain for Unavailable {
        unsafe fn map(
            &self,
            _: &crate::bus::dma::pages::DmaPages,
            _: Direction,
            _: u64,
        ) -> Result<DomainMapping, DmaError> {
            panic!("firmware bytes must not become DMA addresses")
        }
        unsafe fn unmap(&self, _: DomainMapping) -> Result<(), DmaError> {
            panic!("no DMA mapping exists")
        }
        unsafe fn sync_for_device(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            panic!("no DMA mapping exists")
        }
        unsafe fn sync_for_cpu(
            &self,
            _: DomainMapping,
            _: Range<usize>,
            _: Direction,
        ) -> Result<(), DmaError> {
            panic!("no DMA mapping exists")
        }
    }

    struct State(NonNull<u8>, Layout);
    impl State {
        fn new() -> Self {
            let (mut bytes, mut alignment) = (0, 0);
            // SAFETY: writable native integer slots for original type layout.
            unsafe { stela_nvidia_state_layout(&mut bytes, &mut alignment) };
            let layout = Layout::from_size_align(bytes as usize, alignment as usize).unwrap();
            // SAFETY: original type layout; zero PCI fixture, never GPU init.
            Self(
                NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap(),
                layout,
            )
        }
        fn raw(&self) -> *mut c_void {
            self.0.as_ptr().cast()
        }
    }
    impl Drop for State {
        fn drop(&mut self) {
            // SAFETY: fixture callers and bindings ended before final release.
            unsafe { dealloc(self.0.as_ptr(), self.1) };
        }
    }

    #[repr(align(16))]
    struct Aligned([u8; 32]);
    static DATA: Aligned = Aligned([0x5a; 32]);
    fn version() -> &'static str {
        // SAFETY: C returns the static version generated from vendor version.mk.
        unsafe { CStr::from_ptr(stela_nvidia_firmware_version()) }
            .to_str()
            .unwrap()
    }
    fn target(hardware: &str) -> Target<'_> {
        Target {
            driver: "nvidia-rm",
            hardware,
            revision: version(),
            board: None,
        }
    }
    fn make_catalog(name: &str, hardware: &str, bytes: &'static [u8]) -> Catalog {
        Catalog::from_persistent_handoff(vec![Resource {
            name,
            target: target(hardware),
            provenance: Provenance {
                source: "synthetic CPU fixture",
                revision: "1",
                member: name,
                license: "MIT",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(bytes).into(),
            bytes,
        }])
        .unwrap()
    }
    fn bind<'a>(
        provider: Option<&'a dyn Provider>,
        architecture: u32,
        implementation: u32,
        state: &State,
    ) -> Pin<Box<MemoryServices<'a>>> {
        static SOURCE: Unavailable = Unavailable;
        crate::gpu::nvidia::page_geometry::tests::initialize_model(12);
        // SAFETY: CPU model only, same zero PCI requester; no hardware operations.
        let mut service = unsafe {
            MemoryServices::new(
                &SOURCE,
                Arc::new(Unavailable),
                Address {
                    segment: 0,
                    bus: 0,
                    device: 0,
                    function: 0,
                },
                12,
                u64::MAX,
            )
        }
        .unwrap();
        if let Some(provider) = provider {
            // SAFETY: test attests this synthetic observed architecture to this model.
            service = service.with_firmware(
                unsafe { FirmwareBinding::new(provider, architecture, implementation) }.unwrap(),
            );
        }
        let mut service = Box::pin(service);
        // SAFETY: live original fixture state, no concurrent callers, pinned owner.
        unsafe { service.as_mut().bind(state.raw()) }.unwrap();
        service
    }
    fn request(state: *mut c_void, kind: u32, family: u32) -> (*const c_void, *const c_void, u32) {
        let mut buffer = ptr::dangling::<c_void>();
        let mut bytes = 0xabcd;
        // SAFETY: either NULL or exact live fixture state; distinct writable outputs.
        let token = unsafe { nv_get_firmware(state, kind, family, &mut buffer, &mut bytes) };
        (token, buffer, bytes)
    }
    fn failed(state: *mut c_void, kind: u32, family: u32) {
        let (token, buffer, bytes) = request(state, kind, family);
        assert!(token.is_null());
        assert_eq!(buffer, ptr::dangling());
        assert_eq!(bytes, 0xabcd);
    }

    #[test]
    fn original_selectors_cover_architecture_splits_and_all_package_kinds() {
        // Frozen independent expectations from the original nv-firmware*.h switch
        // bodies at the retained vendor pin. No production enum/selector mirror.
        for (arch, implementation, family, hardware, suffix) in [
            (0x160, 6, 1, "tu10x", "tu10x"),
            (0x160, 7, 2, "tu11x", "tu10x"),
            (0x170, 0, 3, "ga100", "tu10x"),
            (0x170, 2, 4, "ga10x", "ga10x"),
            (0x190, 2, 5, "ad10x", "ga10x"),
            (0x180, 0, 6, "gh100", "ga10x"),
            (0x1a0, 0, 8, "gb10x", "ga10x"),
            (0x1b0, 0, 9, "gb20x", "ga10x"),
            (0x1c0, 0, 10, "gr10x", "ga10x"),
            (0x1a0, 11, 11, "gb10y", "ga10x"),
            (0x1b0, 11, 12, "gb20y", "ga10x"),
            (0x1b0, 12, 12, "gb20y", "ga10x"),
        ] {
            // SAFETY: pure selector on scalar fixture values.
            assert_eq!(
                unsafe { stela_nvidia_firmware_family(arch, implementation) },
                family
            );
            for (kind, prefix) in [(0, "gsp"), (1, "gsp_log"), (2, "ucodes")] {
                let name = format!("nvidia/{}/{}_{}.bin", version(), prefix, suffix);
                let catalog = make_catalog(&name, hardware, &DATA.0);
                let state = State::new();
                let mut owner = bind(Some(&catalog), arch, implementation, &state);
                let (token, buffer, bytes) = request(state.raw(), kind, family);
                assert!(!token.is_null());
                assert_eq!(buffer, DATA.0.as_ptr().cast());
                assert_eq!(bytes, 32);
                assert_eq!(owner.firmware_tokens.get(), 1);
                // SAFETY: a token is still live, so refusal preserves installed slots.
                assert_eq!(
                    unsafe { owner.as_mut().unbind() },
                    Err(ServiceError::Native(0x40))
                );
                // SAFETY: no more byte readers, actual unique token, supported context.
                unsafe { nv_put_firmware(token) };
                assert_eq!(owner.firmware_tokens.get(), 0);
                // SAFETY: every token/caller ended, no hardware was activated.
                unsafe { owner.as_mut().unbind() }.unwrap();
            }
        }
    }

    #[test]
    fn original_abi_rejects_invalid_inputs_and_preserves_outputs() {
        let name = format!("nvidia/{}/gsp_ga10x.bin", version());
        let catalog = make_catalog(&name, "ga10x", &DATA.0);
        let state = State::new();
        failed(ptr::null_mut(), 0, 4);
        failed(state.raw(), 0, 4);
        let mut owner = bind(Some(&catalog), 0x170, 2, &state);
        for (kind, family) in [
            (3, 4),
            (u32::MAX, 4),
            (0, 0),
            (0, 7),
            (0, 13),
            (0, u32::MAX),
            (0, 5),
            (1, 4),
        ] {
            failed(state.raw(), kind, family);
        }
        let mut bytes = 73;
        let mut buffer = ptr::dangling::<c_void>();
        // SAFETY: invalid NULL output slots are rejected before lookup/publication.
        unsafe {
            assert!(nv_get_firmware(state.raw(), 0, 4, ptr::null_mut(), &mut bytes).is_null());
            assert!(nv_get_firmware(state.raw(), 0, 4, &mut buffer, ptr::null_mut()).is_null());
            nv_put_firmware(ptr::null());
        }
        assert_eq!(bytes, 73);
        assert_eq!(buffer, ptr::dangling());
        assert_eq!(owner.firmware_tokens.get(), 0);
        // SAFETY: no tokens or callers remain.
        unsafe { owner.as_mut().unbind() }.unwrap();
        let state = State::new();
        let mut owner = bind(None, 0x170, 2, &state);
        failed(state.raw(), 0, 4);
        // SAFETY: no tokens or callers remain.
        unsafe { owner.as_mut().unbind() }.unwrap();
        // SAFETY: pure invalid architecture fixture, must refuse binding.
        assert!(unsafe { FirmwareBinding::new(&catalog, 0, 0) }.is_err());
    }

    #[test]
    fn multiple_real_tokens_prevent_unbind_until_last_put_and_keep_same_bytes() {
        let name = format!("nvidia/{}/gsp_ga10x.bin", version());
        let catalog = make_catalog(&name, "ga10x", &DATA.0);
        let state = State::new();
        let mut owner = bind(Some(&catalog), 0x170, 2, &state);
        let (first, data, _) = request(state.raw(), 0, 4);
        let (second, again, _) = request(state.raw(), 0, 4);
        assert!(!first.is_null() && !second.is_null());
        assert_ne!(first, second);
        assert_eq!(data, again);
        // SAFETY: first token retired, second still owned/readable; unbind refuses.
        unsafe {
            nv_put_firmware(first);
            assert_eq!(owner.as_mut().unbind(), Err(ServiceError::Native(0x40)));
        }
        // SAFETY: second immutable CPU view remains retained by its real token.
        assert_eq!(
            unsafe { core::slice::from_raw_parts(again.cast::<u8>(), 32) },
            &DATA.0
        );
        // SAFETY: last readers stopped, return token then unbind exact owner.
        unsafe {
            nv_put_firmware(second);
            owner.as_mut().unbind().unwrap();
        }
        failed(state.raw(), 0, 4);
    }

    #[test]
    fn metadata_oom_count_overflow_and_invalid_image_never_publish_tokens() {
        let name = format!("nvidia/{}/gsp_ga10x.bin", version());
        let catalog = make_catalog(&name, "ga10x", &DATA.0);
        let state = State::new();
        let mut owner = bind(Some(&catalog), 0x170, 2, &state);
        let requirement = Requirement {
            name: &name,
            target: target("ga10x"),
            minimum_bytes: 1,
        };
        assert!(prepare(&owner, state.raw(), 4, requirement, || None).is_none());
        assert_eq!(owner.firmware_tokens.get(), 0);
        owner.firmware_tokens.set(usize::MAX);
        assert!(
            prepare(&owner, state.raw(), 4, requirement, || panic!(
                "overflow must fail before metadata allocation"
            ))
            .is_none()
        );
        assert_eq!(owner.firmware_tokens.get(), usize::MAX);
        owner.firmware_tokens.set(0);
        // SAFETY: tests' exact resource count reset; no published token ever existed.
        unsafe { owner.as_mut().unbind() }.unwrap();
        for (hardware, bytes) in [
            ("ad10x", &DATA.0[..]),
            ("ga10x", &DATA.0[1..]),
            ("ga10x", &DATA.0[0..0]),
        ] {
            let catalog = make_catalog(&name, hardware, bytes);
            let state = State::new();
            let mut owner = bind(Some(&catalog), 0x170, 2, &state);
            failed(state.raw(), 0, 4);
            assert_eq!(owner.firmware_tokens.get(), 0);
            // SAFETY: failure published no token.
            unsafe { owner.as_mut().unbind() }.unwrap();
        }
        assert_eq!(native_length(u32::MAX as usize, 0x1000, 8), Some(u32::MAX));
        assert_eq!(native_length(u32::MAX as usize + 1, 0x1000, 8), None);
        assert_eq!(native_length(1, 0x1001, 8), None);
        assert_eq!(native_length(0, 0x1000, 8), None);
    }

    #[test]
    fn delegating_provider_cannot_substitute_another_valid_catalog_image() {
        struct Wrong<'a>(&'a Catalog, &'a str, &'a str, Cell<usize>);
        impl Provider for Wrong<'_> {
            fn load(&self, _: Requirement<'_>) -> Result<Image<'_>, crate::firmware::Error> {
                self.3.set(self.3.get() + 1);
                self.0.load(Requirement {
                    name: self.1,
                    target: target(self.2),
                    minimum_bytes: 1,
                })
            }
        }
        let wanted = format!("nvidia/{}/gsp_ga10x.bin", version());
        for (name, hardware) in [("other.bin", "ga10x"), (&wanted, "ad10x")] {
            let catalog = make_catalog(name, hardware, &DATA.0);
            let provider = Wrong(&catalog, name, hardware, Cell::new(0));
            let state = State::new();
            let mut owner = bind(Some(&provider), 0x170, 2, &state);
            failed(state.raw(), 0, 4);
            assert_eq!(provider.3.get(), 1);
            assert_eq!(owner.firmware_tokens.get(), 0);
            // SAFETY: failed lookup published nothing and all callers stopped.
            unsafe { owner.as_mut().unbind() }.unwrap();
        }
    }
}
