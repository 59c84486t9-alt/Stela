//! Canonical physical identity of the full-system loader's existing RAM.
//! Registration neither allocates nor copies guest bytes. Guest VA aliases
//! resolve through one physical view/backing and one all-writer memory system.
use crate::{
    memory::{
        access,
        backing::{AccessKind, AccessPermissions, MemoryBacking, MemoryView},
        domain::{MappingAttributes, MemoryDomain, MemorySystem},
    },
    platform::cpu::system::NativeSystemTarget,
};
use alloc::{sync::Arc, vec::Vec};
use core::ptr::NonNull;
use stela_compiler::{TargetCpu, context::memory::MemoryStatus};

mod completion;
mod transfer;
pub use completion::CanonicalRamService;

const GRANULE: usize = 16;
const MAX_RANGES: usize = 4096;

/// One actual reservation, with both the guest's physical placement and the
/// host physical/CPU mapping identities. Metadata never lends guest references.
#[derive(Debug, Clone, Copy)]
pub struct ReservedSystemRamRange {
    pub source_pa: u64,
    pub host_pa: u64,
    pub host_base: NonNull<u8>,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationError {
    Geometry,
    PhysicalAlias,
    NativeTarget,
    Backing,
    Domain(MemoryStatus),
}

struct Region {
    source_pa: u64,
    host_pa: u64,
    bytes: usize,
    backing: Arc<MemoryBacking>,
}

/// The only canonical backing identities for this reserved physical RAM.
/// Every guest/native/host/table-walker writer must use its memory system;
/// direct RAM and DMA writers are excluded until separately joined.
pub struct RegisteredSystemRam {
    regions: Vec<Region>,
    domain: Arc<MemoryDomain>,
    system: Arc<MemorySystem>,
    target: TargetCpu,
    erg_bytes: u64,
}

impl RegisteredSystemRam {
    /// Bind the loader's real reservations without modifying historical bytes.
    ///
    /// # Safety
    /// Each CPU mapping is coherent Normal-WB RAM with stable readable/writable
    /// host rights, exactly backed by the given host physical extent. `owner`
    /// retains these actual reservations/mappings through their last backing,
    /// every native loan, recovery and final source-PC settlement. Ranges are
    /// disjoint from Rust references, Stela code/data/stacks and other consumers.
    /// This transfers all access discipline: every writer, including aliases,
    /// AF/DBM updates and host services, must participate in this one system.
    /// No firmware, SMI, external DMA or unjoined direct writer may access it.
    /// Called before any admitted concurrent execution with interrupts disabled
    /// at CPL0. Per-worker effective guest controls and actual native target
    /// admission are additional requirements; registration alone grants neither.
    pub unsafe fn register<O: Send + Sync + 'static>(
        ranges: &[ReservedSystemRamRange],
        owner: Arc<O>,
        erg_bytes: u64,
        stripes: usize,
    ) -> Result<Self, RegistrationError> {
        validate(ranges)?;
        let authority =
            NativeSystemTarget::capture().map_err(|_| RegistrationError::NativeTarget)?;
        let (regions, views, system) = unsafe { bindings(ranges, owner, erg_bytes, stripes) }?;
        let domain = MemoryDomain::new_native_system_ram(Arc::clone(&system), views, &authority)
            .map_err(RegistrationError::Domain)?;
        Ok(Self {
            regions,
            domain,
            system,
            target: authority.target(),
            erg_bytes,
        })
    }

    /// Retained source/host physical extents. Metadata does not lend host
    /// pointers or authorize another RAM store/direct native writer.
    pub fn placements(&self) -> impl Iterator<Item = (u64, u64, usize)> + '_ {
        self.regions
            .iter()
            .map(|region| (region.source_pa, region.host_pa, region.bytes))
    }
    pub fn reservation_granule(&self) -> u64 {
        self.erg_bytes
    }
    pub fn target(&self) -> TargetCpu {
        self.target
    }
    pub(crate) fn domain(&self) -> &Arc<MemoryDomain> {
        &self.domain
    }

    fn region(&self, physical: u64) -> Option<(&Region, usize)> {
        let index = self
            .regions
            .partition_point(|region| region.source_pa <= physical);
        let region = self.regions.get(index.checked_sub(1)?)?;
        let offset = usize::try_from(physical - region.source_pa).ok()?;
        (offset < region.bytes).then_some((region, offset))
    }

    /// Observe initialized physical RAM through exact native scalar reads.
    /// Instruction words and descriptors do not use racing Rust byte copies.
    /// Refused whole-range admission leaves the caller's buffer unchanged.
    ///
    /// # Safety
    /// The output is private/disjoint from this registered RAM, live native
    /// frames and host metadata. The retained source mapping and all-writer
    /// contract remain valid. This does not make a multiword snapshot atomic;
    /// instruction/cache publication still requires its own stopped-cohort
    /// protocol and immutable source-byte identity at native preparation.
    pub unsafe fn read_physical(
        &self,
        physical: u64,
        output: &mut [u8],
    ) -> Result<(), MemoryStatus> {
        // SAFETY: the caller retains the same private output and live owner.
        unsafe { self.read_physical_progress(physical, output) }.map_err(|fault| fault.status)
    }

    /// Read through the same canonical scalar access path, retaining the exact
    /// output prefix if a later access encounters a terminal owner failure.
    ///
    /// # Safety
    /// The `read_physical` private-output and live-registration contract applies.
    pub unsafe fn read_physical_progress(
        &self,
        physical: u64,
        output: &mut [u8],
    ) -> Result<(), crate::memory::domain::PublicationFault> {
        use crate::memory::domain::PublicationFault;
        self.preflight(physical, output.len())
            .map_err(|status| PublicationFault {
                status,
                completed: 0,
            })?;
        let mut done = 0;
        while done < output.len() {
            let fault = |status| PublicationFault {
                status,
                completed: done,
            };
            let (region, offset) = self
                .region(physical + done as u64)
                .ok_or_else(|| fault(MemoryStatus::Domain))?;
            let remaining = (output.len() - done).min(region.bytes - offset);
            let pointer = region
                .backing
                .host_pointer(offset, remaining, AccessKind::Read)
                .map_err(|_| fault(MemoryStatus::Domain))?;
            let width = [8, 4, 2, 1]
                .into_iter()
                .find(|width| {
                    remaining >= *width && (pointer.as_ptr() as usize).is_multiple_of(*width)
                })
                .expect("a byte fits the admitted range");
            // SAFETY: a pinned exact aligned scalar part, qualified baseline
            // host, no Rust reference into concurrently mutable guest storage.
            let value = unsafe { access::read_part(pointer.as_ptr(), width, TargetCpu::Baseline) }
                .map_err(|_| fault(MemoryStatus::Domain))?;
            output[done..done + width].copy_from_slice(&value.to_le_bytes()[..width]);
            done += width;
        }
        Ok(())
    }

    /// Validate physical geometry and actual retained backing permissions for a
    /// DMA descriptor. No bytes are copied and no translation is cached.
    pub fn check_dma_range(
        &self,
        physical: u64,
        bytes: usize,
        write: bool,
    ) -> Result<(), MemoryStatus> {
        self.preflight(physical, bytes)?;
        let mut done = 0;
        while done < bytes {
            let (region, offset) = self
                .region(physical + done as u64)
                .ok_or(MemoryStatus::Translation)?;
            let count = (bytes - done).min(region.bytes - offset);
            region
                .backing
                .host_pointer(
                    offset,
                    count,
                    if write {
                        AccessKind::Write
                    } else {
                        AccessKind::Read
                    },
                )
                .map_err(|_| MemoryStatus::Permission)?;
            done += count;
        }
        Ok(())
    }

    pub(crate) fn check_physical(&self, physical: u64, bytes: usize) -> Result<(), MemoryStatus> {
        self.preflight(physical, bytes)
    }

    fn preflight(&self, physical: u64, bytes: usize) -> Result<(), MemoryStatus> {
        self.domain.check_execution()?;
        if bytes == 0 {
            return Ok(());
        }
        physical
            .checked_add(bytes as u64 - 1)
            .ok_or(MemoryStatus::Translation)?;
        let mut done = 0;
        while done < bytes {
            let (region, offset) = self
                .region(physical + done as u64)
                .ok_or(MemoryStatus::Translation)?;
            done += (bytes - done).min(region.bytes - offset);
        }
        Ok(())
    }
}

fn validate(ranges: &[ReservedSystemRamRange]) -> Result<(), RegistrationError> {
    if ranges.is_empty() || ranges.len() > MAX_RANGES {
        return Err(RegistrationError::Geometry);
    }
    for (index, range) in ranges.iter().enumerate() {
        if range.bytes == 0
            || range.bytes > isize::MAX as usize
            || !range.bytes.is_multiple_of(GRANULE)
            || !range.source_pa.is_multiple_of(GRANULE as u64)
            || !range.host_pa.is_multiple_of(GRANULE as u64)
            || !(range.host_base.as_ptr() as usize).is_multiple_of(GRANULE)
            || range.source_pa.checked_add(range.bytes as u64).is_none()
            || range.host_pa.checked_add(range.bytes as u64).is_none()
            || (range.host_base.as_ptr() as usize)
                .checked_add(range.bytes)
                .is_none()
        {
            return Err(RegistrationError::Geometry);
        }
        for other in &ranges[..index] {
            let overlap = |left: u64, left_bytes: usize, right: u64, right_bytes: usize| {
                left < right + right_bytes as u64 && right < left + left_bytes as u64
            };
            if overlap(range.source_pa, range.bytes, other.source_pa, other.bytes)
                || overlap(range.host_pa, range.bytes, other.host_pa, other.bytes)
                || overlap(
                    range.host_base.as_ptr() as u64,
                    range.bytes,
                    other.host_base.as_ptr() as u64,
                    other.bytes,
                )
            {
                return Err(RegistrationError::PhysicalAlias);
            }
        }
    }
    Ok(())
}

type Views = Vec<(Arc<MemoryView>, MappingAttributes)>;
/// # Safety
/// Caller validated geometry and retains actual WB reservations under the full
/// register contract. This never reads or changes guest bytes or creates a
/// caller-selectable native admission shortcut.
unsafe fn bindings<O: Send + Sync + 'static>(
    ranges: &[ReservedSystemRamRange],
    owner: Arc<O>,
    erg_bytes: u64,
    stripes: usize,
) -> Result<(Vec<Region>, Views, Arc<MemorySystem>), RegistrationError> {
    let system = MemorySystem::new(erg_bytes, stripes).map_err(RegistrationError::Domain)?;
    let permissions = AccessPermissions {
        readable: true,
        writable: true,
        executable: true,
    };
    let mut regions = Vec::with_capacity(ranges.len());
    let mut views = Vec::with_capacity(ranges.len());
    for range in ranges {
        // SAFETY: the exact retained actual reservation contract is the caller's.
        let backing = unsafe {
            MemoryBacking::new(
                range.host_base,
                range.bytes,
                permissions,
                Arc::clone(&owner),
            )
        }
        .map_err(|_| RegistrationError::Backing)?;
        let view = MemoryView::new(
            Arc::clone(&backing),
            range.source_pa,
            0,
            range.bytes,
            permissions,
        )
        .map_err(|_| RegistrationError::Backing)?;
        views.push((
            view,
            MappingAttributes {
                tagged: false,
                shareable: true,
            },
        ));
        regions.push(Region {
            source_pa: range.source_pa,
            host_pa: range.host_pa,
            bytes: range.bytes,
            backing,
        });
    }
    regions.sort_unstable_by_key(|region| region.source_pa);
    Ok((regions, views, system))
}

/// Source-MMU fixtures use real pinned bytes/native scalar transfers but the
/// legacy hosted domain. This cannot construct production CPL0 entry authority.
#[cfg(test)]
pub(crate) unsafe fn fixture<O: Send + Sync + 'static>(
    ranges: &[ReservedSystemRamRange],
    owner: Arc<O>,
) -> RegisteredSystemRam {
    validate(ranges).unwrap();
    let (regions, views, system) = unsafe { bindings(ranges, owner, 64, 8) }.unwrap();
    let domain = MemoryDomain::new(Arc::clone(&system), views, TargetCpu::Baseline).unwrap();
    RegisteredSystemRam {
        regions,
        domain,
        system,
        target: TargetCpu::Baseline,
        erg_bytes: 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::UnsafeCell;

    #[repr(C, align(16))]
    struct Storage(UnsafeCell<[u8; 128]>);
    // SAFETY: tests use no Rust references into these bytes once registered;
    // all reached accesses use the existing scalar native access/publication.
    unsafe impl Sync for Storage {}
    impl Storage {
        fn new() -> Arc<Self> {
            Arc::new(Self(UnsafeCell::new([0x53; 128])))
        }
        fn pointer(&self) -> NonNull<u8> {
            NonNull::new(self.0.get().cast::<u8>()).unwrap()
        }
    }

    fn range(
        storage: &Storage,
        source_pa: u64,
        offset: usize,
        bytes: usize,
    ) -> ReservedSystemRamRange {
        ReservedSystemRamRange {
            source_pa,
            host_pa: 0x1000_0000 + offset as u64,
            // SAFETY: fixture geometry stays inside the retained test allocation.
            host_base: unsafe { NonNull::new_unchecked(storage.pointer().as_ptr().add(offset)) },
            bytes,
        }
    }

    // A RAM ownership/access model using the real hosted platform's target
    // admission. It does not manufacture a CPL0 native-system proof or assert
    // freestanding/AP execution, which has its own boot qualification.
    unsafe fn model(ranges: &[ReservedSystemRamRange], owner: Arc<Storage>) -> RegisteredSystemRam {
        validate(ranges).unwrap();
        let (regions, views, system) = unsafe { bindings(ranges, owner, 64, 8) }.unwrap();
        let domain = MemoryDomain::new(Arc::clone(&system), views, TargetCpu::Baseline).unwrap();
        RegisteredSystemRam {
            regions,
            domain,
            system,
            target: TargetCpu::Baseline,
            erg_bytes: 64,
        }
    }

    #[test]
    fn canonical_service_excludes_native_and_mapping_publication_until_drop() {
        let storage = Storage::new();
        let ranges = [range(&storage, 0x4000, 0, 128)];
        let ram = unsafe { model(&ranges, storage) };
        let other_storage = Storage::new();
        let other = unsafe { model(&[range(&other_storage, 0x4000, 0, 128)], other_storage) };
        let native = ram.domain.execution_loan().unwrap();
        assert!(ram.try_service().unwrap().is_none());
        drop(native);
        let service = ram.try_service().unwrap().unwrap();
        assert!(service.belongs_to(&ram));
        assert!(!service.belongs_to(&other));
        assert_eq!(service.generation(), ram.domain.generation().unwrap());
        service.validate_current().unwrap();
        assert!(matches!(
            ram.domain.try_execution_loan().unwrap(),
            crate::memory::domain::ExecutionLoanAttempt::ServiceBusy
        ));
        assert!(ram.try_service().unwrap().is_none());
        // An independent physical domain still works; geometry is not authority.
        drop(other.try_service().unwrap().unwrap());
        drop(service);
        drop(ram.domain.execution_loan().unwrap());
        drop(ram.try_service().unwrap().unwrap());
        let mut bytes = [0; 128];
        unsafe { ram.read_physical(0x4000, &mut bytes) }.unwrap();
        assert_eq!(bytes, [0x53; 128]);
    }

    #[test]
    fn canonical_service_blocks_real_alias_copyout_and_descriptor_writers() {
        use std::{sync::mpsc, time::Duration};
        let storage = Storage::new();
        let ram = Arc::new(unsafe { model(&[range(&storage, 0x4000, 0, 128)], storage) });
        let service = ram.try_service().unwrap().unwrap();
        let (started, ready) = mpsc::channel();
        let (finished, done) = mpsc::channel();
        std::thread::scope(|scope| {
            for descriptor in [false, true] {
                let ram = Arc::clone(&ram);
                let started = started.clone();
                let finished = finished.clone();
                scope.spawn(move || {
                    started.send(()).unwrap();
                    if descriptor {
                        assert!(
                            ram.update_descriptor(0x4040, u64::from_le_bytes([0x53; 8]), 7)
                                .unwrap()
                        );
                    } else {
                        // Same retained physical backing through the host writer.
                        unsafe { ram.system.publish(&ram.regions[0].backing, 0, &[9; 8]) }.unwrap();
                    }
                    finished.send(()).unwrap();
                });
            }
            for _ in 0..2 {
                ready.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            service.validate_current().unwrap();
            assert!(done.try_recv().is_err());
            let mut before = [0; 128];
            unsafe { ram.read_physical(0x4000, &mut before) }.unwrap();
            assert_eq!(before, [0x53; 128]);
            drop(service);
            for _ in 0..2 {
                done.recv_timeout(Duration::from_secs(2)).unwrap();
            }
        });
        let mut after = [0; 128];
        unsafe { ram.read_physical(0x4000, &mut after) }.unwrap();
        assert_eq!(&after[..8], &[9; 8]);
        assert_eq!(&after[64..72], &7u64.to_le_bytes());
        assert!(
            after[8..64]
                .iter()
                .chain(after[72..].iter())
                .all(|byte| *byte == 0x53)
        );
    }

    #[test]
    fn canonical_registration_retains_original_bytes_and_actual_mapping_owner() {
        let storage = Storage::new();
        let weak = Arc::downgrade(&storage);
        let ranges = [range(&storage, 0x4000, 0, 128)];
        let registered = unsafe { model(&ranges, Arc::clone(&storage)) };
        drop(storage);
        assert!(weak.upgrade().is_some());
        let mut bytes = [0; 128];
        unsafe { registered.read_physical(0x4000, &mut bytes) }.unwrap();
        assert_eq!(bytes, [0x53; 128]);
        drop(registered);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn physical_cpu_aliases_overlaps_and_overflow_refuse_before_binding() {
        let storage = Storage::new();
        let first = range(&storage, 0x4000, 0, 64);
        let mut second = range(&storage, 0x4080, 64, 64);
        assert_eq!(validate(&[first, second]), Ok(()));
        second.source_pa = first.source_pa;
        assert_eq!(
            validate(&[first, second]),
            Err(RegistrationError::PhysicalAlias)
        );
        second = range(&storage, 0x4080, 64, 64);
        second.host_pa = first.host_pa;
        assert_eq!(
            validate(&[first, second]),
            Err(RegistrationError::PhysicalAlias)
        );
        second = range(&storage, 0x4080, 64, 64);
        second.host_base = first.host_base;
        assert_eq!(
            validate(&[first, second]),
            Err(RegistrationError::PhysicalAlias)
        );
        second = range(&storage, u64::MAX - 15, 64, 64);
        assert_eq!(validate(&[second]), Err(RegistrationError::Geometry));
        assert_eq!(validate(&[]), Err(RegistrationError::Geometry));
    }

    #[test]
    fn a_hole_or_outer_boundary_never_exposes_a_read_prefix() {
        let storage = Storage::new();
        let ranges = [
            range(&storage, 0x4000, 0, 64),
            range(&storage, 0x4080, 64, 64),
        ];
        let registered = unsafe { model(&ranges, storage) };
        for physical in [0x3ff0, 0x4038, 0x40b8, u64::MAX - 7] {
            let mut bytes = [0xa5; 16];
            assert_eq!(
                unsafe { registered.read_physical(physical, &mut bytes) },
                Err(MemoryStatus::Translation)
            );
            assert_eq!(bytes, [0xa5; 16]);
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn actual_native_scalar_fetches_are_coherent_with_the_same_host_writer_system() {
        let storage = Storage::new();
        let ranges = [range(&storage, 0x4000, 0, 128)];
        let registered = unsafe { model(&ranges, storage) };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for value in
                    (0..10_000).map(|iteration| if iteration & 1 == 0 { 0x55 } else { 0xaa })
                {
                    unsafe {
                        registered
                            .system
                            .publish(&registered.regions[0].backing, 0, &[value; 8])
                    }
                    .unwrap();
                }
            });
            for _ in 0..10_000 {
                let mut value = [0; 8];
                unsafe { registered.read_physical(0x4000, &mut value) }.unwrap();
                assert!(matches!(value[0], 0x53 | 0x55 | 0xaa));
                assert!(value.iter().all(|byte| *byte == value[0]));
            }
        });
    }

    #[test]
    fn physical_host_copy_preflights_holes_and_keeps_descriptor_prefix_precise() {
        let storage = Storage::new();
        let ranges = [
            range(&storage, 0x4000, 0, 64),
            range(&storage, 0x4080, 64, 64),
        ];
        let registered = unsafe { model(&ranges, storage) };
        let refused = unsafe { registered.publish_physical(0x4038, &[0; 16]) }.unwrap_err();
        assert_eq!(refused.completed, 0);
        assert_eq!(refused.status, MemoryStatus::Translation);
        assert_eq!(
            registered.read_descriptor(0x4038),
            Ok(0x5353_5353_5353_5353)
        );
        assert_eq!(
            registered.update_descriptor(0x4001, 0, 1),
            Err(MemoryStatus::InvalidRequest)
        );
        assert_eq!(
            registered.update_descriptor(0x4040, 0, 1),
            Err(MemoryStatus::Translation)
        );
        assert_eq!(
            registered.update_descriptor(0x4000, 0x5353_5353_5353_5353, 0x1234),
            Ok(true)
        );
        assert_eq!(
            registered.update_descriptor(0x4000, 0x5353_5353_5353_5353, 0x9999),
            Ok(false)
        );
        assert_eq!(registered.read_descriptor(0x4000), Ok(0x1234));
        assert_eq!(
            registered.read_descriptor(0x4008),
            Ok(0x5353_5353_5353_5353)
        );
        unsafe { registered.publish_physical(0x4080, &42u64.to_le_bytes()) }.unwrap();
        assert_eq!(registered.read_descriptor(0x4080), Ok(42));
    }

    #[test]
    fn hosted_ram_layout_does_not_mint_a_freestanding_target_proof() {
        let storage = Storage::new();
        let ranges = [range(&storage, 0x4000, 0, 128)];
        assert!(matches!(
            unsafe { RegisteredSystemRam::register(&ranges, storage, 64, 8) },
            Err(RegistrationError::NativeTarget)
        ));
    }
}
