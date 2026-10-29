//! Canonical native PMP AP-buffer service. The source IOMapper supplies IOVAs;
//! every transfer rewalks the mounted DART into the same registered RAM.
//! No native PMP private ARM cache exists in this implementation. Ordering is
//! coherent Normal-WB CPU visibility, never an MCC/DCS/PTD/MC completion.
use super::Access;
use super::AppleDevices;
use super::Asc;
use super::Bus;
use super::Dart;
use super::DeviceError;
use super::DeviceId;
use super::Memory;
use super::Port;
use crate::Result;
use crate::platform::apple::pmp::native::dma;
use crate::platform::apple::pmp::native::platform::owner::Completion;
use alloc::{collections::BTreeMap, rc::Rc, string::String, sync::Arc};
use core::sync::atomic::{Ordering, fence};
use stela_contracts::refuse;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::board;

/// Exact static source inputs, not runtime IORegistry observations. Native
/// startup admits no later mapper-index or asc-dram-mask overlay. Hashes keep
/// provenance only; no behavior is selected by a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceProvenance {
    original_tree_sha256: String,
    prepared_tree_sha256: String,
    pmp: board::PmpController,
    mapper_index_property: Option<u32>,
    asc_dram_mask_property: Option<u64>,
}
impl SourceProvenance {
    pub fn from_trees(
        original: &[u8],
        prepared: &[u8],
        pmp: &board::PmpController,
    ) -> Result<Self> {
        let original_configuration = pmp.native_dma_configuration(original)?;
        let prepared_configuration = pmp.native_dma_configuration(prepared)?;
        if original_configuration != prepared_configuration
            || original_configuration.0.unwrap_or(0) != 0
            || original_configuration.1.unwrap_or(0) != 0
        {
            return Err(refuse!(
                "PMP native DMA static configuration changed or requires an unsupported address transformation"
            ));
        }
        Ok(Self {
            original_tree_sha256: stela_formats::sha256(original),
            prepared_tree_sha256: stela_formats::sha256(prepared),
            pmp: *pmp,
            mapper_index_property: original_configuration.0,
            asc_dram_mask_property: original_configuration.1,
        })
    }
    pub fn original_tree_sha256(&self) -> &str {
        &self.original_tree_sha256
    }
    pub fn prepared_tree_sha256(&self) -> &str {
        &self.prepared_tree_sha256
    }
}

/// Host observation supplied from the admitted native processor's
/// CPUID leaf1 snapshot. CLFLUSH's size field is in eight-byte units;
/// eight is an encoding unit, not an assumed cache line or ARM cache geometry.
#[derive(Clone, Debug)]
pub struct ExplicitRuntimeConfiguration {
    source: SourceProvenance,
    leaf1_ebx: u32,
    leaf1_edx: u32,
    synchronization_granule: u64,
}
impl ExplicitRuntimeConfiguration {
    pub fn from_observed_cpuid(
        source: SourceProvenance,
        leaf1_ebx: u32,
        leaf1_edx: u32,
    ) -> Result<Self> {
        let synchronization_granule = u64::from((leaf1_ebx >> 8) & 0xff) * 8;
        if leaf1_edx & (1 << 19) == 0 || !synchronization_granule.is_power_of_two() {
            return Err(refuse!(
                "PMP native DMA requires an actual valid CPUID CLFLUSH line observation"
            ));
        }
        Ok(Self {
            source,
            leaf1_ebx,
            leaf1_edx,
            synchronization_granule,
        })
    }
    pub fn synchronization_granule(&self) -> u64 {
        self.synchronization_granule
    }
    pub fn source(&self) -> &SourceProvenance {
        &self.source
    }
    pub fn cpuid_leaf1(&self) -> (u32, u32) {
        (self.leaf1_ebx, self.leaf1_edx)
    }
}

/// Keeps the bus devices, canonical RAM and native descriptor session.
/// Neither an AP allocation nor its DART page tables are owned by this object.
pub(super) struct PmpDma {
    asc: DeviceId,
    dart: DeviceId,
    wrapper: (u64, u64),
    aperture: (u64, u64),
    profile: stela_soc_data::dart::Profile,
    streams: usize,
    owners: dma::Owners,
    service: dma::Service,
    coherence: WriteBackCoherence,
    _configuration: ExplicitRuntimeConfiguration,
}
impl PmpDma {
    fn check_bus(&self, bus: &Bus) -> Result<()> {
        bus.shared_view(self.asc, self.wrapper.0, self.wrapper.1, 0)
            .map_err(|e| refuse!("PMP native DMA ASC view changed: {e}", ?e))?;
        bus.shared_view(self.dart, self.aperture.0, self.aperture.1, 0)
            .map_err(|e| refuse!("PMP native DMA DART view changed: {e}", ?e))?;
        if bus.device::<Asc>(self.asc).is_none() {
            return Err(refuse!("PMP native DMA actual ASC owner disappeared"));
        }
        let dart = bus
            .device::<Dart>(self.dart)
            .ok_or(refuse!("PMP native DMA actual DART owner disappeared"))?;
        if dart.profile() != self.profile || dart.stream_capacity() != self.streams {
            return Err(refuse!(
                "PMP native DMA actual DART profile/capacity changed"
            ));
        }
        Ok(())
    }
}

impl AppleDevices {
    /// Bind once, before advertising reporting/trace resources. This does not
    /// enable a stream, allocate AP RAM or bypass a DART fault.
    ///
    /// # Safety
    /// `ram` is the SAME Arc used by every canonical Host/table walker
    /// passed to this device set. At cold binding, no guest frame/native loan
    /// has ever been published, AP executors are parked and every raw
    /// input copy is finished. Otherwise all physical native workers are held,
    /// frames recovered and real worker/copyout memory fences completed. Every
    /// synchronous producer is closed. All future service calls must
    /// preserve this contract. No legacy/raw transfer may call this binding.
    /// CPUID words come from the admitted host processor's snapshot;
    /// static source properties have no runtime IORegistry/startup overrides.
    pub unsafe fn bind_native_pmp_dma(
        &mut self,
        board: &board::Board,
        ram: Arc<RegisteredSystemRam>,
        configuration: ExplicitRuntimeConfiguration,
    ) -> Result<dma::Broker> {
        if self.native_pmp_dma.is_some() {
            return Err(refuse!("PMP native DMA is already bound"));
        }
        let pmp = board
            .pmp
            .as_ref()
            .ok_or(refuse!("PMP native DMA has no source controller"))?;
        if *pmp != configuration.source.pmp {
            return Err(refuse!(
                "PMP native DMA source controller differs from the parsed configuration"
            ));
        }
        let selected = pmp.dma_route(&board.darts)?;
        let source = board
            .darts
            .get(selected.iommu)
            .ok_or(refuse!("PMP native DMA source IOMMU index is invalid"))?;
        let instance = source
            .instances
            .get(selected.instance)
            .ok_or(refuse!("PMP native DMA source DART instance is invalid"))?;
        let streams = usize::from(source.streams);
        let stream = source.profile.mapper_input_stream(
            streams,
            selected.context as usize,
            &source.remap,
        )?;
        if stream != selected.stream as usize || stream >= streams {
            return Err(refuse!(
                "PMP native DMA context/remap/stream source join differs"
            ));
        }
        let asc = self
            .bus
            .window_at(pmp.wrapper.0)
            .map(|v| v.2)
            .ok_or(refuse!("PMP native DMA has no mounted ASC wrapper"))?;
        let mut pmp_owners = self.coprocessors.iter().filter(|(role, _)| *role == "PMP");
        if pmp_owners.next().map(|(_, id)| *id) != Some(asc) || pmp_owners.next().is_some() {
            return Err(refuse!(
                "PMP native DMA wrapper is not the unique actual PMP ASC"
            ));
        }
        let dart = self
            .bus
            .window_at(instance.physical)
            .map(|v| v.2)
            .ok_or(refuse!(
                "PMP native DMA has no mounted source DART instance"
            ))?;
        if asc == dart {
            return Err(refuse!("PMP native DMA ASC and DART owners alias"));
        }
        let route = dma::Route {
            mapper: selected.mapper,
            iommu: selected.iommu,
            instance: selected.instance,
            context: selected.context,
            stream,
        };
        let generation = ram
            .generation()
            .map_err(|e| refuse!("PMP native DMA RAM domain is unavailable: {e}", ?e))?;
        let owners = dma::Owners {
            dart: Rc::new(()),
            canonical_ram: Rc::new(()),
            allocator: Rc::new(()),
        };
        let (broker, service) = dma::pair(
            route,
            owners.clone(),
            dma::Configuration {
                mapper_index: configuration.source.mapper_index_property.unwrap_or(0),
                asc_dram_mask: configuration.source.asc_dram_mask_property.unwrap_or(0),
                synchronization_granule: configuration.synchronization_granule,
            },
        )?;
        let mut master = PmpDma {
            asc,
            dart,
            wrapper: pmp.wrapper,
            aperture: (instance.physical, instance.bytes),
            profile: source.profile,
            streams,
            owners: owners.clone(),
            service,
            coherence: WriteBackCoherence {
                ram,
                generation,
                owners,
                route,
                views: BTreeMap::new(),
                terminal: false,
            },
            _configuration: configuration,
        };
        master.check_bus(&self.bus)?;
        match master.coherence.ready() {
            Completion::Retired { refusal: None, .. } => (),
            Completion::Busy { .. } => {
                return Err(refuse!(
                    "PMP native DMA canonical RAM ownership is busy at binding"
                ));
            }
            Completion::Refused(reason)
            | Completion::Retired {
                refusal: Some(reason),
                ..
            } => return Err(reason),
        }
        self.native_pmp_dma = Some(master);
        Ok(broker)
    }

    /// One finite Port dispatch, with no borrowed Port kept.
    ///
    /// # Safety
    /// Called ONLY by the canonical all-workers-held DeviceTransfer path after
    /// its real remote-worker/copyout fences, with this binding's same
    /// canonical Host/RAM and closed synchronous producers. This persistent
    /// ownership premise cannot be inferred from a BSP fence or numeric ranges.
    pub unsafe fn service_native_pmp_dma(
        &mut self,
        cpu: usize,
        memory: &mut dyn Memory,
        now: u64,
    ) -> Result<(), DeviceError> {
        let Some(master) = &mut self.native_pmp_dma else {
            return Ok(());
        };
        if !master.service.has_work() {
            return Ok(());
        }
        master
            .check_bus(&self.bus)
            .map_err(DeviceError::TransferRefused)?;
        match master.coherence.ready() {
            Completion::Busy { .. } => return Ok(()),
            Completion::Refused(reason) => return Err(DeviceError::TransferRefused(reason)),
            Completion::Retired { .. } => (),
        }
        let Some((asc, dart)) = self.bus.pair_mut::<Asc, Dart>(master.asc, master.dart) else {
            return Err(DeviceError::TransferRefused(
                "PMP native DMA actual device pair disappeared".into(),
            ));
        };
        // The real source ASC's execution gates also own native DMA work.
        // Paused work keeps its same queued request; no mapping effect retires.
        if !asc.execution_enabled() {
            return Ok(());
        }
        let mut access = Access::new(cpu, now, &mut self.latch);
        let mut port = Port {
            iommu: dart,
            stream: master.service.route().stream,
            memory,
            access: &mut access,
        };
        match master
            .service
            .dispatch(&master.owners, &mut port, &mut master.coherence)
        {
            Completion::Busy { .. } | Completion::Retired { refusal: None, .. } => Ok(()),
            Completion::Refused(reason)
            | Completion::Retired {
                refusal: Some(reason),
                ..
            } => Err(DeviceError::TransferRefused(reason)),
        }
    }
    pub(super) fn native_pmp_dma_deadline(&self) -> Option<u64> {
        self.native_pmp_dma
            .as_ref()
            .filter(|m| {
                m.service.has_work()
                    && self
                        .bus
                        .device::<Asc>(m.asc)
                        .is_some_and(Asc::execution_enabled)
            })
            .map(|_| 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Life {
    Mapped,
    Unmapped,
    Released,
}
struct View {
    descriptor: dma::Descriptor,
    life: Life,
}
/// Only constructed by the unsafe canonical binding above. Its real all-writer
/// service guard excludes native execution and every registered physical writer.
struct WriteBackCoherence {
    ram: Arc<RegisteredSystemRam>,
    generation: u64,
    owners: dma::Owners,
    route: dma::Route,
    views: BTreeMap<u64, View>,
    terminal: bool,
}
impl WriteBackCoherence {
    // Guard acquisition before EVERY operation, including reads/writes.
    // Drop before Port entry: no writer gate is held into a canonical transfer.
    fn ready(&mut self) -> Completion<()> {
        if self.terminal {
            return Completion::Refused(refuse!("PMP native DMA coherence session is retired"));
        }
        let guard = match self.ram.try_service() {
            Ok(Some(guard)) => guard,
            Ok(None) => return Completion::Busy { deadline: None },
            Err(_) => {
                self.terminal = true;
                return Completion::Refused(refuse!("PMP native DMA canonical RAM service failed"));
            }
        };
        if !guard.belongs_to(&self.ram)
            || guard.generation() != self.generation
            || guard.validate_current().is_err()
        {
            guard.fail();
            self.terminal = true;
            return Completion::Refused(refuse!(
                "PMP native DMA canonical RAM service generation differs"
            ));
        }
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }
}
impl dma::Coherence for WriteBackCoherence {
    fn effect(
        &mut self,
        _request: &dma::ServiceRequest,
        owners: &dma::Owners,
        descriptor: dma::Descriptor,
        effect: dma::Effect,
        port: &mut Port<'_, '_>,
    ) -> Completion<()> {
        if self.terminal {
            return Completion::Refused(refuse!("PMP native DMA coherence session is retired"));
        }
        if !Rc::ptr_eq(&owners.dart, &self.owners.dart)
            || !Rc::ptr_eq(&owners.canonical_ram, &self.owners.canonical_ram)
            || !Rc::ptr_eq(&owners.allocator, &self.owners.allocator)
            || descriptor.route != self.route
            || descriptor.flags != 0x202
        {
            return Completion::Refused(refuse!(
                "PMP native DMA coherence owner/descriptor differs"
            ));
        }
        let expected = if effect == dma::Effect::Release {
            Life::Unmapped
        } else {
            Life::Mapped
        };
        match self.views.get(&descriptor.identity()) {
            None if effect == dma::Effect::Map => (),
            Some(view)
                if effect != dma::Effect::Map
                    && view.descriptor == descriptor
                    && view.life == expected => {}
            _ => {
                return Completion::Refused(refuse!(
                    "PMP native DMA native descriptor lifecycle differs"
                ));
            }
        }
        if let dma::Effect::ReportingSynchronize { offset, bytes } = effect
            && offset
                .checked_add(bytes)
                .is_none_or(|end| end > descriptor.bytes)
        {
            return Completion::Refused(refuse!(
                "PMP native DMA synchronization exceeds native descriptor"
            ));
        }
        // A Busy Map retry revalidates the live DART, even though the broker
        // already checked it before this callback. No PA translation is cached.
        if effect == dma::Effect::Map {
            for write in [false, true] {
                if port
                    .check(descriptor.iova, descriptor.bytes as usize, write)
                    .is_err()
                {
                    return Completion::Refused(refuse!(
                        "PMP native DMA live map admission changed"
                    ));
                }
            }
        }
        // No Port operation while all writer gates are frozen: its canonical
        // physical writer would need the same gates. Map checked read+write
        // under the Port first; preceding writes have already retired.
        let guard = match self.ram.try_service() {
            Ok(Some(guard)) => guard,
            Ok(None) => return Completion::Busy { deadline: None },
            Err(_) => {
                self.terminal = true;
                return Completion::Refused(refuse!("PMP native DMA canonical RAM service failed"));
            }
        };
        if !guard.belongs_to(&self.ram)
            || guard.generation() != self.generation
            || guard.validate_current().is_err()
        {
            guard.fail();
            self.terminal = true;
            return Completion::Refused(refuse!(
                "PMP native DMA canonical RAM service generation differs"
            ));
        }
        // X86 coherent Normal-WB ordering of the Port's canonical stores.
        // Remote worker fences occurred in the held engine before this call.
        // This supplies no ARM cache-line eviction or controller acknowledgement.
        fence(Ordering::SeqCst);
        let life = match effect {
            dma::Effect::Unmap => Life::Unmapped,
            dma::Effect::Release => Life::Released,
            _ => Life::Mapped,
        };
        self.views
            .insert(descriptor.identity(), View { descriptor, life });
        let refusal = if guard.validate_current().is_err() {
            guard.fail();
            self.terminal = true;
            Some(refuse!(
                "PMP native DMA RAM failed after actual WB visibility retirement"
            ))
        } else {
            None
        };
        // Preserve the retired fence/native-view prefix even if its subsequent
        // validation fails; the caller must not replay this operation.
        Completion::Retired { value: (), refusal }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec, vec::Vec};
    use core::{cell::UnsafeCell, ptr::NonNull};
    use stela_contracts::adt::encode;
    use stela_engine::memory::ReservedSystemRamRange;

    fn pmp() -> board::PmpController {
        board::PmpController {
            wrapper: (0x2_3bc0_0000, 0x6c000),
            interrupts: [0x275, 0x274, 0x277, 0x276],
            quiesced: false,
            mapper: Some(0x7d),
        }
    }
    fn tree(index: Option<&[u8]>, mask: Option<&[u8]>, duplicate: bool, mapper: u32) -> Vec<u8> {
        let managed = 1u32.to_le_bytes();
        let mut nub = vec![
            ("name", b"iop-pmp-nub\0".as_slice()),
            ("compatible", b"iop-nub,rtbuddy-v2\0".as_slice()),
            ("user-power-managed", managed.as_slice()),
        ];
        if let Some(mask) = mask {
            nub.push(("asc-dram-mask", mask));
        }
        let nub = encode(&nub, &[]);
        let mapper = mapper.to_le_bytes();
        let reg: Vec<_> = [0x3bc0_0000u64, 0x6c000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let mut node = vec![
            ("name", b"pmp\0".as_slice()),
            ("compatible", b"iop,ascwrap-v4\0".as_slice()),
            ("role", b"PMP\0".as_slice()),
            ("reg", reg.as_slice()),
            ("iommu-parent", mapper.as_slice()),
        ];
        if let Some(index) = index {
            node.push(("mapper-index", index));
            if duplicate {
                node.push(("mapper-index", index));
            }
        }
        let node = encode(&node, &[nub]);
        let ranges: Vec<_> = [0u64, 0x2_0000_0000, 0x1_0000_0000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect();
        let io = encode(&[("name", b"arm-io\0"), ("ranges", &ranges)], &[node]);
        encode(&[("name", b"device-tree\0")], &[io])
    }
    #[test]
    fn static_mapper_configuration_requires_both_source_coordinates_and_exact_properties() {
        let absent = tree(None, None, false, 0x7d);
        let source = SourceProvenance::from_trees(&absent, &absent, &pmp()).unwrap();
        assert_eq!(
            source.original_tree_sha256(),
            stela_formats::sha256(&absent)
        );
        assert_eq!(source.mapper_index_property, None);
        assert_eq!(source.asc_dram_mask_property, None);
        let zero = tree(
            Some(&0u32.to_le_bytes()),
            Some(&0u64.to_le_bytes()),
            false,
            0x7d,
        );
        assert!(SourceProvenance::from_trees(&zero, &zero, &pmp()).is_ok());
        // Absent versus explicit zero is still a changed original property.
        assert!(SourceProvenance::from_trees(&absent, &zero, &pmp()).is_err());
        for invalid in [
            tree(Some(&1u32.to_le_bytes()), None, false, 0x7d),
            tree(None, Some(&1u64.to_le_bytes()), false, 0x7d),
            tree(Some(&[0; 3]), None, false, 0x7d),
            tree(None, Some(&[0; 4]), false, 0x7d),
            tree(Some(&[0; 4]), None, true, 0x7d),
            tree(None, None, false, 0x7e),
        ] {
            assert!(SourceProvenance::from_trees(&invalid, &invalid, &pmp()).is_err());
        }
        let mut wrong = pmp();
        wrong.wrapper.0 += 0x4000;
        assert!(SourceProvenance::from_trees(&absent, &absent, &wrong).is_err());
    }
    #[test]
    fn host_granule_comes_from_kept_cpuid_instead_of_a_constant() {
        let bytes = tree(None, None, false, 0x7d);
        let source = SourceProvenance::from_trees(&bytes, &bytes, &pmp()).unwrap();
        for (field, expected) in [(8, 64), (16, 128)] {
            let config = ExplicitRuntimeConfiguration::from_observed_cpuid(
                source.clone(),
                field << 8,
                1 << 19,
            )
            .unwrap();
            assert_eq!(config.synchronization_granule(), expected);
            assert_eq!(config.cpuid_leaf1(), (field << 8, 1 << 19));
        }
        for (ebx, edx) in [(0, 1 << 19), (3 << 8, 1 << 19), (8 << 8, 0)] {
            assert!(
                ExplicitRuntimeConfiguration::from_observed_cpuid(source.clone(), ebx, edx)
                    .is_err()
            );
        }
    }
    struct Storage(UnsafeCell<Box<[u128; 256]>>);
    // SAFETY: this authored ownership test has no native executor or racing
    // direct writer. All RAM accesses belong to the registered domain.
    unsafe impl Send for Storage {}
    // SAFETY: shared references rely on the same argument as `Send` above.
    unsafe impl Sync for Storage {}
    fn coherence() -> WriteBackCoherence {
        let storage = Arc::new(Storage(UnsafeCell::new(Box::new([0; 256]))));
        let pointer =
            // SAFETY: stable aligned allocation; no references to its bytes survive
            // registration and the fixture starts no native worker.
            unsafe { NonNull::new_unchecked((*storage.0.get()).as_mut_ptr().cast::<u8>()) };
        // SAFETY: `storage` keeps these 256 bytes alive with the registration, and nothing else
        // writes them.
        let ram = Arc::new(unsafe {
            stela_engine::memory::system_ram::fixture(
                &[ReservedSystemRamRange {
                    source_pa: 0x4000,
                    host_pa: 0x1000_0000,
                    host_base: pointer,
                    bytes: 4096,
                }],
                storage,
            )
        });
        let generation = ram.generation().unwrap();
        WriteBackCoherence {
            ram,
            generation,
            owners: dma::Owners {
                dart: Rc::new(()),
                canonical_ram: Rc::new(()),
                allocator: Rc::new(()),
            },
            route: dma::Route {
                mapper: 0x7d,
                iommu: 0,
                instance: 0,
                context: 0,
                stream: 0,
            },
            views: BTreeMap::new(),
            terminal: false,
        }
    }
    #[test]
    fn mounted_profile_and_bus_identity_are_required_beside_numeric_geometry() {
        let mut devices = AppleDevices::new();
        devices
            .add_pmp(&pmp(), stela_formats::builds::DEFAULT)
            .unwrap();
        let asc = devices
            .coprocessors
            .iter()
            .find(|(role, _)| *role == "PMP")
            .unwrap()
            .1;
        let dart = devices
            .bus
            .install(
                Box::new(
                    Dart::for_profile(stela_soc_data::dart::Profile::T6000, 16, None).unwrap(),
                ),
                &[(0x5000_0000, 0x4000, 0)],
            )
            .unwrap();
        let coherence = coherence();
        let owners = coherence.owners.clone();
        let (_, service) = dma::pair(
            coherence.route,
            owners.clone(),
            dma::Configuration {
                mapper_index: 0,
                asc_dram_mask: 0,
                synchronization_granule: 64,
            },
        )
        .unwrap();
        let bytes = tree(None, None, false, 0x7d);
        let source = SourceProvenance::from_trees(&bytes, &bytes, &pmp()).unwrap();
        let mut master = PmpDma {
            asc,
            dart,
            wrapper: pmp().wrapper,
            aperture: (0x5000_0000, 0x4000),
            profile: stela_soc_data::dart::Profile::T8110,
            streams: 16,
            owners,
            service,
            coherence,
            _configuration: ExplicitRuntimeConfiguration::from_observed_cpuid(
                source,
                8 << 8,
                1 << 19,
            )
            .unwrap(),
        };
        assert!(master.check_bus(&devices.bus).is_err());
        master.profile = stela_soc_data::dart::Profile::T6000;
        assert!(master.check_bus(&devices.bus).is_ok());
        master.dart = asc;
        assert!(master.check_bus(&devices.bus).is_err());
    }
    #[test]
    fn native_loan_is_busy_and_a_failed_domain_retires_the_session() {
        let mut coherence = coherence();
        let loan = coherence.ram.reference_execution_loan().unwrap();
        assert_eq!(coherence.ready(), Completion::Busy { deadline: None });
        assert!(!coherence.terminal);
        drop(loan);
        assert_eq!(
            coherence.ready(),
            Completion::Retired {
                value: (),
                refusal: None
            }
        );
        let guard = coherence.ram.try_service().unwrap().unwrap();
        guard.fail();
        drop(guard);
        assert!(matches!(coherence.ready(), Completion::Refused(_)));
        assert!(coherence.terminal);
        assert!(matches!(coherence.ready(), Completion::Refused(_)));
    }
    #[test]
    fn changed_canonical_generation_refuses_before_any_port_effect() {
        let mut coherence = coherence();
        coherence.generation += 1;
        assert!(matches!(coherence.ready(), Completion::Refused(_)));
        assert!(coherence.terminal);
        assert!(coherence.ram.generation().is_err());
    }
    #[test]
    #[ignore = "oracle: STELA_TEST_CPU_DT_DIR"]
    fn original_j473_static_dma_configuration_keeps_source_identity() {
        let bytes = std::fs::read(
            std::path::PathBuf::from(std::env::var("STELA_TEST_CPU_DT_DIR").unwrap())
                .join("DeviceTree.j473ap.adt"),
        )
        .unwrap();
        assert_eq!(
            stela_formats::sha256(&bytes),
            "a99fa2260f292236fbad210fcee380fc69f101e591125bce347819e84e68034c"
        );
        let pmp = board::board(&bytes).unwrap().pmp.unwrap();
        assert_eq!(pmp.mapper, Some(0x7d));
        let source = SourceProvenance::from_trees(&bytes, &bytes, &pmp).unwrap();
        assert_eq!(
            (source.mapper_index_property, source.asc_dram_mask_property),
            (None, None)
        );
        assert_eq!(source.original_tree_sha256(), source.prepared_tree_sha256());
    }
}
