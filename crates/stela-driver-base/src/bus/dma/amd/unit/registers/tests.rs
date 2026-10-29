extern crate std;
use super::*;
use crate::bus::pci::regs;
use crate::bus::{
    mmio::owned::{
        AddressSpace, Authority, InstalledMapping, MapFailure, MapRequest, MappingPlatform,
        PhysicalSpan, Resource, ResourceBacking, ResourceKind,
    },
    pci::owned::test_support::fixture,
};
use alloc::{
    alloc::{Layout, alloc_zeroed, dealloc},
    boxed::Box,
    sync::Arc,
    vec,
};
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{collections::BTreeSet, sync::Mutex};

const ADDRESS: Address = Address {
    segment: 0x1234,
    bus: 0xab,
    device: 0x1f,
    function: 7,
};
const SPACE: AddressSpace = AddressSpace {
    identity: 29,
    physical_bits: 48,
    virtual_bits: 48,
};
const BASE: u64 = 0xfed8_0000;
const CAP: u16 = 0x40;

struct Backing(PhysicalSpan);
// SAFETY: this symbolic resource belongs exclusively to one isolated RAM
// model; it confers no native hardware or production mapping permission.
unsafe impl ResourceBacking for Backing {
    fn physical_span(&self) -> PhysicalSpan {
        self.0
    }
    fn kind(&self) -> ResourceKind {
        ResourceKind::Registers
    }
}
struct Model {
    memory: NonNull<u8>,
    bytes: usize,
    request: Mutex<Option<MapRequest>>,
    unmaps: AtomicUsize,
}
// SAFETY: stable fixture RAM is accessed through raw volatile pointers;
// tests do not run readers/writers concurrently and metadata is locked.
unsafe impl Send for Model {}
// SAFETY: same fixture-only exclusion; no safe mutable RAM view escapes.
unsafe impl Sync for Model {}
impl Model {
    fn pointer(&self) -> NonNull<u8> {
        self.memory
    }
    fn set(&self, offset: usize, value: u64) {
        assert!(offset.is_multiple_of(8));
        // SAFETY: test prefill occurs before inspection, within owned RAM.
        unsafe {
            self.pointer()
                .as_ptr()
                .add(offset)
                .cast::<u64>()
                .write_volatile(value.to_le())
        };
    }
    fn image(&self) -> Vec<u64> {
        // SAFETY: isolated synchronous model, no concurrent writer.
        let count = self.bytes / size_of::<u64>();
        (0..count)
            // SAFETY: the pointer addresses this test's own live pages, and the stopped model
            // writes nothing concurrently.
            .map(|i| unsafe { self.pointer().as_ptr().cast::<u64>().add(i).read_volatile() })
            .collect()
    }
}
impl Drop for Model {
    fn drop(&mut self) {
        // SAFETY: fixture allocation, original layout, all
        // registry mapping leases and synchronous consumers are gone.
        unsafe {
            dealloc(
                self.memory.as_ptr(),
                Layout::from_size_align(self.bytes, 4096).unwrap(),
            )
        };
    }
}
// SAFETY: each model maps its isolated RAM over one
// symbolic resource. No native cache, physical IOMMU or IRQ is modeled.
unsafe impl MappingPlatform for Model {
    fn check_context(&self, space: AddressSpace) -> Result<(), MappingError> {
        assert_eq!(space, SPACE);
        Ok(())
    }
    unsafe fn map(
        &self,
        _: &Resource,
        request: MapRequest,
    ) -> Result<InstalledMapping, MapFailure> {
        assert!(self.request.lock().unwrap().replace(request).is_none());
        Ok(InstalledMapping {
            token: request.id,
            cpu_base: self.pointer(),
            physical: request.physical,
            attribute: request.attribute,
            protection: request.protection,
        })
    }
    unsafe fn unmap(
        &self,
        request: MapRequest,
        mapping: InstalledMapping,
    ) -> Result<(), MappingError> {
        assert_eq!(self.request.lock().unwrap().take(), Some(request));
        assert_eq!(mapping.cpu_base, self.pointer());
        self.unmaps.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
fn make_mapping(base: u64, bytes: usize, protection: Protection) -> (Mapping, Arc<Model>) {
    let layout = Layout::from_size_align(bytes, 4096).unwrap();
    // SAFETY: nonzero test-only allocation; page alignment is required by
    // the registry, just as for a native installed mapping.
    let memory = NonNull::new(unsafe { alloc_zeroed(layout) }).expect("fixture RAM");
    let model = Arc::new(Model {
        memory,
        bytes,
        request: Mutex::new(None),
        unmaps: AtomicUsize::new(0),
    });
    // SAFETY: isolated test registry and symbolic resource, no native unit.
    let authority = unsafe { Authority::isolated_model(model.clone(), SPACE, Vec::new()) }.unwrap();
    let resource = Resource::new(Box::new(Backing(
        PhysicalSpan::new(base, bytes as u64).unwrap(),
    )));
    let mapping = authority
        .map(resource, 0, bytes, CacheAttribute::Uncached, protection)
        .unwrap();
    (mapping, model)
}
fn make_function(caps: &[(u16, u64, u32)], msix: bool) -> Function<OwnedConfig> {
    let (mut config, _) = fixture(ADDRESS);
    config.write32(0, 0x1234_1022);
    config.write32(8, 0x0806_0001);
    config.write16(regs::STATUS, regs::STATUS_CAP_LIST);
    config.write8(0x34, caps[0].0 as u8);
    for (index, &(offset, base, extra)) in caps.iter().enumerate() {
        let next = caps
            .get(index + 1)
            .map(|x| x.0)
            .unwrap_or(if msix { 0xa0 } else { 0 });
        config.write32(
            offset,
            u32::from(SECURE_DEVICE)
                | u32::from(next) << 8
                | IOMMU_TYPE << 16
                | IOMMU_REVISION << 19
                | extra,
        );
        config.write32(offset + 4, base as u32 | BASE_ENABLED);
        config.write32(offset + 8, (base >> 32) as u32);
        config.write32(offset + 12, 0xfe00_ab80);
        config.write32(offset + 16, 48 << 15 | 48 << 8 | 2 << 5 | 7);
        if extra & CAP_EXTENDED != 0 {
            config.write32(offset + 20, 9);
        }
    }
    if msix {
        config.write32(0xa0, 0x001f_0011);
    }
    Function::new(ADDRESS, config).unwrap()
}
#[derive(Clone, Copy)]
struct Unit {
    cap: u16,
    base: u64,
    long: bool,
    attributes: u32,
    features: u64,
}
impl Unit {
    fn small() -> Self {
        Self {
            cap: CAP,
            base: BASE,
            long: false,
            attributes: 0,
            features: 0,
        }
    }
}
fn firmware(units: &[Unit], info: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 48];
    bytes[..4].copy_from_slice(b"IVRS");
    bytes[8] = 2;
    bytes[36..40].copy_from_slice(&info.to_le_bytes());
    for unit in units {
        let mut block = vec![0; if unit.long { 40 } else { 24 }];
        block[0] = if unit.long { 0x11 } else { 0x10 };
        let len = block.len() as u16;
        block[2..4].copy_from_slice(&len.to_le_bytes());
        block[4..6].copy_from_slice(&0xabffu16.to_le_bytes());
        block[6..8].copy_from_slice(&unit.cap.to_le_bytes());
        block[8..16].copy_from_slice(&unit.base.to_le_bytes());
        block[16..18].copy_from_slice(&ADDRESS.segment.to_le_bytes());
        block[18..20].copy_from_slice(&11u16.to_le_bytes());
        block[20..24].copy_from_slice(&unit.attributes.to_le_bytes());
        if unit.long {
            block[24..32].copy_from_slice(&unit.features.to_le_bytes());
        }
        bytes.extend(block);
    }
    checksum(&mut bytes);
    bytes
}
fn checksum(bytes: &mut [u8]) {
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    bytes[9] = 0;
    bytes[9] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |sum, x| sum.wrapping_add(*x)));
}
fn inspect(inputs: Inputs, bytes: &[u8]) -> Result<FunctionInspection, (Error, Inputs)> {
    let ivrs = Ivrs::parse(bytes, 48).unwrap();
    // SAFETY: all inputs are held, synchronous isolated fixtures.
    unsafe { FunctionInspection::inspect(inputs, &ivrs) }
}
fn success(result: Result<FunctionInspection, (Error, Inputs)>) -> FunctionInspection {
    match result {
        Ok(group) => group,
        Err((error, inputs)) => {
            retire(inputs);
            panic!("{error:?}")
        }
    }
}
fn failure(result: Result<FunctionInspection, (Error, Inputs)>, expected: Error) {
    match result {
        Ok(group) => {
            retire(group.into_inputs());
            panic!("unexpected success");
        }
        Err((error, inputs)) => {
            assert_eq!(error, expected);
            retire(inputs);
        }
    }
}
fn retire(inputs: Inputs) {
    let mut config = inputs.function.into_config().into_mapping();
    // SAFETY: all synchronous inspection consumers have stopped.
    unsafe { config.retire() }.unwrap();
    for mut mapping in inputs.mappings {
        // SAFETY: no hardware or fixture worker can access returned owners.
        unsafe { mapping.retire() }.unwrap();
    }
}

#[test]
fn kept_function_and_all_register_bytes_are_unchanged() {
    let mut function = make_function(&[(CAP, BASE, CAP_EXTENDED | EFR_SUPPORTED)], false);
    let original_config: Vec<_> = (0..4096u16)
        .step_by(4)
        .map(|offset| function.config().read32(offset))
        .collect();
    let (mapping, model) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
    for (i, offset) in [
        DEVICE_TABLE,
        COMMAND_BUFFER,
        EVENT_LOG,
        CONTROL,
        COMMAND_HEAD,
        COMMAND_TAIL,
        EVENT_HEAD,
        EVENT_TAIL,
        STATUS,
    ]
    .into_iter()
    .enumerate()
    {
        model.set(offset, 0x1000 + i as u64);
    }
    model.set(EXTENDED_FEATURES_2, 0x1234);
    let original = model.image();
    let table = firmware(&[Unit::small()], 1);
    let group = success(inspect(
        Inputs {
            function,
            mappings: vec![mapping],
        },
        &table,
    ));
    assert_eq!(group.address(), ADDRESS);
    assert_eq!(group.profiles()[0].configuration.miscellaneous_1, Some(9));
    assert_eq!(
        group.profiles()[0].hardware_extended_features,
        Some((0, 0x1234))
    );
    assert_eq!(
        group.snapshot(CAP).unwrap().unwrap(),
        Snapshot {
            device_table: 0x1000,
            command_buffer: 0x1001,
            event_log: 0x1002,
            control: 0x1003,
            command_head: 0x1004,
            command_tail: 0x1005,
            event_head: 0x1006,
            event_tail: 0x1007,
            status: 0x1008
        }
    );
    assert_eq!(group.snapshot(0x44), Ok(None));
    assert_eq!(model.image(), original);
    assert_eq!(model.unmaps.load(Ordering::Relaxed), 0);
    let mut inputs = group.into_inputs();
    let returned_config: Vec<_> = (0..4096u16)
        .step_by(4)
        .map(|offset| inputs.function.config().read32(offset))
        .collect();
    assert_eq!(returned_config, original_config);
    assert_eq!(inputs.function.config().read32(CAP + 20), 9);
    assert_eq!(inputs.function.config().read32(CAP + 4), BASE as u32 | 1);
    retire(inputs);
    assert_eq!(model.unmaps.load(Ordering::Relaxed), 1);
}

#[test]
fn complete_function_groups_match_caps_and_mappings_independently_of_order() {
    let second = Unit {
        cap: 0x60,
        base: BASE + COUNTER_APERTURE as u64,
        ..Unit::small()
    };
    for reverse_table in [false, true] {
        for reverse_maps in [false, true] {
            let function = make_function(&[(CAP, BASE, 0), (second.cap, second.base, 0)], true);
            let (a, ma) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
            let (b, mb) = make_mapping(second.base, SMALL_APERTURE, Protection::ReadWrite);
            let mut units = [Unit::small(), second];
            if reverse_table {
                units.reverse();
            }
            let mut mappings = vec![a, b];
            if reverse_maps {
                mappings.reverse();
            }
            let group = success(inspect(Inputs { function, mappings }, &firmware(&units, 0)));
            assert_eq!(group.profiles().len(), 2);
            assert_eq!(
                group
                    .profiles()
                    .iter()
                    .map(|p| p.configuration.capability_offset)
                    .collect::<BTreeSet<_>>(),
                BTreeSet::from([CAP, second.cap])
            );
            assert!(
                group
                    .profiles()
                    .iter()
                    .all(|p| p.hardware_extended_features.is_none())
            );
            retire(group.into_inputs());
            assert_eq!(ma.unmaps.load(Ordering::Relaxed), 1);
            assert_eq!(mb.unmaps.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn physical_and_firmware_counter_reports_keep_the_larger_aperture() {
    for actual in [false, true] {
        for reported in [false, true] {
            for long in [false, true] {
                let unit = Unit {
                    long,
                    attributes: if reported && !long {
                        1 << 17 | 1 << 13
                    } else {
                        0
                    },
                    features: if reported { PERFORMANCE_COUNTERS } else { 0 },
                    ..Unit::small()
                };
                let bytes = if actual || reported {
                    COUNTER_APERTURE
                } else {
                    SMALL_APERTURE
                };
                let (mapping, model) = make_mapping(BASE, bytes, Protection::ReadWrite);
                model.set(
                    EXTENDED_FEATURES,
                    if actual { PERFORMANCE_COUNTERS } else { 0 },
                );
                let original = model.image();
                let function = make_function(&[(CAP, BASE, EFR_SUPPORTED)], false);
                let group = success(inspect(
                    Inputs {
                        function,
                        mappings: vec![mapping],
                    },
                    &firmware(&[unit], 1),
                ));
                let profile = group.profiles()[0];
                assert_eq!(profile.aperture_bytes, bytes);
                assert_eq!(
                    profile.firmware.extended_features,
                    long.then_some((unit.features, 0))
                );
                assert_eq!(
                    profile.hardware_extended_features,
                    Some((if actual { PERFORMANCE_COUNTERS } else { 0 }, 0))
                );
                assert_eq!(model.image(), original);
                retire(group.into_inputs());
            }
        }
    }
}

#[test]
fn mismatched_or_incomplete_apertures_are_refused_without_mutation() {
    for (actual, reported, bytes, base) in [
        (true, false, SMALL_APERTURE, BASE),
        (false, true, SMALL_APERTURE, BASE),
        (false, false, COUNTER_APERTURE, BASE),
        (true, true, COUNTER_APERTURE, BASE + SMALL_APERTURE as u64),
    ] {
        let unit = Unit {
            base,
            long: true,
            features: if reported { PERFORMANCE_COUNTERS } else { 0 },
            ..Unit::small()
        };
        let (mapping, model) = make_mapping(base, bytes, Protection::ReadWrite);
        model.set(
            EXTENDED_FEATURES,
            if actual { PERFORMANCE_COUNTERS } else { 0 },
        );
        let original = model.image();
        let function = make_function(&[(CAP, base, EFR_SUPPORTED)], false);
        failure(
            inspect(
                Inputs {
                    function,
                    mappings: vec![mapping],
                },
                &firmware(&[unit], 1),
            ),
            Error::MappingGeometry,
        );
        assert_eq!(model.image(), original);
        assert_eq!(model.unmaps.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn disabled_reserved_and_unknown_inputs_return_original_resources() {
    for case in 0..10 {
        let mut function = make_function(&[(CAP, BASE, 0)], false);
        let (mapping, model) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
        let mut unit = Unit::small();
        let mut info = 0;
        let expected = match case {
            0 => {
                function.config().write32(CAP + 4, BASE as u32);
                model.set(CONTROL, u64::MAX);
                Error::Disabled(CAP)
            }
            1 => {
                info = 1;
                Error::FeatureReporting(CAP)
            }
            2 => {
                unit.long = true;
                Error::FeatureReporting(CAP)
            }
            3 => {
                unit.attributes = 1 << 17;
                info = 1;
                function.config().write32(
                    CAP,
                    u32::from(SECURE_DEVICE)
                        | IOMMU_TYPE << 16
                        | IOMMU_REVISION << 19
                        | EFR_SUPPORTED,
                );
                Error::FeatureReporting(CAP)
            }
            4 => {
                function.address.segment ^= 1;
                Error::Identity
            }
            5 => {
                function.config().write32(0, 0xffff_ffff);
                Error::Identity
            }
            6 => {
                unit.cap = 0x44;
                Error::MissingInstance(0x44)
            }
            7 => {
                unit.base += SMALL_APERTURE as u64;
                Error::Firmware
            }
            8 => {
                function.config().write32(CAP, 0x0013_000f);
                Error::UnsupportedLayout(CAP)
            }
            _ => {
                function.config().write32(CAP + 16, u32::MAX);
                Error::ReadFailed(CAP + 16)
            }
        };
        let original = model.image();
        failure(
            inspect(
                Inputs {
                    function,
                    mappings: vec![mapping],
                },
                &firmware(&[unit], info),
            ),
            expected,
        );
        assert_eq!(model.image(), original);
        assert_eq!(model.unmaps.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn a_base_without_its_enable_bit_is_used_when_its_registers_answer() {
    let mut function = make_function(&[(CAP, BASE, 0)], false);
    function.config().write32(CAP + 4, BASE as u32);
    let (mapping, _model) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
    let group = success(inspect(
        Inputs {
            function,
            mappings: vec![mapping],
        },
        &firmware(&[Unit::small()], 0),
    ));
    assert_eq!(group.profiles().len(), 1);
    retire(group.into_inputs());
}

#[test]
fn mapping_count_policy_identity_and_overlaps_are_checked() {
    let unit = Unit::small();
    let function = make_function(&[(CAP, BASE, 0)], false);
    failure(
        inspect(
            Inputs {
                function,
                mappings: vec![],
            },
            &firmware(&[unit], 0),
        ),
        Error::MappingCount,
    );
    let function = make_function(&[(CAP, BASE, 0)], false);
    let (mapping, _) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadOnly);
    failure(
        inspect(
            Inputs {
                function,
                mappings: vec![mapping],
            },
            &firmware(&[unit], 0),
        ),
        Error::MappingPolicy,
    );
    let second = Unit { cap: 0x60, ..unit };
    let function = make_function(&[(CAP, BASE, 0), (second.cap, BASE, 0)], true);
    let (a, _) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
    let (b, _) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
    failure(
        inspect(
            Inputs {
                function,
                mappings: vec![a, b],
            },
            &firmware(&[unit, second], 0),
        ),
        Error::Overlap,
    );
}

#[test]
fn reserved_firmware_fields_and_reserved_registers_are_never_used() {
    for attributes in [1 << 17, 1 << 13, u32::MAX] {
        for actual_efr in [false, true] {
            let function = make_function(
                &[(CAP, BASE, if actual_efr { EFR_SUPPORTED } else { 0 })],
                false,
            );
            let (mapping, model) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
            if !actual_efr {
                // These would produce Register errors if incorrectly read.
                model.set(EXTENDED_FEATURES, u64::MAX);
                model.set(EXTENDED_FEATURES_2, u64::MAX);
            }
            let unit = Unit {
                attributes,
                ..Unit::small()
            };
            let group = success(inspect(
                Inputs {
                    function,
                    mappings: vec![mapping],
                },
                &firmware(&[unit], 0),
            ));
            let profile = group.profiles()[0];
            assert_eq!(profile.aperture_bytes, SMALL_APERTURE);
            assert_eq!(profile.firmware.feature_or_attributes, attributes);
            assert_eq!(
                profile.hardware_extended_features,
                actual_efr.then_some((0, 0))
            );
            retire(group.into_inputs());
        }
    }
}

#[test]
fn all_known_profile_refusals_precede_feature_observation() {
    for invalid in 0..3 {
        let second = Unit {
            cap: 0x60,
            base: BASE + COUNTER_APERTURE as u64,
            long: true,
            features: PERFORMANCE_COUNTERS,
            ..Unit::small()
        };
        let function = make_function(
            &[
                (CAP, BASE, EFR_SUPPORTED),
                (second.cap, second.base, EFR_SUPPORTED),
            ],
            true,
        );
        let (first, first_model) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
        // If any MMIO observation occurs before complete preflight, this
        // earlier unit fails with Register rather than the expected error.
        first_model.set(EXTENDED_FEATURES, u64::MAX);
        let (last, _) = make_mapping(second.base, SMALL_APERTURE, Protection::ReadWrite);
        let mut units = [Unit::small(), second];
        let expected = match invalid {
            0 => Error::MappingGeometry,
            1 => {
                units[1].cap = 0x64;
                Error::MissingInstance(0x64)
            }
            _ => {
                units[1].base += SMALL_APERTURE as u64;
                Error::Firmware
            }
        };
        failure(
            inspect(
                Inputs {
                    function,
                    mappings: vec![first, last],
                },
                &firmware(&units, 1),
            ),
            expected,
        );
    }
}

#[test]
fn missing_function_instances_and_multiple_units_without_msix_are_refused() {
    let second = Unit {
        cap: 0x60,
        base: BASE + COUNTER_APERTURE as u64,
        ..Unit::small()
    };
    for msix in [false, true] {
        let function = make_function(&[(CAP, BASE, 0), (second.cap, second.base, 0)], msix);
        let (a, _) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
        let (b, _) = make_mapping(second.base, SMALL_APERTURE, Protection::ReadWrite);
        let units = if msix {
            vec![Unit::small()]
        } else {
            vec![Unit::small(), second]
        };
        failure(
            inspect(
                Inputs {
                    function,
                    mappings: vec![a, b],
                },
                &firmware(&units, 0),
            ),
            if msix {
                Error::Firmware
            } else {
                Error::InterruptLayout
            },
        );
    }
}

#[test]
fn inaccessible_registers_never_become_feature_or_completion_facts() {
    for offset in [EXTENDED_FEATURES, EXTENDED_FEATURES_2, STATUS] {
        let function = make_function(&[(CAP, BASE, EFR_SUPPORTED)], false);
        let (mapping, model) = make_mapping(BASE, SMALL_APERTURE, Protection::ReadWrite);
        model.set(offset, u64::MAX);
        let result = inspect(
            Inputs {
                function,
                mappings: vec![mapping],
            },
            &firmware(&[Unit::small()], 1),
        );
        if offset == STATUS {
            let group = success(result);
            assert_eq!(group.snapshot(CAP), Err(Error::Register(STATUS)));
            retire(group.into_inputs());
        } else {
            failure(result, Error::Register(offset));
        }
    }
}
