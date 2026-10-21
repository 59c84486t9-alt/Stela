//! Native Apple DART generation selection. Chip placement selects an explicit
//! register/table profile; a compatible string is never a generation alias.
//! All bus masters keep the same [`Dart`] DMA and lifecycle boundary.
//! See `docs/research/dart-iommu.md` for evidence and qualification limits.
mod descriptor;
pub mod gen3;
mod irq;
mod legacy;
mod legacy_umms;
pub mod smmu;
mod t8110;

use super::bus::{Access, MmioDevice, MmioError, Width};
use super::interrupt::AicInput;
use crate::platform::dma::{DmaError, Iommu, Memory};
use alloc::vec::Vec;
pub use irq::SharedIrq;
pub use smmu::SmmuBlock;
/// Internal bus offsets of the independently placed APF and UMMS views.
pub const DAPF_OFFSET: u64 = 0x4000;
pub const DAPF_BYTES: u64 = 0x4000;
pub const SMMU_OFFSET: u64 = DAPF_OFFSET + DAPF_BYTES;
pub const SMMU_BYTES: u64 = 0x4000;

/// A t8110 translation fault's ERROR code; legacy generations use their
/// separately encoded error bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    NoTtbr = 1,
    NoPmd = 1 << 2,
    NoPte = 1 << 3,
    Write = 1 << 4,
    Read = 1 << 5,
    Region = 1 << 29,
}

/// Register and page-entry format, independently selected for each DT node.
/// This does not qualify every optional feature of a physical chip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    T8020,
    T6000,
    T8110,
}

impl Profile {
    /// Select one native family from an entire DT compatible string list.
    /// A conflicting or unknown DART family cannot fall back to another
    /// entry in the list. Selection alone does not qualify optional features.
    pub fn from_compatible(compatible: &[u8]) -> Option<Self> {
        let mut selected = None;
        for name in compatible
            .split(|&byte| byte == 0)
            .filter(|name| !name.is_empty())
        {
            let profile = match name {
                b"dart,t8020" => Self::T8020,
                b"dart,t6000" => Self::T6000,
                b"dart,t8110" => Self::T8110,
                name if name.starts_with(b"dart,") => return None,
                _ => continue,
            };
            if selected.is_some_and(|previous| previous != profile) {
                return None;
            }
            selected = Some(profile);
        }
        selected
    }

    pub const fn stream_limit(self) -> usize {
        match self {
            Self::T8020 | Self::T6000 => 16,
            Self::T8110 => 256,
        }
    }

    /// Resolve an OS mapper context to the incoming stream declared by DT.
    /// T6000 SPTM programs the source->context table before enabling DMA;
    /// mapper entry points reject remapped sources. This is a board route
    /// declaration, not an observation of a physical bus transaction.
    pub fn mapper_input_stream(
        self,
        streams: usize,
        context: usize,
        remaps: &[(u8, u8)],
    ) -> Result<usize, &'static str> {
        if streams == 0 || streams > self.stream_limit() || context >= streams {
            return Err("DART mapper context is outside the native profile");
        }
        if !remaps.is_empty() && self != Self::T6000 {
            return Err("DART mapper remap routing is unqualified for this generation");
        }
        for (index, &(source, target)) in remaps.iter().enumerate() {
            if usize::from(source) >= streams
                || usize::from(target) >= streams
                || source == target
                || remaps[..index]
                    .iter()
                    .any(|&(s, t)| [source, target].contains(&s) || [source, target].contains(&t))
            {
                return Err("DART mapper remaps overlap or exceed the native profile");
            }
            if usize::from(source) == context {
                return Err("DART mapper names an incoming remapped source instead of its context");
            }
        }
        Ok(remaps
            .iter()
            .find(|&&(_, target)| usize::from(target) == context)
            .map_or(context, |&(source, _)| usize::from(source)))
    }
}

enum Model {
    Legacy(legacy::Dart),
    T8110(t8110::Dart),
}

pub struct Dart {
    model: Model,
}

impl Dart {
    /// Join a physical input's wired-OR owner before mapping this translator.
    /// An active source cannot be rebound without losing its old assertion.
    pub fn bind_shared_irq(&mut self, irq: &SharedIrq) -> Result<(), &'static str> {
        match &mut self.model {
            Model::Legacy(model) => model.bind_shared_irq(irq),
            Model::T8110(model) => model.bind_shared_irq(irq),
        }
    }

    /// The existing cacheless revision-1 t8110 profile.
    pub fn new(streams: usize, irq: Option<AicInput>) -> Self {
        Self {
            model: Model::T8110(t8110::Dart::new(streams, irq)),
        }
    }

    /// Construct the native generation's register/table format. Original
    /// per-chip placement and optional interfaces require separate validation.
    pub fn for_profile(
        profile: Profile,
        streams: usize,
        irq: Option<AicInput>,
    ) -> Result<Self, &'static str> {
        if streams == 0 || streams > profile.stream_limit() {
            return Err("DART stream count is outside the selected native profile");
        }
        Ok(Self {
            model: match profile {
                Profile::T8110 => Model::T8110(t8110::Dart::new(streams, irq)),
                Profile::T8020 | Profile::T6000 => {
                    Model::Legacy(legacy::Dart::new(profile, streams, irq))
                }
            },
        })
    }

    /// Independent TRAD windows sharing one level-sensitive fault wire.
    pub fn group(streams: usize, irq: Option<AicInput>, count: usize) -> Vec<Self> {
        assert!(count != 0, "a DART group needs a translation instance");
        t8110::Dart::group(streams, irq, count)
            .into_iter()
            .map(|model| Self {
                model: Model::T8110(model),
            })
            .collect()
    }

    pub fn group_for_profile(
        profile: Profile,
        streams: usize,
        irq: Option<AicInput>,
        count: usize,
    ) -> Result<Vec<Self>, &'static str> {
        if count == 0 {
            return Err("a DART group needs a translation instance");
        }
        Self::for_profile(profile, streams, irq)?;
        Ok(match profile {
            Profile::T8110 => Self::group(streams, irq, count),
            Profile::T8020 | Profile::T6000 => legacy::Dart::group(profile, streams, irq, count)
                .into_iter()
                .map(|model| Self {
                    model: Model::Legacy(model),
                })
                .collect(),
        })
    }

    pub fn with_apf(mut self, slices: usize) -> Self {
        self.model = match self.model {
            Model::T8110(model) => Model::T8110(model.with_apf(slices)),
            Model::Legacy(model) => Model::Legacy(model.with_apf(slices)),
        };
        self
    }

    pub fn with_smmu(mut self) -> Result<Self, &'static str> {
        self.enable_smmu()?;
        Ok(self)
    }

    /// Whether this generation implements a native paired UMMS view. This
    /// does not qualify optional hardware capture/performance/configuration
    /// forms: unsupported accesses still refuse inside the selected family.
    /// The query never attaches a view or changes a device's state.
    pub fn supports_smmu(&self) -> bool {
        match &self.model {
            Model::T8110(_) => true,
            Model::Legacy(model) => model.supports_smmu(),
        }
    }

    /// Validate support and uniqueness before placing any physical window.
    pub fn can_attach_smmu(&self) -> bool {
        self.supports_smmu() && !self.has_smmu()
    }

    /// Attach only a supported, unique view. A refused attachment leaves the
    /// model unchanged; machine placement must validate before mapping MMIO.
    pub fn enable_smmu(&mut self) -> Result<(), &'static str> {
        match &mut self.model {
            Model::T8110(model) => {
                if model.enable_smmu() {
                    Ok(())
                } else {
                    Err("DART already has a paired SMMU instance")
                }
            }
            Model::Legacy(model) => model.enable_smmu(),
        }
    }

    /// Whether this instance already has a supported paired capture view.
    pub fn has_smmu(&self) -> bool {
        match &self.model {
            Model::T8110(model) => model.has_smmu(),
            Model::Legacy(model) => model.has_smmu(),
        }
    }

    pub fn set_power(&mut self, powered: bool, retention: bool, access: &mut Access<'_>) {
        match &mut self.model {
            Model::T8110(model) => model.set_power(powered, retention, access),
            Model::Legacy(model) => model.set_power(powered, retention, access),
        }
    }

    pub fn set_quiesced(&mut self, quiesced: bool) {
        match &mut self.model {
            Model::T8110(model) => model.set_quiesced(quiesced),
            Model::Legacy(model) => model.set_quiesced(quiesced),
        }
    }

    /// Gate the functional clock without resetting any register state. A
    /// clock-disabled device cannot perform MMIO or DMA; power is independent.
    pub fn set_clock(&mut self, enabled: bool) {
        match &mut self.model {
            Model::T8110(model) => model.set_clock(enabled),
            Model::Legacy(model) => model.set_clock(enabled),
        }
    }

    pub fn set_reset(&mut self, asserted: bool, access: &mut Access<'_>) {
        match &mut self.model {
            Model::T8110(model) => model.set_reset(asserted, access),
            Model::Legacy(model) => model.set_reset(asserted, access),
        }
    }
}

impl Iommu for Dart {
    fn page(&self) -> u64 {
        match &self.model {
            Model::T8110(model) => model.page(),
            Model::Legacy(model) => model.page(),
        }
    }

    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        write: bool,
        access: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        match &mut self.model {
            Model::T8110(model) => model.translate(memory, stream, iova, last, write, access),
            Model::Legacy(model) => model.translate(memory, stream, iova, last, write, access),
        }
    }
}

impl MmioDevice for Dart {
    fn name(&self) -> &'static str {
        match &self.model {
            Model::T8110(model) => model.name(),
            Model::Legacy(model) => model.name(),
        }
    }

    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        match &mut self.model {
            Model::T8110(model) => model.read(offset, width, access),
            Model::Legacy(model) => model.read(offset, width, access),
        }
    }

    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        match &mut self.model {
            Model::T8110(model) => model.write(offset, width, value, access),
            Model::Legacy(model) => model.write(offset, width, value, access),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{
        apple::interrupt::{InterruptLatch, Wire},
        dma::{Port, tests::Ram},
    };
    use alloc::vec;

    #[test]
    fn explicit_profiles_keep_the_shared_bus_master_type_and_actual_table_effects() {
        const ROOT: u64 = 0x8_0000_0000;
        const PAGE: u64 = 0x4000;
        for profile in [Profile::T8020, Profile::T6000, Profile::T8110] {
            let mut model = Dart::for_profile(profile, 16, None).unwrap();
            let mut sink = InterruptLatch::new();
            let mut a = Access::new(0, 0, &mut sink);
            let mut ram = Ram::new(ROOT, (4 * PAGE) as usize);
            let entry = |address: u64| -> u64 {
                if profile == Profile::T8020 {
                    address | 1
                } else {
                    address >> 4 | 1
                }
            };
            ram.put_u64(ROOT + 8, entry(ROOT + PAGE));
            ram.put_u64(ROOT + PAGE + 8, entry(ROOT + 2 * PAGE) | 0xfff << 40);
            let (enable, tcr, ttbr, ttbr_value) = if profile == Profile::T8110 {
                (0xc00, 0x1004, 0x1404, ROOT >> 14 << 2 | 1)
            } else {
                (0xfc, 0x104, 0x210, ROOT >> 12 | 1 << 31)
            };
            for (offset, value) in [
                (enable, 2),
                (tcr, if profile == Profile::T8110 { 1 } else { 1 << 7 }),
                (ttbr, ttbr_value),
            ] {
                model.write(offset, Width::Word, value, &mut a).unwrap();
            }
            let mut port = Port {
                iommu: &mut model,
                stream: 1,
                memory: &mut ram,
                access: &mut a,
            };
            port.write(0x200_4007, &[1, 3, 5, 7]).unwrap();
            let mut actual = [0; 4];
            assert!(ram.read(ROOT + 2 * PAGE + 7, &mut actual));
            assert_eq!(actual, [1, 3, 5, 7]);
            let invalid_address = if profile == Profile::T8020 {
                1 << 36
            } else {
                1 << 38
            };
            let leaf_permission = if profile == Profile::T8020 {
                1 << 7
            } else {
                1 << 2
            };
            // Exercise both descriptor levels through a real DMA master.
            // Rejection must precede the data write and cannot invent a
            // physical fault classification or silently mask an address.
            for (table_bits, page_bits, reason) in [
                (1 << 9, 0, "DART descriptor contains unmodeled attributes"),
                (0, 1 << 9, "DART descriptor contains unmodeled attributes"),
                (
                    leaf_permission,
                    0,
                    "DART descriptor contains unmodeled attributes",
                ),
                (
                    invalid_address,
                    0,
                    "DART descriptor target exceeds its native profile",
                ),
                (
                    0,
                    invalid_address,
                    "DART descriptor target exceeds its native profile",
                ),
            ] {
                ram.put_u64(ROOT + 8, entry(ROOT + PAGE) | table_bits);
                ram.put_u64(
                    ROOT + PAGE + 8,
                    entry(ROOT + 2 * PAGE) | 0xfff << 40 | page_bits,
                );
                let mut port = Port {
                    iommu: &mut model,
                    stream: 1,
                    memory: &mut ram,
                    access: &mut a,
                };
                assert_eq!(
                    port.write(0x200_4007, &[9, 9, 9, 9]),
                    Err(DmaError::Unsupported(reason))
                );
                assert!(ram.read(ROOT + 2 * PAGE + 7, &mut actual));
                assert_eq!(actual, [1, 3, 5, 7]);
                let error = if profile == Profile::T8110 {
                    0x100
                } else {
                    0x40
                };
                assert_eq!(model.read(error, Width::Word, &mut a), Ok(0));
            }
        }
        assert!(Dart::for_profile(Profile::T8020, 64, None).is_err());
        assert!(Dart::for_profile(Profile::T6000, 0, None).is_err());
        assert_eq!(Dart::new(16, None).name(), "dart-t8110");
    }

    #[test]
    fn grouped_generation_dispatch_preserves_independent_faults_on_the_shared_wire() {
        let irq = AicInput::new(0, 19);
        for profile in [Profile::T8020, Profile::T6000, Profile::T8110] {
            let mut models = Dart::group_for_profile(profile, 16, Some(irq), 2).unwrap();
            let mut sink = InterruptLatch::new();
            let mut ram = Ram::new(0, 0x4000);
            {
                let mut a = Access::new(0, 0, &mut sink);
                for model in &mut models {
                    assert!(model.translate(&mut ram, 0, 0, 0, false, &mut a).is_err());
                }
            }
            assert!(sink.is_asserted(Wire::Aic(irq)));
            let error = if profile == Profile::T8110 {
                0x100
            } else {
                0x40
            };
            {
                let mut a = Access::new(0, 0, &mut sink);
                models[0]
                    .write(error, Width::Word, 1 << 31, &mut a)
                    .unwrap();
            }
            assert!(sink.is_asserted(Wire::Aic(irq)));
            {
                let mut a = Access::new(0, 0, &mut sink);
                models[1]
                    .write(error, Width::Word, 1 << 31, &mut a)
                    .unwrap();
            }
            assert!(!sink.is_asserted(Wire::Aic(irq)));
        }
    }

    #[test]
    fn paired_capture_view_is_available_only_for_its_implemented_generation() {
        for profile in [Profile::T8020, Profile::T6000, Profile::T8110] {
            let mut model = Dart::for_profile(profile, 16, None).unwrap();
            assert!(!model.has_smmu());
            let supported = matches!(profile, Profile::T6000 | Profile::T8110);
            assert_eq!(model.supports_smmu(), supported);
            assert_eq!(model.can_attach_smmu(), supported);
            // Capability queries have no attachment side effect.
            assert!(!model.has_smmu());
            if supported {
                model.enable_smmu().unwrap();
                assert_eq!(
                    model.enable_smmu(),
                    Err("DART already has a paired SMMU instance")
                );
            } else {
                assert_eq!(
                    model.enable_smmu(),
                    Err("legacy DART paired SMMU capture format is unsupported")
                );
            }
            assert_eq!(model.has_smmu(), supported);
            assert!(!model.can_attach_smmu());
            let constructed = Dart::for_profile(profile, 16, None).unwrap().with_smmu();
            assert_eq!(constructed.is_ok(), supported);
        }
    }

    #[test]
    fn grouped_profile_requires_an_actual_translation_instance() {
        for profile in [Profile::T8020, Profile::T6000, Profile::T8110] {
            assert!(matches!(
                Dart::group_for_profile(profile, 16, None, 0),
                Err("a DART group needs a translation instance")
            ));
        }
    }

    #[test]
    fn mapper_context_and_declared_incoming_stream_remain_distinct() {
        assert_eq!(Profile::T6000.mapper_input_stream(16, 0, &[(5, 0)]), Ok(5));
        assert_eq!(Profile::T6000.mapper_input_stream(16, 4, &[]), Ok(4));
        for (streams, context, remaps) in [
            (0, 0, vec![]),
            (17, 0, vec![]),
            (16, 16, vec![]),
            (16, 5, vec![(5, 0)]),
            (16, 0, vec![(5, 0), (6, 0)]),
            (16, 0, vec![(5, 0), (0, 1)]),
            (16, 0, vec![(5, 16)]),
            (16, 0, vec![(5, 5)]),
        ] {
            assert!(
                Profile::T6000
                    .mapper_input_stream(streams, context, &remaps)
                    .is_err()
            );
        }
        for profile in [Profile::T8020, Profile::T8110] {
            assert!(profile.mapper_input_stream(16, 0, &[(5, 0)]).is_err());
            assert_eq!(profile.mapper_input_stream(16, 0, &[]), Ok(0));
        }
    }

    #[test]
    fn separate_logical_groups_and_generations_share_one_physical_irq_owner() {
        let input = AicInput::new(0, 873);
        let shared = SharedIrq::new(input);
        let mut legacy = Dart::for_profile(Profile::T6000, 16, Some(input)).unwrap();
        let mut modern = Dart::for_profile(Profile::T8110, 16, Some(input)).unwrap();
        legacy.bind_shared_irq(&shared).unwrap();
        modern.bind_shared_irq(&shared).unwrap();
        let mut sink = InterruptLatch::new();
        let mut ram = Ram::new(0, 0x4000);
        {
            let mut access = Access::new(0, 0, &mut sink);
            for model in [&mut legacy, &mut modern] {
                assert!(matches!(
                    model.translate(&mut ram, 0, 0, 0, false, &mut access),
                    Err(DmaError::Fault(_))
                ));
                assert!(model.bind_shared_irq(&shared).is_err());
            }
            legacy.write(0x40, Width::Word, 1, &mut access).unwrap();
        }
        assert!(sink.is_asserted(crate::platform::apple::interrupt::Wire::Aic(input)));
        {
            let mut access = Access::new(0, 0, &mut sink);
            modern.set_reset(true, &mut access);
        }
        assert!(!sink.is_asserted(crate::platform::apple::interrupt::Wire::Aic(input)));
        assert!(
            legacy
                .bind_shared_irq(&SharedIrq::new(AicInput::new(0, 1)))
                .is_err()
        );
        assert!(
            Dart::for_profile(Profile::T6000, 16, None)
                .unwrap()
                .bind_shared_irq(&shared)
                .is_err()
        );
    }

    #[test]
    fn an_active_original_group_cannot_be_split_by_rebinding_its_idle_peer() {
        let input = AicInput::new(0, 873);
        let mut models = Dart::group_for_profile(Profile::T6000, 16, Some(input), 2).unwrap();
        let mut sink = InterruptLatch::new();
        let mut ram = Ram::new(0, 0x4000);
        let mut access = Access::new(0, 0, &mut sink);
        assert!(matches!(
            models[0].translate(&mut ram, 0, 0, 0, false, &mut access),
            Err(DmaError::Fault(_))
        ));
        assert!(models[1].bind_shared_irq(&SharedIrq::new(input)).is_err());
    }

    #[test]
    fn incoming_streams_outside_the_profile_never_truncate_into_fault_sids() {
        for profile in [Profile::T8020, Profile::T6000, Profile::T8110] {
            let mut model = Dart::for_profile(profile, 1, None).unwrap();
            let mut sink = InterruptLatch::new();
            let mut a = Access::new(0, 0, &mut sink);
            let mut ram = Ram::new(0, 0x4000);
            for stream in [1, 16, 256, usize::MAX] {
                assert_eq!(
                    model.translate(&mut ram, stream, 0, 0, false, &mut a),
                    Err(DmaError::Unsupported(
                        "DART incoming stream is outside the native profile"
                    ))
                );
                let error = if profile == Profile::T8110 {
                    0x100
                } else {
                    0x40
                };
                assert_eq!(model.read(error, Width::Word, &mut a), Ok(0));
            }
        }
    }

    #[test]
    fn functional_clock_gating_retains_configuration_and_blocks_both_access_paths() {
        for profile in [Profile::T8020, Profile::T6000, Profile::T8110] {
            let mut model = Dart::for_profile(profile, 16, None).unwrap();
            let mut sink = InterruptLatch::new();
            let mut a = Access::new(0, 0, &mut sink);
            let mut ram = Ram::new(0, 0x4000);
            let (tcr, bypass) = if profile == Profile::T8110 {
                (0x1000, 6)
            } else {
                (0x100, 1 << 8 | 1 << 12)
            };
            let enable = if profile == Profile::T8110 {
                0xc00
            } else {
                0xfc
            };
            model.write(enable, Width::Word, 1, &mut a).unwrap();
            model.write(tcr, Width::Word, bypass, &mut a).unwrap();
            assert_eq!(model.translate(&mut ram, 0, 0, 0, false, &mut a), Ok(0));
            model.set_clock(false);
            assert!(model.read(tcr, Width::Word, &mut a).is_err());
            assert!(model.write(tcr, Width::Word, 0, &mut a).is_err());
            assert_eq!(
                model.translate(&mut ram, 0, 0, 0, false, &mut a),
                Err(DmaError::Unsupported("DART functional clock is gated"))
            );
            model.set_clock(true);
            assert_eq!(model.read(tcr, Width::Word, &mut a), Ok(bypass));
            assert_eq!(model.translate(&mut ram, 0, 0, 0, false, &mut a), Ok(0));
            // Clock gating itself cannot clear an independent reset line.
            model.set_reset(true, &mut a);
            model.set_clock(false);
            model.set_clock(true);
            assert!(model.read(tcr, Width::Word, &mut a).is_err());
            model.set_reset(false, &mut a);
            assert_eq!(model.read(tcr, Width::Word, &mut a), Ok(0));
        }
    }

    #[test]
    fn compatible_selection_never_aliases_a_different_native_family() {
        for (bytes, expected) in [
            (b"dart,t8020\0".as_slice(), Some(Profile::T8020)),
            (b"dart,t6000\0".as_slice(), Some(Profile::T6000)),
            (b"generic\0dart,t8110\0".as_slice(), Some(Profile::T8110)),
            (b"dart,gen3\0".as_slice(), None),
            (b"dart,gen3\0dart,t8110\0".as_slice(), None),
            (b"dart,t8020\0dart,t6000\0".as_slice(), None),
            (b"dart,unknown\0dart,t8020\0".as_slice(), None),
        ] {
            assert_eq!(Profile::from_compatible(bytes), expected);
        }
        assert_eq!(Profile::T8020.stream_limit(), 16);
        assert_eq!(Profile::T6000.stream_limit(), 16);
        assert_eq!(Profile::T8110.stream_limit(), 256);
    }
}
