//! AArch64 EL1 stage-1 translation by reading descriptors from physical memory.
//!
//! Supports lower and upper 47/48-bit VA ranges, 4 KiB and 16 KiB granules, up to
//! 48-bit PA, and little-endian Normal write-back tables. No EL2/EL3, stage 2,
//! permission indirection or overlays; callers decline those configurations.
//! The contiguous hint is treated as zero, as the architecture permits. Every
//! walk reads the descriptors afresh; there is no TLB. Follows the Arm
//! pseudocode `AArch64.S1Walk`, `S1CheckPermissions` and related functions.

mod config;
mod disabled;
mod walk;

pub use config::{
    AsidBits, Config, Controls, CpuProfile, Granule, GranuleSupport, Mode, PaBits, RegionConfig,
    TableConfig, VaRegion,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Fetch,
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionLevel {
    El0,
    El1,
}

/// Ordinary access. LDTR/STTR and UAO need their own adapter rather than being
/// treated as ordinary accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub kind: AccessKind,
    pub exception_level: ExceptionLevel,
    pub raw_virtual_address: u64,
    pub source_pc: u64,
    pub pan: bool,
    pub uao: bool,
    /// Actual source access's natural alignment, computed by its instruction
    /// owner. This is not guessed from a flattened aggregate transfer width.
    pub aligned: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalReadError {
    /// A synchronous, non-parity physical external abort on a descriptor read.
    /// RAS, parity errors, and asynchronous delivery need a separate adapter.
    ExternalAbort { external_abort_type: bool },
    /// Host backing, platform, or synchronization limitations are not aborts.
    Platform(&'static str),
}

/// Authoritative physical read boundary, not a flattened virtual table view.
/// Implementations perform one aligned little-endian 64-bit read through their
/// physical backing owner, including its synchronization and lifetime checks.
pub trait PhysicalMemory {
    fn read_descriptor(&self, physical_address: u64) -> Result<u64, PhysicalReadError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    Control(&'static str),
    Access(&'static str),
    Descriptor { level: u8, feature: &'static str },
    PhysicalPlatform(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    AddressSize,
    Translation,
    AccessFlag,
    Permission,
    ExternalAbort,
}

/// Where a fault came from, from which the CPU owner derives ESR and FAR. The
/// descriptor PA is diagnostic; FAR is the access's raw VA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub level: u8,
    pub access: Access,
    pub virtual_address_valid: bool,
    /// Internal provenance, never the architectural stage-2 `s2fs1walk` bit.
    pub during_walk: bool,
    pub descriptor_address: Option<u64>,
    /// Physical memory's EA classification, only for synchronous external abort.
    pub external_abort_type: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationError {
    Fault(Fault),
    Unsupported(Unsupported),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shareability {
    NonShareable,
    Outer,
    Inner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    NormalWriteBackReadWriteAllocate,
    NormalWriteThroughReadAllocate,
    NormalNonCacheable,
    DeviceNgnrne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeOrigin {
    Walk,
    MmuDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attributes {
    pub memory_type: MemoryType,
    pub origin: AttributeOrigin,
    /// A reached leaf's MAIR byte; MMU-off attributes are not MAIR-selected.
    pub mair: Option<u8>,
    pub tagged: bool,
    pub xs: bool,
    pub shareability: Shareability,
    pub not_global: bool,
    /// The instruction/fetch owner must apply the selected CPU's BTI behavior.
    pub guarded_page: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Permissions {
    pub el0_read: bool,
    pub el0_write: bool,
    pub el0_execute: bool,
    pub el1_read: bool,
    pub el1_write: bool,
    pub el1_execute: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    access: Access,
    physical_address: u64,
    /// Remaining bytes in this leaf or flat output, before translation is needed.
    contiguous_bytes: u64,
    attributes: Attributes,
    /// Page permissions, present only after a table walk.
    permissions: Option<Permissions>,
    walk: Option<WalkMetadata>,
}

impl Translation {
    pub const fn access(self) -> Access {
        self.access
    }
    pub const fn physical_address(self) -> u64 {
        self.physical_address
    }
    pub const fn contiguous_bytes(self) -> u64 {
        self.contiguous_bytes
    }
    pub const fn attributes(self) -> Attributes {
        self.attributes
    }
    pub const fn permissions(self) -> Option<Permissions> {
        self.permissions
    }
    pub const fn walk(self) -> Option<WalkMetadata> {
        self.walk
    }
}

/// Diagnostic walk provenance; never synthesized for an MMU-disabled output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalkMetadata {
    pub region: VaRegion,
    pub level: u8,
    pub descriptor_address: u64,
    pub descriptor: u64,
    pub asid: u16,
}

pub fn translate(
    config: &Config,
    memory: &(impl PhysicalMemory + ?Sized),
    access: Access,
) -> Result<Translation, TranslationError> {
    walk::translate(config, memory, access)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    const PAGE: u64 = 0x1000;
    const ROOT: u64 = PAGE;
    const LEAF_PA: u64 = 0x8000;
    const VA: u64 = 0x123;
    const AF: u64 = 1 << 10;
    const READ_ONLY: u64 = 1 << 7;
    const USER: u64 = 1 << 6;
    const PXN: u64 = 1 << 53;
    const UXN: u64 = 1 << 54;
    const TABLE_PXN: u64 = 1 << 59;
    const TABLE_UXN: u64 = 1 << 60;
    const TABLE_NO_USER: u64 = 1 << 61;
    const TABLE_READ_ONLY: u64 = 1 << 62;

    #[derive(Default)]
    struct Ram {
        descriptors: BTreeMap<u64, u64>,
        reads: RefCell<Vec<u64>>,
        failure: Option<(u64, PhysicalReadError)>,
    }

    impl PhysicalMemory for Ram {
        fn read_descriptor(&self, address: u64) -> Result<u64, PhysicalReadError> {
            self.reads.borrow_mut().push(address);
            if let Some((failed_address, error)) = self.failure
                && failed_address == address
            {
                return Err(error);
            }
            self.descriptors
                .get(&address)
                .copied()
                .ok_or(PhysicalReadError::ExternalAbort {
                    external_abort_type: false,
                })
        }
    }

    // A test CPU profile.
    fn cpu() -> CpuProfile {
        CpuProfile {
            pa_max: PaBits::Bits48,
            asid_bits: AsidBits::Bits16,
            granules: GranuleSupport {
                kib4: true,
                kib16: true,
                kib64: false,
                lower_fallback: Granule::KiB4,
                upper_fallback: Granule::KiB4,
            },
            pauth: true,
            pan: true,
            pan3: true,
        }
    }

    fn controls() -> Controls {
        Controls {
            ttbr0_el1: ROOT,
            ttbr1_el1: 0,
            tcr_el1: 16 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (5 << 32),
            sctlr_el1: 1 | (1 << 2) | (1 << 12),
            mair_el1: 0xff,
        }
    }

    fn config() -> Config {
        Config::from_controls_for_cpu(controls(), cpu()).unwrap()
    }

    fn access(kind: AccessKind, exception_level: ExceptionLevel) -> Access {
        Access {
            kind,
            exception_level,
            raw_virtual_address: VA,
            source_pc: 0xfeed_0040,
            pan: false,
            uao: false,
            aligned: true,
        }
    }

    fn page(leaf_attributes: u64, table_attributes: u64) -> Ram {
        let mut memory = Ram::default();
        for level in 0..3 {
            memory.descriptors.insert(
                ROOT + level * PAGE,
                (ROOT + (level + 1) * PAGE) | 3 | table_attributes,
            );
        }
        memory
            .descriptors
            .insert(ROOT + 3 * PAGE, LEAF_PA | 3 | AF | leaf_attributes);
        memory
    }

    fn assert_fault(
        result: Result<Translation, TranslationError>,
        kind: FaultKind,
        level: u8,
        during_walk: bool,
    ) -> Fault {
        let Err(TranslationError::Fault(fault)) = result else {
            panic!("expected {kind:?} level {level}, got {result:?}");
        };
        assert_eq!(fault.kind, kind);
        assert_eq!(fault.level, level);
        assert_eq!(fault.during_walk, during_walk);
        assert!(fault.virtual_address_valid);
        assert_eq!(fault.access.source_pc, 0xfeed_0040);
        fault
    }

    #[test]
    fn actual_physical_indices_and_leaf_extents() {
        for leaf_level in 1..=3u8 {
            let mut memory = Ram::default();
            let va = 0x1234_5678_9abcu64;
            let mut table = ROOT;
            let mut expected_reads = Vec::new();
            for level in 0..=leaf_level {
                let offset_bits = 12 + 9 * u32::from(3 - level);
                let address = table + ((va >> offset_bits) & 511) * 8;
                expected_reads.push(address);
                if level < leaf_level {
                    let next_table = table + PAGE;
                    memory.descriptors.insert(address, next_table | 3);
                    table = next_table;
                } else {
                    // Aligned output base distinct from the VA and table backing.
                    let descriptor_type = if level == 3 { 3 } else { 1 };
                    memory
                        .descriptors
                        .insert(address, 0x4000_0000 | descriptor_type | AF);
                }
            }
            let mut request = access(AccessKind::Read, ExceptionLevel::El1);
            request.raw_virtual_address = va;
            let translated = translate(&config(), &memory, request).unwrap();
            let leaf_bytes = 1 << (12 + 9 * u32::from(3 - leaf_level));
            assert_eq!(
                translated.physical_address,
                0x4000_0000 | (va & (leaf_bytes - 1))
            );
            assert_eq!(
                translated.contiguous_bytes,
                leaf_bytes - (va & (leaf_bytes - 1))
            );
            assert_eq!(translated.walk.unwrap().level, leaf_level);
            assert_eq!(*memory.reads.borrow(), expected_reads);
        }
    }

    #[test]
    fn exhaustive_ap_table_permissions_xn_wxn_and_privilege_matrix() {
        // Independent expected truth table for all AP, table AP, and XN controls.
        for ap in 0..4u64 {
            for table_ap in 0..4u64 {
                for xn in 0..16u64 {
                    for wxn in [false, true] {
                        let leaf = (ap << 6)
                            | if xn & 1 != 0 { PXN } else { 0 }
                            | if xn & 2 != 0 { UXN } else { 0 };
                        let table = (table_ap << 61)
                            | if xn & 4 != 0 { TABLE_PXN } else { 0 }
                            | if xn & 8 != 0 { TABLE_UXN } else { 0 };
                        let memory = page(leaf, table);
                        let mut controls = controls();
                        controls.sctlr_el1 |= u64::from(wxn) << 19;
                        let config = Config::from_controls_for_cpu(controls, cpu()).unwrap();
                        let user_read = ap & 1 != 0 && table_ap & 1 == 0;
                        let privileged_write = ap < 2 && table_ap < 2;
                        let user_write = user_read && privileged_write;
                        let privileged_fetch =
                            xn & 5 == 0 && !user_write && !(wxn && privileged_write);
                        let user_fetch = xn & 10 == 0 && !(wxn && user_write);
                        for (el, kind, allowed) in [
                            (ExceptionLevel::El0, AccessKind::Read, user_read),
                            (ExceptionLevel::El0, AccessKind::Write, user_write),
                            (ExceptionLevel::El0, AccessKind::Fetch, user_fetch),
                            (ExceptionLevel::El1, AccessKind::Read, true),
                            (ExceptionLevel::El1, AccessKind::Write, privileged_write),
                            (ExceptionLevel::El1, AccessKind::Fetch, privileged_fetch),
                        ] {
                            let result = translate(&config, &memory, access(kind, el));
                            assert_eq!(
                                result.is_ok(),
                                allowed,
                                "AP{ap} tableAP{table_ap} XN{xn} WXN{wxn} {el:?} {kind:?}: {result:?}"
                            );
                            if !allowed {
                                assert_fault(result, FaultKind::Permission, 3, false);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn permissions_accumulate_across_distinct_table_levels() {
        let mut memory = page(USER, 0);
        *memory.descriptors.get_mut(&ROOT).unwrap() |= TABLE_READ_ONLY;
        *memory.descriptors.get_mut(&(ROOT + PAGE)).unwrap() |= TABLE_NO_USER;
        *memory.descriptors.get_mut(&(ROOT + 2 * PAGE)).unwrap() |= TABLE_PXN | TABLE_UXN;
        let result = translate(
            &config(),
            &memory,
            access(AccessKind::Read, ExceptionLevel::El1),
        )
        .unwrap();
        assert_eq!(
            result.permissions,
            Some(Permissions {
                el0_read: false,
                el0_write: false,
                el0_execute: false,
                el1_read: true,
                el1_write: false,
                el1_execute: false,
            })
        );
    }

    #[test]
    fn pan_affects_privileged_data_only_and_uao_declines_before_reads() {
        let memory = page(USER | READ_ONLY, 0);
        for kind in [AccessKind::Read, AccessKind::Write] {
            let mut request = access(kind, ExceptionLevel::El1);
            request.pan = true;
            assert_fault(
                translate(&config(), &memory, request),
                FaultKind::Permission,
                3,
                false,
            );
        }
        let mut request = access(AccessKind::Fetch, ExceptionLevel::El1);
        request.pan = true;
        assert!(translate(&config(), &memory, request).is_ok());
        memory.reads.borrow_mut().clear();
        request.uao = true;
        assert!(matches!(
            translate(&config(), &memory, request),
            Err(TranslationError::Unsupported(Unsupported::Access(_)))
        ));
        assert!(memory.reads.borrow().is_empty());
    }

    #[test]
    fn invalid_types_are_translation_faults_at_the_descriptor_level() {
        for level in 0..=3u8 {
            for descriptor_type in 0..4u64 {
                let invalid = descriptor_type & 1 == 0
                    || ((level == 0 || level == 3) && descriptor_type == 1);
                if !invalid {
                    continue;
                }
                let mut memory = page(0, 0);
                memory.descriptors.insert(
                    ROOT + u64::from(level) * PAGE,
                    LEAF_PA | AF | descriptor_type,
                );
                assert_fault(
                    translate(
                        &config(),
                        &memory,
                        access(AccessKind::Read, ExceptionLevel::El1),
                    ),
                    FaultKind::Translation,
                    level,
                    true,
                );
                assert_eq!(memory.reads.borrow().len(), usize::from(level + 1));
            }
        }
    }

    #[test]
    fn external_walk_abort_and_platform_failures_are_distinct() {
        for level in 0..=3u8 {
            let mut memory = page(0, 0);
            let address = ROOT + u64::from(level) * PAGE;
            memory.failure = Some((
                address,
                PhysicalReadError::ExternalAbort {
                    external_abort_type: level & 1 != 0,
                },
            ));
            let fault = assert_fault(
                translate(
                    &config(),
                    &memory,
                    access(AccessKind::Write, ExceptionLevel::El1),
                ),
                FaultKind::ExternalAbort,
                level,
                true,
            );
            assert_eq!(fault.descriptor_address, Some(address));
            assert_eq!(fault.external_abort_type, Some(level & 1 != 0));
            memory.failure = Some((address, PhysicalReadError::Platform("retired backing")));
            assert_eq!(
                translate(
                    &config(),
                    &memory,
                    access(AccessKind::Write, ExceptionLevel::El1)
                ),
                Err(TranslationError::Unsupported(
                    Unsupported::PhysicalPlatform("retired backing")
                ))
            );
        }
    }

    #[test]
    fn address_size_faults_keep_root_table_and_leaf_provenance() {
        let mut controls = controls();
        controls.tcr_el1 &= !(7 << 32); // 32-bit PA.
        controls.ttbr0_el1 = 1 << 32;
        let memory = Ram::default();
        assert_fault(
            translate(
                &Config::from_controls_for_cpu(controls, cpu()).unwrap(),
                &memory,
                access(AccessKind::Read, ExceptionLevel::El1),
            ),
            FaultKind::AddressSize,
            0,
            true,
        );
        assert!(memory.reads.borrow().is_empty());
        controls.ttbr0_el1 = ROOT;
        let config = Config::from_controls_for_cpu(controls, cpu()).unwrap();
        for level in 0..=3u8 {
            let mut memory = page(0, 0);
            *memory
                .descriptors
                .get_mut(&(ROOT + u64::from(level) * PAGE))
                .unwrap() |= 1 << 32;
            assert_fault(
                translate(
                    &config,
                    &memory,
                    access(AccessKind::Read, ExceptionLevel::El1),
                ),
                FaultKind::AddressSize,
                level,
                level < 3,
            );
            assert_eq!(memory.reads.borrow().len(), usize::from(level + 1));
        }
    }

    #[test]
    fn af_precedes_permissions_and_never_mutates_descriptors() {
        let mut memory = page(READ_ONLY | USER, 0);
        *memory.descriptors.get_mut(&(ROOT + 3 * PAGE)).unwrap() &= !AF;
        let before = memory.descriptors.clone();
        assert_fault(
            translate(
                &config(),
                &memory,
                access(AccessKind::Write, ExceptionLevel::El1),
            ),
            FaultKind::AccessFlag,
            3,
            false,
        );
        assert_eq!(memory.descriptors, before);
    }

    #[test]
    fn ignored_address_bits_dbm_software_and_contiguous_hint_do_not_gain_effects() {
        let memory = page(
            (3 << 48) | (1 << 51) | (1 << 52) | (0xf << 55) | READ_ONLY,
            0,
        );
        let result = translate(
            &config(),
            &memory,
            access(AccessKind::Read, ExceptionLevel::El1),
        )
        .unwrap();
        assert_eq!(result.physical_address, LEAF_PA + VA);
        assert_eq!(result.contiguous_bytes, PAGE - VA);
        assert!(!result.permissions.unwrap().el1_write);
        assert_fault(
            translate(
                &config(),
                &memory,
                access(AccessKind::Write, ExceptionLevel::El1),
            ),
            FaultKind::Permission,
            3,
            false,
        );
        let mut memory = Ram::default();
        memory.descriptors.insert(ROOT, (2 * PAGE) | 3);
        memory
            .descriptors
            .insert(2 * PAGE, 0x4000_0000 | 0x1234_5000 | 1 | AF);
        let result = translate(
            &config(),
            &memory,
            access(AccessKind::Read, ExceptionLevel::El1),
        )
        .unwrap();
        assert_eq!(result.physical_address, 0x4000_0000 | VA);
    }

    #[test]
    fn mair_selection_shareability_and_guarded_metadata_are_preserved() {
        let mut controls = controls();
        controls.mair_el1 = 0xff << 40;
        let memory = page((5 << 2) | (3 << 8) | (1 << 11) | (1 << 50), 0);
        let translated = translate(
            &Config::from_controls_for_cpu(controls, cpu()).unwrap(),
            &memory,
            access(AccessKind::Fetch, ExceptionLevel::El1),
        )
        .unwrap();
        assert_eq!(
            translated.attributes,
            Attributes {
                memory_type: MemoryType::NormalWriteBackReadWriteAllocate,
                origin: AttributeOrigin::Walk,
                mair: Some(0xff),
                tagged: false,
                xs: false,
                shareability: Shareability::Inner,
                not_global: true,
                guarded_page: true
            }
        );
        controls.mair_el1 = 0x44 << 40;
        assert!(matches!(
            translate(
                &Config::from_controls_for_cpu(controls, cpu()).unwrap(),
                &memory,
                access(AccessKind::Read, ExceptionLevel::El1)
            ),
            Err(TranslationError::Unsupported(
                Unsupported::Descriptor { .. }
            ))
        ));
        let memory = page(1 << 8, 0);
        assert!(matches!(
            translate(
                &config(),
                &memory,
                access(AccessKind::Read, ExceptionLevel::El1)
            ),
            Err(TranslationError::Unsupported(
                Unsupported::Descriptor { .. }
            ))
        ));
    }

    #[test]
    fn config_rejects_unsupported_controls_and_keeps_asid_and_alignment() {
        for inner in 0..4 {
            for outer in 0..4 {
                let mut controls = controls();
                controls.tcr_el1 &= !(0xf << 8);
                controls.tcr_el1 |= (inner << 8) | (outer << 10);
                assert_eq!(
                    Config::from_controls_for_cpu(controls, cpu()).is_ok(),
                    matches!(inner, 1 | 3) && matches!(outer, 1 | 3)
                );
            }
        }
        for bit in [2, 12] {
            let mut controls = controls();
            controls.sctlr_el1 &= !(1 << bit);
            assert!(Config::from_controls_for_cpu(controls, cpu()).is_err());
        }
        for bit in [35, 39, 40, 41, 42, 43, 59] {
            let mut controls = controls();
            controls.tcr_el1 |= 1 << bit;
            assert!(
                Config::from_controls_for_cpu(controls, cpu()).is_err(),
                "TCR bit {bit}"
            );
        }
        for bit in [24, 25] {
            let mut controls = controls();
            controls.sctlr_el1 |= 1 << bit;
            assert!(Config::from_controls_for_cpu(controls, cpu()).is_err());
        }
        let mut controls = controls();
        controls.ttbr0_el1 |= (0xabcd << 48) | 0x7fe;
        let config = Config::from_controls_for_cpu(controls, cpu()).unwrap();
        let Some(RegionConfig::Tables(lower)) = config.region(VaRegion::Lower) else {
            panic!("lower table expected")
        };
        assert_eq!(lower.table_base(), ROOT);
        assert_eq!(config.asid(), Some(0xcd));
        assert_eq!(lower.table_shareability(), Shareability::Inner);
        controls.tcr_el1 |= 1 << 36;
        assert_eq!(
            Config::from_controls_for_cpu(controls, cpu())
                .unwrap()
                .asid(),
            Some(0xabcd)
        );
    }

    #[test]
    fn disabled_walk_has_no_physical_reads() {
        let mut controls = controls();
        controls.tcr_el1 |= 1 << 7;
        let memory = Ram::default();
        assert_fault(
            translate(
                &Config::from_controls_for_cpu(controls, cpu()).unwrap(),
                &memory,
                access(AccessKind::Read, ExceptionLevel::El1),
            ),
            FaultKind::Translation,
            0,
            false,
        );
        assert!(memory.reads.borrow().is_empty());
    }

    #[test]
    fn input_va_range_and_disabled_upper_region_are_translation_faults() {
        let memory = Ram::default();
        for va in [1 << 48, 1 << 55, 1 << 63, u64::MAX] {
            let mut request = access(AccessKind::Fetch, ExceptionLevel::El0);
            request.raw_virtual_address = va;
            assert_fault(
                translate(&config(), &memory, request),
                FaultKind::Translation,
                0,
                false,
            );
        }
        assert!(memory.reads.borrow().is_empty());
    }

    const GRANULE16_BYTES: u64 = 1 << 14;
    const ROOT_UPPER: u64 = 0x8000;
    const DUAL_47_TCR: u64 = 17
        | (1 << 8)
        | (1 << 10)
        | (2 << 12)
        | (2 << 14)
        | (17 << 16)
        | (1 << 24)
        | (1 << 26)
        | (2 << 28)
        | (1 << 30)
        | (2 << 32);
    const UPPER_47_START: u64 = u64::MAX << 47;
    const TCR_TBI0_TEST: u64 = 1 << 37;
    const TCR_TBID0_TEST: u64 = 1 << 51;
    const SCTLR_EPAN_TEST: u64 = 1 << 57;

    fn dual_controls() -> Controls {
        Controls {
            ttbr0_el1: GRANULE16_BYTES,
            ttbr1_el1: ROOT_UPPER,
            tcr_el1: DUAL_47_TCR,
            ..controls()
        }
    }

    #[test]
    fn regions16_exact_walk_indices_and_l2_l3_extents() {
        for (region, virtual_address, root) in [
            (VaRegion::Lower, 0x1234_5678_9abc, GRANULE16_BYTES),
            (
                VaRegion::Upper,
                UPPER_47_START | 0x1234_5678_9abc,
                ROOT_UPPER,
            ),
        ] {
            for leaf_level in [2, 3] {
                let config = Config::from_controls_for_cpu(dual_controls(), cpu()).unwrap();
                let mut memory = Ram::default();
                let mut table = root;
                let mut expected = Vec::new();
                for (level, shift) in [(1, 36), (2, 25), (3, 14)] {
                    if level > leaf_level {
                        break;
                    }
                    let address = table + ((virtual_address >> shift) & 2047) * 8;
                    expected.push(address);
                    if level < leaf_level {
                        let next = table + 2 * GRANULE16_BYTES;
                        memory.descriptors.insert(address, next | 3);
                        table = next;
                    } else {
                        memory
                            .descriptors
                            .insert(address, 0x4000_0000 | AF | if level == 3 { 3 } else { 1 });
                    }
                }
                let mut request = access(AccessKind::Read, ExceptionLevel::El1);
                request.raw_virtual_address = virtual_address;
                let result = translate(&config, &memory, request).unwrap();
                let metadata = result.walk.unwrap();
                let shift = if leaf_level == 2 { 25 } else { 14 };
                let mask = (1 << shift) - 1;
                assert_eq!(
                    result.physical_address,
                    0x4000_0000 | (virtual_address & mask)
                );
                assert_eq!(
                    result.contiguous_bytes,
                    (1 << shift) - (virtual_address & mask)
                );
                assert_eq!(metadata.region, region);
                assert_eq!(metadata.level, leaf_level);
                assert_eq!(*memory.reads.borrow(), expected);
            }
        }
    }
    #[test]
    fn regions16_l1_block_is_invalid_with_ds_and_d128_disabled() {
        let config = Config::from_controls_for_cpu(dual_controls(), cpu()).unwrap();
        let mut memory = Ram::default();
        memory.descriptors.insert(GRANULE16_BYTES, AF | 1);
        assert_fault(
            translate(
                &config,
                &memory,
                access(AccessKind::Read, ExceptionLevel::El1),
            ),
            FaultKind::Translation,
            1,
            true,
        );
        assert_eq!(*memory.reads.borrow(), vec![GRANULE16_BYTES]);
    }
    #[test]
    fn regions_asid_a1_and_cpu_width_are_common_to_both_roots() {
        let mut controls = dual_controls();
        controls.ttbr0_el1 |= 0xabcd << 48;
        controls.ttbr1_el1 |= 0x1234 << 48;
        let mut narrow = cpu();
        narrow.asid_bits = AsidBits::Bits8;
        for a1 in [false, true] {
            for as16 in [false, true] {
                let mut values = controls;
                values.tcr_el1 |= u64::from(a1) << 22 | u64::from(as16) << 36;
                let selected = if a1 { 0x1234 } else { 0xabcd };
                assert_eq!(
                    Config::from_controls_for_cpu(values, cpu()).unwrap().asid(),
                    Some(if as16 { selected } else { selected & 0xff })
                );
                assert_eq!(
                    Config::from_controls_for_cpu(values, narrow)
                        .unwrap()
                        .asid(),
                    Some(selected & 0xff)
                );
            }
        }
    }
    #[test]
    fn regions_granule_fallback_ips_clamp_and_root_alignment_are_source_derived() {
        let mut values = dual_controls();
        values.tcr_el1 &= !(3 << 14);
        values.tcr_el1 |= 3 << 14;
        values.ttbr0_el1 |= 0x3ffe;
        let mut profile = cpu();
        profile.pa_max = PaBits::Bits40;
        profile.granules.lower_fallback = Granule::KiB16;
        values.tcr_el1 |= 7 << 32;
        let config = Config::from_controls_for_cpu(values, profile).unwrap();
        let Some(RegionConfig::Tables(table)) = config.region(VaRegion::Lower) else {
            panic!("table expected")
        };
        assert_eq!(table.granule(), Granule::KiB16);
        assert_eq!(table.table_base(), GRANULE16_BYTES);
        assert_eq!(table.start_level(), 1);
        assert_eq!(config.pa_mask, (1_u64 << 40) - 1);
        // A4K47-bit root has256 entries and2KiB alignment, not a full page.
        values = controls();
        values.tcr_el1 = (values.tcr_el1 & !63) | 17;
        values.ttbr0_el1 = ROOT | 0x800;
        let config = Config::from_controls_for_cpu(values, cpu()).unwrap();
        let Some(RegionConfig::Tables(table)) = config.region(VaRegion::Lower) else {
            panic!("table expected")
        };
        assert_eq!(table.table_base(), ROOT | 0x800);
    }
    #[test]
    fn regions_tbi_tbid_by_access_kind_preserves_raw_fault_address() {
        let mut values = controls();
        values.tcr_el1 |= TCR_TBI0_TEST | TCR_TBID0_TEST;
        let config = Config::from_controls_for_cpu(values, cpu()).unwrap();
        let memory = page(0, 0);
        let mut request = access(AccessKind::Read, ExceptionLevel::El1);
        request.raw_virtual_address = 0xab00_0000_0000_0123;
        assert_eq!(
            translate(&config, &memory, request)
                .unwrap()
                .physical_address,
            LEAF_PA | VA
        );
        request.kind = AccessKind::Fetch;
        let fault = assert_fault(
            translate(&config, &memory, request),
            FaultKind::Translation,
            0,
            false,
        );
        assert_eq!(
            fault.access.raw_virtual_address,
            request.raw_virtual_address
        );
        let mut profile = cpu();
        profile.pauth = false;
        let config = Config::from_controls_for_cpu(values, profile).unwrap();
        assert!(translate(&config, &memory, request).is_ok());
    }
    #[test]
    fn regions_epan_checks_user_execute_before_wxn() {
        let mut values = controls();
        values.sctlr_el1 |= SCTLR_EPAN_TEST | (1 << 19);
        let config = Config::from_controls_for_cpu(values, cpu()).unwrap();
        let memory = page(0, 0);
        let mut request = access(AccessKind::Read, ExceptionLevel::El1);
        request.pan = true;
        // AP00 is not user-readable, but UXN0 is user-executable before WXN.
        assert_fault(
            translate(&config, &memory, request),
            FaultKind::Permission,
            3,
            false,
        );
        assert!(translate(&config, &page(UXN, 0), request).is_ok());
        let mut profile = cpu();
        profile.pan3 = false;
        let config = Config::from_controls_for_cpu(values, profile).unwrap();
        assert!(translate(&config, &memory, request).is_ok());
    }
    #[test]
    fn regions_mmu_off_attributes_pamax_and_metadata_are_truthful() {
        let mut values = controls();
        values.sctlr_el1 &= !1;
        values.tcr_el1 = !((1 << 60) | (1 << 61));
        let memory = Ram::default();
        let mut profile = cpu();
        profile.pa_max = PaBits::Bits40;
        for instruction_cache in [false, true] {
            values.sctlr_el1 =
                (values.sctlr_el1 & !(1 << 12)) | (u64::from(instruction_cache) << 12);
            let config = Config::from_controls_for_cpu(values, profile).unwrap();
            assert_eq!(config.asid(), None);
            for kind in [AccessKind::Read, AccessKind::Write, AccessKind::Fetch] {
                let request = access(kind, ExceptionLevel::El1);
                let result = translate(&config, &memory, request).unwrap();
                assert_eq!(result.physical_address, VA);
                assert_eq!(result.walk, None);
                assert_eq!(result.permissions, None);
                assert_eq!(result.attributes.mair, None);
                assert_eq!(result.attributes.origin, AttributeOrigin::MmuDisabled);
                assert_eq!(result.attributes.shareability, Shareability::Outer);
                assert!(result.attributes.xs);
                assert!(!result.attributes.tagged);
                assert_eq!(
                    result.attributes.memory_type,
                    match (kind, instruction_cache) {
                        (AccessKind::Fetch, true) => MemoryType::NormalWriteThroughReadAllocate,
                        (AccessKind::Fetch, false) => MemoryType::NormalNonCacheable,
                        _ => MemoryType::DeviceNgnrne,
                    }
                );
            }
        }
        values.tcr_el1 = 0;
        let config = Config::from_controls_for_cpu(values, profile).unwrap();
        let mut request = access(AccessKind::Read, ExceptionLevel::El1);
        request.raw_virtual_address = 1 << 40;
        assert_fault(
            translate(&config, &memory, request),
            FaultKind::AddressSize,
            0,
            false,
        );
        request.raw_virtual_address = VA;
        request.aligned = false;
        assert!(matches!(
            translate(&config, &memory, request),
            Err(TranslationError::Unsupported(Unsupported::Access(_)))
        ));
        assert!(memory.reads.borrow().is_empty());
    }

    #[test]
    fn regions_partial_root_indices_ignore_upper_canonical_extension() {
        for (granule16, va_bits, first_shift, root_index, raw) in [
            (false, 47, 39, 0, UPPER_47_START | VA),
            (true, 48, 47, 1, (u64::MAX << 48) | (1_u64 << 47) | VA),
        ] {
            let mut values = dual_controls();
            values.tcr_el1 &= !((63_u64 << 16) | (3_u64 << 30));
            values.tcr_el1 |= ((u64::BITS - va_bits) as u64) << 16;
            values.tcr_el1 |= if granule16 { 1_u64 << 30 } else { 2_u64 << 30 };
            values.ttbr1_el1 = ROOT_UPPER;
            let config = Config::from_controls_for_cpu(values, cpu()).unwrap();
            let mut memory = Ram::default();
            let mut table = ROOT_UPPER;
            let page_bits = if granule16 { 14 } else { 12 };
            let stride = page_bits - 3;
            for level in 0..=3_u8 {
                let shift = if level == 0 {
                    first_shift
                } else {
                    page_bits + stride * u32::from(3 - level)
                };
                let index = if level == 0 {
                    root_index
                } else {
                    (raw >> shift) & ((1 << stride) - 1)
                };
                let address = table + index * 8;
                if level == 3 {
                    memory.descriptors.insert(address, LEAF_PA | AF | 3);
                } else {
                    let next = 0x1_0000 + u64::from(level) * GRANULE16_BYTES;
                    memory.descriptors.insert(address, next | 3);
                    table = next;
                }
            }
            let mut request = access(AccessKind::Read, ExceptionLevel::El1);
            request.raw_virtual_address = raw;
            assert_eq!(
                translate(&config, &memory, request)
                    .unwrap()
                    .physical_address,
                LEAF_PA | VA
            );
            assert_eq!(memory.reads.borrow()[0], ROOT_UPPER + root_index * 8);
        }
    }

    #[test]
    fn regions_mmu_off_tbi_tbid_use_actual_access_kind() {
        let mut values = controls();
        values.sctlr_el1 &= !1;
        values.tcr_el1 = TCR_TBI0_TEST | TCR_TBID0_TEST;
        let memory = Ram::default();
        let config = Config::from_controls_for_cpu(values, cpu()).unwrap();
        let mut request = access(AccessKind::Read, ExceptionLevel::El1);
        request.raw_virtual_address = 0xab00_0000_0000_0123;
        assert_eq!(
            translate(&config, &memory, request)
                .unwrap()
                .physical_address,
            VA
        );
        request.kind = AccessKind::Fetch;
        let fault = assert_fault(
            translate(&config, &memory, request),
            FaultKind::AddressSize,
            0,
            false,
        );
        assert_eq!(
            fault.access.raw_virtual_address,
            request.raw_virtual_address
        );
        let mut profile = cpu();
        profile.pauth = false;
        let config = Config::from_controls_for_cpu(values, profile).unwrap();
        assert_eq!(
            translate(&config, &memory, request)
                .unwrap()
                .physical_address,
            VA
        );
        assert!(memory.reads.borrow().is_empty());
    }
}
