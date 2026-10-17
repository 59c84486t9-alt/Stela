//! Stage-2 translation of the EL1&0 regime (Arm ARM D8.2 to D8.6;
//! pseudocode AArch64.S2Translate, AArch64.S2Walk and
//! AArch64.S2CheckPermissions), with 4 KiB and 16 KiB granules, concatenated
//! start-level tables, FEAT_XNX execute permissions and FEAT_S2FWB.

use super::{
    Access, Alignment, Fault, FaultKind, MemoryType, Outcome, SecondStage, Stage2, TableMemory,
    Unsupported,
    alignment::{self, Shape},
    attributes,
    geometry::{self, Geometry},
};

const HCR_PTW: u64 = 1 << 2;
const HCR_CD: u64 = 1 << 32;
const HCR_ID: u64 = 1 << 33;
const HCR_FWB: u64 = 1 << 46;

const VTCR_T0SZ: u64 = 63;
const VTCR_SL0_SHIFT: u64 = 6;
const VTCR_TG0_SHIFT: u64 = 14;
const VTCR_PS_SHIFT: u64 = 16;

/// Tables smaller than 64 bytes are still 64-byte aligned, as at stage 1.
const MIN_TABLE_ALIGNMENT: u64 = 64;
/// VTTBR_EL2.BADDR[47:1]; bit 0 is CnP.
const VTTBR_BADDR: u64 = 0x0000_ffff_ffff_fffe;

const DESCRIPTOR_VALID: u64 = 1;
const DESCRIPTOR_TABLE: u64 = 2;
const MEMATTR_SHIFT: u64 = 2;
const SHAREABILITY_SHIFT: u64 = 8;
const S2AP_READ: u64 = 1 << 6;
const S2AP_WRITE: u64 = 1 << 7;
const ACCESS_FLAG: u64 = 1 << 10;
/// FEAT_XS: the output has XS 0.
const FNXS: u64 = 1 << 11;
/// FEAT_XNX: XN[0], which with XN[1] selects EL0 and EL1 execution.
const XNX: u64 = 1 << 53;
const XN: u64 = 1 << 54;
/// Output address bits [47:12]. Bits [51:48] are RES0 without FEAT_LPA;
/// the Contiguous hint, DBM (no FEAT_HAFDBS) and the software bits are
/// ignored.
const OUTPUT_ADDRESS: u64 = 0x0000_ffff_ffff_f000;

/// What stage 2 translates an IPA for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Access(Access),
    /// A stage-1 descriptor read (S1PTW).
    Walk,
}

/// Stage 1's attribute byte and SH field, which stage 2 combines with its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Input {
    pub attributes: u8,
    pub shareability: u8,
}

/// A completed stage-2 translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Output {
    pub physical: u64,
    /// The combined attribute byte and effective SH.
    pub attributes: u8,
    pub shareability: u8,
    /// Stage-2 permissions of the page for the requesting EL.
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub size: u64,
    /// Stage 2's part of the alignment rules.
    pub alignment: Alignment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Fault(Fault),
    Unsupported(Unsupported),
}

impl From<Stop> for Outcome {
    fn from(stop: Stop) -> Self {
        match stop {
            Stop::Fault(fault) => Outcome::Fault(fault),
            Stop::Unsupported(unsupported) => Outcome::Unsupported(unsupported),
        }
    }
}

/// The walk's shape from VTCR_EL2, or the level-0 Translation fault of an
/// invalid or inconsistent SL0 (pseudocode AArch64.S2InvalidSL and
/// AArch64.S2InconsistentSL). T0SZ is forced into range as for stage 1;
/// TG0 selecting 64 KiB or a reserved value is refused.
fn walk_shape(vtcr: u64) -> Result<Geometry, Result<(), Unsupported>> {
    let granule_bits = match (vtcr >> VTCR_TG0_SHIFT) & 3 {
        0 => 12,
        2 => 14,
        1 => return Err(Err(Unsupported::Granule { bits: 16 })),
        _ => return Err(Err(Unsupported::Granule { bits: 0 })),
    };
    let input_bits = 64 - geometry::forced_tnsz((vtcr & VTCR_T0SZ) as u32);
    // SL0 0b11 needs FEAT_TTST (4 KiB) or FEAT_LPA2 (16 KiB); 4 KiB level 0
    // needs a PARange of at least 44 bits and 16 KiB level 1 one of 42,
    // which the 48-bit profile has.
    let start_level = match (granule_bits, (vtcr >> VTCR_SL0_SHIFT) & 3) {
        (12, 0) | (14, 1) => 2,
        (12, 1) | (14, 2) => 1,
        (12, 2) => 0,
        (14, 0) => 3,
        _ => return Err(Ok(())),
    };
    // The start level resolves at least one bit and at most a granule's
    // worth plus four (sixteen concatenated tables).
    let stride = granule_bits - 3;
    let smallest = (3 - start_level) as u32 * stride + granule_bits + 1;
    if !(smallest..smallest + stride + 4).contains(&input_bits) {
        return Err(Ok(()));
    }
    Ok(Geometry {
        granule_bits,
        input_bits,
        start_level,
    })
}

/// Translate `ipa` for `purpose`. `el0` selects the EL0 execute permission
/// of FEAT_XNX; `input` is stage 1's attributes (`None` for a walk, whose
/// attributes nobody observes). With `shape`, an access stage 2's memory
/// type does not allow unaligned is an Alignment fault, ahead of a
/// Permission fault.
pub fn translate(
    stage2: &Stage2,
    ipa: u64,
    purpose: Purpose,
    el0: bool,
    input: Option<Input>,
    shape: Option<Shape>,
    memory: &mut dyn TableMemory,
) -> Result<Output, Stop> {
    let walk = purpose == Purpose::Walk;
    let fault = |kind, level| {
        Stop::Fault(Fault {
            kind,
            level,
            second_stage: Some(SecondStage { ipa, walk }),
        })
    };
    let geometry = match walk_shape(stage2.vtcr) {
        Ok(geometry) => geometry,
        Err(Ok(())) => return Err(fault(FaultKind::Translation, 0)),
        Err(Err(unsupported)) => return Err(Stop::Unsupported(unsupported)),
    };
    if ipa >> geometry.input_bits != 0 {
        return Err(fault(FaultKind::Translation, 0));
    }
    let output_bits = geometry::output_bits(stage2.vtcr >> VTCR_PS_SHIFT);
    let alignment = geometry.start_table_bytes().max(MIN_TABLE_ALIGNMENT);
    let mut table = stage2.vttbr & VTTBR_BADDR & !(alignment - 1);
    if table >> output_bits != 0 {
        return Err(fault(FaultKind::AddressSize, 0));
    }
    let mut level = geometry.start_level;
    let descriptor = loop {
        let address = table + geometry.index(ipa, level) * 8;
        let Some(descriptor) = memory.read_descriptor(address) else {
            return Err(fault(FaultKind::ExternalOnWalk, level));
        };
        if descriptor & DESCRIPTOR_VALID == 0 {
            return Err(fault(FaultKind::Translation, level));
        }
        let is_table = descriptor & DESCRIPTOR_TABLE != 0;
        if level < 3 && is_table {
            table = descriptor & OUTPUT_ADDRESS & !((1u64 << geometry.granule_bits) - 1);
            if table >> output_bits != 0 {
                return Err(fault(FaultKind::AddressSize, level));
            }
            level += 1;
            continue;
        }
        if level < 3 && !geometry.block_allowed(level) || level == 3 && !is_table {
            return Err(fault(FaultKind::Translation, level));
        }
        break descriptor;
    };
    let size = 1u64 << geometry.shift(level);
    let output = descriptor & OUTPUT_ADDRESS & !(size - 1);
    if output >> output_bits != 0 {
        return Err(fault(FaultKind::AddressSize, level));
    }
    // FEAT_HAFDBS is not in the profile: VTCR_EL2.HA is RES0.
    if descriptor & ACCESS_FLAG == 0 {
        return Err(fault(FaultKind::AccessFlag, level));
    }

    let readable = descriptor & S2AP_READ != 0;
    let writable = descriptor & S2AP_WRITE != 0;
    let executable = match (descriptor & XN != 0, descriptor & XNX != 0) {
        (false, false) => true,
        (false, true) => el0,
        (true, false) => false,
        (true, true) => !el0,
    };
    // Stage 2's own attributes (pseudocode AArch64.S2NextWalkStateLeaf):
    // MemAttr, or under FWB the override of stage 1's (a walk's are Normal
    // Write-Back).
    let field = ((descriptor >> MEMATTR_SHIFT) & 0xf) as u8;
    let forced = stage2.hcr & HCR_FWB != 0;
    let first = input.unwrap_or(Input {
        attributes: attributes::NORMAL_WRITE_BACK,
        shareability: attributes::INNER_SHAREABLE,
    });
    // FEAT_XS: FnXS clears the XS attribute of the output.
    let no_xs = stage2.xs && descriptor & FNXS != 0;
    let own = if forced {
        attributes::forced(first.attributes, field, no_xs, stage2.xs)
    } else {
        match attributes::of_stage2(field) {
            Some(own) => own,
            None => return Err(Stop::Unsupported(Unsupported::Stage2Attributes { field })),
        }
    };
    let device = attributes::memory_type(own) == MemoryType::Device;
    let alignment = Alignment { device };
    if shape.is_some_and(|shape| alignment::after_translation(alignment, ipa, shape)) {
        return Err(fault(FaultKind::Alignment, level));
    }
    let permitted = match purpose {
        // HCR_EL2.PTW: a stage-1 walk into stage-2 Device memory faults.
        Purpose::Walk => readable && !(stage2.hcr & HCR_PTW != 0 && device),
        Purpose::Access(Access::Read) => readable,
        Purpose::Access(Access::Write) => writable,
        Purpose::Access(Access::Execute) => executable,
    };
    if !permitted {
        return Err(fault(FaultKind::Permission, level));
    }

    let physical = output | (ipa & (size - 1));
    let Some(input) = input else {
        return Ok(Output {
            physical,
            attributes: attributes::NORMAL_WRITE_BACK,
            shareability: attributes::INNER_SHAREABLE,
            readable,
            writable,
            executable,
            size,
            alignment,
        });
    };
    // Stage 2 treats its output as Normal Non-cacheable for an instruction
    // fetch from Device memory or with HCR_EL2.ID, a data access to Normal
    // memory with HCR_EL2.CD, and a walk into Device memory without PTW
    // (pseudocode AArch64.S2TreatAsNormalNC). Instruction fetch from
    // Device memory does not fault (Unpredictable_INSTRDEVICE: NONE).
    let non_cacheable = match purpose {
        Purpose::Walk => device,
        Purpose::Access(Access::Execute) => device || stage2.hcr & HCR_ID != 0,
        Purpose::Access(_) => !device && stage2.hcr & HCR_CD != 0,
    };
    let (attributes, shareability) = if non_cacheable {
        let attribute = if forced {
            attributes::non_cacheable(own, stage2.xs)
        } else {
            attributes::combine(
                input.attributes,
                attributes::NORMAL_NON_CACHEABLE,
                !no_xs,
                stage2.xs,
            )
        };
        (attribute, attributes::OUTER_SHAREABLE)
    } else if forced {
        (own, descriptor_shareability(descriptor))
    } else {
        (
            attributes::combine(input.attributes, own, !no_xs, stage2.xs),
            descriptor_shareability(descriptor),
        )
    };
    let shareability = attributes::combine_shareability(input.shareability, shareability);
    Ok(Output {
        physical,
        attributes,
        shareability: attributes::effective_shareability(attributes, shareability),
        readable,
        writable,
        executable,
        size,
        alignment,
    })
}

fn descriptor_shareability(descriptor: u64) -> u8 {
    (descriptor >> SHAREABILITY_SHIFT) as u8 & 3
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    #[derive(Default)]
    struct Tables(BTreeMap<u64, u64>);

    impl TableMemory for Tables {
        fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
            (physical < 0x1_0000_0000).then(|| self.0.get(&physical).copied().unwrap_or(0))
        }
        fn update_descriptor(&mut self, _: u64, _: u64, _: u64) -> Option<bool> {
            unreachable!("the profile has no hardware descriptor updates")
        }
    }

    const TABLE: u64 = DESCRIPTOR_VALID | DESCRIPTOR_TABLE;
    /// A readable, writable, executable Normal Write-Back Inner Shareable page.
    const PAGE: u64 = TABLE | ACCESS_FLAG | S2AP_READ | S2AP_WRITE | 0b1111 << 2 | 0b11 << 8;
    const KERNEL_DATA: Input = Input {
        attributes: 0xff,
        shareability: 0b11,
    };

    /// 4 KiB, 40-bit IPA starting at level 1 with two concatenated tables
    /// (SL0 1), 48-bit PS.
    const VTCR_4K: u64 = 24 | 1 << 6 | 5 << 16 | 1 << 31;
    /// 16 KiB, 36-bit IPA starting at level 2 (SL0 1), 40-bit PS.
    const VTCR_16K: u64 = 28 | 1 << 6 | 2 << 14 | 2 << 16 | 1 << 31;

    fn stage2(vtcr: u64) -> Stage2 {
        Stage2 {
            hcr: 1,
            vtcr,
            vttbr: 0x10_0000 | 7 << 48,
            xs: super::super::test_xs(),
        }
    }

    fn data(
        stage2: &Stage2,
        ipa: u64,
        access: Access,
        tables: &mut Tables,
    ) -> Result<Output, Stop> {
        translate(
            stage2,
            ipa,
            Purpose::Access(access),
            false,
            Some(KERNEL_DATA),
            None,
            tables,
        )
    }

    fn fault(result: Result<Output, Stop>) -> Option<(FaultKind, i8, bool)> {
        match result {
            Err(Stop::Fault(fault)) => {
                let second_stage = fault.second_stage.expect("stage-2 fault");
                Some((fault.kind, fault.level, second_stage.walk))
            }
            _ => None,
        }
    }

    /// Map `ipa` through a 4 KiB level-1 (concatenated), 2 and 3 walk.
    fn map_4k(tables: &mut Tables, ipa: u64, leaf: u64) {
        let level1 = 0x10_0000 + ((ipa >> 30) & 0x3ff) * 8;
        let level2 = 0x20_0000 + ((ipa >> 21) & 0x1ff) * 8;
        let level3 = 0x30_0000 + ((ipa >> 12) & 0x1ff) * 8;
        tables.0.insert(level1, 0x20_0000 | TABLE);
        tables.0.insert(level2, 0x30_0000 | TABLE);
        tables.0.insert(level3, leaf);
    }

    #[test]
    fn walks_4k_concatenated_and_16k_tables_with_blocks() {
        let mut tables = Tables::default();
        let s2 = stage2(VTCR_4K);
        // IPA bit 39 selects the second concatenated level-1 table.
        let ipa = 0x80_4000_5123;
        map_4k(&mut tables, ipa, 0x8_0000_1000 | PAGE);
        let output = data(&s2, ipa, Access::Write, &mut tables).unwrap();
        assert_eq!(output.physical, 0x8_0000_1123);
        assert_eq!(
            (output.attributes, output.shareability, output.size),
            (0xff, 0b11, 1 << 12)
        );
        // A 2 MiB block at level 2 and a 1 GiB block at level 1.
        let block = (PAGE & !DESCRIPTOR_TABLE) | 0x8_0020_0000;
        tables
            .0
            .insert(0x20_0000 + ((ipa >> 21) & 0x1ff) * 8, block);
        let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
        assert_eq!((output.physical, output.size), (0x8_0020_5123, 1 << 21));
        tables.0.insert(
            0x10_0000 + ((ipa >> 30) & 0x3ff) * 8,
            (PAGE & !DESCRIPTOR_TABLE) | 0x8_4000_0000,
        );
        let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
        assert_eq!((output.physical, output.size), (0x8_4000_5123, 1 << 30));

        // 16 KiB: levels 2 and 3, 32 MiB blocks at level 2 only.
        let s2 = stage2(VTCR_16K);
        let mut tables = Tables::default();
        let ipa = 0xf_ffff_c010;
        tables
            .0
            .insert(0x10_0000 + ((ipa >> 25) & 0x7ff) * 8, 0x40_0000 | TABLE);
        tables
            .0
            .insert(0x40_0000 + ((ipa >> 14) & 0x7ff) * 8, 0x80_0000_8000 | PAGE);
        let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
        assert_eq!((output.physical, output.size), (0x80_0000_8010, 1 << 14));
        tables.0.insert(
            0x10_0000 + ((ipa >> 25) & 0x7ff) * 8,
            (PAGE & !DESCRIPTOR_TABLE) | 0x80_0200_0000,
        );
        let output = data(&s2, ipa, Access::Read, &mut tables).unwrap();
        assert_eq!((output.physical, output.size), (0x80_03ff_c010, 1 << 25));
        // A 16 KiB level-3 block encoding is a Translation fault.
        tables
            .0
            .insert(0x10_0000 + ((ipa >> 25) & 0x7ff) * 8, 0x40_0000 | TABLE);
        tables.0.insert(
            0x40_0000 + ((ipa >> 14) & 0x7ff) * 8,
            (PAGE & !DESCRIPTOR_TABLE) | 0x80_0000_8000,
        );
        assert_eq!(
            fault(data(&s2, ipa, Access::Read, &mut tables)),
            Some((FaultKind::Translation, 3, false))
        );
    }

    #[test]
    fn start_level_input_size_and_output_size_faults_are_reported() {
        let mut tables = Tables::default();
        let ipa = 0x1000;
        map_4k(&mut tables, ipa, 0x10_0000_1000 | PAGE);
        let translation = |vtcr: u64, ipa: u64, tables: &mut Tables| {
            fault(data(&stage2(vtcr), ipa, Access::Read, tables))
        };
        // SL0 0b11 (no FEAT_TTST) and 16 KiB SL0 0b11 (no FEAT_LPA2).
        assert_eq!(
            translation(VTCR_4K | 3 << 6, ipa, &mut tables),
            Some((FaultKind::Translation, 0, false))
        );
        assert_eq!(
            translation(VTCR_16K | 3 << 6, ipa, &mut tables),
            Some((FaultKind::Translation, 0, false))
        );
        // A 40-bit IPA starting at level 2 would need 512 concatenated tables.
        let inconsistent = VTCR_4K & !(3 << 6);
        assert_eq!(
            translation(inconsistent, ipa, &mut tables),
            Some((FaultKind::Translation, 0, false))
        );
        // An IPA beyond the 40-bit input size.
        assert_eq!(
            translation(VTCR_4K, 1 << 40, &mut tables),
            Some((FaultKind::Translation, 0, false))
        );
        // An output above a 36-bit PS faults at the leaf; a table above it
        // at the level that pointed to it; VTTBR above it at level 0.
        let small = (VTCR_4K & !(7 << 16)) | 1 << 16;
        assert_eq!(
            translation(small, ipa, &mut tables),
            Some((FaultKind::AddressSize, 3, false))
        );
        let mut far = Tables::default();
        far.0.insert(0x10_0000, 0x10_0000_0000 | TABLE);
        assert_eq!(
            translation(small, ipa, &mut far),
            Some((FaultKind::AddressSize, 1, false))
        );
        let high = Stage2 {
            vttbr: 0x10_0000_0000,
            ..stage2(small)
        };
        assert_eq!(
            fault(data(&high, ipa, Access::Read, &mut tables)),
            Some((FaultKind::AddressSize, 0, false))
        );
        // Invalid descriptors, AF clear and walks outside memory.
        map_4k(&mut tables, ipa, 0x8_0000_1000 | (PAGE & !ACCESS_FLAG));
        assert_eq!(
            translation(VTCR_4K, ipa, &mut tables),
            Some((FaultKind::AccessFlag, 3, false))
        );
        assert_eq!(
            translation(VTCR_4K, 0x4000_0000, &mut tables),
            Some((FaultKind::Translation, 1, false))
        );
        let outside = Stage2 {
            vttbr: 0x2_0000_0000,
            ..stage2(VTCR_4K)
        };
        assert_eq!(
            fault(data(&outside, ipa, Access::Read, &mut tables)),
            Some((FaultKind::ExternalOnWalk, 1, false))
        );
        // T0SZ below 16 is forced, not faulted; 64 KiB and reserved TG0 refuse.
        assert_eq!(
            data(&stage2(VTCR_16K | 3 << 14), ipa, Access::Read, &mut tables),
            Err(Stop::Unsupported(Unsupported::Granule { bits: 0 }))
        );
        assert_eq!(
            data(
                &stage2((VTCR_4K & !(3 << 14)) | 1 << 14),
                ipa,
                Access::Read,
                &mut tables
            ),
            Err(Stop::Unsupported(Unsupported::Granule { bits: 16 }))
        );
    }

    #[test]
    fn s2ap_and_xnx_give_read_write_and_per_el_execute() {
        let mut tables = Tables::default();
        let s2 = stage2(VTCR_4K);
        let ipa = 0x7000;
        let rights = |leaf: u64, el0: bool, tables: &mut Tables| {
            map_4k(tables, ipa, 0x8_0000_0000 | leaf);
            [Access::Read, Access::Write, Access::Execute].map(|access| {
                translate(
                    &s2,
                    ipa,
                    Purpose::Access(access),
                    el0,
                    Some(KERNEL_DATA),
                    None,
                    tables,
                )
                .is_ok()
            })
        };
        let base = PAGE & !(S2AP_READ | S2AP_WRITE);
        assert_eq!(rights(base, false, &mut tables), [false, false, true]);
        assert_eq!(
            rights(base | S2AP_READ, false, &mut tables),
            [true, false, true]
        );
        assert_eq!(
            rights(base | S2AP_WRITE, false, &mut tables),
            [false, true, true]
        );
        // XN[1:0]: 01 executes at EL0 only, 10 nowhere, 11 at EL1 only.
        assert_eq!(rights(PAGE | XNX, false, &mut tables), [true, true, false]);
        assert_eq!(rights(PAGE | XNX, true, &mut tables), [true, true, true]);
        assert_eq!(rights(PAGE | XN, true, &mut tables), [true, true, false]);
        assert_eq!(
            rights(PAGE | XN | XNX, false, &mut tables),
            [true, true, true]
        );
        assert_eq!(
            rights(PAGE | XN | XNX, true, &mut tables),
            [true, true, false]
        );
        map_4k(&mut tables, ipa, 0x8_0000_0000 | (PAGE & !S2AP_WRITE));
        assert_eq!(
            fault(data(&s2, ipa, Access::Write, &mut tables)),
            Some((FaultKind::Permission, 3, false))
        );
        // A walk needs read permission, and with HCR_EL2.PTW Normal memory.
        map_4k(&mut tables, ipa, 0x8_0000_0000 | (PAGE & !S2AP_READ));
        let walk = |s2: &Stage2, tables: &mut Tables| {
            fault(translate(s2, ipa, Purpose::Walk, false, None, None, tables))
        };
        assert_eq!(
            walk(&s2, &mut tables),
            Some((FaultKind::Permission, 3, true))
        );
        let device = (PAGE & !(0xf << 2)) | 0b0001 << 2;
        map_4k(&mut tables, ipa, 0x8_0000_0000 | device);
        assert_eq!(walk(&s2, &mut tables), None);
        let ptw = Stage2 {
            hcr: s2.hcr | HCR_PTW,
            ..s2
        };
        assert_eq!(
            walk(&ptw, &mut tables),
            Some((FaultKind::Permission, 3, true))
        );
    }

    #[test]
    fn attributes_combine_with_stage_one_or_are_forced() {
        let mut tables = Tables::default();
        let s2 = stage2(VTCR_4K);
        let ipa = 0x9000;
        let leaf = |field: u64, shareability: u64| {
            PAGE & !(0xf << 2 | 3 << 8) | field << 2 | shareability << 8
        };
        let mut attributes = |s2: &Stage2, input: Input, leaf: u64, execute: bool| {
            map_4k(&mut tables, ipa, 0x8_0000_0000 | leaf);
            let access = if execute {
                Access::Execute
            } else {
                Access::Read
            };
            let output = translate(
                s2,
                ipa,
                Purpose::Access(access),
                false,
                Some(input),
                None,
                &mut tables,
            );
            output.map(|output| (output.attributes, output.shareability))
        };
        let non_shareable = Input {
            attributes: 0xff,
            shareability: 0,
        };
        // Stage 2 Normal WT Inner Shareable: WT with stage 1's hints, ISH.
        assert_eq!(
            attributes(&s2, non_shareable, leaf(0b1010, 0b11), false),
            Ok((0xbb, 0b11))
        );
        // Stage 2 Device-nGnRE: Device, Outer Shareable, with stage 1's
        // Write-Back XS of 0 under FEAT_XS.
        let device = if super::super::test_xs() { 0x05 } else { 0x04 };
        assert_eq!(
            attributes(&s2, non_shareable, leaf(0b0001, 0), false),
            Ok((device, 0b10))
        );
        // Reserved MemAttr refuses.
        assert_eq!(
            attributes(&s2, non_shareable, leaf(0b1000, 0), false),
            Err(Stop::Unsupported(Unsupported::Stage2Attributes {
                field: 0b1000
            }))
        );
        // HCR_EL2.CD makes Normal data Non-cacheable; HCR_EL2.ID and Device
        // memory make instruction fetch Non-cacheable, keeping stage 1's
        // Write-Back XS of 0 under FEAT_XS.
        let nc = if super::super::test_xs() { 0x40 } else { 0x44 };
        let cd = Stage2 {
            hcr: s2.hcr | HCR_CD,
            ..s2
        };
        assert_eq!(
            attributes(&cd, non_shareable, leaf(0b1111, 0b11), false),
            Ok((nc, 0b10))
        );
        assert_eq!(
            attributes(&s2, non_shareable, leaf(0b0000, 0), true),
            Ok((nc, 0b10))
        );
        let id = Stage2 {
            hcr: s2.hcr | HCR_ID,
            ..s2
        };
        assert_eq!(
            attributes(&id, non_shareable, leaf(0b1111, 0b11), true),
            Ok((nc, 0b10))
        );
        // FWB: 0b110 forces Write-Back over stage-1 Device, and the SH
        // fields still combine.
        let fwb = Stage2 {
            hcr: s2.hcr | HCR_FWB,
            ..s2
        };
        let device_ngre = if super::super::test_xs() { 0x09 } else { 0x08 };
        let device = Input {
            attributes: 0x00,
            shareability: 0,
        };
        assert_eq!(
            attributes(&fwb, device, leaf(0b0110, 0b11), false),
            Ok((0xff, 0b11))
        );
        assert_eq!(
            attributes(&fwb, non_shareable, leaf(0b0111, 0), false),
            Ok((0xff, 0))
        );
        assert_eq!(
            attributes(&fwb, non_shareable, leaf(0b0010, 0), false),
            Ok((device_ngre, 0b10))
        );
        // FEAT_XS: stage-1 Device-nGnRE with XS 1 stays XS 1 unless the
        // descriptor's FnXS clears it, with and without FWB; without
        // FEAT_XS bit 11 is ignored.
        let xs = Stage2 { xs: true, ..s2 };
        let fwb_xs = Stage2 { xs: true, ..fwb };
        let device = Input {
            attributes: 0x04,
            shareability: 0,
        };
        for s2 in [&xs, &fwb_xs] {
            assert_eq!(
                attributes(s2, device, leaf(0b0111, 0), false).map(|(a, _)| a),
                Ok(0x04)
            );
            assert_eq!(
                attributes(s2, device, leaf(0b0111, 0) | FNXS, false).map(|(a, _)| a),
                Ok(0x05)
            );
        }
        let no_xs = Stage2 { xs: false, ..s2 };
        assert_eq!(
            attributes(&no_xs, device, leaf(0b0111, 0) | FNXS, false).map(|(a, _)| a),
            Ok(0x04)
        );
    }
}
