//! Stage-2 translation of the EL1&0 regime (Arm ARM D8.2 to D8.6;
//! pseudocode AArch64.S2Translate, AArch64.S2Walk and
//! AArch64.S2CheckPermissions), with 4 KiB and 16 KiB granules, concatenated
//! start-level tables, FEAT_XNX execute permissions and FEAT_S2FWB.

use super::{
    Access, Alignment, Fault, FaultKind, MemoryType, Outcome, SecondStage, Stage2, TableMemory,
    Unsupported,
    alignment::MemoryCheck,
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
    shape: Option<MemoryCheck>,
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
    if shape.is_some_and(|shape| shape.faults(alignment)) {
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
mod tests;
