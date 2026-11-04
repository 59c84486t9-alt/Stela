//! Stage-1 translation of the EL1&0, EL2&0 and EL2 regimes (Arm ARM D8.2
//! to D8.5; pseudocode AArch64.S1Translate and AArch64.S1Walk).

use super::{
    Access, Alignment, Controls, Fault, FaultKind, MemoryType, Outcome, PHYSICAL_ADDRESS_BITS,
    PagePermissions, Regime, Requester, SCTLR_M, SCTLR_WXN, TableMemory, Translation, Unsupported,
    alignment::MemoryCheck,
    attributes,
    geometry::{self, Geometry},
    sprr,
};

// TCR_EL1, and TCR_EL2 with E2H set.
/// FEAT_PAN3: PAN also covers locations EL0 may execute.
const SCTLR_EPAN: u64 = 1 << 57;
const TCR_T0SZ_SHIFT: u64 = 0;
const TCR_EPD0: u64 = 1 << 7;
const TCR_TG0_SHIFT: u64 = 14;
const TCR_T1SZ_SHIFT: u64 = 16;
const TCR_A1: u64 = 1 << 22;
const TCR_EPD1: u64 = 1 << 23;
const TCR_TG1_SHIFT: u64 = 30;
const TCR_IPS_SHIFT: u64 = 32;
const TCR_AS: u64 = 1 << 36;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_HPD0: u64 = 1 << 41;
const TCR_HPD1: u64 = 1 << 42;
const TCR_TBID0: u64 = 1 << 51;
const TCR_TBID1: u64 = 1 << 52;
const TCR_E0PD0: u64 = 1 << 55;
const TCR_E0PD1: u64 = 1 << 56;
// TCR_EL2 with E2H clear.
const TCR_EL2_PS_SHIFT: u64 = 16;
const TCR_EL2_TBI: u64 = 1 << 20;
const TCR_EL2_HPD: u64 = 1 << 24;
const TCR_EL2_TBID: u64 = 1 << 29;
const TNSZ_MASK: u64 = 63;

/// TTBR BADDR[47:1]; bit 0 is CnP (FEAT_TTCNP), a hint for shared TLBs.
const TTBR_BADDR: u64 = 0x0000_ffff_ffff_fffe;
const TTBR_ASID_SHIFT: u64 = 48;
/// Tables smaller than 64 bytes are still 64-byte aligned.
const MIN_TABLE_ALIGNMENT: u64 = 64;

const DESCRIPTOR_VALID: u64 = 1;
const DESCRIPTOR_TABLE: u64 = 2;
const AP_EL0: u64 = 1 << 6;
const AP_READ_ONLY: u64 = 1 << 7;
const ACCESS_FLAG: u64 = 1 << 10;
const NOT_GLOBAL: u64 = 1 << 11;
/// FEAT_BTI's Guarded Page bit of a stage-1 leaf.
const GUARDED: u64 = 1 << 50;
const SHAREABILITY_SHIFT: u64 = 8;
const PXN: u64 = 1 << 53;
/// UXN in a two-privilege regime, XN in EL2.
const UXN: u64 = 1 << 54;
const PXN_TABLE: u64 = 1 << 59;
/// UXNTable in a two-privilege regime, XNTable in EL2.
const UXN_TABLE: u64 = 1 << 60;
const AP_TABLE_NO_EL0: u64 = 1 << 61;
const AP_TABLE_READ_ONLY: u64 = 1 << 62;
/// Output address bits [47:12]. Bits [51:48] are RES0 without FEAT_LPA and
/// are ignored; so are nT (no FEAT_BBM), the Contiguous hint, DBM (no
/// FEAT_HAFDBS) and GP (FEAT_BTI is not advertised).
const OUTPUT_ADDRESS: u64 = 0x0000_ffff_ffff_f000;

/// The walk of the half of the regime an address selects.
struct Range {
    ttbr: u64,
    /// 64 - TnSZ.
    input_bits: u32,
    /// The granule, resolved only when a walk needs it: a range that EPD or
    /// E0PD disables faults whatever TGn holds.
    granule: Result<u32, Unsupported>,
    /// EPDn: a TLB miss in this half faults without a walk.
    disabled: bool,
    /// FEAT_E0PD: EL0 accesses to this half fault without a walk.
    no_el0: bool,
    /// APTable, PXNTable and UXNTable apply (HPDn clear).
    hierarchical: bool,
    output_bits: u32,
    /// Top-byte-ignore for this access.
    top_byte_ignored: bool,
}

/// The granule of a TG0 (`upper` false) or TG1 encoding.
fn granule(encoding: u64, upper: bool) -> Result<u32, Unsupported> {
    match (encoding & 3, upper) {
        (0, false) | (2, true) => Ok(12),
        (2, false) | (1, true) => Ok(14),
        (1, false) | (3, true) => Err(Unsupported::Granule { bits: 16 }),
        _ => Err(Unsupported::Granule { bits: 0 }),
    }
}

fn two_ranges(regime: Regime) -> bool {
    regime != Regime::El2
}

fn range(controls: &Controls, upper: bool, access: Access) -> Range {
    let tcr = controls.tcr;
    let execute = access == Access::Execute;
    if !two_ranges(controls.regime) {
        let tnsz = geometry::forced_tnsz((tcr & TNSZ_MASK) as u32);
        return Range {
            ttbr: controls.ttbr0,
            input_bits: 64 - tnsz,
            granule: granule(tcr >> TCR_TG0_SHIFT, false),
            disabled: false,
            no_el0: false,
            hierarchical: tcr & TCR_EL2_HPD == 0,
            output_bits: geometry::output_bits(tcr >> TCR_EL2_PS_SHIFT),
            top_byte_ignored: tcr & TCR_EL2_TBI != 0 && !(execute && tcr & TCR_EL2_TBID != 0),
        };
    }
    let (tnsz_shift, tg_shift, ttbr, epd, e0pd, hpd, tbi, tbid) = if upper {
        (
            TCR_T1SZ_SHIFT,
            TCR_TG1_SHIFT,
            controls.ttbr1,
            TCR_EPD1,
            TCR_E0PD1,
            TCR_HPD1,
            TCR_TBI1,
            TCR_TBID1,
        )
    } else {
        (
            TCR_T0SZ_SHIFT,
            TCR_TG0_SHIFT,
            controls.ttbr0,
            TCR_EPD0,
            TCR_E0PD0,
            TCR_HPD0,
            TCR_TBI0,
            TCR_TBID0,
        )
    };
    let tnsz = geometry::forced_tnsz(((tcr >> tnsz_shift) & TNSZ_MASK) as u32);
    Range {
        ttbr,
        input_bits: 64 - tnsz,
        granule: granule(tcr >> tg_shift, upper),
        disabled: tcr & epd != 0,
        no_el0: tcr & e0pd != 0,
        hierarchical: tcr & hpd == 0,
        output_bits: geometry::output_bits(tcr >> TCR_IPS_SHIFT),
        top_byte_ignored: tcr & tbi != 0 && !(execute && tcr & tbid != 0),
    }
}

/// The ASID that tags non-global entries; the EL2 regime has none.
pub fn asid(controls: &Controls) -> u16 {
    if !two_ranges(controls.regime) {
        return 0;
    }
    let ttbr = if controls.tcr & TCR_A1 != 0 {
        controls.ttbr1
    } else {
        controls.ttbr0
    };
    let asid = (ttbr >> TTBR_ASID_SHIFT) as u16;
    if controls.tcr & TCR_AS != 0 {
        asid
    } else {
        asid & 0xff
    }
}

fn fault(kind: FaultKind, level: i8) -> Outcome {
    Outcome::Fault(Fault::stage1(kind, level))
}

/// Stage 1 disabled: the address is the output address, checked against
/// PARange after any top byte the regime ignores (pseudocode
/// AArch64.S1DisabledOutput). Returns the outcome and its SH field.
fn disabled(
    controls: &Controls,
    address: u64,
    access: Access,
    shape: Option<MemoryCheck>,
) -> (Outcome, u8) {
    let upper = two_ranges(controls.regime) && address & (1 << 55) != 0;
    let ignored = range(controls, upper, access).top_byte_ignored;
    let checked = if ignored {
        address & ((1 << 56) - 1)
    } else {
        address
    };
    if checked >> PHYSICAL_ADDRESS_BITS != 0 {
        return (fault(FaultKind::AddressSize, 0), 0);
    }
    // HCR_EL2.DC makes EL1&0 output Normal Write-Back, Non-shareable, and
    // Tagged with HCR_EL2.DCT.
    let (attributes, memory, shareability) = if default_cacheable(controls) {
        let tagged = controls.tagged
            && controls
                .second_stage
                .is_some_and(|stage2| stage2.default_tagged());
        (
            if tagged {
                attributes::TAGGED
            } else {
                attributes::NORMAL_WRITE_BACK
            },
            MemoryType::Normal,
            attributes::NON_SHAREABLE,
        )
    } else {
        let (attributes, memory) = attributes::disabled(controls.sctlr, access == Access::Execute);
        (attributes, memory, attributes::OUTER_SHAREABLE)
    };
    let translation = Translation {
        physical: checked,
        memory,
        attributes,
        shareability,
        readable: true,
        writable: true,
        executable: true,
        pan_sensitive: false,
        guarded: false,
        global: true,
        asid: 0,
        size: 1 << 12,
        alignment: stage_alignment(attributes),
    };
    if shape.is_some_and(|shape| shape.faults(translation.alignment)) {
        return (fault(FaultKind::Alignment, 0), 0);
    }
    (Outcome::Mapped(translation), shareability)
}

/// The alignment summary of stage-1 attributes: whether the memory is
/// Device (pseudocode AArch64.S1HasAlignmentFaultDueToMemType).
fn stage_alignment(attribute: u8) -> Alignment {
    Alignment {
        device: attributes::memory_type(attribute) == MemoryType::Device,
    }
}

fn default_cacheable(controls: &Controls) -> bool {
    controls
        .second_stage
        .is_some_and(|stage2| stage2.default_cacheable(controls.regime))
}

/// Permission limits collected from table descriptors.
#[derive(Default)]
struct Hierarchy {
    no_el0: bool,
    read_only: bool,
    pxn: bool,
    uxn: bool,
}

#[cfg(test)]
pub fn translate(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
) -> Outcome {
    walk(controls, address, access, requester, None, memory).0
}

/// The stage-1 outcome, and for a mapping the descriptor's SH field, which a
/// stage-2 combination uses before Device and Non-cacheable memory make it
/// Outer Shareable. With `shape`, an access the memory type does not allow
/// unaligned is an Alignment fault, ahead of a Permission fault.
pub fn walk(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    shape: Option<MemoryCheck>,
    memory: &mut dyn TableMemory,
) -> (Outcome, u8) {
    if controls.sctlr & SCTLR_M == 0 || default_cacheable(controls) {
        return disabled(controls, address, access, shape);
    }
    let mut shareability = 0;
    let outcome = walk_enabled(
        controls,
        address,
        access,
        requester,
        shape,
        memory,
        &mut shareability,
    );
    (outcome, shareability)
}

fn walk_enabled(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    shape: Option<MemoryCheck>,
    memory: &mut dyn TableMemory,
    shareability_field: &mut u8,
) -> Outcome {
    let upper = two_ranges(controls.regime) && address & (1 << 55) != 0;
    let range = range(controls, upper, access);
    // Every bit above the region must equal bit 55 (zero in the EL2 regime);
    // with TBI the top byte is excluded from that check.
    let input_bits = range.input_bits;
    let checked_top = if range.top_byte_ignored { 56 } else { 64 };
    let extension = (address >> input_bits) & ((1u64 << (checked_top - input_bits)) - 1);
    let expected = if upper {
        (1u64 << (checked_top - input_bits)) - 1
    } else {
        0
    };
    let as_el0 = requester.el == 0 || requester.unprivileged;
    if extension != expected || range.disabled || range.no_el0 && as_el0 {
        return fault(FaultKind::Translation, 0);
    }
    let geometry = match range.granule {
        Ok(granule) => Geometry::stage1(granule, input_bits),
        Err(unsupported) => return Outcome::Unsupported(unsupported),
    };
    let alignment = geometry.start_table_bytes().max(MIN_TABLE_ALIGNMENT);
    let mut table = range.ttbr & TTBR_BADDR & !(alignment - 1);
    if table >> range.output_bits != 0 {
        return fault(FaultKind::AddressSize, 0);
    }
    let mut level = geometry.start_level;
    let mut hierarchy = Hierarchy::default();
    loop {
        let descriptor_address = table + geometry.index(address, level) * 8;
        let Some(descriptor) = memory.read_descriptor(descriptor_address) else {
            return fault(FaultKind::ExternalOnWalk, level);
        };
        if descriptor & DESCRIPTOR_VALID == 0 {
            return fault(FaultKind::Translation, level);
        }
        let is_table = descriptor & DESCRIPTOR_TABLE != 0;
        if level < 3 && is_table {
            if range.hierarchical {
                hierarchy.no_el0 |= descriptor & AP_TABLE_NO_EL0 != 0;
                hierarchy.read_only |= descriptor & AP_TABLE_READ_ONLY != 0;
                hierarchy.pxn |= descriptor & PXN_TABLE != 0;
                hierarchy.uxn |= descriptor & UXN_TABLE != 0;
            }
            table = descriptor & OUTPUT_ADDRESS & !((1u64 << geometry.granule_bits) - 1);
            if table >> range.output_bits != 0 {
                return fault(FaultKind::AddressSize, level);
            }
            level += 1;
            continue;
        }
        // A block where none is allowed, and type 0b01 at level 3, are
        // Translation faults.
        if level < 3 && !geometry.block_allowed(level) || level == 3 && !is_table {
            return fault(FaultKind::Translation, level);
        }
        let size = 1u64 << geometry.shift(level);
        let output = descriptor & OUTPUT_ADDRESS & !(size - 1);
        if output >> range.output_bits != 0 {
            return fault(FaultKind::AddressSize, level);
        }
        // FEAT_HAFDBS is not in the profile: TCR.HA is RES0.
        if descriptor & ACCESS_FLAG == 0 {
            return fault(FaultKind::AccessFlag, level);
        }
        let (mut attributes, mut memory, mut shareability) =
            attributes::of_descriptor(controls.mair, descriptor, controls.xs, controls.tagged);
        let field = (descriptor >> SHAREABILITY_SHIFT) as u8 & 3;
        let alignment = stage_alignment(attributes);
        if shape.is_some_and(|shape| shape.faults(alignment)) {
            return fault(FaultKind::Alignment, level);
        }
        let rights = if controls.sprr.enabled() {
            let sprr_hierarchy = sprr::Hierarchy {
                no_el0: hierarchy.no_el0,
                read_only: hierarchy.read_only,
                pxn_table: hierarchy.pxn,
                uxn_table: hierarchy.uxn,
            };
            match sprr::permissions(controls.sprr, requester, &sprr_hierarchy, descriptor) {
                Ok(rights) => rights,
                Err(unsupported) => return Outcome::Unsupported(unsupported),
            }
        } else {
            rights(controls, requester, &hierarchy, descriptor)
        };
        if !rights.permits(access) {
            return fault(FaultKind::Permission, level);
        }
        // Caches off (pseudocode AArch64.S1TreatAsNormalNC), after the
        // alignment check, which sees the descriptor's attributes. Stage 2
        // still combines the descriptor's SH field.
        if attributes::stage1_non_cacheable(controls.sctlr, attributes, access == Access::Execute) {
            attributes = attributes::non_cacheable(attributes, controls.xs);
            memory = MemoryType::Normal;
            shareability = attributes::OUTER_SHAREABLE;
        }
        let global = !two_ranges(controls.regime) || descriptor & NOT_GLOBAL == 0;
        *shareability_field = field;
        return Outcome::Mapped(Translation {
            physical: output | (address & (size - 1)),
            memory,
            attributes,
            shareability,
            readable: rights.readable,
            writable: rights.writable,
            executable: rights.executable,
            pan_sensitive: rights.pan_sensitive,
            guarded: descriptor & GUARDED != 0 && rights.executable,
            global,
            asid: if global { 0 } else { asid(controls) },
            size,
            alignment,
        });
    }
}

/// The rights of a leaf for `requester` (Arm ARM
/// D8.4, pseudocode AArch64.S1DirectBasePermissions and
/// AArch64.S1HasPermissionsFault): data rights after PAN, execution at the
/// requesting EL.
fn rights(
    controls: &Controls,
    requester: Requester,
    hierarchy: &Hierarchy,
    descriptor: u64,
) -> PagePermissions {
    let read_only = descriptor & AP_READ_ONLY != 0 || hierarchy.read_only;
    let wxn = controls.sctlr & SCTLR_WXN != 0;
    if !two_ranges(controls.regime) {
        // One privilege level: AP[1] and PXN are ignored, bit 54 is XN.
        let writable = !read_only;
        let executable = descriptor & UXN == 0 && !hierarchy.uxn && !(wxn && writable);
        return PagePermissions {
            readable: true,
            writable,
            executable,
            pan_sensitive: false,
        };
    }
    let el0_readable = descriptor & AP_EL0 != 0 && !hierarchy.no_el0;
    let el0_writable = el0_readable && !read_only;
    let privileged_writable = !read_only;
    // EL0 may execute a location it cannot read (execute-only memory); the
    // kernel level never executes a location EL0 can write.
    let el0_executable = descriptor & UXN == 0 && !hierarchy.uxn && !(wxn && el0_writable);
    let privileged_executable =
        descriptor & PXN == 0 && !hierarchy.pxn && !el0_writable && !(wxn && privileged_writable);
    if requester.el == 0 || requester.unprivileged {
        return PagePermissions {
            readable: el0_readable,
            writable: el0_writable,
            executable: if requester.el == 0 {
                el0_executable
            } else {
                privileged_executable
            },
            pan_sensitive: false,
        };
    }
    // PAN removes kernel-level data access to EL0-accessible locations, and
    // with SCTLR_ELx.EPAN (FEAT_PAN3, RES0 without it) to locations EL0 may
    // execute, before WXN; it never affects execution.
    let el0_execute_permitted = descriptor & UXN == 0 && !hierarchy.uxn;
    let enhanced = controls.sctlr & SCTLR_EPAN != 0;
    let pan_sensitive = el0_readable || enhanced && el0_execute_permitted;
    let pan = requester.pan && pan_sensitive;
    PagePermissions {
        readable: !pan,
        writable: !pan && privileged_writable,
        executable: privileged_executable,
        pan_sensitive,
    }
}

#[cfg(test)]
mod tests;
