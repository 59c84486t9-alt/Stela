//! Arm shared pseudocode functions the generated accessors call, written from
//! the ASL of `ISA_A64_xml_A_profile-2026-06` `shared_pseudocode.xml` for the
//! profile: EL2 is implemented and enabled (no EL3, Non-secure only) and
//! FEAT_VHE without FEAT_E2H0 (HCR_EL2.E2H is RES1).
use super::{CacheOp, CacheScope, CacheType, Context, Effect, Feature, Register};

pub const HCR_TGE: u32 = 27;
pub const VTTBR_VMID: u32 = 48;

/// `value[low + width - 1 : low]`.
pub fn bits(value: u64, low: u64, width: u64) -> u64 {
    if low >= 64 {
        return 0;
    }
    let shifted = value >> low;
    if width >= 64 {
        shifted
    } else {
        shifted & ((1u64 << width) - 1)
    }
}

/// `old` with `old[low + width - 1 : low] = value`.
pub fn insert(old: u64, low: u64, width: u64, value: u64) -> u64 {
    let mask = if width >= 64 {
        u64::MAX
    } else {
        ((1u64 << width) - 1) << low
    };
    (old & !mask) | ((value << low) & mask)
}

/// `SignExtend{64}(value)` of a `width`-bit value.
pub fn sign_extend(value: u64, width: u64) -> u64 {
    let shift = 64 - width;
    (((value << shift) as i64) >> shift) as u64
}

pub const HCR_NV: u32 = 42;
pub const HCR_NV2: u32 = 45;

/// Arm `EffectiveHCR_EL2_NVx` of an HCR_EL2 value: HCR_EL2.{NV2, NV1, NV}
/// in effect, EL2 being enabled. NV1 is RAZ (the IMPLEMENTATION DEFINED
/// choice "HCR_EL2.NV1 is implemented as RAZ", `cargo xtask system-matrix`
/// IMPDEF), so NV = 0 gives '000' and NV1 reads 0; NV2 takes effect only when
/// it is set (the choice that '10' does not behave as '11').
pub fn effective_nvx(hcr: u64, nv: bool, nv2: bool) -> u64 {
    if !nv || bits(hcr, u64::from(HCR_NV), 1) == 0 {
        return 0;
    }
    let nv2 = nv2 && bits(hcr, u64::from(HCR_NV2), 1) == 1;
    u64::from(nv2) << 2 | 1
}

/// [`effective_nvx`] for the PE in `c`: '000' without FEAT_NV.
pub fn hcr_nvx(c: &mut dyn Context) -> Result<u64, Effect> {
    let nv = c.implemented(Feature::FEAT_NV)?;
    let nv2 = nv && c.implemented(Feature::FEAT_NV2)?;
    Ok(effective_nvx(c.read(Register::HCR_EL2, 0), nv, nv2))
}

fn tge(c: &dyn Context) -> bool {
    bits(c.read(Register::HCR_EL2, 0), u64::from(HCR_TGE), 1) == 1
}

/// `ELIsInHost(el)`: EL2 is always in host (E2H RES1); EL0 is in host while
/// HCR_EL2.TGE is 1; EL1 never is.
pub fn is_in_host(c: &dyn Context, el: u64) -> bool {
    match el {
        2 => true,
        0 => tge(c),
        _ => false,
    }
}

/// `EffectivelyAtEL0InHost()`.
pub fn at_el0_in_host(c: &dyn Context) -> bool {
    c.el() == 0 && is_in_host(c, 0)
}

/// `EffectivelyAtEL0NotInHost()`.
pub fn at_el0_not_in_host(c: &dyn Context) -> bool {
    c.el() == 0 && !is_in_host(c, 0)
}

/// `EffectiveTGEforEL0Traps()`: HCR_EL2.TGE, EL2 being enabled.
pub fn tge_for_el0_traps(c: &dyn Context) -> u64 {
    u64::from(tge(c))
}

/// `AArch64_SystemAccessTraptoEL1orEL2(ec)`: an EL0 trap goes to EL2 when
/// HCR_EL2.TGE is 1, else to EL1.
pub fn trap_el1_or_el2(c: &dyn Context, ec: u64) -> Effect {
    Effect::Trap {
        el: if tge(c) { 2 } else { 1 },
        ec,
    }
}

/// `UnimplementedIDRegister()` with FEAT_IDST: an access to an ID register
/// encoding the profile does not implement traps with EC 0x18 to the current
/// EL, or from EL0 to EL1 or, under HCR_EL2.TGE, EL2.
pub fn unimplemented_id_register(c: &dyn Context) -> Effect {
    match c.el() {
        0 => trap_el1_or_el2(c, 0x18),
        el => Effect::Trap {
            el: el as u8,
            ec: 0x18,
        },
    }
}

/// `VMID()`: 8-bit VMIDs (no FEAT_VMID16), from VTTBR_EL2.
pub fn vmid(c: &dyn Context) -> u64 {
    bits(c.read(Register::VTTBR_EL2, 0), u64::from(VTTBR_VMID), 8)
}

/// `AArch64_TreatDCAsNOP()`. The IMPLEMENTATION DEFINED NOP choices are all
/// FALSE: cache maintenance is always performed (and trappable).
pub fn treat_dc_as_nop(c: &dyn Context, kind: CacheType, op: CacheOp, scope: CacheScope) -> bool {
    let _ = (c, kind, op, scope);
    false
}

/// `AArch64_CanTrapDC()`.
pub fn can_trap_dc(c: &dyn Context, kind: CacheType, op: CacheOp, scope: CacheScope) -> bool {
    !treat_dc_as_nop(c, kind, op, scope)
}

/// `AArch64_TreatICAsNOP()`: only with CTR_EL0.DIC set, and the choice is
/// FALSE.
pub fn treat_ic_as_nop(c: &dyn Context, kind: CacheType, op: CacheOp, scope: CacheScope) -> bool {
    let _ = (c, kind, op, scope);
    false
}

/// `AArch64_CanTrapIC()`.
pub fn can_trap_ic(c: &dyn Context, kind: CacheType, op: CacheOp, scope: CacheScope) -> bool {
    !treat_ic_as_nop(c, kind, op, scope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_virtualization_controls_take_effect_only_with_nv() {
        let (nv, nv1, nv2) = (1u64 << HCR_NV, 1u64 << 43, 1u64 << HCR_NV2);
        assert_eq!(effective_nvx(nv | nv2, false, false), 0);
        assert_eq!(effective_nvx(nv1 | nv2, true, true), 0);
        assert_eq!(effective_nvx(nv | nv1, true, true), 0b001);
        assert_eq!(effective_nvx(nv | nv2, true, true), 0b101);
        assert_eq!(effective_nvx(nv | nv2, true, false), 0b001);
    }

    #[test]
    fn bit_fields_insert_and_extend() {
        assert_eq!(bits(0xf0, 4, 4), 0xf);
        assert_eq!(bits(u64::MAX, 0, 64), u64::MAX);
        assert_eq!(insert(0, 4, 4, 0xff), 0xf0);
        assert_eq!(sign_extend(0x8000_0000, 32), 0xffff_ffff_8000_0000);
        assert_eq!(sign_extend(0x7fff_ffff, 32), 0x7fff_ffff);
    }
}
