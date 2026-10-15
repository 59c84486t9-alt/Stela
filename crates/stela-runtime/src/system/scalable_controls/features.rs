//! Exact June ID-field interpretation. Values remain in the borrowed Snapshot.
use super::{Error, Snapshot};
use crate::system::identification::Register;
use stela_compiler::aarch64::scalable::features::{ScalableFeature as F, ScalableFeatures};

const FIELD_MASK: u64 = 0xf;

pub(super) fn field(ids: &Snapshot, register: Register, shift: u32) -> Result<u8, Error> {
    Ok(((ids.read(register).map_err(Error::Identification)? >> shift) & FIELD_MASK) as u8)
}

fn level(
    ids: &Snapshot,
    register: Register,
    name: &'static str,
    shift: u32,
    valid: &[u8],
) -> Result<u8, Error> {
    let value = field(ids, register, shift)?;
    if valid.contains(&value) {
        Ok(value)
    } else {
        Err(Error::IdField {
            register,
            name,
            value,
        })
    }
}

pub(super) fn sme(ids: &Snapshot) -> Result<u8, Error> {
    level(ids, Register::IdAa64Pfr1El1, "SME", 24, &[0, 1, 2])
}
pub(super) fn sve(ids: &Snapshot) -> Result<bool, Error> {
    Ok(level(ids, Register::IdAa64Pfr0El1, "SVE", 32, &[0, 1])? == 1)
}

/// This subset excludes optional CPACR consumers without an actual owner.
/// Their RES0 storage choice is explicit and does not infer write-ignore.
pub(super) fn check_control_subset(ids: &Snapshot) -> Result<(), Error> {
    ids.check_el10_regime().map_err(Error::Identification)?;
    let fp = level(ids, Register::IdAa64Pfr0El1, "FP", 16, &[0, 1, 15])?;
    let simd = level(ids, Register::IdAa64Pfr0El1, "AdvSIMD", 20, &[0, 1, 15])?;
    if fp != simd {
        return Err(Error::IncoherentIdentification("FP/AdvSIMD"));
    }
    if fp == 15 {
        return Err(Error::UnsupportedControlConsumer("absent FP/AdvSIMD"));
    }
    for (register, name, shift, valid) in [
        (Register::IdAa64Dfr0El1, "TraceVer", 4, &[0, 1][..]),
        (Register::IdAa64Mmfr3El1, "S1POE", 16, &[0, 1][..]),
        (Register::IdAa64Mmfr4El1, "SRMASK", 44, &[0, 1, 2][..]),
    ] {
        if level(ids, register, name, shift, valid)? != 0 {
            return Err(Error::UnsupportedControlConsumer(name));
        }
    }
    let nv = level(ids, Register::IdAa64Mmfr4El1, "NV_frac", 20, &[0, 1, 2, 3])?;
    if nv >= 2 {
        return Err(Error::UnsupportedControlConsumer("NV2p1"));
    }
    Ok(())
}

pub(super) fn derive(ids: &Snapshot) -> Result<ScalableFeatures, Error> {
    let mut result = ScalableFeatures::empty();
    let sme = sme(ids)? != 0;
    let sve = sve(ids)?;
    if sme {
        result = result.with(F::Sme);
        let smfr = ids
            .read(Register::IdAa64Smfr0El1)
            .map_err(Error::Identification)?;
        let version = level(
            ids,
            Register::IdAa64Smfr0El1,
            "SMEver",
            56,
            &[0, 1, 2, 3, 4],
        )?;
        if version >= 1 {
            result = result.with(F::Sme2);
        }
        if version >= 2 {
            result = result.with(F::Sme2p1);
        }
        for (bit, feature) in [
            (63, F::SmeFa64),
            (48, F::SmeF64F64),
            (43, F::SmeB16B16),
            (42, F::SmeF16F16),
            (41, F::SmeF8F16),
        ] {
            if smfr & (1u64 << bit) != 0 {
                result = result.with(feature);
            }
        }
        if level(ids, Register::IdAa64Smfr0El1, "I16I64", 52, &[0, 15])? == 15 {
            result = result.with(F::SmeI16I64);
        }
    }
    if sme || sve {
        if level(ids, Register::IdAa64Zfr0El1, "B16B16", 24, &[0, 1, 2, 3])? != 0 {
            result = result.with(F::SveB16B16);
        }
        let bf = level(ids, Register::IdAa64Zfr0El1, "BF16", 20, &[0, 1, 2])?;
        if bf != level(ids, Register::IdAa64Isar1El1, "BF16", 44, &[0, 1, 2])? {
            return Err(Error::IncoherentIdentification("BF16"));
        }
        if bf != 0 {
            result = result.with(F::Bf16);
        }
        let i8 = level(ids, Register::IdAa64Zfr0El1, "I8MM", 44, &[0, 1])?;
        let simd = level(ids, Register::IdAa64Pfr0El1, "AdvSIMD", 20, &[0, 1, 15])? != 15;
        if sve && simd && i8 != level(ids, Register::IdAa64Isar1El1, "I8MM", 52, &[0, 1])? {
            return Err(Error::IncoherentIdentification("I8MM"));
        }
        if i8 != 0 {
            result = result.with(F::I8mm);
        }
    }
    if level(ids, Register::IdAa64Isar3El1, "FAMINMAX", 4, &[0, 1])? == 1 {
        result = result.with(F::FaMinMax);
    }
    Ok(result)
}
