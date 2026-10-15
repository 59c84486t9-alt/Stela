//! Match existing fixed-domain QARMA helpers to this retained PE's actual IDs
//! and SCTLR/TCR bank. No key copies, alternate policy or completion authority.
use crate::{
    pauth,
    system::{identification::Register, identification_snapshot::Snapshot},
};
use stela_compiler::block::{
    PointerAuthenticationKey as Key, PointerAuthenticationOperation as Op,
};

const ID_FIELD_MASK: u64 = 0xf;
const APA_SHIFT: u32 = 4;
const API_SHIFT: u32 = 8;
const APA3_SHIFT: u32 = 12;
const APA_QARMA5_CLASSIC: u64 = 1;
const APA_QARMA5_FAULTING_COMBINED: u64 = 5;
const TCR_T0SZ_MASK: u64 = 0x3f;
const TCR_VA47_T0SZ: u64 = 17;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_TBID0: u64 = 1 << 51;
const TCR_TBID1: u64 = 1 << 52;
const SCTLR_ENIA: u64 = 1 << 31;
const SCTLR_ENIB: u64 = 1 << 30;
const SCTLR_ENDA: u64 = 1 << 27;
const SCTLR_ENDB: u64 = 1 << 13;

pub(super) fn qualify(
    ids: &Snapshot,
    sctlr_el1: u64,
    tcr_el1: u64,
    context: &pauth::Context,
    operation: Op,
) -> anyhow::Result<()> {
    let isar1 = ids.read(Register::IdAa64Isar1El1)?;
    let isar2 = ids.read(Register::IdAa64Isar2El1)?;
    let tuple = (
        (isar1 >> APA_SHIFT) & ID_FIELD_MASK,
        (isar1 >> API_SHIFT) & ID_FIELD_MASK,
        (isar2 >> APA3_SHIFT) & ID_FIELD_MASK,
    );
    let version = match tuple {
        (APA_QARMA5_CLASSIC, 0, 0) => pauth::Version::Classic,
        (APA_QARMA5_FAULTING_COMBINED, 0, 0) => pauth::Version::FaultingCombined,
        _ => anyhow::bail!("unsupported actual PAuth algorithm tuple"),
    };
    anyhow::ensure!(
        context.version() == version,
        "PAuth key algorithm differs from the actual identification owner"
    );
    anyhow::ensure!(
        tcr_el1 & TCR_T0SZ_MASK == TCR_VA47_T0SZ,
        "PAuth requires actual lower VA47 controls"
    );
    anyhow::ensure!(
        !matches!(operation, Op::GenericCode(_) | Op::Load(_)),
        "generic authentication and authenticated-load controls are unsupported"
    );
    let data = matches!(operation, Op::Strip { data: true, .. })
        || matches!(operation.required_key(), Some(Key::Da | Key::Db));
    if data {
        // Pointer admission separately requires bit55=0. Data helpers preserve
        // the tag byte, matching the lower range's actual TBI0 semantics.
        anyhow::ensure!(
            tcr_el1 & TCR_TBI0 != 0,
            "PAuth data domain requires actual TBI0"
        );
    } else {
        // InsertPAC chooses its global selector from BOTH ranges' effective
        // instruction TBI, even for an input with invalid extension bits.
        let lower_itbi = tcr_el1 & TCR_TBI0 != 0 && tcr_el1 & TCR_TBID0 == 0;
        let upper_itbi = tcr_el1 & TCR_TBI1 != 0 && tcr_el1 & TCR_TBID1 == 0;
        anyhow::ensure!(
            !lower_itbi && !upper_itbi,
            "PAuth instruction domain requires both actual instruction TBI ranges off"
        );
    }
    if let Some(key) = operation.required_key() {
        let (key, enable) = match key {
            Key::Ia => (pauth::Key::Ia, SCTLR_ENIA),
            Key::Ib => (pauth::Key::Ib, SCTLR_ENIB),
            Key::Da => (pauth::Key::Da, SCTLR_ENDA),
            Key::Db => (pauth::Key::Db, SCTLR_ENDB),
        };
        anyhow::ensure!(
            sctlr_el1 & enable != 0 && context.has_key(key),
            "PAuth disabled controls or unavailable actual key are unsupported"
        );
    }
    Ok(())
}

/// Check the actual helper operand AFTER its genuine ordinary prefix. This
/// reads the sole register bank and has no effect; it cannot qualify entry or PC.
pub(super) fn qualify_pointer(
    operation: Op,
    registers: &stela_compiler::GuestState,
) -> anyhow::Result<()> {
    const LINK_REGISTER: u8 = 30;
    const ZERO_REGISTER: u8 = 31;
    const UPPER_REGION: u64 = 1 << 55;
    const VA47_ADDRESS_MASK: u64 = (1 << 47) - 1;
    let register = match operation {
        Op::SignIbSp | Op::AuthenticateIbSp | Op::ReturnIbSp | Op::ReturnIaSp => LINK_REGISTER,
        Op::Sign { destination, .. }
        | Op::Authenticate { destination, .. }
        | Op::Strip { destination, .. } => destination,
        Op::Branch { target, .. } => target,
        Op::GenericCode(_) | Op::Load(_) => anyhow::bail!("PAuth pointer operation is unsupported"),
    };
    let pointer = if register == ZERO_REGISTER {
        0
    } else {
        *registers
            .x
            .get(usize::from(register))
            .ok_or_else(|| anyhow::anyhow!("invalid PAuth pointer register"))?
    };
    anyhow::ensure!(
        pointer & UPPER_REGION == 0,
        "upper-region PAuth inputs are unsupported"
    );
    if matches!(operation, Op::SignIbSp | Op::Sign { .. }) {
        anyhow::ensure!(
            pointer & !VA47_ADDRESS_MASK == 0,
            "noncanonical lower signing input is unsupported"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
