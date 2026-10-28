//! Selecting the PAC algorithm parameters from the PE's ID registers and
//! SCTLR/TCR.
use crate::{
    pauth,
    system::{
        identification::Register,
        identification_snapshot::Snapshot,
        process_memory::{SCTLR_ENDA, SCTLR_ENDB, SCTLR_ENIA, SCTLR_ENIB},
    },
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
        _ => {
            pauth::features::LinkRegisterPauthCapability::from_profile(ids)
                .map_err(|error| anyhow::anyhow!("LR tuple: {error:?}"))?;
            pauth::Version::FaultingCombined
        }
    };
    anyhow::ensure!(
        context.version() == version,
        "PAuth key algorithm differs from the identification owner"
    );
    anyhow::ensure!(
        tcr_el1 & TCR_T0SZ_MASK == TCR_VA47_T0SZ,
        "PAuth requires lower VA47 controls"
    );
    anyhow::ensure!(
        !matches!(operation, Op::GenericCode(_) | Op::Load(_)),
        "generic authentication and authenticated-load controls are unsupported"
    );
    let data = matches!(operation, Op::Strip { data: true, .. })
        || matches!(operation.required_key(), Some(Key::Da | Key::Db));
    if data {
        // Pointer admission separately requires bit 55 clear. Data helpers keep
        // the tag byte, matching TBI0 for the lower range.
        anyhow::ensure!(tcr_el1 & TCR_TBI0 != 0, "PAuth data domain requires TBI0");
    } else {
        // InsertPAC chooses its global selector from BOTH ranges' effective
        // instruction TBI, even for an input with invalid extension bits.
        let lower_itbi = tcr_el1 & TCR_TBI0 != 0 && tcr_el1 & TCR_TBID0 == 0;
        let upper_itbi = tcr_el1 & TCR_TBI1 != 0 && tcr_el1 & TCR_TBID1 == 0;
        anyhow::ensure!(
            !lower_itbi && !upper_itbi,
            "PAuth instruction domain requires both instruction TBI ranges off"
        );
    }
    if let Some(key) = operation.required_key() {
        let (key, enable) = match key {
            Key::Ia => (stela_contracts::pauth::Key::Ia, SCTLR_ENIA),
            Key::Ib => (stela_contracts::pauth::Key::Ib, SCTLR_ENIB),
            Key::Da => (stela_contracts::pauth::Key::Da, SCTLR_ENDA),
            Key::Db => (stela_contracts::pauth::Key::Db, SCTLR_ENDB),
        };
        anyhow::ensure!(
            sctlr_el1 & enable != 0 && context.has_key(key),
            "PAuth disabled controls or unavailable key are unsupported"
        );
    }
    Ok(())
}

/// Check the helper's operand after the ordinary prefix has run. Reads the
/// register bank only.
pub(super) fn qualify_pointer(
    operation: Op,
    registers: &stela_compiler::GuestState,
) -> anyhow::Result<()> {
    const LINK_REGISTER: u8 = 30;
    const HINT_POINTER_REGISTER: u8 = 17;
    const ZERO_REGISTER: u8 = 31;
    const UPPER_REGION: u64 = 1 << 55;
    const VA47_ADDRESS_MASK: u64 = (1 << 47) - 1;
    let register = match operation {
        Op::SignIbSp | Op::AuthenticateIbSp | Op::ReturnIbSp | Op::ReturnIaSp => LINK_REGISTER,
        Op::Sign1716 { .. } | Op::Authenticate1716 { .. } => HINT_POINTER_REGISTER,
        Op::LinkRegister(_) => anyhow::bail!("LR operands require borrowed control service"),
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
    if matches!(
        operation,
        Op::SignIbSp | Op::Sign1716 { .. } | Op::Sign { .. }
    ) {
        anyhow::ensure!(
            pointer & !VA47_ADDRESS_MASK == 0,
            "noncanonical lower signing input is unsupported"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use stela_compiler::block::PointerAuthenticationModifier as Modifier;

    const ADDRESS_SPACE: u64 = 1;
    const ENABLE_ALL_KEYS: u64 = SCTLR_ENIA | SCTLR_ENIB | SCTLR_ENDA | SCTLR_ENDB;
    const TAGGED_DATA_UNTAGGED_INSTRUCTIONS: u64 =
        TCR_VA47_T0SZ | TCR_TBI0 | TCR_TBI1 | TCR_TBID0 | TCR_TBID1;
    const TEST_KEYS: [u64; 2] = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];

    fn ids(apa: u64, api: u64, apa3: u64) -> Snapshot {
        Snapshot::declared(
            "retained-pauth-policy-software-test",
            &[
                (
                    Register::IdAa64Isar1El1,
                    (apa << APA_SHIFT) | (api << API_SHIFT),
                ),
                (Register::IdAa64Isar2El1, apa3 << APA3_SHIFT),
            ],
        )
        .unwrap()
    }
    fn context(version: pauth::Version) -> pauth::Context {
        pauth::Context::new_with_version(
            ADDRESS_SPACE,
            pauth::Keys::from_words(TEST_KEYS, TEST_KEYS, TEST_KEYS, TEST_KEYS),
            version,
        )
    }
    fn sign(key: Key) -> Op {
        Op::Sign {
            key,
            destination: 0,
            modifier: Modifier::Zero,
        }
    }

    #[test]
    fn algorithm_tuple_and_actual_key_version_must_match() {
        for (apa, version) in [
            (APA_QARMA5_CLASSIC, pauth::Version::Classic),
            (
                APA_QARMA5_FAULTING_COMBINED,
                pauth::Version::FaultingCombined,
            ),
        ] {
            let context = context(version);
            assert!(
                qualify(
                    &ids(apa, 0, 0),
                    ENABLE_ALL_KEYS,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &context,
                    Op::SignIbSp
                )
                .is_ok()
            );
            for other_apa in 0..=ID_FIELD_MASK {
                assert_eq!(
                    qualify(
                        &ids(other_apa, 0, 0),
                        ENABLE_ALL_KEYS,
                        TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                        &context,
                        Op::SignIbSp
                    )
                    .is_ok(),
                    other_apa == apa
                );
            }
            assert!(
                qualify(
                    &ids(apa, 1, 0),
                    ENABLE_ALL_KEYS,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &context,
                    Op::SignIbSp
                )
                .is_err()
            );
            assert!(
                qualify(
                    &ids(apa, 0, 1),
                    ENABLE_ALL_KEYS,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &context,
                    Op::SignIbSp
                )
                .is_err()
            );
        }
        let missing = Snapshot::declared(
            "missing-PAuth-ID",
            &[(Register::IdAa64Isar1El1, APA_QARMA5_CLASSIC << APA_SHIFT)],
        )
        .unwrap();
        assert!(
            qualify(
                &missing,
                ENABLE_ALL_KEYS,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &context(pauth::Version::Classic),
                Op::SignIbSp
            )
            .is_err()
        );
    }

    #[test]
    fn instruction_global_tbi_and_data_lower_tbi_are_distinct() {
        let ids = ids(APA_QARMA5_CLASSIC, 0, 0);
        let context = context(pauth::Version::Classic);
        for bits in 0..16 {
            let tbi0 = bits & 1 != 0;
            let tbi1 = bits & 2 != 0;
            let tbid0 = bits & 4 != 0;
            let tbid1 = bits & 8 != 0;
            let tcr = TCR_VA47_T0SZ
                | if tbi0 { TCR_TBI0 } else { 0 }
                | if tbi1 { TCR_TBI1 } else { 0 }
                | if tbid0 { TCR_TBID0 } else { 0 }
                | if tbid1 { TCR_TBID1 } else { 0 };
            for operation in [
                sign(Key::Ia),
                Op::Strip {
                    data: false,
                    destination: 0,
                },
            ] {
                assert_eq!(
                    qualify(&ids, ENABLE_ALL_KEYS, tcr, &context, operation).is_ok(),
                    (!tbi0 || tbid0) && (!tbi1 || tbid1)
                );
            }
            for operation in [
                sign(Key::Da),
                Op::Strip {
                    data: true,
                    destination: 0,
                },
            ] {
                assert_eq!(
                    qualify(&ids, ENABLE_ALL_KEYS, tcr, &context, operation).is_ok(),
                    tbi0
                );
            }
        }
        for t0sz in 0..=TCR_T0SZ_MASK {
            assert_eq!(
                qualify(&ids, ENABLE_ALL_KEYS, t0sz, &context, Op::SignIbSp).is_ok(),
                t0sz == TCR_VA47_T0SZ
            );
        }
    }

    #[test]
    fn actual_enable_and_key_presence_are_required_while_strip_is_keyless() {
        let ids = ids(APA_QARMA5_CLASSIC, 0, 0);
        let context = context(pauth::Version::Classic);
        for (key, enable) in [
            (Key::Ia, SCTLR_ENIA),
            (Key::Ib, SCTLR_ENIB),
            (Key::Da, SCTLR_ENDA),
            (Key::Db, SCTLR_ENDB),
        ] {
            assert!(
                qualify(
                    &ids,
                    ENABLE_ALL_KEYS,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &context,
                    sign(key)
                )
                .is_ok()
            );
            assert!(
                qualify(
                    &ids,
                    ENABLE_ALL_KEYS & !enable,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &context,
                    sign(key)
                )
                .is_err()
            );
        }
        let ib_only = pauth::Context::new(
            ADDRESS_SPACE,
            pauth::Keys::from_ib_words(TEST_KEYS[0], TEST_KEYS[1]),
        );
        assert!(
            qualify(
                &ids,
                ENABLE_ALL_KEYS,
                TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                &ib_only,
                sign(Key::Da)
            )
            .is_err()
        );
        for data in [false, true] {
            assert!(
                qualify(
                    &ids,
                    0,
                    TAGGED_DATA_UNTAGGED_INSTRUCTIONS,
                    &ib_only,
                    Op::Strip {
                        data,
                        destination: 0
                    }
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn actual_pointer_admission_is_read_only_and_keeps_signing_conservative() {
        const LOWER_VA47: u64 = (1 << 47) - 1;
        const TOP_BYTE_TAG: u64 = 0xa5 << 56;
        const UPPER_REGION: u64 = 1 << 55;
        let mut actual = stela_compiler::GuestState::default();
        for pointer in [0, LOWER_VA47, 1 << 47, TOP_BYTE_TAG | 0x1234, UPPER_REGION] {
            actual.x[0] = pointer;
            actual.x[30] = pointer;
            let before = actual.clone();
            for operation in [sign(Key::Ia), sign(Key::Da), Op::SignIbSp] {
                assert_eq!(
                    qualify_pointer(operation, &actual).is_ok(),
                    pointer <= LOWER_VA47
                );
            }
            for operation in [
                Op::Strip {
                    data: true,
                    destination: 0,
                },
                Op::Authenticate {
                    key: Key::Da,
                    destination: 0,
                    modifier: Modifier::Zero,
                },
                Op::ReturnIbSp,
            ] {
                assert_eq!(
                    qualify_pointer(operation, &actual).is_ok(),
                    pointer & UPPER_REGION == 0
                );
            }
            assert_eq!(actual, before);
        }
        actual.x[0] = u64::MAX;
        assert!(
            qualify_pointer(
                Op::Sign {
                    key: Key::Ia,
                    destination: 31,
                    modifier: Modifier::Zero
                },
                &actual
            )
            .is_ok()
        );
        assert!(
            qualify_pointer(
                Op::Strip {
                    data: false,
                    destination: 32
                },
                &actual
            )
            .is_err()
        );
    }
}
