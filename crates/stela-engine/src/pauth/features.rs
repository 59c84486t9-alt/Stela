//! Instruction PAuth features, read from the PE's identification registers.

use crate::system::{identification::Register, identification_snapshot::Snapshot};

const ID_FIELD_MASK: u64 = 0xf;
const ISAR1_APA_SHIFT: u32 = 4;
const ISAR1_API_SHIFT: u32 = 8;
const ISAR2_APA3_SHIFT: u32 = 12;
const ISAR3_PACM_SHIFT: u32 = 12;
const PACM_FULL_IMPLEMENTATION: u64 = 2;
const APA_QARMA5_PAUTH_LR: u64 = 6;
const AUTHENTICATION_ALGORITHM_ABSENT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedInstructionProfile {
    MissingId(Register),
    Qarma5Version(u8),
    ImplementationDefinedAlgorithm(u8),
    Qarma3Algorithm(u8),
    PacmImplementation(u8),
}

/// Exact QARMA5 PAuth_LR feature fact borrowed from the same CPU snapshot.
/// This capability does not authorize controls, PACM, source, BTI or GCS effects.
pub(crate) struct LinkRegisterPauthCapability<'profile> {
    _source: &'profile Snapshot,
}

impl<'profile> LinkRegisterPauthCapability<'profile> {
    pub(crate) fn from_profile(
        source: &'profile Snapshot,
    ) -> Result<Self, UnsupportedInstructionProfile> {
        check_snapshot(source, APA_QARMA5_PAUTH_LR)?;
        let isar3 = source
            .read(Register::IdAa64Isar3El1)
            .map_err(|_| UnsupportedInstructionProfile::MissingId(Register::IdAa64Isar3El1))?;
        let pacm = (isar3 >> ISAR3_PACM_SHIFT) & ID_FIELD_MASK;
        if pacm != PACM_FULL_IMPLEMENTATION {
            return Err(UnsupportedInstructionProfile::PacmImplementation(
                pacm as u8,
            ));
        }
        Ok(Self { _source: source })
    }
}

fn check_snapshot(
    source: &Snapshot,
    expected_apa: u64,
) -> Result<(), UnsupportedInstructionProfile> {
    check_ids_for(
        source
            .read(Register::IdAa64Isar1El1)
            .map_err(|_| UnsupportedInstructionProfile::MissingId(Register::IdAa64Isar1El1))?,
        source
            .read(Register::IdAa64Isar2El1)
            .map_err(|_| UnsupportedInstructionProfile::MissingId(Register::IdAa64Isar2El1))?,
        expected_apa,
    )
}

fn check_ids_for(
    isar1: u64,
    isar2: u64,
    expected_apa: u64,
) -> Result<(), UnsupportedInstructionProfile> {
    let api = (isar1 >> ISAR1_API_SHIFT) & ID_FIELD_MASK;
    if api != AUTHENTICATION_ALGORITHM_ABSENT {
        return Err(UnsupportedInstructionProfile::ImplementationDefinedAlgorithm(api as u8));
    }
    let apa3 = (isar2 >> ISAR2_APA3_SHIFT) & ID_FIELD_MASK;
    if apa3 != AUTHENTICATION_ALGORITHM_ABSENT {
        return Err(UnsupportedInstructionProfile::Qarma3Algorithm(apa3 as u8));
    }
    let apa = (isar1 >> ISAR1_APA_SHIFT) & ID_FIELD_MASK;
    if apa != expected_apa {
        return Err(UnsupportedInstructionProfile::Qarma5Version(apa as u8));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_lr_tuple_rejects_other_algorithm_versions() {
        for apa in 0..=ID_FIELD_MASK {
            for api in 0..=ID_FIELD_MASK {
                for apa3 in 0..=ID_FIELD_MASK {
                    let isar1 = (apa << ISAR1_APA_SHIFT) | (api << ISAR1_API_SHIFT);
                    let isar2 = apa3 << ISAR2_APA3_SHIFT;
                    assert_eq!(
                        check_ids_for(isar1, isar2, APA_QARMA5_PAUTH_LR).is_ok(),
                        apa == APA_QARMA5_PAUTH_LR
                            && api == AUTHENTICATION_ALGORITHM_ABSENT
                            && apa3 == AUTHENTICATION_ALGORITHM_ABSENT
                    );
                }
            }
        }
    }

    #[test]
    fn lr_capability_keeps_exact_shared_snapshot_and_named_missing_ids_decline() {
        let values = [
            (
                Register::IdAa64Isar1El1,
                APA_QARMA5_PAUTH_LR << ISAR1_APA_SHIFT,
            ),
            (Register::IdAa64Isar2El1, 0),
            (
                Register::IdAa64Isar3El1,
                PACM_FULL_IMPLEMENTATION << ISAR3_PACM_SHIFT,
            ),
        ];
        for missing in [
            Register::IdAa64Isar1El1,
            Register::IdAa64Isar2El1,
            Register::IdAa64Isar3El1,
        ] {
            let present: Vec<_> = values
                .into_iter()
                .filter(|(register, _)| *register != missing)
                .collect();
            let source = Snapshot::declared("lr-capability-missing-id", &present).unwrap();
            assert!(matches!(
                LinkRegisterPauthCapability::from_profile(&source),
                Err(UnsupportedInstructionProfile::MissingId(register)) if register == missing
            ));
        }
        let source = Snapshot::declared("lr-capability-declared-profile", &values).unwrap();
        let capability = LinkRegisterPauthCapability::from_profile(&source).unwrap();
        assert!(std::ptr::eq(capability._source, &source));
    }

    #[test]
    fn qarma5_lr_requires_full_pacm_and_rejects_absent_trivial_reserved_values() {
        for pacm in 0..=ID_FIELD_MASK {
            let source = Snapshot::declared(
                "lr-capability-pacm-coherence",
                &[
                    (
                        Register::IdAa64Isar1El1,
                        APA_QARMA5_PAUTH_LR << ISAR1_APA_SHIFT,
                    ),
                    (Register::IdAa64Isar2El1, 0),
                    (Register::IdAa64Isar3El1, pacm << ISAR3_PACM_SHIFT),
                ],
            )
            .unwrap();
            let result = LinkRegisterPauthCapability::from_profile(&source);
            if pacm == PACM_FULL_IMPLEMENTATION {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(UnsupportedInstructionProfile::PacmImplementation(value))
                        if value == pacm as u8
                ));
            }
        }
    }
}
