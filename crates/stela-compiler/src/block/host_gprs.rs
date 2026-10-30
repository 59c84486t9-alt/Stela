//! Normalized host integer-register capture and recovery availability.

/// Host registers in architectural encoding order after platform capture.
/// The extended bank exists only when the platform captured or checked its
/// architectural initialization state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostGprSnapshot {
    legacy: [u64; 16],
    extended: Option<[u64; 16]>,
}
impl HostGprSnapshot {
    pub const fn legacy(registers: [u64; 16]) -> Self {
        Self {
            legacy: registers,
            extended: None,
        }
    }
    pub const fn complete(registers: [u64; 32]) -> Self {
        let mut legacy = [0; 16];
        let mut extended = [0; 16];
        let mut i = 0;
        while i < 16 {
            legacy[i] = registers[i];
            extended[i] = registers[i + 16];
            i += 1;
        }
        Self {
            legacy,
            extended: Some(extended),
        }
    }
    pub const fn extended_available(&self) -> bool {
        self.extended.is_some()
    }
    pub const fn get(&self, register: u8) -> Option<u64> {
        match register {
            0..=15 => Some(self.legacy[register as usize]),
            16..=31 => match &self.extended {
                Some(bank) => Some(bank[(register - 16) as usize]),
                None => None,
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GuestAddress, GuestState,
        block::{
            FaultRecovery, FaultRecoveryError, HostFaultSnapshot, HostSpillSnapshot,
            RecoveryBinding, RecoverySettlement, RetirementPoint,
        },
    };
    use alloc::vec;

    fn apply_recovery(
        table: &[FaultRecovery],
        offset: usize,
        gprs: &HostGprSnapshot,
        state: &mut crate::GuestState,
    ) -> Result<Option<RecoverySettlement>, FaultRecoveryError> {
        FaultRecovery::apply(
            table,
            offset,
            HostFaultSnapshot {
                gprs,
                spills: &HostSpillSnapshot::new(),
            },
            state,
        )
    }
    #[test]
    fn legacy_capture_does_not_supply_an_extended_bank() {
        let snapshot = HostGprSnapshot::legacy(core::array::from_fn(|i| i as u64 + 10));
        assert!(!snapshot.extended_available());
        assert_eq!(snapshot.get(15), Some(25));
        assert_eq!(snapshot.get(16), None);
        assert_eq!(snapshot.get(31), None);
        assert_eq!(snapshot.get(32), None);
    }

    #[test]
    fn complete_capture_keeps_every_architectural_encoding() {
        let values = core::array::from_fn(|i| 0x123456789abcdef0u64.wrapping_add(i as u64));
        let snapshot = HostGprSnapshot::complete(values);
        assert!(snapshot.extended_available());
        for (i, value) in values.into_iter().enumerate() {
            assert_eq!(snapshot.get(i as u8), Some(value));
        }
    }

    #[test]
    fn unavailable_extended_recovery_cannot_partially_write_guest_state() {
        let snapshot = HostGprSnapshot::legacy([55; 16]);
        let mut state = GuestState::default();
        state.x[0] = 7;
        state.x[1] = 8;
        let before = state.clone();
        let table = [FaultRecovery {
            site: crate::block::RecoverySite::native_internal(),
            start: 2,
            end: 8,
            retirement: RetirementPoint::before(GuestAddress(0x1000), 0).unwrap(),
            bindings: vec![(0, 0), (1, 16)]
                .into_iter()
                .map(|(guest, host)| RecoveryBinding::gpr(guest, host))
                .collect(),
        }];
        assert_eq!(
            apply_recovery(&table, 3, &snapshot, &mut state),
            Err(FaultRecoveryError::ExtendedStateUnavailable { register: 16 })
        );
        assert_eq!(state.x, before.x);
        assert_eq!(state.sp, before.sp);
        assert_eq!(state.nzcv, before.nzcv);
        assert!(apply_recovery(&table, 9, &snapshot, &mut state).is_ok());
    }

    #[test]
    fn complete_recovery_settles_high_registers_and_guest_sp() {
        let snapshot = HostGprSnapshot::complete(core::array::from_fn(|i| 100 + i as u64));
        let mut state = GuestState::default();
        let table = [FaultRecovery {
            site: crate::block::RecoverySite::native_internal(),
            start: 2,
            end: 8,
            retirement: RetirementPoint::before(GuestAddress(0x1000), 0).unwrap(),
            bindings: vec![(0, 16), (30, 31), (31, 4)]
                .into_iter()
                .map(|(guest, host)| RecoveryBinding::gpr(guest, host))
                .collect(),
        }];
        apply_recovery(&table, 3, &snapshot, &mut state).unwrap();
        assert_eq!((state.x[0], state.x[30], state.sp), (116, 131, 104));
    }

    #[test]
    fn invalid_metadata_is_rejected_before_any_guest_write() {
        let snapshot = HostGprSnapshot::complete([55; 32]);
        for (binding, expected) in [
            (
                (32, 1),
                FaultRecoveryError::InvalidGuestRegister { register: 32 },
            ),
            (
                (1, 32),
                FaultRecoveryError::InvalidHostRegister { register: 32 },
            ),
        ] {
            let table = [FaultRecovery {
                site: crate::block::RecoverySite::native_internal(),
                start: 0,
                end: 1,
                retirement: RetirementPoint::before(GuestAddress(0x1000), 0).unwrap(),
                bindings: vec![(0, 0), binding]
                    .into_iter()
                    .map(|(guest, host)| RecoveryBinding::gpr(guest, host))
                    .collect(),
            }];
            let mut state = GuestState::default();
            state.x[0] = 7;
            assert_eq!(
                apply_recovery(&table, 0, &snapshot, &mut state),
                Err(expected)
            );
            assert_eq!(state.x[0], 7);
        }
    }
}
