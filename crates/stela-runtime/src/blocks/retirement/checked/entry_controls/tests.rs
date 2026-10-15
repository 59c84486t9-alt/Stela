use super::*;
use crate::system::{identification::Register, state::El1Registers};
const A64_EL0_EL1: u64 = 0x11;
const APA_SHIFT: u32 = 4;
const APA_LR: u64 = 6;
const PACM_FULL: u64 = 2 << 12;

fn snapshot() -> Arc<Snapshot> {
    Arc::new(
        Snapshot::declared(
            "actual-lr-entry-tests",
            &[
                (Register::IdAa64Isar1El1, APA_LR << APA_SHIFT),
                (Register::IdAa64Isar2El1, 0),
                (Register::IdAa64Isar3El1, PACM_FULL),
                (Register::IdAa64Pfr0El1, A64_EL0_EL1),
                (Register::IdAa64Pfr1El1, 0),
                (Register::IdAa64Pfr2El1, 0),
                (Register::IdAa64Dfr0El1, 0),
                (Register::IdAa64Dfr1El1, 0),
                (Register::IdAa64Mmfr0El1, 0),
                (Register::IdAa64Mmfr1El1, 0),
                (Register::IdAa64Mmfr2El1, 0),
                (Register::IdAa64Mmfr3El1, 0),
            ],
        )
        .unwrap(),
    )
}
fn controls(ids: &Arc<Snapshot>) -> ProcessEntryControls {
    // SAFETY: fresh local declared controls; no entry permission or live PE adoption.
    unsafe {
        ProcessEntryControls::fresh_software_link_register_pauth(
            ids,
            ids.base_spe_absence().unwrap(),
            0,
            DebugControls::default(),
        )
    }
    .unwrap()
}
fn system(feature: PacmStateFeature) -> SystemState {
    SystemState::new_with_pacm(0, 0, El1Registers::new(0, 0, 0, 0, 0), feature).unwrap()
}

#[test]
fn lr_scope_requires_original_snapshot_allocation_and_full_storage() {
    let ids = snapshot();
    let owner = controls(&ids);
    assert!(
        owner
            .check_snapshot(Some(&ids), &system(PacmStateFeature::Full))
            .is_ok()
    );
    assert!(
        owner
            .check_snapshot(Some(&snapshot()), &system(PacmStateFeature::Full))
            .is_err()
    );
    assert!(
        owner
            .check_snapshot(None, &system(PacmStateFeature::Full))
            .is_err()
    );
    assert!(
        owner
            .check_snapshot(Some(&ids), &system(PacmStateFeature::Absent))
            .is_err()
    );
}

#[test]
fn lr_scope_does_not_manufacture_lr_absent_entry_profile() {
    let ids = snapshot();
    assert!(ids.non_pauth_entry_absence().is_ok());
    assert!(ids.entry_profile().is_err());
    assert!(controls(&ids).link_register());
}

#[test]
fn fresh_lr_scope_rejects_actual_halted_or_step_controls() {
    let ids = snapshot();
    for (mdscr, debug) in [
        (MDSCR_SOFTWARE_STEP, DebugControls::default()),
        (
            0,
            DebugControls {
                halted: true,
                ..DebugControls::default()
            },
        ),
    ] {
        // SAFETY: fresh local declared controls; constructor must decline this profile.
        assert!(
            unsafe {
                ProcessEntryControls::fresh_software_link_register_pauth(
                    &ids,
                    ids.base_spe_absence().unwrap(),
                    mdscr,
                    debug,
                )
            }
            .is_err()
        );
    }
}
