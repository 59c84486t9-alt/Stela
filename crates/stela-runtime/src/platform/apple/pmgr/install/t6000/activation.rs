//! Original T6000's complete guarded AP activation effects.
//!
//! LLB `4b030` admits stage3/kind0 and stage10/kind1. The trailing callback
//! `3d7d4` has one indirect format2 row, mask/value1 and no callback: it is a
//! real RMW of physical292000204, not the adjacent coefficient tables. These
//! are ordered controller inputs only. No native PC, request response, PS value
//! or retirement follows because this transaction was published.
use super::super::{Error, History, Installation, Step, write};
use alloc::{rc::Rc, vec::Vec};
use stela_contracts::bus::Width;

use stela_soc_data::pmgr::t6000::PRE_ACTIVATION_BASE;

/// T6000 first-die effects only. The caller supplies stage/kind inputs
/// and exclusively owns the controller across this transaction.
/// `None` is the source's no-access branch, not controller readiness.
pub fn sequence(stage: u32, kind: u32) -> Result<Option<Installation>, Error> {
    if kind > 2 {
        return Err(Error::UnqualifiedKind(kind));
    }
    if (stage, kind) != (3, 0) && (stage, kind) != (10, 1) {
        return Ok(None);
    }
    let mut steps = Vec::new();
    if stage == 3 {
        for address in (PRE_ACTIVATION_BASE..=PRE_ACTIVATION_BASE + 12).step_by(4) {
            write(&mut steps, address, Width::Word, 1);
        }
    }
    steps.push(Step::DmbSy);
    write(&mut steps, 0x28e09906c, Width::Word, 1);
    write(&mut steps, 0x28e099074, Width::Word, 1);
    write(&mut steps, 0x292000200, Width::Word, 0x1c000000);
    steps.push(Step::DmbSy);
    steps.push(Step::Modify {
        address: 0x292000204,
        clear: 1,
        set: 1,
        latched: None,
    });
    steps.push(Step::DmbSy);
    Ok(Some(Installation {
        owner: Rc::new(()),
        ticket: 0,
        flight: None,
        blocked: None,
        suspended: false,
        steps,
        step: 0,
        placements: Vec::new(),
        history: History::default(),
        committed_reads: 0,
        committed_writes: 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec};
    use {
        crate::platform::apple::pmgr::install::Action,
        crate::platform::apple::pmgr::install::FinishError,
        crate::platform::apple::pmgr::install::Outcome,
        crate::platform::apple::pmgr::sequencer::PhysicalWrite,
        crate::platform::apple::power::t6000::Bank,
        crate::platform::apple::power::t6000::Controller,
        crate::platform::apple::power::t6000::Instance,
        crate::platform::apple::power::t6000::Observation,
        crate::platform::apple::power::t6000::native, stela_contracts::bus::Access,
        stela_contracts::bus::Bus, stela_contracts::bus::LifecycleState,
        stela_contracts::bus::MmioError, stela_contracts::interrupt::InterruptLatch,
    };

    fn owner(unknown_rmw: bool) -> Controller {
        // Explicit supplied test handoff, not native Apple reset observations.
        let controls = native::controls()
            .into_iter()
            .map(|row| native::Observation {
                address: row.address,
                value: if row.address == 0x292000204 {
                    0xa5a50000
                } else {
                    0
                },
                known: if unknown_rmw && row.address == 0x292000204 {
                    0
                } else {
                    u32::MAX
                },
            })
            .collect();
        Controller::with_native(
            vec![Instance {
                complexes: 1,
                cio_ports: 0,
                cpm_controls: 0,
                isp_clocks: 0,
            }],
            LifecycleState {
                powered: true,
                clocked: true,
                retention: true,
                quiesced: false,
                reset: false,
            },
            [Observation {
                instance: 0,
                bank: Bank::Pmgr,
                offset: 0x18000,
                value: 0,
                known: u32::MAX,
            }],
            native::Handoff::Observed {
                controls,
                sram: vec![],
            },
        )
        .unwrap()
    }
    fn mount(owner: &Controller) -> Bus {
        let mut bus = Bus::new();
        let id = bus.add(Box::new(owner.native_controls().unwrap()));
        for row in native::controls() {
            bus.map(id, row.address, 4, row.address).unwrap();
        }
        bus
    }
    fn expected(stage: u32) -> Vec<Action> {
        let store = |address, value| {
            Action::Write(PhysicalWrite {
                address,
                value,
                width: Width::Word,
            })
        };
        let mut actions = Vec::new();
        if stage == 3 {
            for address in (PRE_ACTIVATION_BASE..=PRE_ACTIVATION_BASE + 12).step_by(4) {
                actions.push(store(address, 1));
            }
        }
        actions.extend([
            Action::DmbSy,
            store(0x28e09906c, 1),
            store(0x28e099074, 1),
            store(0x292000200, 0x1c000000),
            Action::DmbSy,
            Action::Read {
                address: 0x292000204,
                width: Width::Word,
            },
            store(0x292000204, 0xa5a50001),
            Action::DmbSy,
        ]);
        actions
    }
    #[test]
    fn both_source_branches_reach_actual_controls_in_order_without_native_retirement() {
        for (stage, kind) in [(3, 0), (10, 1)] {
            let owner = owner(false);
            let mut bus = mount(&owner);
            let mut sram = owner.native_memory().unwrap();
            sram.write_checked(super::super::CODE_BASE, &[1, 2, 3, 4])
                .unwrap();
            let mut sink = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut sink);
            let mut transaction = sequence(stage, kind).unwrap().unwrap();
            let mut actual = Vec::new();
            while let Some(claim) = transaction.begin().unwrap() {
                let action = transaction.dispatch(&claim).unwrap();
                actual.push(action);
                let outcome = match action {
                    Action::Read { address, width } => {
                        Outcome::<MmioError>::Read(bus.read(address, width, &mut access).unwrap())
                    }
                    Action::Write(write) => {
                        bus.write(write.address, write.width, write.value, &mut access)
                            .unwrap();
                        Outcome::Written
                    }
                    // This single-threaded test route has no outstanding
                    // stores at a join. Production must perform its real join.
                    Action::DmbSy => Outcome::Ordered,
                };
                transaction.finish(&claim, outcome).unwrap();
            }
            assert_eq!(actual, expected(stage));
            assert!(transaction.published());
            assert_eq!(
                bus.read(0x292000204, Width::Word, &mut access),
                Ok(0xa5a50001)
            );
            assert!(owner.requests().is_empty());
            assert!(owner.captured_pending().is_empty());
            assert!(owner.native_entry(2, 0).is_err());
            assert_eq!(
                owner.native_observations().unwrap().activation_inputs.len(),
                if stage == 3 { 8 } else { 4 }
            );
            // The AP activation prefix cannot be erased by another
            // register input or used to authorize replacing installed code.
            assert!(
                sram.write_checked(super::super::CODE_BASE, &[0; 4])
                    .is_err()
            );
            bus.write(0x28e09906c, Width::Word, 0, &mut access).unwrap();
            assert!(
                sram.write_checked(super::super::CODE_BASE, &[0; 4])
                    .is_err()
            );
            let mut old = [0; 4];
            sram.read_checked(super::super::CODE_BASE, &mut old)
                .unwrap();
            assert_eq!(old, [1, 2, 3, 4]);
            assert!(sink.take_aic_inputs().is_empty());
        }
        for (stage, kind) in [(3, 1), (3, 2), (10, 0), (10, 2), (8, 0), (5, 0)] {
            assert!(sequence(stage, kind).unwrap().is_none());
        }
        assert!(matches!(sequence(3, 3), Err(Error::UnqualifiedKind(3))));
    }
    #[test]
    fn unknown_actual_rmw_and_uncertain_join_preserve_the_committed_prefix() {
        let owner = owner(true);
        let mut bus = mount(&owner);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut transaction = sequence(10, 1).unwrap().unwrap();
        let mut writes = 0;
        loop {
            let claim = transaction.begin().unwrap().unwrap();
            let action = transaction.dispatch(&claim).unwrap();
            let outcome = match action {
                Action::Read { address, width } => match bus.read(address, width, &mut access) {
                    Ok(value) => Outcome::Read(value),
                    Err(error) => Outcome::Uncertain(error),
                },
                Action::Write(write) => {
                    bus.write(write.address, write.width, write.value, &mut access)
                        .unwrap();
                    writes += 1;
                    Outcome::Written
                }
                Action::DmbSy => Outcome::Ordered,
            };
            if let Err(error) = transaction.finish(&claim, outcome) {
                assert!(matches!(error, FinishError::Uncertain(_)));
                break;
            }
        }
        assert_eq!(writes, 3);
        assert_eq!(
            owner.native_observations().unwrap().activation_inputs.len(),
            3
        );
        assert_eq!(
            bus.read(0x292000200, Width::Word, &mut access),
            Ok(0x1c000000)
        );
        assert!(!transaction.published());
        assert!(matches!(transaction.begin(), Err(Error::Blocked)));
        let mut join = sequence(3, 0).unwrap().unwrap();
        for _ in 0..4 {
            let claim = join.begin().unwrap().unwrap();
            let Action::Write(write) = join.dispatch(&claim).unwrap() else {
                panic!("source store")
            };
            bus.write(write.address, write.width, write.value, &mut access)
                .unwrap();
            join.finish(&claim, Outcome::<()>::Written).unwrap();
        }
        let claim = join.begin().unwrap().unwrap();
        assert_eq!(join.dispatch(&claim), Ok(Action::DmbSy));
        assert_eq!(
            join.finish(&claim, Outcome::Uncertain("physical join failed")),
            Err(FinishError::Uncertain("physical join failed"))
        );
        assert!(matches!(join.begin(), Err(Error::Blocked)));
        assert!(!join.published());
    }
    #[cfg(feature = "std")]
    #[test]
    #[ignore = "oracle: STELA_TEST_PMGR_M1_LLB"]
    fn original_activation_single_indirect_row_and_barriers_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb =
            std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").expect("original J314s LLB"))
                .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (lo, hi, digest) in [
            (
                0x4b030,
                0x4b104,
                "4204f61ead18e5ed7010bc8455c4840ed32b9cac14680ba42b3d3235c83a3f16",
            ),
            (
                0x4b2e0,
                0x4b2f4,
                "719c539560d4f83109bd294d819c1fbf851194ba2635ce8dba83df4c78d205d4",
            ),
            (
                0x3d7d4,
                0x3d7e0,
                "6efcf514890ab9216db7309ca2c8ccb794bee8208b9b51a1e2c6a0b193e77a63",
            ),
            (
                0x915fc,
                0x91678,
                "cd6447f6623b939eb989dfd68a3febe00303332adf679131fe941c71ea855485",
            ),
            (
                0x4b49c,
                0x4bd68,
                "9f417401d0ee6a47a6380e624ca5cd7202e3706ec736411c788a141f4ab01c11",
            ),
            (
                0x254cc,
                0x254d0,
                "fb4d08fb0da3c78aaec93f540a13930319d1ddaa9e9d29303625877867f1fb92",
            ),
            (
                0x4ac,
                0x4b4,
                "fe9882de8494aba337ae1ca5164bee6b8617022af8cd2815d0ca5c2f28811249",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        let quad = |offset: usize| u64::from_le_bytes(llb[offset..offset + 8].try_into().unwrap());
        let word = |offset: usize| u32::from_le_bytes(llb[offset..offset + 4].try_into().unwrap());
        // Decode the MOVZ/MOVK address producer. Window hashes alone
        // must not let a model/test pair repeat the same transcription error.
        let mut address = 0;
        for (offset, opcode, shift) in [
            (0x4b064, 0xd2800009, 0),
            (0x4b068, 0xf2a00009, 16),
            (0x4b06c, 0xf2c00009, 32),
        ] {
            assert_eq!(word(offset) & 0xffe0001f, opcode);
            address |= u64::from((word(offset) >> 5) & 0xffff) << shift;
        }
        assert_eq!(PRE_ACTIVATION_BASE, address);
        const LINKED: u64 = 0x1fc058000;
        assert_eq!(&llb[0x1ae7c4..0x1ae7c6], &[1, 1]); // indirect payload/row
        assert_eq!(quad(0x17ce98), LINKED + 0x17cde4);
        assert_eq!(quad(0x17cea0), 0); // complete pointer-list terminator
        assert_eq!(word(0x17cde4), 0x40000204); // width4, offset204
        assert_eq!(quad(0x17cde8), LINKED + 0x1af850);
        assert_eq!(word(0x1af850), 1); // mask
        assert_eq!(word(0x1af854), 1); // value
        assert_eq!(quad(0x1af858), 0); // no dynamic callback
        assert_eq!(quad(0x233fd0), 0x292000000); // native controller descriptor
        assert!(llb[0x233fd8..0x234000].iter().all(|byte| *byte == 0));
    }
}
