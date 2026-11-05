//! Actual LVT/readback controls for the independent RAM bank.
use super::*;
#[test]
fn every_spurious_lvt_collision_refuses_before_mask_or_svr_write() {
    for n in 0..=6 {
        for masked in [0, 1 << 16] {
            let b = bank(Mode::Xapic, false);
            let value = masked | 255;
            b.borrow_mut().words[slot(Register::Lvt(n))] = value;
            let f = match Startup::new(Model(b.clone())).configure() {
                Err(f) => f,
                Ok(_) => panic!("LVT collision"),
            };
            assert_eq!(
                f.error.cause,
                Cause::SpuriousCollision {
                    lvt: n,
                    observed: value
                }
            );
            assert_eq!(f.effect(), Effect::NotWritten);
            assert!(b.borrow().operations.is_empty());
            assert_eq!(b.borrow().words[slot(Register::Svr)], (1 << 12) | 0x23);
        }
    }
}
#[test]
fn real_readback_mismatch_retains_exact_register_value_and_mask() {
    let b = bank(Mode::Xapic, false);
    b.borrow_mut().corrupt_value = true;
    let f = match Startup::new(Model(b.clone())).configure() {
        Err(f) => f,
        Ok(_) => panic!("mismatch"),
    };
    let expected = (1 << 17) | (1 << 16) | 0x75;
    assert_eq!(
        f.error.cause,
        Cause::Readback {
            register: Register::Lvt(0),
            expected,
            observed: expected ^ 1,
            mask: !0x1000,
        }
    );
    assert_eq!(f.failure(), FaultState::Ready(f.error));
    assert_eq!(b.borrow().operations.len(), 1);
}
