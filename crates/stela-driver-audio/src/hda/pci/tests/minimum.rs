//! Actual minimum denial never permits preparation cleanup or enable writes.
use super::*;
struct RefusingMinimum {
    nominal: Clock,
    late: bool,
    waits: Cell<usize>,
}
impl crate::bus::i2c::Timer for RefusingMinimum {
    fn now_us(&self) -> u64 {
        self.nominal.now_us()
    }
    fn relax(&self) {
        self.nominal.relax();
    }
}
// SAFETY: diagnostic provider refuses every minimum wait; no hardware grant.
unsafe impl crate::bus::pci::power::Timer for RefusingMinimum {
    fn check(&self) -> Result<(), crate::bus::pci::power::Error> {
        if self.late {
            Ok(())
        } else {
            Err(crate::bus::pci::power::Error::Clock)
        }
    }
    fn wait_us(&self, _: u64) -> Result<(), crate::bus::pci::power::Error> {
        self.waits.set(self.waits.get() + 1);
        Err(crate::bus::pci::power::Error::Clock)
    }
}
#[test]
fn standalone_pci_minimum_refusal_keeps_the_exact_effect_prefix_and_cause() {
    for late in [false, true] {
        let (mut function, nominal, bar) = fixture(3);
        let timer = RefusingMinimum {
            nominal,
            late,
            waits: Cell::new(0),
        };
        let original = function.config().words;
        // SAFETY: same isolated original config owner; no physical authority.
        let error =
            unsafe { prepare(&mut function, bar, &timer, Ownership::ExclusiveLegacy) }.unwrap_err();
        assert_eq!(
            error,
            AttachError::MinimumDelay(crate::bus::pci::power::Error::Clock)
        );
        let owner = function.config();
        if late {
            assert_eq!(timer.waits.get(), 1);
            assert_eq!(
                owner.writes.len(),
                2,
                "cleanup or enable followed failed D0 minimum"
            );
            assert_eq!((owner.writes[0].0, owner.writes[0].1), (4, 2));
            assert_eq!((owner.writes[1].0, owner.writes[1].1), (0x54, 2));
            assert_eq!(owner.get16(4) & 6, 0);
            assert_eq!(
                owner.get16(0x54) & 3,
                0,
                "actual D0 write was silently rolled back"
            );
        } else {
            assert_eq!(timer.waits.get(), 0);
            assert!(owner.writes.is_empty());
            assert_eq!(owner.words, original);
        }
    }
}
