//! Explicit oscillator epoch configuration without a running clock owner.
/// An explicitly created Stela PMIC oscillator at a system-counter
/// value. This is resource configuration, not an Apple reset observation or an
/// execution/completion receipt. The rate has no implicit default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PmicEpoch {
    pub counter: u64,
    pub cycles: u64,
    pub hz: u64,
}
impl PmicEpoch {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.hz == 0 {
            return Err("native PMIC oscillator requires a nonzero explicit rate");
        }
        Ok(())
    }
}
