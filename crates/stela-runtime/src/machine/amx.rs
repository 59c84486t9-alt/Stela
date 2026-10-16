//! The Apple AMX unit of one PE in system mode and its control registers.
//!
//! On hardware the AMX register file belongs to the PE, not to a thread: the
//! guest kernel enables it with `AMX_CTL_EL1` bit 63 and saves and restores
//! it in its own context switch with ordinary AMX transfers. The evidence is
//! the 26A434 J473 kernelcache, cited by address in
//! `docs/research/amx.md#system-mode-abi-26a434-xnu-j473`:
//!
//! - CPU initialization writes `AMX_CTL_EL1` = 0x100, or 0x100 | MPIDR.Aff0
//!   under one boot configuration, and in others writes MPIDR.Aff0 to
//!   `AMX_CTX_EL1` (`0xfffffe000bd80ef4`). The meaning of bits 0..8 is
//!   unknown; they are kept as written and have no effect here.
//! - Every `AMX_CTL` copy is reached through [`Unit::control`] with an
//!   [`AmxView`]; [`view`] alone maps encodings to views, so EL2 with VHE
//!   changes only that mapping.
//! - Every context-switch use sets or clears only bit 63 with
//!   read-modify-write, and reads `AMX_STATE_T` after `dsb ish` testing only
//!   for nonzero (`0xfffffe000bd83694`). Live state reads as 1 here
//!   (inference: the kernel only compares with zero).
use crate::machine::registers::{Changes, Outcome, Refusal};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use stela_compiler::{aarch64::system::registers::Encoding, amx::AmxRegisters};

/// `S3_4_C15_C1_4`: AMX enable (bit 63) and the CPU-init fields.
pub const AMX_CTL_EL1: Encoding = Encoding::new(3, 4, 15, 1, 4);
/// `S3_4_C15_C4_6` and `S3_4_C15_C4_7`, used only by XNU's hypervisor paths.
pub const AMX_CTL_EL12: Encoding = Encoding::new(3, 4, 15, 4, 6);
pub const AMX_CTL_EL2: Encoding = Encoding::new(3, 4, 15, 4, 7);
/// `S3_4_C15_C1_3`: nonzero while `set` state is live. Read-only in the kernel.
pub const AMX_STATE_T: Encoding = Encoding::new(3, 4, 15, 1, 3);
pub const AMX_CTL_ENABLE: u64 = 1 << 63;
/// The low fields CPU initialization writes (0x100 | MPIDR.Aff0).
const AMX_CTL_INIT_FIELDS: u64 = 0x1ff;

/// The `AMX_CTL` copy an access reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmxView {
    El1,
    El2,
}

/// The view an MRS/MSR encoding reaches at the current EL. Without EL2 only
/// `AMX_CTL_EL1` maps (to `El1`); `AMX_CTL_EL12` and `AMX_CTL_EL2` stay
/// refused. With VHE, `AMX_CTL_EL1` at EL2 with E2H reaches `El2`,
/// `AMX_CTL_EL12` reaches `El1` and `AMX_CTL_EL2` reaches `El2`.
pub fn view(encoding: Encoding) -> Option<AmxView> {
    match encoding {
        AMX_CTL_EL1 => Some(AmxView::El1),
        _ => None,
    }
}

/// One PE's AMX unit. `registers` exists between `set` and `clr`.
#[derive(Debug, Clone, Default)]
pub struct Unit {
    controls: [u64; 2],
    pub registers: Option<Box<AmxRegisters>>,
}

impl Unit {
    /// The single accessor of every `AMX_CTL` copy.
    pub fn control(&mut self, view: AmxView) -> &mut u64 {
        &mut self.controls[view as usize]
    }

    /// Whether the `AMX_CTL` copy governing the current EL admits AMX
    /// instructions (`El1` for EL1 and EL0 without EL2).
    pub fn enabled(&self, view: AmxView) -> bool {
        self.controls[view as usize] & AMX_CTL_ENABLE != 0
    }

    pub fn live(&self) -> bool {
        self.registers.is_some()
    }

    /// MRS of an AMX control register, or `None` for other encodings.
    pub fn read(&mut self, encoding: Encoding) -> Option<Outcome> {
        if let Some(view) = view(encoding) {
            return Some(Outcome::Read(*self.control(view)));
        }
        match encoding {
            AMX_STATE_T => Some(Outcome::Read(u64::from(self.live()))),
            _ => None,
        }
    }

    /// Whether `encoding` is an AMX register this unit answers.
    pub fn owns(encoding: Encoding) -> bool {
        view(encoding).is_some() || encoding == AMX_STATE_T
    }

    /// MSR of an AMX control register, or `None` for other encodings.
    pub fn write(&mut self, encoding: Encoding, value: u64) -> Option<Outcome> {
        let refuse = |reason| Outcome::Refused(Refusal::UnsupportedSetting(reason));
        if let Some(view) = view(encoding) {
            if value & !(AMX_CTL_ENABLE | AMX_CTL_INIT_FIELDS) != 0 {
                return Some(refuse("AMX_CTL bit the kernel never writes"));
            }
            *self.control(view) = value;
            return Some(Outcome::Written(Changes::default()));
        }
        match encoding {
            AMX_STATE_T => Some(refuse("AMX_STATE_T write: the kernel only reads it")),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_keeps_the_kernel_fields_and_state_reports_liveness() {
        let mut unit = Unit::default();
        assert!(!unit.enabled(AmxView::El1));
        assert_eq!(
            unit.write(AMX_CTL_EL1, 0x100 | 3),
            Some(Outcome::Written(Changes::default()))
        );
        assert_eq!(unit.read(AMX_CTL_EL1), Some(Outcome::Read(0x103)));
        unit.write(AMX_CTL_EL1, AMX_CTL_ENABLE | 0x100);
        assert!(unit.enabled(AmxView::El1));
        assert!(!unit.enabled(AmxView::El2));
        assert_eq!(view(AMX_CTL_EL12), None, "no EL2");
        assert_eq!(view(AMX_CTL_EL2), None, "no EL2");
        assert_eq!(unit.read(AMX_STATE_T), Some(Outcome::Read(0)));
        unit.registers = Some(Box::new(AmxRegisters::zeroed()));
        assert_eq!(unit.read(AMX_STATE_T), Some(Outcome::Read(1)));
        assert!(matches!(
            unit.write(AMX_CTL_EL1, 1 << 62),
            Some(Outcome::Refused(_))
        ));
        assert!(matches!(
            unit.write(AMX_STATE_T, 0),
            Some(Outcome::Refused(_))
        ));
        assert_eq!(unit.read(Encoding::new(3, 4, 15, 1, 5)), None);
    }
}
