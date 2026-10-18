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
//!   [`AmxView`], and [`route`] alone maps encodings to views by the kernel's
//!   EL. All three `AMX_CTL` encodings are op1=4, CRn=15, outside the generic
//!   VHE alias tables, so this module routes them itself.
//! - `AMXIDR_EL1` advertises the AMX generation: the kernel's
//!   `machine_routines_apple.c` (`0xfffffe000c551f80`) takes its highest set
//!   bit of 0..5 as generation 1..6, panics on any of bits 6..15 ("Unknown
//!   AMX feature ID bit") or none ("doesn't advertise any known version"),
//!   and CPU initialization branches on the result. The model is corsix's
//!   `AMX_VER_M2`, generation 2; whether hardware also sets bit 0 is not
//!   known and the kernel would not see it.
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
/// `S3_6_C15_C2_7`: the AMX generation, one bit per generation.
pub const AMXIDR_EL1: Encoding = Encoding::new(3, 6, 15, 2, 7);
/// The generation this unit implements (`docs/research/amx.md`).
const GENERATION: u32 = 2;
pub const AMX_CTL_ENABLE: u64 = 1 << 63;
/// The low fields CPU initialization writes (0x100 | MPIDR.Aff0).
const AMX_CTL_INIT_FIELDS: u64 = 0x1ff;

/// The `AMX_CTL` copy an access reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmxView {
    El1,
    El2,
}

/// Where an `AMX_CTL` encoding goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    View(AmxView),
    Undefined,
}

/// The route of an MRS/MSR encoding for a kernel at `kernel_el`, or `None`
/// for encodings that are not `AMX_CTL`.
///
/// - Kernel at EL1 (no EL2): `AMX_CTL_EL1` reaches `El1`; `AMX_CTL_EL2` and
///   `AMX_CTL_EL12` are UNDEFINED.
/// - Kernel at EL2 as a VHE host: `AMX_CTL_EL1` and `AMX_CTL_EL2` reach `El2`,
///   and `AMX_CTL_EL12` reaches `El1`, a stored value because EL1 never runs.
///   Inference: an EL12 encoding exists only because E2H redirects the EL1
///   name, as m1n1 `cpu_regs.h` lists for `APCTL`; 26A434 XNU uses the EL12
///   and EL2 names only in its hypervisor paths (`0xfffffe000bd9ec44`,
///   `0xfffffe000bda2a8c`).
pub fn route(encoding: Encoding, kernel_el: u8) -> Option<Route> {
    Some(match (encoding, kernel_el) {
        (AMX_CTL_EL1, 1) => Route::View(AmxView::El1),
        (AMX_CTL_EL2 | AMX_CTL_EL12, 1) => Route::Undefined,
        (AMX_CTL_EL1 | AMX_CTL_EL2, _) => Route::View(AmxView::El2),
        (AMX_CTL_EL12, _) => Route::View(AmxView::El1),
        _ => return None,
    })
}

/// The view governing AMX instructions at EL0 and the kernel's EL. With E2H
/// and TGE, EL0 runs in the EL2&0 regime under the EL2 copy (inference).
pub fn governing(kernel_el: u8) -> AmxView {
    if kernel_el == 2 {
        AmxView::El2
    } else {
        AmxView::El1
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

    /// Whether an `AMX_CTL` copy admits AMX instructions; [`governing`]
    /// selects the copy.
    pub fn enabled(&self, view: AmxView) -> bool {
        self.controls[view as usize] & AMX_CTL_ENABLE != 0
    }

    pub fn live(&self) -> bool {
        self.registers.is_some()
    }

    /// MRS of an AMX control register, or `None` for other encodings.
    pub fn read(&mut self, encoding: Encoding, kernel_el: u8) -> Option<Outcome> {
        match route(encoding, kernel_el) {
            Some(Route::View(view)) => return Some(Outcome::Read(*self.control(view))),
            Some(Route::Undefined) => return Some(Outcome::Undefined),
            None => {}
        }
        match encoding {
            AMX_STATE_T => Some(Outcome::Read(u64::from(self.live()))),
            AMXIDR_EL1 => Some(Outcome::Read(1 << (GENERATION - 1))),
            _ => None,
        }
    }

    /// Whether `encoding` is an AMX register this unit answers.
    pub fn owns(encoding: Encoding) -> bool {
        matches!(
            encoding,
            AMX_CTL_EL1 | AMX_CTL_EL12 | AMX_CTL_EL2 | AMX_STATE_T | AMXIDR_EL1
        )
    }

    /// MSR of an AMX control register, or `None` for other encodings.
    pub fn write(&mut self, encoding: Encoding, kernel_el: u8, value: u64) -> Option<Outcome> {
        let refuse = |reason| Outcome::Refused(Refusal::UnsupportedSetting(reason));
        match route(encoding, kernel_el) {
            Some(Route::View(_)) if value & !(AMX_CTL_ENABLE | AMX_CTL_INIT_FIELDS) != 0 => {
                return Some(refuse("AMX_CTL bit the kernel never writes"));
            }
            Some(Route::View(view)) => {
                *self.control(view) = value;
                return Some(Outcome::Written(Changes::default()));
            }
            Some(Route::Undefined) => return Some(Outcome::Undefined),
            None => {}
        }
        match encoding {
            AMX_STATE_T => Some(refuse("AMX_STATE_T write: the kernel only reads it")),
            AMXIDR_EL1 => Some(refuse("AMXIDR_EL1 write: an identification register")),
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
        assert!(!unit.enabled(governing(1)));
        assert_eq!(
            unit.write(AMX_CTL_EL1, 1, 0x100 | 3),
            Some(Outcome::Written(Changes::default()))
        );
        assert_eq!(unit.read(AMX_CTL_EL1, 1), Some(Outcome::Read(0x103)));
        unit.write(AMX_CTL_EL1, 1, AMX_CTL_ENABLE | 0x100);
        assert!(unit.enabled(AmxView::El1));
        assert!(!unit.enabled(AmxView::El2));
        assert_eq!(unit.read(AMX_STATE_T, 1), Some(Outcome::Read(0)));
        unit.registers = Some(Box::new(AmxRegisters::zeroed()));
        assert_eq!(unit.read(AMX_STATE_T, 1), Some(Outcome::Read(1)));
        assert!(matches!(
            unit.write(AMX_CTL_EL1, 1, 1 << 62),
            Some(Outcome::Refused(_))
        ));
        assert!(matches!(
            unit.write(AMX_STATE_T, 1, 0),
            Some(Outcome::Refused(_))
        ));
        assert_eq!(unit.read(Encoding::new(3, 4, 15, 1, 5), 1), None);
        assert_eq!(unit.read(AMXIDR_EL1, 2), Some(Outcome::Read(0b10)));
        assert!(matches!(
            unit.write(AMXIDR_EL1, 2, 0),
            Some(Outcome::Refused(_))
        ));
    }

    #[test]
    fn control_views_follow_the_kernel_el() {
        let mut unit = Unit::default();
        // Without EL2 the EL2 and EL12 names are UNDEFINED.
        for encoding in [AMX_CTL_EL2, AMX_CTL_EL12] {
            assert!(Unit::owns(encoding));
            assert_eq!(unit.read(encoding, 1), Some(Outcome::Undefined));
            assert_eq!(unit.write(encoding, 1, 0), Some(Outcome::Undefined));
        }
        // A VHE host: the EL1 and EL2 names are the EL2 copy, EL12 the EL1 copy.
        unit.write(AMX_CTL_EL1, 2, AMX_CTL_ENABLE | 0x100);
        assert_eq!(
            unit.read(AMX_CTL_EL2, 2),
            Some(Outcome::Read(AMX_CTL_ENABLE | 0x100))
        );
        assert!(unit.enabled(governing(2)) && !unit.enabled(AmxView::El1));
        unit.write(AMX_CTL_EL12, 2, 0x100);
        assert_eq!(unit.read(AMX_CTL_EL12, 2), Some(Outcome::Read(0x100)));
        assert_eq!(*unit.control(AmxView::El1), 0x100);
        assert_eq!(
            *unit.control(AmxView::El2),
            AMX_CTL_ENABLE | 0x100,
            "unchanged"
        );
    }
}
