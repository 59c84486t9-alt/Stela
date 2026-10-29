//! The Apple AMX unit of one PE in system mode and its control registers.
//!
//! On hardware the AMX register file belongs to the PE, not to a thread: the
//! guest kernel enables it with `AMX_CTL_EL1` bit 63 and saves and restores
//! it in its own context switch with ordinary AMX transfers. The evidence is
//! the 26A434 J473 kernelcache, cited by address in
//! `docs/research/amx.md#system-mode-abi-26a434-xnu-j473`:
//!
//! - CPU initialization writes `AMX_CTL_EL1` = 0x100, or 0x100 | MPIDR.Aff0
//!   for generation 1, and for generations 2–4 writes MPIDR.Aff0 to
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
//!   and CPU initialization branches on the result. The declared emulated
//!   capability is generation 1–4 on M1–M4, matching the selected reference
//!   model. These IDR answers are not observed hardware register values.
//!   M3/M4 accept only the source-checked CTL bit 8 and enable bit 63;
//!   M5/M6 controls and instructions refuse pending validation.
//! - Every context-switch use sets or clears only bit 63 with
//!   read-modify-write, and reads `AMX_STATE_T` after `dsb ish` testing only
//!   for nonzero (`0xfffffe000bd83694`). Live state reads as 1 here
//!   (inference: the kernel only compares with zero).
use crate::machine::registers::{Changes, Outcome, Refusal};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use stela_compiler::{
    aarch64::system::registers::Encoding,
    amx::{AmxRegisters, Generation},
};

/// `S3_4_C15_C1_4`: AMX enable (bit 63) and the CPU-init fields.
pub const AMX_CTL_EL1: Encoding = Encoding::new(3, 4, 15, 1, 4);
/// `S3_4_C15_C4_6` and `S3_4_C15_C4_7`, used only by XNU's hypervisor paths.
pub const AMX_CTL_EL12: Encoding = Encoding::new(3, 4, 15, 4, 6);
pub const AMX_CTL_EL2: Encoding = Encoding::new(3, 4, 15, 4, 7);
/// `S3_4_C15_C1_3`: nonzero while `set` state is live. Read-only in the kernel.
pub const AMX_STATE_T: Encoding = Encoding::new(3, 4, 15, 1, 3);
/// `S3_6_C15_C2_7`: the AMX generation, one bit per generation.
pub const AMXIDR_EL1: Encoding = Encoding::new(3, 6, 15, 2, 7);
/// No M5/M6 behavior is inferred from the checked M1–M4 reference semantics.
pub(super) const UNQUALIFIED_GENERATION: &str =
    "AMX controls and instruction generation are not source-qualified for this chip";
pub const AMX_CTL_ENABLE: u64 = 1 << 63;
/// The low fields CPU initialization writes (0x100 | MPIDR.Aff0).
const AMX_CTL_INIT_FIELDS: u64 = 0x1ff;
/// Original selected version-3/4 initialization writes CTL=0x100 only.
const AMX_CTL_VERSION_3_4_INIT_FIELDS: u64 = 1 << 8;

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
#[derive(Debug, Clone)]
pub struct Unit {
    generation: Option<Generation>,
    controls: [u64; 2],
    pub registers: Option<Box<AmxRegisters>>,
}

/// Preserve the original M2 unit API. CPU construction must use `on(chip)`.
impl Default for Unit {
    fn default() -> Self {
        Self::on(super::Chip::AppleM2)
    }
}

impl Unit {
    /// The emulated generation checked by the reference semantics and original
    /// kernel control flow. This is not an observation of silicon IDR bits.
    pub fn on(chip: super::Chip) -> Self {
        let generation = match chip {
            super::Chip::AppleM1 => Some(Generation::M1),
            super::Chip::AppleM2 => Some(Generation::M2),
            super::Chip::AppleM3 => Some(Generation::M3),
            super::Chip::AppleM4 => Some(Generation::M4),
            _ => None,
        };
        Self {
            generation,
            controls: [0; 2],
            registers: None,
        }
    }

    pub fn generation(&self) -> Option<Generation> {
        self.generation
    }

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
        if !Self::owns(encoding) {
            return None;
        }
        let Some(generation) = self.generation else {
            return Some(Outcome::Refused(Refusal::UnsupportedSetting(
                UNQUALIFIED_GENERATION,
            )));
        };
        match route(encoding, kernel_el) {
            Some(Route::View(view)) => return Some(Outcome::Read(*self.control(view))),
            Some(Route::Undefined) => return Some(Outcome::Undefined),
            None => {}
        }
        match encoding {
            AMX_STATE_T => Some(Outcome::Read(u64::from(self.live()))),
            AMXIDR_EL1 => Some(Outcome::Read(1 << (generation.reference_version() - 1))),
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
        if !Self::owns(encoding) {
            return None;
        }
        if self.generation.is_none() {
            return Some(refuse(UNQUALIFIED_GENERATION));
        }
        // M3/M4's selected version-3/4 initialization writes only bit 8;
        // PE identity is written separately to CTX. Other low fields remain
        // unchecked, not silently inherited from the legacy M2 API domain.
        let init_fields = match self.generation {
            Some(Generation::M3 | Generation::M4) => AMX_CTL_VERSION_3_4_INIT_FIELDS,
            _ => AMX_CTL_INIT_FIELDS,
        };
        match route(encoding, kernel_el) {
            Some(Route::View(_)) if value & !(AMX_CTL_ENABLE | init_fields) != 0 => {
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
    fn chip_binding_selects_declared_capability_and_refuses_unqualified_controls() {
        for chip in super::super::Chip::ALL {
            let mut unit = Unit::on(chip);
            match chip {
                super::super::Chip::AppleM1
                | super::super::Chip::AppleM2
                | super::super::Chip::AppleM3
                | super::super::Chip::AppleM4 => {
                    let (version, init) = match chip {
                        super::super::Chip::AppleM1 => (1, 0x107),
                        super::super::Chip::AppleM2 => (2, 0x107),
                        super::super::Chip::AppleM3 => (3, 0x100),
                        super::super::Chip::AppleM4 => (4, 0x100),
                        _ => unreachable!(),
                    };
                    assert_eq!(unit.generation().unwrap().reference_version(), version);
                    assert_eq!(
                        unit.read(AMXIDR_EL1, 1),
                        Some(Outcome::Read(1 << (version - 1)))
                    );
                    // The original version-1 CPU-init branch includes Aff0.
                    unit.write(AMX_CTL_EL1, 1, init);
                    assert_eq!(unit.read(AMX_CTL_EL1, 1), Some(Outcome::Read(init)));
                    assert!(!unit.enabled(AmxView::El1));
                    if version >= 3 {
                        for bit in (0..63).filter(|&bit| bit != 8) {
                            assert!(matches!(
                                unit.write(AMX_CTL_EL1, 1, init | (1 << bit)),
                                Some(Outcome::Refused(_))
                            ));
                            assert_eq!(unit.read(AMX_CTL_EL1, 1), Some(Outcome::Read(init)));
                        }
                    }
                    unit.write(AMX_CTL_EL1, 1, AMX_CTL_ENABLE | init);
                    assert!(unit.enabled(AmxView::El1));
                    assert!(matches!(
                        unit.write(AMX_CTL_EL1, 1, 1 << 62),
                        Some(Outcome::Refused(_))
                    ));
                    assert_eq!(
                        unit.read(AMX_CTL_EL1, 1),
                        Some(Outcome::Read(AMX_CTL_ENABLE | init))
                    );
                }
                _ => {
                    assert!(unit.generation().is_none());
                    for encoding in [
                        AMX_CTL_EL1,
                        AMX_CTL_EL2,
                        AMX_CTL_EL12,
                        AMXIDR_EL1,
                        AMX_STATE_T,
                    ] {
                        assert_eq!(
                            unit.read(encoding, 2),
                            Some(Outcome::Refused(Refusal::UnsupportedSetting(
                                UNQUALIFIED_GENERATION
                            )))
                        );
                        assert_eq!(
                            unit.write(encoding, 2, AMX_CTL_ENABLE),
                            Some(Outcome::Refused(Refusal::UnsupportedSetting(
                                UNQUALIFIED_GENERATION
                            )))
                        );
                    }
                    assert_eq!(unit.controls, [0; 2]);
                    assert!(!unit.live());
                }
            }
        }
    }

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
