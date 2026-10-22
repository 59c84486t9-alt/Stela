//! The Apple generic timer of the M3 and later (XNU `HAS_APPLE_GENERIC_TIMER`,
//! "Supports 24 MHz Apple timer", in `pexpert/arm64/H15.h` to `H17.h` of
//! xnu-12377.121.6). Its registers (`AGTCNT*`; names from qemu-sptm's
//! Binary Ninja table, m1n1 `cpu_regs.h` for AGTCNTRDIR) mirror the generic
//! timer's in Apple's encoding space, with the VHE pattern of their `_EL02`
//! and `_EL12` names.
//!
//! The kernel's timer always uses the Apple timebase: XNU names
//! `S3_1_C15_C15_4`, `S3_4_C15_C11_7`, `S3_1_C15_C0_5` and `S3_4_C15_C9_6`
//! where other chips use CNTV_TVAL_EL0, CNTVCT_EL0, CNTV_CTL_EL0 and
//! CNTKCTL_EL1 (`osfmk/arm64/machine_routines.c`), and masks the physical
//! timer in both families. On hardware the architectural registers can
//! instead count a counter scaled to 1 GHz, Armv8.6's frequency: m1n1 sets
//! up that "counter redirect" on the M3 (`src/chickens.c`), and reads 1 GHz
//! from CNTFRQ_EL0 beside 24 MHz from the Apple frequency register on an
//! M4 Pro (`src/hv/hv_sprr.c`). XNU's `AIDR_AGT` test (AIDR_EL1 bit 32)
//! expects CNTFRQ_EL0 to read 1 GHz when that bit is set.
//!
//! The profiles leave AIDR_EL1 bit 32 clear and count 24 MHz, so this
//! machine has one timer bank on the Apple timebase and the Apple registers
//! are views of the architectural ones (`machine::timer`), reached through
//! their generated accessors with the same traps and VHE redirection.
//! Whether hardware gives the families separate comparators or scales one
//! bank is not established; the kernel programs them consistently.
//!
//! AGTCNTRDIR is held per regime. Bit 1 (m1n1 `AGTCNTRDIR_DISABLE`) turns
//! the 1 GHz redirect off, so the architectural registers count the Apple
//! timebase: firmware leaves it set for macOS (m1n1
//! `proxyclient/tools/run_guest.py`), SPTM sets it at boot and the kernel
//! sets it for the EL1&0 regime, whose guests' timers its hypervisor saves
//! through the Apple `_EL02` and `_EL12` forms alone. A value with it clear
//! asks for the scaled counter, which is not modeled and is reported. Bit
//! 0 (m1n1 `AGTCNTRDIR_EL0_TRAP_CTL`) the 26A434 kernel sets on a switch to
//! a thread without `ARM_MACHINE_THREAD_USES_1GHZ_TIMBASE` and clears for
//! one with it (J613AP 0xfffffe000bcffe18, 0xfffffe000bcfc5a0): EL0 keeps
//! the Apple timebase, which EL0 always sees here. AGTCNTKCTL_NOREDIR,
//! which bypasses the redirect, has no bank of its own here: it is held, and
//! a nonzero value is reported as unmodeled.
use super::super::{Chip, impdef};
use stela_compiler::aarch64::system::registers::{CNTVCT_EL0, Encoding};

macro_rules! encodings {
    ($($name:ident = $op0:literal, $op1:literal, $crn:literal, $crm:literal, $op2:literal;)*) => {
        $(pub const $name: Encoding = Encoding::new($op0, $op1, $crn, $crm, $op2);)*
    };
}

encodings! {
    AGTCNTV_CTL_EL0 = 3, 1, 15, 0, 5;
    AGTCNTV_TVAL_EL0 = 3, 1, 15, 15, 4;
    AGTCNTP_CTL_EL0 = 3, 1, 15, 13, 4;
    AGTCNTVCT_EL0 = 3, 4, 15, 11, 7;
    AGTCNTKCTL_EL1 = 3, 4, 15, 9, 6;
    AGTCNTKCTL_EL12 = 3, 4, 15, 9, 7;
    AGTCNTV_CTL_EL02 = 3, 4, 15, 2, 7;
    AGTCNTP_CVAL_EL02 = 3, 4, 15, 4, 1;
    AGTCNTP_CTL_EL02 = 3, 4, 15, 4, 3;
    AGTCNTV_CVAL_EL02 = 3, 4, 15, 4, 4;
    AGTCNTHCTL_EL2 = 3, 4, 15, 12, 6;
    AGTCNTVOFF_EL2 = 3, 1, 15, 9, 4;
    AGTCNTHV_CTL_EL2 = 3, 1, 15, 7, 4;
    AGTCNTRDIR_EL1 = 3, 1, 15, 1, 5;
    AGTCNTRDIR_EL12 = 3, 4, 15, 14, 6;
    AGTCNTKCTL_NOREDIR_EL1 = 3, 1, 15, 1, 6;
}

// The architectural counterparts (Arm ARM DDI0487, Generic Timer registers).
encodings! {
    CNTV_CTL_EL0 = 3, 3, 14, 3, 1;
    CNTV_TVAL_EL0 = 3, 3, 14, 3, 0;
    CNTP_CTL_EL0 = 3, 3, 14, 2, 1;
    CNTKCTL_EL1 = 3, 0, 14, 1, 0;
    CNTKCTL_EL12 = 3, 5, 14, 1, 0;
    CNTV_CTL_EL02 = 3, 5, 14, 3, 1;
    CNTP_CVAL_EL02 = 3, 5, 14, 2, 2;
    CNTP_CTL_EL02 = 3, 5, 14, 2, 1;
    CNTV_CVAL_EL02 = 3, 5, 14, 3, 2;
    CNTHCTL_EL2 = 3, 4, 14, 1, 0;
    CNTVOFF_EL2 = 3, 4, 14, 0, 3;
    CNTHV_CTL_EL2 = 3, 4, 14, 3, 1;
}

/// Each Apple register that is a view, with the architectural register it
/// shows. Consumers in the 26A434 J613AP (M3) kernel unless noted:
/// - The four `KERNEL_*` registers and AGTCNTP_CTL_EL0 as XNU names them
///   (timer setup 0xfffffe000c4aabd0, 0xfffffe000c4ab194; deadlines
///   0xfffffe000bd020a8; the FIQ handler tests ISTATUS at
///   0xfffffe000bcf762c).
/// - The `_EL02` and `_EL12` forms: the hypervisor saves a guest's timers
///   with them (0xfffffe000bd1ae98) and restores them (0xfffffe000bd1eb18);
///   this kernel never accesses the architectural forms.
/// - AGTCNTVOFF_EL2 holds a guest's virtual offset (written
///   0xfffffe000bd1e91c, read 0xfffffe000bd1d5e8; SPTM clears it,
///   `__text+0x4b358`); this kernel never accesses CNTVOFF_EL2.
/// - AGTCNTHCTL_EL2 takes a guest's timer controls except bits 15 and 16,
///   which go to CNTHCTL_EL2 (0xfffffe000bd1e970).
/// - AGTCNTHV_CTL_EL2: the J773GAP (M4) kernel clears its ENABLE before
///   WFI (0xfffffe000bc31628), where the kernel's AGTCNTV_CTL_EL0 timer
///   reaches at EL2.
const VIEWS: [(Encoding, Encoding); 13] = [
    (AGTCNTV_CTL_EL0, CNTV_CTL_EL0),
    (AGTCNTV_TVAL_EL0, CNTV_TVAL_EL0),
    (AGTCNTP_CTL_EL0, CNTP_CTL_EL0),
    (AGTCNTVCT_EL0, CNTVCT_EL0),
    (AGTCNTKCTL_EL1, CNTKCTL_EL1),
    (AGTCNTKCTL_EL12, CNTKCTL_EL12),
    (AGTCNTV_CTL_EL02, CNTV_CTL_EL02),
    (AGTCNTP_CVAL_EL02, CNTP_CVAL_EL02),
    (AGTCNTP_CTL_EL02, CNTP_CTL_EL02),
    (AGTCNTV_CVAL_EL02, CNTV_CVAL_EL02),
    (AGTCNTHCTL_EL2, CNTHCTL_EL2),
    (AGTCNTVOFF_EL2, CNTVOFF_EL2),
    (AGTCNTHV_CTL_EL2, CNTHV_CTL_EL2),
];

/// AGTCNTRDIR bit 0: EL0 keeps the Apple timebase.
pub const REDIRECT_EL0_TRAP_CONTROL: u64 = 1 << 0;
/// AGTCNTRDIR bit 1: the architectural registers count the Apple timebase,
/// not the scaled 1 GHz counter.
pub const REDIRECT_DISABLE: u64 = 1 << 1;
const REDIRECT_KNOWN: u64 = REDIRECT_EL0_TRAP_CONTROL | REDIRECT_DISABLE;

const REDIRECT_UNMODELED: &str = "AGTCNTRDIR bit without known meaning: no software sets it and \
    its effect is not modeled";
const SCALED_COUNTER_UNMODELED: &str = "AGTCNTRDIR enables the 1 GHz scaled counter, which is \
    not modeled: the architectural registers keep counting the 24 MHz Apple timebase that \
    CNTFRQ_EL0 and AIDR_EL1 bit 32 describe";
const NO_REDIRECT_UNMODELED: &str = "AGTCNTKCTL_NOREDIR nonzero: the non-redirected generic \
    timer controls have no bank of their own here, where both timer families share the 24 MHz \
    Apple timebase";

/// What an Apple generic timer encoding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {
    /// A view of the architectural register at this encoding.
    View(Encoding),
    /// AGTCNTRDIR of the current regime (`_EL1`) or, from EL2, of the
    /// EL1&0 regime (`_EL12`): SPTM writes 3 to both at boot (J613AP
    /// `__text+0x1a310`), sets the current one to 1 on entry and restores
    /// it on return (`__text+0x2ad4`, `__text+0x28dc`), and sets the EL12
    /// one to 3 for an EL1 guest it runs (`__text+0x4b3d4`). The kernel
    /// writes 0 to its own and 3 to the EL12 one at boot (J613AP
    /// 0xfffffe000c4aabac, 0xfffffe000c4aabb4).
    Redirect { el12: bool },
    /// AGTCNTKCTL_NOREDIR of the current regime: SPTM saves it, clears it
    /// for an EL1 guest it runs and restores it after (J613AP
    /// `__text+0x4b34c`, `__text+0x4b5c0`).
    NoRedirectControl,
}

/// What `encoding` names on `chip`: an Apple generic timer register the
/// chip's censused components access ([`impdef::consumed`]).
pub fn decode(encoding: Encoding, chip: Chip) -> Option<Name> {
    if !impdef::consumed(encoding, chip) {
        return None;
    }
    match encoding {
        AGTCNTRDIR_EL1 => Some(Name::Redirect { el12: false }),
        AGTCNTRDIR_EL12 => Some(Name::Redirect { el12: true }),
        AGTCNTKCTL_NOREDIR_EL1 => Some(Name::NoRedirectControl),
        _ => VIEWS
            .iter()
            .find(|&&(apple, _)| apple == encoding)
            .map(|&(_, architectural)| Name::View(architectural)),
    }
}

/// The Apple generic timer's own registers, each per regime: EL1&0 (0)
/// and EL2&0 (1). Both reset to 0; software writes them before it reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    redirect: [u64; 2],
    no_redirect_control: [u64; 2],
}

/// One of [`State`]'s registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    Redirect(usize),
    NoRedirectControl(usize),
}

impl State {
    pub fn read(&self, register: Register) -> u64 {
        match register {
            Register::Redirect(regime) => self.redirect[regime],
            Register::NoRedirectControl(regime) => self.no_redirect_control[regime],
        }
    }

    /// Hold `value`; what it would need that this machine does not model.
    pub fn write(&mut self, register: Register, value: u64) -> Option<&'static str> {
        match register {
            Register::Redirect(regime) => {
                self.redirect[regime] = value;
                if value & !REDIRECT_KNOWN != 0 {
                    Some(REDIRECT_UNMODELED)
                } else {
                    (value & REDIRECT_DISABLE == 0).then_some(SCALED_COUNTER_UNMODELED)
                }
            }
            Register::NoRedirectControl(regime) => {
                self.no_redirect_control[regime] = value;
                (value != 0).then_some(NO_REDIRECT_UNMODELED)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The census gates the family: the M1 and M2 components access none
    /// of it, every later chip all but AGTCNTHV_CTL_EL2, which the M4 and
    /// later add.
    #[test]
    fn the_census_gates_each_register_by_chip() {
        let all = VIEWS.map(|(apple, _)| apple).into_iter().chain([
            AGTCNTRDIR_EL1,
            AGTCNTRDIR_EL12,
            AGTCNTKCTL_NOREDIR_EL1,
        ]);
        for chip in Chip::ALL {
            for encoding in all.clone() {
                let modern = !matches!(chip, Chip::AppleM1 | Chip::AppleM2);
                let present = modern && (encoding != AGTCNTHV_CTL_EL2 || chip != Chip::AppleM3);
                assert_eq!(
                    decode(encoding, chip).is_some(),
                    present,
                    "{chip:?} {encoding:?}"
                );
            }
        }
        assert_eq!(
            decode(AGTCNTV_TVAL_EL0, Chip::AppleM3),
            Some(Name::View(CNTV_TVAL_EL0))
        );
        assert_eq!(
            decode(AGTCNTRDIR_EL12, Chip::AppleM6),
            Some(Name::Redirect { el12: true })
        );
    }

    /// Each view names a distinct architectural register of the generic
    /// timer space (op0 3, CRn 14).
    #[test]
    fn views_are_distinct_generic_timer_registers() {
        for (index, &(apple, architectural)) in VIEWS.iter().enumerate() {
            assert_eq!((apple.op0(), apple.crn()), (3, 15));
            assert_eq!((architectural.op0(), architectural.crn()), (3, 14));
            assert!(
                VIEWS[index + 1..]
                    .iter()
                    .all(|&(a, b)| a != apple && b != architectural)
            );
        }
    }

    /// The redirect is held per regime; it completes with the 1 GHz
    /// redirect disabled, and reports enabling it or an unknown bit. A
    /// nonzero non-redirected control is held and reported.
    #[test]
    fn own_registers_hold_and_report_unmodeled_settings() {
        let mut state = State::default();
        for (value, unmodeled) in [
            (REDIRECT_DISABLE | REDIRECT_EL0_TRAP_CONTROL, None),
            (REDIRECT_DISABLE, None),
            (REDIRECT_EL0_TRAP_CONTROL, Some(SCALED_COUNTER_UNMODELED)),
            (0, Some(SCALED_COUNTER_UNMODELED)),
        ] {
            assert_eq!(state.write(Register::Redirect(1), value), unmodeled);
            assert_eq!(state.read(Register::Redirect(1)), value);
        }
        assert_eq!(state.read(Register::Redirect(0)), 0);
        assert_eq!(
            state.write(Register::Redirect(0), 1 << 2 | REDIRECT_DISABLE),
            Some(REDIRECT_UNMODELED)
        );
        assert_eq!(state.read(Register::Redirect(0)), 0b110);
        assert_eq!(state.write(Register::NoRedirectControl(1), 0), None);
        assert_eq!(
            state.write(Register::NoRedirectControl(1), 0xf),
            Some(NO_REDIRECT_UNMODELED)
        );
        assert_eq!(state.read(Register::NoRedirectControl(1)), 0xf);
        assert_eq!(state.read(Register::NoRedirectControl(0)), 0);
    }
}
