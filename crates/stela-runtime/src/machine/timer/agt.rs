//! The Apple generic timer of the M3 and later (XNU `HAS_APPLE_GENERIC_TIMER`,
//! "Supports 24 MHz Apple timer", in `pexpert/arm64/H15.h` to `H17.h` of
//! xnu-12377.121.6). Its registers (`AGTCNT*`; names from qemu-sptm's
//! Binary Ninja table, m1n1 `cpu_regs.h` for AGTCNTRDIR) mirror the generic
//! timer's in Apple's encoding space, with the VHE pattern of their `_EL02`
//! and `_EL12` names.
//!
//! These chips have two timer banks on one time base:
//! - The Apple bank counts the 24 MHz Apple timebase. The kernel's timer
//!   always uses it: XNU names `S3_1_C15_C15_4`, `S3_4_C15_C11_7`,
//!   `S3_4_C15_C10_6`, `S3_1_C15_C0_5` and `S3_4_C15_C9_6` where other chips
//!   use CNTV_TVAL_EL0, CNTVCT_EL0, CNTVCTSS_EL0, CNTV_CTL_EL0 and
//!   CNTKCTL_EL1 (`osfmk/arm64/machine_routines.c`), and the commpage's
//!   `mach_absolute_time` reads `S3_4_C15_C10_6` (`user_timebase_type`).
//! - The Arm bank is the architectural generic timer on a counter scaled to
//!   1 GHz, Armv8.6's frequency: m1n1 programs this "counter redirect" on
//!   the M3 (`src/chickens.c`) and reads 1 GHz from CNTFRQ_EL0 beside a
//!   24 MHz Apple timer on an M4 Pro (`src/hv/hv_sprr.c`); XNU expects
//!   CNTFRQ_EL0 to read 1 GHz where AIDR_EL1 bit 32 (`AIDR_AGT`) is set
//!   (`tests/apple_generic_timer.c`), as the identification sets it here.
//!
//! The banks are separate registers, not one bank seen at two scales: XNU
//! masks the physical timer in both because "its registers reset to
//! architecturally unknown values" and, after programming the Apple
//! CNTKCTL, enables "EL0 access to the ARM timebase registers too", and
//! m1n1 writes CNTHCTL_EL2 only after the redirect on the M3 and later
//! (`src/hv/hv.c`). Both banks' timers signal FIQ, under the same
//! VM_TMR_FIQ_ENA_EL2 gate for the EL1 timers (inference).
//!
//! The Apple registers (`AGTCNT*`) always reach the Apple bank, with the
//! traps and VHE redirection of their architectural counterparts. The
//! architectural encodings reach the bank AGTCNTRDIR selects for the current
//! regime (`_EL1` names it, at EL2 the EL2&0 one; `_EL12` the EL1&0 one):
//! - Bit 1 (m1n1 `AGTCNTRDIR_DISABLE`) turns the redirect off, so the
//!   architectural encodings reach the Apple bank. Firmware leaves both set
//!   for macOS (m1n1 `proxyclient/tools/run_guest.py`), which is their
//!   value here at reset; the kernel sets it for the EL1&0 regime, whose
//!   guests' timers its hypervisor saves through the Apple `_EL02` and
//!   `_EL12` forms alone, and clears it for its own.
//! - Bit 0 (m1n1 `AGTCNTRDIR_EL0_TRAP_CTL`) gives EL0 the Apple bank. The
//!   26A434 kernel sets it on a switch to a thread without
//!   `ARM_MACHINE_THREAD_USES_1GHZ_TIMBASE` and clears it for one with it
//!   (J613AP 0xfffffe000bcffe18, 0xfffffe000bcfc5a0); such a thread expects
//!   a 24 MHz CNTFRQ_EL0 (`tests/apple_generic_timer_legacy.c`), and XNU
//!   handles an EL0 MSR or MRS trap only as EXC_BAD_INSTRUCTION
//!   (`osfmk/arm64/sleh.c` `handle_msr_trap`), so it is taken to redirect,
//!   not trap (inference from the name and those consumers).
//!
//! AGTCNTKCTL_NOREDIR bypasses both redirections: it reaches the Apple
//! bank's EL1&0 CNTKCTL from EL1 and EL2 alike (inference: SPTM saves it,
//! clears it for an EL1 guest whose CNTKCTL it then writes through
//! AGTCNTKCTL_EL12, and restores it after).
use super::super::{Chip, cpu::Cpu, impdef, system::Register};
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
    AGTCNTVCTSS_EL0 = 3, 4, 15, 10, 6;
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
    CNTVCTSS_EL0 = 3, 3, 14, 0, 6;
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

/// Each Apple register with the architectural register whose Apple bank
/// copy it reaches. Consumers in the 26A434 J613AP (M3) kernel unless noted:
/// - The `KERNEL_*` registers and AGTCNTP_CTL_EL0 as XNU names them (timer
///   setup 0xfffffe000c4aabd0, 0xfffffe000c4ab194; deadlines
///   0xfffffe000bd020a8; the FIQ handler tests ISTATUS at
///   0xfffffe000bcf762c). AGTCNTVCTSS_EL0 is the encoding of the M1 and
///   M2's CNTVCT_ALIAS_EL0, which on those chips reads their one bank.
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
const VIEWS: [(Encoding, Encoding); 14] = [
    (AGTCNTV_CTL_EL0, CNTV_CTL_EL0),
    (AGTCNTV_TVAL_EL0, CNTV_TVAL_EL0),
    (AGTCNTP_CTL_EL0, CNTP_CTL_EL0),
    (AGTCNTVCT_EL0, CNTVCT_EL0),
    (AGTCNTVCTSS_EL0, CNTVCTSS_EL0),
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

/// Whether `chip` has the Apple generic timer and the scaled Arm bank: the
/// M3 to M5 by XNU's `HAS_APPLE_GENERIC_TIMER`, and every chip whose
/// censused SPTM or kernel programs AGTCNTRDIR (the M3 to M6 SPTMs at boot,
/// the M3 to M5 kernels at boot and on every thread switch).
pub const fn present(chip: Chip) -> bool {
    !matches!(chip, Chip::AppleM1 | Chip::AppleM2)
}

/// The Arm bank's frequency on a chip with the Apple generic timer.
pub const SCALED_HZ: u64 = 1_000_000_000;
/// The Apple timebase, XNU's "24 MHz Apple timer", until the profile's
/// counter frequency is loaded ([`State::set_timebase`]).
const APPLE_HZ: u64 = 24_000_000;

/// One timer bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bank {
    /// The architectural generic timer: the system counter, scaled to
    /// [`SCALED_HZ`] on a chip with the Apple generic timer.
    Arm,
    /// The Apple generic timer, on the unscaled system counter.
    Apple,
}

/// AGTCNTRDIR bit 0: EL0 reaches the Apple bank.
pub const REDIRECT_EL0_TRAP_CONTROL: u64 = 1 << 0;
/// AGTCNTRDIR bit 1: the architectural encodings reach the Apple bank.
pub const REDIRECT_DISABLE: u64 = 1 << 1;
const REDIRECT_KNOWN: u64 = REDIRECT_EL0_TRAP_CONTROL | REDIRECT_DISABLE;

const REDIRECT_UNMODELED: &str = "AGTCNTRDIR bit without known meaning: no software sets it and \
    its effect is not modeled";

/// What an Apple generic timer encoding names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Name {
    /// The Apple bank copy of the architectural register at this encoding.
    View(Encoding),
    /// AGTCNTRDIR of the current regime (`_EL1`) or, from EL2, of the
    /// EL1&0 regime (`_EL12`): SPTM writes 3 to both at boot (J613AP
    /// `__text+0x1a310`), sets the current one to 1 on entry and restores
    /// it on return (`__text+0x2ad4`, `__text+0x28dc`), and sets the EL12
    /// one to 3 for an EL1 guest it runs (`__text+0x4b3d4`). The kernel
    /// writes 0 to its own and 3 to the EL12 one at boot (J613AP
    /// 0xfffffe000c4aabac, 0xfffffe000c4aabb4).
    Redirect { el12: bool },
    /// AGTCNTKCTL_NOREDIR: SPTM saves it, clears it for an EL1 guest it runs
    /// and restores it after (J613AP `__text+0x4b34c`, `__text+0x4b5c0`).
    NoRedirectControl,
}

/// What `encoding` names on `chip`: an Apple generic timer register the
/// chip's censused components access ([`impdef::consumed`]).
pub fn decode(encoding: Encoding, chip: Chip) -> Option<Name> {
    if !present(chip) || !impdef::consumed(encoding, chip) {
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

/// The architectural encoding AGTCNTKCTL_NOREDIR reaches at `el`: the
/// EL1&0 CNTKCTL, named from EL2 by its `_EL12` form.
pub fn no_redirect_control(el: u8) -> Encoding {
    if el == 2 { CNTKCTL_EL12 } else { CNTKCTL_EL1 }
}

/// The registers each bank has its own copy of.
const BANKED: [Register; 12] = [
    Register::CNTFRQ_EL0,
    Register::CNTKCTL_EL1,
    Register::CNTHCTL_EL2,
    Register::CNTVOFF_EL2,
    Register::CNTP_CTL_EL0,
    Register::CNTP_CVAL_EL0,
    Register::CNTV_CTL_EL0,
    Register::CNTV_CVAL_EL0,
    Register::CNTHP_CTL_EL2,
    Register::CNTHP_CVAL_EL2,
    Register::CNTHV_CTL_EL2,
    Register::CNTHV_CVAL_EL2,
];

/// The Apple generic timer's state: AGTCNTRDIR of the EL1&0 (0) and EL2&0
/// (1) regimes, the Apple bank's registers and the system counter's
/// frequency (the Arm bank lives in the System register file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    redirect: [u64; 2],
    bank: [u64; BANKED.len()],
    timebase: u64,
}

impl State {
    /// Reset: the redirect disabled for every level, as firmware hands the
    /// PE over, and the Apple bank at the generic timer's reset values with
    /// the Apple timebase in CNTFRQ_EL0.
    pub fn new(chip: Chip) -> Self {
        let mut bank = BANKED.map(|register| register.reset(chip));
        bank[0] = APPLE_HZ;
        Self {
            redirect: [REDIRECT_KNOWN; 2],
            bank,
            timebase: APPLE_HZ,
        }
    }

    /// Count the system counter at `hz`: the Apple bank's CNTFRQ_EL0 and
    /// the base the Arm bank scales from.
    pub fn set_timebase(&mut self, hz: u64) {
        self.timebase = hz;
        self.bank[0] = hz;
    }

    pub fn redirect(&self, regime: usize) -> u64 {
        self.redirect[regime]
    }

    /// Set AGTCNTRDIR of `regime`; what it would need that this machine
    /// does not model.
    pub fn set_redirect(&mut self, regime: usize, value: u64) -> Option<&'static str> {
        self.redirect[regime] = value;
        (value & !REDIRECT_KNOWN != 0).then_some(REDIRECT_UNMODELED)
    }

    /// The Apple bank's copy of `register`, if it has one.
    pub fn get(&self, register: Register) -> Option<u64> {
        BANKED
            .iter()
            .position(|&banked| banked == register)
            .map(|slot| self.bank[slot])
    }

    /// Store an already masked value in the Apple bank's copy of `register`;
    /// false when the bank has none.
    pub fn set(&mut self, register: Register, value: u64) -> bool {
        let slot = BANKED.iter().position(|&banked| banked == register);
        if let Some(slot) = slot {
            self.bank[slot] = value;
        }
        slot.is_some()
    }

    /// The Arm bank's count at system count `physical`.
    pub fn scale(&self, physical: u64) -> u64 {
        (u128::from(physical) * u128::from(SCALED_HZ) / u128::from(self.timebase)) as u64
    }

    /// The first system count whose scaled count reaches `count`.
    pub fn unscale(&self, count: u64) -> u64 {
        let base = u128::from(self.timebase);
        let product = u128::from(count) * base;
        let scaled = u128::from(SCALED_HZ);
        u64::try_from(product.div_ceil(scaled)).unwrap_or(u64::MAX)
    }
}

/// The bank an architectural encoding reaches on `cpu`: the Arm bank
/// without the Apple generic timer, else the one AGTCNTRDIR of the current
/// regime selects.
pub fn selected(cpu: &Cpu) -> Bank {
    let pstate = cpu.pstate;
    if !present(cpu.registers.chip()) {
        return Bank::Arm;
    }
    let host = pstate.el == 2 || (pstate.el == 0 && cpu.in_host());
    let redirect = cpu.apple.generic_timer.redirect(usize::from(host));
    let apple = redirect & REDIRECT_DISABLE != 0
        || (pstate.el == 0 && redirect & REDIRECT_EL0_TRAP_CONTROL != 0);
    if apple { Bank::Apple } else { Bank::Arm }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The family is present from the M3 on, as the census shows: there the
    /// components program AGTCNTRDIR, and they access every view but
    /// AGTCNTHV_CTL_EL2, which the M4 and later add.
    #[test]
    fn the_census_gates_each_register_by_chip() {
        let all = VIEWS.map(|(apple, _)| apple).into_iter().chain([
            AGTCNTRDIR_EL1,
            AGTCNTRDIR_EL12,
            AGTCNTKCTL_NOREDIR_EL1,
        ]);
        for chip in Chip::ALL {
            assert_eq!(present(chip), impdef::consumed(AGTCNTRDIR_EL1, chip));
            for encoding in all.clone() {
                let expected =
                    present(chip) && (encoding != AGTCNTHV_CTL_EL2 || chip != Chip::AppleM3);
                assert_eq!(
                    decode(encoding, chip).is_some(),
                    expected,
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

    /// AGTCNTRDIR resets disabled, holds its two known bits and reports
    /// another; the Apple bank holds its own copies.
    #[test]
    fn state_holds_the_redirect_and_the_apple_bank() {
        let mut state = State::new(Chip::AppleM3);
        assert_eq!(state.redirect(0), REDIRECT_KNOWN);
        for value in [3, 1, 0, REDIRECT_DISABLE] {
            assert_eq!(state.set_redirect(1, value), None);
            assert_eq!(state.redirect(1), value);
        }
        assert_eq!(
            state.set_redirect(0, 1 << 2 | REDIRECT_DISABLE),
            Some(REDIRECT_UNMODELED)
        );
        assert_eq!(state.redirect(0), 0b110);
        assert_eq!(state.get(Register::CNTFRQ_EL0), Some(APPLE_HZ));
        assert!(state.set(Register::CNTV_CVAL_EL0, 7));
        assert_eq!(state.get(Register::CNTV_CVAL_EL0), Some(7));
        assert!(!state.set(Register::SCTLR_EL1, 7));
        assert_eq!(state.get(Register::SCTLR_EL1), None);
    }

    /// The Arm bank counts 125 ticks per 3 of the 24 MHz system counter,
    /// and `unscale` gives the first system count reaching a scaled count.
    #[test]
    fn scaling_is_exact_and_its_inverse_rounds_up() {
        let state = State::new(Chip::AppleM4);
        assert_eq!(state.scale(APPLE_HZ), SCALED_HZ);
        assert_eq!((state.scale(1), state.scale(3)), (41, 125));
        assert_eq!(
            (state.unscale(0), state.unscale(41), state.unscale(42)),
            (0, 1, 2)
        );
        assert_eq!(state.unscale(125), 3);
        for count in [1, 41, 42, 1000, 1 << 40] {
            let physical = state.unscale(count);
            assert!(state.scale(physical) >= count && state.scale(physical - 1) < count);
        }
    }
}
