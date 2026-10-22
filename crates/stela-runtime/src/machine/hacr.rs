//! HACR_EL2, Apple's hypervisor auxiliary control: which Apple-specific
//! operations of an EL1&0 guest (EL1 or EL0 with HCR_EL2.TGE clear) trap to
//! EL2.
//!
//! The register is held: every bit reads back what was written, except bit
//! 20, which [`unsupported_bits`] refuses. Each bit's guest operations come
//! from m1n1's names (`proxyclient/m1n1/sysreg.py` `HACR`, the summary of
//! its `experiments/hacr_trap_bits.py` sweep, which sets one bit at a time
//! and lists the op0 3, CRn 11 and 15 encodings whose EL1 reads stop
//! completing with HCR_EL2.TGE clear) and its register names
//! (`src/cpu_regs.h`). m1n1's hypervisor takes these traps as MSR and MRS
//! traps (`hv_exc.c`, EC 0x18 with the instruction's ISS), and the 26A434
//! kernel's guest exit records ESR, FAR, ELR and SPSR in the vCPU's exit
//! state, and no AFSR1 (0xfffffe000bb9db00), so the exit carries the
//! register in that syndrome (inference): a guest EL1 access an owned bit
//! traps is taken to EL2 as EC 0x18.
//!
//! The 26A434 SPTM writes 0 when it starts EL1 (`__text+0x49ea0`) and, on
//! every VM guest entry (`__text+0x58c3c`), 0x061f000061002000 ORed with its
//! caller's bits; a DeviceTree `/product` `internal-isa-vm-allowed`
//! property, or `/chosen/asmb` `lp-sip0` bits 0x1010, selects
//! 0x041f000000000000 instead (`__text+0x19a98`).
//!
//! An operation a bit owns traps when that bit is set and the trap's
//! condition is recovered; otherwise it refuses by name. An operation no
//! bit owns refuses while a bit whose operations are not all named is set
//! (bit 0, bit 48's beyond `S3_5_C15_C10_1`, and every unnamed bit, among
//! them the SPTM's 24, 29 and 30), since that bit might trap it.
use super::registers::encodings::{self as regs, Encoding};

/// An Apple-specific operation of a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// MRS or MSR of an op0 3, CRn 11 or 15 encoding, or of AIDR_EL1.
    Register(Encoding),
    /// GENTER or GEXIT.
    Guarded { enter: bool },
    /// SDSB.
    SynchronizationBarrier,
    /// An AMX instruction.
    Amx,
    /// WKDMC or WKDMD.
    Compression,
}

impl core::fmt::Display for Operation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Register(e) => write!(
                f,
                "S{}_{}_C{}_C{}_{}",
                e.op0(),
                e.op1(),
                e.crn(),
                e.crm(),
                e.op2()
            ),
            Self::Guarded { enter: true } => f.write_str("GENTER"),
            Self::Guarded { enter: false } => f.write_str("GEXIT"),
            Self::SynchronizationBarrier => f.write_str("SDSB"),
            Self::Amx => f.write_str("an AMX instruction"),
            Self::Compression => f.write_str("WKDMC or WKDMD"),
        }
    }
}

/// Where in a guest the operation runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub el: u8,
    /// At a guarded level (GXF), where m1n1 also sees an IMPLEMENTATION
    /// DEFINED report (EC 0x3f, ISS 0x20, the MSR syndrome in AFSR1_EL2)
    /// whose condition is not recovered.
    pub guarded: bool,
}

/// What HACR_EL2 does to a guest's operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No set bit traps it.
    Runs,
    /// Taken to EL2 as an MSR or MRS trap (EC 0x18).
    Trap,
    /// A set bit's effect on it is not recovered.
    Refused(alloc::string::String),
}

/// How a bit acts on an operation it owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trap {
    /// Accesses from the guest's EL1 trap; m1n1's sweep observed them.
    El1,
    /// The bit's name covers the operation, but whether and how it traps
    /// is not recovered.
    Unrecovered,
}

/// Bit 20 masks the guest's virtual timer (Asahi Linux "ARM System
/// Registers": "Mask guest CNTV timer (1=masked)", leaving the FIQ pending
/// in an Apple register this machine does not model).
const GUEST_TIMER_MASK: u64 = 1 << 20;

/// The bits a write may not set, with the reason.
pub fn unsupported_bits(value: u64) -> Option<&'static str> {
    (value & GUEST_TIMER_MASK != 0).then_some(
        "HACR_EL2 bit 20 masks the guest's virtual timer, whose pending FIQ register is not modeled",
    )
}

/// Bits whose every guest operation m1n1 names, so they act on nothing
/// else: AIDR (4), AMX (10), SPRR (11), GXF (13), CTRR (14), IPI (16), the
/// encoding ranges (18, 19, 25, 51 and 59), EHID (49), HID (50), ACC (52),
/// PM (57) and UPM (58).
const NAMED: u64 = 1 << 4
    | 1 << 10
    | 1 << 11
    | 1 << 13
    | 1 << 14
    | 1 << 16
    | 1 << 18
    | 1 << 19
    | 1 << 25
    | 1 << 49
    | 1 << 50
    | 1 << 51
    | 1 << 52
    | 1 << 57
    | 1 << 58
    | 1 << 59;

const fn sys(op1: u8, crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, op1, 15, crm, op2)
}

/// m1n1 `cpu_regs.h` HIDn: op1 0 with op2 0 (HID11_LEGACY at CRm 13), and
/// HID16, HID18, HID21, HID26 and HID27.
const HID: &[Encoding] = &[
    sys(0, 0, 0),
    sys(0, 1, 0),
    sys(0, 3, 0),
    sys(0, 4, 0),
    sys(0, 5, 0),
    sys(0, 6, 0),
    sys(0, 7, 0),
    sys(0, 8, 0),
    sys(0, 9, 0),
    sys(0, 10, 0),
    sys(0, 11, 0),
    sys(0, 12, 0),
    sys(0, 13, 0),
    sys(0, 14, 0),
    sys(0, 15, 0),
    sys(0, 15, 2),
    sys(0, 11, 2),
    sys(0, 1, 3),
    sys(0, 0, 3),
    sys(0, 0, 4),
];

/// m1n1 `cpu_regs.h` EHIDn.
const EHID: &[Encoding] = &[
    sys(0, 0, 1),
    sys(0, 1, 1),
    sys(0, 3, 1),
    sys(0, 4, 1),
    sys(0, 7, 1),
    sys(0, 9, 1),
    sys(0, 10, 1),
    sys(0, 11, 1),
    sys(0, 11, 3),
    sys(0, 1, 2),
];

/// The bits that own an operation and how each acts on it.
fn owners(operation: Operation) -> alloc::vec::Vec<(u8, Trap)> {
    use Trap::{El1, Unrecovered};
    let mut owners = alloc::vec::Vec::new();
    let encoding = match operation {
        Operation::Register(encoding) => encoding,
        // TRAP_GXF names the guarded execution feature; whether GENTER and
        // GEXIT trap, and how, is not recovered.
        Operation::Guarded { .. } => return alloc::vec![(13, Unrecovered)],
        // TRAP_AMX names AMX; m1n1 observed only register reads.
        Operation::Amx => return alloc::vec![(10, Unrecovered)],
        // No m1n1 name covers WKdm, so it traps under no named bit.
        Operation::SynchronizationBarrier | Operation::Compression => return owners,
    };
    let (op1, crn, crm, op2) = (
        encoding.op1(),
        encoding.crn(),
        encoding.crm(),
        encoding.op2(),
    );
    let mut own = |bit: u8, trap: Trap| owners.push((bit, trap));
    if encoding == regs::AIDR_EL1 {
        own(4, El1);
    }
    if encoding.op0() != 3 || !matches!(crn, 11 | 15) {
        return owners;
    }
    // AMX_STATE_T, AMX_CTL_EL1 and AMX_CTX_EL1.
    if matches!((op1, crn, crm, op2), (4, 15, 1, 3 | 4) | (4, 15, 5, 0)) {
        own(10, El1);
    }
    if matches!(
        encoding,
        regs::SPRR_CONFIG_EL1 | regs::SPRR_PERM_EL0 | regs::SPRR_PERM_EL1
    ) {
        own(11, El1);
    }
    if matches!(
        encoding,
        regs::GXF_CONFIG_EL1 | regs::GXF_STATUS_EL1 | regs::GXF_ENTER_EL1 | regs::GXF_ABORT_EL1
    ) {
        own(13, El1);
    }
    // The guarded level's bank (m1n1 `*_GL1`, AFSR1_GL1 among them): GXF
    // state, inferred to be bit 13's, whose trap is not observed.
    if matches!(
        encoding,
        regs::TPIDR_GL1
            | regs::VBAR_GL1
            | regs::SPSR_GL1
            | regs::ASPSR_GL1
            | regs::ESR_GL1
            | regs::ELR_GL1
            | regs::FAR_GL1
    ) || (op1, crn, crm, op2) == (6, 15, 0, 1)
    {
        own(13, Unrecovered);
    }
    // EL1's CTRR registers (CRn 11, and the A range in CRn 15).
    if crn == 11 || super::ctrr::in_el1_range(encoding) {
        own(14, El1);
    }
    // IPI_RR_LOCAL, IPI_RR_GLOBAL, IPI_SR and IPI_CR.
    if matches!((op1, crn, crm, op2), (5, 15, 0, 0 | 1) | (5, 15, 1 | 3, 1)) {
        own(16, El1);
    }
    if crn == 15 {
        if op1 == 4 && matches!(crm, 5 | 6) {
            own(18, El1);
        }
        if op1 == 4 && crm <= 12 && op2 == 5 {
            own(19, El1);
        }
        if (op1, crm, op2) == (4, 10, 4) {
            own(25, El1);
        }
        // The register M1RACLES disclosed, which m1n1's hypervisor traps
        // with this bit as the mitigation.
        if (op1, crm, op2) == (5, 10, 1) {
            own(48, El1);
        }
        if EHID.contains(&encoding) {
            own(49, El1);
        }
        if HID.contains(&encoding) {
            own(50, El1);
        }
        if (op1, crm) == (0, 12) && matches!(op2, 1 | 2) {
            own(51, El1);
        }
        // ACC_CFG and ACC_OVRD.
        if (op1, op2) == (5, 0) && matches!(crm, 4 | 6) {
            own(52, El1);
        }
        // PMCR0-4, PMESR0-1, PMSR and PMC0-9.
        if (op1 == 1 && op2 == 0 && matches!(crm, 0..=6 | 13))
            || (op1 == 2 && op2 == 0 && matches!(crm, 0..=7 | 9 | 10))
        {
            own(57, El1);
        }
        // UPMCR0, UPMESR0-1, UPMECM0-3, UPMPCM, UPMSR and UPMC0-15.
        if op1 == 7 && (op2 == 4 || (op2 == 5 && crm <= 11)) {
            own(58, El1);
        }
        if op1 >= 1 && op2 == 3 {
            own(59, El1);
        }
    }
    owners
}

/// What HACR_EL2 (`hacr`) does to `operation` of a guest at `context`.
pub fn guest(hacr: u64, operation: Operation, context: Context) -> Outcome {
    let not_recovered = |bit: u8| {
        alloc::format!("HACR_EL2 bit {bit} on {operation}: trapped operation not recovered")
    };
    let owners = owners(operation);
    if !owners.is_empty() {
        let mut refused = None;
        for (bit, trap) in owners {
            if hacr & (1 << bit) == 0 {
                continue;
            }
            match trap {
                Trap::El1 if context.el == 1 && !context.guarded => return Outcome::Trap,
                _ => refused = refused.or(Some(bit)),
            }
        }
        return refused.map_or(Outcome::Runs, |bit| Outcome::Refused(not_recovered(bit)));
    }
    let unnamed = hacr & !NAMED;
    if unnamed == 0 {
        Outcome::Runs
    } else {
        Outcome::Refused(not_recovered(unnamed.trailing_zeros() as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EL1: Context = Context {
        el: 1,
        guarded: false,
    };
    /// The SPTM's VM entry value without the internal-ISA property.
    const CUSTOMER: u64 = 0x061f_0000_6100_2000;
    /// With it.
    const INTERNAL: u64 = 0x041f_0000_0000_0000;

    fn register(op1: u8, crn: u8, crm: u8, op2: u8) -> Operation {
        Operation::Register(Encoding::new(3, op1, crn, crm, op2))
    }

    #[test]
    fn named_bits_trap_their_registers_from_a_guests_el1() {
        // HID4 under TRAP_HID, EHID4 under TRAP_EHID, PMCR0 under TRAP_PM,
        // UPMCR0 under TRAP_UPM and ACC_CFG under TRAP_ACC.
        for (bit, operation) in [
            (50, register(0, 15, 4, 0)),
            (49, register(0, 15, 4, 1)),
            (57, register(1, 15, 0, 0)),
            (58, register(7, 15, 0, 4)),
            (52, register(5, 15, 4, 0)),
            (48, register(5, 15, 10, 1)),
            (51, register(0, 15, 12, 2)),
            (59, register(3, 15, 7, 3)),
            (4, Operation::Register(regs::AIDR_EL1)),
            (11, Operation::Register(regs::SPRR_PERM_EL1)),
            (13, Operation::Register(regs::GXF_CONFIG_EL1)),
        ] {
            assert_eq!(
                guest(1 << bit, operation, EL1),
                Outcome::Trap,
                "{operation}"
            );
            // Another named bit leaves it alone.
            let other = if bit == 50 { 1 << 49 } else { 1 << 50 };
            assert_eq!(guest(other, operation, EL1), Outcome::Runs, "{operation}");
        }
        // The SPTM's values trap the HID, EHID and uncore PMU registers.
        for hacr in [CUSTOMER, INTERNAL] {
            assert_eq!(guest(hacr, register(0, 15, 4, 0), EL1), Outcome::Trap);
            assert_eq!(guest(hacr, register(7, 15, 7, 4), EL1), Outcome::Trap);
        }
        // Only the customer value traps the core PMU.
        assert_eq!(guest(CUSTOMER, register(1, 15, 0, 0), EL1), Outcome::Trap);
        assert_eq!(guest(INTERNAL, register(1, 15, 0, 0), EL1), Outcome::Runs);
    }

    #[test]
    fn unrecovered_conditions_refuse_by_name() {
        let refused = |hacr, operation, context| match guest(hacr, operation, context) {
            Outcome::Refused(reason) => reason,
            other => panic!("{other:?}"),
        };
        // An encoding no bit names, under the SPTM's unnamed bit 24, or
        // bit 48 beyond the register it is known to trap.
        assert_eq!(
            refused(CUSTOMER, register(6, 15, 2, 5), EL1),
            "HACR_EL2 bit 24 on S3_6_C15_C2_5: trapped operation not recovered"
        );
        assert_eq!(
            refused(INTERNAL, register(6, 15, 2, 5), EL1),
            "HACR_EL2 bit 48 on S3_6_C15_C2_5: trapped operation not recovered"
        );
        assert_eq!(
            refused(INTERNAL, Operation::SynchronizationBarrier, EL1),
            "HACR_EL2 bit 48 on SDSB: trapped operation not recovered"
        );
        assert_eq!(
            refused(CUSTOMER, Operation::Compression, EL1),
            "HACR_EL2 bit 24 on WKDMC or WKDMD: trapped operation not recovered"
        );
        assert_eq!(guest(1 << 10, Operation::Compression, EL1), Outcome::Runs);
        // GENTER under TRAP_GXF, and an owned register from EL0 or a
        // guarded level.
        assert_eq!(
            refused(CUSTOMER, Operation::Guarded { enter: true }, EL1),
            "HACR_EL2 bit 13 on GENTER: trapped operation not recovered"
        );
        let el0 = Context {
            el: 0,
            guarded: false,
        };
        assert!(refused(1 << 11, Operation::Register(regs::SPRR_PERM_EL0), el0).contains("bit 11"));
        let guarded = Context {
            el: 1,
            guarded: true,
        };
        assert!(refused(CUSTOMER, register(0, 15, 4, 0), guarded).contains("bit 50"));
        // Named bits leave unnamed encodings alone; nothing set traps
        // nothing.
        assert_eq!(guest(1 << 50, register(6, 15, 2, 5), EL1), Outcome::Runs);
        assert_eq!(guest(0, Operation::Amx, EL1), Outcome::Runs);
        assert_eq!(guest(1 << 13, Operation::Amx, EL1), Outcome::Runs);
        assert!(refused(1 << 10, Operation::Amx, EL1).contains("bit 10"));
    }

    #[test]
    fn only_the_guest_timer_mask_is_refused_on_write() {
        assert_eq!(unsupported_bits(CUSTOMER), None);
        assert_eq!(unsupported_bits(INTERNAL | 1 << 0), None);
        assert!(unsupported_bits(1 << 20).is_some());
    }
}
