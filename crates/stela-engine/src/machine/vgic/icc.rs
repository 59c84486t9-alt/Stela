//! The `ICC_*` encodings: Arm's accessor pseudocode for each GICv3 CPU
//! interface register (`ICC_PMR_EL1` and the rest, AARCHMRS 2026-06) without
//! EL3, and the `ICV_*` registers EL1 reaches through them.
//!
//! At EL1, ICH_HCR_EL2.TALL0, TALL1 and TC trap the group 0, group 1 and
//! common registers to EL2 (EC 0x18), and with FEAT_FGT HFGRTR_EL2 and
//! HFGWTR_EL2.ICC_IGRPENn_EL1 trap the group enables before them (the
//! register file holds that bit RES0, as it needs FEAT_GICv3). Then
//! HCR_EL2.FMO selects the virtual group 0 registers, IMO the group 1 ones,
//! and either the common ones, while the SGI registers trap to EL2. What is
//! left is the physical interface, which these cores do not have, so it is
//! UNDEFINED, as is every access at EL0. ICC_SRE_EL1 is the exception: SRE,
//! DFB and DIB read as one at EL1 and EL2 and ignore writes, and ICC_SRE_EL2's
//! Enable reads as one, so EL1's accesses never trap.
//!
//! The virtual registers follow Arm's GICv3 architecture:
//! - ICV_IAR0/1 acknowledge the highest-priority pending interrupt of their
//!   group when it has sufficient priority (`CpuInterface::sufficient`),
//!   making it active and setting its active-priority bit; otherwise they
//!   return the spurious INTID 1023, as ICV_HPPIR0/1 do when the
//!   highest-priority pending interrupt is in the other group.
//! - ICV_EOIR0/1 drop the running priority. With ICV_CTLR_EL1.EOImode 0
//!   they also deactivate the list register holding the INTID, and ICV_DIR
//!   deactivates with EOImode 1. A deactivation that finds no active list
//!   register increments ICH_HCR_EL2.EOIcount, except for an LPI. The
//!   CONSTRAINED UNPREDICTABLE cases take the choice of doing nothing: EOI
//!   of an interrupt of the other group, DIR with EOImode 0, a priority drop
//!   with nothing active, and the special INTIDs 1020 to 1023.
//! - ICV_PMR, BPR0, BPR1, CTLR.{CBPR,EOImode} and IGRPEN0/1 are fields of
//!   ICH_VMCR_EL2, and ICV_AP0R0 and AP1R0 are ICH_AP0R0_EL2 and
//!   ICH_AP1R0_EL2. ICV_CTLR_EL1's identification fields repeat
//!   ICH_VTR_EL2's. Higher active-priority registers are UNDEFINED with five
//!   priority bits, and ICC_NMIAR1_EL1 without FEAT_GICv3_NMI.
use super::{
    ACTIVE_PRIORITIES, CpuInterface, HCR_EOICOUNT_MASK, HCR_EOICOUNT_SHIFT, HCR_TALL0, HCR_TALL1,
    HCR_TC, INTID_MASK, LIST_REGISTERS, LR_ACTIVE, LR_PENDING, PRIORITY_BITS, VMCR_VBPR0_SHIFT,
    VMCR_VBPR1_SHIFT, VMCR_VCBPR, VMCR_VENG0, VMCR_VENG1, VMCR_VEOIM, VMCR_VPMR_SHIFT, VTR_SEIS,
    in_group1, priority as list_priority,
    priority::{self, BPR0_MIN, BPR1_MIN, PRIORITY_MASK},
    state, with_state,
};
use crate::machine::registers::{Changes, Outcome};
use stela_compiler::aarch64::system::registers::Encoding;

/// ICC_PMR_EL1 is outside the CRn=12 CPU interface register space.
pub(super) const PMR: Encoding = Encoding::new(3, 0, 4, 6, 0);

/// ICC_SRE_EL1: SRE, DFB and DIB, each RAO/WI.
const SRE_EL1_VALUE: u64 = 0b111;
/// ICC_SRE_EL2: SRE, DFB, DIB and Enable, each RAO/WI.
pub const SRE_EL2_VALUE: u64 = 0b1111;

const HCR_FMO: u64 = 1 << 3;
const HCR_IMO: u64 = 1 << 4;

/// The INTID an acknowledge or HPPIR read returns with nothing to report.
const SPURIOUS: u64 = 1023;
/// INTIDs 1020 to 1023 are special.
const SPECIAL: core::ops::RangeInclusive<u64> = 1020..=1023;
/// The first LPI.
const LPI: u64 = 8192;
/// The INTID field of IAR, EOIR, DIR and HPPIR.
const INTID_FIELD: u64 = 0xff_ffff;

const CTLR_CBPR: u64 = 1 << 0;
const CTLR_EOIMODE: u64 = 1 << 1;
const CTLR_PRIBITS_SHIFT: u32 = 8;
/// ICV_CTLR_EL1.SEIS, ICH_VTR_EL2.SEIS moved down.
const CTLR_SEIS: u64 = VTR_SEIS >> 8;

/// What the accessor of one encoding needs from the PE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub el: u8,
    /// HCR_EL2.
    pub hcr: u64,
    /// HCR_EL2.NV in effect.
    pub nested: bool,
    /// With FEAT_FGT, HFGRTR_EL2 (MRS) or HFGWTR_EL2 (MSR) ICC_IGRPENn_EL1.
    pub fine_grained_trap: bool,
}

/// The register group whose controls an encoding answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// TALL0; virtual under FMO.
    Group0,
    /// TALL1; virtual under IMO.
    Group1,
    /// TC; virtual under FMO or IMO.
    Common,
    /// TC; trapped under FMO or IMO.
    Generate,
}

/// The ICC_* registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Register {
    Iar(bool),
    Eoir(bool),
    Hppir(bool),
    Bpr(bool),
    /// ICC_AP0R<n>_EL1 (false) or ICC_AP1R<n>_EL1 (true).
    ActivePriorities(bool, u8),
    Igrpen(bool),
    Nmiar1,
    Dir,
    Rpr,
    Pmr,
    Ctlr,
    Sre,
    Sgi0r,
    Sgi1r,
    Asgi1r,
}

/// Whether an access may be a read, a write or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
    Both,
}

impl Register {
    fn decode(encoding: Encoding) -> Option<Self> {
        let (op0, op1, crn, crm, op2) = (
            encoding.op0(),
            encoding.op1(),
            encoding.crn(),
            encoding.crm(),
            encoding.op2(),
        );
        if encoding == PMR {
            return Some(Self::Pmr);
        }
        if (op0, op1, crn) != (3, 0, 12) {
            return None;
        }
        Some(match (crm, op2) {
            (8, 0) => Self::Iar(false),
            (8, 1) => Self::Eoir(false),
            (8, 2) => Self::Hppir(false),
            (8, 3) => Self::Bpr(false),
            (8, 4..=7) => Self::ActivePriorities(false, op2 - 4),
            (9, 0..=3) => Self::ActivePriorities(true, op2),
            (9, 5) => Self::Nmiar1,
            (11, 1) => Self::Dir,
            (11, 3) => Self::Rpr,
            (11, 5) => Self::Sgi1r,
            (11, 6) => Self::Asgi1r,
            (11, 7) => Self::Sgi0r,
            (12, 0) => Self::Iar(true),
            (12, 1) => Self::Eoir(true),
            (12, 2) => Self::Hppir(true),
            (12, 3) => Self::Bpr(true),
            (12, 4) => Self::Ctlr,
            (12, 5) => Self::Sre,
            (12, 6) => Self::Igrpen(false),
            (12, 7) => Self::Igrpen(true),
            _ => return None,
        })
    }

    fn class(self) -> Class {
        let group = |group1| if group1 { Class::Group1 } else { Class::Group0 };
        match self {
            Self::Iar(g)
            | Self::Eoir(g)
            | Self::Hppir(g)
            | Self::Bpr(g)
            | Self::ActivePriorities(g, _)
            | Self::Igrpen(g) => group(g),
            Self::Nmiar1 => Class::Group1,
            Self::Dir | Self::Rpr | Self::Pmr | Self::Ctlr | Self::Sre => Class::Common,
            Self::Sgi0r | Self::Sgi1r | Self::Asgi1r => Class::Generate,
        }
    }

    fn direction(self) -> Direction {
        match self {
            Self::Iar(_) | Self::Hppir(_) | Self::Nmiar1 | Self::Rpr => Direction::Read,
            Self::Eoir(_) | Self::Dir | Self::Sgi0r | Self::Sgi1r | Self::Asgi1r => {
                Direction::Write
            }
            _ => Direction::Both,
        }
    }
}

/// Where an access goes.
enum Route {
    Undefined,
    Trapped,
    Virtual,
}

impl CpuInterface {
    /// An access to an ICC_* encoding, or `None` for any other encoding.
    pub(super) fn icc(
        &mut self,
        encoding: Encoding,
        write: Option<u64>,
        context: &Context,
    ) -> Option<Outcome> {
        let register = Register::decode(encoding)?;
        let direction_ok = match (register.direction(), write.is_some()) {
            (Direction::Both, _) => true,
            (Direction::Read, read_only) => !read_only,
            (Direction::Write, writes) => writes,
        };
        // Encodings Arm leaves without the accessor: the other direction,
        // active-priority registers beyond five priority bits (Arm
        // `NUM_GIC_PRIORITY_BITS < 6`) and NMIAR1 without FEAT_GICv3_NMI.
        let unimplemented = match register {
            Register::ActivePriorities(_, 1) => PRIORITY_BITS < 6,
            Register::ActivePriorities(_, n) => n > 1 && PRIORITY_BITS < 7,
            Register::Nmiar1 => true,
            _ => false,
        };
        if !direction_ok || unimplemented || context.el == 0 {
            return Some(Outcome::Undefined);
        }
        if register == Register::Sre {
            return Some(match write {
                None => Outcome::Read(SRE_EL1_VALUE),
                Some(_) => Outcome::Written(Changes::default()),
            });
        }
        Some(match self.route(register, context) {
            Route::Undefined => Outcome::Undefined,
            Route::Trapped => Outcome::Trapped(Some(2)),
            Route::Virtual => match write {
                None => Outcome::Read(self.virtual_read(register)),
                Some(value) => {
                    self.virtual_write(register, value);
                    Outcome::Written(Changes {
                        interrupts: true,
                        ..Changes::default()
                    })
                }
            },
        })
    }

    /// Arm's accessor order at EL1: the fine-grained IGRPEN trap, then
    /// ICH_HCR_EL2's trap of the class, then HCR_EL2's routing. What
    /// remains, and every access at EL2, reaches the physical interface,
    /// which these cores do not have.
    fn route(&self, register: Register, context: &Context) -> Route {
        if context.el != 1 {
            return Route::Undefined;
        }
        if matches!(register, Register::Igrpen(_)) && context.fine_grained_trap {
            return Route::Trapped;
        }
        let (trap, routing) = match register.class() {
            Class::Group0 => (HCR_TALL0, HCR_FMO),
            Class::Group1 => (HCR_TALL1, HCR_IMO),
            Class::Common | Class::Generate => (HCR_TC, HCR_FMO | HCR_IMO),
        };
        if self.hcr & trap != 0 {
            return Route::Trapped;
        }
        match (register.class(), context.hcr & routing != 0) {
            (_, false) => Route::Undefined,
            (Class::Generate, true) => Route::Trapped,
            (_, true) => Route::Virtual,
        }
    }

    fn virtual_read(&mut self, register: Register) -> u64 {
        match register {
            Register::Iar(group1) => self.acknowledge(group1),
            Register::Hppir(group1) => match self.highest_pending() {
                Some(index) if in_group1(self.list[index]) == group1 => {
                    self.list[index] & INTID_MASK
                }
                _ => SPURIOUS,
            },
            Register::Bpr(false) => u64::from(self.binary_point0()),
            Register::Bpr(true) => u64::from(self.binary_point1()),
            Register::ActivePriorities(group1, _) => self.active_priorities[usize::from(group1)],
            Register::Igrpen(group1) => u64::from(self.group_enabled(group1)),
            Register::Rpr => u64::from(self.running_priority()),
            Register::Pmr => u64::from(self.priority_mask()),
            Register::Ctlr => {
                let bit = |set: bool, bit: u64| if set { bit } else { 0 };
                bit(self.vmcr & VMCR_VCBPR != 0, CTLR_CBPR)
                    | bit(self.vmcr & VMCR_VEOIM != 0, CTLR_EOIMODE)
                    | u64::from(PRIORITY_BITS - 1) << CTLR_PRIBITS_SHIFT
                    | CTLR_SEIS
            }
            // Write-only, unimplemented or not virtual: excluded by `icc`.
            _ => unreachable!("{register:?} has no virtual read"),
        }
    }

    fn virtual_write(&mut self, register: Register, value: u64) {
        let set_field = |vmcr: &mut u64, shift: u32, width: u32, field: u64| {
            let mask = ((1 << width) - 1) << shift;
            *vmcr = *vmcr & !mask | field << shift & mask;
        };
        match register {
            Register::Eoir(group1) => self.end_of_interrupt_write(group1, value & INTID_FIELD),
            Register::Dir => {
                let intid = value & INTID_FIELD;
                if self.vmcr & VMCR_VEOIM != 0 && !SPECIAL.contains(&intid) {
                    self.deactivate(intid, None);
                }
            }
            Register::Bpr(false) => {
                let point = (value & 0b111).max(u64::from(BPR0_MIN));
                set_field(&mut self.vmcr, VMCR_VBPR0_SHIFT, 3, point);
            }
            // With VCBPR, ICV_BPR1_EL1 is BPR0's view and ignores writes.
            Register::Bpr(true) if self.vmcr & VMCR_VCBPR != 0 => {}
            Register::Bpr(true) => {
                let point = (value & 0b111).max(u64::from(BPR1_MIN));
                set_field(&mut self.vmcr, VMCR_VBPR1_SHIFT, 3, point);
            }
            Register::ActivePriorities(group1, _) => {
                self.active_priorities[usize::from(group1)] = value & ACTIVE_PRIORITIES;
            }
            Register::Igrpen(group1) => {
                let bit = if group1 { VMCR_VENG1 } else { VMCR_VENG0 };
                self.vmcr = self.vmcr & !bit | if value & 1 != 0 { bit } else { 0 };
            }
            Register::Pmr => {
                let mask = u64::from(value as u8 & PRIORITY_MASK);
                set_field(&mut self.vmcr, VMCR_VPMR_SHIFT, 8, mask);
            }
            Register::Ctlr => {
                let cbpr = if value & CTLR_CBPR != 0 {
                    VMCR_VCBPR
                } else {
                    0
                };
                let eoimode = if value & CTLR_EOIMODE != 0 {
                    VMCR_VEOIM
                } else {
                    0
                };
                self.vmcr = self.vmcr & !(VMCR_VCBPR | VMCR_VEOIM) | cbpr | eoimode;
            }
            // Read-only, unimplemented or not virtual: excluded by `icc`.
            _ => unreachable!("{register:?} has no virtual write"),
        }
    }

    /// ICV_IAR0_EL1 or ICV_IAR1_EL1.
    fn acknowledge(&mut self, group1: bool) -> u64 {
        let Some(index) = self.highest_pending() else {
            return SPURIOUS;
        };
        let list = self.list[index];
        if in_group1(list) != group1 || !self.sufficient(index) {
            return SPURIOUS;
        }
        self.list[index] = with_state(list, LR_ACTIVE);
        let group_priority = self.group_priority(list_priority(list), group1);
        self.active_priorities[usize::from(group1)] |= 1 << priority::active_bit(group_priority);
        list & INTID_MASK
    }

    /// ICV_EOIR0_EL1 or ICV_EOIR1_EL1 with `intid`.
    fn end_of_interrupt_write(&mut self, group1: bool, intid: u64) {
        if SPECIAL.contains(&intid) {
            return;
        }
        self.drop_priority(group1);
        // EOImode 1 leaves deactivation to ICV_DIR_EL1, except for an LPI,
        // which has no active state to keep.
        if self.vmcr & VMCR_VEOIM != 0 && intid < LPI {
            return;
        }
        self.deactivate(intid, Some(group1));
    }

    /// Clear the highest active priority; of equal ones, the EOI's group's.
    fn drop_priority(&mut self, group1: bool) {
        let lowest = |bits: u64| (bits != 0).then(|| bits.trailing_zeros());
        let [group0_bits, group1_bits] = self.active_priorities;
        let target = match (lowest(group0_bits), lowest(group1_bits)) {
            (None, None) => return,
            (Some(_), None) => 0,
            (None, Some(_)) => 1,
            (Some(a), Some(b)) if a == b => usize::from(group1),
            (Some(a), Some(b)) => usize::from(b < a),
        };
        let bits = &mut self.active_priorities[target];
        *bits &= *bits - 1;
    }

    /// Deactivate the active list register holding `intid` (of `group`, when
    /// given); with none, count the EOI in EOIcount unless it is an LPI's.
    fn deactivate(&mut self, intid: u64, group: Option<bool>) {
        let found = (0..LIST_REGISTERS).find(|&index| {
            let list = self.list[index];
            list & INTID_MASK == intid && state(list) & LR_ACTIVE != 0
        });
        match found {
            Some(index) => {
                let list = self.list[index];
                if group.is_some_and(|group1| in_group1(list) != group1) {
                    return;
                }
                // Active becomes invalid, pending and active becomes pending.
                // A hardware interrupt has no distributor to deactivate.
                self.list[index] = with_state(list, state(list) & LR_PENDING);
            }
            None if intid < LPI => {
                let count = (self.hcr >> HCR_EOICOUNT_SHIFT).wrapping_add(1) & HCR_EOICOUNT_MASK;
                self.hcr = self.hcr & !(HCR_EOICOUNT_MASK << HCR_EOICOUNT_SHIFT)
                    | count << HCR_EOICOUNT_SHIFT;
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{HCR, HCR_EN, LR_EOI, LR_GROUP, LR_HW, LR_PRIORITY_SHIFT, LR_STATE_SHIFT};
    use super::*;
    use crate::machine::registers::Lines;

    const fn icc(crm: u8, op2: u8) -> Encoding {
        Encoding::new(3, 0, 12, crm, op2)
    }

    const IAR0: Encoding = icc(8, 0);
    const EOIR0: Encoding = icc(8, 1);
    const HPPIR0: Encoding = icc(8, 2);
    const BPR0: Encoding = icc(8, 3);
    const AP0R1: Encoding = icc(8, 5);
    const AP1R0: Encoding = icc(9, 0);
    const NMIAR1: Encoding = icc(9, 5);
    const DIR: Encoding = icc(11, 1);
    const RPR: Encoding = icc(11, 3);
    const SGI1R: Encoding = icc(11, 5);
    const IAR1: Encoding = icc(12, 0);
    const EOIR1: Encoding = icc(12, 1);
    const HPPIR1: Encoding = icc(12, 2);
    const BPR1: Encoding = icc(12, 3);
    const CTLR: Encoding = icc(12, 4);
    const SRE: Encoding = icc(12, 5);
    const IGRPEN1: Encoding = icc(12, 7);
    const PMR: Encoding = Encoding::new(3, 0, 4, 6, 0);
    const GUEST: Context = Context {
        el: 1,
        hcr: HCR_FMO | HCR_IMO,
        nested: false,
        fine_grained_trap: false,
    };
    const HOST: Context = Context { el: 2, ..GUEST };

    fn lr(state: u64, group1: bool, priority: u8, intid: u64) -> u64 {
        state << LR_STATE_SHIFT
            | if group1 { LR_GROUP } else { 0 }
            | u64::from(priority) << LR_PRIORITY_SHIFT
            | intid
    }

    /// An interface with En set, both groups enabled and no priority mask,
    /// holding `lists` from LR0 on.
    fn interface(lists: &[u64]) -> CpuInterface {
        let mut gic = CpuInterface {
            hcr: HCR_EN,
            ..CpuInterface::default()
        };
        gic.set_vmcr(VMCR_VENG0 | VMCR_VENG1 | 0xff << VMCR_VPMR_SHIFT);
        gic.list[..lists.len()].copy_from_slice(lists);
        gic
    }

    fn read(gic: &mut CpuInterface, encoding: Encoding) -> u64 {
        match gic.access(encoding, None, &GUEST) {
            Some(Outcome::Read(value)) => value,
            other => panic!("{encoding:?}: {other:?}"),
        }
    }

    fn write(gic: &mut CpuInterface, encoding: Encoding, value: u64) {
        assert!(
            matches!(
                gic.access(encoding, Some(value), &GUEST),
                Some(Outcome::Written(_))
            ),
            "{encoding:?}"
        );
    }

    #[test]
    fn a_virtual_interrupt_is_signaled_acknowledged_preempted_and_completed() {
        let mut gic = interface(&[
            lr(LR_PENDING, true, 0xa0, 40),
            lr(LR_PENDING, true, 0x80, 41),
        ]);
        // The higher priority (lower value) is signaled first, as vIRQ.
        let irq = Lines {
            irq: true,
            fiq: false,
        };
        assert_eq!(gic.signals(), irq);
        assert_eq!(read(&mut gic, HPPIR1), 41);
        assert_eq!(read(&mut gic, HPPIR0), SPURIOUS);
        assert_eq!(read(&mut gic, IAR0), SPURIOUS, "the other group");
        assert_eq!(read(&mut gic, IAR1), 41);
        assert_eq!(state(gic.list[1]), LR_ACTIVE);
        // Group 1 preempts in bits 7:BPR1 (BPR1 3: 0x80 is level 16).
        assert_eq!(gic.active_priorities, [0, 1 << 16]);
        assert_eq!(read(&mut gic, RPR), 0x80);
        // 0xa0 cannot preempt 0x80: nothing is signaled or acknowledged.
        assert_eq!(gic.signals(), Lines::default());
        assert_eq!(read(&mut gic, IAR1), SPURIOUS);
        assert_eq!(state(gic.list[0]), LR_PENDING);
        // EOImode 0: the EOI drops the priority and deactivates LR1.
        write(&mut gic, EOIR1, 41);
        assert_eq!(state(gic.list[1]), 0);
        assert_eq!(read(&mut gic, RPR), u64::from(priority::IDLE));
        assert_eq!(gic.signals(), irq);
        assert_eq!(read(&mut gic, IAR1), 40);
        // A priority mask at or above the pending priority hides it.
        let mut masked = interface(&[lr(LR_PENDING, true, 0xa0, 40)]);
        write(&mut masked, PMR, 0xa0);
        assert_eq!(read(&mut masked, PMR), 0xa0);
        assert_eq!(masked.signals(), Lines::default());
        assert_eq!(read(&mut masked, IAR1), SPURIOUS);
        write(&mut masked, PMR, 0xff);
        assert_eq!(read(&mut masked, PMR), 0xf8, "five priority bits");
        // A disabled group is neither signaled nor reported.
        write(&mut masked, IGRPEN1, 0);
        assert_eq!(read(&mut masked, IGRPEN1), 0);
        assert_eq!(read(&mut masked, HPPIR1), SPURIOUS);
        assert_eq!(masked.signals(), Lines::default());
        // Group 0 is signaled as vFIQ; without En nothing is signaled,
        // though the registers still work.
        let mut disabled = interface(&[lr(LR_PENDING, false, 0, 7)]);
        assert_eq!(
            disabled.signals(),
            Lines {
                irq: false,
                fiq: true
            }
        );
        disabled.hcr = 0;
        assert_eq!(disabled.signals(), Lines::default());
        assert_eq!(read(&mut disabled, IAR0), 7);
    }

    #[test]
    fn eoi_mode_one_splits_priority_drop_from_deactivation() {
        let mut gic = interface(&[lr(LR_PENDING, false, 0x40, 5)]);
        write(&mut gic, CTLR, CTLR_EOIMODE);
        assert_eq!(read(&mut gic, CTLR), CTLR_EOIMODE | 4 << 8 | CTLR_SEIS);
        assert_eq!(read(&mut gic, IAR0), 5);
        // Group 0 preempts in bits 7:BPR0+1 (BPR0 2: 0x40 is level 8).
        assert_eq!(gic.active_priorities, [1 << 8, 0]);
        write(&mut gic, EOIR0, 5);
        assert_eq!(gic.active_priorities, [0, 0]);
        assert_eq!(state(gic.list[0]), LR_ACTIVE, "still active");
        write(&mut gic, DIR, 5);
        assert_eq!(state(gic.list[0]), 0);
        // A deactivation that finds no active list register counts in
        // EOIcount, except for an LPI.
        write(&mut gic, DIR, 6);
        write(&mut gic, DIR, LPI);
        assert_eq!(gic.hcr >> HCR_EOICOUNT_SHIFT, 1);
        // With EOImode 0 DIR is ignored (its CONSTRAINED UNPREDICTABLE
        // choice), and an EOI of the other group's interrupt only drops.
        let mut other = interface(&[lr(LR_ACTIVE, true, 0x40, 9)]);
        other.active_priorities = [0, 1 << 8];
        write(&mut other, DIR, 9);
        write(&mut other, EOIR0, 9);
        assert_eq!(other.active_priorities, [0, 0]);
        assert_eq!(state(other.list[0]), LR_ACTIVE);
        assert_eq!(other.hcr >> HCR_EOICOUNT_SHIFT, 0);
        // Deactivating an interrupt that asked for it raises the EOI
        // maintenance interrupt; a hardware one has no distributor to tell.
        let mut eoi = interface(&[
            lr(LR_ACTIVE, true, 0, 3) | LR_EOI,
            lr(LR_ACTIVE, true, 0, 4) | LR_HW,
        ]);
        eoi.active_priorities = [0, 0b11];
        assert!(!eoi.maintenance_asserted());
        write(&mut eoi, EOIR1, 3);
        write(&mut eoi, EOIR1, 4);
        assert_eq!(state(eoi.list[1]), 0);
        assert_eq!(eoi.end_of_interrupt(), 1);
        assert!(eoi.maintenance_asserted());
        // Special INTIDs change nothing.
        eoi.active_priorities = [0, 1];
        write(&mut eoi, EOIR1, 1023);
        assert_eq!(eoi.active_priorities, [0, 1]);
    }

    #[test]
    fn binary_points_have_minima_and_cbpr_shares_bpr0() {
        let mut gic = interface(&[]);
        write(&mut gic, BPR0, 0);
        write(&mut gic, BPR1, 0);
        assert_eq!((read(&mut gic, BPR0), read(&mut gic, BPR1)), (2, 3));
        write(&mut gic, BPR0, 6);
        write(&mut gic, CTLR, CTLR_CBPR);
        // ICV_BPR1_EL1 reads BPR0 + 1, at most 7, and ignores writes.
        assert_eq!(read(&mut gic, BPR1), 7);
        write(&mut gic, BPR1, 4);
        assert_eq!(read(&mut gic, BPR1), 7);
        assert_eq!(gic.vmcr_field(VMCR_VBPR1_SHIFT, 3), 3);
        // Group 1 then preempts by BPR0 6: 0xc0 has group priority 0x80.
        gic.list[0] = lr(LR_PENDING, true, 0xc0, 12);
        assert_eq!(read(&mut gic, IAR1), 12);
        assert_eq!(gic.active_priorities, [0, 1 << 16]);
    }

    #[test]
    fn el1_accesses_trap_redirect_or_are_undefined() {
        let mut gic = interface(&[]);
        // ICH_HCR_EL2.TALL1, TALL0 and TC trap their classes to EL2.
        for (trap, encoding) in [
            (HCR_TALL1, IAR1),
            (HCR_TALL0, BPR0),
            (HCR_TC, PMR),
            (HCR_TC, SGI1R),
        ] {
            gic.hcr = HCR_EN | trap;
            let write = (encoding == SGI1R).then_some(0);
            assert_eq!(
                gic.access(encoding, write, &GUEST),
                Some(Outcome::Trapped(Some(2))),
                "{encoding:?}"
            );
        }
        gic.hcr = HCR_EN;
        // FMO alone reaches the group 0 and common registers, not group 1.
        let fmo = Context {
            hcr: HCR_FMO,
            ..GUEST
        };
        assert!(matches!(
            gic.access(PMR, None, &fmo),
            Some(Outcome::Read(_))
        ));
        assert!(matches!(
            gic.access(BPR0, None, &fmo),
            Some(Outcome::Read(_))
        ));
        assert_eq!(gic.access(IAR1, None, &fmo), Some(Outcome::Undefined));
        // The SGI registers trap under either routing bit.
        assert_eq!(
            gic.access(SGI1R, Some(0), &fmo),
            Some(Outcome::Trapped(Some(2)))
        );
        // The fine-grained trap of the group enables comes first.
        let fine = Context {
            fine_grained_trap: true,
            ..GUEST
        };
        assert_eq!(
            gic.access(IGRPEN1, None, &fine),
            Some(Outcome::Trapped(Some(2)))
        );
        // Without IMO and FMO, at EL2 and at EL0 the physical interface is
        // absent.
        let physical = Context { hcr: 0, ..GUEST };
        let el0 = Context { el: 0, ..GUEST };
        for context in [&physical, &HOST, &el0] {
            assert_eq!(gic.access(PMR, None, context), Some(Outcome::Undefined));
            assert_eq!(
                gic.access(SGI1R, Some(0), context),
                Some(Outcome::Undefined)
            );
        }
        // Wrong directions, the active-priority registers beyond five
        // priority bits and NMIAR1 without FEAT_GICv3_NMI are UNDEFINED.
        assert_eq!(gic.access(IAR1, Some(0), &GUEST), Some(Outcome::Undefined));
        assert_eq!(gic.access(EOIR1, None, &GUEST), Some(Outcome::Undefined));
        assert_eq!(gic.access(AP0R1, None, &GUEST), Some(Outcome::Undefined));
        assert_eq!(gic.access(NMIAR1, None, &GUEST), Some(Outcome::Undefined));
        write(&mut gic, AP1R0, u64::MAX);
        assert_eq!(read(&mut gic, AP1R0), 0xffff_ffff);
        // ICC_SRE_EL1 reads SRE, DFB and DIB at EL1 and EL2, without IMO.
        for context in [&physical, &HOST] {
            assert_eq!(gic.access(SRE, None, context), Some(Outcome::Read(0b111)));
            assert!(matches!(
                gic.access(SRE, Some(0), context),
                Some(Outcome::Written(_))
            ));
        }
        assert_eq!(gic.access(HCR, None, &GUEST), Some(Outcome::Undefined));
        assert_eq!(
            gic.access(Encoding::new(3, 0, 12, 0, 0), None, &GUEST),
            None,
            "VBAR_EL1"
        );
    }
}
