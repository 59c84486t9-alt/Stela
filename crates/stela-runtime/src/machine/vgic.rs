//! Apple's GICv3 virtual CPU interface of one PE: the `ICH_*_EL2` registers,
//! the `ICV_*` registers EL1 reaches through the `ICC_*` encodings, the
//! virtual IRQ and FIQ it signals and its maintenance interrupt, without the
//! physical `ICC_*` interface or a distributor, which the AIC replaces.
//!
//! M1 and M2 cores implement the virtual half of the GICv3 CPU interface
//! only. Their ID_AA64PFR0_EL1.GIC reads 0 (Linux 5163373a "KVM: arm64:
//! vgic-v3: Consistently populate ID_AA64PFR0_EL1.GIC": the M1 does not
//! advertise it, so KVM forces it for guests). Linux `irq-apple-aic.c`
//! describes the interface to KVM as a GICv3 without hardware deactivation or
//! a maskable maintenance interrupt (`no_hw_deactivation`,
//! `no_maint_irq_mask`), clears ICH_HCR_EL2.En on every PE at EL2, and finds
//! the maintenance interrupt in its IRQ handler by reading ICH_MISR_EL2 while
//! En is set: it arrives as the core's IRQ, with no AIC event. KVM's
//! `broken_seis[]` lists M1 and M2 as "not-quite-a-vgic" whose ICH_VTR_EL2
//! reports SEIS without it working. KVM reads and writes ICC_SRE_EL1 at EL2
//! on every host (`__vgic_v3_get_gic_config`) and finds no GICv2 view, so
//! ICC_SRE_EL1.SRE is RAO/WI; DFB and DIB are too, and ICC_SRE_EL2 reads
//! SRE, DFB, DIB and Enable as one (the GICv3 configuration without legacy
//! operation; inference, since nothing on these cores reads it).
//!
//! The 26A434 kernelcache uses ICH_HCR_EL2 in every exception path
//! (`0xfffffe000bb9d9d0`), ICH_VMCR_EL2, ICH_MISR_EL2, ICH_ELRSR_EL2,
//! ICH_AP0R0_EL2, ICH_AP1R0_EL2 and exactly ICH_LR0..7_EL2 in its vCPU
//! switch (`0xfffffe000bd9eb0c`, `0xfffffe000bda24d8`), and stores
//! ICH_VTR_EL2 per vCPU without decoding it (`0xfffffe000bd9e54c`). So
//! ICH_VTR_EL2 reports eight list registers (ListRegs 7) and five preemption
//! and priority bits (PREbits and PRIbits 4, one active-priority register per
//! group), and SEIS. It reports 16-bit INTIDs (IDbits 0), no Aff3 (A3V 0),
//! no TDIR (TDS 0) and no direct injection (nV4 1, DVIM 0): direct injection
//! needs a GICv4 redistributor, which the AIC does not have. Those values
//! beyond the kernel's use are inferences pending hardware.
//!
//! Everything else follows Arm's GICv3 architecture: ICH_MISR_EL2,
//! ICH_EISR_EL2 and ICH_ELRSR_EL2 from the list registers and controls, and
//! acknowledgement, priority drop and deactivation in `icc`. Deactivating a
//! hardware (HW 1) list register deactivates no physical interrupt, since
//! there is no distributor. State resets to 0 apart from the RES1 VFIQEn
//! and the binary point minima (inference).
use super::registers::{Changes, Lines, Outcome};
use priority::{BPR_MAX, BPR0_MIN, BPR1_MIN, PREEMPTION_BITS, PRIORITY_BITS, PRIORITY_MASK};
use stela_compiler::aarch64::system::registers::Encoding;

mod icc;
mod priority;

pub use icc::Context;

const fn ich(crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, 4, 12, crm, op2)
}

const AP0R0: Encoding = ich(8, 0);
const AP1R0: Encoding = ich(9, 0);
const SRE_EL2: Encoding = ich(9, 5);
const HCR: Encoding = ich(11, 0);
const VTR: Encoding = ich(11, 1);
const MISR: Encoding = ich(11, 2);
const EISR: Encoding = ich(11, 3);
const ELRSR: Encoding = ich(11, 5);
const VMCR: Encoding = ich(11, 7);
const LIST_REGISTERS: usize = 8;

const VTR_NV4: u64 = 1 << 20;
const VTR_SEIS: u64 = 1 << 22;
const VTR_PREBITS_SHIFT: u32 = 26;
const VTR_PRIBITS_SHIFT: u32 = 29;
/// ListRegs 7, nV4, SEIS, PREbits 4, PRIbits 4.
const VTR_VALUE: u64 = (LIST_REGISTERS as u64 - 1)
    | VTR_NV4
    | VTR_SEIS
    | ((PREEMPTION_BITS - 1) as u64) << VTR_PREBITS_SHIFT
    | ((PRIORITY_BITS - 1) as u64) << VTR_PRIBITS_SHIFT;

const HCR_EN: u64 = 1 << 0;
const HCR_UIE: u64 = 1 << 1;
const HCR_LRENPIE: u64 = 1 << 2;
const HCR_NPIE: u64 = 1 << 3;
const HCR_VGRP0EIE: u64 = 1 << 4;
const HCR_VGRP0DIE: u64 = 1 << 5;
const HCR_VGRP1EIE: u64 = 1 << 6;
const HCR_VGRP1DIE: u64 = 1 << 7;
const HCR_TC: u64 = 1 << 10;
const HCR_TALL0: u64 = 1 << 11;
const HCR_TALL1: u64 = 1 << 12;
const HCR_TSEI: u64 = 1 << 13;
const HCR_EOICOUNT_SHIFT: u32 = 27;
const HCR_EOICOUNT_MASK: u64 = 0x1f;
/// TDIR (no TDS), DVIM (no DVIM), vSGIEOICount (no GICv4.1) and bit 9 are
/// RES0. TSEI is stored: no locally generated SEI exists for it to trap.
const HCR_WRITABLE: u64 =
    0xff | HCR_TC | HCR_TALL0 | HCR_TALL1 | HCR_TSEI | HCR_EOICOUNT_MASK << HCR_EOICOUNT_SHIFT;

const VMCR_VENG0: u64 = 1 << 0;
const VMCR_VENG1: u64 = 1 << 1;
/// RES1 while ICC_SRE_EL1.SRE is always 1: group 0 is signaled as vFIQ.
const VMCR_VFIQEN: u64 = 1 << 3;
const VMCR_VCBPR: u64 = 1 << 4;
const VMCR_VEOIM: u64 = 1 << 9;
const VMCR_VBPR1_SHIFT: u32 = 18;
const VMCR_VBPR0_SHIFT: u32 = 21;
const VMCR_VPMR_SHIFT: u32 = 24;
const VMCR_RESET: u64 =
    VMCR_VFIQEN | (BPR0_MIN as u64) << VMCR_VBPR0_SHIFT | (BPR1_MIN as u64) << VMCR_VBPR1_SHIFT;

const LR_STATE_SHIFT: u32 = 62;
const LR_PENDING: u64 = 0b01;
const LR_ACTIVE: u64 = 0b10;
const LR_HW: u64 = 1 << 61;
const LR_GROUP: u64 = 1 << 60;
const LR_PRIORITY_SHIFT: u32 = 48;
const LR_PINTID_SHIFT: u32 = 32;
/// With HW set, the physical INTID: 10 bits, as ICC_CTLR_EL1.ExtRange 0
/// makes bits 44:42 RES0.
const LR_PINTID_MASK: u64 = 0x3ff;
/// With HW clear, bit 41 asks for a maintenance interrupt at deactivation;
/// bits 44:42 and 40:32 are RES0.
const LR_EOI: u64 = 1 << 41;
/// vINTID's implemented bits (IDbits 0); bits 31:16 are RES0.
const INTID_MASK: u64 = 0xffff;
/// 32 active priorities per group.
const ACTIVE_PRIORITIES: u64 = 0xffff_ffff;

/// One PE's virtual CPU interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuInterface {
    hcr: u64,
    vmcr: u64,
    /// ICH_AP0R0_EL2 and ICH_AP1R0_EL2.
    active_priorities: [u64; 2],
    list: [u64; LIST_REGISTERS],
}

impl Default for CpuInterface {
    fn default() -> Self {
        Self {
            hcr: 0,
            vmcr: VMCR_RESET,
            active_priorities: [0; 2],
            list: [0; LIST_REGISTERS],
        }
    }
}

/// The list register ICH_LR<n>_EL2 names: CRm 12, op2 n, for n below 8.
fn list_index(encoding: Encoding) -> Option<usize> {
    let index = usize::from(encoding.op2());
    ((
        encoding.op0(),
        encoding.op1(),
        encoding.crn(),
        encoding.crm(),
    ) == (3, 4, 12, 12))
        .then_some(index)
        .filter(|&index| index < LIST_REGISTERS)
}

/// Whether `encoding` is in the `ICH_*_EL2` space (op1 4, CRn 12, CRm 8-13),
/// which also holds ICC_SRE_EL2.
fn hypervisor_space(encoding: Encoding) -> bool {
    (encoding.op0(), encoding.op1(), encoding.crn()) == (3, 4, 12)
        && (8..=13).contains(&encoding.crm())
}

fn state(list: u64) -> u64 {
    list >> LR_STATE_SHIFT
}

fn with_state(list: u64, state: u64) -> u64 {
    list & !(0b11 << LR_STATE_SHIFT) | state << LR_STATE_SHIFT
}

fn priority(list: u64) -> u8 {
    (list >> LR_PRIORITY_SHIFT) as u8
}

fn in_group1(list: u64) -> bool {
    list & LR_GROUP != 0
}

/// A list register as written, with its RES0 bits clear.
fn list_value(value: u64) -> u64 {
    let physical = if value & LR_HW != 0 {
        LR_PINTID_MASK << LR_PINTID_SHIFT
    } else {
        LR_EOI
    };
    value
        & (0b11 << LR_STATE_SHIFT
            | LR_HW
            | LR_GROUP
            | u64::from(PRIORITY_MASK) << LR_PRIORITY_SHIFT
            | physical
            | INTID_MASK)
}

impl CpuInterface {
    fn vmcr_field(&self, shift: u32, width: u32) -> u8 {
        (self.vmcr >> shift & ((1 << width) - 1)) as u8
    }

    fn priority_mask(&self) -> u8 {
        self.vmcr_field(VMCR_VPMR_SHIFT, 8)
    }

    fn binary_point0(&self) -> u8 {
        self.vmcr_field(VMCR_VBPR0_SHIFT, 3)
    }

    /// ICV_BPR1_EL1: VBPR1, or with VCBPR one more than VBPR0, at most 7.
    fn binary_point1(&self) -> u8 {
        if self.vmcr & VMCR_VCBPR != 0 {
            (self.binary_point0() + 1).min(BPR_MAX)
        } else {
            self.vmcr_field(VMCR_VBPR1_SHIFT, 3)
        }
    }

    /// The group priority of `priority` in its group: group 0's BPR0, and
    /// group 1's BPR1 (whose group priority field is bits 7:BPR1) unless
    /// VCBPR makes it share BPR0.
    fn group_priority(&self, priority: u8, group1: bool) -> u8 {
        if group1 && self.vmcr & VMCR_VCBPR == 0 {
            priority::group_bits(priority, self.binary_point1().saturating_sub(1))
        } else {
            priority::group_bits(priority, self.binary_point0())
        }
    }

    fn group_enabled(&self, group1: bool) -> bool {
        self.vmcr & if group1 { VMCR_VENG1 } else { VMCR_VENG0 } != 0
    }

    fn running_priority(&self) -> u8 {
        priority::running(self.active_priorities)
    }

    /// The highest-priority pending list register of an enabled group, the
    /// lowest-numbered of equal priorities.
    fn highest_pending(&self) -> Option<usize> {
        (0..LIST_REGISTERS)
            .filter(|&index| {
                let list = self.list[index];
                state(list) == LR_PENDING && self.group_enabled(in_group1(list))
            })
            .min_by_key(|&index| priority(self.list[index]))
    }

    /// Whether list register `index` has sufficient priority to be signaled
    /// or acknowledged: higher than the priority mask, and its group
    /// priority higher than the running priority.
    fn sufficient(&self, index: usize) -> bool {
        let list = self.list[index];
        let priority = priority(list);
        priority < self.priority_mask()
            && self.group_priority(priority, in_group1(list)) < self.running_priority()
    }

    /// The virtual interrupts the interface signals to the PE while
    /// ICH_HCR_EL2.En is set: group 1 as vIRQ and group 0 as vFIQ (VFIQEn
    /// is RES1). HCR_EL2.IMO and FMO decide whether EL1 takes them.
    pub fn signals(&self) -> Lines {
        if self.hcr & HCR_EN == 0 {
            return Lines::default();
        }
        match self.highest_pending() {
            Some(index) if self.sufficient(index) => {
                let group1 = in_group1(self.list[index]);
                Lines {
                    irq: group1,
                    fiq: !group1,
                }
            }
            _ => Lines::default(),
        }
    }

    /// The maintenance interrupt: asserted on the core's IRQ while
    /// ICH_HCR_EL2.En is set and ICH_MISR_EL2 holds a condition.
    pub fn maintenance_asserted(&self) -> bool {
        self.hcr & HCR_EN != 0 && self.maintenance() != 0
    }

    /// One bit per list register that satisfies `test`.
    fn select(&self, test: impl Fn(u64) -> bool) -> u64 {
        (0..LIST_REGISTERS)
            .filter(|&index| test(self.list[index]))
            .fold(0, |bits, index| bits | 1 << index)
    }

    /// ICH_EISR_EL2: invalid list registers that ask for an end-of-interrupt
    /// maintenance interrupt.
    fn end_of_interrupt(&self) -> u64 {
        self.select(|list| state(list) == 0 && list & LR_HW == 0 && list & LR_EOI != 0)
    }

    /// ICH_ELRSR_EL2: list registers free for a new interrupt.
    fn empty(&self) -> u64 {
        self.select(|list| state(list) == 0 && (list & LR_HW != 0 || list & LR_EOI == 0))
    }

    /// ICH_MISR_EL2: the maintenance conditions, each gated by its enable.
    fn maintenance(&self) -> u64 {
        let hcr = self.hcr;
        let valid = self.select(|list| state(list) != 0).count_ones();
        let pending = self.select(|list| state(list) == LR_PENDING) != 0;
        let group0 = self.vmcr & VMCR_VENG0 != 0;
        let group1 = self.vmcr & VMCR_VENG1 != 0;
        [
            self.end_of_interrupt() != 0,
            hcr & HCR_UIE != 0 && valid <= 1,
            hcr & HCR_LRENPIE != 0 && (hcr >> HCR_EOICOUNT_SHIFT) & HCR_EOICOUNT_MASK != 0,
            hcr & HCR_NPIE != 0 && !pending,
            hcr & HCR_VGRP0EIE != 0 && group0,
            hcr & HCR_VGRP0DIE != 0 && !group0,
            hcr & HCR_VGRP1EIE != 0 && group1,
            hcr & HCR_VGRP1DIE != 0 && !group1,
        ]
        .into_iter()
        .enumerate()
        .fold(0, |bits, (bit, set)| bits | u64::from(set) << bit)
    }

    /// ICH_VMCR_EL2 as written: VFIQEn RES1, VAckCtl and the reserved bits
    /// RES0, the priority mask's implemented bits, and each binary point at
    /// least its minimum.
    fn set_vmcr(&mut self, value: u64) {
        let point = |shift: u32, minimum: u8| {
            u64::from(((value >> shift & 0b111) as u8).max(minimum)) << shift
        };
        self.vmcr = value & (VMCR_VENG0 | VMCR_VENG1 | VMCR_VCBPR | VMCR_VEOIM)
            | VMCR_VFIQEN
            | point(VMCR_VBPR0_SHIFT, BPR0_MIN)
            | point(VMCR_VBPR1_SHIFT, BPR1_MIN)
            | u64::from((value >> VMCR_VPMR_SHIFT) as u8 & PRIORITY_MASK) << VMCR_VPMR_SHIFT;
    }

    /// An ICH_*_EL2 access at EL2.
    fn hypervisor(&mut self, encoding: Encoding, write: Option<u64>) -> Outcome {
        let Some(value) = write else {
            return match encoding {
                HCR => Outcome::Read(self.hcr),
                VTR => Outcome::Read(VTR_VALUE),
                MISR => Outcome::Read(self.maintenance()),
                EISR => Outcome::Read(self.end_of_interrupt()),
                ELRSR => Outcome::Read(self.empty()),
                VMCR => Outcome::Read(self.vmcr),
                AP0R0 => Outcome::Read(self.active_priorities[0]),
                AP1R0 => Outcome::Read(self.active_priorities[1]),
                SRE_EL2 => Outcome::Read(icc::SRE_EL2_VALUE),
                _ => match list_index(encoding) {
                    Some(index) => Outcome::Read(self.list[index]),
                    // Active-priority and list registers beyond the
                    // implemented ones.
                    None => Outcome::Undefined,
                },
            };
        };
        match encoding {
            HCR => self.hcr = value & HCR_WRITABLE,
            VMCR => self.set_vmcr(value),
            AP0R0 => self.active_priorities[0] = value & ACTIVE_PRIORITIES,
            AP1R0 => self.active_priorities[1] = value & ACTIVE_PRIORITIES,
            // RAO/WI.
            SRE_EL2 => {}
            _ => match list_index(encoding) {
                Some(index) => self.list[index] = list_value(value),
                // The read-only status registers and unimplemented ones.
                None => return Outcome::Undefined,
            },
        }
        Outcome::Written(Changes {
            interrupts: true,
            ..Changes::default()
        })
    }

    /// An MRS (`write` `None`) or MSR of `encoding` that this interface
    /// answers before the generated accessors, which follow the profile's
    /// absent FEAT_GICv3: the ICH_* space and ICC_SRE_EL2 at EL2, and the
    /// ICC_* encodings (`icc`). `None` for any other encoding.
    pub fn access(
        &mut self,
        encoding: Encoding,
        write: Option<u64>,
        context: &Context,
    ) -> Option<Outcome> {
        if hypervisor_space(encoding) {
            return Some(match context.el {
                2 => self.hypervisor(encoding, write),
                // Under HCR_EL2.NV an EL1 access to an EL2 register traps.
                1 if context.nested => Outcome::Trapped(Some(2)),
                _ => Outcome::Undefined,
            });
        }
        self.icc(encoding, write, context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EL2: Context = Context {
        el: 2,
        hcr: 0,
        nested: false,
        fine_grained_trap: false,
    };

    fn read(gic: &mut CpuInterface, encoding: Encoding) -> Option<Outcome> {
        gic.access(encoding, None, &EL2)
    }

    fn write(gic: &mut CpuInterface, encoding: Encoding, value: u64) {
        assert!(matches!(
            gic.access(encoding, Some(value), &EL2),
            Some(Outcome::Written(_))
        ));
    }

    #[test]
    fn the_kernels_vcpu_switch_round_trips_and_status_follows_the_list() {
        let mut gic = CpuInterface::default();
        assert_eq!(read(&mut gic, VTR), Some(Outcome::Read(0x9050_0007)));
        let el1 = Context { el: 1, ..EL2 };
        assert_eq!(gic.access(HCR, None, &el1), Some(Outcome::Undefined));
        let nested = Context {
            nested: true,
            ..el1
        };
        assert_eq!(
            gic.access(HCR, None, &nested),
            Some(Outcome::Trapped(Some(2)))
        );
        assert_eq!(
            read(&mut gic, Encoding::new(3, 0, 12, 1, 0)),
            None,
            "ISR_EL1"
        );
        // Every list register free, no maintenance condition.
        assert_eq!(read(&mut gic, ELRSR), Some(Outcome::Read(0xff)));
        assert_eq!(read(&mut gic, MISR), Some(Outcome::Read(0)));
        // A pending interrupt in LR3, an invalid EOI-requesting LR5.
        write(&mut gic, ich(12, 3), LR_PENDING << LR_STATE_SHIFT | 27);
        write(&mut gic, ich(12, 5), LR_EOI | 30);
        assert_eq!(
            read(&mut gic, ELRSR),
            Some(Outcome::Read(0xff & !(1 << 3 | 1 << 5)))
        );
        assert_eq!(read(&mut gic, EISR), Some(Outcome::Read(1 << 5)));
        write(&mut gic, HCR, HCR_UIE | HCR_NPIE | HCR_VGRP1DIE);
        write(&mut gic, VMCR, VMCR_VENG1);
        // EOI, and underflow with one valid list register.
        assert_eq!(read(&mut gic, MISR), Some(Outcome::Read(0b11)));
        // The maintenance interrupt needs En.
        assert!(!gic.maintenance_asserted());
        write(&mut gic, HCR, HCR_EN | HCR_UIE);
        assert!(gic.maintenance_asserted());
        write(&mut gic, AP1R0, 1 << 4);
        assert_eq!(read(&mut gic, AP1R0), Some(Outcome::Read(1 << 4)));
        // Unimplemented registers and read-only writes.
        assert_eq!(read(&mut gic, ich(13, 0)), Some(Outcome::Undefined), "LR8");
        assert_eq!(read(&mut gic, ich(8, 1)), Some(Outcome::Undefined), "AP0R1");
        assert_eq!(gic.access(VTR, Some(0), &EL2), Some(Outcome::Undefined));
    }

    #[test]
    fn writes_keep_only_the_implemented_bits() {
        let mut gic = CpuInterface::default();
        // VFIQEn RES1, VAckCtl RES0, VPMR's three low bits RES0, and each
        // binary point raised to its minimum.
        assert_eq!(read(&mut gic, VMCR), Some(Outcome::Read(VMCR_RESET)));
        write(
            &mut gic,
            VMCR,
            !(0b111 << VMCR_VBPR0_SHIFT | 0b111 << VMCR_VBPR1_SHIFT),
        );
        assert_eq!(
            read(&mut gic, VMCR),
            Some(Outcome::Read(
                0xf8 << VMCR_VPMR_SHIFT
                    | 2 << VMCR_VBPR0_SHIFT
                    | 3 << VMCR_VBPR1_SHIFT
                    | VMCR_VEOIM
                    | VMCR_VCBPR
                    | VMCR_VFIQEN
                    | VMCR_VENG1
                    | VMCR_VENG0
            ))
        );
        // ICH_HCR_EL2: TDIR, DVIM, vSGIEOICount and bit 9 are RES0.
        write(&mut gic, HCR, u64::MAX);
        assert_eq!(read(&mut gic, HCR), Some(Outcome::Read(0xf800_3cff)));
        // A list register: priority bits 50:48, vINTID bits 31:16 and, with
        // HW clear, every pINTID bit but EOI are RES0.
        write(&mut gic, ich(12, 0), !LR_HW);
        assert_eq!(
            read(&mut gic, ich(12, 0)),
            Some(Outcome::Read(0xd0f8_0200_0000_ffff))
        );
        // With HW set, pINTID keeps bits 41:32.
        write(&mut gic, ich(12, 1), u64::MAX);
        assert_eq!(
            read(&mut gic, ich(12, 1)),
            Some(Outcome::Read(0xf0f8_03ff_0000_ffff))
        );
        write(&mut gic, AP0R0, u64::MAX);
        assert_eq!(read(&mut gic, AP0R0), Some(Outcome::Read(0xffff_ffff)));
        // ICC_SRE_EL2 reads SRE, DFB, DIB and Enable and ignores writes.
        write(&mut gic, SRE_EL2, 0);
        assert_eq!(read(&mut gic, SRE_EL2), Some(Outcome::Read(0xf)));
    }
}
