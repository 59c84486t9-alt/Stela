//! Apple's GICv3 virtual CPU interface: the `ICH_*_EL2` registers of one PE,
//! without the physical `ICC_*` interface or a distributor, which the AIC
//! replaces.
//!
//! M1 and M2 cores implement the hypervisor half of the GICv3 CPU interface
//! only: Linux `irq-apple-aic.c` clears ICH_HCR_EL2.En on every PE at EL2 and
//! takes the vGIC maintenance interrupt through the AIC, and KVM's
//! `broken_seis[]` lists M1 and M2 as "not-quite-a-vgic" whose ICH_VTR_EL2
//! reports SEIS without it working. The architectural FEAT_GICv3 would bring
//! the physical interface too, so this module answers the `ICH_*` encodings
//! itself and every `ICC_*` encoding stays UNDEFINED.
//!
//! The 26A434 kernelcache uses ICH_HCR_EL2 in every exception path
//! (`0xfffffe000bb9d9d0`), ICH_VMCR_EL2, ICH_MISR_EL2, ICH_ELRSR_EL2,
//! ICH_AP0R0_EL2, ICH_AP1R0_EL2 and exactly ICH_LR0..7_EL2 in its vCPU
//! switch (`0xfffffe000bd9eb0c`, `0xfffffe000bda24d8`), and stores
//! ICH_VTR_EL2 per vCPU without decoding it (`0xfffffe000bd9e54c`). So
//! ICH_VTR_EL2 reports eight list registers (ListRegs 7) and five preemption
//! bits (PREbits 4, one active-priority register per group) with as many
//! priority bits, and SEIS; IDbits, A3V, nV4 and TDS read 0. Those values
//! beyond the kernel's use are inferences pending hardware.
//!
//! ICH_MISR_EL2, ICH_EISR_EL2 and ICH_ELRSR_EL2 follow from the list
//! registers and controls as Arm's GICv3 architecture defines them. Registers
//! reset to 0 (inference). Delivering virtual interrupts, which
//! ICH_HCR_EL2.En enables, is not modelled: setting it stops.
use super::registers::{Changes, Outcome, Refusal};
use stela_compiler::aarch64::system::registers::Encoding;

const fn ich(crm: u8, op2: u8) -> Encoding {
    Encoding::new(3, 4, 12, crm, op2)
}

const AP0R0: Encoding = ich(8, 0);
const AP1R0: Encoding = ich(9, 0);
const HCR: Encoding = ich(11, 0);
const VTR: Encoding = ich(11, 1);
const MISR: Encoding = ich(11, 2);
const EISR: Encoding = ich(11, 3);
const ELRSR: Encoding = ich(11, 5);
const VMCR: Encoding = ich(11, 7);
const LIST_REGISTERS: usize = 8;

/// ListRegs 7, PREbits 4, PRIbits 4, SEIS.
const VTR_VALUE: u64 = (LIST_REGISTERS as u64 - 1) | 4 << 26 | 4 << 29 | 1 << 22;

const HCR_EN: u64 = 1 << 0;
const HCR_UIE: u64 = 1 << 1;
const HCR_LRENPIE: u64 = 1 << 2;
const HCR_NPIE: u64 = 1 << 3;
const HCR_VGRP0EIE: u64 = 1 << 4;
const HCR_VGRP0DIE: u64 = 1 << 5;
const HCR_VGRP1EIE: u64 = 1 << 6;
const HCR_VGRP1DIE: u64 = 1 << 7;
const HCR_EOICOUNT_SHIFT: u32 = 27;
const VMCR_VENG0: u64 = 1 << 0;
const VMCR_VENG1: u64 = 1 << 1;
const LR_STATE_SHIFT: u32 = 62;
const LR_PENDING: u64 = 0b01;
const LR_HW: u64 = 1 << 61;
/// With HW clear, bit 41 asks for a maintenance interrupt at deactivation.
const LR_EOI: u64 = 1 << 41;

/// One PE's virtual CPU interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuInterface {
    hcr: u64,
    vmcr: u64,
    active_priorities: [u64; 2],
    list: [u64; LIST_REGISTERS],
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

/// Whether `encoding` is in the `ICH_*_EL2` space (op1 4, CRn 12, CRm 8-13).
pub fn owns(encoding: Encoding) -> bool {
    (encoding.op0(), encoding.op1(), encoding.crn()) == (3, 4, 12)
        && (8..=13).contains(&encoding.crm())
}

fn state(list: u64) -> u64 {
    list >> LR_STATE_SHIFT
}

impl CpuInterface {
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
            hcr & HCR_LRENPIE != 0 && (hcr >> HCR_EOICOUNT_SHIFT) & 0x1f != 0,
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

    /// MRS at `el`; `None` for an encoding [`owns`] rejects.
    pub fn read(&self, encoding: Encoding, el: u8) -> Option<Outcome> {
        if !owns(encoding) {
            return None;
        }
        if el < 2 {
            return Some(Outcome::Undefined);
        }
        Some(match encoding {
            HCR => Outcome::Read(self.hcr),
            VTR => Outcome::Read(VTR_VALUE),
            MISR => Outcome::Read(self.maintenance()),
            EISR => Outcome::Read(self.end_of_interrupt()),
            ELRSR => Outcome::Read(self.empty()),
            VMCR => Outcome::Read(self.vmcr),
            AP0R0 => Outcome::Read(self.active_priorities[0]),
            AP1R0 => Outcome::Read(self.active_priorities[1]),
            _ => match list_index(encoding) {
                Some(index) => Outcome::Read(self.list[index]),
                // Active-priority and list registers beyond the
                // implemented ones.
                None => Outcome::Undefined,
            },
        })
    }

    /// MSR at `el`; `None` for an encoding [`owns`] rejects.
    pub fn write(&mut self, encoding: Encoding, el: u8, value: u64) -> Option<Outcome> {
        if !owns(encoding) {
            return None;
        }
        if el < 2 {
            return Some(Outcome::Undefined);
        }
        let refuse = |reason| Outcome::Refused(Refusal::UnsupportedSetting(reason));
        match encoding {
            HCR if value & HCR_EN != 0 => {
                return Some(refuse(
                    "ICH_HCR_EL2.En: virtual interrupt delivery is not modelled",
                ));
            }
            HCR => self.hcr = value,
            VTR | MISR | EISR | ELRSR => return Some(Outcome::Undefined),
            VMCR => self.vmcr = value,
            AP0R0 => self.active_priorities[0] = value & 0xffff_ffff,
            AP1R0 => self.active_priorities[1] = value & 0xffff_ffff,
            _ => match list_index(encoding) {
                Some(index) => self.list[index] = value,
                None => return Some(Outcome::Undefined),
            },
        }
        Some(Outcome::Written(Changes::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernels_vcpu_switch_round_trips_and_status_follows_the_list() {
        let mut gic = CpuInterface::default();
        assert_eq!(gic.read(VTR, 2), Some(Outcome::Read(0x9040_0007)));
        assert_eq!(gic.read(HCR, 1), Some(Outcome::Undefined));
        assert_eq!(
            gic.read(Encoding::new(3, 0, 12, 12, 5), 2),
            None,
            "ICC_SRE_EL1"
        );
        // Every list register free, no maintenance condition.
        assert_eq!(gic.read(ELRSR, 2), Some(Outcome::Read(0xff)));
        assert_eq!(gic.read(MISR, 2), Some(Outcome::Read(0)));
        // A pending interrupt in LR3, an invalid EOI-requesting LR5.
        gic.write(ich(12, 3), 2, LR_PENDING << LR_STATE_SHIFT | 27);
        gic.write(ich(12, 5), 2, LR_EOI | 30);
        assert_eq!(
            gic.read(ELRSR, 2),
            Some(Outcome::Read(0xff & !(1 << 3 | 1 << 5)))
        );
        assert_eq!(gic.read(EISR, 2), Some(Outcome::Read(1 << 5)));
        gic.write(HCR, 2, HCR_UIE | HCR_NPIE | HCR_VGRP1DIE);
        gic.write(VMCR, 2, VMCR_VENG1);
        // EOI, and underflow with one valid list register.
        assert_eq!(gic.read(MISR, 2), Some(Outcome::Read(0b11)));
        gic.write(AP1R0, 2, 1 << 4);
        assert_eq!(gic.read(AP1R0, 2), Some(Outcome::Read(1 << 4)));
        // Unimplemented registers, read-only writes and En.
        assert_eq!(gic.read(ich(13, 0), 2), Some(Outcome::Undefined), "LR8");
        assert_eq!(gic.read(ich(8, 1), 2), Some(Outcome::Undefined), "AP0R1");
        assert_eq!(gic.write(VTR, 2, 0), Some(Outcome::Undefined));
        assert!(matches!(
            gic.write(HCR, 2, HCR_EN),
            Some(Outcome::Refused(_))
        ));
    }
}
