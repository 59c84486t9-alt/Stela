//! Self-hosted debug for the profile: debug exception enablement and routing,
//! breakpoint and watchpoint matching, and the software step state, from
//! Arm's pseudocode (`AArch64_GenerateDebugExceptionsFrom`, `DebugTarget`,
//! `AArch64_CheckBreakpoint`, `AArch64_BreakpointMatch`,
//! `AArch64_BreakpointValueMatch`, `AArch64_StateMatch`,
//! `CheckValidStateMatch`, `AArch64_CheckWatchpoint`,
//! `AArch64_WatchpointMatch`, `AArch64_WatchpointByteMatch` and
//! `DebugExceptionReturnSS`).
//!
//! The profile has EL2 without EL3, Non-secure state only, no AArch32, no
//! FEAT_ABLE, FEAT_BWE, FEAT_LVA, FEAT_RME, FEAT_VMID16, FEAT_DoubleLock or
//! halting. Every CONSTRAINED UNPREDICTABLE case resolves to the choice named
//! where it arises; reserved types and controls behave as disabled.
use super::{
    cpu::{Cpu, HCR_TGE},
    system::Register,
};

/// Breakpoints implemented; the last [`CONTEXT_AWARE`] are context-aware.
pub const BREAKPOINTS: u64 = 6;
pub const CONTEXT_AWARE: u64 = 2;
pub const WATCHPOINTS: u64 = 4;

/// `DebugAddrTop()` without FEAT_LVA.
const ADDRESS_TOP: u32 = 48;
const MDCR_TDE: u32 = 8;
const MDSCR_SS: u32 = 0;
const MDSCR_KDE: u32 = 13;
const MDSCR_MDE: u32 = 15;
/// VTTBR_EL2.VMID, 8 bits without FEAT_VMID16.
const VMID_SHIFT: u32 = 48;

fn bits(value: u64, low: u32, width: u32) -> u64 {
    (value >> low) & ((1 << width) - 1)
}

/// Bits `high..=low` of `value`.
fn range(value: u64, high: u32, low: u32) -> u64 {
    (value >> low) & (u64::MAX >> (63 - (high - low)))
}

/// `DebugTargetFrom()`: EL2 under HCR_EL2.TGE or MDCR_EL2.TDE, else EL1.
pub fn target(cpu: &Cpu) -> u8 {
    if cpu.hcr(HCR_TGE) || cpu.field(Register::MDCR_EL2, MDCR_TDE, 1) != 0 {
        2
    } else {
        1
    }
}

/// `AArch64_GenerateDebugExceptionsFrom(el, NonSecure, mask)`.
pub fn enabled_from(cpu: &Cpu, el: u8, masked: bool) -> bool {
    if cpu.field(Register::OSLSR_EL1, 1, 1) != 0 {
        return false;
    }
    let target = target(cpu);
    if el == target {
        cpu.field(Register::MDSCR_EL1, MDSCR_KDE, 1) != 0 && !masked
    } else {
        target > el
    }
}

/// `AArch64_GenerateDebugExceptions()` at the current EL and PSTATE.D.
pub fn enabled(cpu: &Cpu) -> bool {
    enabled_from(
        cpu,
        cpu.pstate.el,
        cpu.pstate.daif & super::exception::DAIF_D != 0,
    )
}

/// Breakpoints and watchpoints can fire now: debug exceptions are enabled
/// and MDSCR_EL1.MDE is set (Arm `AArch64_CheckDebug`).
pub fn watching(cpu: &Cpu) -> bool {
    enabled(cpu) && cpu.field(Register::MDSCR_EL1, MDSCR_MDE, 1) != 0
}

/// The debug communications channel (Arm `DTRRX`, `DTRTX` and EDSCR's
/// RXfull and TXfull). No external debugger fills DTRRX or drains DTRTX.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dcc {
    pub rx: u32,
    pub tx: u32,
    pub rx_full: bool,
    pub tx_full: bool,
}

/// Eight claim tag bits (DBGCLAIMSET_EL1 reads them as ones).
pub const CLAIM_TAGS: u64 = 0xff;

/// MDCCSR_EL0 and MDSCR_EL1 bits 30 (RXfull) and 29 (TXfull).
pub const DCC_FULL: u64 = 0b11 << 29;

impl Dcc {
    /// TXfull and RXfull at bits 29 and 30.
    pub fn status(self) -> u64 {
        u64::from(self.tx_full) << 29 | u64::from(self.rx_full) << 30
    }

    /// `Read_DBGDTR_EL0{width}`: UNKNOWN (0) while RXfull is clear; clears
    /// RXfull.
    pub fn read(&mut self, width: u32) -> u64 {
        let value = if self.rx_full {
            let low = u64::from(self.rx);
            if width == 64 {
                u64::from(self.tx) << 32 | low
            } else {
                low
            }
        } else {
            0
        };
        self.rx_full = false;
        value
    }

    /// `Write_DBGDTR_EL0{width}`: while TXfull is set the value is UNKNOWN,
    /// and the channel keeps what it holds (Stela's choice). Sets TXfull.
    pub fn write(&mut self, width: u32, value: u64) {
        if !self.tx_full {
            if width == 64 {
                self.rx = (value >> 32) as u32;
            }
            self.tx = value as u32;
        }
        self.tx_full = true;
    }
}

/// The software step state machine (Arm `CheckSoftwareStep`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Inactive,
    /// The next instruction executes, then the state becomes active-pending.
    ActiveNotPending,
    /// A Software Step exception is taken before the next instruction.
    ActivePending,
}

pub fn step(cpu: &Cpu) -> Step {
    if !(enabled(cpu) && cpu.field(Register::MDSCR_EL1, MDSCR_SS, 1) != 0) {
        Step::Inactive
    } else if cpu.pstate.ss {
        Step::ActiveNotPending
    } else {
        Step::ActivePending
    }
}

/// `DebugExceptionReturnSS(spsr)` for a return from the current EL to
/// `destination` with `spsr`; called before PSTATE changes.
pub fn return_ss(cpu: &Cpu, spsr: u64, destination: u8) -> bool {
    const SPSR_SS: u64 = 1 << 21;
    const SPSR_D: u64 = 1 << 9;
    cpu.field(Register::MDSCR_EL1, MDSCR_SS, 1) != 0
        && !enabled(cpu)
        && enabled_from(cpu, destination, spsr & SPSR_D != 0)
        && spsr & SPSR_SS != 0
}

/// `CheckValidStateMatch` for this profile, with reserved combinations
/// DISABLED: SSC 0b00 with PxC nonzero (and PxC 0b01 or 0b11 when HMC is
/// set), or HMC 1, SSC 0b11, PxC 0b00 (EL2 only).
fn valid_state(hmc: bool, ssc: u64, pxc: u64) -> bool {
    matches!(
        (hmc, ssc, pxc),
        (false, 0b00, 0b01..=0b11) | (true, 0b00, 0b01 | 0b11) | (true, 0b11, 0b00)
    )
}

fn context_aware(n: u64) -> bool {
    (BREAKPOINTS - CONTEXT_AWARE..BREAKPOINTS).contains(&n)
}

/// `AArch64_StateMatch` at `el` in Non-secure state. A link to a
/// breakpoint that is not context-aware does not match (the
/// CONSTRAINED UNPREDICTABLE choice).
fn state_match(cpu: &Cpu, control: u64, pxc: u64, el: u8, linked: bool) -> bool {
    let hmc = bits(control, 13, 1) != 0;
    let ssc = bits(control, 14, 2);
    if !valid_state(hmc, ssc, pxc) {
        return false;
    }
    let privilege = match el {
        2 => (hmc && (ssc << 2 | pxc) != 0b1000) || ssc == 0b11,
        1 => pxc & 1 != 0,
        _ => pxc & 2 != 0,
    };
    if !privilege {
        return false;
    }
    if !linked {
        return true;
    }
    let linked_n = bits(control, 16, 4);
    if !context_aware(linked_n) {
        return false;
    }
    matches!(
        value_match(cpu, linked_n, 0, true),
        Some((Kind::Context, true))
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Address,
    Context,
}

/// `AArch64_BreakpointValueMatch(n, vaddress, linked_to, TRUE, FALSE)`:
/// `None` for an inactive breakpoint.
fn value_match(cpu: &Cpu, n: u64, vaddress: u64, linked_to: bool) -> Option<(Kind, bool)> {
    if n >= BREAKPOINTS {
        // A non-existent breakpoint: the DISABLED choice.
        return None;
    }
    let control = cpu.registers.get(Register::DBGBCR_EL1, n);
    let value = cpu.registers.get(Register::DBGBVR_EL1, n);
    if control & 1 == 0 {
        return None;
    }
    let bt = bits(control, 20, 4);
    // AArch64_ReservedBreakpointType, DISABLED: context types on a
    // breakpoint that is not context-aware, and address mismatch.
    if !matches!(bt, 0b0000 | 0b0001) && !context_aware(n) || matches!(bt, 0b0100 | 0b0101) {
        return None;
    }
    let match_address = matches!(bt, 0b0000 | 0b0001);
    let match_vmid = bt & 0b1100 == 0b1000;
    let match_cid = bt & 0b1110 == 0b0010;
    let match_cid1 = bt & 0b1110 == 0b1010 || bt & 0b0110 == 0b0110;
    let match_cid2 = bt & 0b1100 == 0b1100;
    let linking_enabled = bt & 0b0011 == 0b0011 || bt & 0b1001 == 0b1001;
    if linked_to != linking_enabled {
        return None;
    }
    let el = cpu.pstate.el;
    let in_host = el == 2 || (el == 0 && cpu.in_host());
    let guest = el != 2 && !in_host;
    let cid = |register| cpu.read(register) & 0xffff_ffff;
    let bvr = if match_address {
        range(vaddress, ADDRESS_TOP, 2) == range(value, ADDRESS_TOP, 2)
    } else if match_cid {
        if in_host {
            cid(Register::CONTEXTIDR_EL2) == value & 0xffff_ffff
        } else {
            cid(Register::CONTEXTIDR_EL1) == value & 0xffff_ffff
        }
    } else if match_cid1 {
        guest && cid(Register::CONTEXTIDR_EL1) == value & 0xffff_ffff
    } else {
        false
    };
    let bxvr = if match_vmid {
        guest && bits(cpu.read(Register::VTTBR_EL2), VMID_SHIFT, 8) == bits(value, 32, 8)
    } else if match_cid2 {
        cid(Register::CONTEXTIDR_EL2) == value >> 32
    } else {
        false
    };
    let bvr_valid = match_address || match_cid || match_cid1;
    let bxvr_valid = match_vmid || match_cid2;
    let matched = (!bxvr_valid || bxvr) && (!bvr_valid || bvr);
    Some((
        if match_address {
            Kind::Address
        } else {
            Kind::Context
        },
        matched,
    ))
}

/// `AArch64_CheckBreakpoint` for the instruction at `pc`, at the current EL.
/// The caller has checked [`watching`].
pub fn breakpoint(cpu: &Cpu, pc: u64) -> bool {
    (0..BREAKPOINTS).any(|n| {
        let control = cpu.registers.get(Register::DBGBCR_EL1, n);
        let bt = bits(control, 20, 4);
        // A breakpoint with linking enabled generates no event by itself.
        if bt & 0b0011 == 0b0011 || bt & 0b1001 == 0b1001 || control & 1 == 0 {
            return false;
        }
        let linked = bt == 0b0001;
        state_match(cpu, control, bits(control, 1, 2), cpu.pstate.el, linked)
            && value_match(cpu, n, pc, false).is_some_and(|(_, matched)| matched)
    })
}

/// Whether any breakpoint is enabled (DBGBCR_EL1.E).
pub fn any_breakpoint(cpu: &Cpu) -> bool {
    (0..BREAKPOINTS).any(|n| cpu.registers.get(Register::DBGBCR_EL1, n) & 1 != 0)
}

/// One data access, as Arm's AccessDescriptor sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub address: u64,
    pub size: u64,
    pub read: bool,
    pub write: bool,
    /// Cache maintenance (DC IVAC): matches LSC store watchpoints.
    pub maintenance: bool,
    /// The EL the access is made at: EL0 for LDTR/STTR.
    pub el: u8,
}

/// A watchpoint match: the reported address and the access direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub address: u64,
    pub write: bool,
}

/// `AArch64_WatchpointByteMatch`. Reserved MASK values (1 and 2) disable the
/// watchpoint; with MASK and a partial BAS, or a non-contiguous BAS, the
/// byte select is used as programmed (the CONSTRAINED UNPREDICTABLE choice),
/// and masked DBGWVR bits that are not zero take part as programmed.
fn byte_match(control: u64, value: u64, address: u64) -> bool {
    let bas = bits(control, 5, 8);
    let mask = bits(control, 24, 5) as u32;
    let mut bottom = if value & 4 != 0 { 2 } else { 3 };
    let select = bits(address, 0, bottom);
    if !(mask > 0 && bas != 0xff) {
        let lowest = bas.isolate_lowest_one();
        let above = (bas + lowest) & 0x1ff;
        if above & above.wrapping_sub(1) != 0 {
            bottom = 3;
        }
    }
    let byte = bas >> select & 1 != 0;
    if mask == 1 || mask == 2 {
        return false;
    }
    let low = mask.max(bottom);
    byte && range(address, ADDRESS_TOP, low) == range(value, ADDRESS_TOP, low)
}

/// Whether watchpoint `n` is enabled for this kind of access: E, LSC and the
/// state match (Arm `AArch64_WatchpointMatch`).
fn watchpoint_active(cpu: &Cpu, n: u64, access: &Access) -> bool {
    let control = cpu.registers.get(Register::DBGWCR_EL1, n);
    if control & 1 == 0 {
        return false;
    }
    let lsc = bits(control, 3, 2);
    let direction = match lsc {
        0b01 => access.read,
        0b10 => access.write || access.maintenance,
        0b11 => true,
        _ => false,
    };
    let linked = bits(control, 20, 1) != 0;
    direction && state_match(cpu, control, bits(control, 1, 2), access.el, linked)
}

/// `AArch64_CheckWatchpoint` for one access; the caller has checked
/// [`watching`]. The reported address is the first matching byte of the
/// last matching watchpoint (`AddressInNaturallyAlignedBlock` is FALSE).
pub fn watchpoint(cpu: &Cpu, access: &Access) -> Option<Hit> {
    let mut hit = None;
    for n in 0..WATCHPOINTS {
        if !watchpoint_active(cpu, n, access) {
            continue;
        }
        let control = cpu.registers.get(Register::DBGWCR_EL1, n);
        let value = cpu.registers.get(Register::DBGWVR_EL1, n);
        let Some(byte) = (0..access.size)
            .map(|byte| access.address.wrapping_add(byte))
            .find(|&address| byte_match(control, value, address))
        else {
            continue;
        };
        let lsc = bits(control, 3, 2);
        let write = if lsc & 1 != 0 && access.read {
            false
        } else {
            lsc & 2 != 0 && (access.write || access.maintenance)
        };
        hit = Some(Hit {
            address: byte,
            write,
        });
    }
    hit
}

/// The virtual address ranges (first, last) that enabled watchpoints can
/// match, for keeping their pages out of the shadow tables; empty when
/// watchpoints cannot fire.
pub fn watched(cpu: &Cpu) -> alloc::vec::Vec<(u64, u64)> {
    let mut ranges = alloc::vec::Vec::new();
    if !watching(cpu) {
        return ranges;
    }
    for n in 0..WATCHPOINTS {
        let control = cpu.registers.get(Register::DBGWCR_EL1, n);
        if control & 1 == 0 {
            continue;
        }
        let value = cpu.registers.get(Register::DBGWVR_EL1, n);
        let mask = bits(control, 24, 5) as u32;
        let size: u64 = if mask >= 3 { 1 << mask } else { 8 };
        // Bits 48:0 compare; the matching range repeats with every
        // sign-extension of bit 48, so cover both halves.
        let base = range(value, ADDRESS_TOP, 0) & !(size - 1);
        let upper = base | !((1u64 << (ADDRESS_TOP + 1)) - 1);
        for start in [base, upper] {
            ranges.push((start, start + (size - 1)));
        }
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::exception::{DAIF_ALL, Pstate};

    fn cpu(el: u8) -> Cpu {
        let mut cpu = Cpu::new(0, Pstate::reset(el));
        // Clear the OS lock and enable monitor debug and kernel debug.
        cpu.registers.set(Register::OSLSR_EL1, 0, 0b1000);
        cpu.registers
            .set(Register::MDSCR_EL1, 0, 1 << MDSCR_MDE | 1 << MDSCR_KDE);
        cpu.pstate.daif = 0;
        cpu
    }

    #[test]
    fn enablement_follows_the_os_lock_kde_pstate_d_and_tde() {
        let mut cpu = cpu(1);
        assert_eq!(target(&cpu), 1);
        assert!(enabled(&cpu));
        cpu.pstate.daif = DAIF_ALL;
        assert!(!enabled(&cpu), "PSTATE.D masks same-EL debug");
        assert!(enabled_from(&cpu, 0, true), "lower ELs are not masked");
        cpu.registers.set(Register::OSLSR_EL1, 0, 0b1010);
        assert!(!enabled_from(&cpu, 0, false), "the OS lock disables all");
        let mut cpu = super::tests::cpu(1);
        cpu.registers.set(Register::MDCR_EL2, 0, 1 << MDCR_TDE);
        assert_eq!(target(&cpu), 2);
        assert!(enabled(&cpu), "EL1 is below the EL2 target");
        assert!(!enabled_from(&cpu, 2, false) || cpu.field(Register::MDSCR_EL1, MDSCR_KDE, 1) != 0);
    }

    #[test]
    fn breakpoints_match_address_state_and_linked_context() {
        let mut cpu = cpu(1);
        // Breakpoint 0: address 0x8000, EL1 only (HMC 0, SSC 0, PMC 0b01).
        cpu.registers.set(Register::DBGBVR_EL1, 0, 0x8000);
        cpu.registers
            .set(Register::DBGBCR_EL1, 0, 0b1111 << 5 | 0b01 << 1 | 1);
        assert!(watching(&cpu) && any_breakpoint(&cpu));
        assert!(breakpoint(&cpu, 0x8000));
        assert!(!breakpoint(&cpu, 0x8004));
        // The same breakpoint does not match at EL0 (PMC bit 1 clear).
        cpu.pstate.el = 0;
        assert!(!breakpoint(&cpu, 0x8000));
        cpu.pstate.el = 1;
        // Reserved state control (HMC 0, SSC 0, PMC 0): disabled.
        cpu.registers.set(Register::DBGBCR_EL1, 0, 0b1111 << 5 | 1);
        assert!(!breakpoint(&cpu, 0x8000));
        // Linked address breakpoint (BT 0b0001) to context-aware breakpoint 5
        // with linking enabled on CONTEXTIDR_EL1 0x42 (BT 0b0011).
        cpu.registers.set(
            Register::DBGBCR_EL1,
            0,
            0b0001 << 20 | 5 << 16 | 0b1111 << 5 | 0b01 << 1 | 1,
        );
        cpu.registers.set(Register::DBGBVR_EL1, 5, 0x42);
        cpu.registers.set(
            Register::DBGBCR_EL1,
            5,
            0b0011 << 20 | 0b1111 << 5 | 0b11 << 1 | 1,
        );
        assert!(!breakpoint(&cpu, 0x8000), "CONTEXTIDR_EL1 is 0");
        cpu.registers.set(Register::CONTEXTIDR_EL1, 0, 0x42);
        assert!(breakpoint(&cpu, 0x8000));
        // A context type on a breakpoint that is not context-aware is reserved.
        cpu.registers.set(Register::DBGBVR_EL1, 1, 0x42);
        cpu.registers.set(
            Register::DBGBCR_EL1,
            1,
            0b0010 << 20 | 0b1111 << 5 | 0b11 << 1 | 1,
        );
        cpu.registers.set(Register::DBGBCR_EL1, 0, 0);
        assert!(!breakpoint(&cpu, 0x1234));
        // An unlinked context ID breakpoint on a context-aware unit matches
        // any address.
        cpu.registers.set(
            Register::DBGBCR_EL1,
            4,
            0b0010 << 20 | 0b1111 << 5 | 0b11 << 1 | 1,
        );
        cpu.registers.set(Register::DBGBVR_EL1, 4, 0x42);
        assert!(breakpoint(&cpu, 0x1234));
    }

    #[test]
    fn watchpoints_match_bytes_masks_and_directions() {
        let cpu = {
            let mut cpu = cpu(1);
            // Watchpoint 0: bytes 4..=5 of the doubleword at 0x9000, stores,
            // EL1 (PAC 0b01).
            cpu.registers.set(Register::DBGWVR_EL1, 0, 0x9000);
            cpu.registers.set(
                Register::DBGWCR_EL1,
                0,
                0b0011_0000 << 5 | 0b10 << 3 | 0b01 << 1 | 1,
            );
            cpu
        };
        let access = |address: u64, size: u64, write: bool| Access {
            address,
            size,
            read: !write,
            write,
            maintenance: false,
            el: 1,
        };
        assert_eq!(watchpoint(&cpu, &access(0x9000, 4, true)), None);
        assert_eq!(
            watchpoint(&cpu, &access(0x9000, 8, true)),
            Some(Hit {
                address: 0x9004,
                write: true
            })
        );
        assert_eq!(watchpoint(&cpu, &access(0x9004, 8, false)), None, "loads");
        assert_eq!(
            watchpoint(
                &cpu,
                &Access {
                    el: 0,
                    ..access(0x9004, 1, true)
                }
            ),
            None
        );
        // MASK 12 watches the 4 KiB block at 0x9000 with BAS all ones.
        let mut cpu = cpu;
        cpu.registers.set(
            Register::DBGWCR_EL1,
            0,
            12 << 24 | 0xff << 5 | 0b11 << 3 | 0b01 << 1 | 1,
        );
        assert!(watchpoint(&cpu, &access(0x9ff8, 8, false)).is_some());
        assert!(watchpoint(&cpu, &access(0xa000, 8, false)).is_none());
        assert_eq!(watched(&cpu)[0], (0x9000, 0x9fff));
        // Reserved MASK 1 disables the watchpoint.
        cpu.registers.set(
            Register::DBGWCR_EL1,
            0,
            1 << 24 | 0xff << 5 | 0b11 << 3 | 0b01 << 1 | 1,
        );
        assert!(watchpoint(&cpu, &access(0x9000, 8, false)).is_none());
    }

    #[test]
    fn software_step_state_and_return() {
        let mut cpu = cpu(1);
        cpu.registers
            .set(Register::MDSCR_EL1, 0, 1 << MDSCR_SS | 1 << MDSCR_MDE);
        // At EL1 without KDE debug is disabled: the step is inactive, and an
        // ERET to EL0 with SPSR.SS set makes it active-not-pending there.
        assert_eq!(step(&cpu), Step::Inactive);
        assert!(return_ss(&cpu, 1 << 21, 0));
        assert!(!return_ss(&cpu, 0, 0));
        cpu.pstate = Pstate {
            el: 0,
            sp: false,
            daif: 0,
            ss: true,
            ..Pstate::reset(1)
        };
        assert_eq!(step(&cpu), Step::ActiveNotPending);
        cpu.pstate.ss = false;
        assert_eq!(step(&cpu), Step::ActivePending);
    }
}
