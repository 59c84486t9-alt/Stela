//! VMSAv8-64 translation (docs/design/system.md, "Memory translation").
//!
//! One software walker serves instruction fetch, shadow-page fills, AT and
//! fault reporting, so every consumer sees the same translation and the same
//! fault. Sources: Arm ARM DDI0487 (June 2026) chapter D8 (VMSAv8-64
//! translation, descriptors, permissions, attributes, the Access flag and
//! fault prioritization).

mod attributes;
mod geometry;
mod sprr;
mod stage1;

pub use sprr::{
    SPRR_CONFIG_EN, SPRR_CONFIG_LOCK_CONFIG, SPRR_CONFIG_LOCK_PERM_EL0, SPRR_CONFIG_LOCK_PERM_EL1,
    SPRR_CONFIG_UNDOCUMENTED, Sprr,
};

/// The stage-1 translation regime the controls describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Regime {
    /// EL1&0: two VA ranges, EL0 and EL1 permissions, ASIDs.
    #[default]
    El10,
    /// EL2&0 (HCR_EL2.E2H set): the EL1&0 layout through the `*_EL2`
    /// registers, with EL2 in place of EL1.
    El20,
    /// EL2 with E2H clear: one VA range through TTBR0_EL2 and the non-VHE
    /// TCR_EL2 layout, one privilege level and no ASIDs.
    El2,
}

/// Translation controls of the current regime, as last written by the guest.
/// For EL2&0 and EL2 these are the `*_EL2` registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Controls {
    pub sctlr: u64,
    pub tcr: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub mair: u64,
    pub sprr: Sprr,
    pub regime: Regime,
    /// The EL1&0 regime with HCR_EL2.VM set also translates through stage
    /// 2, which this walker does not implement yet.
    pub stage2: bool,
}

pub const SCTLR_M: u64 = 1 << 0;
pub const SCTLR_WXN: u64 = 1 << 19;
pub const SCTLR_SPAN: u64 = 1 << 23;

/// The largest physical address this profile implements (48 bits,
/// ID_AA64MMFR0_EL1.PARange 0b0101).
pub const PHYSICAL_ADDRESS_BITS: u32 = 48;

/// The kind of access being translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// Who is accessing: the current EL and whether PSTATE.PAN applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requester {
    pub el: u8,
    pub pan: bool,
    /// LDTR/STTR without PSTATE.UAO, and AT S1E0*: a kernel-level access
    /// checked with EL0 permissions.
    pub unprivileged: bool,
    /// At the Apple GXF guarded level (GL1 permissions under SPRR).
    pub guarded: bool,
}

/// The architectural fault, with the level it was found at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    AddressSize,
    Translation,
    AccessFlag,
    Permission,
    /// The walk read a descriptor outside RAM: a synchronous external abort
    /// on a translation table walk.
    ExternalOnWalk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub level: i8,
}

impl Fault {
    /// The DFSC/IFSC encoding (levels 0–3; ESR ISS[5:0]).
    pub fn status_code(self) -> u32 {
        let level = (self.level.clamp(0, 3)) as u32;
        match self.kind {
            FaultKind::AddressSize => level,
            FaultKind::Translation => 0b00_0100 | level,
            FaultKind::AccessFlag => 0b00_1000 | level,
            FaultKind::Permission => 0b00_1100 | level,
            FaultKind::ExternalOnWalk => 0b01_0100 | level,
        }
    }
}

/// Memory type from MAIR, reduced to what the engine distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Device,
    Normal,
}

/// A completed translation of one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translation {
    pub physical: u64,
    pub memory: MemoryType,
    /// The MAIR attribute byte (PAR_EL1.ATTR format).
    pub attributes: u8,
    /// SH, with Device and Non-cacheable memory reported Outer Shareable.
    pub shareability: u8,
    /// Data permissions at the requesting EL after PAN, and execution at that
    /// EL, for the whole page.
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub global: bool,
    pub asid: u16,
    /// Bytes mapped by the descriptor (page or block size).
    pub size: u64,
}

/// Physical memory the walker reads descriptors from.
pub trait TableMemory {
    fn read_descriptor(&mut self, physical: u64) -> Option<u64>;
    /// Replace `old` with `new` only if the descriptor still holds `old`.
    /// Hardware descriptor updates (FEAT_HAFDBS) are not in the profile, so
    /// the walker never calls it.
    fn update_descriptor(&mut self, physical: u64, old: u64, new: u64) -> Option<bool>;
}

/// Refusals that are limits of this implementation, not guest faults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// TG0/TG1 select 64 KiB or a reserved value: the architecture leaves
    /// the granule used IMPLEMENTATION DEFINED, and no observation fixes it.
    Granule { bits: u32 },
    /// SPRR with hierarchical table permissions, PAN or an EL0 nibble beyond
    /// the documented values: their composition with SPRR is not documented.
    Sprr(&'static str),
    /// Stage-2 translation (HCR_EL2.VM).
    Stage2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Mapped(Translation),
    Fault(Fault),
    Unsupported(Unsupported),
}

const PAR_FAULT: u64 = 1 << 0;
const PAR_FST_SHIFT: u64 = 1;
const PAR_SH_SHIFT: u64 = 7;
/// PAR_EL1.NS is UNKNOWN for a Non-secure regime; this implementation
/// reports 1, the Non-secure PA space every output is in (as QEMU does).
const PAR_NS: u64 = 1 << 9;
/// PAR_EL1 bit 11 is RES1 in the 64-bit format, for both results.
const PAR_RES1: u64 = 1 << 11;
const PAR_ATTR_SHIFT: u64 = 56;
const PAR_ADDRESS: u64 = 0x0000_ffff_ffff_f000;

/// PAR_EL1 after an AT whose stage-1 translation gave `outcome`, or `None`
/// for a translation this implementation refuses. A fault reports FST with
/// S=0 and PTW=0 (stage 1); IMPLEMENTATION DEFINED bits read 0.
pub fn par(outcome: &Outcome) -> Option<u64> {
    match outcome {
        Outcome::Mapped(translation) => Some(
            u64::from(translation.attributes) << PAR_ATTR_SHIFT
                | translation.physical & PAR_ADDRESS
                | PAR_RES1
                | PAR_NS
                | u64::from(translation.shareability) << PAR_SH_SHIFT,
        ),
        Outcome::Fault(fault) => {
            Some(PAR_RES1 | u64::from(fault.status_code()) << PAR_FST_SHIFT | PAR_FAULT)
        }
        Outcome::Unsupported(_) => None,
    }
}

/// Whether `access` is permitted by (readable, writable, executable).
fn permits(rights: (bool, bool, bool), access: Access) -> bool {
    match access {
        Access::Read => rights.0,
        Access::Write => rights.1,
        Access::Execute => rights.2,
    }
}

/// The ASID that tags non-global entries of this regime; EL2 has none.
pub fn current_asid(controls: &Controls) -> u16 {
    stage1::asid(controls)
}

/// Translate `address` for `access` by `requester`.
pub fn translate(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
) -> Outcome {
    if controls.stage2 {
        return Outcome::Unsupported(Unsupported::Stage2);
    }
    stage1::translate(controls, address, access, requester, memory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_reports_the_output_attributes_or_the_fault() {
        let translation = Translation {
            physical: 0x8_1234_5678,
            memory: MemoryType::Normal,
            attributes: 0xff,
            shareability: 0b11,
            readable: true,
            writable: true,
            executable: false,
            global: true,
            asid: 0,
            size: 1 << 14,
        };
        assert_eq!(
            par(&Outcome::Mapped(translation)),
            Some(0xff00_0008_1234_5000 | 1 << 11 | 1 << 9 | 0b11 << 7)
        );
        let device = Translation {
            attributes: 0x04,
            shareability: 0b10,
            memory: MemoryType::Device,
            ..translation
        };
        assert_eq!(
            par(&Outcome::Mapped(device)),
            Some(0x0400_0008_1234_5000 | 1 << 11 | 1 << 9 | 0b10 << 7)
        );
        let fault = Fault {
            kind: FaultKind::Permission,
            level: 3,
        };
        assert_eq!(
            par(&Outcome::Fault(fault)),
            Some(1 << 11 | 0b00_1111 << 1 | 1)
        );
        assert_eq!(par(&Outcome::Unsupported(Unsupported::Stage2)), None);
    }
}
