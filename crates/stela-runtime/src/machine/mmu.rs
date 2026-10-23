//! VMSAv8-64 translation (docs/design/system.md, "Memory translation").
//!
//! One software walker serves instruction fetch, shadow-page fills, AT and
//! fault reporting, so every consumer sees the same translation and the same
//! fault. Sources: Arm ARM DDI0487 (June 2026) chapter D8 (VMSAv8-64
//! translation, descriptors, permissions, attributes, the Access flag and
//! fault prioritization).

pub mod alignment;
pub mod attributes;
mod geometry;
pub mod placement;
pub mod shadow;
mod sprr;
mod stage1;
mod stage2;
pub mod tlbi;
pub mod translated;

pub use sprr::{
    SPRR_CONFIG_EN, SPRR_CONFIG_LOCK_CONFIG, SPRR_CONFIG_LOCK_PERM_EL0, SPRR_CONFIG_LOCK_PERM_EL1,
    SPRR_CONFIG_UNDOCUMENTED, Sprr, sprr_unlocked,
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
    /// The chip implements FEAT_XS: MAIR's XS encodings are allocated and
    /// the attributes report XS (`attributes`).
    pub xs: bool,
    /// The chip implements FEAT_MTE2: MAIR's `0xf0` and, with HCR_EL2.DCT,
    /// the HCR_EL2.DC default are Tagged memory (`attributes::TAGGED`).
    pub tagged: bool,
    pub sprr: Sprr,
    /// Apple's CTRR, applied to the output address of an access.
    pub ctrr: Ctrr,
    pub regime: Regime,
    /// The caller requires stage 2 (HCR_EL2.VM in the EL1&0 regime). Without
    /// [`Controls::second_stage`] the walker refuses instead of translating
    /// stage 1 alone.
    pub stage2: bool,
    /// The stage-2 controls. They apply to the EL1&0 regime while HCR_EL2.VM
    /// or DC is set and TGE is clear.
    pub second_stage: Option<Stage2>,
}

/// Apple's CTRR as one PE applies it after translation (`machine::ctrr`):
/// the core regions of the regime's privileged level (one on the M1 to M3,
/// CTRR-C and CTRR-D later), which bind every access but EL0's, and a
/// region the memory controller has locked against writes from any
/// requester. All work on whole pages of the translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ctrr {
    pub privileged: [Option<CtrrRegion>; 2],
    pub memory: MemoryLocks,
}

/// The regions the memory controller's lock groups (CTRR-A to CTRR-D) have
/// locked against writes, each its first and last byte.
pub type MemoryLocks = [Option<(u64, u64)>; 4];

/// A core CTRR group's region, first and last byte, and what it forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtrrRegion {
    pub first: u64,
    pub last: u64,
    pub write_protect: bool,
    pub execute_inside_only: bool,
}

/// The smallest page a CTRR decision covers: a translation whose block
/// straddles a region boundary is narrowed to it.
const CTRR_PAGE: u64 = 1 << 12;
/// XNU xnu-12377.121.6 `osfmk/arm64/platform_tests.c`'s
/// `ctrr_test_ro_fault_handler` and `ctrr_test_nx_fault_handler` require
/// FSC_PERMISSION_FAULT_L3, independently of the translation leaf size.
const CTRR_FAULT_LEVEL: i8 = 3;

fn overlaps(base: u64, bytes: u64, (first, last): (u64, u64)) -> bool {
    base <= last && first <= base + (bytes - 1)
}

fn within(base: u64, bytes: u64, (first, last): (u64, u64)) -> bool {
    first <= base && base + (bytes - 1) <= last
}

impl Ctrr {
    /// Apply physical CTRR protection after successful translation. A denied
    /// store or privileged fetch reports the level-3 Permission fault XNU
    /// expects; the caller retains the original virtual fault address. Clear
    /// removed rights so a cached allowed read cannot admit a later store.
    fn limit(&self, mut translation: Translation, access: Access, requester: Requester) -> Outcome {
        let privileged = self
            .privileged
            .map(|region| region.filter(|_| requester.el != 0));
        let bounds = privileged
            .into_iter()
            .flatten()
            .map(|region| (region.first, region.last))
            .chain(self.memory.into_iter().flatten());
        for region in bounds.clone() {
            let base = translation.physical & !(translation.size - 1);
            if overlaps(base, translation.size, region) && !within(base, translation.size, region) {
                translation.size = translation.size.min(CTRR_PAGE);
            }
        }
        let base = translation.physical & !(translation.size - 1);
        let mut write = false;
        let mut execute = false;
        if self
            .memory
            .into_iter()
            .flatten()
            .any(|region| overlaps(base, translation.size, region))
        {
            write = true;
        }
        for region in privileged.into_iter().flatten() {
            let bounds = (region.first, region.last);
            if region.write_protect && overlaps(base, translation.size, bounds) {
                write = true;
            }
            if region.execute_inside_only && !within(base, translation.size, bounds) {
                execute = true;
            }
        }
        if matches!(
            (access, write, execute),
            (Access::Write, true, _) | (Access::Execute, _, true)
        ) {
            return Outcome::Fault(Fault::stage1(FaultKind::Permission, CTRR_FAULT_LEVEL));
        }
        translation.writable &= !write;
        translation.executable &= !execute;
        translation.guarded &= translation.executable;
        Outcome::Mapped(translation)
    }
}

/// The EL2 registers that control stage 2 of the EL1&0 regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stage2 {
    pub hcr: u64,
    pub vtcr: u64,
    pub vttbr: u64,
    /// The chip implements FEAT_XS: bit 11 of a stage-2 descriptor is FnXS.
    pub xs: bool,
}

/// Whether the chip the tests run on implements FEAT_XS, as
/// `Cpu::controls` states it in [`Controls::xs`] and [`Stage2::xs`].
#[cfg(test)]
pub(crate) fn test_xs() -> bool {
    super::system::Feature::FEAT_XS.on(super::test_chip())
}

/// The chip the tests run on, after checking that its identification
/// advertises the translation profile the walker implements: a 48-bit
/// PARange, 16-bit ASIDs, 4 KiB and 16 KiB granules but not 64 KiB (so no
/// FEAT_LPA or FEAT_LPA2), no FEAT_LVA or FEAT_TTST, FEAT_LSE2's alignment
/// and the TLBI range and Outer Shareable forms.
#[cfg(test)]
pub(crate) fn test_translation_chip() -> super::Chip {
    use super::registers::encodings::{ID_AA64ISAR0_EL1, ID_AA64MMFR0_EL1, ID_AA64MMFR2_EL1};
    let chip = super::test_chip();
    let values = super::identification::derive(
        chip,
        stela_compiler::TargetCpu::Baseline,
        true,
        super::identification::Speculation::NONE,
    );
    let value = |register| {
        values
            .iter()
            .find(|(found, _)| *found == register)
            .map_or(0, |(_, value)| *value)
    };
    let field = |register, shift: u32| value(register) >> shift & 0xf;
    assert_eq!(
        value(ID_AA64MMFR0_EL1) & 0xffff_ffff,
        0x0f10_0025,
        "{chip:?}"
    );
    assert_eq!(
        (
            field(ID_AA64MMFR2_EL1, 16),
            field(ID_AA64MMFR2_EL1, 28),
            field(ID_AA64MMFR2_EL1, 32)
        ),
        (0, 0, 1),
        "{chip:?} VARange, ST and AT"
    );
    assert_eq!(field(ID_AA64ISAR0_EL1, 56), 2, "{chip:?} TLB");
    chip
}

const HCR_VM: u64 = 1 << 0;
const HCR_DC: u64 = 1 << 12;
const HCR_DCT: u64 = 1 << 57;
const HCR_TGE: u64 = 1 << 27;

impl Stage2 {
    /// Whether stage 2 translates `regime` (pseudocode AArch64.NSS2TTWParams
    /// `vm`: HCR_EL2.VM or DC; neither applies while TGE is set).
    fn applies(&self, regime: Regime) -> bool {
        regime == Regime::El10 && self.hcr & HCR_TGE == 0 && self.hcr & (HCR_VM | HCR_DC) != 0
    }

    /// HCR_EL2.DC: stage 1 of EL1&0 behaves as disabled, with Normal
    /// Write-Back output (pseudocode AArch64.S1Enabled and
    /// AArch64.S1DisabledOutput).
    fn default_cacheable(&self, regime: Regime) -> bool {
        self.applies(regime) && self.hcr & HCR_DC != 0
    }

    /// HCR_EL2.DCT: the HCR_EL2.DC default is Tagged memory (FEAT_MTE2).
    fn default_tagged(&self) -> bool {
        self.hcr & HCR_DCT != 0
    }

    /// VTTBR_EL2.VMID: 8 bits, because FEAT_VMID16 is not in the profile.
    pub fn vmid(&self) -> u8 {
        (self.vttbr >> 48) as u8
    }
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
    /// At an Apple GXF guarded level: under SPRR, GL0 takes the GL fields of
    /// SPRR_PERM_EL0 and GL1 and GL2 those of SPRR_PERM_EL1.
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
    /// An access the alignment rules forbid (`mmu::alignment`); it has no
    /// level.
    Alignment,
    /// A synchronous Tag Check fault (FEAT_MTE2): the logical tag of a
    /// tag-checked access differs from the Allocation Tag of its memory
    /// (`engine::tags`). It has no level.
    TagCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    pub kind: FaultKind,
    pub level: i8,
    /// A stage-2 fault, which is taken to EL2.
    pub second_stage: Option<SecondStage>,
}

/// Where a stage-2 fault happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecondStage {
    /// The intermediate physical address being translated.
    pub ipa: u64,
    /// On the stage-2 translation of a stage-1 table walk (S1PTW).
    pub walk: bool,
}

const ISS_WRITE: u32 = 1 << 6;
const ISS_S1PTW: u32 = 1 << 7;
const ISS_CACHE_MAINTENANCE: u32 = 1 << 8;
const HPFAR_FIPA_SHIFT: u64 = 4;

impl Fault {
    pub(crate) fn stage1(kind: FaultKind, level: i8) -> Self {
        Self {
            kind,
            level,
            second_stage: None,
        }
    }

    /// Stage-2 faults go to EL2 whatever the current routing.
    pub fn to_el2(self) -> bool {
        self.second_stage.is_some()
    }

    /// ISS[8:0] of a Data Abort (pseudocode AArch64.FaultSyndrome): DFSC,
    /// WnR, S1PTW and CM. Cache maintenance and AT report WnR set.
    pub fn data_syndrome(self, write: bool, maintenance: bool) -> u32 {
        self.status_code()
            | if write || maintenance { ISS_WRITE } else { 0 }
            | self.walk_syndrome()
            | if maintenance {
                ISS_CACHE_MAINTENANCE
            } else {
                0
            }
    }

    /// ISS[7:0] of an Instruction Abort: IFSC and S1PTW.
    pub fn instruction_syndrome(self) -> u32 {
        self.status_code() | self.walk_syndrome()
    }

    fn walk_syndrome(self) -> u32 {
        match self.second_stage {
            Some(SecondStage { walk: true, .. }) => ISS_S1PTW,
            _ => 0,
        }
    }

    /// HPFAR_EL2 when the fault reports its IPA (pseudocode IPAValid):
    /// FIPA holds IPA[47:12] for Translation, Access flag and Address size
    /// faults at stage 2, and also Permission faults on a stage-1 walk.
    /// Other aborts taken to EL2 leave HPFAR_EL2 UNKNOWN (`None`).
    pub fn hpfar(self) -> Option<u64> {
        let second_stage = self.second_stage?;
        let reported = match self.kind {
            FaultKind::Translation | FaultKind::AccessFlag | FaultKind::AddressSize => true,
            FaultKind::Permission => second_stage.walk,
            FaultKind::ExternalOnWalk | FaultKind::Alignment | FaultKind::TagCheck => false,
        };
        reported.then_some(second_stage.ipa >> 12 << HPFAR_FIPA_SHIFT)
    }

    /// The DFSC/IFSC encoding (levels 0–3; ESR ISS[5:0]).
    pub fn status_code(self) -> u32 {
        let level = (self.level.clamp(0, 3)) as u32;
        match self.kind {
            FaultKind::AddressSize => level,
            FaultKind::Translation => 0b00_0100 | level,
            FaultKind::AccessFlag => 0b00_1000 | level,
            FaultKind::Permission => 0b00_1100 | level,
            FaultKind::ExternalOnWalk => 0b01_0100 | level,
            FaultKind::Alignment => 0b10_0001,
            FaultKind::TagCheck => 0b01_0001,
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
    /// FEAT_BTI: the stage-1 leaf's GP bit for a location executable at the
    /// requesting EL (Arm `InGuardedPage`).
    pub guarded: bool,
    pub global: bool,
    pub asid: u16,
    /// Bytes mapped by the descriptor (page or block size).
    pub size: u64,
    /// The memory type as the alignment rules see it, over both stages.
    pub alignment: Alignment,
}

/// What the alignment rules need from the memory type (pseudocode
/// AArch64.S1HasAlignmentFaultDueToMemType and
/// AArch64.S2HasAlignmentFaultDueToMemType).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Alignment {
    /// Device memory at either stage.
    pub device: bool,
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
    /// Stage 2 is required but the caller supplied no stage-2 controls.
    Stage2,
    /// A stage-2 MemAttr field with a reserved encoding: the resulting
    /// attributes are CONSTRAINED UNPREDICTABLE.
    Stage2Attributes { field: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Mapped(Translation),
    Fault(Fault),
    Unsupported(Unsupported),
}

const PAR_FAULT: u64 = 1 << 0;
const PAR_FST_SHIFT: u64 = 1;
/// PAR_EL1.PTW: the fault was on the stage-2 translation of a stage-1 walk.
const PAR_PTW: u64 = 1 << 8;
/// PAR_EL1.S: the fault was at stage 2.
const PAR_STAGE2: u64 = 1 << 9;
const PAR_SH_SHIFT: u64 = 7;
/// PAR_EL1.NS is UNKNOWN for a Non-secure regime; this implementation
/// reports 1, the Non-secure PA space every output is in (as QEMU does).
const PAR_NS: u64 = 1 << 9;
/// PAR_EL1 bit 11 is RES1 in the 64-bit format, for both results.
const PAR_RES1: u64 = 1 << 11;
const PAR_ATTR_SHIFT: u64 = 56;
const PAR_ADDRESS: u64 = 0x0000_ffff_ffff_f000;

/// PAR_EL1 after an AT whose translation gave `outcome`, or `None` for a
/// translation this implementation refuses (pseudocode AArch64.EncodePAR). A
/// fault reports FST, S and PTW; IMPLEMENTATION DEFINED bits read 0.
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
            let stage = match fault.second_stage {
                Some(SecondStage { walk: true, .. }) => PAR_STAGE2 | PAR_PTW,
                Some(_) => PAR_STAGE2,
                None => 0,
            };
            Some(PAR_RES1 | stage | u64::from(fault.status_code()) << PAR_FST_SHIFT | PAR_FAULT)
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

/// The stage-2 controls that apply, or the refusal when stage 2 is required
/// but none were supplied.
fn second_stage(controls: &Controls) -> Result<Option<Stage2>, Unsupported> {
    match controls.second_stage {
        Some(stage2) => Ok(stage2.applies(controls.regime).then_some(stage2)),
        None if controls.stage2 => Err(Unsupported::Stage2),
        None => Ok(None),
    }
}

/// Descriptor reads of a stage-1 walk, each translated through stage 2 as
/// the walk's own access (S1PTW). The first stop ends the walk.
struct ThroughStage2<'a> {
    stage2: Stage2,
    memory: &'a mut dyn TableMemory,
    stop: Option<stage2::Stop>,
}

impl TableMemory for ThroughStage2<'_> {
    fn read_descriptor(&mut self, ipa: u64) -> Option<u64> {
        match stage2::translate(
            &self.stage2,
            ipa,
            stage2::Purpose::Walk,
            false,
            None,
            None,
            self.memory,
        ) {
            Ok(output) => self.memory.read_descriptor(output.physical),
            Err(stop) => {
                self.stop = Some(stop);
                None
            }
        }
    }

    fn update_descriptor(&mut self, _: u64, _: u64, _: u64) -> Option<bool> {
        // The walker makes no hardware descriptor updates (no FEAT_HAFDBS).
        None
    }
}

/// Stage 1 with its table walk translated through `stage2` when that
/// applies, and the stage-1 SH field of a mapped result.
fn first_stage(
    controls: &Controls,
    stage2: Option<Stage2>,
    address: u64,
    access: Access,
    requester: Requester,
    shape: Option<alignment::MemoryCheck>,
    memory: &mut dyn TableMemory,
) -> (Outcome, u8) {
    let Some(stage2) = stage2 else {
        return stage1::walk(controls, address, access, requester, shape, memory);
    };
    let mut tables = ThroughStage2 {
        stage2,
        memory,
        stop: None,
    };
    let walked = stage1::walk(controls, address, access, requester, shape, &mut tables);
    match tables.stop {
        Some(stop) => (stop.into(), 0),
        None => walked,
    }
}

/// Translate `address` for `access` by `requester`: stage 1 of the regime
/// and, for EL1&0 under HCR_EL2.VM or DC, stage 2 (pseudocode
/// AArch64.FullTranslate). Alignment is not checked; see
/// [`translate_checked`].
pub fn translate(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
) -> Outcome {
    limited(
        controls,
        access,
        requester,
        full(controls, address, access, requester, None, memory),
    )
}

/// [`translate`] as the translation tables alone decide it, for AT: CTRR
/// limits accesses, not the address translation AT reports.
pub fn translate_tables(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
) -> Outcome {
    full(controls, address, access, requester, None, memory)
}

fn limited(controls: &Controls, access: Access, requester: Requester, outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Mapped(translation) => controls.ctrr.limit(translation, access, requester),
        other => other,
    }
}

/// [`translate`] for a data access of `shape`, with Arm's alignment checks
/// in the pseudocode's order (Mem, AArch64.S1Translate and
/// AArch64.S2Translate): SCTLR_ELx.A and the exclusive, atomic and ordered
/// rules before translation, then each stage's memory type ahead of its
/// permissions. An alignment fault reports DFSC 0b100001.
pub fn translate_checked(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    shape: alignment::Shape,
    memory: &mut dyn TableMemory,
) -> Outcome {
    if alignment::before_translation(controls.sctlr, address, shape) {
        return Outcome::Fault(Fault::stage1(FaultKind::Alignment, 0));
    }
    translate_checked_part(
        controls,
        address,
        access,
        requester,
        alignment::MemoryCheck::new(shape, address),
        memory,
    )
}

/// Translate one reached MemSingle part after the caller checked the original
/// Mem access's SCTLR alignment rules. Preserve Mem's actual `aligned` value
/// through both stages, ahead of their permission checks; splitting must not
/// reinterpret this part as a new whole instruction.
pub fn translate_checked_part(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    alignment: alignment::MemoryCheck,
    memory: &mut dyn TableMemory,
) -> Outcome {
    let outcome = full(
        controls,
        address,
        access,
        requester,
        Some(alignment),
        memory,
    );
    limited(controls, access, requester, outcome)
}

fn full(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    shape: Option<alignment::MemoryCheck>,
    memory: &mut dyn TableMemory,
) -> Outcome {
    let stage2 = match second_stage(controls) {
        Ok(stage2) => stage2,
        Err(unsupported) => return Outcome::Unsupported(unsupported),
    };
    let (outcome, shareability) =
        first_stage(controls, stage2, address, access, requester, shape, memory);
    let (Some(stage2), Outcome::Mapped(first)) = (stage2, outcome) else {
        return outcome;
    };
    let input = stage2::Input {
        attributes: first.attributes,
        shareability,
    };
    let el0 = requester.el == 0 || requester.unprivileged;
    match stage2::translate(
        &stage2,
        first.physical,
        stage2::Purpose::Access(access),
        el0,
        Some(input),
        shape,
        memory,
    ) {
        Ok(second) => Outcome::Mapped(Translation {
            physical: second.physical,
            memory: attributes::memory_type(second.attributes),
            attributes: second.attributes,
            shareability: second.shareability,
            readable: first.readable && second.readable,
            writable: first.writable && second.writable,
            executable: first.executable && second.executable,
            size: first.size.min(second.size),
            alignment: Alignment {
                device: first.alignment.device || second.alignment.device,
            },
            ..first
        }),
        Err(stop) => stop.into(),
    }
}

/// Stage 1 alone, for AT S1E*: the result is an IPA with stage-1
/// attributes, but the table walk still goes through stage 2, and its
/// faults are stage-2 faults with `walk` set.
pub fn translate_stage1(
    controls: &Controls,
    address: u64,
    access: Access,
    requester: Requester,
    memory: &mut dyn TableMemory,
) -> Outcome {
    match second_stage(controls) {
        Ok(stage2) => first_stage(controls, stage2, address, access, requester, None, memory).0,
        Err(unsupported) => Outcome::Unsupported(unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn par_reports_the_output_attributes_or_the_fault() {
        // PAR_EL1.PA holds the chip's 48-bit physical address.
        test_translation_chip();
        let translation = Translation {
            physical: 0x8_1234_5678,
            memory: MemoryType::Normal,
            attributes: 0xff,
            shareability: 0b11,
            readable: true,
            writable: true,
            executable: false,
            guarded: false,
            global: true,
            asid: 0,
            size: 1 << 14,
            alignment: Alignment::default(),
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
        let fault = Fault::stage1(FaultKind::Permission, 3);
        assert_eq!(
            par(&Outcome::Fault(fault)),
            Some(1 << 11 | 0b00_1111 << 1 | 1)
        );
        let second_stage = |walk| Fault {
            kind: FaultKind::Translation,
            level: 2,
            second_stage: Some(SecondStage {
                ipa: 0x8000_4000,
                walk,
            }),
        };
        assert_eq!(
            par(&Outcome::Fault(second_stage(false))),
            Some(1 << 11 | 1 << 9 | 0b00_0110 << 1 | 1)
        );
        assert_eq!(
            par(&Outcome::Fault(second_stage(true))),
            Some(1 << 11 | 1 << 9 | 1 << 8 | 0b00_0110 << 1 | 1)
        );
        assert_eq!(par(&Outcome::Unsupported(Unsupported::Stage2)), None);
    }

    #[test]
    fn ctrr_permission_faults_preserve_allowed_reads_at_and_physical_boundaries() {
        let protected = (0x8000_4000, 0x8000_4fff);
        let mut controls = Controls {
            ctrr: Ctrr {
                privileged: [
                    Some(CtrrRegion {
                        first: protected.0,
                        last: protected.1,
                        write_protect: true,
                        execute_inside_only: true,
                    }),
                    None,
                ],
                memory: [None; 4],
            },
            ..Controls::default()
        };
        let mut tables = Tables::default();
        let permission = Outcome::Fault(Fault::stage1(FaultKind::Permission, 3));
        assert_eq!(
            translate(&controls, protected.0, Access::Write, KERNEL, &mut tables),
            permission
        );
        assert_eq!(
            translate(
                &controls,
                protected.1 + 1,
                Access::Execute,
                KERNEL,
                &mut tables
            ),
            permission
        );
        let Outcome::Mapped(read) =
            translate(&controls, protected.0, Access::Read, KERNEL, &mut tables)
        else {
            panic!("CTRR must permit reads");
        };
        assert!(!read.writable && read.executable);
        for (address, access) in [
            (protected.0 - 1, Access::Write),
            (protected.1 + 1, Access::Write),
            (protected.0, Access::Execute),
        ] {
            assert!(matches!(
                translate(&controls, address, access, KERNEL, &mut tables),
                Outcome::Mapped(_)
            ));
        }
        // AT reports the translation tables, not the subsequent physical
        // core protection. Core CTRR does not restrict an EL0 requester.
        assert!(matches!(
            translate_tables(&controls, protected.0, Access::Write, KERNEL, &mut tables),
            Outcome::Mapped(_)
        ));
        let user = Requester { el: 0, ..KERNEL };
        assert!(matches!(
            translate(&controls, protected.0, Access::Write, user, &mut tables),
            Outcome::Mapped(_)
        ));
        // Memory-controller locks bind writes from EL0 as well.
        controls.ctrr.privileged = [None; 2];
        controls.ctrr.memory[0] = Some(protected);
        assert_eq!(
            translate(&controls, protected.0, Access::Write, user, &mut tables),
            permission
        );
        assert!(matches!(
            translate(&controls, protected.0, Access::Read, user, &mut tables),
            Outcome::Mapped(_)
        ));
    }

    #[test]
    fn ctrr_checks_the_final_pa_and_does_not_report_a_stage_two_walk_fault() {
        let (mut controls, mut tables) = two_stages(0x4000_0000);
        controls.ctrr.memory[0] = Some((0x8000_4000, 0x8000_4fff));
        let address = 0x4008;
        let Outcome::Fault(fault) =
            translate(&controls, address, Access::Write, KERNEL, &mut tables)
        else {
            panic!("the final physical CTRR region must deny the store");
        };
        assert_eq!((fault.kind, fault.level), (FaultKind::Permission, 3));
        assert_eq!(fault.data_syndrome(true, false), 0x4f);
        assert_eq!(fault.instruction_syndrome(), 0x0f);
        assert!(!fault.to_el2());
        assert_eq!(fault.hpfar(), None);
        assert!(matches!(
            translate_tables(&controls, address, Access::Write, KERNEL, &mut tables),
            Outcome::Mapped(Translation {
                physical: 0x8000_4008,
                ..
            })
        ));
    }

    #[derive(Default)]
    struct Tables(alloc::collections::BTreeMap<u64, u64>);

    impl TableMemory for Tables {
        fn read_descriptor(&mut self, physical: u64) -> Option<u64> {
            (physical < 0x1_0000_0000).then(|| self.0.get(&physical).copied().unwrap_or(0))
        }
        fn update_descriptor(&mut self, _: u64, _: u64, _: u64) -> Option<bool> {
            unreachable!("the profile has no hardware descriptor updates")
        }
    }

    const KERNEL: Requester = Requester {
        el: 1,
        pan: false,
        unprivileged: false,
        guarded: false,
    };
    /// Stage 2: 4 KiB, 40-bit IPA from two concatenated level-1 tables at
    /// PA 0x10_0000, mapping IPA 1-2 GiB to PA 2-3 GiB as a Normal
    /// Write-Back, Inner Shareable, read/write block.
    const VTCR: u64 = 24 | 1 << 6 | 5 << 16 | 1 << 31;
    const STAGE2_BLOCK: u64 = 0x8000_0000 | 1 | 1 << 10 | 0b11 << 6 | 0b1111 << 2 | 0b11 << 8;
    /// Stage 1: 4 KiB, 39-bit VA from level 1 (EPD1), 48-bit IPS.
    const TCR: u64 = 25 | 1 << 23 | 5 << 32;

    /// Stage-1 table at IPA 0x4000_0000 (PA 0x8000_0000) whose first entry
    /// maps VA 0-1 GiB as a block at `output`.
    fn two_stages(output: u64) -> (Controls, Tables) {
        let mut tables = Tables::default();
        tables.0.insert(0x10_0008, STAGE2_BLOCK);
        tables
            .0
            .insert(0x8000_0000, output | 1 | 1 << 10 | 0b11 << 8);
        let controls = Controls {
            sctlr: SCTLR_M | alignment::SCTLR_C,
            tcr: TCR,
            ttbr0: 0x4000_0000,
            mair: 0xff,
            stage2: true,
            second_stage: Some(Stage2 {
                hcr: HCR_VM,
                vtcr: VTCR,
                vttbr: 0x10_0000,
                xs: test_xs(),
            }),
            xs: test_xs(),
            ..Controls::default()
        };
        (controls, tables)
    }

    #[test]
    fn stage_one_tables_and_output_translate_through_stage_two() {
        let (controls, mut tables) = two_stages(0x4000_0000);
        let Outcome::Mapped(full) =
            translate(&controls, 0x1234, Access::Write, KERNEL, &mut tables)
        else {
            panic!("full translation")
        };
        assert_eq!(full.physical, 0x8000_1234);
        assert_eq!(
            (full.attributes, full.shareability, full.size),
            (0xff, 0b11, 1 << 30)
        );
        let Outcome::Mapped(first) =
            translate_stage1(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
        else {
            panic!("stage 1 alone")
        };
        assert_eq!(first.physical, 0x4000_1234);

        // An output IPA stage 2 does not map: a stage-2 Translation fault on
        // the access, reported with its IPA.
        let (controls, mut tables) = two_stages(0xc000_0000);
        let Outcome::Fault(fault) = translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
        else {
            panic!("stage-2 fault")
        };
        assert_eq!((fault.kind, fault.level), (FaultKind::Translation, 1));
        assert_eq!(
            fault.second_stage,
            Some(SecondStage {
                ipa: 0xc000_1234,
                walk: false
            })
        );
        assert_eq!(fault.hpfar(), Some(0x000c_0001 << 4));

        // A stage-1 table at an IPA stage 2 does not map: a stage-2 fault
        // on the walk, for AT S1E* as well.
        let (mut controls, mut tables) = two_stages(0x4000_0000);
        controls.ttbr0 = 0;
        let walk = Fault {
            kind: FaultKind::Translation,
            level: 1,
            second_stage: Some(SecondStage { ipa: 0, walk: true }),
        };
        assert_eq!(
            translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables),
            Outcome::Fault(walk)
        );
        assert_eq!(
            translate_stage1(&controls, 0x1234, Access::Read, KERNEL, &mut tables),
            Outcome::Fault(walk)
        );
        assert_eq!(
            par(&Outcome::Fault(walk)),
            Some(1 << 11 | 1 << 9 | 1 << 8 | 0b00_0101 << 1 | 1)
        );
    }

    #[test]
    fn stage_two_applies_under_vm_or_dc_without_tge_and_is_never_skipped() {
        let (mut controls, mut tables) = two_stages(0x4000_0000);
        // HCR_EL2.DC alone: stage 1 behaves as disabled with Normal
        // Write-Back Non-shareable output, and stage 2 applies.
        controls.second_stage = Some(Stage2 {
            hcr: HCR_DC,
            ..controls.second_stage.unwrap()
        });
        let Outcome::Mapped(default) =
            translate(&controls, 0x4000_1234, Access::Read, KERNEL, &mut tables)
        else {
            panic!("HCR_EL2.DC")
        };
        assert_eq!(default.physical, 0x8000_1234);
        assert_eq!((default.attributes, default.shareability), (0xff, 0b11));
        // HCR_EL2.DCT makes that default Tagged where the chip has
        // FEAT_MTE2 (AArch64.S1DisabledOutput), through stage 2's
        // Write-Back memory.
        controls.second_stage = Some(Stage2 {
            hcr: HCR_DC | HCR_DCT,
            ..controls.second_stage.unwrap()
        });
        for tagged in [false, true] {
            controls.tagged = tagged;
            let Outcome::Mapped(default) =
                translate(&controls, 0x4000_1234, Access::Read, KERNEL, &mut tables)
            else {
                panic!("HCR_EL2.DCT")
            };
            assert_eq!(
                default.attributes,
                if tagged { attributes::TAGGED } else { 0xff }
            );
        }
        // A descriptor selecting MAIR's 0xf0 is Tagged through stage 2's
        // Write-Back block; stage-2 Non-cacheable memory is Untagged.
        controls.mair = u64::from(attributes::TAGGED);
        for (block, expected) in [
            (STAGE2_BLOCK, attributes::TAGGED),
            (
                STAGE2_BLOCK & !(0b1111 << 2) | 0b0101 << 2,
                attributes::non_cacheable(attributes::TAGGED, test_xs()),
            ),
        ] {
            tables.0.insert(0x10_0008, block);
            controls.second_stage = Some(Stage2 {
                hcr: HCR_VM,
                ..controls.second_stage.unwrap()
            });
            let Outcome::Mapped(tagged) =
                translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
            else {
                panic!("Tagged stage 1")
            };
            assert_eq!(tagged.attributes, expected);
        }
        tables.0.insert(0x10_0008, STAGE2_BLOCK);
        controls.mair = 0xff;
        controls.tagged = false;
        controls.second_stage = Some(Stage2 {
            hcr: HCR_DC,
            ..controls.second_stage.unwrap()
        });
        // TGE set: the EL1&0 regime has no stage 2, so TTBR0 is a PA.
        tables.0.insert(0x4000_0000, tables.0[&0x8000_0000]);
        controls.second_stage = Some(Stage2 {
            hcr: HCR_VM | HCR_TGE,
            ..controls.second_stage.unwrap()
        });
        let Outcome::Mapped(stage1) =
            translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables)
        else {
            panic!("TGE")
        };
        assert_eq!(stage1.physical, 0x4000_1234);
        // Stage 2 required without its controls refuses.
        controls.second_stage = None;
        assert_eq!(
            translate(&controls, 0x1234, Access::Read, KERNEL, &mut tables),
            Outcome::Unsupported(Unsupported::Stage2)
        );
        assert_eq!(
            Stage2 {
                vttbr: 0xab << 48,
                ..Stage2::default()
            }
            .vmid(),
            0xab
        );
    }

    #[test]
    fn alignment_is_checked_before_translation_and_ahead_of_permissions() {
        use alignment::{Kind, Shape};
        let plain = Shape {
            kind: Kind::Plain,
            bytes: 8,
            pair: false,
        };
        let atomic = Shape {
            kind: Kind::Atomic,
            ..plain
        };
        let alignment_fault = |outcome: Outcome| match outcome {
            Outcome::Fault(fault) => Some((fault.kind, fault.second_stage.is_some())),
            _ => None,
        };
        let (mut controls, mut tables) = two_stages(0x4000_0000);
        controls.stage2 = false;
        controls.second_stage = None;
        let checked = |controls: &Controls, address, shape, requester, tables: &mut Tables| {
            translate_checked(controls, address, Access::Read, requester, shape, tables)
        };
        // Stage 1 maps VA 0-1 GiB at PA 0x4000_0000 (no stage 2), Normal
        // Write-Back Inner Shareable, EL1 only.
        tables
            .0
            .insert(0x4000_0000, 0x4000_0000 | 1 | 1 << 10 | 0b11 << 8);
        controls.ttbr0 = 0x4000_0000;
        let user = Requester { el: 0, ..KERNEL };
        assert!(matches!(
            checked(&controls, 0x1004, plain, KERNEL, &mut tables),
            Outcome::Mapped(_)
        ));
        // SCTLR.A faults before the walk, even where nothing is mapped.
        controls.sctlr |= alignment::SCTLR_A;
        assert_eq!(
            alignment_fault(checked(
                &controls,
                0x7fff_ffff_0004,
                plain,
                KERNEL,
                &mut tables
            )),
            Some((FaultKind::Alignment, false))
        );
        controls.sctlr &= !(alignment::SCTLR_A | alignment::SCTLR_C);
        // An unaligned atomic inside 16 bytes needs no Write-Back memory or
        // SCTLR.C (Arm's choice for Unpredictable_LSE2_ALIGNMENT_FAULT).
        for sctlr in [controls.sctlr, controls.sctlr | alignment::SCTLR_C] {
            controls.sctlr = sctlr;
            assert!(matches!(
                checked(&controls, 0x1004, atomic, KERNEL, &mut tables),
                Outcome::Mapped(_)
            ));
        }
        // Device memory (AttrIndx 1, MAIR byte 0) faults an unaligned access
        // ahead of the Permission fault EL0 would take.
        controls.mair = 0x00ff;
        tables
            .0
            .insert(0x4000_0000, 0x4000_0000 | 1 | 1 << 10 | 1 << 2);
        assert_eq!(
            alignment_fault(checked(&controls, 0x1004, plain, user, &mut tables)),
            Some((FaultKind::Alignment, false))
        );
        assert_eq!(
            alignment_fault(checked(&controls, 0x1008, plain, user, &mut tables)),
            Some((FaultKind::Permission, false))
        );

        // Stage 2 Device memory under Normal stage 1: a stage-2 Alignment
        // fault, taken to EL2 without HPFAR_EL2.
        let (controls, mut tables) = two_stages(0x4000_0000);
        let device = (STAGE2_BLOCK & !(0xf << 2)) | 0b0001 << 2;
        tables.0.insert(0x10_0008, device);
        let Outcome::Fault(fault) = checked(&controls, 0x1004, plain, KERNEL, &mut tables) else {
            panic!("stage-2 alignment")
        };
        assert_eq!(fault.kind, FaultKind::Alignment);
        assert!(fault.to_el2() && fault.hpfar().is_none());
        assert_eq!(fault.data_syndrome(false, false), 0b10_0001);
        let Outcome::Mapped(aligned) = checked(&controls, 0x1008, plain, KERNEL, &mut tables)
        else {
            panic!("aligned Device access")
        };
        assert_eq!(aligned.alignment, Alignment { device: true });
    }

    #[test]
    fn fault_syndromes_and_hpfar_follow_the_stage_and_the_walk() {
        // HPFAR_EL2.FIPA holds IPA[47:12] of the chip's 48-bit IPA space.
        test_translation_chip();
        let stage1 = Fault::stage1(FaultKind::Translation, 3);
        assert_eq!(stage1.data_syndrome(true, false), 0b100_0111);
        assert_eq!(stage1.data_syndrome(false, true), 1 << 8 | 1 << 6 | 0b111);
        assert!(!stage1.to_el2() && stage1.hpfar().is_none());
        let fault = |kind, walk| Fault {
            kind,
            level: 1,
            second_stage: Some(SecondStage {
                ipa: 0x8_1234_5678,
                walk,
            }),
        };
        let walk = fault(FaultKind::Permission, true);
        assert!(walk.to_el2());
        assert_eq!(walk.data_syndrome(false, false), 1 << 7 | 0b00_1101);
        assert_eq!(walk.instruction_syndrome(), 1 << 7 | 0b00_1101);
        assert_eq!(walk.hpfar(), Some(0x0081_2345 << 4));
        // A stage-2 Permission fault on the access itself leaves HPFAR_EL2
        // UNKNOWN (no FEAT_EAESR); Translation, Access flag and Address size
        // faults report it.
        assert_eq!(fault(FaultKind::Permission, false).hpfar(), None);
        assert_eq!(
            fault(FaultKind::AccessFlag, false).hpfar(),
            Some(0x0081_2345 << 4)
        );
        assert_eq!(fault(FaultKind::ExternalOnWalk, false).hpfar(), None);
    }
}
