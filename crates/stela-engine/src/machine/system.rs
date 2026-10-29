//! Architectural System register and System instruction access.
//!
//! `generated` holds every accessor of the Apple CPU profiles as its
//! AARCHMRS permission tree folded against them, a feature only some chips
//! have decided by [`Context::implemented`] for the PE's [`Chip`]: which EL gets UNDEFINED, which trap goes to
//! which EL, which register a name reaches under VHE or NV2, and which
//! operation runs. This module supplies the vocabulary those trees use:
//! `helpers` holds Arm's shared pseudocode functions, and a [`Context`]
//! implements state, memory and operations for one PE.
use stela_compiler::aarch64::system::registers::Encoding;

pub mod file;
pub mod generated;
pub mod helpers;

pub use file::File;
pub use generated::{ACCESSORS, Register};
use stela_contracts::Chip;
use stela_contracts::Feature;

/// How an access ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Completed; an MRS result, if any, was set.
    Done,
    Undefined,
    /// A trapped access: exception class `ec` taken to `el`.
    Trap {
        el: u8,
        ec: u64,
    },
    /// A data abort or other exception raised by an operation.
    Exception(crate::machine::cpu::Exception),
    /// The engine cannot honor the access and stops, naming why.
    Refused(&'static str),
}

/// A register's layout on a PE of `chip` whose identification withholds
/// exactly `withheld` of the `relevant` features (bits of [`Feature`]), where
/// it differs from the chip's (`generated::WITHHELD_LAYOUTS`).
#[derive(Debug)]
pub struct WithheldLayout {
    pub register: Register,
    pub chip: Chip,
    pub relevant: u64,
    pub withheld: u64,
    pub res0: u64,
    pub res1: u64,
    pub reset: u64,
    pub warm: u64,
}

/// One accessor encoding: a pattern over the 16-bit key
/// `op0:op1:CRn:CRm:op2`, the array index bits and the folded tree.
pub struct Accessor {
    pub name: &'static str,
    pub kind: &'static str,
    pub mask: u16,
    pub value: u16,
    /// (key bit, index bit)
    pub index: &'static [(u8, u8)],
    pub run: fn(&mut dyn Context, u64) -> Result<Effect, Effect>,
}

impl Accessor {
    /// MRS and the System instructions with a result read; the rest write.
    pub fn reads(&self) -> bool {
        matches!(self.kind, "MRS" | "SYSL")
    }
}

/// The 16-bit accessor key of an encoding.
pub fn key(encoding: Encoding) -> u16 {
    (u16::from(encoding.op0()) << 14)
        | (u16::from(encoding.op1()) << 11)
        | (u16::from(encoding.crn()) << 7)
        | (u16::from(encoding.crm()) << 3)
        | u16::from(encoding.op2())
}

/// Accessors by key and direction: entry `key * 2 + read` holds the
/// accessor's position plus one, or 0 when none matches.
pub struct Lookup(alloc::vec::Vec<u16>);

impl Default for Lookup {
    fn default() -> Self {
        Self::new()
    }
}

impl Lookup {
    pub fn new() -> Self {
        let mut table = alloc::vec![0u16; 1 << 17];
        for (position, accessor) in ACCESSORS.iter().enumerate() {
            // Enumerate the keys the pattern admits through its index bits.
            let bits: alloc::vec::Vec<u8> =
                accessor.index.iter().map(|&(key_bit, _)| key_bit).collect();
            for combination in 0..1u32 << bits.len() {
                let mut key = accessor.value;
                for (number, bit) in bits.iter().enumerate() {
                    if combination >> number & 1 != 0 {
                        key |= 1 << bit;
                    }
                }
                let slot = usize::from(key) * 2 + usize::from(accessor.reads());
                if table[slot] == 0 {
                    table[slot] = position as u16 + 1;
                }
            }
        }
        Self(table)
    }

    /// The accessor for an encoding and direction, with its array index.
    pub fn find(&self, encoding: Encoding, read: bool) -> Option<(&'static Accessor, u64)> {
        let key = key(encoding);
        let position = self.0[usize::from(key) * 2 + usize::from(read)].checked_sub(1)?;
        let accessor = &ACCESSORS[usize::from(position)];
        let index = accessor
            .index
            .iter()
            .map(|&(key_bit, index_bit)| u64::from((key >> key_bit) & 1) << index_bit)
            .fold(0, |a, b| a | b);
        Some((accessor, index))
    }
}

/// PSTATE fields an accessor reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pstate {
    N,
    Z,
    C,
    V,
    D,
    A,
    I,
    F,
    SP,
    PAN,
    UAO,
    DIT,
    SSBS,
    /// FEAT_MTE tag check override.
    TCO,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Regime {
    EL10,
    EL20,
    EL2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broadcast {
    NSH,
    ISH,
    OSH,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbiLevel {
    Any,
    Last,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbiAttr {
    AllAttr,
    ExcludeXS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbiKind {
    ALL,
    ASID,
    VA,
    VAA,
    RVA,
    RVAA,
    VMALL,
    VMALLS12,
    IPAS2,
    RIPAS2,
}

/// One TLB maintenance operation (Arm `AArch64_TLBI_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlbi {
    pub kind: TlbiKind,
    pub regime: Regime,
    pub vmid: Option<u64>,
    pub broadcast: Broadcast,
    pub level: TlbiLevel,
    pub attr: TlbiAttr,
    pub operand: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheType {
    Data,
    Instruction,
    /// Allocation tags alone (FEAT_MTE2 `DC *GVA*`, `DC GZVA`).
    Tag,
    /// Data and allocation tags (FEAT_MTE2 `DC *GDVA*`).
    DataTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOp {
    Clean,
    CleanInvalidate,
    Invalidate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheScope {
    PoU,
    PoC,
    PoP,
    PoDP,
    SetWay,
    ALLU,
    ALLUIS,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtAccess {
    Read,
    Write,
    ReadPAN,
    WritePAN,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    S1,
    S12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restrict {
    DataValue,
    ControlFlow,
    CachePrefetch,
    /// `COSP RCTX` (FEAT_SPECRES2).
    Other,
}

/// The operations System instructions perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Tlbi(Tlbi),
    /// `AT`: translate `address` for `el` and stage and write PAR_EL1.
    At {
        stage: Stage,
        el: u64,
        access: AtAccess,
        address: u64,
    },
    /// `DC` by VA or set/way.
    Dc {
        kind: CacheType,
        op: CacheOp,
        scope: CacheScope,
        operand: u64,
    },
    /// `IC`; the operand is the VA for `IC IVAU`.
    Ic {
        scope: CacheScope,
        operand: u64,
    },
    /// `DC ZVA`.
    ZeroBlock {
        kind: CacheType,
        address: u64,
    },
    /// `CFP`, `DVP`, `CPP RCTX`.
    RestrictPrediction {
        kind: Restrict,
        context: u64,
    },
}

/// Implementation sizes accessors test against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Breakpoints,
    Watchpoints,
    AuxiliaryMonitors,
}

/// RAS error record registers reached through the ERX*_EL1 window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorRecord {
    Addr,
    Ctlr,
    Fr,
    /// ERRGSR (FEAT_RASv2), the error group status.
    Gsr,
    Misc0,
    Misc1,
    Misc2,
    Misc3,
    Pfgcdn,
    Pfgctl,
    Pfgf,
    Status,
}

/// One PE's state, memory and operations, as the generated accessors see
/// them.
pub trait Context {
    /// The PE's chip.
    fn chip(&self) -> Chip;
    /// Arm `IsFeatureImplemented` for a feature only some chips have, as
    /// the PE's identification presents it (`File::implemented`); a feature
    /// the PE has and the engine does not implement stops.
    fn implemented(&self, feature: Feature) -> Result<bool, Effect>;
    /// PSTATE.EL.
    fn el(&self) -> u64;
    fn pstate(&self, field: Pstate) -> u64;
    fn set_pstate(&mut self, field: Pstate, value: u64);
    /// The transfer register's value; XZR reads 0.
    fn x(&self) -> u64;
    /// The MRS or SYSL result.
    fn set_x(&mut self, value: u64);
    fn read(&self, register: Register, index: u64) -> u64;
    fn write(&mut self, register: Register, index: u64, value: u64) -> Result<(), Effect>;
    /// `PhysicalCountInt()`: the physical count of the system counter.
    fn physical_count(&self) -> u64;
    /// FEAT_NV2 register access redirected to memory at VNCR_EL2 + offset.
    fn nv_mem(&mut self, offset: u64) -> Result<u64, Effect>;
    fn set_nv_mem(&mut self, offset: u64, value: u64) -> Result<(), Effect>;
    fn operation(&mut self, operation: Operation) -> Result<(), Effect>;
    /// The IMPLEMENTATION DEFINED register and System instruction space.
    fn implementation_defined(&mut self, read: bool) -> Result<Effect, Effect>;
    /// `Read_DBGDTR_EL0{width}`: MRS DBGDTRRX_EL0 (32) or DBGDTR_EL0 (64).
    fn read_dbgdtr(&mut self, width: u32) -> u64;
    /// `Write_DBGDTR_EL0{width}`: MSR DBGDTRTX_EL0 (32) or DBGDTR_EL0 (64).
    fn write_dbgdtr(&mut self, width: u32, value: u64) -> Result<(), Effect>;
    fn error_record(&self, register: ErrorRecord, index: u64) -> u64;
    fn set_error_record(
        &mut self,
        register: ErrorRecord,
        index: u64,
        value: u64,
    ) -> Result<(), Effect>;
    /// Whether auxiliary activity monitor `index` is implemented.
    fn auxiliary_monitor(&self, index: u64) -> bool;
    fn limit(&self, limit: Limit) -> u64;
    /// The value chosen for an ARBITRARY (UNKNOWN) result.
    fn arbitrary(&self) -> u64 {
        0
    }
}
