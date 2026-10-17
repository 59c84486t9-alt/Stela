//! The AArch64 identification registers the system engine presents.
//!
//! They advertise exactly what this engine implements, never more than the
//! chip implements: each field is set from one table row whose architectural
//! feature must be in the chip's Apple clang feature set ([`Chip::cap`],
//! `isa/apple-codegen-profiles.json`, from `clang -mcpu=apple-mN
//! --print-enabled-extensions`) and whose basis must hold here. An
//! instruction feature holds when its sample encodings compile for the
//! system-mode block profile on the host target; any other feature is an
//! engine property stated with its reason, or holds only when the kernel
//! level is EL2 as a VHE host. A field with no satisfied row reads its "not
//! implemented" value.
use super::{Chip, registers::encodings::*};
use alloc::vec::Vec;
use stela_compiler::{
    GuestAddress, TargetCpu,
    aarch64::system::registers::Encoding,
    block::{BlockProfile, CompilationPlan},
};

/// Why a row's level holds on this engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// Every sample (clang-assembled A64 words) compiles for the system-mode
    /// profile on the host target, and the engine completes their exits.
    Instructions(&'static [u32]),
    /// An engine property, true or false, and why.
    Engine(bool, &'static str),
    /// Holds when the profile has EL2, which runs only as a VHE host
    /// (HCR_EL2.E2H set, EL1 never executing).
    Host(&'static str),
}

/// One level of one field. A field's rows are listed in increasing level;
/// the field reads the highest satisfied level, or `absent`.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub register: Encoding,
    pub shift: u8,
    pub level: u64,
    pub absent: u64,
    /// The `FEAT_` tag the chip must have; `None` for fields the architecture
    /// fixes for any AArch64 PE.
    pub feature: Option<&'static str>,
    pub basis: Basis,
}

const fn row(
    register: Encoding,
    shift: u8,
    level: u64,
    absent: u64,
    feature: Option<&'static str>,
    basis: Basis,
) -> Row {
    Row {
        register,
        shift,
        level,
        absent,
        feature,
        basis,
    }
}

const fn feature(
    register: Encoding,
    shift: u8,
    level: u64,
    name: &'static str,
    basis: Basis,
) -> Row {
    row(register, shift, level, 0, Some(name), basis)
}

const fn fixed(register: Encoding, shift: u8, level: u64, reason: &'static str) -> Row {
    row(register, shift, level, 0, None, Basis::Engine(true, reason))
}

const fn engine(holds: bool, reason: &'static str) -> Basis {
    Basis::Engine(holds, reason)
}

const NO_NESTING: &str = "nested virtualization is outside the profile (Apple offers it from M3)";
const VHE_HOST: &str = "EL2 with E2H set and the EL1 register redirection";
const STAGE2_HOST: &str = "stage-2 translation of the EL1&0 regime";
const NO_MONITORS: &str = "no activity, performance or trace monitor is modeled";
const NO_GUARANTEE: &str = "translated code gives no such timing or speculation guarantee";

/// Every ID register the table defines; all their other fields read 0.
pub const REGISTERS: &[Encoding] = &[
    ID_AA64PFR0_EL1,
    ID_AA64PFR1_EL1,
    ID_AA64ISAR0_EL1,
    ID_AA64ISAR1_EL1,
    ID_AA64ISAR2_EL1,
    ID_AA64MMFR0_EL1,
    ID_AA64MMFR1_EL1,
    ID_AA64MMFR2_EL1,
    ID_AA64DFR0_EL1,
    ID_AA64DFR1_EL1,
    ID_AA64AFR0_EL1,
    ID_AA64AFR1_EL1,
    ID_AA64ZFR0_EL1,
    ID_AA64SMFR0_EL1,
    ID_AA64PFR2_EL1,
    ID_AA64FPFR0_EL1,
    ID_AA64DFR2_EL1,
    ID_AA64ISAR3_EL1,
    ID_AA64MMFR3_EL1,
    ID_AA64MMFR4_EL1,
    CTR_EL0,
    AIDR_EL1,
    // No caches are visible: memory is coherent and CTR_EL0.IDC holds, so
    // CLIDR_EL1 reports no cache level and LoC, LoUU and LoUIS 0, and
    // CCSIDR_EL1 (UNKNOWN for an unimplemented cache) reads 0.
    CLIDR_EL1,
    CCSIDR_EL1,
    // No revision-specific information.
    REVIDR_EL1,
    // FEAT_LOR with no LORegions or descriptors (LORID_EL1 LR = LD = 0),
    // FEAT_MPAM with only PARTID 0 and PMG 0 and no MPAMHCR_EL2 or virtual
    // PARTID mapping, and FEAT_RAS with no error records (ERRIDR_EL1.NUM 0).
    LORID_EL1,
    MPAMIDR_EL1,
    ERRIDR_EL1,
    // No external debug ROM table.
    MDRAR_EL1,
    DBGAUTHSTATUS_EL1,
];

pub const TABLE: &[Row] = &[
    // ID_AA64PFR0_EL1
    fixed(ID_AA64PFR0_EL1, 0, 1, "EL0 is AArch64-only"),
    fixed(ID_AA64PFR0_EL1, 4, 1, "EL1 is AArch64-only"),
    row(ID_AA64PFR0_EL1, 8, 1, 0, None, Basis::Host(VHE_HOST)),
    row(
        ID_AA64PFR0_EL1,
        16,
        0,
        0xf,
        Some("FEAT_FP"),
        Basis::Instructions(&[0x1e22_2820]),
    ),
    feature(
        ID_AA64PFR0_EL1,
        16,
        1,
        "FEAT_FP16",
        Basis::Instructions(&[0x1ee2_2820]),
    ),
    row(
        ID_AA64PFR0_EL1,
        20,
        0,
        0xf,
        Some("FEAT_AdvSIMD"),
        Basis::Instructions(&[0x4ea2_8420]),
    ),
    feature(
        ID_AA64PFR0_EL1,
        20,
        1,
        "FEAT_FP16",
        Basis::Instructions(&[0x4e42_1420]),
    ),
    feature(
        ID_AA64PFR0_EL1,
        28,
        1,
        "FEAT_RAS",
        engine(
            true,
            "no error records (ERRIDR_EL1.NUM 0, ERX* RAZ/WI); ESB and virtual SErrors",
        ),
    ),
    feature(
        ID_AA64PFR0_EL1,
        28,
        2,
        "FEAT_RASv1p1",
        engine(true, "ERXMISC2/3 and ERXPFG* of no error record, RAZ/WI"),
    ),
    feature(
        ID_AA64PFR0_EL1,
        36,
        1,
        "FEAT_SEL2",
        engine(false, "no Secure state"),
    ),
    feature(
        ID_AA64PFR0_EL1,
        40,
        1,
        "FEAT_MPAM",
        engine(
            true,
            "MPAM v1.0 with only PARTID 0 and PMG 0, no MPAMHCR_EL2 or VPM",
        ),
    ),
    feature(
        ID_AA64PFR0_EL1,
        44,
        1,
        "FEAT_AMUv1",
        engine(false, NO_MONITORS),
    ),
    feature(
        ID_AA64PFR0_EL1,
        48,
        1,
        "FEAT_DIT",
        engine(false, NO_GUARANTEE),
    ),
    feature(
        ID_AA64PFR0_EL1,
        56,
        2,
        "FEAT_CSV2_2",
        engine(false, NO_GUARANTEE),
    ),
    // ID_AA64PFR1_EL1
    feature(
        ID_AA64PFR1_EL1,
        0,
        1,
        "FEAT_BTI",
        engine(
            true,
            "the engine sets PSTATE.BTYPE at block exits and checks the first \
             instruction of a guarded-page block against it",
        ),
    ),
    feature(
        ID_AA64PFR1_EL1,
        4,
        1,
        "FEAT_SSBS",
        engine(true, "PSTATE.SSBS and MSR SSBS, #imm"),
    ),
    feature(
        ID_AA64PFR1_EL1,
        4,
        2,
        "FEAT_SSBS2",
        engine(true, "MRS and MSR of SSBS"),
    ),
    // ID_AA64ISAR0_EL1
    feature(
        ID_AA64ISAR0_EL1,
        4,
        1,
        "FEAT_AES",
        Basis::Instructions(&[0x4e28_4820]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        4,
        2,
        "FEAT_PMULL",
        Basis::Instructions(&[0x0ee2_e020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        8,
        1,
        "FEAT_SHA1",
        Basis::Instructions(&[0x5e02_0020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        12,
        1,
        "FEAT_SHA256",
        Basis::Instructions(&[0x5e02_4020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        12,
        2,
        "FEAT_SHA512",
        Basis::Instructions(&[0xce62_8020]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        16,
        1,
        "FEAT_CRC32",
        Basis::Instructions(&[0x9ac2_4c20]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        20,
        2,
        "FEAT_LSE",
        Basis::Instructions(&[0xf820_0041, 0xc8e0_fc41]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        28,
        1,
        "FEAT_RDM",
        Basis::Instructions(&[0x6e82_8420]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        32,
        1,
        "FEAT_SHA3",
        Basis::Instructions(&[0xce02_0c20]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        44,
        1,
        "FEAT_DotProd",
        Basis::Instructions(&[0x4e82_9420]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        48,
        1,
        "FEAT_FHM",
        Basis::Instructions(&[0x0e22_ec20]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        52,
        1,
        "FEAT_FlagM",
        Basis::Instructions(&[0xd500_401f]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        52,
        2,
        "FEAT_FlagM2",
        Basis::Instructions(&[0xd500_405f]),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        56,
        1,
        "FEAT_TLBIOS",
        engine(true, "every TLBI invalidates"),
    ),
    feature(
        ID_AA64ISAR0_EL1,
        56,
        2,
        "FEAT_TLBIRANGE",
        engine(true, "every TLBI invalidates"),
    ),
    // ID_AA64ISAR1_EL1
    feature(
        ID_AA64ISAR1_EL1,
        0,
        1,
        "FEAT_DPB",
        Basis::Instructions(&[0xd50b_7c20]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        0,
        2,
        "FEAT_DPB2",
        Basis::Instructions(&[0xd50b_7d20]),
    ),
    // QARMA5 in the Classic policy; FPAC (level 4) needs faulting AUT.
    feature(
        ID_AA64ISAR1_EL1,
        4,
        1,
        "FEAT_PAuth",
        Basis::Instructions(&[0xdac1_0020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        4,
        4,
        "FEAT_FPAC",
        engine(
            true,
            "PAuth2 with failed AUT* taking EC 0x1C; combined forms corrupt",
        ),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        12,
        1,
        "FEAT_JSCVT",
        Basis::Instructions(&[0x1e7e_0020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        16,
        1,
        "FEAT_FCMA",
        Basis::Instructions(&[0x6e82_c420]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        20,
        1,
        "FEAT_LRCPC",
        Basis::Instructions(&[0xf8bf_c020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        20,
        2,
        "FEAT_LRCPC2",
        Basis::Instructions(&[0xd940_0020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        24,
        1,
        "FEAT_PAuth",
        Basis::Instructions(&[0x9ac2_3020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        32,
        1,
        "FEAT_FRINTTS",
        Basis::Instructions(&[0x1e28_4020]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        36,
        1,
        "FEAT_SB",
        Basis::Instructions(&[0xd503_30ff]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        40,
        1,
        "FEAT_SPECRES",
        engine(false, "CFP, DVP and CPP RCTX are not modeled"),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        44,
        1,
        "FEAT_BF16",
        Basis::Instructions(&[0x6e42_fc20]),
    ),
    feature(
        ID_AA64ISAR1_EL1,
        52,
        1,
        "FEAT_I8MM",
        Basis::Instructions(&[0x4e82_a420]),
    ),
    // ID_AA64MMFR0_EL1
    fixed(ID_AA64MMFR0_EL1, 0, 0b0101, "48-bit physical addresses"),
    fixed(ID_AA64MMFR0_EL1, 4, 0b0010, "16-bit ASIDs"),
    fixed(ID_AA64MMFR0_EL1, 20, 1, "16 KiB stage-1 granule"),
    row(
        ID_AA64MMFR0_EL1,
        24,
        0,
        0xf,
        None,
        engine(false, "the walker refuses 64 KiB granules"),
    ),
    row(
        ID_AA64MMFR0_EL1,
        28,
        0,
        0xf,
        None,
        engine(true, "4 KiB stage-1 granule"),
    ),
    // TGran16_2, TGran64_2 and TGran4_2: 0b0001 (not supported) without
    // EL2; with it, machine::mmu's stage 2 takes 16 KiB and 4 KiB granules
    // (0b0010) and refuses 64 KiB.
    fixed(ID_AA64MMFR0_EL1, 32, 1, "no stage 2 without EL2"),
    row(ID_AA64MMFR0_EL1, 32, 2, 1, None, Basis::Host(STAGE2_HOST)),
    fixed(
        ID_AA64MMFR0_EL1,
        36,
        1,
        "the walker refuses 64 KiB stage-2 granules",
    ),
    fixed(ID_AA64MMFR0_EL1, 40, 1, "no stage 2 without EL2"),
    row(ID_AA64MMFR0_EL1, 40, 2, 1, None, Basis::Host(STAGE2_HOST)),
    feature(
        ID_AA64MMFR0_EL1,
        56,
        1,
        "FEAT_FGT",
        engine(
            true,
            "the generated accessors apply HFG*TR, HDFG*TR and HAFGRTR; \
             HFGITR_EL2 also traps ERET and SVC",
        ),
    ),
    feature(
        ID_AA64MMFR0_EL1,
        60,
        1,
        "FEAT_ECV",
        engine(
            true,
            "CNTPCTSS_EL0 and CNTVCTSS_EL0, EVNTIS on both event streams and \
             the EL1TVT and EL1TVCT traps; CNTPOFF_EL2 is FEAT_ECV_POFF, \
             outside the profile",
        ),
    ),
    // ID_AA64MMFR1_EL1
    feature(ID_AA64MMFR1_EL1, 8, 1, "FEAT_VHE", Basis::Host(VHE_HOST)),
    // FEAT_HPDS (Armv8.1), FEAT_XNX, FEAT_TTCNP (Armv8.2), FEAT_S2FWB,
    // FEAT_TTL (Armv8.4) and FEAT_E0PD (Armv8.5) are mandatory in the
    // Armv8.6 profile, without an Apple clang feature name.
    row(
        ID_AA64MMFR1_EL1,
        12,
        1,
        0,
        None,
        engine(
            true,
            "TCR_ELx.HPD0 and HPD1 disable hierarchical permissions",
        ),
    ),
    row(
        ID_AA64MMFR1_EL1,
        28,
        1,
        0,
        None,
        Basis::Host("stage-2 XN[1:0] selects EL0 and EL1 execution"),
    ),
    feature(
        ID_AA64MMFR1_EL1,
        16,
        1,
        "FEAT_LOR",
        // No LORegions (LORID_EL1 0): LDLAR and STLLR order like LDAR and
        // STLR, which is always permitted.
        Basis::Instructions(&[0xc8df_7c20, 0xc89f_7c20]),
    ),
    feature(
        ID_AA64MMFR1_EL1,
        20,
        1,
        "FEAT_PAN",
        engine(true, "PSTATE.PAN and SPAN"),
    ),
    feature(
        ID_AA64MMFR1_EL1,
        20,
        2,
        "FEAT_PAN2",
        engine(true, "AT S1E1RP and S1E1WP"),
    ),
    // ID_AA64MMFR2_EL1
    row(
        ID_AA64MMFR2_EL1,
        0,
        1,
        0,
        None,
        engine(
            true,
            "CnP is a hint for TLBs that PEs share, and one PE shares none",
        ),
    ),
    row(
        ID_AA64MMFR2_EL1,
        40,
        1,
        0,
        None,
        Basis::Host("HCR_EL2.FWB lets stage 2 override stage-1 attributes"),
    ),
    row(
        ID_AA64MMFR2_EL1,
        48,
        1,
        0,
        None,
        engine(true, "TTL hints narrow the TLBI scope (machine::mmu::tlbi)"),
    ),
    row(
        ID_AA64MMFR2_EL1,
        60,
        1,
        0,
        None,
        engine(
            true,
            "TCR_ELx.E0PD0 and E0PD1 fault EL0 accesses at level 0",
        ),
    ),
    // FEAT_IDST (Armv8.4) and FEAT_EVT (Armv8.5), with the profile's
    // FEAT_EVT2, are mandatory in the Armv8.6 profile, without an Apple clang
    // feature name.
    row(
        ID_AA64MMFR2_EL1,
        36,
        1,
        0,
        None,
        engine(
            true,
            "EL0 reads of the ID space and accesses to unimplemented ID \
             registers trap with EC 0x18",
        ),
    ),
    row(
        ID_AA64MMFR2_EL1,
        56,
        1,
        0,
        None,
        Basis::Host("HCR_EL2.TID4, TICAB and TOCU trap through the generated accessors"),
    ),
    row(
        ID_AA64MMFR2_EL1,
        56,
        2,
        0,
        None,
        Basis::Host("HCR_EL2.TTLBIS and TTLBOS trap the Inner and Outer Shareable TLBIs"),
    ),
    feature(
        ID_AA64MMFR2_EL1,
        4,
        1,
        "FEAT_UAO",
        engine(
            true,
            "the engine performs LDTR/STTR with EL0 permissions unless \
             PSTATE.UAO makes them privileged",
        ),
    ),
    feature(
        ID_AA64MMFR2_EL1,
        24,
        1,
        "FEAT_NV",
        engine(false, NO_NESTING),
    ),
    feature(
        ID_AA64MMFR2_EL1,
        32,
        1,
        "FEAT_LSE2",
        engine(false, "unaligned single-copy atomicity is not guaranteed"),
    ),
    // ID_AA64DFR0_EL1: the Armv8.4 debug architecture (FEAT_Debugv8p4,
    // implied by Armv8.6), and the breakpoint and watchpoint counts of
    // machine::debug, which are Stela's choice.
    fixed(ID_AA64DFR0_EL1, 0, 0b1001, "self-hosted debug of Armv8.4"),
    fixed(
        ID_AA64DFR0_EL1,
        12,
        super::debug::BREAKPOINTS - 1,
        "breakpoints (machine::debug::BREAKPOINTS)",
    ),
    fixed(
        ID_AA64DFR0_EL1,
        20,
        super::debug::WATCHPOINTS - 1,
        "watchpoints (machine::debug::WATCHPOINTS)",
    ),
    fixed(
        ID_AA64DFR0_EL1,
        28,
        super::debug::CONTEXT_AWARE - 1,
        "context-aware breakpoints (machine::debug::CONTEXT_AWARE)",
    ),
    feature(
        ID_AA64DFR0_EL1,
        8,
        1,
        "FEAT_PMUv3",
        engine(false, NO_MONITORS),
    ),
    fixed(ID_AA64DFR0_EL1, 36, 0xf, "no OS Double Lock"),
    feature(
        ID_AA64DFR0_EL1,
        40,
        1,
        "FEAT_TRF",
        engine(false, NO_MONITORS),
    ),
    // CTR_EL0: bit 31 is RES1; 64-byte lines like the DC ZVA block; PIPT
    // instruction cache; instruction fetch needs IC (DIC 0) but no data
    // clean (IDC 1), because translation reads guest RAM directly.
    fixed(CTR_EL0, 0, 4, "64-byte instruction cache lines"),
    fixed(CTR_EL0, 14, 0b11, "PIPT instruction cache"),
    fixed(CTR_EL0, 16, 4, "64-byte data cache lines"),
    fixed(CTR_EL0, 20, 4, "64-byte exclusives reservation granule"),
    fixed(CTR_EL0, 24, 4, "64-byte writeback granule"),
    fixed(
        CTR_EL0,
        28,
        1,
        "IDC: no data clean for instruction coherence",
    ),
    fixed(CTR_EL0, 31, 1, "RES1"),
    // ID_AA64MMFR4_EL1.E2H0 = 0b1110: HCR_EL2.E2H is RES1 (no FEAT_E2H0) and
    // HCR_EL2.NV1 is RES0 (no FEAT_NV). The M2 itself predates the field.
    fixed(
        ID_AA64MMFR4_EL1,
        24,
        0b1110,
        "E2H is RES1 and there is no FEAT_NV1",
    ),
    // DBGAUTHSTATUS_EL1: Non-secure invasive and non-invasive debug are
    // implemented and externally disabled (no external debugger); no Secure,
    // Realm or Root state.
    fixed(
        DBGAUTHSTATUS_EL1,
        0,
        0b10,
        "external invasive debug disabled",
    ),
    fixed(
        DBGAUTHSTATUS_EL1,
        2,
        0b10,
        "external non-invasive debug disabled",
    ),
    // AIDR_EL1: Apple feature bits, named by m1n1 `cpu_regs.h`. Apple
    // features have no clang `FEAT_` tag; each bit is an engine property.
    // Bits m1n1 does not name read 0.
    fixed(
        AIDR_EL1,
        4,
        1,
        "AMX: machine::amx executes the AMX instructions",
    ),
    fixed(
        AIDR_EL1,
        16,
        1,
        "GXF: GENTER, GEXIT and the guarded-level banks",
    ),
    row(
        AIDR_EL1,
        0,
        1,
        0,
        None,
        engine(false, "MUL53 instructions are not modeled"),
    ),
    row(
        AIDR_EL1,
        1,
        1,
        0,
        None,
        engine(false, "WKdm compression instructions are not modeled"),
    ),
    row(
        AIDR_EL1,
        2,
        1,
        0,
        None,
        engine(false, "architectural state retention is not modeled"),
    ),
    row(
        AIDR_EL1,
        9,
        1,
        0,
        None,
        engine(false, "the ACTLR TSO mode switch is not modeled"),
    ),
    row(
        AIDR_EL1,
        19,
        1,
        0,
        None,
        engine(false, "APFLG is not modeled"),
    ),
    row(
        AIDR_EL1,
        20,
        1,
        0,
        None,
        engine(false, "PSRV is not modeled"),
    ),
];

fn holds(row: &Row, chip: Chip, target: TargetCpu, el2: bool) -> bool {
    if row
        .feature
        .is_some_and(|feature| !chip.cap().contains(&feature))
    {
        return false;
    }
    match row.basis {
        Basis::Engine(holds, _) => holds,
        Basis::Host(_) => el2,
        Basis::Instructions(samples) => samples.iter().all(|word| {
            CompilationPlan::new(
                &word.to_le_bytes(),
                GuestAddress(0x1000),
                BlockProfile::SystemModeV1,
                target,
            )
            .and_then(CompilationPlan::compile)
            .is_ok()
        }),
    }
}

/// Every register of [`REGISTERS`] with its value for `chip` on this host
/// target, with or without EL2.
pub fn derive(chip: Chip, target: TargetCpu, el2: bool) -> Vec<(Encoding, u64)> {
    REGISTERS
        .iter()
        .map(|&register| {
            let mut value = 0u64;
            let mut fields: Vec<(u8, u64)> = Vec::new();
            for row in TABLE.iter().filter(|row| row.register == register) {
                let current = match fields.iter_mut().find(|(shift, _)| *shift == row.shift) {
                    Some(field) => field,
                    None => {
                        fields.push((row.shift, row.absent));
                        fields.last_mut().expect("just pushed")
                    }
                };
                if holds(row, chip, target, el2) {
                    current.1 = row.level;
                }
            }
            for (shift, field) in fields {
                value |= field << shift;
            }
            (register, value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, path::Path};

    fn json(name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../isa")
            .join(name);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn every_row_names_an_apple_clang_feature() {
        let profiles = json("apple-codegen-profiles.json");
        let known: BTreeSet<String> = profiles["profiles"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|profile| {
                profile["architectural_features"]
                    .as_array()
                    .unwrap()
                    .clone()
            })
            .map(|feature| feature.as_str().unwrap().to_owned())
            .collect();
        for row in TABLE {
            if let Some(feature) = row.feature {
                assert!(
                    known.contains(feature),
                    "{feature} is not an Apple clang feature"
                );
            }
        }
    }

    #[test]
    fn minimal_feature_configurations_are_advertised() {
        let values = derive(Chip::DEFAULT, TargetCpu::detect(), true);
        let value = |register| values.iter().find(|(r, _)| *r == register).unwrap().1;
        let field = |register, shift: u32| (value(register) >> shift) & 0xf;
        // RASv1p1, MPAM v1.0 and no AMU in ID_AA64PFR0_EL1; LOR in MMFR1.
        assert_eq!(field(ID_AA64PFR0_EL1, 28), 2);
        assert_eq!(field(ID_AA64PFR0_EL1, 40), 1);
        assert_eq!(field(ID_AA64PFR0_EL1, 44), 0);
        assert_eq!(field(ID_AA64MMFR1_EL1, 16), 1);
        assert_eq!(field(ID_AA64MMFR4_EL1, 24), 0b1110);
        for register in [
            LORID_EL1,
            MPAMIDR_EL1,
            ERRIDR_EL1,
            CLIDR_EL1,
            CCSIDR_EL1,
            MDRAR_EL1,
            REVIDR_EL1,
            ID_AA64ISAR3_EL1,
        ] {
            assert_eq!(value(register), 0, "{register:?}");
        }
        assert_eq!(value(DBGAUTHSTATUS_EL1), 0b1010);
    }

    #[test]
    fn advertised_instruction_fields_match_what_the_decoder_compiles() {
        let target = TargetCpu::detect();
        let values = derive(Chip::DEFAULT, target, false);
        let value = |register| values.iter().find(|(r, _)| *r == register).unwrap().1;
        for row in TABLE {
            let field = (value(row.register) >> row.shift) & 0xf;
            let Basis::Instructions(samples) = row.basis else {
                continue;
            };
            let compiles = samples.iter().all(|word| {
                CompilationPlan::new(
                    &word.to_le_bytes(),
                    GuestAddress(0x1000),
                    BlockProfile::SystemModeV1,
                    target,
                )
                .and_then(CompilationPlan::compile)
                .is_ok()
            });
            // A satisfied row means the field reads at least its level; an
            // unsatisfied lowest row means it reads `absent`.
            if compiles {
                assert!(
                    field == row.level || field > row.level && field != row.absent,
                    "{:?} field {} reads {field}",
                    row.register,
                    row.shift
                );
            }
            let lowest = TABLE
                .iter()
                .filter(|other| other.register == row.register && other.shift == row.shift)
                .map(|other| other.level)
                .min()
                .unwrap();
            if !compiles && row.level == lowest {
                assert_eq!(field, row.absent, "{:?} field {}", row.register, row.shift);
            }
        }
        // Features the M2 lacks are never advertised: SVE stays 0.
        assert_eq!(value(ID_AA64PFR0_EL1) >> 32 & 0xf, 0);
        assert_eq!(value(ID_AA64ZFR0_EL1), 0);
    }

    #[test]
    fn fixed_and_engine_fields() {
        let values = derive(Chip::DEFAULT, TargetCpu::detect(), false);
        let value = |register| values.iter().find(|(r, _)| *r == register).unwrap().1;
        // EL0/EL1 AArch64, no EL2/EL3; 48-bit PA, 16-bit ASID, 16K and 4K but
        // not 64K granules; PAN2; Armv8.0 debug without double lock.
        assert_eq!(value(ID_AA64PFR0_EL1) & 0xffff, 0x0011);
        assert_eq!(value(ID_AA64MMFR0_EL1) & 0xffff_ffff, 0x0f10_0025);
        assert_eq!(value(ID_AA64MMFR1_EL1) >> 20 & 0xf, 2);
        assert_eq!(value(ID_AA64DFR0_EL1) & 0xf0f0_f00f, 0x1030_5009);
        // Every other debug field reads its absent value: no PMU, trace,
        // SPE, BRBE or trace buffer, and no OS Double Lock (0xf). The
        // extended counts of ID_AA64DFR1_EL1 defer to ID_AA64DFR0_EL1, and
        // ID_AA64DFR2_EL1 describes only absent features.
        assert_eq!(value(ID_AA64DFR0_EL1), 0xf0_1030_5009);
        assert_eq!(value(ID_AA64DFR1_EL1), 0);
        assert_eq!(value(ID_AA64DFR2_EL1), 0);
        assert_eq!(value(CTR_EL0), 0x9444_c004);
        assert_eq!(value(AIDR_EL1), 1 << 4 | 1 << 16);
        assert_eq!(value(ID_AA64MMFR1_EL1) >> 8 & 0xf, 0);
        // No stage 2 without EL2; HPDS; CnP, TTL and E0PD.
        assert_eq!(value(ID_AA64MMFR0_EL1) >> 32 & 0xfff, 0x111);
        assert_eq!(value(ID_AA64MMFR1_EL1) >> 12 & 0xf, 1);
        assert_eq!(value(ID_AA64MMFR1_EL1) >> 28 & 0xf, 0);
        assert_eq!(
            value(ID_AA64MMFR2_EL1) & (0xf << 60 | 0xf << 48 | 0xf << 40 | 0xf),
            1 << 60 | 1 << 48 | 1
        );
        // With EL2: AArch64 EL2 and VHE.
        let hosted = derive(Chip::DEFAULT, TargetCpu::detect(), true);
        let host = |register| hosted.iter().find(|(r, _)| *r == register).unwrap().1;
        assert_eq!(host(ID_AA64PFR0_EL1), value(ID_AA64PFR0_EL1) | 0x100);
        // With EL2, stage 2 adds 4 KiB and 16 KiB stage-2 granules, XNX and
        // FWB.
        assert_eq!(
            host(ID_AA64MMFR1_EL1),
            value(ID_AA64MMFR1_EL1) | 0x100 | 1 << 28
        );
        assert_eq!(
            host(ID_AA64MMFR0_EL1),
            value(ID_AA64MMFR0_EL1) + (1 << 32) + (1 << 40)
        );
        // FWB and FEAT_EVT2's HCR_EL2 traps; IDST without EL2.
        assert_eq!(
            host(ID_AA64MMFR2_EL1),
            value(ID_AA64MMFR2_EL1) | 1 << 40 | 2 << 56
        );
        assert_eq!(value(ID_AA64MMFR2_EL1) >> 36 & 0xf, 1);
        for &register in REGISTERS {
            if !matches!(
                register,
                ID_AA64PFR0_EL1 | ID_AA64MMFR0_EL1 | ID_AA64MMFR1_EL1 | ID_AA64MMFR2_EL1
            ) {
                assert_eq!(host(register), value(register));
            }
        }
    }

    #[test]
    fn each_chip_advertises_only_its_own_features() {
        let field = |chip: Chip, register, shift: u32| {
            let values = derive(chip, TargetCpu::detect(), true);
            let value = values.iter().find(|(r, _)| *r == register).unwrap().1;
            (value >> shift) & 0xf
        };
        // FGT and ECV (MMFR0), BF16 and I8MM (ISAR1) came with the M2.
        for (register, shift) in [
            (ID_AA64MMFR0_EL1, 56),
            (ID_AA64MMFR0_EL1, 60),
            (ID_AA64ISAR1_EL1, 44),
            (ID_AA64ISAR1_EL1, 52),
        ] {
            assert_eq!(
                field(Chip::AppleM1, register, shift),
                0,
                "{register:?} {shift}"
            );
            assert_ne!(
                field(Chip::AppleM2, register, shift),
                0,
                "{register:?} {shift}"
            );
        }
        // The M2's FPAC (APA 4 in ISAR1) reads as classic PAuth on the M1,
        // whose PACs the engine computes that way.
        assert_eq!(field(Chip::AppleM2, ID_AA64ISAR1_EL1, 4), 4);
        assert_eq!(field(Chip::AppleM1, ID_AA64ISAR1_EL1, 4), 1);
        // Apple clang drops SSBS from the M4 on (PFR1.SSBS).
        assert_ne!(field(Chip::AppleM3, ID_AA64PFR1_EL1, 4), 0);
        assert_eq!(field(Chip::AppleM4, ID_AA64PFR1_EL1, 4), 0);
    }
}
