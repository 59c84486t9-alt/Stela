//! The complete diagnostic ARM kernel input, generated from named encodings.
use alloc::vec::Vec;
use stela_compiler::aarch64::system::registers::Encoding;
pub(super) const BASE: u64 = 0x100000;
pub(super) const BYTES: usize = 16 * 4096;
pub(super) const DATA: u64 = BASE + 0x4000;
pub(super) const ALIAS: u64 = BASE + 0x5000;
pub(super) const FAULT_OFFSET: u64 = 5 * 4;
pub(super) const CODE: u64 = BASE + 0x8000;
pub(super) const READY: u64 = 0x200000;
pub(super) const INCREMENTS: usize = 192;
const PAGE: u64 = 4096;
const TABLE: u64 = 3;
const AF: u64 = 1 << 10;
const INNER_SHAREABLE: u64 = 3 << 8;
const OUTER_SHAREABLE: u64 = 2 << 8;
const WRITE_SYSTEM_REGISTER: u32 = 0xd5000000;
const SELECTOR_SHIFT: u32 = 5;
const MOVZ64: u32 = 0xd2800000;
const MOVK64: u32 = 0xf2800000;
const IMMEDIATE_SHIFT: u32 = 5;
const HALFWORD_SHIFT: u32 = 21;
const STR_X1_X0: u32 = 0xf9000001;
const STP_X1_X1_X0: u32 = 0xa9000401;
const LDADD_X1_X2_X0: u32 = 0xf8210002;
const STXP_W7_X4_X5_X6: u32 = 0xc82714c4;
const LDXP_X4_X5_X6: u32 = 0xc87f14c4;
const ADD_X9_ONE: u32 = 0x91000529;
const ADD_X3_ONE: u32 = 0x91000463;
const B: u32 = 0x14000000;
const WFI: u32 = 0xd503207f;
const ISB: u32 = 0xd5033fdf;
const SCTLR: u64 = 1 | (1 << 2) | (1 << 12);
const TCR: u64 = 16 | (16 << 16) | (1 << 23) | (5 << 32);
const TTBR0_EL2: Encoding = Encoding::new(3, 4, 2, 0, 0);
const TCR_EL2: Encoding = Encoding::new(3, 4, 2, 0, 2);
const MAIR_EL2: Encoding = Encoding::new(3, 4, 10, 2, 0);
const SCTLR_EL2: Encoding = Encoding::new(3, 4, 1, 0, 0);
pub(super) fn constant(words: &mut Vec<u32>, register: u32, value: u64) {
    for half in 0..4 {
        let opcode = if half == 0 { MOVZ64 } else { MOVK64 };
        words.push(
            opcode
                | (half << HALFWORD_SHIFT)
                | (((value >> (half * 16)) as u32 & 0xffff) << IMMEDIATE_SHIFT)
                | register,
        );
    }
}
fn control(words: &mut Vec<u32>, encoding: Encoding, value: u64) {
    constant(words, 0, value);
    words.push(WRITE_SYSTEM_REGISTER | (u32::from(encoding.selector()) << SELECTOR_SHIFT));
}
fn branch(from: u64, to: u64) -> u32 {
    let displacement = (to as i64 - from as i64) / 4;
    assert!((-(1 << 25)..1 << 25).contains(&displacement));
    B | (displacement as u32 & 0x03ffffff)
}
fn bytes(words: Vec<u32>) -> Vec<u8> {
    words.into_iter().flat_map(u32::to_le_bytes).collect()
}
/// A real ARM prologue establishes EL2 VHE controls and signals readiness over
/// the fixture's Device register. No guest RAM writer runs in the serial warmup.
pub(super) fn warmup() -> (Vec<u8>, u64) {
    let mut words = Vec::new();
    control(&mut words, TTBR0_EL2, BASE);
    control(&mut words, TCR_EL2, TCR);
    control(&mut words, MAIR_EL2, 0xff);
    control(&mut words, SCTLR_EL2, SCTLR);
    words.push(ISB);
    constant(&mut words, 0, READY);
    constant(&mut words, 1, 1);
    words.push(STR_X1_X0);
    words.push(WFI);
    let entry = CODE + words.len() as u64 * 4;
    words.push(ADD_X9_ONE);
    words.push(branch(entry + 4, entry));
    (bytes(words), entry)
}
/// The same real ARM control prologue, entered through checked M0 on every
/// assigned PE. No direct/serial warmup or synthetic Device-ready store runs.
pub(super) fn cold_startup(entry: u64) -> Vec<u8> {
    let mut words = Vec::new();
    control(&mut words, TTBR0_EL2, BASE);
    control(&mut words, TCR_EL2, TCR);
    control(&mut words, MAIR_EL2, 0xff);
    control(&mut words, SCTLR_EL2, SCTLR);
    words.push(ISB);
    words.push(branch(CODE + words.len() as u64 * 4, entry));
    bytes(words)
}
pub(super) fn atomic_body(entry: u64) -> Vec<u8> {
    let mut words = Vec::new();
    constant(&mut words, 0, DATA);
    constant(&mut words, 1, 1);
    constant(&mut words, 6, DATA + 64);
    words.push(LDXP_X4_X5_X6);
    words.extend(core::iter::repeat_n(LDADD_X1_X2_X0, INCREMENTS));
    words.push(ADD_X3_ONE);
    let pc = entry + words.len() as u64 * 4;
    words.push(branch(pc, entry));
    bytes(words)
}
pub(super) fn tables() -> Vec<(u64, u64)> {
    let mut entries = alloc::vec![
        (BASE, (BASE + PAGE) | TABLE),
        (BASE + PAGE, (BASE + 2 * PAGE) | TABLE),
        (BASE + 2 * PAGE, (BASE + 3 * PAGE) | TABLE),
        (BASE + 2 * PAGE + 8, (BASE + 6 * PAGE) | TABLE),
        (
            BASE + 6 * PAGE,
            READY | TABLE | AF | OUTER_SHAREABLE | (1 << 2)
        ),
    ];
    for page in 0..BYTES as u64 / PAGE {
        let address = BASE + page * PAGE;
        entries.push((
            BASE + 3 * PAGE + (address / PAGE) * 8,
            address | TABLE | AF | INNER_SHAREABLE,
        ));
    }
    entries
}

/// Writes through a read-only source VA alias must retain the exact ADD prefix.
pub(super) fn permission_body() -> Vec<u8> {
    let mut words = Vec::new();
    constant(&mut words, 0, ALIAS);
    words.push(ADD_X3_ONE);
    words.push(STR_X1_X0);
    words.push(ADD_X3_ONE);
    words.push(WFI);
    bytes(words)
}
pub(super) fn read_only_alias() -> (u64, u64) {
    const READ_ONLY_EL1: u64 = 1 << 7;
    (
        BASE + 3 * PAGE + (ALIAS / PAGE) * 8,
        DATA | TABLE | AF | INNER_SHAREABLE | READ_ONLY_EL1,
    )
}

/// The scheduler executes this source program through ordinary checked blocks,
/// stopped system services, a real timer FIQ/ERET and a precise data abort.
pub(super) struct KernelProgram {
    pub(super) code: Vec<u8>,
    pub(super) done: u64,
    pub(super) fault_pc: u64,
    pub(super) vectors: Vec<(u64, Vec<u8>)>,
}
pub(super) fn scheduler_body(entry: u64, spsr: u64) -> KernelProgram {
    const ELR_EL2: Encoding = Encoding::new(3, 4, 4, 0, 1);
    const SPSR_EL2: Encoding = Encoding::new(3, 4, 4, 0, 0);
    const VBAR_EL2: Encoding = Encoding::new(3, 4, 12, 0, 0);
    const TPIDR_EL1: Encoding = Encoding::new(3, 0, 13, 0, 4);
    const CNTPCT_EL0: Encoding = Encoding::new(3, 3, 14, 0, 1);
    const CNTP_CVAL_EL0: Encoding = Encoding::new(3, 3, 14, 2, 2);
    const CNTP_CTL_EL0: Encoding = Encoding::new(3, 3, 14, 2, 1);
    const ESR_EL2: Encoding = Encoding::new(3, 4, 5, 2, 0);
    const FAR_EL2: Encoding = Encoding::new(3, 4, 6, 0, 0);
    const READ_SYSTEM_REGISTER: u32 = 0xd5200000;
    const ERET: u32 = 0xd69f03e0;
    const SEVL: u32 = 0xd50320bf;
    const WFE: u32 = 0xd503205f;
    const DSB_SY: u32 = 0xd5033f9f;
    const DAIFCLR_F: u32 = 0xd50341ff;
    const ADD_X0_4096: u32 = 0x91400400;
    const ADD_X20_ONE: u32 = 0x91000694;
    const ADD_X24_ONE: u32 = 0x91000718;
    const VECTOR_BASE: u64 = CODE + 0x2000;
    const SYNC_SPX: u64 = 0x200;
    const FIQ_SPX: u64 = 0x300;
    let msr = |encoding: Encoding, register: u32| {
        WRITE_SYSTEM_REGISTER | (u32::from(encoding.selector()) << SELECTOR_SHIFT) | register
    };
    let mrs = |encoding: Encoding, register: u32| {
        READ_SYSTEM_REGISTER | (u32::from(encoding.selector()) << SELECTOR_SHIFT) | register
    };
    let mut words: Vec<_> = atomic_body(entry)
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect();
    words.pop(); // continue after the exact atomic body, rather than looping it
    constant(&mut words, 0, READY);
    constant(&mut words, 1, 1);
    words.extend([STR_X1_X0, STP_X1_X1_X0]);
    let resume_constant = words.len();
    constant(&mut words, 10, 0);
    words.push(msr(ELR_EL2, 10));
    control(&mut words, SPSR_EL2, spsr);
    words.push(ERET);
    let resume = entry + words.len() as u64 * 4;
    let mut address = Vec::new();
    constant(&mut address, 10, resume);
    words[resume_constant..resume_constant + 4].copy_from_slice(&address);
    words.extend([STXP_W7_X4_X5_X6, SEVL, WFE]);
    control(&mut words, TPIDR_EL1, 0x112233);
    words.push(mrs(TPIDR_EL1, 19));
    constant(&mut words, 0, DATA + 128);
    constant(&mut words, 1, 0x1122334455667788);
    words.extend([STR_X1_X0, DSB_SY]);
    control(&mut words, VBAR_EL2, VECTOR_BASE);
    words.extend([mrs(CNTPCT_EL0, 0), ADD_X0_4096, msr(CNTP_CVAL_EL0, 0)]);
    control(&mut words, CNTP_CTL_EL0, 1);
    words.extend([DAIFCLR_F, WFI]);
    let fault_entry = entry + words.len() as u64 * 4;
    words.extend(
        permission_body()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .take(6),
    );
    let done = entry + words.len() as u64 * 4;
    words.push(branch(done, done));
    let mut fiq = Vec::new();
    control(&mut fiq, CNTP_CTL_EL0, 0);
    constant(&mut fiq, 10, fault_entry);
    fiq.extend([msr(ELR_EL2, 10), ADD_X20_ONE, ERET]);
    let mut abort = alloc::vec![mrs(ESR_EL2, 22), mrs(FAR_EL2, 23), ADD_X24_ONE];
    abort.push(branch(
        VECTOR_BASE + SYNC_SPX + abort.len() as u64 * 4,
        done,
    ));
    KernelProgram {
        code: bytes(words),
        done,
        fault_pc: fault_entry + FAULT_OFFSET,
        vectors: alloc::vec![
            (VECTOR_BASE + FIQ_SPX, bytes(fiq)),
            (VECTOR_BASE + SYNC_SPX, bytes(abort))
        ],
    }
}
