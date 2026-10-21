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
fn constant(words: &mut Vec<u32>, register: u32, value: u64) {
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

/// Reuses the actual preceding LDXP reservation after a host-side ABA write.
pub(super) fn reservation_body(entry: u64) -> Vec<u8> {
    bytes(alloc::vec![STXP_W7_X4_X5_X6, branch(entry + 4, entry)])
}

/// Independent fresh reservations after the stopped CPU clear checkpoint.
pub(super) fn reservation_load_body(entry: u64) -> Vec<u8> {
    bytes(alloc::vec![LDXP_X4_X5_X6, branch(entry + 4, entry)])
}
