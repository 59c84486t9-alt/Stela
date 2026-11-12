//! NZCV that pinned code leaves in the host flags between a setter and its
//! readers ([`super::emit_selected`]): every condition after every setter
//! over the carry and overflow edges, in both widths, against the frame
//! emitter, which stores NZCV at each setter; and the word a fault, an
//! exit and a frame-bound emitter find.
use super::{emit_for_target, emit_system_mode};
use crate::{
    GuestAddress, GuestState, Lifter, TargetCpu,
    aarch64::{Decoder, Instruction},
    state::Limit,
    x86_64::{MemoryChecks, NativeSystem, flag_word, native, pinned},
};
use alloc::{vec, vec::Vec};

const CMP_X0_X1: u32 = 0xeb01_001f;
const CMP_W0_W1: u32 = 0x6b01_001f;
const CMP_X0_1: u32 = 0xf100_041f;
const CMP_W0_1: u32 = 0x7100_041f;
const CMN_X0_X1: u32 = 0xab01_001f;
const CMN_W0_1: u32 = 0x3100_041f;
const SUBS_X2: u32 = 0xeb01_0002;
const SUBS_W2: u32 = 0x6b01_0002;
const ADDS_X2: u32 = 0xab01_0002;
const ADDS_W2: u32 = 0x2b01_0002;
const ANDS_X2: u32 = 0xea01_0002;
const ANDS_W2_FF: u32 = 0x7200_1c02;
const TST_X0_X1: u32 = 0xea01_001f;
const BICS_W2: u32 = 0x6a21_0002;
/// CMP X0, W1, UXTW: the extended form.
const CMP_X0_W1_UXTW: u32 = 0xeb21_401f;
const ADDS_X2_W1_SXTW: u32 = 0xab21_c002;

const SETTERS: [u32; 16] = [
    CMP_X0_X1,
    CMP_W0_W1,
    CMP_X0_1,
    CMP_W0_1,
    CMN_X0_X1,
    CMN_W0_1,
    SUBS_X2,
    SUBS_W2,
    ADDS_X2,
    ADDS_W2,
    ANDS_X2,
    ANDS_W2_FF,
    TST_X0_X1,
    BICS_W2,
    CMP_X0_W1_UXTW,
    ADDS_X2_W1_SXTW,
];

const ADD_X3: u32 = 0x9100_0463;
const ADDS_X4: u32 = 0xab01_0004;
const CSEL_X5: u32 = 0x9a81_0005;
const CSINC_W6: u32 = 0x1a80_0426;
const CSINV_X7: u32 = 0xda81_0007;
const CSET_X8: u32 = 0x9a9f_07e8;
const CSETM_X9: u32 = 0xda9f_03e9;
const CSNEG_X10: u32 = 0xda81_040a;
const LDR_X11_X12: u32 = 0xf940_018b;
const MRS_X13_NZCV: u32 = 0xd53b_420d;
const MSR_NZCV_X14: u32 = 0xd51b_420e;

/// The operands: zero, one, the signed and unsigned edges of both widths.
const VALUES: [u64; 10] = [
    0,
    1,
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    0xffff_ffff_ffff_fffe,
    u64::MAX,
];

/// B.cond to `offset` bytes from itself.
const fn b_cond(condition: u32, offset: i32) -> u32 {
    0x5400_0000 | ((offset >> 2) as u32 & 0x7_ffff) << 5 | condition
}

/// `word` with its condition field (bits 15:12) set to `condition`.
const fn with_condition(word: u32, condition: u32) -> u32 {
    word & !(0xf << 12) | condition << 12
}

fn lift(words: &[u32]) -> Vec<Instruction> {
    words
        .iter()
        .enumerate()
        .map(|(index, &word)| {
            Decoder
                .lift(GuestAddress(0x1000 + 4 * index as u64), word)
                .unwrap_or_else(|error| panic!("{word:08x}: {error:?}"))
        })
        .collect()
}

/// The pinned system-mode block of `words` and the frame emitter's.
fn blocks(words: &[u32], target: TargetCpu) -> (Vec<u8>, Vec<u8>) {
    let instructions = lift(words);
    let end = GuestAddress(0x1000 + 4 * words.len() as u64);
    let (system, _) = emit_system_mode(
        &instructions,
        None,
        end,
        target,
        MemoryChecks::DEFAULT,
        NativeSystem::NONE,
    );
    let frame = emit_for_target(&instructions, None, end, target, MemoryChecks::DEFAULT);
    (pinned::entered(&system.x86_64_code), frame.x86_64_code)
}

/// Run both blocks of `words` from states that hold each pair of `VALUES`
/// in X0 and X1 and assert that they leave the same state and exit.
fn agree(words: &[u32], target: TargetCpu, memory: &mut [u64; 2]) -> usize {
    let (system, frame) = blocks(words, target);
    let mut runs = 0;
    for (index, &left) in VALUES.iter().enumerate() {
        for &right in &VALUES {
            let mut expected = GuestState {
                nzcv: ((index as u32 * 7 + runs as u32) % 16) << 28,
                lower_limit: Limit(u64::MAX),
                ..GuestState::default()
            };
            for (register, x) in expected.x.iter_mut().enumerate() {
                *x = 0x1111 * register as u64;
            }
            expected.x[0] = left;
            expected.x[1] = right;
            expected.x[12] = memory.as_mut_ptr() as u64;
            expected.x[14] = u64::from(expected.nzcv ^ 0xa000_0000);
            let mut actual = expected.clone();
            let frame_exit = native::run(&frame, &mut expected);
            let system_exit = native::run(&system, &mut actual);
            assert_eq!(
                (system_exit, &actual),
                (frame_exit, &expected),
                "{words:08x?} {left:#x} {right:#x}"
            );
            runs += 1;
        }
    }
    runs
}

fn targets() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [TargetCpu::Baseline, TargetCpu::X86_64_V3, host]
        .into_iter()
        .filter(|target| host.supports(*target))
        .collect()
}

/// Every condition after every setter: by a side exit, a select, a second
/// select after HI or LS turned the carry over, a CSET and the word the
/// block's end stores, against the frame emitter.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn every_condition_after_every_setter_matches_the_frame_emitter() {
    let mut memory = [0x1234_5678_9abc_def0, 0];
    let mut runs = 0;
    for target in targets() {
        for setter in SETTERS {
            for condition in 0..14 {
                let other = (condition + 5) % 14;
                let shapes: [Vec<u32>; 4] = [
                    vec![setter, b_cond(condition, 0x40), ADD_X3],
                    vec![
                        setter,
                        with_condition(CSEL_X5, condition),
                        with_condition(CSINC_W6, other),
                        with_condition(CSINV_X7, condition ^ 1),
                        b_cond(other, 0x40),
                        with_condition(CSET_X8, condition),
                    ],
                    vec![
                        setter,
                        b_cond(condition, 0x40),
                        with_condition(CSETM_X9, other),
                        b_cond(other, 0x40),
                        with_condition(CSNEG_X10, condition),
                    ],
                    vec![
                        setter,
                        b_cond(condition, 0x40),
                        ADDS_X4,
                        b_cond(other, 0x40),
                    ],
                ];
                for words in shapes {
                    runs += agree(&words, target, &mut memory);
                }
            }
        }
    }
    assert!(runs > 30_000, "{runs}");
}

/// The word between a setter and its reader where something else comes
/// first: an ADD, a load, MRS and MSR of NZCV (frame-bound), and a reader
/// that a dead setter follows.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn the_word_is_stored_before_what_may_need_it() {
    let mut memory = [0x8000_0000_0000_0000, 0];
    let mut runs = 0;
    for target in targets() {
        for setter in [CMP_X0_X1, ADDS_W2, ANDS_X2, CMP_X0_W1_UXTW] {
            for condition in [0, 2, 4, 6, 8, 9, 10, 13] {
                let shapes: [Vec<u32>; 5] = [
                    vec![setter, ADD_X3, b_cond(condition, 0x40)],
                    vec![setter, LDR_X11_X12, b_cond(condition, 0x40), ADD_X3],
                    vec![setter, MRS_X13_NZCV, b_cond(condition, 0x40)],
                    vec![setter, b_cond(condition, 0x40), MSR_NZCV_X14, ADD_X3],
                    vec![
                        setter,
                        with_condition(CSEL_X5, condition),
                        setter ^ 0x0001_0000,
                        b_cond(condition ^ 1, 0x40),
                    ],
                ];
                for words in shapes {
                    runs += agree(&words, target, &mut memory);
                }
            }
        }
    }
    assert!(runs > 3_000, "{runs}");
}

/// A load that faults after a setter, before its reader: the word at the
/// fault is the setter's NZCV, whether a reader or another setter follows,
/// so the engine's settlement finds it.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn a_fault_after_a_setter_finds_its_nzcv() {
    use super::vector_cache_tests::faulting;
    let guard = faulting::guard_page();
    let mut faults = 0;
    for target in targets() {
        let setters: [(u32, Model); 2] = [(CMP_X0_X1, nzcv_of_subtract), (CMN_X0_X1, nzcv_of_add)];
        for (setter, flags) in setters {
            for after in [b_cond(0, 0x40), ADDS_X4, with_condition(CSEL_X5, 8)] {
                let words = [setter, LDR_X11_X12, after, ADD_X3];
                let instructions = lift(&words);
                let end = GuestAddress(0x1000 + 4 * words.len() as u64);
                let (system, _) = emit_system_mode(
                    &instructions,
                    None,
                    end,
                    target,
                    MemoryChecks::DEFAULT,
                    NativeSystem::NONE,
                );
                let code = pinned::entered(&system.x86_64_code);
                for &left in &VALUES {
                    for &right in &VALUES {
                        let mut state = GuestState {
                            nzcv: 0x5000_0000,
                            lower_limit: Limit(u64::MAX),
                            ..GuestState::default()
                        };
                        state.x[0] = left;
                        state.x[1] = right;
                        state.x[12] = guard;
                        assert!(
                            faulting::run(&code, &mut state).is_err(),
                            "{words:08x?} does not fault"
                        );
                        assert_eq!(
                            flag_word::arm(state.nzcv),
                            flags(left, right),
                            "{words:08x?} {left:#x} {right:#x}"
                        );
                        faults += 1;
                    }
                }
            }
        }
    }
    assert!(faults >= 600, "{faults}");
}

/// The Arm NZCV of a setter from its operands.
type Model = fn(u64, u64) -> u32;

/// Arm NZCV of the 64-bit subtraction `left - right`.
fn nzcv_of_subtract(left: u64, right: u64) -> u32 {
    let (result, borrow) = left.overflowing_sub(right);
    let overflow = (left as i64).overflowing_sub(right as i64).1;
    nzcv(result, !borrow, overflow)
}

/// Arm NZCV of the 64-bit addition `left + right`.
fn nzcv_of_add(left: u64, right: u64) -> u32 {
    let (result, carry) = left.overflowing_add(right);
    let overflow = (left as i64).overflowing_add(right as i64).1;
    nzcv(result, carry, overflow)
}

fn nzcv(result: u64, carry: bool, overflow: bool) -> u32 {
    u32::from(result >> 63 != 0) << 31
        | u32::from(result == 0) << 30
        | u32::from(carry) << 29
        | u32::from(overflow) << 28
}

/// A xorshift generator: the randomized cases are the same on every run.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: u32) -> u32 {
        (self.next() % u64::from(bound)) as u32
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u32) as usize]
    }
}

/// Source registers of the randomized cases (31 is XZR or SP), and their
/// destinations, which leave X11 to X14 to the fixed instructions.
const SOURCES: [u32; 5] = [0, 1, 2, 3, 31];
const DESTINATIONS: [u32; 8] = [0, 1, 2, 3, 5, 6, 7, 31];

/// A flag setter of every form [`super::sets_flags_alone`] takes, its
/// fields random: ADDS/SUBS by immediate (shifted or not), by shifted and
/// by extended register, ANDS by immediate, ANDS/BICS by shifted register,
/// in both widths. Some field values are reserved; lifting rejects them.
fn random_setter(random: &mut Random) -> u32 {
    let sf = random.below(2) << 31;
    let wide = sf != 0;
    let op = random.below(2) << 30;
    let (rd, rn, rm) = (
        random.pick(&DESTINATIONS),
        random.pick(&SOURCES),
        random.pick(&SOURCES),
    );
    let amount = random.pick(&[
        0,
        1,
        3,
        31,
        if wide { 32 } else { 7 },
        if wide { 63 } else { 30 },
    ]);
    match random.below(5) {
        0 => {
            let shift = random.below(2) << 22;
            let any = random.below(0x1000);
            let immediate = random.pick(&[0, 1, 2, 0x7ff, 0x800, 0xfff, any]);
            sf | op | 0x3100_0000 | shift | immediate << 10 | rn << 5 | rd
        }
        1 => sf | op | 0x2b00_0000 | random.below(3) << 22 | rm << 16 | amount << 10 | rn << 5 | rd,
        2 => {
            let option = random.below(8);
            sf | op | 0x2b20_0000 | rm << 16 | option << 13 | random.below(5) << 10 | rn << 5 | rd
        }
        3 => {
            let n = if wide { random.below(2) } else { 0 };
            let (immr, imms) = (random.below(64), random.below(64));
            sf | 0x7200_0000 | n << 22 | immr << 16 | imms << 10 | rn << 5 | rd
        }
        _ => {
            let invert = random.below(2) << 21;
            sf | 0x6a00_0000
                | random.below(4) << 22
                | invert
                | rm << 16
                | amount << 10
                | rn << 5
                | rd
        }
    }
}

/// A reader that may take NZCV from the host flags: B.cond to a side
/// exit (AL and NV, unconditional, end a block), or a select of any form
/// and condition.
fn random_reader(random: &mut Random) -> u32 {
    let condition = random.below(16);
    if random.below(3) == 0 {
        return b_cond(condition % 14, 0x40);
    }
    let sf = random.below(2) << 31;
    let (op, o2) = (random.below(2) << 30, random.below(2) << 10);
    let (rd, rn, rm) = (
        random.pick(&DESTINATIONS),
        random.pick(&SOURCES),
        random.pick(&SOURCES),
    );
    sf | op | 0x1a80_0000 | rm << 16 | condition << 12 | o2 | rn << 5 | rd
}

/// Something else between them: an ADD, a load, MRS and MSR of NZCV
/// (frame-bound), ADCS/SBCS (which read C) and CCMP/CCMN (which read the
/// condition and set NZCV).
fn random_other(random: &mut Random) -> u32 {
    let sf = random.below(2) << 31;
    let (rd, rn, rm) = (
        random.pick(&DESTINATIONS),
        random.pick(&SOURCES),
        random.pick(&SOURCES),
    );
    match random.below(6) {
        0 => ADD_X3,
        1 => LDR_X11_X12,
        2 => MRS_X13_NZCV,
        3 => MSR_NZCV_X14,
        4 => sf | random.below(2) << 30 | 0x3a00_0000 | rm << 16 | rn << 5 | rd,
        _ => {
            let immediate = random.below(2) << 11;
            let condition = random.below(16);
            sf | random.below(2) << 30
                | 0x3a40_0000
                | rm << 16
                | condition << 12
                | immediate
                | rn << 5
                | random.below(16)
        }
    }
}

/// Random sequences of setters, readers and other instructions, from
/// random operands, against the frame emitter: every setter form with
/// every reader, chains of readers, setters a reader or another setter
/// follows, and the frame-bound and carry-reading instructions between.
#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn random_flag_sequences_match_the_frame_emitter() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut memory = [0x8000_0000_0000_0001_u64, 0];
    let (mut sequences, mut runs) = (0, 0);
    for target in targets() {
        let mut built = 0;
        while built < 1500 {
            let length = 2 + random.below(7) as usize;
            let mut words = vec![random_setter(&mut random)];
            while words.len() < length {
                words.push(match random.below(20) {
                    0..7 => random_setter(&mut random),
                    7..14 => random_reader(&mut random),
                    _ => random_other(&mut random),
                });
            }
            let lifted: Option<Vec<_>> = words
                .iter()
                .enumerate()
                .map(|(index, &word)| {
                    Decoder
                        .lift(GuestAddress(0x1000 + 4 * index as u64), word)
                        .ok()
                })
                .collect();
            if lifted.is_none() {
                continue;
            }
            built += 1;
            let (system, frame) = blocks(&words, target);
            for _ in 0..12 {
                let mut expected = GuestState {
                    nzcv: random.below(16) << 28,
                    lower_limit: Limit(u64::MAX),
                    sp: random.pick(&VALUES),
                    ..GuestState::default()
                };
                for (register, x) in expected.x.iter_mut().enumerate() {
                    *x = 0x1111 * register as u64;
                }
                for x in &mut expected.x[..4] {
                    *x = random.pick(&VALUES);
                }
                expected.x[12] = memory.as_mut_ptr() as u64;
                expected.x[14] = u64::from(random.below(16)) << 28 | random.next() & 0x0fff_ffff;
                let mut actual = expected.clone();
                let frame_exit = native::run(&frame, &mut expected);
                let system_exit = native::run(&system, &mut actual);
                assert_eq!(
                    (system_exit, &actual),
                    (frame_exit, &expected),
                    "{words:08x?} {target:?}"
                );
                runs += 1;
            }
        }
        sequences += built;
    }
    assert!(sequences >= 1500 && runs >= 18_000, "{sequences} {runs}");
}

/// Run `words` at 0x1000 from `state` as the engine runs system-mode
/// blocks, with or without self-loops, until it leaves past its end:
/// each exit's next PC starts the block there. The number of entries.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn run_program(
    words: &[u32],
    self_loops: bool,
    target: TargetCpu,
    state: &mut GuestState,
) -> usize {
    use crate::{Anchor, x86_64::chain::ChainControl};
    const BASE: u64 = 0x1000;
    let source: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let end = BASE + source.len() as u64;
    let options = super::host_cost::options(target).with_native_system(NativeSystem {
        exclusive: true,
        self_loops,
        ..NativeSystem::NONE
    });
    let mut blocks = alloc::collections::BTreeMap::new();
    let mut control = ChainControl::default();
    state.anchors[Anchor::Control] = (&raw mut control) as u64;
    let (mut pc, mut entries) = (BASE, 0);
    while pc != end {
        assert!(entries < 1 << 20, "{words:08x?} does not end");
        let code = blocks.entry(pc).or_insert_with(|| {
            let compiled = crate::block::CompilationPlan::new(
                &source[(pc - BASE) as usize..],
                GuestAddress(pc),
                &options,
            )
            .and_then(|plan| plan.compile())
            .unwrap();
            if pc == BASE {
                assert_eq!(compiled.self_loop, self_loops, "{words:08x?}");
            }
            pinned::entered(&compiled.native.x86_64_code)
        });
        pc = native::run(code, state);
        entries += 1;
    }
    entries
}

/// Self-loops whose bodies keep a compare's NZCV in the host flags across
/// a branch to a join inside the body, selects and the back edge's
/// SUBS/B.NE: run as one loop, as linked blocks and by a model, over
/// bytes and doublewords at the signed and unsigned edges, they agree.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
#[test]
fn self_loops_keep_flags_across_joins_and_back_edges() {
    const LDRB_W8: u32 = 0x3840_1408;
    const LDR_X8: u32 = 0xf840_8408;
    const CMP_W8_W9: u32 = 0x6b09_011f;
    const CMP_X8_X9: u32 = 0xeb09_011f;
    const ADD_X10_1: u32 = 0x9100_054a;
    const ADD_X11_1: u32 = 0x9100_056b;
    /// CSEL X11, X8, X11, HI.
    const CSEL_X11_HI: u32 = 0x9a8b_810b;
    /// CINC X10, X10, LT (CSINC X10, X10, X10, GE).
    const CINC_X10_LT: u32 = 0x9a8a_a54a;
    /// TST X8, #1.
    const TST_X8_1: u32 = 0xf240_011f;
    /// CINC X11, X11, NE (CSINC X11, X11, X11, EQ).
    const CINC_X11_NE: u32 = 0x9a8b_056b;
    const ADDS_X10_X8: u32 = 0xab08_014a;
    /// CINC X10, X10, LS (CSINC X10, X10, X10, HI).
    const CINC_X10_LS: u32 = 0x9a8a_854a;
    /// CSEL X11, X8, X11, NE.
    const CSEL_X11_NE: u32 = 0x9a8b_110b;
    const SUBS_X2_1: u32 = 0xf100_0442;
    let back = |words: &[u32]| b_cond(1, -4 * words.len() as i32);
    let finish = |mut words: Vec<u32>| {
        words.push(SUBS_X2_1);
        words.push(back(&words));
        words
    };
    // Each body, its element size and its model of X10 and X11 over the
    // elements and X9.
    type Model = fn(&[u64], u64) -> (u64, u64);
    let bodies: [(Vec<u32>, usize, Model); 5] = [
        (
            finish(vec![LDRB_W8, CMP_W8_W9, b_cond(1, 8), ADD_X10_1]),
            1,
            |elements, x9| {
                let equal = elements.iter().filter(|&&e| e == x9 & 0xffff_ffff).count();
                (0x1111 * 10 + equal as u64, 0x1111 * 11)
            },
        ),
        (
            finish(vec![LDRB_W8, CMP_W8_W9, CSEL_X11_HI, CINC_X10_LT]),
            1,
            |elements, x9| {
                let w9 = x9 as u32;
                let mut x11 = 0x1111 * 11;
                let mut below = 0;
                for &e in elements {
                    let e = e as u32;
                    if e > w9 {
                        x11 = u64::from(e);
                    }
                    if (e as i32) < (w9 as i32) {
                        below += 1;
                    }
                }
                (0x1111 * 10 + below, x11)
            },
        ),
        (
            finish(vec![
                LDR_X8,
                CMP_X8_X9,
                b_cond(10, 8),
                ADD_X10_1,
                TST_X8_1,
                CINC_X11_NE,
            ]),
            8,
            |elements, x9| {
                let less = elements.iter().filter(|&&e| (e as i64) < x9 as i64).count();
                let odd = elements.iter().filter(|&&e| e & 1 != 0).count();
                (0x1111 * 10 + less as u64, 0x1111 * 11 + odd as u64)
            },
        ),
        (
            finish(vec![LDR_X8, ADDS_X10_X8, b_cond(2, 8), ADD_X11_1]),
            8,
            |elements, _| {
                let (mut sum, mut carries) = (0x1111 * 10_u64, 0);
                for &e in elements {
                    let (next, carry) = sum.overflowing_add(e);
                    sum = next;
                    carries += u64::from(carry);
                }
                (sum, 0x1111 * 11 + elements.len() as u64 - carries)
            },
        ),
        (
            // The branch lands on a select, which the fallthrough reaches
            // after another select kept the flags in the host's.
            finish(vec![
                LDRB_W8,
                CMP_W8_W9,
                b_cond(8, 8),
                CINC_X10_LS,
                CSEL_X11_NE,
            ]),
            1,
            |elements, x9| {
                let w9 = x9 & 0xffff_ffff;
                let mut x11 = 0x1111 * 11;
                for &e in elements {
                    if e != w9 {
                        x11 = e;
                    }
                }
                let at_most = elements.iter().filter(|&&e| e <= w9).count();
                (0x1111 * 10 + at_most as u64, x11)
            },
        ),
    ];
    let mut random = Random(0x2545_f491_4f6c_dd1d);
    let mut checked = 0;
    for target in targets() {
        for (words, size, model) in &bodies {
            for (count, x9) in [
                (1, 0),
                (7, 0x7f),
                (64, 0x80),
                (300, 0xff),
                (1000, 0x8000_0000_0000_0000),
            ] {
                let elements: Vec<u64> = (0..count)
                    .map(|_| {
                        let value = if random.below(2) == 0 {
                            random.pick(&VALUES)
                        } else {
                            random.next()
                        };
                        if *size == 1 { value & 0xff } else { value }
                    })
                    .collect();
                let bytes: Vec<u8> = elements
                    .iter()
                    .flat_map(|e| e.to_le_bytes()[..*size].to_vec())
                    .collect();
                let mut initial = GuestState {
                    lower_limit: Limit(u64::MAX),
                    ..GuestState::default()
                };
                for (register, x) in initial.x.iter_mut().enumerate() {
                    *x = 0x1111 * register as u64;
                }
                initial.x[0] = bytes.as_ptr() as u64;
                initial.x[2] = count as u64;
                initial.x[9] = x9;
                let mut looped = initial.clone();
                let mut linked = initial.clone();
                let entries = run_program(words, true, target, &mut looped);
                run_program(words, false, target, &mut linked);
                // Joins keep the branches inside the loop.
                assert!(
                    count < 64 || entries < count / 8,
                    "{words:08x?}: {entries} entries"
                );
                let (x10, x11) = model(&elements, x9);
                let label = alloc::format!("{words:08x?} {count} {x9:#x} {target:?}");
                assert_eq!((looped.x[10], looped.x[11]), (x10, x11), "{label}");
                assert_eq!(looped.x[0], initial.x[0] + bytes.len() as u64, "{label}");
                assert_eq!(looped.x[2], 0, "{label}");
                // The last SUBS X2 left Z and C set.
                assert_eq!(looped.nzcv, 0x6000_0000, "{label}");
                looped.anchors = linked.anchors;
                assert_eq!(looped, linked, "{label}");
                checked += 1;
            }
        }
    }
    assert!(checked >= 20, "{checked}");
}
