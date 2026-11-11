//! System-mode blocks that keep guest vectors in host registers
//! ([`crate::x86_64::vector_cache`]) run as the frame layout does, and
//! every fault site, exit and helper finds the exact V state.
use super::*;
use crate::{
    GuestState, Lifter, Limit, TargetCpu,
    aarch64::Decoder,
    block::RecoverySiteKind,
    x86_64::{
        MemoryChecks, NativeSystem,
        asm::{Gpr, Mem, Size},
        native, pinned,
    },
};

/// Guest memory at X1.
const WORDS: usize = 64;
type Memory = [u64; WORDS];

/// A small deterministic generator (xorshift64*).
struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u32) -> u32 {
        (self.next() >> 33) as u32 % bound
    }
    fn vector(&mut self) -> u32 {
        // Few registers, so that results are read back and homes spill.
        self.below(12)
    }
}

/// One instruction word: mostly cached AdvSIMD operations, with accesses,
/// integer arithmetic, a side exit, uncached AdvSIMD and FP (the latter
/// taking a helper exit for some inputs).
fn word(random: &mut Random) -> u32 {
    let (d, n, m) = (random.vector(), random.vector(), random.vector());
    let three = |base: u32| base | m << 16 | n << 5 | d;
    // By element: Vm in 0..15, element h[index] from H:L:M.
    let index = random.below(8);
    let element = |base: u32| {
        base | (index & 1) << 20
            | (index >> 1 & 1) << 21
            | (index >> 2) << 11
            | (m & 15) << 16
            | n << 5
            | d
    };
    match random.below(64) {
        0 => three(0x4ea0_8400),        // add vd.4s,vn.4s,vm.4s
        1 => three(0x6ea0_8400),        // sub vd.4s
        2 => three(0x0e20_8400),        // add vd.8b (D write)
        3 => three(0x4e20_1c00),        // and vd.16b
        4 => three(0x4ea0_1c00),        // orr vd.16b (mov when n == m)
        5 => three(0x6e20_1c00),        // eor vd.16b
        6 => three(0x4e60_1c00),        // bic vd.16b
        7 => three(0x4ee0_1c00),        // orn vd.16b
        8 => three(0x6e60_1c00),        // bsl vd.16b
        9 => three(0x6ea0_1c00),        // bit vd.16b
        10 => three(0x6ee0_1c00),       // bif vd.16b
        11 => three(0x6e20_8c00),       // cmeq vd.16b
        12 => three(0x4ea0_3400),       // cmgt vd.4s
        13 => three(0x6e60_3400),       // cmhi vd.8h
        14 => three(0x4ee0_3c00),       // cmge vd.2d
        15 => 0x4ea0_b800 | n << 5 | d, // abs vd.4s
        16 => 0x6ea0_b800 | n << 5 | d, // neg vd.4s
        17 => 0x4f00_e400 | (random.below(8)) << 16 | (random.below(32)) << 5 | d, // movi .16b
        18 | 19 => 0x3dc0_0000 | random.below(28) << 10 | 1 << 5 | d, // ldr qd,[x1,#16k]
        20 => 0x3d80_0000 | random.below(28) << 10 | 1 << 5 | d, // str qd,[x1,#16k]
        21 => {
            // ldp qd,qm,[x1,#16k] (distinct registers)
            let m = if m == d { (d + 1) % 12 } else { m };
            0xad40_0000 | random.below(28) << 15 | m << 10 | 1 << 5 | d
        }
        22 => 0xad00_0000 | random.below(28) << 15 | m << 10 | 1 << 5 | d, // stp q
        23 => 0xfd40_0000 | random.below(56) << 10 | 1 << 5 | d,           // ldr dd,[x1,#8k]
        24 => 0x9100_0400,                                                 // add x0,x0,#1
        25 => 0xf940_0022 | random.below(56) << 10,                        // ldr x2,[x1,#8k]
        26 => three(0x2e60_c000),                                          // umull vd.4s
        27 => 0xb400_0805,                                                 // cbz x5,.+0x100
        28 => three(0x4e20_d400),                                          // fadd vd.4s (uncached)
        29 => 0x4e08_3c00 | n << 5 | 3,                                    // mov x3,vn.d[0]
        30 => three(0x2e60_8000),                 // umlal vd.4s,vn.4h,vm.4h
        31 => three(0x6e60_8000),                 // umlal2
        32 => element(0x0f40_2000),               // smlal vd.4s,vn.4h,vm.h[i]
        33 => element(0x4f40_2000),               // smlal2 by element
        34 => three(0x6e60_c000),                 // umull2
        35 => three(0x0e60_c000),                 // smull
        36 => 0x0f10_8c00 | n << 5 | d,           // rshrn vd.4h,vn.4s,#16
        37 => 0x4f10_8c00 | n << 5 | d,           // rshrn2
        38 => 0x2f10_8c00 | n << 5 | d,           // sqrshrun vd.4h,vn.4s,#16
        39 => 0x6f10_8c00 | n << 5 | d,           // sqrshrun2
        40 => 0x2f08_8c00 | n << 5 | d,           // sqrshrun vd.8b,vn.8h,#8
        41 => three(0x2e60_0400),                 // uhadd vd.8h
        42 => 0x4f3d_2400 | n << 5 | d,           // srshr vd.4s,#3
        43 => three(0x4ea0_0c00),                 // sqadd vd.4s
        44 => three(0x6ea0_4400),                 // ushl vd.4s (uncached)
        45 => three(0x6e20_1400),                 // urhadd vd.16b
        46 => 0x4f3d_0400 | n << 5 | d,           // sshr vd.4s,#3
        47 => 0x2f10_a400 | n << 5 | d,           // uxtl vd.4s,vn.4h
        48 => 0x2e61_2800 | n << 5 | d,           // sqxtun vd.4h,vn.4s
        49 => three(0x2e20_8400),                 // sub vd.8b (D write)
        50 => three(0x2e20_1c00),                 // eor vd.8b
        51 => 0x0ea0_1c00 | n << 16 | n << 5 | d, // mov vd.8b
        52 => 0x4ea0_1c00 | n << 16 | n << 5 | d, // mov vd.16b
        53 => three(0x6e60_8400),                 // sub vd.8h
        54 => element(0x0f40_a000),               // smull vd.4s,vn.4h,vm.h[i]
        55 => element(0x0f40_6000),               // smlsl by element
        56 => element(0x2f40_2000),               // umlal by element
        57 => element(0x6f40_a000),               // umull2 by element
        58 => three(0x0e60_8000),                 // smlal vd.4s,vn.4h,vm.4h
        59 => three(0x4e60_c000),                 // smull2 (signed upper by vector)
        60 => three(0x0e60_a000),                 // smlsl
        61 => three(0x6e60_a000),                 // umlsl2
        62 => element(0x4f40_6000),               // smlsl2 by element
        _ => three(0x4e20_d400),                  // fadd vd.4s (uncached)
    }
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

fn initial(random: &mut Random, memory: &mut Memory) -> GuestState {
    let mut state = GuestState::default();
    for vector in state.v.iter_mut() {
        *vector = [random.next(), random.next()];
    }
    for word in memory.iter_mut() {
        *word = random.next();
    }
    state.x[1] = memory.as_mut_ptr() as u64;
    state.x[5] = random.next() & 1;
    state.lower_limit = Limit(u64::MAX);
    state
}

fn system(
    instructions: &[Instruction],
    end: GuestAddress,
    target: TargetCpu,
) -> (Vec<u8>, NativeBlock) {
    let (block, _) = emit_system_mode(
        instructions,
        None,
        end,
        target,
        MemoryChecks::DEFAULT,
        NativeSystem::NONE,
    );
    (pinned::entered(&block.x86_64_code), block)
}

/// Whether `code` names XMM8-15 as a ModRM.reg operand: a legacy SSE form
/// with REX.R, or a VEX form with (inverted) R clear.
fn names_a_home(code: &[u8]) -> bool {
    code.windows(2).any(|w| {
        (w[0] == 0x66 && matches!(w[1], 0x44 | 0x45))
            || (matches!(w[0], 0xc4 | 0xc5) && w[1] & 0x80 == 0)
    })
}

/// The host tiers whose recipes the cache changes, each the running host
/// supports: SSE2, SSE4.1, AVX2 (VEX three-operand forms), AVX-512 and the
/// host itself.
fn tiers() -> Vec<TargetCpu> {
    let host = TargetCpu::detect();
    [
        TargetCpu::Baseline,
        TargetCpu::Sse41,
        TargetCpu::X86_64_V3,
        TargetCpu::X86_64_V4,
        host,
    ]
    .into_iter()
    .filter(|tier| host.supports(*tier))
    .collect()
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn blocks_with_cached_vectors_run_as_the_frame_layout() {
    for target in tiers() {
        run_random_blocks(target, 600);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
fn run_random_blocks(target: TargetCpu, cases: usize) {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut cached = 0;
    for case in 0..cases {
        let length = 4 + random.below(40) as usize;
        let words: Vec<u32> = (0..length).map(|_| word(&mut random)).collect();
        let instructions = lift(&words);
        let end = GuestAddress(0x1000 + 4 * length as u64);
        let frame = emit(&instructions, None, end);
        let (entered, block) = system(&instructions, end, target);
        if names_a_home(&block.x86_64_code) {
            cached += 1;
        }
        let mut memory = [0; WORDS];
        let mut state = initial(&mut random, &mut memory);
        let mut expected_memory = memory;
        let mut expected = state.clone();
        expected.x[1] = expected_memory.as_mut_ptr() as u64;
        let expected_exit = native::run(&frame.x86_64_code, &mut expected);
        let exit = native::run(&entered, &mut state);
        state.x[1] = 0;
        expected.x[1] = 0;
        assert_eq!(exit, expected_exit, "{target:?} case {case}: {words:08x?}");
        assert_eq!(state, expected, "{target:?} case {case}: {words:08x?}");
        assert_eq!(
            memory, expected_memory,
            "{target:?} case {case}: {words:08x?}"
        );
    }
    assert!(cached > cases * 4 / 5, "{target:?}: {cached}");
}

/// No fault site of a block finds a vector only in a host register: the
/// encoder refuses one ([`crate::x86_64::asm::Code::guest_access`]), so
/// emitting blocks whose accesses follow cached writes proves that the
/// state block a fault's settlement reads is current at every site.
#[test]
fn every_fault_site_finds_the_cached_writes_stored() {
    let mut random = Random(0x0123_4567_89ab_cdef);
    // Three cached writes, then a load whose fault the engine settles.
    let fixed = [
        0x4ea2_8420_u32, // add v0.4s,v1.4s,v2.4s
        0x6e24_1c63,     // eor v3.16b,v3.16b,v4.16b
        0x4ea0_8405,     // add v5.4s,v0.4s,v0.4s
        0x3dc0_0426,     // ldr q6,[x1,#16]
        0x4ea6_84c7,     // add v7.4s,v6.4s,v6.4s
        0xf940_0422,     // ldr x2,[x1,#8]
    ];
    let mut sites = 0;
    for case in 0..300 {
        let words: Vec<u32> = if case == 0 {
            fixed.to_vec()
        } else {
            let length = 4 + random.below(30) as usize;
            (0..length).map(|_| word(&mut random)).collect()
        };
        let instructions = lift(&words);
        let end = GuestAddress(0x1000 + 4 * words.len() as u64);
        let (block, recovery) = emit_system_mode(
            &instructions,
            None,
            end,
            TargetCpu::detect(),
            MemoryChecks::DEFAULT,
            NativeSystem::NONE,
        );
        let accesses: Vec<_> = recovery
            .iter()
            .filter(|row| row.site.kind() == RecoverySiteKind::GuestAccess)
            .collect();
        if case == 0 {
            // The load of Q6 retires after three instructions, whose three
            // cached results are stored before it.
            let load = accesses[0];
            assert_eq!(load.retirement.position().unwrap().retired_instructions, 3);
            // The last is written straight to its slot from the recipe's
            // register, since the access follows it.
            let code = &block.x86_64_code[block.source_map[2].1..load.start];
            let stores = (0..code.len().saturating_sub(4))
                .filter(|&at| {
                    code[at..at + 4] == [0xf3, 0x44, 0x0f, 0x7f]
                        || code[at..at + 3] == [0xf3, 0x0f, 0x7f] && code[at + 3] & 0xc7 == 0x87
                })
                .count();
            assert_eq!(stores, 3);
        }
        sites += accesses.len();
    }
    assert!(sites > 700, "{sites}");
}

#[test]
#[should_panic(expected = "a guest access with V registers only in XMM")]
fn a_guest_access_after_an_unstored_write_is_refused() {
    let mut code = Code::pinned();
    code.set_vector_cache(true);
    code.allocate_vector(2);
    code.mark_vector_dirty(2);
    code.guest_access(|code| {
        code.asm()
            .mov_load(Size::Qword, Gpr::Rax, Mem::base(Gpr::Rax, 0))
    });
}

/// The cache stores the dirty homes before an access, a side exit, an
/// uncached instruction and the terminal, and only there; a result the
/// next of those follows goes straight to its slot.
#[test]
fn dirty_vectors_are_stored_where_the_state_must_be_current() {
    // add v0.4s,v1.4s,v2.4s; add v0.4s,v0.4s,v2.4s; ldr x2,[x1];
    // add v3.4s,v0.4s,v0.4s; ushl v4.4s,v3.4s,v0.4s; add v5.4s,v4.4s,v4.4s
    let words = [
        0x4ea2_8420,
        0x4ea2_8400,
        0xf940_0022,
        0x4ea0_8403,
        0x6ea0_4464,
        0x4ea4_8485,
    ];
    let instructions = lift(&words);
    let end = GuestAddress(0x1018);
    let (block, _) = emit_system_mode(
        &instructions,
        None,
        end,
        TargetCpu::Baseline,
        MemoryChecks::DEFAULT,
        NativeSystem::NONE,
    );
    let code = &block.x86_64_code;
    let rows: Vec<usize> = block.source_map.iter().map(|&(_, at)| at).collect();
    // movdqu [rdi+0x108+16v],xmm8..15: a home stored to V`v`'s slot.
    let stores_of = |range: core::ops::Range<usize>| -> Vec<u8> {
        let bytes = &code[range];
        // From a home (REX.R) or straight from a recipe's register.
        (0..bytes.len().saturating_sub(7))
            .filter_map(|at| {
                let rex = usize::from(bytes[at + 1] == 0x44);
                (at + 8 + rex <= bytes.len()
                    && bytes[at] == 0xf3
                    && bytes[at + 1 + rex..at + 3 + rex] == [0x0f, 0x7f]
                    && bytes[at + 3 + rex] & 0xc7 == 0x87)
                    .then_some(at + 4 + rex)
            })
            .map(|at| {
                let offset = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                ((offset - 0x108) / 16) as u8
            })
            .collect()
    };
    // Stores come before the row of the instruction that needs them.
    assert!(stores_of(rows[0]..rows[1]).is_empty());
    // The second ADD reads V0 from its home: no load of its slot.
    let load = [0xf3, 0x0f, 0x6f, 0x87, 0x08, 0x01, 0, 0];
    assert!(!code[rows[1]..rows[2]].windows(8).any(|w| w == load));
    // V0, dirty, is stored once, before the access.
    assert_eq!(stores_of(rows[1]..rows[2]), [0]);
    assert!(stores_of(rows[2]..rows[3]).is_empty());
    // Before the uncached USHL: V3.
    assert_eq!(stores_of(rows[3]..rows[4]), [3]);
    assert_eq!(stores_of(rows[5]..code.len()), [5]);
}
