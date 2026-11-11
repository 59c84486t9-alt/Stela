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
    match random.below(30) {
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
        26 => three(0x2e60_c000),                                          // umull vd.4s (uncached)
        27 => 0xb400_0805,                                                 // cbz x5,.+0x100
        28 => three(0x4e20_d400),                                          // fadd vd.4s (uncached)
        _ => 0x4e08_3c00 | n << 5 | 3,                                     // mov x3,vn.d[0]
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

fn system(instructions: &[Instruction], end: GuestAddress) -> (Vec<u8>, NativeBlock) {
    let (block, _) = emit_system_mode(
        instructions,
        None,
        end,
        TargetCpu::detect(),
        MemoryChecks::DEFAULT,
        NativeSystem::NONE,
    );
    (pinned::entered(&block.x86_64_code), block)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "macos", target_os = "linux")))]
#[test]
fn blocks_with_cached_vectors_run_as_the_frame_layout() {
    let mut random = Random(0x9e37_79b9_7f4a_7c15);
    let mut cached = 0;
    for case in 0..400 {
        let length = 4 + random.below(40) as usize;
        let words: Vec<u32> = (0..length).map(|_| word(&mut random)).collect();
        let instructions = lift(&words);
        let end = GuestAddress(0x1000 + 4 * length as u64);
        let frame = emit(&instructions, None, end);
        let (entered, block) = system(&instructions, end);
        // movdqa xmm8..15 from a recipe's scratch register: the cache ran.
        if block
            .x86_64_code
            .windows(3)
            .any(|w| w == [0x66, 0x44, 0x0f])
        {
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
        assert_eq!(exit, expected_exit, "case {case}: {words:08x?}");
        assert_eq!(state, expected, "case {case}: {words:08x?}");
        assert_eq!(memory, expected_memory, "case {case}: {words:08x?}");
    }
    assert!(cached > 300, "{cached}");
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
            let code = &block.x86_64_code[block.source_map[2].1..load.start];
            let stores = code
                .windows(4)
                .filter(|w| *w == [0xf3, 0x44, 0x0f, 0x7f])
                .count();
            assert_eq!(stores, 3);
        }
        sites += accesses.len();
    }
    assert!(sites > 1000, "{sites}");
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
/// uncached instruction and the terminal, and only there.
#[test]
fn dirty_vectors_are_stored_where_the_state_must_be_current() {
    // add v0.4s,v1.4s,v2.4s; add v0.4s,v0.4s,v2.4s; ldr x2,[x1];
    // add v3.4s,v0.4s,v0.4s; umull v4.4s,v3.4h,v0.4h; add v5.4s,v4.4s,v4.4s
    let words = [
        0x4ea2_8420,
        0x4ea2_8400,
        0xf940_0022,
        0x4ea0_8403,
        0x2e60_c064,
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
        (0..bytes.len().saturating_sub(4))
            .filter(|&at| {
                bytes[at..at + 4] == [0xf3, 0x44, 0x0f, 0x7f] && bytes[at + 4] & 0xc7 == 0x87
            })
            .map(|at| {
                let offset = u32::from_le_bytes(bytes[at + 5..at + 9].try_into().unwrap());
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
    // Before the uncached UMULL: V3.
    assert_eq!(stores_of(rows[3]..rows[4]), [3]);
    assert_eq!(stores_of(rows[5]..code.len()), [5]);
}
