//! The workloads: where each function comes from, its inputs and expected
//! result, and the arena its code and data live in.
use super::{PAGE, RET};
use anyhow::{Context, Result, bail, ensure};
use object::read::macho::{FatArch, MachOFatFile32};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind, macho};
use stela_compiler::GuestState;

#[derive(Clone, Copy, Debug)]
pub(super) enum Source {
    M1n1String,
    Dyld,
    /// A microbenchmark's words, not a program's.
    Words(&'static [u32]),
}

/// Microbenchmark loop: per iteration, two loads from X0 into X9 and X11,
/// ADD and EOR into X10, then SUBS X1 and B.NE; returns X10.
pub(super) const fn micro_loop(first: u32, second: u32) -> [u32; 8] {
    const ADD_X10_X10_X9: u32 = 0x8b09_014a;
    const EOR_X10_X10_X11: u32 = 0xca0b_014a;
    const SUBS_X1_X1_ONE: u32 = 0xf100_0421;
    const B_NE_MINUS_5: u32 = 0x54ff_ff61;
    const MOV_X0_X10: u32 = 0xaa0a_03e0;
    [
        first,
        ADD_X10_X10_X9,
        second,
        EOR_X10_X10_X11,
        SUBS_X1_X1_ONE,
        B_NE_MINUS_5,
        MOV_X0_X10,
        RET,
    ]
}
/// LDR X9, [X0, #8] and LDR X11, [X0, #16].
pub(super) const MICRO_DOUBLEWORD: [u32; 8] = micro_loop(0xf940_0409, 0xf940_080b);
/// LDRH W9, [X0, #2] and LDRH W11, [X0, #4].
pub(super) const MICRO_HALFWORD: [u32; 8] = micro_loop(0x7940_0409, 0x7940_080b);
pub(super) const MICRO_ITERATIONS: usize = 1000;

/// The input a workload passes, which decides its expected result.
#[derive(Clone, Copy, Debug)]
pub(super) enum Input {
    /// memchr over `n` bytes without the byte.
    MemchrMiss(usize),
    /// strncmp of two equal `n`-byte strings, limit `n`.
    StrncmpEqual(usize),
    Atol(&'static str),
    /// lsl::Allocator::owned over a list of `n` regions none of which owns
    /// the pointer: half start above it, half end below it.
    AllocatorMiss(usize),
    /// RuntimeState::inPermanentRange over two chunks of `n` ranges, none
    /// containing the range: half start above it, half are compared fully.
    PermanentRangeMiss(usize),
    /// murmurHash over `n` bytes.
    Murmur(usize),
    /// A microbenchmark loop for `n` iterations over loads of `bytes`.
    Micro {
        iterations: usize,
        bytes: usize,
    },
}

pub(super) struct Workload {
    pub(super) name: &'static str,
    pub(super) source: Source,
    pub(super) symbol: &'static str,
    pub(super) input: Input,
}

pub(super) const WORKLOADS: [Workload; 10] = [
    Workload {
        name: "m1n1 memchr, 257-byte miss",
        source: Source::M1n1String,
        symbol: "_memchr",
        input: Input::MemchrMiss(257),
    },
    Workload {
        name: "m1n1 memchr, 4096-byte miss",
        source: Source::M1n1String,
        symbol: "_memchr",
        input: Input::MemchrMiss(4096),
    },
    Workload {
        name: "m1n1 strncmp, 257 equal bytes",
        source: Source::M1n1String,
        symbol: "_strncmp",
        input: Input::StrncmpEqual(257),
    },
    Workload {
        name: "m1n1 atol, 19 digits",
        source: Source::M1n1String,
        symbol: "_atol",
        input: Input::Atol("1234567890123456789"),
    },
    Workload {
        name: "dyld lsl::Allocator::owned, 64-region list",
        source: Source::Dyld,
        symbol: "__ZNK3lsl9Allocator5ownedEPKvy",
        input: Input::AllocatorMiss(64),
    },
    Workload {
        name: "dyld RuntimeState::inPermanentRange, 2x64 ranges",
        source: Source::Dyld,
        symbol: "__ZN5dyld412RuntimeState16inPermanentRangeEmmPhPPKNS_6LoaderE",
        input: Input::PermanentRangeMiss(64),
    },
    Workload {
        name: "dyld murmurHash, 1027 bytes",
        source: Source::Dyld,
        symbol: "__Z10murmurHashPKviy",
        input: Input::Murmur(1027),
    },
    Workload {
        name: "dyld murmurHash, 64 bytes",
        source: Source::Dyld,
        symbol: "__Z10murmurHashPKviy",
        input: Input::Murmur(64),
    },
    Workload {
        name: "micro: LDR X offset loop, 1000 iterations",
        source: Source::Words(&MICRO_DOUBLEWORD),
        symbol: "",
        input: Input::Micro {
            iterations: MICRO_ITERATIONS,
            bytes: 8,
        },
    },
    Workload {
        name: "micro: LDRH offset loop, 1000 iterations",
        source: Source::Words(&MICRO_HALFWORD),
        symbol: "",
        input: Input::Micro {
            iterations: MICRO_ITERATIONS,
            bytes: 2,
        },
    },
];

pub(super) fn arm64e_slice(file: &[u8]) -> Result<&[u8]> {
    let fat = MachOFatFile32::parse(file)?;
    for arch in fat.arches() {
        if arch.cputype() == macho::CPU_TYPE_ARM64
            && arch.cpusubtype() & !macho::CPU_SUBTYPE_MASK == macho::CPU_SUBTYPE_ARM64E
        {
            return Ok(arch.data(file)?);
        }
    }
    bail!("no arm64e slice")
}

/// The bytes of `symbol`, up to the next symbol of its section, refusing
/// any relocation inside them.
pub(super) fn function(data: &[u8], symbol: &str) -> Result<Vec<u8>> {
    let file = object::File::parse(data)?;
    let found = file
        .symbols()
        .find(|candidate| candidate.name() == Ok(symbol))
        .with_context(|| format!("no symbol {symbol}"))?;
    let section = file.section_by_index(found.section_index().context("undefined symbol")?)?;
    let start = found.address();
    let end = file
        .symbols()
        .filter(|other| {
            other.section_index() == found.section_index()
                && other.address() > start
                && matches!(other.kind(), SymbolKind::Text | SymbolKind::Label)
        })
        .map(|other| other.address())
        .min()
        .unwrap_or(section.address() + section.size());
    let offset = |address: u64| (address - section.address()) as usize;
    ensure!(
        section
            .relocations()
            .all(|(at, _)| !(start..end).contains(&(section.address() + at))),
        "{symbol} has relocations"
    );
    let bytes = section.data()?[offset(start)..offset(end)].to_vec();
    ensure!(
        bytes.len() % 4 == 0 && bytes.ends_with(&RET.to_le_bytes()),
        "{symbol} does not end in RET"
    );
    Ok(bytes)
}

/// Where every arena is mapped, so that code placement, pointers and final
/// states are the same in every worker and build.
pub(super) const ARENA: u64 = 0x7_0000_0000;

/// Host memory a workload's function and data live in: guest addresses are
/// host addresses in both engines.
pub(super) struct Arena {
    base: *mut u8,
    bytes: usize,
}

impl Arena {
    pub(super) fn new(bytes: usize) -> Result<Self> {
        let bytes = bytes.next_multiple_of(PAGE);
        // SAFETY: a fresh private anonymous mapping owned by this value, at
        // a hint only, so nothing else is replaced.
        let base = unsafe {
            libc::mmap(
                ARENA as *mut libc::c_void,
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        ensure!(base != libc::MAP_FAILED, "cannot map the bench arena");
        if base as u64 != ARENA {
            // SAFETY: the mapping just made.
            unsafe { libc::munmap(base, bytes) };
            bail!("the bench arena's address {ARENA:#x} is in use");
        }
        Ok(Self {
            base: base.cast(),
            bytes,
        })
    }

    pub(super) fn address(&self, offset: usize) -> u64 {
        assert!(offset < self.bytes);
        self.base as u64 + offset as u64
    }

    pub(super) fn write(&mut self, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= self.bytes);
        // SAFETY: inside the mapping.
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.base.add(offset), data.len()) };
    }

    pub(super) fn write_u64(&mut self, offset: usize, value: u64) {
        self.write(offset, &value.to_le_bytes());
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: the mapping this value owns.
        unsafe { libc::munmap(self.base.cast(), self.bytes) };
    }
}

pub(super) const CODE: usize = 0;
pub(super) const STOP: usize = PAGE - 4;
/// The hosted engine's padding function, below the stack.
pub(super) const PADDING: usize = PAGE;
/// Padding instructions: round times the step, modulo the span.
pub(super) const PADDING_STEP: usize = 7;
pub(super) const PADDING_SPAN: usize = 32;
pub(super) const STACK_TOP: usize = 2 * PAGE;
pub(super) const DATA: usize = 2 * PAGE;

/// The arena, initial state and expected X0 of one workload.
pub(super) fn prepare(input: Input, code: &[u8]) -> Result<(Arena, GuestState, u64)> {
    ensure!(code.len() < STOP, "function larger than its page");
    let mut arena = Arena::new(DATA + 64 * PAGE)?;
    arena.write(CODE, code);
    // Never executed: the run stops at its breakpoint first.
    arena.write(STOP, &0u32.to_le_bytes());
    let mut state = GuestState::default();
    state.x[30] = arena.address(STOP);
    state.sp = arena.address(STACK_TOP);
    let data = arena.address(DATA);
    let expected = match input {
        Input::MemchrMiss(bytes) => {
            arena.write(DATA, &vec![b'a'; bytes]);
            state.x[..3].copy_from_slice(&[data, u64::from(b'z'), bytes as u64]);
            0
        }
        Input::StrncmpEqual(bytes) => {
            let text = vec![b'a'; bytes];
            arena.write(DATA, &text);
            arena.write(DATA + PAGE, &text);
            state.x[..3].copy_from_slice(&[data, data + PAGE as u64, bytes as u64]);
            0
        }
        Input::Atol(text) => {
            arena.write(DATA, text.as_bytes());
            state.x[0] = data;
            text.parse::<i64>()? as u64
        }
        Input::AllocatorMiss(regions) => {
            // Region: next at 0x10, start at 0x20, size at 0x28.
            const NODE: usize = 0x40;
            const POINTER: u64 = 0x10_0000;
            let first = DATA + NODE;
            arena.write_u64(DATA + 8, arena.address(first));
            for index in 0..regions {
                let node = first + index * NODE;
                let next = if index + 1 == regions {
                    0
                } else {
                    arena.address(node + NODE)
                };
                let (start, size) = if index % 2 == 0 {
                    (POINTER + 0x1000, 0x100)
                } else {
                    (0x1000, 0x100)
                };
                arena.write_u64(node + 0x10, next);
                arena.write_u64(node + 0x20, start);
                arena.write_u64(node + 0x28, size);
            }
            state.x[..3].copy_from_slice(&[data, POINTER, 0x10]);
            0
        }
        Input::PermanentRangeMiss(ranges) => {
            // State: chunk list at 0x468. Chunk: next at 0, count at 8,
            // 32-byte ranges (start, end, ...) from 0x10.
            const START: u64 = 0x8000;
            let chunks = [DATA + PAGE, DATA + 2 * PAGE];
            arena.write_u64(DATA + 0x468, arena.address(chunks[0]));
            for (index, &chunk) in chunks.iter().enumerate() {
                let next = chunks.get(index + 1).map_or(0, |&next| arena.address(next));
                arena.write_u64(chunk, next);
                arena.write_u64(chunk + 8, ranges as u64);
                for range in 0..ranges {
                    let entry = chunk + 0x10 + range * 0x20;
                    let start = if range % 2 == 0 { START + 1 } else { 0x1000 };
                    arena.write_u64(entry, start);
                    arena.write_u64(entry + 8, 0x2000);
                }
            }
            state.x[..3].copy_from_slice(&[data, START, u64::MAX]);
            0
        }
        Input::Murmur(bytes) => {
            let text: Vec<u8> = (0..bytes).map(|index| (index * 131 + 7) as u8).collect();
            arena.write(DATA, &text);
            const SEED: u64 = 0x5bd1_e995_1234_5678;
            state.x[..3].copy_from_slice(&[data, bytes as u64, SEED]);
            murmur(&text, SEED)
        }
        Input::Micro { iterations, bytes } => {
            let (first, second) = (0x0123_4567_89ab_cdef_u64, 0xfedc_ba98_7654_3210_u64);
            let mask = u64::MAX >> (64 - 8 * bytes);
            arena.write_u64(DATA + bytes, first);
            arena.write_u64(DATA + 2 * bytes, second);
            let (first, second) = (first & mask, second & mask);
            state.x[..2].copy_from_slice(&[data, iterations as u64]);
            (0..iterations).fold(0u64, |sum, _| sum.wrapping_add(first) ^ second)
        }
    };
    Ok((arena, state, expected))
}

/// dyld's `murmurHash(const void*, int, uint64_t)`, as its 26A434 code
/// computes it (MurmurHash64A, multiplying once more before the
/// finalization).
pub(super) fn murmur(data: &[u8], seed: u64) -> u64 {
    const M: u64 = 0xc6a4_a793_5bd1_e995;
    const R: u32 = 47;
    let mut hash = (data.len() as i64 as u64).wrapping_mul(M) ^ seed;
    let (blocks, tail) = data.split_at(data.len() / 8 * 8);
    for block in blocks.as_chunks::<8>().0 {
        let mut k = u64::from_le_bytes(*block).wrapping_mul(M);
        k ^= k >> R;
        hash ^= k.wrapping_mul(M);
        hash = hash.wrapping_mul(M);
    }
    for (index, &byte) in tail.iter().enumerate() {
        hash ^= u64::from(byte) << (8 * index);
    }
    hash = hash.wrapping_mul(M);
    hash ^= hash >> R;
    hash = hash.wrapping_mul(M);
    hash ^ (hash >> R)
}

pub(super) fn state_digest(state: &GuestState) -> String {
    let mut bytes = vec![];
    for value in state.x.iter().chain([&state.sp]) {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(state.nzcv.to_le_bytes());
    stela_runtime::sha256(&bytes)
}
