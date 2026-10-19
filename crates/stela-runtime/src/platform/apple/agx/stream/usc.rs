//! USC words: the shader state a launch, a vertex draw or a fragment
//! pipeline points to (cmdbuf.xml `USC Control`; Mesa `agxdecode_usc`).
//!
//! The words follow each other until `Preshader` or `No preshader` ends the
//! list. Addresses of shader code and of the list itself are offsets from
//! the USC execution base the command names (Mesa `decode_usc`).

use super::{StreamError, check_known, field, groups, mask, read_u64, refuse};
use crate::platform::apple::agx::isa::machine::Memory;
use alloc::vec::Vec;

/// Most words in one list.
const MAX_WORDS: usize = 256;

/// `USC Control` tags.
mod tag {
    pub const PRESHADER: u8 = 0x38;
    pub const FRAGMENT_PROPERTIES: u8 = 0x58;
    pub const NO_PRESHADER: u8 = 0x88;
    pub const SHADER: u8 = 0x0d;
    pub const UNIFORM: u8 = 0x1d;
    pub const UNIFORM_HIGH: u8 = 0x3d;
    pub const SHARED: u8 = 0x4d;
    pub const REGISTERS: u8 = 0x8d;
    pub const SAMPLER: u8 = 0x9d;
    pub const TEXTURE: u8 = 0xdd;
}

/// Uniform halves past which `Uniform high` starts.
const UNIFORM_HIGH_BASE: u32 = 256;
/// The `Preshader` word's fixed middle field.
const PRESHADER_UNKNOWN: u64 = 0xc0_8000;
/// Bytes per spill unit (Mesa `AGX_SPILL_UNIT_DWORDS` dwords).
const SPILL_UNIT_BYTES: u32 = 32;

/// Uniform halves loaded from memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniformLoad {
    pub start: u32,
    pub halves: u32,
    pub address: u64,
}

/// Texture or sampler state registers loaded from memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateLoad {
    pub start: u32,
    pub count: u32,
    pub address: u64,
}

/// `USC Shared`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shared {
    pub uses_shared_memory: bool,
    /// `Shared layout`: vertex/compute or a tile size.
    pub layout: u32,
    pub samples: u32,
    pub sample_stride_bytes: u32,
    pub bytes_per_threadgroup: u32,
}

/// `Shared layout` values.
pub mod layout {
    pub const VERTEX_COMPUTE: u32 = 0x24;
    pub const TILE_32X32: u32 = 0x2f;
    pub const TILE_32X16: u32 = 0x3f;
    pub const TILE_16X16: u32 = 0x36;
}

/// `USC Fragment Properties`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentProperties {
    pub early_z: bool,
    pub unconditional_discard: bool,
}

/// One parsed list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UscState {
    pub uniforms: Vec<UniformLoad>,
    pub textures: Vec<StateLoad>,
    pub samplers: Vec<StateLoad>,
    pub shared: Option<Shared>,
    /// The main shader's code, from the USC base.
    pub code: Option<u32>,
    pub loads_varyings: bool,
    /// Register halves the shader allocates.
    pub register_halves: Option<u32>,
    /// Scratch bytes per thread.
    pub spill_bytes: u32,
    /// The preshader's code, from the USC base.
    pub preshader: Option<u32>,
    pub fragment: Option<FragmentProperties>,
}

/// Parse the list at `base + offset`.
pub fn parse(memory: &mut dyn Memory, base: u64, offset: u64) -> Result<UscState, StreamError> {
    let mut state = UscState::default();
    let mut address = base.wrapping_add(offset);
    for _ in 0..MAX_WORDS {
        // Every word fits in the next eight bytes; a list ending at a page
        // edge still has its short final word mapped.
        let word = match read_u64(memory, address) {
            Ok(word) => word,
            Err(_) => {
                let mut bytes = [0u8; 2];
                memory.read(address, &mut bytes)?;
                u64::from(u16::from_le_bytes(bytes))
            }
        };
        let length = match word as u8 {
            tag::NO_PRESHADER => {
                check_known(
                    address,
                    word & 0xffff,
                    0xff,
                    "a No preshader word with unnamed bits",
                )?;
                return Ok(state);
            }
            tag::PRESHADER => {
                if field(word, 8, 24) != PRESHADER_UNKNOWN {
                    return refuse(address, "a Preshader word with an unrecorded middle field");
                }
                state.preshader = Some(field(word, 32, 32) as u32);
                return Ok(state);
            }
            tag::UNIFORM | tag::UNIFORM_HIGH => {
                check_known(
                    address,
                    word,
                    mask(&[(0, 8), (8, 8), (20, 6), (26, 38)]),
                    "a Uniform word with unnamed bits",
                )?;
                let high = if word as u8 == tag::UNIFORM_HIGH {
                    UNIFORM_HIGH_BASE
                } else {
                    0
                };
                state.uniforms.push(UniformLoad {
                    start: high + field(word, 8, 8) as u32,
                    halves: groups(field(word, 20, 6), 1, 6) as u32,
                    address: field(word, 26, 38) << 2,
                });
                8
            }
            tag::TEXTURE | tag::SAMPLER => {
                check_known(
                    address,
                    word,
                    mask(&[(0, 8), (8, 8), (20, 7), (27, 36)]),
                    "a Texture or Sampler word with unnamed bits",
                )?;
                let load = StateLoad {
                    start: field(word, 8, 8) as u32,
                    count: field(word, 20, 7) as u32,
                    address: field(word, 27, 36) << 3,
                };
                if word as u8 == tag::TEXTURE {
                    state.textures.push(load);
                } else {
                    state.samplers.push(load);
                }
                8
            }
            tag::SHARED => {
                let word = word & 0xffff_ffff;
                check_known(
                    address,
                    word,
                    mask(&[(0, 9), (10, 6), (16, 2), (20, 4), (24, 8)]),
                    "a Shared word with unnamed bits",
                )?;
                state.shared = Some(Shared {
                    uses_shared_memory: field(word, 8, 1) != 0,
                    layout: field(word, 10, 6) as u32,
                    samples: 1 << field(word, 16, 2),
                    sample_stride_bytes: 8 * field(word, 20, 4) as u32,
                    bytes_per_threadgroup: groups(field(word, 24, 8), 256, 8) as u32,
                });
                4
            }
            tag::SHADER => {
                let word = word & 0xffff_ffff_ffff;
                state.loads_varyings = field(word, 8, 1) != 0;
                state.code = Some(field(word, 16, 32) as u32);
                6
            }
            tag::REGISTERS => {
                let word = word & 0xffff_ffff;
                check_known(
                    address,
                    word,
                    mask(&[(0, 14), (18, 4), (24, 8)]),
                    "a Registers word with unnamed bits",
                )?;
                state.register_halves = Some(groups(field(word, 8, 5), 8, 5) as u32);
                let bucket = field(word, 18, 4) as u32;
                // Mesa `agx_scratch_get_bucket`: bucket b > 0 holds up to
                // 8 << (b - 1) dwords per thread.
                state.spill_bytes = if bucket == 0 {
                    0
                } else {
                    SPILL_UNIT_BYTES << (bucket - 1)
                };
                4
            }
            tag::FRAGMENT_PROPERTIES => {
                let word = word & 0xffff_ffff;
                state.fragment = Some(FragmentProperties {
                    early_z: field(word, 8, 1) != 0,
                    unconditional_discard: field(word, 10, 2) != 0,
                });
                4
            }
            _ => return refuse(address, "a USC word with an unknown tag"),
        };
        address += length;
    }
    refuse(address, "a USC word list without an end")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Flat, words};
    use super::*;

    const BASE: u64 = 0x1_0000_0000;

    #[test]
    fn a_compute_list_parses_to_its_state() {
        let mut memory = Flat::new(BASE, 0x1000);
        // Shared (vertex/compute, 1 KiB), Registers (32 halves, bucket 2),
        // Uniform (4 halves at 0 from 0x1_0000_0800), Texture (2 at ts1),
        // Shader at 0x400, No preshader.
        let shared = 0x4d | 1 << 8 | 0x24 << 10 | 4 << 24;
        let registers = 0x8d | 4 << 8 | 2 << 18;
        let uniform = 0x1d | 4 << 20 | (0x1_0000_0800u64 >> 2) << 26;
        let texture = 0xdd | 1 << 8 | 2 << 20 | (0x1_0000_0900u64 >> 3) << 27;
        let mut bytes = alloc::vec::Vec::new();
        bytes.extend_from_slice(&(shared as u32).to_le_bytes());
        bytes.extend_from_slice(&(registers as u32).to_le_bytes());
        bytes.extend_from_slice(&uniform.to_le_bytes());
        bytes.extend_from_slice(&texture.to_le_bytes());
        bytes.extend_from_slice(&[0x0d, 0, 0, 4, 0, 0]);
        bytes.extend_from_slice(&[0x88, 0]);
        memory.put(BASE + 0x40, &bytes);
        let state = parse(&mut memory, BASE, 0x40).unwrap();
        assert_eq!(state.shared.unwrap().bytes_per_threadgroup, 1024);
        assert_eq!(state.register_halves, Some(32));
        assert_eq!(state.spill_bytes, 64);
        assert_eq!(
            state.uniforms,
            [UniformLoad {
                start: 0,
                halves: 4,
                address: 0x1_0000_0800
            }]
        );
        assert_eq!(
            state.textures,
            [StateLoad {
                start: 1,
                count: 2,
                address: 0x1_0000_0900
            }]
        );
        assert_eq!(state.code, Some(0x400));
        assert_eq!(state.preshader, None);
    }

    #[test]
    fn unknown_tags_and_bits_refuse() {
        let mut memory = Flat::new(BASE, 0x100);
        words(&mut memory, BASE, &[0x77]);
        assert!(matches!(
            parse(&mut memory, BASE, 0),
            Err(StreamError::Refused { .. })
        ));
        words(&mut memory, BASE, &[0x8d | 1 << 15]);
        assert!(matches!(
            parse(&mut memory, BASE, 0),
            Err(StreamError::Refused { .. })
        ));
    }
}
