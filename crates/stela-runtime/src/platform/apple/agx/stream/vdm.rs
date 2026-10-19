//! The VDM control stream (cmdbuf.xml `VDM ...`, `Index List`; Mesa
//! `agxdecode_vdm`, `agx_vdm_draw`).
//!
//! Blocks: `PPP State Update` (a PPP record's address and size), `VDM State
//! Update` (restart index, vertex shader words, vertex outputs, vertex
//! unknown, padded to eight bytes unless the tessellation scale ends it),
//! `Index List` (a draw), `Barrier` (whose `Returns` flag returns from a
//! stream call, as Mesa's decoder treats it), `Stream Link` and `Stream
//! Terminate`. The walker yields state updates and draws in order and leaves
//! their effect to the caller. Tessellation and the index list's two unknown
//! words have no published semantics and refuse by name.

use super::{
    BLOCK_BUDGET, CALL_DEPTH, StreamError, check_known, field, groups, mask, read_u32, refuse,
};
use crate::platform::apple::agx::isa::machine::Memory;
use alloc::vec::Vec;

/// `VDM Block Type`.
mod block {
    pub const PPP_STATE_UPDATE: u32 = 0;
    pub const BARRIER: u32 = 1;
    pub const VDM_STATE_UPDATE: u32 = 2;
    pub const INDEX_LIST: u32 = 3;
    pub const STREAM_LINK: u32 = 4;
    pub const TESSELLATE: u32 = 5;
    pub const STREAM_TERMINATE: u32 = 6;
}

const BARRIER_RETURNS: u64 = 1 << 27;
const LONG_BLOCK: u64 = 8;

/// The vertex shader a `VDM State Update` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VertexShader {
    pub uniform_halves: u32,
    pub texture_states: u32,
    pub sampler_states: u32,
    pub preshader_registers: u32,
}

/// One `VDM State Update`; absent words leave earlier state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StateUpdate {
    pub restart_index: Option<u32>,
    pub shader: Option<VertexShader>,
    /// The vertex shader's USC word list, from the USC base.
    pub pipeline: Option<u32>,
    /// `Output count 1` and `2`.
    pub outputs: Option<[u32; 2]>,
    /// `Flat shading control`, `Unknown 4`/`5`, `Generate primitive ID`.
    pub vertex_unknown: Option<u32>,
}

/// `Index size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexSize {
    U8,
    U16,
    U32,
}

impl IndexSize {
    pub fn bytes(self) -> u64 {
        match self {
            IndexSize::U8 => 1,
            IndexSize::U16 => 2,
            IndexSize::U32 => 4,
        }
    }
}

/// One `Index List` draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Draw {
    /// The `Primitive` value.
    pub primitive: u32,
    pub restart: bool,
    /// The index buffer, its element size and size in bytes, when indexed.
    pub indices: Option<(u64, IndexSize, Option<u64>)>,
    pub count: Option<u32>,
    pub instances: Option<u32>,
    /// The first vertex, or the base vertex of an indexed draw.
    pub start: Option<u32>,
    /// An indirect draw's arguments (Metal's layout).
    pub indirect: Option<u64>,
}

/// What the stream asks for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Apply the PPP record of `words` words at `address`.
    Ppp {
        address: u64,
        words: u32,
    },
    State(StateUpdate),
    Draw(Draw),
    Barrier(u32),
}

#[derive(Debug, Clone)]
pub struct Walker {
    address: u64,
    returns: Vec<u64>,
    blocks: usize,
    done: bool,
}

impl Walker {
    pub fn new(start: u64) -> Self {
        Walker {
            address: start,
            returns: Vec::new(),
            blocks: 0,
            done: false,
        }
    }

    pub fn next(&mut self, memory: &mut dyn Memory) -> Result<Option<Command>, StreamError> {
        while !self.done {
            self.blocks += 1;
            if self.blocks > BLOCK_BUDGET {
                return refuse(self.address, "a VDM stream that never terminates");
            }
            let at = self.address;
            let word = u64::from(read_u32(memory, at)?);
            match field(word, 29, 3) as u32 {
                block::PPP_STATE_UPDATE => {
                    check_known(
                        at,
                        word,
                        mask(&[(0, 16), (29, 3)]),
                        "a PPP state update with unnamed bits",
                    )?;
                    let low = u64::from(read_u32(memory, at + 4)?);
                    self.address = at + LONG_BLOCK;
                    return Ok(Some(Command::Ppp {
                        address: field(word, 0, 8) << 32 | low,
                        words: field(word, 8, 8) as u32,
                    }));
                }
                block::BARRIER => {
                    check_known(
                        at,
                        word,
                        mask(&[(0, 28), (29, 3)]),
                        "a VDM barrier with unnamed bits",
                    )?;
                    if word & BARRIER_RETURNS != 0 {
                        self.address = match self.returns.pop() {
                            Some(back) => back,
                            None => {
                                return refuse(
                                    at,
                                    "a VDM barrier returning with nothing to return to",
                                );
                            }
                        };
                    } else {
                        self.address = at + 4;
                    }
                    return Ok(Some(Command::Barrier(word as u32 & !(0xf << 28))));
                }
                block::VDM_STATE_UPDATE => {
                    return self
                        .state(memory, at, word)
                        .map(|s| Some(Command::State(s)));
                }
                block::INDEX_LIST => {
                    return self.draw(memory, at, word).map(|d| Some(Command::Draw(d)));
                }
                block::STREAM_LINK => {
                    check_known(
                        at,
                        word,
                        mask(&[(0, 8), (28, 4)]),
                        "a VDM stream link with unnamed bits",
                    )?;
                    let low = u64::from(read_u32(memory, at + 4)?);
                    if field(word, 28, 1) != 0 {
                        if self.returns.len() == CALL_DEPTH {
                            return refuse(at, "VDM stream calls nested past the return stack");
                        }
                        self.returns.push(at + LONG_BLOCK);
                    }
                    self.address = field(word, 0, 8) << 32 | low;
                }
                block::STREAM_TERMINATE => {
                    check_known(
                        at,
                        word,
                        mask(&[(29, 3)]),
                        "a VDM stream terminate with unnamed bits",
                    )?;
                    self.done = true;
                }
                block::TESSELLATE => {
                    return refuse(at, "VDM tessellation (its layout is unconfirmed)");
                }
                _ => return refuse(at, "a VDM block of an unknown type"),
            }
        }
        Ok(None)
    }

    fn state(
        &mut self,
        memory: &mut dyn Memory,
        at: u64,
        header: u64,
    ) -> Result<StateUpdate, StreamError> {
        check_known(
            at,
            header,
            mask(&[(0, 6), (7, 1), (29, 3)]),
            "a VDM state update with unnamed bits",
        )?;
        if field(header, 4, 1) != 0 || field(header, 7, 1) != 0 {
            return refuse(at, "VDM tessellation state (its layout is unconfirmed)");
        }
        let mut cursor = at + 4;
        let mut next = |memory: &mut dyn Memory| -> Result<(u64, u64), StreamError> {
            let address = cursor;
            cursor += 4;
            Ok((address, u64::from(read_u32(memory, address)?)))
        };
        let mut update = StateUpdate::default();
        if field(header, 0, 1) != 0 {
            update.restart_index = Some(next(memory)?.1 as u32);
        }
        if field(header, 1, 1) != 0 {
            let (address, word) = next(memory)?;
            check_known(
                address,
                word,
                mask(&[(0, 16)]),
                "a vertex shader word 0 with unnamed bits",
            )?;
            if word & 1 != 0 {
                return refuse(address, "a vertex shader word 0 with its unknown bit set");
            }
            update.shader = Some(VertexShader {
                uniform_halves: groups(field(word, 1, 3), 64, 3) as u32,
                texture_states: groups(field(word, 4, 5), 8, 5) as u32,
                sampler_states: field(word, 9, 3) as u32,
                preshader_registers: groups(field(word, 12, 4), 16, 4) as u32,
            });
        }
        if field(header, 2, 1) != 0 {
            let (address, word) = next(memory)?;
            check_known(
                address,
                word,
                mask(&[(6, 26)]),
                "a vertex shader word 1 with unnamed bits",
            )?;
            update.pipeline = Some((field(word, 6, 26) << 6) as u32);
        }
        if field(header, 3, 1) != 0 {
            let (address, word) = next(memory)?;
            check_known(
                address,
                word,
                mask(&[(0, 16)]),
                "a vertex outputs word with unnamed bits",
            )?;
            update.outputs = Some([field(word, 0, 8) as u32, field(word, 8, 8) as u32]);
        }
        if field(header, 5, 1) != 0 {
            let (address, word) = next(memory)?;
            check_known(
                address,
                word,
                mask(&[(0, 2), (4, 3)]),
                "a vertex unknown word with unnamed bits",
            )?;
            update.vertex_unknown = Some(word as u32);
        }
        let length = cursor - at;
        self.address = at + length.next_multiple_of(LONG_BLOCK);
        Ok(update)
    }

    fn draw(&mut self, memory: &mut dyn Memory, at: u64, header: u64) -> Result<Draw, StreamError> {
        check_known(
            at,
            header,
            mask(&[(0, 28), (29, 3)]),
            "an index list with unnamed bits",
        )?;
        if field(header, 25, 1) != 0 || field(header, 27, 1) != 0 {
            return refuse(at, "an index list with its unknown words present");
        }
        let mut cursor = at + 4;
        let mut next = |memory: &mut dyn Memory| -> Result<u64, StreamError> {
            let word = u64::from(read_u32(memory, cursor)?);
            cursor += 4;
            Ok(word)
        };
        let present = |bit: u32| field(header, bit, 1) != 0;
        let buffer = if present(21) {
            Some(field(header, 0, 8) << 32 | next(memory)?)
        } else {
            None
        };
        let count = if present(22) {
            Some(next(memory)? as u32)
        } else {
            None
        };
        let instances = if present(23) {
            Some(next(memory)? as u32)
        } else {
            None
        };
        let start = if present(24) {
            Some(next(memory)? as u32)
        } else {
            None
        };
        let indirect = if present(26) {
            let high = next(memory)?;
            let low = next(memory)?;
            Some(field(high, 0, 8) << 32 | low)
        } else {
            None
        };
        let size = if present(20) {
            Some(next(memory)? << 2)
        } else {
            None
        };
        let index_size = match field(header, 17, 3) {
            0 => IndexSize::U8,
            1 => IndexSize::U16,
            2 => IndexSize::U32,
            _ => return refuse(at, "an index list of an unknown index size"),
        };
        self.address = cursor;
        Ok(Draw {
            primitive: field(header, 8, 8) as u32,
            restart: present(16),
            indices: buffer.map(|address| (address, index_size, size)),
            count,
            instances,
            start,
            indirect,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Flat, words};
    use super::*;

    const BASE: u64 = 0x1_0000_0000;

    #[test]
    fn state_ppp_and_draws_walk_in_order() {
        let mut memory = Flat::new(BASE, 0x1000);
        words(
            &mut memory,
            BASE,
            &[
                // VDM state: word 1 (pipeline 0x80) and outputs; padded to 8.
                2 << 29 | 1 << 2 | 1 << 3,
                2 << 6,
                0x0404,
                0,
                // PPP update: 3 words at 0x1_0000_0400.
                1 | 3 << 8,
                0x400,
                // A 3-vertex triangle list, one instance, from 0.
                3 << 29 | 6 << 8 | 1 << 22 | 1 << 23 | 1 << 24,
                3,
                1,
                0,
                6 << 29,
            ],
        );
        let mut walker = Walker::new(BASE);
        let mut commands = Vec::new();
        while let Some(command) = walker.next(&mut memory).unwrap() {
            commands.push(command);
        }
        assert_eq!(
            commands,
            [
                Command::State(StateUpdate {
                    pipeline: Some(0x80),
                    outputs: Some([4, 4]),
                    ..Default::default()
                }),
                Command::Ppp {
                    address: 0x1_0000_0400,
                    words: 3
                },
                Command::Draw(Draw {
                    primitive: 6,
                    restart: false,
                    indices: None,
                    count: Some(3),
                    instances: Some(1),
                    start: Some(0),
                    indirect: None,
                }),
            ]
        );
    }

    #[test]
    fn tessellation_refuses() {
        let mut memory = Flat::new(BASE, 0x100);
        words(&mut memory, BASE, &[5 << 29]);
        assert!(matches!(
            Walker::new(BASE).next(&mut memory),
            Err(StreamError::Refused { .. })
        ));
    }
}
