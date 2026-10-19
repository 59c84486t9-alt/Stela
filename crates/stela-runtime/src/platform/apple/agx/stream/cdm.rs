//! The CDM control stream (cmdbuf.xml `CDM ...`; Mesa `agxdecode_cdm`,
//! `agx_cdm_launch`).
//!
//! Blocks carry their type in bits 29..31 of the first word: `Launch`
//! (word 0 counts and mode, word 1 the USC pipeline, then the global size
//! and local size, an indirect buffer and local size, or an indirect buffer
//! holding both), `Barrier`, `Stream Link` (optionally with return),
//! `Stream Return` and `Stream Terminate`. G14G has no G14X word (Mesa emits
//! it only for `AGX_CHIP_G14X`). The walker yields one launch or barrier at
//! a time and reads the next block only after the caller asks, so a stream
//! a previous launch wrote is read after that launch ran.

use super::{
    BLOCK_BUDGET, CALL_DEPTH, StreamError, check_known, field, groups, mask, read_u32, refuse,
};
use crate::platform::apple::agx::isa::machine::Memory;
use alloc::vec::Vec;

/// `CDM Block Type`.
mod block {
    pub const LAUNCH: u32 = 0;
    pub const STREAM_LINK: u32 = 1;
    pub const STREAM_TERMINATE: u32 = 2;
    pub const BARRIER: u32 = 3;
    pub const STREAM_RETURN: u32 = 4;
}

/// `CDM Mode`.
mod mode {
    pub const DIRECT: u64 = 0;
    pub const INDIRECT_GLOBAL: u64 = 1;
    pub const INDIRECT_LOCAL: u64 = 2;
}

/// Bytes of the eight-byte stream blocks.
const LONG_BLOCK: u64 = 8;
/// The barrier's `Returns` flag (bit 27), whose effect is unrecovered.
const BARRIER_RETURNS: u64 = 1 << 27;

/// How a launch sizes its grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grid {
    /// Threads in the grid and in each threadgroup.
    Direct { global: [u32; 3], local: [u32; 3] },
    /// Three words of grid size at `address`, the local size inline.
    IndirectGlobal { address: u64, local: [u32; 3] },
    /// Six words at `address`: the grid size, then the local size.
    IndirectLocal { address: u64 },
}

/// `Sampler states` (cmdbuf.xml).
pub fn extended_samplers(states: u32) -> bool {
    states == 6 || states == 7
}

/// One `Launch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Launch {
    pub uniform_halves: u32,
    pub texture_states: u32,
    /// The `Sampler states` value.
    pub sampler_states: u32,
    pub preshader_registers: u32,
    /// The USC word list, from the USC base.
    pub pipeline: u32,
    pub grid: Grid,
}

impl Launch {
    /// The grid and local sizes, reading an indirect buffer.
    pub fn sizes(&self, memory: &mut dyn Memory) -> Result<([u32; 3], [u32; 3]), StreamError> {
        let read3 = |memory: &mut dyn Memory, address: u64| -> Result<[u32; 3], StreamError> {
            Ok([
                read_u32(memory, address)?,
                read_u32(memory, address + 4)?,
                read_u32(memory, address + 8)?,
            ])
        };
        Ok(match self.grid {
            Grid::Direct { global, local } => (global, local),
            Grid::IndirectGlobal { address, local } => (read3(memory, address)?, local),
            Grid::IndirectLocal { address } => {
                (read3(memory, address)?, read3(memory, address + 12)?)
            }
        })
    }
}

/// What the stream asks for next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Launch(Launch),
    /// A barrier: earlier launches complete (and their caches flush)
    /// before later ones start. The flags name cache operations.
    Barrier(u32),
}

/// A CDM stream being walked.
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

    /// The next launch or barrier, or `None` at `Stream Terminate`.
    pub fn next(&mut self, memory: &mut dyn Memory) -> Result<Option<Command>, StreamError> {
        while !self.done {
            self.blocks += 1;
            if self.blocks > BLOCK_BUDGET {
                return refuse(self.address, "a CDM stream that never terminates");
            }
            let at = self.address;
            let word = u64::from(read_u32(memory, at)?);
            match field(word, 29, 3) as u32 {
                block::LAUNCH => {
                    return self
                        .launch(memory, at, word)
                        .map(|l| Some(Command::Launch(l)));
                }
                block::BARRIER => {
                    if word & BARRIER_RETURNS != 0 {
                        return refuse(at, "a CDM barrier with its Returns flag (unrecovered)");
                    }
                    check_known(
                        at,
                        word,
                        mask(&[(0, 21), (24, 1), (26, 2), (29, 3)]),
                        "a CDM barrier with unnamed bits",
                    )?;
                    self.address = at + 4;
                    return Ok(Some(Command::Barrier(word as u32 & !(7 << 29))));
                }
                block::STREAM_LINK => {
                    check_known(
                        at,
                        word,
                        mask(&[(0, 8), (28, 4)]),
                        "a CDM stream link with unnamed bits",
                    )?;
                    let low = u64::from(read_u32(memory, at + 4)?);
                    let target = field(word, 0, 8) << 32 | low;
                    if field(word, 28, 1) != 0 {
                        if self.returns.len() == CALL_DEPTH {
                            return refuse(at, "CDM stream calls nested past the return stack");
                        }
                        self.returns.push(at + LONG_BLOCK);
                    }
                    self.address = target;
                }
                block::STREAM_RETURN => {
                    check_known(
                        at,
                        word,
                        mask(&[(29, 3)]),
                        "a CDM stream return with unnamed bits",
                    )?;
                    self.address = match self.returns.pop() {
                        Some(back) => back,
                        None => return refuse(at, "a CDM stream return with nothing to return to"),
                    };
                }
                block::STREAM_TERMINATE => {
                    check_known(
                        at,
                        word,
                        mask(&[(29, 3)]),
                        "a CDM stream terminate with unnamed bits",
                    )?;
                    self.done = true;
                }
                _ => return refuse(at, "a CDM block of an unknown type"),
            }
        }
        Ok(None)
    }

    fn launch(
        &mut self,
        memory: &mut dyn Memory,
        at: u64,
        word0: u64,
    ) -> Result<Launch, StreamError> {
        check_known(
            at,
            word0,
            mask(&[(1, 15), (27, 5)]),
            "a CDM launch word 0 with unnamed bits",
        )?;
        let word1 = u64::from(read_u32(memory, at + 4)?);
        check_known(
            at + 4,
            word1,
            mask(&[(6, 26)]),
            "a CDM launch word 1 with unnamed bits",
        )?;
        let mut cursor = at + 8;
        let mut read3 = |memory: &mut dyn Memory| -> Result<[u32; 3], StreamError> {
            let values = [
                read_u32(memory, cursor)?,
                read_u32(memory, cursor + 4)?,
                read_u32(memory, cursor + 8)?,
            ];
            cursor += 12;
            Ok(values)
        };
        let grid = match field(word0, 27, 2) {
            mode::DIRECT => {
                let global = read3(memory)?;
                Grid::Direct {
                    global,
                    local: read3(memory)?,
                }
            }
            mode::INDIRECT_GLOBAL | mode::INDIRECT_LOCAL => {
                let indirect = at + 8;
                let high = u64::from(read_u32(memory, indirect)?);
                let low = u64::from(read_u32(memory, indirect + 4)?);
                check_known(
                    indirect,
                    high,
                    0xff,
                    "a CDM indirect word with unnamed bits",
                )?;
                check_known(
                    indirect + 4,
                    low,
                    !3 & 0xffff_ffff,
                    "a CDM indirect address with unnamed bits",
                )?;
                let address = high << 32 | low;
                if field(word0, 27, 2) == mode::INDIRECT_LOCAL {
                    cursor = indirect + 8;
                    Grid::IndirectLocal { address }
                } else {
                    cursor = indirect + 8;
                    let mut local = [0u32; 3];
                    for (i, value) in local.iter_mut().enumerate() {
                        *value = read_u32(memory, cursor + 4 * i as u64)?;
                    }
                    cursor += 12;
                    Grid::IndirectGlobal { address, local }
                }
            }
            _ => return refuse(at, "a CDM launch of an unknown mode"),
        };
        self.address = cursor;
        Ok(Launch {
            uniform_halves: groups(field(word0, 1, 3), 64, 3) as u32,
            texture_states: groups(field(word0, 4, 5), 8, 5) as u32,
            sampler_states: field(word0, 9, 3) as u32,
            preshader_registers: groups(field(word0, 12, 4), 16, 4) as u32,
            pipeline: (field(word1, 6, 26) << 6) as u32,
            grid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Flat, words};
    use super::*;

    const BASE: u64 = 0x1_0000_0000;

    fn walk(memory: &mut Flat, start: u64) -> Result<Vec<Command>, StreamError> {
        let mut walker = Walker::new(start);
        let mut commands = Vec::new();
        while let Some(command) = walker.next(memory)? {
            commands.push(command);
        }
        Ok(commands)
    }

    #[test]
    fn launches_barriers_and_calls_walk_in_order() {
        let mut memory = Flat::new(BASE, 0x1000);
        // Launch: 64 uniform halves, pipeline 0x40, grid 64x1x1, local 32x1x1.
        let launch = [1 << 1, 1 << 6, 64, 1, 1, 32, 1, 1];
        words(&mut memory, BASE, &launch);
        // Call the stream at 0x200, then terminate.
        words(
            &mut memory,
            BASE + 32,
            &[1 << 29 | 1 << 28 | 1, 0x200, 2 << 29, 0],
        );
        // At 0x1_0000_0200: a barrier, then return.
        words(&mut memory, BASE + 0x200, &[3 << 29 | 1 << 5, 4 << 29, 0]);
        let commands = walk(&mut memory, BASE).unwrap();
        assert_eq!(
            commands,
            [
                Command::Launch(Launch {
                    uniform_halves: 64,
                    texture_states: 256,
                    sampler_states: 0,
                    preshader_registers: 256,
                    pipeline: 0x40,
                    grid: Grid::Direct {
                        global: [64, 1, 1],
                        local: [32, 1, 1]
                    },
                }),
                Command::Barrier(1 << 5),
            ]
        );
    }

    #[test]
    fn indirect_launches_read_their_buffer_when_asked() {
        let mut memory = Flat::new(BASE, 0x1000);
        words(&mut memory, BASE, &[2 << 27, 0, 1, 0x100, 2 << 29]);
        words(&mut memory, BASE + 0x100, &[8, 4, 2, 4, 2, 1]);
        let commands = walk(&mut memory, BASE).unwrap();
        let Command::Launch(launch) = commands[0] else {
            panic!()
        };
        assert_eq!(
            launch.grid,
            Grid::IndirectLocal {
                address: 0x1_0000_0100
            }
        );
        assert_eq!(launch.sizes(&mut memory).unwrap(), ([8, 4, 2], [4, 2, 1]));
    }

    #[test]
    fn malformed_streams_refuse() {
        let mut memory = Flat::new(BASE, 0x100);
        words(&mut memory, BASE, &[7 << 29]);
        assert!(matches!(
            walk(&mut memory, BASE),
            Err(StreamError::Refused { .. })
        ));
        words(&mut memory, BASE, &[4 << 29]);
        assert!(matches!(
            walk(&mut memory, BASE),
            Err(StreamError::Refused { .. })
        ));
        // A link to itself never ends.
        words(&mut memory, BASE, &[1 << 29 | 1, 0]);
        assert!(matches!(
            walk(&mut memory, BASE),
            Err(StreamError::Refused { .. })
        ));
    }
}
