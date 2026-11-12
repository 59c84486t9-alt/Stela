//! `MTLFunctionStitchingGraph`s, as the frontend's [`decode`] stream carries
//! them: little-endian 32-bit words, each graph
//! `[name bytes, node count, output + 1, kernel]`, its padded name and its
//! nodes, an
//! input `[0, argument index]`, a builtin `[u32::MAX, builtin]`, a buffer
//! address `[u32::MAX - 1, buffer index, offset low, offset high, dereference]`,
//! an early return `[u32::MAX - 2, condition node index, value node index + 1]`,
//! a texture `[u32::MAX - 3, texture index]`, a sampler
//! `[u32::MAX - 4, sampler index]` and a call
//! `[function + 1, argument count, node indices...]`. Nodes follow what they
//! use, so running them in order keeps every dependency, control or data, and
//! `function` indexes the descriptor's `functions`.
use super::error::{Error, Result};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StitchedNode {
    /// The stitched function's argument.
    Input(u32),
    /// A builtin of the stitched kernel.
    Builtin(StitchedBuiltin),
    /// `MTLFunctionStitchingInputBufferAddress`: `offset` bytes into the
    /// buffer the stitched kernel binds at `index`, or with `dereference` the
    /// value there.
    BufferAddress {
        index: u32,
        offset: u64,
        dereference: bool,
    },
    /// `MTLFunctionStitchingEarlyReturnNode`: the stitched function returns
    /// the earlier node `value`, or nothing, here when the earlier node
    /// `condition` is nonzero.
    EarlyReturn {
        condition: u32,
        value: Option<u32>,
    },
    /// `MTLFunctionStitchingInputTexture`: the texture the stitched kernel
    /// binds at the index.
    Texture(u32),
    /// `MTLFunctionStitchingInputSampler`: likewise its sampler.
    Sampler(u32),
    /// `MTLFunctionStitchingInputThreadgroup`: likewise its threadgroup
    /// memory, which its dispatches size.
    Threadgroup(u32),
    Call {
        function: u32,
        arguments: Vec<u32>,
    },
}

/// The builtins a node reads, by the stream's numbers, which are
/// `enum stela_air_stitch_builtin`'s.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StitchedBuiltin {
    /// `MTLFunctionStitchingBuiltinThreadPositionInGrid`.
    ThreadPositionInGrid = 1,
    /// `MTLFunctionStitchingBuiltinThreadPositionInThreadgroup`.
    ThreadPositionInThreadgroup = 2,
}

/// The first word of a builtin node.
const BUILTIN: u32 = u32::MAX;
/// The first word of a buffer address node.
const BUFFER_ADDRESS: u32 = u32::MAX - 1;
/// The first word of an early return node.
const EARLY_RETURN: u32 = u32::MAX - 2;
/// The first words of texture, sampler and threadgroup memory nodes.
const TEXTURE: u32 = u32::MAX - 3;
const SAMPLER: u32 = u32::MAX - 4;
const THREADGROUP: u32 = u32::MAX - 5;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StitchedGraph {
    pub name: String,
    pub nodes: Vec<StitchedNode>,
    /// The node whose result the function returns.
    pub output: Option<u32>,
    /// The graph is a kernel's, as `MTLFunctionStitchingAttributeKernel`
    /// makes it, rather than a visible function's.
    pub kernel: bool,
}

const MALFORMED: Error = Error::Invalid("stitched function graph");

struct Words<'a>(&'a [u8]);

impl Words<'_> {
    fn word(&mut self) -> Result<u32> {
        let (word, rest) = self.0.split_first_chunk().ok_or(MALFORMED)?;
        self.0 = rest;
        Ok(u32::from_le_bytes(*word))
    }

    /// A count of things that each take a word at least, so the stream bounds
    /// what it asks for.
    fn count(&mut self) -> Result<usize> {
        let count = self.word()? as usize;
        (count <= self.0.len() / 4)
            .then_some(count)
            .ok_or(MALFORMED)
    }

    fn name(&mut self, bytes: usize) -> Result<String> {
        let padded = bytes.next_multiple_of(4);
        let name = self.0.get(..bytes).ok_or(MALFORMED)?;
        let name = String::from(str::from_utf8(name).map_err(|_| MALFORMED)?);
        self.0 = self.0.get(padded..).ok_or(MALFORMED)?;
        Ok(name)
    }

    fn node(&mut self, index: usize, functions: usize) -> Result<StitchedNode> {
        let first = self.word()?;
        if first == BUILTIN {
            return match self.word()? {
                1 => Ok(StitchedNode::Builtin(StitchedBuiltin::ThreadPositionInGrid)),
                2 => Ok(StitchedNode::Builtin(
                    StitchedBuiltin::ThreadPositionInThreadgroup,
                )),
                _ => Err(MALFORMED),
            };
        }
        if first == BUFFER_ADDRESS {
            let index = self.word()?;
            let offset = u64::from(self.word()?) | u64::from(self.word()?) << 32;
            let dereference = match self.word()? {
                0 => false,
                1 => true,
                _ => return Err(MALFORMED),
            };
            return Ok(StitchedNode::BufferAddress {
                index,
                offset,
                dereference,
            });
        }
        if first == TEXTURE {
            return Ok(StitchedNode::Texture(self.word()?));
        }
        if first == SAMPLER {
            return Ok(StitchedNode::Sampler(self.word()?));
        }
        if first == THREADGROUP {
            return Ok(StitchedNode::Threadgroup(self.word()?));
        }
        if first == EARLY_RETURN {
            let earlier = |node: u32| ((node as usize) < index).then_some(node);
            let condition = earlier(self.word()?).ok_or(MALFORMED)?;
            let value = match self.word()?.checked_sub(1) {
                Some(value) => Some(earlier(value).ok_or(MALFORMED)?),
                None => None,
            };
            return Ok(StitchedNode::EarlyReturn { condition, value });
        }
        let Some(function) = first.checked_sub(1) else {
            return Ok(StitchedNode::Input(self.word()?));
        };
        if function as usize >= functions {
            return Err(MALFORMED);
        }
        let count = self.count()?;
        let arguments = (0..count)
            .map(|_| {
                let argument = self.word()?;
                ((argument as usize) < index)
                    .then_some(argument)
                    .ok_or(MALFORMED)
            })
            .collect::<Result<_>>()?;
        Ok(StitchedNode::Call {
            function,
            arguments,
        })
    }
}

/// The graphs of `stream`, whose calls index `functions` functions.
pub fn decode(stream: &[u8], functions: usize) -> Result<Vec<StitchedGraph>> {
    let mut words = Words(stream);
    let mut graphs = Vec::new();
    while !words.0.is_empty() {
        let name_bytes = words.word()? as usize;
        let count = words.word()? as usize;
        let output = words.word()?.checked_sub(1);
        let kernel = match words.word()? {
            0 => false,
            1 => true,
            _ => return Err(MALFORMED),
        };
        let name = words.name(name_bytes)?;
        if name.is_empty() || name.contains('\0') {
            return Err(MALFORMED);
        }
        if count > words.0.len() / 8 {
            return Err(MALFORMED);
        }
        let nodes = (0..count)
            .map(|index| words.node(index, functions))
            .collect::<Result<Vec<_>>>()?;
        if output.is_some_and(|output| output as usize >= count) {
            return Err(MALFORMED);
        }
        graphs.push(StitchedGraph {
            name,
            nodes,
            output,
            kernel,
        });
    }
    Ok(graphs)
}

/// The stream [`decode`] reads `graphs` from.
pub fn encode(graphs: &[StitchedGraph]) -> Vec<u8> {
    let mut words = Vec::new();
    for graph in graphs {
        let name = graph.name.as_bytes();
        words.extend([
            name.len() as u32,
            graph.nodes.len() as u32,
            graph.output.map_or(0, |output| output + 1),
            graph.kernel.into(),
        ]);
        let mut padded = name.to_vec();
        padded.resize(name.len().next_multiple_of(4), 0);
        let (chunks, _) = padded.as_chunks::<4>();
        words.extend(chunks.iter().map(|chunk| u32::from_le_bytes(*chunk)));
        for node in &graph.nodes {
            match node {
                StitchedNode::Input(index) => words.extend([0, *index]),
                &StitchedNode::Builtin(builtin) => words.extend([BUILTIN, builtin as u32]),
                &StitchedNode::BufferAddress {
                    index,
                    offset,
                    dereference,
                } => words.extend([
                    BUFFER_ADDRESS,
                    index,
                    offset as u32,
                    (offset >> 32) as u32,
                    dereference.into(),
                ]),
                StitchedNode::EarlyReturn { condition, value } => {
                    words.extend([EARLY_RETURN, *condition, value.map_or(0, |value| value + 1)])
                }
                StitchedNode::Texture(index) => words.extend([TEXTURE, *index]),
                StitchedNode::Sampler(index) => words.extend([SAMPLER, *index]),
                StitchedNode::Threadgroup(index) => words.extend([THREADGROUP, *index]),
                StitchedNode::Call {
                    function,
                    arguments,
                } => {
                    words.extend([function + 1, arguments.len() as u32]);
                    words.extend(arguments);
                }
            }
        }
    }
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn stream(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn nodes_decode_in_their_order() {
        // `f(a) = g(g(a))`.
        let words = [1, 3, 3, 0, 0x66, 0, 0, 1, 1, 0, 1, 1, 1];
        assert_eq!(
            decode(&stream(&words), 1).unwrap(),
            [StitchedGraph {
                name: "f".into(),
                nodes: vec![
                    StitchedNode::Input(0),
                    StitchedNode::Call {
                        function: 0,
                        arguments: vec![0],
                    },
                    StitchedNode::Call {
                        function: 0,
                        arguments: vec![1],
                    },
                ],
                output: Some(2),
                kernel: false,
            }]
        );
    }

    #[test]
    fn builtins_decode_and_unknown_ones_are_refused() {
        // `kernel f() { g(thread_position_in_grid); }`.
        let words = [1, 2, 0, 1, 0x66, u32::MAX, 1, 1, 1, 0];
        let graph = &decode(&stream(&words), 1).unwrap()[0];
        assert!(graph.kernel);
        assert_eq!(
            graph.nodes,
            [
                StitchedNode::Builtin(StitchedBuiltin::ThreadPositionInGrid),
                StitchedNode::Call {
                    function: 0,
                    arguments: vec![0],
                },
            ]
        );
        let mut unknown = words;
        unknown[6] = 3;
        assert!(decode(&stream(&unknown), 1).is_err());
    }

    #[test]
    fn textures_samplers_and_threadgroups_decode_their_indices() {
        // `kernel f() { g(texture 3, sampler 1, threadgroup 2); }`.
        let words = [
            1,
            4,
            0,
            1,
            0x66,
            u32::MAX - 3,
            3,
            u32::MAX - 4,
            1,
            u32::MAX - 5,
            2,
            1,
            3,
            0,
            1,
            2,
        ];
        assert_eq!(
            decode(&stream(&words), 1).unwrap()[0].nodes[..3],
            [
                StitchedNode::Texture(3),
                StitchedNode::Sampler(1),
                StitchedNode::Threadgroup(2)
            ]
        );
    }

    #[test]
    fn buffer_addresses_decode_their_offsets() {
        // `kernel f() { g(*(buffer 3 + 2^32 + 8)); }`.
        let words = [1, 2, 0, 1, 0x66, u32::MAX - 1, 3, 8, 1, 1, 1, 1, 0];
        assert_eq!(
            decode(&stream(&words), 1).unwrap()[0].nodes[0],
            StitchedNode::BufferAddress {
                index: 3,
                offset: (1 << 32) + 8,
                dereference: true,
            }
        );
        let mut unknown = words;
        unknown[9] = 2;
        assert!(decode(&stream(&unknown), 1).is_err());
    }

    #[test]
    fn early_returns_name_an_earlier_condition() {
        // `f(a) { if (g(a)) return g(a); }`.
        let words = [1, 3, 0, 0, 0x66, 0, 0, 1, 1, 0, u32::MAX - 2, 1, 2];
        assert_eq!(
            decode(&stream(&words), 1).unwrap()[0].nodes[2],
            StitchedNode::EarlyReturn {
                condition: 1,
                value: Some(1),
            }
        );
        let mut nothing = words;
        nothing[12] = 0;
        assert_eq!(
            decode(&stream(&nothing), 1).unwrap()[0].nodes[2],
            StitchedNode::EarlyReturn {
                condition: 1,
                value: None,
            }
        );
        for (at, later) in [(11, 2), (12, 3)] {
            let mut bad = words;
            bad[at] = later;
            assert!(decode(&stream(&bad), 1).is_err(), "{at}");
        }
    }

    #[test]
    fn graphs_encode_as_they_decode() {
        let streams: [&[u32]; 5] = [
            &[1, 3, 3, 0, 0x66, 0, 0, 1, 1, 0, 1, 1, 1],
            &[1, 2, 0, 1, 0x66, u32::MAX, 1, 1, 1, 0],
            &[1, 2, 0, 1, 0x66, u32::MAX - 1, 3, 8, 1, 1, 1, 1, 0],
            &[1, 3, 0, 0, 0x66, 0, 0, 1, 1, 0, u32::MAX - 2, 1, 2],
            &[
                5,
                4,
                0,
                1,
                0x6c_6c_65_68,
                0x6f,
                u32::MAX - 3,
                3,
                u32::MAX - 4,
                1,
                u32::MAX - 5,
                2,
                1,
                3,
                0,
                1,
                2,
            ],
        ];
        let mut all = Vec::new();
        for words in streams {
            assert_eq!(encode(&decode(&stream(words), 1).unwrap()), stream(words));
            all.extend_from_slice(words);
        }
        assert_eq!(encode(&decode(&stream(&all), 1).unwrap()), stream(&all));
    }

    #[test]
    fn refuses_what_a_graph_cannot_be() {
        let good = [1, 2, 2, 0, 0x66, 0, 0, 1, 1, 0];
        assert!(decode(&stream(&good), 1).is_ok());
        for (at, value) in [
            // The function, a later node, an output past the nodes, no name,
            // a kind of graph past the two.
            (7, 2),
            (9, 1),
            (2, 3),
            (0, 0),
            (3, 2),
            // A node count past the stream.
            (1, u32::MAX),
        ] {
            let mut bad = good;
            bad[at] = value;
            assert!(decode(&stream(&bad), 1).is_err(), "{at}");
        }
        assert!(decode(&stream(&good)[..34], 1).is_err());
    }
}
