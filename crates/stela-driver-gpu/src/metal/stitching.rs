//! `MTLFunctionStitchingGraph`s, as the frontend's [`decode`] stream carries
//! them: little-endian 32-bit words, each graph
//! `[name bytes, node count, output + 1]`, its padded name and its nodes, an
//! input `[0, argument index]` and a call
//! `[function + 1, argument count, node indices...]`. Nodes follow what they
//! use, so running them in order keeps every dependency, control or data, and
//! `function` indexes the descriptor's `functions`.
use super::error::{Error, Result};
use alloc::{string::String, vec::Vec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StitchedNode {
    /// The stitched function's argument.
    Input(u32),
    Call {
        function: u32,
        arguments: Vec<u32>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StitchedGraph {
    pub name: String,
    pub nodes: Vec<StitchedNode>,
    /// The node whose result the function returns.
    pub output: Option<u32>,
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
        let Some(function) = self.word()?.checked_sub(1) else {
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
        });
    }
    Ok(graphs)
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
        let words = [1, 3, 3, 0x66, 0, 0, 1, 1, 0, 1, 1, 1];
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
            }]
        );
    }

    #[test]
    fn refuses_what_a_graph_cannot_be() {
        let good = [1, 2, 2, 0x66, 0, 0, 1, 1, 0];
        assert!(decode(&stream(&good), 1).is_ok());
        for (at, value) in [
            // The function, a later node, an output past the nodes, no name.
            (6, 2),
            (8, 1),
            (2, 3),
            (0, 0),
            // A node count past the stream.
            (1, u32::MAX),
        ] {
            let mut bad = good;
            bad[at] = value;
            assert!(decode(&stream(&bad), 1).is_err(), "{at}");
        }
        assert!(decode(&stream(&good)[..30], 1).is_err());
    }
}
