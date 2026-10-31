//! The credential manager service `scrd`, which refuses every command.
//!
//! **Wire.** 26A434 kernel VM addresses. `AppleCredentialManager` finds the
//! `sep-endpoint,scrd` nub (`ACMKernelUtils::waitForSEPEndpoint`
//! 0xfffffe00092e3528, 5 s per client) and registers one 16 KiB buffer each
//! way (`getSEPEndpoint` 0xfffffe00092e1568). `handleSEPMessage`
//! 0xfffffe00092e092c asserts that a reply names `SCRD_ENDPOINT`, 10.
//! `sendSEPCommand` 0xfffffe00092deda8 sends the frame's tag as its request,
//! and the opcode and parameter as the little-endian input length. Request
//! [`PAYLOAD`] leads its input with an `SCRDRequestPayload_v1`: a version
//! byte, a u16 size and at +4 the u32 request ID. A reply echoes the request
//! in its tag, carries the output length in the same two bytes and its
//! status in the data word. Request [`PAYLOAD`]'s output must lead with an
//! `SCRDResponsePayloadHead`: a nonzero version, a u16 size and the request
//! ID, at least [`HEAD_BYTES`] in all, or the kernel logs an assertion.
//!
//! **Service.** The commands' bodies are not recovered, so each is answered
//! with [`UNSUPPORTED`]. A client gets its error at once where an absent
//! service would cost it the 5 s nub wait, and a client that needs a
//! credential, such as a passcode check, fails. The refusal is reported.
use super::{
    endpoint::Service,
    message::Frame,
    transaction::{Answer, Payload, Refusal},
};
use alloc::vec::Vec;
use stela_contracts::refuse;

/// `SCRD_ENDPOINT`.
pub const ID: u8 = 10;
/// `kIOReturnUnsupported`.
const UNSUPPORTED: u32 = 0xe000_02c7;
/// The request whose buffers carry SCRD payloads.
const PAYLOAD: u8 = 4;
/// `SCRDRequestPayload_v1` through its request ID.
const REQUEST_ID_END: usize = 8;
/// `sizeof(SCRDResponsePayloadHead)` as `sendSEPCommand` requires it.
const HEAD_BYTES: usize = 12;
/// The version of `SCRDResponsePayload_v2`.
const RESPONSE_VERSION: u8 = 2;

pub fn service() -> Service {
    Service {
        id: ID,
        name: u32::from_be_bytes(*b"scrd"),
        capacities: [1, 1, 1, 1],
    }
}

/// The failure reply to `frame`, with `length` output bytes.
fn reply(frame: Frame, length: u16) -> Frame {
    let [opcode, parameter] = length.to_le_bytes();
    Frame {
        service: ID,
        tag: frame.tag,
        opcode,
        parameter,
        data: UNSUPPORTED,
    }
}

/// The answer to a request refused before its buffers were read.
pub fn failure(frame: Frame) -> Frame {
    reply(frame, 0)
}

/// Refuse `frame`, with the response head its input asks for.
pub fn request(frame: Frame, payload: &mut dyn Payload) -> Refusal {
    let mut request = [0; REQUEST_ID_END];
    let answer = if frame.tag == PAYLOAD && payload.input(&mut request).is_ok() {
        Answer {
            frame: reply(frame, HEAD_BYTES as u16),
            output: head(&request),
        }
    } else {
        Answer::frame(failure(frame))
    };
    Refusal::answered(
        refuse!("SEP credential manager commands are not implemented"),
        answer,
    )
}

fn head(request: &[u8; REQUEST_ID_END]) -> Vec<u8> {
    let mut head = alloc::vec![0; HEAD_BYTES];
    head[0] = RESPONSE_VERSION;
    head[2..4].copy_from_slice(&(HEAD_BYTES as u16).to_le_bytes());
    head[4..8].copy_from_slice(&request[4..8]);
    head
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Result;

    struct Buffers {
        input: Vec<u8>,
        output: Vec<u8>,
    }

    impl Payload for Buffers {
        fn input(&mut self, bytes: &mut [u8]) -> Result<()> {
            bytes.copy_from_slice(&self.input[..bytes.len()]);
            Ok(())
        }
        fn output(&mut self, bytes: &[u8]) -> Result<()> {
            self.output.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn frame(tag: u8) -> Frame {
        Frame {
            service: ID,
            tag,
            opcode: 28,
            parameter: 0,
            data: 0,
        }
    }

    #[test]
    fn a_payload_request_gets_a_failure_with_the_head_naming_its_id() {
        let mut buffers = Buffers {
            input: alloc::vec![1, 0, 28, 0, 0x78, 0x56, 0x34, 0x12],
            output: Vec::new(),
        };
        let answer = request(frame(PAYLOAD), &mut buffers).answer.unwrap();
        assert_eq!(
            answer.output,
            [2, 0, 12, 0, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]
        );
        assert_eq!(
            answer.frame,
            Frame {
                service: 10,
                tag: PAYLOAD,
                opcode: 12,
                parameter: 0,
                data: UNSUPPORTED,
            }
        );
    }

    #[test]
    fn another_request_gets_the_failure_alone() {
        let mut buffers = Buffers {
            input: Vec::new(),
            output: Vec::new(),
        };
        let answer = request(frame(1), &mut buffers).answer.unwrap();
        assert!(answer.output.is_empty());
        assert_eq!(answer.frame, failure(frame(1)));
    }

    #[test]
    fn the_service_is_the_kernels_endpoint_with_its_16_kib_buffers() {
        let scrd = service();
        assert_eq!(scrd.id, 10);
        assert!(scrd.accepts(true, 0x4000, 0x4000));
        assert!(scrd.accepts(false, 0x4000, 0x4000));
        assert!(!scrd.accepts(true, 0x8000, 0x4000));
    }
}
