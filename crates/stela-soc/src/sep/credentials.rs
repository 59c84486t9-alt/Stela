//! The credential manager service `scrd`, which serves two commands and
//! refuses the rest.
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
//! The bytes after the head are the command's output
//! (`sendSEPCommand`+0x4e0..+0x5c0).
//!
//! **Commands.** An ACM command follows the 28-byte request payload: u32
//! `SCRD`, the command byte and three bytes, then its input
//! (`LibCall_BuildCommand` 0xfffffe00092e8c30).
//! - [`INITIALIZE`] (`performSCRDInitialization` 0xfffffe00092debc8) has no
//!   input and wants no output. A status of zero is the whole answer.
//! - [`GET_ENVIRONMENT_VARIABLE`] (`LibCall_ACMGetEnvironmentVariable`
//!   0xfffffe00092ed958) sends a u32 variable. Only [`LOCKDOWN_MODE`] is
//!   served: one byte (`LDMCheckParity` 0xfffffe000986b758), which is
//!   [`LOCKDOWN_OFF`], so enabling Lockdown Mode does not survive a reboot.
//!
//! **Service.** No other command's body is recovered, so each is answered
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
/// `SCRDRequestPayload_v1`, whose request ID ends at byte 8.
const REQUEST_BYTES: usize = 28;
/// An ACM command's first word, `SCRD` in little-endian order.
const COMMAND_MAGIC: &[u8; 4] = b"DRCS";
/// An ACM command's bytes before its input.
const COMMAND_BYTES: usize = 8;
/// The largest served request: a u32 of input.
const LARGEST_REQUEST: usize = REQUEST_BYTES + COMMAND_BYTES + 4;
const INITIALIZE: u8 = 10;
const GET_ENVIRONMENT_VARIABLE: u8 = 25;
/// The environment variable `LDMCheckParity` compares with NVRAM.
const LOCKDOWN_MODE: u32 = 41;
const LOCKDOWN_OFF: u8 = 0;
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

/// The reply to `frame`, with `length` output bytes.
fn reply(frame: Frame, length: u16, status: u32) -> Frame {
    let [opcode, parameter] = length.to_le_bytes();
    Frame {
        service: ID,
        tag: frame.tag,
        opcode,
        parameter,
        data: status,
    }
}

/// The answer to a request refused before its buffers were read.
pub fn failure(frame: Frame) -> Frame {
    reply(frame, 0, UNSUPPORTED)
}

/// Serve `frame`, or refuse it with the response head its input asks for.
pub fn request(frame: Frame, payload: &mut dyn Payload) -> Result<Frame, Refusal> {
    let mut request = [0; LARGEST_REQUEST];
    if frame.tag != PAYLOAD || payload.input(&mut request).is_err() {
        return Err(refused(Answer::frame(failure(frame))));
    }
    let mut output = head(&request);
    let Some(served) = output_of(frame, &request) else {
        return Err(refused(Answer {
            frame: reply(frame, HEAD_BYTES as u16, UNSUPPORTED),
            output,
        }));
    };
    output.extend_from_slice(served);
    payload
        .output(&output)
        .map_err(|reason| Refusal::answered(reason, Answer::frame(failure(frame))))?;
    Ok(reply(frame, output.len() as u16, 0))
}

fn refused(answer: Answer) -> Refusal {
    Refusal::answered(
        refuse!("SEP credential manager commands are not implemented"),
        answer,
    )
}

/// The output of a served command, by the input length `frame` names.
fn output_of(frame: Frame, request: &[u8; LARGEST_REQUEST]) -> Option<&'static [u8]> {
    let command = &request[REQUEST_BYTES..];
    if &command[..COMMAND_MAGIC.len()] != COMMAND_MAGIC {
        return None;
    }
    let length = usize::from(u16::from_le_bytes([frame.opcode, frame.parameter]));
    let input = length.checked_sub(REQUEST_BYTES + COMMAND_BYTES)?;
    match (command[COMMAND_MAGIC.len()], input) {
        (INITIALIZE, 0) => Some(&[]),
        (GET_ENVIRONMENT_VARIABLE, 4)
            if command[COMMAND_BYTES..] == LOCKDOWN_MODE.to_le_bytes() =>
        {
            Some(&[LOCKDOWN_OFF])
        }
        _ => None,
    }
}

fn head(request: &[u8; LARGEST_REQUEST]) -> Vec<u8> {
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

    fn frame(tag: u8, length: u8) -> Frame {
        Frame {
            service: ID,
            tag,
            opcode: length,
            parameter: 0,
            data: 0,
        }
    }

    /// A request numbered 0x12345678 for `command` with `input`.
    fn buffers(command: u8, input: &[u8]) -> Buffers {
        let mut bytes = alloc::vec![0; LARGEST_REQUEST];
        bytes[..8].copy_from_slice(&[1, 0, 28, 0, 0x78, 0x56, 0x34, 0x12]);
        bytes[28..32].copy_from_slice(COMMAND_MAGIC);
        bytes[32] = command;
        bytes[36..36 + input.len()].copy_from_slice(input);
        Buffers {
            input: bytes,
            output: Vec::new(),
        }
    }

    #[test]
    fn initialization_succeeds_with_the_head_alone() {
        let mut buffers = buffers(INITIALIZE, &[]);
        let answer = request(frame(PAYLOAD, 36), &mut buffers).unwrap();
        assert_eq!(answer, reply(frame(PAYLOAD, 36), 12, 0));
        assert_eq!(
            buffers.output,
            [2, 0, 12, 0, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]
        );
    }

    #[test]
    fn lockdown_mode_reads_as_off_after_the_head() {
        let mut buffers = buffers(GET_ENVIRONMENT_VARIABLE, &LOCKDOWN_MODE.to_le_bytes());
        let answer = request(frame(PAYLOAD, 40), &mut buffers).unwrap();
        assert_eq!(answer, reply(frame(PAYLOAD, 40), 13, 0));
        assert_eq!(buffers.output.len(), 13);
        assert_eq!(buffers.output[12], LOCKDOWN_OFF);
    }

    #[test]
    fn another_variable_or_a_foreign_command_is_refused() {
        let mut other = buffers(GET_ENVIRONMENT_VARIABLE, &2u32.to_le_bytes());
        let mut foreign = buffers(INITIALIZE, &[]);
        foreign.input[28] = 0;
        for (buffers, length) in [(&mut other, 40), (&mut foreign, 36)] {
            let refusal = request(frame(PAYLOAD, length), buffers).unwrap_err();
            assert_eq!(refusal.answer.unwrap().frame.data, UNSUPPORTED);
            assert!(buffers.output.is_empty());
        }
    }

    #[test]
    fn a_payload_request_gets_a_failure_with_the_head_naming_its_id() {
        let mut buffers = buffers(22, &[2]);
        let answer = request(frame(PAYLOAD, 37), &mut buffers)
            .unwrap_err()
            .answer
            .unwrap();
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
        let answer = request(frame(1, 28), &mut buffers)
            .unwrap_err()
            .answer
            .unwrap();
        assert!(answer.output.is_empty());
        assert_eq!(answer.frame, failure(frame(1, 28)));
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
