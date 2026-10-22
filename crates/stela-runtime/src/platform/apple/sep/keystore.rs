//! The AppleKeyStore service, `sks`, seen from the SEP.
//!
//! The AP side is `AppleKeyStore` in the 26A434 kernel (file offsets).
//!
//! **Frame.** `sep_deliver_msg_gated` 0x2d27158..0x2d27168 sends byte 1 the
//! command (seven bits), byte 2 a sequence number from an atomic counter
//! (0x2d26b14), bytes 6..7 the OOL request length and every other byte zero.
//! `sep_action` 0x2d27d4c..0x2d27da0 takes a frame with byte 1 bit 7 set as
//! the reply. The waiter (0x2d27470..0x2d27490) requires its sequence in
//! byte 2 and reads byte 3 as the status, bytes 4..5 as reply call flags
//! (`_msg_process_ipc_call_flags` 0x2d4b0bc) and bytes 6..7 as the reply's
//! OOL length, which must fit its receive buffer (0x2d2764c). A nonzero
//! status, sign-extended, becomes the request's result (0x2d275e8). In
//! [`Frame`] fields: tag = command, plus [`REPLY`] in a reply; opcode = the
//! sequence; parameter = the status; data = flags | length << 16.
//!
//! **Message.** Each command's `_code_ipc_*` codec (`_code_ipc_set_env`
//! 0x2d43040, `_code_ipc_get_capabilities` 0x2d47c20) writes:
//! - a header (`_ipc_header` 0x2d4b190): a u32 length L, 72 for version 1
//!   and 80 for version 2 (`_ipc_header_effective_size` 0x2d4b060), then L
//!   bytes of `_gen_ipc_header` 0x2d4ae80's record: a 16-byte digest, the
//!   u32 version, a u64 time and u32 flags at message offsets 4, 20, 24 and
//!   32, then further client fields;
//! - the digest, SHA-256 over everything from the version to the message
//!   end, truncated to 16 bytes (`_payload_hash` 0x2d4b7ac with
//!   `ccsha256_di`); flags bit 0 skips it, and bit 1 announces an extended
//!   header in a version-2 reply (`_ipc_msg_process_extended_header`
//!   0x2d5df14);
//! - a u32 **command variant** (`_word` 0x2d5dba4), not a result: startup
//!   uses 0, create uses 4 and copy uses 1 in the AP builders below;
//!   status is the mailbox parameter, sign-extended by the AP;
//! - the command's fields: u64 (`_lword` 0x2d5dd70) and blobs (`_blob`
//!   0x2d5dbfc: a u32 length, the bytes, zero padding to four).
//!
//! A reply decoder consumes exactly the reply's length (0x2d431b0).
//!
//! **Startup.** `init_sep_endpoint` 0x2d27eac sends GET_CAPABILITIES (0x4d,
//! `__ipc_get_capabilities` 0x2d5c954) with u64 1 and an empty blob; the
//! reply carries variant 0, a u64 and a blob. The u64 is the SEP's highest
//! IPC header version: the kernel negotiates the lower of it and 2
//! (0x2d27f9c..0x2d27fac, "negotiated to ipc header theirs:v%llu, ours:v%u")
//! and falls back to version 1 on failure. It then sends SET_ENVIRONMENT
//! (0x2a, `__ipc_set_env` 0x2d3b69c from `set_env` 0x2d2a80c) with u64 1 and
//! a 1036-byte environment: u32 1, the u32 `/defaults` `cpx-encryption-mode`
//! (0 when absent), u32 4 (6 when `set_env`'s Boolean is set), then zeros.
//! Its reply carries variant 0 alone.
//!
//! This SEP parses both header versions, so it reports version 2, and it
//! records the environment, which nothing consumes yet. The command-specific
//! keybag codecs validate the recovered AP layouts, then explicitly refuse
//! their unresolved security semantics. Keybags, class, media and wrapped keys need
//! the keystore lifecycle in docs/research/sep-requirements.md, and no
//! success is invented for them. The failure answer is the status
//! [`FAILURE`], Stela's choice of generic failure: the AP sign-extends
//! 0xff to -1, then maps it to IOReturn 0xe00002bc (0x2d3a324, table
//! 0x725990). No sepOS-specific authorization error is invented.
mod keybag;

use super::{
    endpoint::Service,
    message::Frame,
    transaction::{Answer, Payload, Refusal},
};
use alloc::{vec, vec::Vec};
use sha2::{Digest, Sha256};

/// Stela's catalog ID for the service, after the xART pair.
pub const ID: u8 = 0x12;
pub const NAME: u32 = u32::from_be_bytes(*b"sks\0");
/// `sep_endpoint` 0x2d574a0..0x2d574c8 and 0x2d576c8 size each OOL buffer
/// to the advertised maximum pages. Two 16 KiB pages each way is Stela's
/// choice, not a recovered sepOS capacity.
pub const CAPACITIES: [u8; 4] = [2, 2, 2, 2];

/// Byte 1's reply bit; the command is the low seven bits.
pub const REPLY: u8 = 0x80;
const LENGTH_SHIFT: u32 = 16;
const CALL_FLAGS: u32 = 0xffff;
/// Stela's refusal status: -1, mapped by the AP to generic IOReturn failure.
pub const FAILURE: u8 = 0xff;

pub const GET_CAPABILITIES: u8 = 0x4d;
pub const SET_ENVIRONMENT: u8 = 0x2a;

const LENGTH_BYTES: usize = 4;
const DIGEST_START: usize = 4;
const DIGEST_BYTES: usize = 16;
const VERSION: usize = 20;
const FLAGS: usize = 32;
const HEADER_V1: usize = 72;
const HEADER_V2: usize = 80;
const VARIANT_BYTES: usize = 4;
/// The highest IPC header version this SEP parses.
const HEADER_VERSION: u64 = 2;
/// The u64 the kernel sends with both startup commands; its meaning is
/// not recovered, so no other value is accepted.
const STARTUP_ARGUMENT: u64 = 1;
const ENVIRONMENT_BYTES: usize = 1036;
const ENVIRONMENT_VERSION: u32 = 1;
const ENVIRONMENT_MODES: [u32; 2] = [4, 6];

pub fn service() -> Service {
    Service {
        id: ID,
        name: NAME,
        capacities: CAPACITIES,
    }
}

/// The failure reply to `frame`: its command with the reply bit, its
/// sequence, the [`FAILURE`] status and no OOL bytes.
pub fn failure(frame: Frame) -> Frame {
    Frame {
        tag: frame.tag | REPLY,
        parameter: FAILURE,
        data: 0,
        ..frame
    }
}

/// The environment the kernel set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Environment {
    /// `/defaults` `cpx-encryption-mode`, 0 when the DeviceTree has none.
    pub cpx_encryption_mode: u32,
    /// 4, or 6 when `set_env`'s Boolean is set; its meaning is not
    /// recovered.
    pub mode: u32,
}

#[derive(Default)]
pub struct KeyStore {
    environment: Option<Environment>,
}

impl KeyStore {
    pub fn environment(&self) -> Option<Environment> {
        self.environment
    }

    /// Answer one AP request: read its message, write the reply message
    /// and return the reply frame.
    pub fn request(&mut self, frame: Frame, payload: &mut dyn Payload) -> Result<Frame, Refusal> {
        let refuse = |reason| Refusal::answered(reason, Answer::frame(failure(frame)));
        if frame.tag & REPLY != 0 {
            return Err(Refusal::unanswerable(
                "SEP keystore frame from the AP carries the reply bit",
            ));
        }
        if frame.parameter != 0 || frame.data & CALL_FLAGS != 0 {
            return Err(refuse(
                "SEP keystore request status or call flags are not modeled",
            ));
        }
        let command = frame.tag;
        if !matches!(command, GET_CAPABILITIES | SET_ENVIRONMENT) && !keybag::recognizes(command) {
            return Err(refuse("SEP keystore command is not implemented"));
        }
        let mut bytes = vec![0; (frame.data >> LENGTH_SHIFT) as usize];
        payload.input(&mut bytes).map_err(refuse)?;
        let message = Message::parse(&bytes).map_err(refuse)?;
        let mut fields = message.fields();
        if keybag::recognizes(command) {
            keybag::validate(command, message.variant(), &mut fields).map_err(refuse)?;
            return Err(refuse(keybag::UNIMPLEMENTED));
        }
        if message.variant() != 0 {
            return Err(refuse("SEP keystore startup command variant is not zero"));
        }
        if fields.lword().map_err(refuse)? != STARTUP_ARGUMENT {
            return Err(refuse(
                "SEP keystore startup command argument is not the kernel's",
            ));
        }
        let blob = fields.blob().map_err(refuse)?;
        fields.end().map_err(refuse)?;
        let (reply, environment) = if command == GET_CAPABILITIES {
            if !blob.is_empty() {
                return Err(refuse("SEP keystore capability query carries a blob"));
            }
            let mut fields = HEADER_VERSION.to_le_bytes().to_vec();
            fields.extend_from_slice(&0u32.to_le_bytes());
            (message.reply(&fields), None)
        } else {
            (
                message.reply(&[]),
                Some(Environment::parse(blob).map_err(refuse)?),
            )
        };
        payload.output(&reply).map_err(refuse)?;
        if environment.is_some() {
            self.environment = environment;
        }
        Ok(Frame {
            tag: command | REPLY,
            parameter: 0,
            data: (reply.len() as u32) << LENGTH_SHIFT,
            ..frame
        })
    }
}

impl Environment {
    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != ENVIRONMENT_BYTES {
            return Err("SEP keystore environment is not 1036 bytes");
        }
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        if word(0) != ENVIRONMENT_VERSION
            || !ENVIRONMENT_MODES.contains(&word(8))
            || bytes[12..].iter().any(|&byte| byte != 0)
        {
            return Err("SEP keystore environment is outside the kernel's set_env fields");
        }
        Ok(Self {
            cpx_encryption_mode: word(4),
            mode: word(8),
        })
    }
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, &'static str> {
    bytes
        .get(at..at + 4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .ok_or("SEP keystore IPC message ends inside its header")
}

/// The truncated SHA-256 over everything from the header's version on.
fn digest(message: &[u8]) -> [u8; DIGEST_BYTES] {
    Sha256::digest(&message[VERSION..])[..DIGEST_BYTES]
        .try_into()
        .unwrap()
}

/// A protected IPC message. Variant interpretation belongs to its command.
struct Message<'a> {
    bytes: &'a [u8],
    /// Where the variant starts: after the length and L header bytes.
    body: usize,
}

impl<'a> Message<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, &'static str> {
        let header = u32_at(bytes, 0)? as usize;
        match (u32_at(bytes, VERSION)?, header) {
            (1, HEADER_V1) | (2, HEADER_V2) => {}
            _ => return Err("SEP keystore IPC header is neither 72-byte v1 nor 80-byte v2"),
        }
        let body = LENGTH_BYTES + header;
        if bytes.len() < body + VARIANT_BYTES {
            return Err("SEP keystore IPC message ends inside its header or variant");
        }
        if u32_at(bytes, FLAGS)? != 0 {
            return Err("SEP keystore unprotected or extended IPC headers are not modeled");
        }
        if digest(bytes) != bytes[DIGEST_START..DIGEST_START + DIGEST_BYTES] {
            return Err("SEP keystore IPC message digest does not match");
        }
        Ok(Self { bytes, body })
    }

    fn variant(&self) -> u32 {
        // parse checked that the complete variant word is present.
        u32_at(self.bytes, self.body).unwrap()
    }

    fn fields(&self) -> Fields<'a> {
        Fields {
            bytes: self.bytes,
            at: self.body + VARIANT_BYTES,
        }
    }

    /// The reply: this request's header and variant, then `fields`, with
    /// the digest recomputed over the reply.
    fn reply(&self, fields: &[u8]) -> Vec<u8> {
        let mut reply = self.bytes[..self.body].to_vec();
        reply.extend_from_slice(&self.variant().to_le_bytes());
        reply.extend_from_slice(fields);
        let digest = digest(&reply);
        reply[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&digest);
        reply
    }
}

/// The command fields after the variant, read in order.
struct Fields<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        let field = self
            .at
            .checked_add(count)
            .and_then(|end| self.bytes.get(self.at..end))
            .ok_or("SEP keystore IPC message ends inside a field")?;
        self.at += count;
        Ok(field)
    }

    fn word(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn lword(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn blob(&mut self) -> Result<&'a [u8], &'static str> {
        let length = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        let padded = length
            .checked_next_multiple_of(4)
            .ok_or("SEP keystore IPC blob length overflows")?;
        Ok(&self.take(padded)?[..length])
    }

    fn end(&self) -> Result<(), &'static str> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err("SEP keystore IPC message has bytes after its fields")
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    struct Buffers {
        input: Vec<u8>,
        output: Vec<u8>,
    }

    impl Payload for Buffers {
        fn input(&mut self, bytes: &mut [u8]) -> Result<(), &'static str> {
            let source = self.input.get(..bytes.len()).ok_or("short input")?;
            bytes.copy_from_slice(source);
            Ok(())
        }
        fn output(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
            self.output = bytes.to_vec();
            Ok(())
        }
    }

    /// A startup request as the kernel codecs lay it out: header, variant 0,
    /// u64 argument and one blob, protected by the truncated digest.
    pub(crate) fn message(version: u32, flags: u32, argument: u64, blob: &[u8]) -> Vec<u8> {
        let header = if version == 1 { HEADER_V1 } else { HEADER_V2 };
        let mut bytes = vec![0; LENGTH_BYTES + header];
        bytes[..4].copy_from_slice(&(header as u32).to_le_bytes());
        bytes[VERSION..VERSION + 4].copy_from_slice(&version.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x1234_5678u64.to_le_bytes());
        bytes[FLAGS..FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&argument.to_le_bytes());
        bytes.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        bytes.extend_from_slice(blob);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        let digest = digest(&bytes);
        bytes[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&digest);
        bytes
    }

    fn frame(command: u8, sequence: u8, length: usize) -> Frame {
        Frame {
            service: ID,
            tag: command,
            opcode: sequence,
            parameter: 0,
            data: (length as u32) << LENGTH_SHIFT,
        }
    }

    fn environment(cpx: u32, mode: u32) -> Vec<u8> {
        let mut bytes = vec![0; ENVIRONMENT_BYTES];
        bytes[..4].copy_from_slice(&1u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&cpx.to_le_bytes());
        bytes[8..12].copy_from_slice(&mode.to_le_bytes());
        bytes
    }

    fn ask(
        keystore: &mut KeyStore,
        frame: Frame,
        input: Vec<u8>,
    ) -> (Result<Frame, Refusal>, Vec<u8>) {
        let mut buffers = Buffers {
            input,
            output: Vec::new(),
        };
        (keystore.request(frame, &mut buffers), buffers.output)
    }

    #[test]
    fn capabilities_report_header_version_two_in_the_requests_header() {
        for (version, length) in [(1, 92), (2, 100)] {
            let request = message(version, 0, 1, &[]);
            let (reply, output) = ask(
                &mut KeyStore::default(),
                frame(GET_CAPABILITIES, 9, request.len()),
                request.clone(),
            );
            assert_eq!(
                reply.unwrap(),
                Frame {
                    tag: GET_CAPABILITIES | REPLY,
                    data: (length as u32) << LENGTH_SHIFT,
                    ..frame(GET_CAPABILITIES, 9, 0)
                }
            );
            assert_eq!(output.len(), length);
            // The kernel's decoder accepts it: same header, valid digest,
            // variant 0, the version as u64 and an empty blob.
            let parsed = Message::parse(&output).unwrap();
            assert_eq!(output[..DIGEST_START], request[..DIGEST_START]);
            assert_eq!(output[VERSION..parsed.body], request[VERSION..parsed.body]);
            let mut fields = parsed.fields();
            assert_eq!(fields.lword(), Ok(2));
            assert_eq!(fields.blob(), Ok(&[][..]));
            assert_eq!(fields.end(), Ok(()));
        }
    }

    #[test]
    fn the_environment_is_recorded_and_answered_with_the_result_alone() {
        let mut keystore = KeyStore::default();
        let request = message(2, 0, 1, &environment(3, 4));
        assert_eq!(request.len(), 84 + 4 + 8 + 4 + ENVIRONMENT_BYTES);
        let (reply, output) = ask(
            &mut keystore,
            frame(SET_ENVIRONMENT, 1, request.len()),
            request,
        );
        assert_eq!(reply.unwrap().data >> LENGTH_SHIFT, 88);
        assert_eq!(output.len(), 88);
        assert!(Message::parse(&output).is_ok());
        assert_eq!(
            keystore.environment(),
            Some(Environment {
                cpx_encryption_mode: 3,
                mode: 4,
            })
        );
        // Mode 6 replaces it.
        let request = message(2, 0, 1, &environment(0, 6));
        ask(
            &mut keystore,
            frame(SET_ENVIRONMENT, 2, request.len()),
            request,
        )
        .0
        .unwrap();
        assert_eq!(keystore.environment().unwrap().mode, 6);
    }

    #[test]
    fn decoded_keybags_and_malformed_bodies_never_publish_success_or_change_environment() {
        let mut keystore = KeyStore::default();
        let env = message(2, 0, 1, &environment(3, 4));
        ask(&mut keystore, frame(SET_ENVIRONMENT, 1, env.len()), env)
            .0
            .unwrap();
        let before = keystore.environment();
        for command in [
            keybag::CREATE,
            keybag::COPY,
            keybag::LOAD,
            keybag::UNLOAD,
            keybag::UUID,
        ] {
            let (variant, body) = keybag::tests::body(command);
            for version in [1, 2] {
                let mut request = message(version, 0, 1, &[]);
                let start = Message::parse(&request).unwrap().body;
                request.truncate(start);
                request.extend_from_slice(&variant.to_le_bytes());
                request.extend_from_slice(&body);
                let hash = digest(&request);
                request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
                // A complete source-shaped request reaches the semantic
                // refusal, including create/copy's nonzero variants.
                let (result, output) = ask(
                    &mut keystore,
                    frame(command, 42, request.len()),
                    request.clone(),
                );
                let refusal = result.unwrap_err();
                assert_eq!(refusal.reason, keybag::UNIMPLEMENTED);
                assert_eq!(
                    refusal.answer.unwrap().frame,
                    failure(frame(command, 42, request.len()))
                );
                assert!(output.is_empty());
                assert_eq!(keystore.environment(), before);
                // A valid message digest does not authorize a truncated
                // body, a trailer or a different variant.
                for change in 0..3 {
                    let mut bad = request.clone();
                    match change {
                        0 => {
                            bad.pop();
                        }
                        1 => bad.extend_from_slice(&[0; 4]),
                        _ => bad[start..start + 4].copy_from_slice(&(variant + 1).to_le_bytes()),
                    }
                    let hash = digest(&bad);
                    bad[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
                    let (result, output) = ask(&mut keystore, frame(command, 42, bad.len()), bad);
                    assert_ne!(result.unwrap_err().reason, keybag::UNIMPLEMENTED);
                    assert!(output.is_empty());
                    assert_eq!(keystore.environment(), before);
                }
            }
        }
        let mut request = message(2, 0, 1, &[]);
        request[84..88].copy_from_slice(&1u32.to_le_bytes());
        let hash = digest(&request);
        request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
        let (result, output) = ask(
            &mut keystore,
            frame(GET_CAPABILITIES, 1, request.len()),
            request,
        );
        assert_eq!(
            result.unwrap_err().reason,
            "SEP keystore startup command variant is not zero"
        );
        assert!(output.is_empty());
        assert_eq!(keystore.environment(), before);
    }

    #[test]
    fn other_commands_and_malformed_messages_refuse_with_the_failure_status() {
        let good = message(1, 0, 1, &[]);
        let mut tampered = good.clone();
        tampered[30] ^= 1;
        let mut bad_environment = environment(0, 5);
        let mut cases = vec![
            // Keybag creation and the rest are not implemented.
            (frame(0x01, 1, good.len()), good.clone()),
            (frame(GET_CAPABILITIES, 1, good.len()), tampered),
            (
                frame(GET_CAPABILITIES, 1, good.len() - 4),
                good[..good.len() - 4].to_vec(),
            ),
            (
                frame(GET_CAPABILITIES, 1, good.len()),
                message(1, 1, 1, &[]),
            ),
            (
                frame(GET_CAPABILITIES, 1, good.len()),
                message(1, 0, 2, &[]),
            ),
            (frame(GET_CAPABILITIES, 1, good.len() + 4), {
                let mut long = good.clone();
                long.extend_from_slice(&[0; 4]);
                long
            }),
        ];
        let request = message(1, 0, 1, &bad_environment);
        cases.push((frame(SET_ENVIRONMENT, 1, request.len()), request));
        bad_environment = environment(0, 4);
        bad_environment[100] = 1;
        let request = message(1, 0, 1, &bad_environment);
        cases.push((frame(SET_ENVIRONMENT, 1, request.len()), request));
        let mut flagged = frame(GET_CAPABILITIES, 1, good.len());
        flagged.data |= 1;
        cases.push((flagged, good.clone()));
        for (request, input) in cases {
            let mut keystore = KeyStore::default();
            let (reply, output) = ask(&mut keystore, request, input);
            let refusal = reply.unwrap_err();
            let answer = refusal.answer.unwrap().frame;
            assert_eq!(
                (answer.tag, answer.opcode, answer.parameter, answer.data),
                (request.tag | REPLY, 1, FAILURE, 0),
                "{}",
                refusal.reason
            );
            assert!(output.is_empty());
            assert!(keystore.environment().is_none());
        }
        // A frame already carrying the reply bit is not a request to answer.
        let (reply, _) = ask(
            &mut KeyStore::default(),
            frame(GET_CAPABILITIES | REPLY, 1, good.len()),
            good,
        );
        assert_eq!(reply.unwrap_err().answer, None);
    }
}
