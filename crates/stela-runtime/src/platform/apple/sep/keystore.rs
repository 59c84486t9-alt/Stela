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
mod reference_key;
mod system_key;

use super::{
    endpoint::Service,
    message::Frame,
    observe::Journal,
    transaction::{Answer, Payload, Refusal},
};
use alloc::{string::String, vec, vec::Vec};
use sha2::Digest;
use stela_crypto::Sha256;
use zeroize::Zeroizing;

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
    system_keys: Option<system_key::SystemKeys>,
    diagnostics: Journal,
}

impl KeyStore {
    pub(super) fn with_system_keys(root: Zeroizing<[u8; 32]>) -> Self {
        Self {
            environment: None,
            system_keys: Some(system_key::SystemKeys::new(root)),
            diagnostics: Journal::default(),
        }
    }

    #[cfg(test)]
    pub fn environment(&self) -> Option<Environment> {
        self.environment
    }

    /// Drain bounded, value-free metadata for unsupported system-key requests.
    /// Independent of opt-in raw traffic observation.
    pub(super) fn diagnostics(&mut self) -> impl Iterator<Item = String> + '_ {
        self.diagnostics.drain()
    }

    /// Answer one AP request: read its message, write the reply message
    /// and return the reply frame.
    pub fn request(
        &mut self,
        frame: Frame,
        payload: &mut dyn Payload,
        entropy: &mut dyn super::Entropy,
    ) -> Result<Frame, Refusal> {
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
        if !matches!(
            command,
            GET_CAPABILITIES | SET_ENVIRONMENT | system_key::PERFORM_OPERATION
        ) && !keybag::recognizes(command)
        {
            return Err(refuse("SEP keystore command is not implemented"));
        }
        let mut bytes = vec![0; (frame.data >> LENGTH_SHIFT) as usize];
        payload.input(&mut bytes).map_err(refuse)?;
        let message = Message::parse(&bytes).map_err(refuse)?;
        let mut fields = message.fields();
        if command == system_key::PERFORM_OPERATION {
            let operation = match system_key::operation(message.variant(), &mut fields) {
                Ok(operation) => operation,
                Err(reason) => {
                    self.diagnostics.record(system_key::diagnostic(
                        message.variant(),
                        &mut message.fields(),
                    ));
                    return Err(refuse(reason));
                }
            };
            let keys = self
                .system_keys
                .as_mut()
                .ok_or_else(|| refuse("SEP keystore requires provisioned machine roots"))?;
            let public = match keys.perform(operation, entropy) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    self.diagnostics.record(system_key::diagnostic(
                        message.variant(),
                        &mut message.fields(),
                    ));
                    return Err(refuse(reason));
                }
            };
            let mut reply_fields = (public.len() as u32).to_le_bytes().to_vec();
            reply_fields.extend_from_slice(&public);
            reply_fields.resize(reply_fields.len().next_multiple_of(4), 0);
            let reply = message.reply(&reply_fields);
            payload.output(&reply).map_err(refuse)?;
            return Ok(Frame {
                tag: command | REPLY,
                parameter: 0,
                data: (reply.len() as u32) << LENGTH_SHIFT,
                ..frame
            });
        }
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

    // Authored encoding of the source-recovered public SIK dictionary:
    // SET { SEQUENCE { "skg", 1 }, { "skt", 1 }, { "o", "oskgp" } }.
    /// As run12's restore ramdisk sent it: ascending keys `o`, `skg`, `skt`.
    pub(crate) const SIK_QUERY: &[u8] = b"\x31\x20\x30\x0a\x0c\x01o\x0c\x05oskgp\x30\x08\x0c\x03skg\x02\x01\x01\x30\x08\x0c\x03skt\x02\x01\x01";
    /// The same pairs in DER's encoded-pair order, which the AP never sends.
    const DER_ORDER_QUERY: &[u8] = b"\x31\x20\x30\x08\x0c\x03skg\x02\x01\x01\x30\x08\x0c\x03skt\x02\x01\x01\x30\x0a\x0c\x01o\x0c\x05oskgp";

    pub(crate) fn system_request(version: u32, query: &[u8]) -> Vec<u8> {
        system_request_with_operation(version, 2, query)
    }

    pub(crate) fn system_request_with_operation(
        version: u32,
        operation: u32,
        query: &[u8],
    ) -> Vec<u8> {
        let mut request = message(version, 0, 1, &[]);
        let body = Message::parse(&request).unwrap().body;
        request.truncate(body);
        request.extend_from_slice(&0u32.to_le_bytes()); // variant
        request.extend_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
        request.extend_from_slice(&u32::MAX.to_le_bytes());
        request.extend_from_slice(&operation.to_le_bytes());
        request.extend_from_slice(&(query.len() as u32).to_le_bytes());
        request.extend_from_slice(query);
        request.resize(request.len().next_multiple_of(4), 0);
        let hash = digest(&request);
        request[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
        request
    }

    // Authored from libFDR arm64e 8ae18..8aff8, its resolved outlined
    // helpers and the caller at 1630..1974. Ascending UTF8 key names:
    // {bc: 13, kt: 5, o: "oc", rko: 1}; no captured secrets or Apple bytes.
    const REFERENCE_CREATE: &[u8] = b"\x31\x25\x30\x07\x0c\x02bc\x02\x01\x0d\x30\x07\x0c\x02kt\x02\x01\x05\x30\x07\x0c\x01o\x0c\x02oc\x30\x08\x0c\x03rko\x02\x01\x01";

    #[test]
    fn source_shaped_constructor_returns_reopenable_keys_and_advances_to_attestation() {
        for version in [1, 2] {
            for kind in [4, 5] {
                let root = Zeroizing::new([1; 32]);
                let mut keystore = KeyStore::with_system_keys(root.clone());
                let mut query = REFERENCE_CREATE.to_vec();
                query[19] = kind;
                let request = system_request_with_operation(version, 0, &query);
                let sent = frame(system_key::PERFORM_OPERATION, 26, request.len());
                let (reply, output) =
                    ask_with_entropy(&mut keystore, sent, request, &mut |bytes: &mut [u8]| {
                        bytes.fill(2);
                        Ok(())
                    });
                let reply = reply.unwrap();
                assert_eq!(reply.parameter, 0);
                assert_eq!(reply.opcode, sent.opcode);
                assert_eq!(reply.data as usize >> LENGTH_SHIFT, output.len());
                let parsed = Message::parse(&output).unwrap();
                assert_eq!(parsed.variant(), 0);
                let mut fields = parsed.fields();
                let blob = fields.blob().unwrap();
                fields.end().unwrap();
                reference_key::ReferenceKey::open(&root, blob).unwrap();
                assert_eq!(keystore.diagnostics().count(), 0);
                // Source helper 5c61c inserts the ENTIRE constructor reply
                // as rk, not just its nested public metadata dictionary.
                let params = reference_key::tests::attestation_parameters(blob);
                let request = system_request_with_operation(version, 0, &params);
                let sent = frame(system_key::PERFORM_OPERATION, 27, request.len());
                let (reply, output) = ask(&mut keystore, sent, request);
                assert_eq!(reply.unwrap().parameter, 0);
                let parsed = Message::parse(&output).unwrap();
                let mut fields = parsed.fields();
                let signature = p256::ecdsa::Signature::from_der(fields.blob().unwrap()).unwrap();
                fields.end().unwrap();
                let key = reference_key::ReferenceKey::open(&root, blob).unwrap();
                let public = keystore
                    .system_keys
                    .as_mut()
                    .unwrap()
                    .public(system_key::PublicQuery::Identity)
                    .unwrap();
                let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(public).unwrap();
                use p256::ecdsa::signature::Verifier;
                verifier.verify(&key.public(), &signature).unwrap();
                let mut wrong = key.public();
                wrong[10] ^= 1;
                assert!(verifier.verify(&wrong, &signature).is_err());
                assert_eq!(keystore.diagnostics().count(), 0);
                // A fresh owner with the same machine roots signs the same
                // reference. The signature never authorizes another root.
                let params = reference_key::tests::attestation_parameters(blob);
                let mut reopened = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
                let request = system_request_with_operation(version, 0, &params);
                let (reply, repeated) = ask(
                    &mut reopened,
                    frame(system_key::PERFORM_OPERATION, 28, request.len()),
                    request,
                );
                assert_eq!(reply.unwrap().parameter, 0);
                assert_eq!(output, repeated);
                let mut other = KeyStore::with_system_keys(Zeroizing::new([2; 32]));
                let request = system_request_with_operation(version, 0, &params);
                let (reply, output) = ask(
                    &mut other,
                    frame(system_key::PERFORM_OPERATION, 29, request.len()),
                    request,
                );
                assert_eq!(
                    reply.unwrap_err().reason,
                    "SEP reference-key authentication failed"
                );
                assert!(output.is_empty());
            }
        }
    }

    #[test]
    fn reference_signing_roundtrips_original_dictionary_in_both_ipc_versions() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        use sha2::Digest;
        for version in [1, 2] {
            let root = Zeroizing::new([1; 32]);
            let blob = reference_key::ReferenceKey::create(&root, 5, &mut |bytes: &mut [u8]| {
                bytes.fill(2);
                Ok(())
            })
            .unwrap();
            let digest: [u8; 32] = sha2::Sha256::digest(b"CSR data to be hashed by libFDR").into();
            let params = reference_key::tests::signing_parameters(&blob, &digest);
            let request = system_request_with_operation(version, 0, &params);
            let sent = frame(system_key::PERFORM_OPERATION, 30, request.len());
            let mut keystore = KeyStore::with_system_keys(root.clone());
            let (reply, output) = ask(&mut keystore, sent, request);
            assert_eq!(reply.unwrap().parameter, 0);
            let message = Message::parse(&output).unwrap();
            let mut fields = message.fields();
            let result = fields.blob().unwrap();
            fields.end().unwrap();
            let mut outer = crate::platform::apple::sep::der::Cursor(result);
            let signature = p256::ecdsa::Signature::from_der(outer.take(4).unwrap().value).unwrap();
            outer.end().unwrap();
            let key = reference_key::ReferenceKey::open(&root, &blob).unwrap();
            let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public()).unwrap();
            verifying.verify_prehash(&digest, &signature).unwrap();
            assert_eq!(keystore.diagnostics().count(), 0);
            let mut wrong_root = KeyStore::with_system_keys(Zeroizing::new([2; 32]));
            let params = reference_key::tests::signing_parameters(&blob, &digest);
            let request = system_request_with_operation(version, 0, &params);
            let (reply, output) = ask(
                &mut wrong_root,
                frame(system_key::PERFORM_OPERATION, 31, request.len()),
                request,
            );
            assert_eq!(
                reply.unwrap_err().reason,
                "SEP reference-key authentication failed"
            );
            assert!(output.is_empty());
            for bad_digest in [&digest[..31], &digest[..0]] {
                let params = reference_key::tests::signing_parameters(&blob, bad_digest);
                let request = system_request_with_operation(version, 0, &params);
                let (reply, output) = ask(
                    &mut keystore,
                    frame(system_key::PERFORM_OPERATION, 32, request.len()),
                    request,
                );
                assert_eq!(
                    reply.unwrap_err().reason,
                    "SEP reference-key digest must be SHA-256 sized"
                );
                assert!(output.is_empty());
            }
        }
    }

    #[test]
    fn reference_creation_requires_entropy_without_mutating_identity() {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let request = system_request(2, SIK_QUERY);
        let (_, identity_before) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 19, request.len()),
            request.clone(),
        );
        for version in [1, 2] {
            let create = system_request_with_operation(version, 0, REFERENCE_CREATE);
            let sent = frame(system_key::PERFORM_OPERATION, 23, create.len());
            let (reply, output) = ask(&mut keystore, sent, create);
            let refusal = reply.unwrap_err();
            assert_eq!(refusal.reason, "test entropy unavailable");
            assert_eq!(refusal.answer.unwrap().frame, failure(sent));
            assert!(output.is_empty());
            assert!(keystore.environment().is_none());
            let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
            assert_eq!(diagnostics.len(), 1);
            assert!(diagnostics[0].contains("parameter_operation=oc"));
            assert!(diagnostics[0].contains("reference_key_type=Some(5)"));
            assert!(diagnostics[0].contains("keys=bc,kt,o,rko parsed=true"));
            assert!(
                diagnostics[0]
                    .contains("reference_key_class=Some(13) reference_key_options=Some(1)")
            );
        }
        let (_, identity_after) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 19, request.len()),
            request,
        );
        assert_eq!(identity_after, identity_before);
        // Generation cannot proceed without actual provisioned machine roots.
        let create = system_request_with_operation(2, 0, REFERENCE_CREATE);
        let (reply, output) = ask(
            &mut KeyStore::default(),
            frame(system_key::PERFORM_OPERATION, 24, create.len()),
            create,
        );
        assert_eq!(
            reply.unwrap_err().reason,
            "SEP keystore requires provisioned machine roots"
        );
        assert!(output.is_empty());
    }

    #[test]
    fn creation_rejects_bad_dictionary_and_public_query_transport_before_semantics() {
        let mut bad = vec![REFERENCE_CREATE[..REFERENCE_CREATE.len() - 1].to_vec()];
        let mut duplicate = REFERENCE_CREATE.to_vec();
        duplicate[15..17].copy_from_slice(b"bc");
        bad.push(duplicate);
        let mut unsorted = REFERENCE_CREATE.to_vec();
        unsorted[2..11].copy_from_slice(&REFERENCE_CREATE[11..20]);
        unsorted[11..20].copy_from_slice(&REFERENCE_CREATE[2..11]);
        bad.push(unsorted);
        let mut missing = REFERENCE_CREATE[..29].to_vec();
        missing[1] = 27;
        bad.push(missing);
        for index in [10, 19, 38] {
            // negative class/type/options are not u32
            let mut negative = REFERENCE_CREATE.to_vec();
            negative[index] = 0x80;
            bad.push(negative);
        }
        for (index, value) in [(10, 12), (19, 7), (38, 2)] {
            let mut unsupported = REFERENCE_CREATE.to_vec();
            unsupported[index] = value;
            bad.push(unsupported);
        }
        let mut mixed = REFERENCE_CREATE.to_vec();
        mixed[1] += 10;
        mixed.extend_from_slice(&SIK_QUERY[24..]); // public-only skt
        bad.push(mixed);
        let mut requests: Vec<_> = bad
            .iter()
            .map(|q| system_request_with_operation(2, 0, q))
            .collect();
        // The read-only kernel SIK transport cannot authorize creation.
        requests.push(system_request(2, REFERENCE_CREATE));
        let mut forged = system_request_with_operation(2, 0, REFERENCE_CREATE);
        forged[DIGEST_START] ^= 1;
        requests.push(forged);
        for request in requests {
            let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
            let sent = frame(system_key::PERFORM_OPERATION, 25, request.len());
            let (reply, output) = ask(&mut keystore, sent, request);
            let refusal = reply.unwrap_err();
            assert_ne!(refusal.reason, "test entropy unavailable");
            assert_eq!(refusal.answer.unwrap().frame, failure(sent));
            assert!(output.is_empty());
            assert!(keystore.environment().is_none());
        }
    }

    #[test]
    fn userspace_and_kernel_public_queries_return_the_same_identity() {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let mut expected = None;
        for version in [1, 2] {
            for operation in [0, 2] {
                let request = system_request_with_operation(version, operation, SIK_QUERY);
                let (reply, output) = ask(
                    &mut keystore,
                    frame(system_key::PERFORM_OPERATION, 19, request.len()),
                    request,
                );
                assert_eq!(reply.unwrap().parameter, 0);
                let message = Message::parse(&output).unwrap();
                let mut fields = message.fields();
                let public = fields.blob().unwrap();
                p256::PublicKey::from_sec1_bytes(public).unwrap();
                if let Some(expected) = &expected {
                    assert_eq!(public, expected);
                } else {
                    expected = Some(public.to_vec());
                }
                fields.end().unwrap();
                assert_eq!(keystore.diagnostics().count(), 0);
            }
        }
    }

    #[test]
    fn unsupported_system_metadata_is_sanitized_and_keeps_failure_semantics() {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let mut query = SIK_QUERY.to_vec();
        query[23] = 4;
        query[33] = 3;
        let request = system_request_with_operation(2, 7, &query);
        let (reply, output) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 20, request.len()),
            request,
        );
        assert_eq!(reply.unwrap_err().answer.unwrap().frame.parameter, FAILURE);
        assert!(output.is_empty());
        assert_eq!(
            keystore.diagnostics().collect::<Vec<_>>(),
            [
                "sks refused command=0x22 variant=0 handle=Some(4294967295) operation=Some(7) parameter_operation=oskgp system_key_type=Some(3) reference_key_type=None generation=Some(4) keys=o,skg,skt parsed=true reference_key_class=None reference_key_options=None"
            ]
        );
        // The encoder's pair order is reported, not refused, so a request
        // the strict parser rejects as unsorted still shows which it was.
        let request = system_request_with_operation(2, 0, DER_ORDER_QUERY);
        let (reply, _) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 20, request.len()),
            request,
        );
        assert!(reply.is_err());
        let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("keys=skg,skt,o parsed=true"));
        // Guest-controlled unknown strings and opaque parameter data must
        // never be copied into diagnostics, even when DER parsing succeeds.
        let query = b"\x31\x11\x30\x0f\x0c\x01o\x0c\x0aDO-NOT-LOG";
        let request = system_request_with_operation(2, 0, query);
        let (_, output) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 21, request.len()),
            request,
        );
        assert!(output.is_empty());
        let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("parameter_operation=unknown"));
        assert!(diagnostics[0].contains("keys=o parsed=true"));
        assert!(!diagnostics[0].contains("DO-NOT-LOG"));
        assert!(!diagnostics[0].contains("1311768467463790320")); // session
        assert_eq!(keystore.diagnostics().count(), 0);
    }

    #[test]
    fn unauthenticated_and_malformed_requests_do_not_expose_parameter_bytes() {
        let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
        let mut request = system_request_with_operation(2, 7, SIK_QUERY);
        request[DIGEST_START] ^= 1;
        let (reply, output) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 20, request.len()),
            request,
        );
        assert!(reply.is_err());
        assert!(output.is_empty());
        assert_eq!(keystore.diagnostics().count(), 0);
        let request = system_request_with_operation(2, 7, b"DO-NOT-LOG");
        let (reply, output) = ask(
            &mut keystore,
            frame(system_key::PERFORM_OPERATION, 21, request.len()),
            request,
        );
        assert!(reply.is_err());
        assert!(output.is_empty());
        let diagnostics = keystore.diagnostics().collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0].contains("operation=Some(7)"));
        assert!(diagnostics[0].contains("parsed=false"));
        assert!(!diagnostics[0].contains("DO-NOT-LOG"));
    }

    #[test]
    fn system_identity_query_returns_one_raw_public_point_in_both_ipc_versions() {
        let mut expected = None;
        for version in [1, 2] {
            let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
            let request = system_request(version, SIK_QUERY);
            let before = request.clone();
            let (reply, output) = ask(
                &mut keystore,
                frame(system_key::PERFORM_OPERATION, 19, request.len()),
                request,
            );
            let reply = reply.unwrap();
            assert_eq!(reply.tag, system_key::PERFORM_OPERATION | REPLY);
            assert_eq!(reply.opcode, 19);
            assert_eq!(reply.parameter, 0);
            assert_eq!(reply.data as usize >> LENGTH_SHIFT, output.len());
            let parsed = Message::parse(&output).unwrap();
            assert_eq!(parsed.variant(), 0);
            assert_eq!(output[VERSION..parsed.body], before[VERSION..parsed.body]);
            let mut fields = parsed.fields();
            let public = fields.blob().unwrap();
            p256::PublicKey::from_sec1_bytes(public).unwrap();
            assert_eq!(public.len(), 65);
            if let Some(expected) = &expected {
                assert_eq!(public, expected);
            } else {
                expected = Some(public.to_vec());
            }
            fields.end().unwrap();
            assert!(keystore.environment().is_none());
        }
    }

    #[test]
    fn unsupported_or_malformed_system_queries_never_publish_success() {
        let mut dictionaries = vec![vec![], SIK_QUERY[..SIK_QUERY.len() - 1].to_vec()];
        for index in [23, 33, 13] {
            // generation, type and operation
            let mut bad = SIK_QUERY.to_vec();
            bad[index] ^= 1;
            dictionaries.push(bad);
        }
        let mut duplicate = SIK_QUERY.to_vec();
        duplicate[28..31].copy_from_slice(b"skg");
        dictionaries.push(duplicate);
        let mut unsorted = SIK_QUERY.to_vec();
        unsorted[14..24].copy_from_slice(&SIK_QUERY[24..34]);
        unsorted[24..34].copy_from_slice(&SIK_QUERY[14..24]);
        dictionaries.push(unsorted);
        dictionaries.push(DER_ORDER_QUERY.to_vec());
        let mut trailing = SIK_QUERY.to_vec();
        trailing.push(0);
        dictionaries.push(trailing);
        let mut nonminimal = SIK_QUERY.to_vec();
        nonminimal.insert(2, 0x20);
        nonminimal[1] = 0x81;
        dictionaries.push(nonminimal);
        let mut requests: Vec<_> = dictionaries.iter().map(|q| system_request(2, q)).collect();
        // Even a valid digest cannot authorize different framing operands.
        for index in [84, 96, 100] {
            // variant, handle and operation
            let mut bad = system_request(2, SIK_QUERY);
            bad[index] ^= 1;
            let hash = digest(&bad);
            bad[DIGEST_START..DIGEST_START + DIGEST_BYTES].copy_from_slice(&hash);
            requests.push(bad);
        }
        for request in requests {
            let mut keystore = KeyStore::with_system_keys(Zeroizing::new([1; 32]));
            let (result, output) = ask(
                &mut keystore,
                frame(system_key::PERFORM_OPERATION, 20, request.len()),
                request,
            );
            assert_eq!(result.unwrap_err().answer.unwrap().frame.parameter, FAILURE);
            assert!(output.is_empty());
            assert!(keystore.environment().is_none());
        }
        let request = system_request(2, SIK_QUERY);
        let (result, output) = ask(
            &mut KeyStore::default(),
            frame(system_key::PERFORM_OPERATION, 21, request.len()),
            request,
        );
        assert_eq!(
            result.unwrap_err().reason,
            "SEP keystore requires provisioned machine roots"
        );
        assert!(output.is_empty());
    }

    fn ask(
        keystore: &mut KeyStore,
        frame: Frame,
        input: Vec<u8>,
    ) -> (Result<Frame, Refusal>, Vec<u8>) {
        ask_with_entropy(keystore, frame, input, &mut |_: &mut [u8]| {
            Err("test entropy unavailable")
        })
    }

    fn ask_with_entropy(
        keystore: &mut KeyStore,
        frame: Frame,
        input: Vec<u8>,
        entropy: &mut dyn super::super::Entropy,
    ) -> (Result<Frame, Refusal>, Vec<u8>) {
        let mut buffers = Buffers {
            input,
            output: Vec::new(),
        };
        (
            keystore.request(frame, &mut buffers, entropy),
            buffers.output,
        )
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
