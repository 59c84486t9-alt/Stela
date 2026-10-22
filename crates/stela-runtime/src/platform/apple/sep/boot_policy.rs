//! The BootPolicy service, `pnon`, seen from the SEP.
//!
//! **Transport** (26A434 J473 kernel file offsets). `BootPolicy::sendSEPCommand`
//! 0x329d408 writes the request to its OOL send buffer and
//! `sendSEPCommandMessage` 0x329dd50 sends tag 2 with the request byte count
//! in the data word. `handleSEPMessage` 0x329d940..0x329d9b4 accepts a reply
//! with tag 2, takes its opcode byte as the status and its data word, at most
//! 0x14000, as the byte count it copies from the receive buffer. A nonzero
//! status is returned to the user client as the command's result, which
//! libbootpolicy reports as BOOTPOLICY "SEP communication (2)".
//! `getSEPEndpoint` 0x329dff8..0x329e094 requires more than six send and
//! more than four receive pages of 16 KiB and allocates the advertised
//! maximum, so [`CAPACITIES`] gives exactly 0x1c000 bytes in and 0x14000
//! out.
//!
//! **Command** (26A434 libbootpolicy, shared-cache image 0x1b31e2000;
//! offsets from its `__TEXT`). `__sep_command` +0x100b4 writes a 32-byte
//! header before any body: u32 [`REQUEST_MAGIC`] (bytes "hcPB"), the u32
//! command and 24 zero bytes. The kernel's `validateSEPCommand`
//! 0x329c9a8..0x329c9c0 requires at least those 32 bytes and the magic. A
//! reply must be at least 32 bytes, start with u32 [`REPLY_MAGIC`]
//! ("hrPB") and fit the caller's buffer (+0x10110..+0x10130). Its u32 at +4
//! is the BootPolicy result the call returns; libbootpolicy's result names
//! (+0x42ee7..+0x4303c) give 0 "success" and 255 "not supported". Bytes
//! 8..23 are diagnostics it logs. The current OS type (command 0x3e,
//! `bootpolicy_get_current_os_type`, +0x3670..+0x369c) is a bare header
//! answered by exactly 36 bytes with the type in byte 32 ([`BootOs`]).
//!
//! RecoveryOS policy nonce commands have the recovered zero-body request
//! and digest reply shapes ([`nonces`]). They bind to the same durable store
//! as xART. The SEP answers the current OS type only when the boot chain
//! supplies it. LocalPolicy signing, authenticated/owner-bearing bodies,
//! macOS/remote nonce transactions and tags remain explicit refusals; a
//! successful nonce transaction does not establish policy authentication.
//! A frame or header outside the envelope gets a transport failure.
mod nonces;
use super::{
    Entropy,
    endpoint::Service,
    message::Frame,
    store::{Backend, Nonces},
    transaction::{Answer, Payload, Refusal},
};

/// Stela's catalog ID for the service.
pub const ID: u8 = 0x13;
pub const NAME: u32 = u32::from_be_bytes(*b"pnon");
pub const CAPACITIES: [u8; 4] = [7, 7, 5, 5];

const TAG: u8 = 2;
pub const REQUEST_MAGIC: u32 = u32::from_le_bytes(*b"hcPB");
pub const REPLY_MAGIC: u32 = u32::from_le_bytes(*b"hrPB");
pub const HEADER_BYTES: usize = 32;
pub const CURRENT_OS_TYPE: u32 = 0x3e;
const OS_TYPE_REPLY_BYTES: usize = 36;
/// BootPolicy results.
const SUCCESS: u32 = 0;
pub const NOT_SUPPORTED: u32 = 255;
/// A transport failure's status byte. Any nonzero value fails the command;
/// this one is Stela's.
pub const TRANSPORT_FAILURE: u8 = 1;

/// The OS kinds of libbootpolicy's type names (+0x404a0..+0x408ad, table
/// at `__DATA_CONST` 0x1e1629be8); it reports any other byte as unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BootOs {
    MacOs = 0,
    OneTrueRecovery = 1,
    Recovery = 2,
    KcOs = 3,
    Restore = 4,
    PostUpgrade = 5,
}

pub fn service() -> Service {
    Service {
        id: ID,
        name: NAME,
        capacities: CAPACITIES,
    }
}

/// The transport failure reply to `frame`: status [`TRANSPORT_FAILURE`],
/// no bytes.
pub fn transport_failure(frame: Frame) -> Frame {
    Frame {
        opcode: TRANSPORT_FAILURE,
        parameter: 0,
        data: 0,
        ..frame
    }
}

fn reply_header(result: u32) -> [u8; HEADER_BYTES] {
    let mut header = [0; HEADER_BYTES];
    header[..4].copy_from_slice(&REPLY_MAGIC.to_le_bytes());
    header[4..8].copy_from_slice(&result.to_le_bytes());
    header
}

fn delivered(frame: Frame, bytes: usize) -> Frame {
    Frame {
        opcode: 0,
        parameter: 0,
        data: bytes as u32,
        ..frame
    }
}

/// The not-supported answer: a bare reply header with result 255.
pub(super) fn not_supported(frame: Frame) -> Answer {
    Answer {
        frame: delivered(frame, HEADER_BYTES),
        output: reply_header(NOT_SUPPORTED).to_vec(),
    }
}

pub struct BootPolicy {
    boot_os: Option<BootOs>,
    recovery_nonce: nonces::RecoveryNonce,
}

impl BootPolicy {
    /// `boot_os` is the OS the boot chain started, when the machine
    /// supplies it.
    pub fn new(boot_os: Option<BootOs>) -> Self {
        Self {
            boot_os,
            recovery_nonce: nonces::RecoveryNonce::default(),
        }
    }

    /// Read one AP command and write its reply using the same machine store
    /// as xART. A durable or uncertain mutation is never automatically retried
    /// and cannot receive a failure acknowledgement.
    pub fn request<B: Backend>(
        &mut self,
        frame: Frame,
        payload: &mut dyn Payload,
        store: &mut Nonces<B>,
        entropy: &mut dyn Entropy,
    ) -> Result<Frame, Refusal> {
        let transport = |reason| Refusal::answered(reason, Answer::frame(transport_failure(frame)));
        if frame.service != ID || frame.tag != TAG || frame.opcode != 0 || frame.parameter != 0 {
            return Err(transport(
                "SEP BootPolicy frame is not the kernel's tag-2 command",
            ));
        }
        let length = frame.data as usize;
        if length < HEADER_BYTES {
            return Err(transport(
                "SEP BootPolicy command is shorter than its 32-byte header",
            ));
        }
        let mut header = [0; HEADER_BYTES];
        payload.input(&mut header).map_err(transport)?;
        let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
        if word(0) != REQUEST_MAGIC || header[8..].iter().any(|&byte| byte != 0) {
            return Err(transport(
                "SEP BootPolicy command header is not libbootpolicy's",
            ));
        }
        let unsupported = |reason| Refusal::answered(reason, not_supported(frame));
        if nonces::accepts(word(4)) {
            return self
                .recovery_nonce
                .request(word(4), frame, payload, store, entropy);
        }
        if word(4) != CURRENT_OS_TYPE || length != HEADER_BYTES {
            return Err(unsupported("SEP BootPolicy command is not implemented"));
        }
        let os = self.boot_os.ok_or_else(|| {
            unsupported("SEP BootPolicy OS type needs the booted OS, which the SEP is not given")
        })?;
        let mut reply = [0; OS_TYPE_REPLY_BYTES];
        reply[..HEADER_BYTES].copy_from_slice(&reply_header(SUCCESS));
        reply[HEADER_BYTES] = os as u8;
        payload.output(&reply).map_err(transport)?;
        Ok(delivered(frame, OS_TYPE_REPLY_BYTES))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

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

    fn command(command: u32, body: usize) -> Vec<u8> {
        let mut bytes = vec![0; HEADER_BYTES + body];
        bytes[..4].copy_from_slice(b"hcPB");
        bytes[4..8].copy_from_slice(&command.to_le_bytes());
        bytes
    }

    fn frame(length: usize) -> Frame {
        Frame {
            service: ID,
            tag: TAG,
            opcode: 0,
            parameter: 0,
            data: length as u32,
        }
    }

    fn ask(
        policy: &mut BootPolicy,
        frame: Frame,
        input: Vec<u8>,
    ) -> (Result<Frame, Refusal>, Vec<u8>) {
        let mut buffers = Buffers {
            input,
            output: Vec::new(),
        };
        let roots = super::super::keys::Roots::provisioned([1; 32], [2; 32], 0x1234).unwrap();
        let mut store =
            Nonces::provision(&roots, super::super::store::Volatile::default()).unwrap();
        let mut entropy = |bytes: &mut [u8]| {
            bytes.fill(1);
            Ok(())
        };
        (
            policy.request(frame, &mut buffers, &mut store, &mut entropy),
            buffers.output,
        )
    }

    #[test]
    fn the_wire_magics_are_the_libbootpolicy_constants() {
        assert_eq!(REQUEST_MAGIC, 0x4250_6368);
        assert_eq!(REPLY_MAGIC, REQUEST_MAGIC + 0xf00);
        assert!(service().accepts(true, 0x1c000, 0x4000));
        assert!(service().accepts(false, 0x14000, 0x4000));
    }

    #[test]
    fn the_os_type_is_answered_only_when_the_boot_supplies_it() {
        let (reply, output) = ask(
            &mut BootPolicy::new(Some(BootOs::Restore)),
            frame(32),
            command(CURRENT_OS_TYPE, 0),
        );
        assert_eq!(reply.unwrap(), frame(36));
        assert_eq!(output.len(), 36);
        assert_eq!(output[..4], *b"hrPB");
        assert_eq!(output[4..32], [0; 28]);
        assert_eq!(output[32..], [4, 0, 0, 0]);
        let (reply, output) = ask(
            &mut BootPolicy::new(None),
            frame(32),
            command(CURRENT_OS_TYPE, 0),
        );
        let answer = reply.unwrap_err().answer.unwrap();
        assert_eq!(answer.frame, frame(32));
        assert_eq!(answer.output, reply_header(NOT_SUPPORTED));
        assert!(output.is_empty());
    }

    #[test]
    fn other_commands_are_not_supported_and_malformed_ones_fail_transport() {
        let mut policy = BootPolicy::new(Some(BootOs::MacOs));
        // A LocalPolicy-sized command, and the OS type with a body.
        for (length, input) in [
            (0x4130, command(0x35, 0x4110)),
            (36, command(CURRENT_OS_TYPE, 4)),
        ] {
            let (reply, output) = ask(&mut policy, frame(length), input);
            let answer = reply.unwrap_err().answer.unwrap();
            assert_eq!(answer.frame, frame(32));
            assert_eq!(answer.output[4..8], 255u32.to_le_bytes());
            assert!(output.is_empty());
        }
        let mut bad_magic = command(CURRENT_OS_TYPE, 0);
        bad_magic[0] = b'x';
        let mut reserved = command(CURRENT_OS_TYPE, 0);
        reserved[20] = 1;
        let mut tagged = frame(32);
        tagged.tag = 3;
        let mut foreign = frame(32);
        foreign.service = ID + 1;
        for (frame, input) in [
            (frame(31), command(CURRENT_OS_TYPE, 0)),
            (frame(32), bad_magic),
            (frame(32), reserved),
            (tagged, command(CURRENT_OS_TYPE, 0)),
            (foreign, command(CURRENT_OS_TYPE, 0)),
            (frame(32), Vec::new()),
        ] {
            let (reply, _) = ask(&mut policy, frame, input);
            let answer = reply.unwrap_err().answer.unwrap();
            assert_eq!(answer.frame, transport_failure(frame));
            assert!(answer.output.is_empty());
        }
    }
}
