//! The xART service pair, seen from the SEP.
//!
//! `AppleSEPXARTService::start` (26A434 kernel file 0x2d7f644) binds to a
//! discovered nub named `xarm` (the master instance, `[+0xc1]` set) or
//! `xars` (the slave), and refuses any other name (0x2d7f690..0x2d7f6ac).
//! Before starting either it requires, for each direction, that the minimum
//! OOL pages times the SEP page are at most 0x8000 bytes and the maximum at
//! least 0x8000 (0x2d7f718..0x2d7f7a0): `_initOOLBuffers` 0x2d7f05c registers
//! exactly one 0x8000-byte buffer each way, AP-to-SEP through `[+0xc8]` and
//! SEP-to-AP through `[+0xd0]`. The master then checks in with
//! `AppleSEPManager::checkInMaster` 0x2d6fa04, which ends the manager's wait
//! for the `xarm` endpoint (`xartSEPMasterEP`, which panics after 15 s).
//!
//! A message is the eight-byte SEP frame read as: byte 0 the service, byte 1
//! the tag, byte 2 the operation (the status in a reply), bytes 3..4 the
//! little-endian payload length, byte 5 flags and byte 6 a slot.
//! `_xmsgSendLocked` 0x2d7eba8 tags an AP request with its command-pool
//! index plus one (0x2d7ed40..0x2d7ed48), copies at most 0x8000 input bytes
//! into the AP-to-SEP buffer, and waits up to 0x13880 ms (80 s) for the
//! reply with that tag. Every AP request travels on `xars`; the AP treats
//! whatever arrives on `xarm` as a SEP-driven request and answers there. A reply
//! status of zero is success and its length (at most 0x8000) is the count of
//! result bytes the AP copies from the SEP-to-AP buffer (0x2d7ef20..0x2d7ef5c);
//! any other status is returned to the caller as its error.
//! `_xmsgReceived` 0x2d7e7e4 matches replies by tag (0x2d7e8a4..0x2d7e8d0).
//!
//! The operations are the AP's own senders (their `_block_invoke` bodies set
//! byte 2), with the payloads each sender passes:
//!
//! - setup_OS_UUID (8): exactly 16 bytes in;
//! - flush (12): a one-byte Boolean in; unmount (13) and disable for EACS
//!   (20): nothing;
//! - nonce generate (15) and read (16): at least 20 bytes out, the nonce;
//!   byte 6 set to 1 asks for a Sandcat slot instead; invalidate (17):
//!   nothing;
//! - commit hash (18): byte 6 the hash type, byte 7 a flag, the caller's
//!   hash or `/chosen/boot-manifest-hash` in;
//! - boot nonce (21): exactly 8 bytes out; commit epochs (22): 16 bytes in
//!   although the length field is 0; get epochs (23): exactly 32 bytes out;
//!   AP slot info (24): exactly 56 bytes out (8 nonce, 48 hash); set and get
//!   provisional AP (27, 28) must succeed.
//!
//! The epochs are eight anti-rollback records, `SEPEpoch::EPOCH_COUNT`
//! (`SEPEpoch::getFullEpochs` 0x2d61aa8 and `AppleSEPXART::getFullEpochs`
//! 0x2d71efc assert it). A full read answers eight four-byte slots: byte 0
//! the current epoch, which `AppleSEPUserClient::DispatchGetEpochs`
//! 0x2d841c0..0x2d841dc copies out for `seputil --show-epochs`, byte 1 a
//! proposal flag and bytes 2 and 3 the proposed values, which the M5 and M6
//! kernels' `AppleEpochManager::processEpochProposalsGated` reads at every
//! boot (T8142 restore kernelcache 0x24dfb48..0x24dfbd8) and commits as
//! eight two-byte `{present, value}` records (`_updateEpochCommits`
//! 0x24df4dc..0x24df4e4). That boot path panics unless the read succeeds
//! with exactly 32 bytes (`SEPEpoch::getFullEpochs` asserts success at
//! 0x2d87390, the xART read block its length at 0x2d8c7c0). This SEP
//! enforces no epoch floor and proposes none, since it does not evaluate
//! Image4 epoch properties: every slot reads epoch 0 with no proposal, and a
//! commit, which the AP sends only for a proposal, refuses.
//!
//! `AppleMobileApNonce` uses the AP slots and the boot nonce only when the
//! DeviceTree has `/arm-io/sep/iop-sep-nub/Sandcat`; J473AP has none, so
//! this SEP has no Sandcat slots and refuses those operations by name.
//! The nonce lives in the SEP's anti-replay store ([`super::store`]). The
//! store is durable on every commit, so a flush has nothing left to write.
//! Each other operation is implemented here or refuses, naming what it
//! needs; none is answered with an invented success. A refusal's failure
//! answer is Darwin `ENOTSUP`, which `_xmsgSendLocked` returns to the
//! caller as its error.
use super::{
    Entropy,
    endpoint::Service,
    message::Frame,
    store::{Backend, NONCE_BYTES, Nonces},
    transaction::{Answer, Payload, Refusal},
};
use alloc::{boxed::Box, vec::Vec};

/// The SEP's boot nonce slot outside Sandcat.
const NONCE_SLOT: u8 = 0;
/// `nonce_generate_with_slot` sets byte 6 to ask for a Sandcat slot.
const SANDCAT_SLOT_REQUEST: u8 = 1;
/// setup_OS_UUID carries exactly one UUID.
const UUID_BYTES: usize = 16;
/// `SEPEpoch::EPOCH_COUNT` four-byte slots answer a full epoch read.
const EPOCH_COUNT: usize = 8;
const EPOCH_SLOT_BYTES: usize = 4;
/// A refused request's reply status: Darwin `ENOTSUP`.
const UNSUPPORTED: u8 = 45;

/// The master instance's fourcc (`AppleSEPXARTService::start` 0x2d7f690).
pub const MASTER: u32 = u32::from_be_bytes(*b"xarm");
/// The slave instance's fourcc (0x2d7f6a0).
pub const SLAVE: u32 = u32::from_be_bytes(*b"xars");
/// One 0x8000-byte buffer each way, in 16 KiB SEP pages.
pub const CAPACITIES: [u8; 4] = [2, 2, 2, 2];
/// `_xmsgSendLocked` clamps every payload to this many bytes.
pub const MAX_PAYLOAD: usize = 0x8000;

/// Stela's catalog IDs for the pair. The AP takes IDs from discovery; these
/// are Stela's allocation, not values recovered from sepOS.
pub const MASTER_ID: u8 = 0x10;
pub const SLAVE_ID: u8 = 0x11;

pub fn services() -> [Service; 2] {
    [
        Service {
            id: MASTER_ID,
            name: MASTER,
            capacities: CAPACITIES,
        },
        Service {
            id: SLAVE_ID,
            name: SLAVE,
            capacities: CAPACITIES,
        },
    ]
}

/// An xART message in the field layout above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XartMessage {
    pub service: u8,
    pub tag: u8,
    pub op: u8,
    pub length: u16,
    pub flags: u8,
    pub slot: u8,
    pub reserved: u8,
}

impl XartMessage {
    pub fn from_frame(frame: Frame) -> Self {
        let [low, flags, slot, reserved] = frame.data.to_le_bytes();
        Self {
            service: frame.service,
            tag: frame.tag,
            op: frame.opcode,
            length: u16::from_le_bytes([frame.parameter, low]),
            flags,
            slot,
            reserved,
        }
    }

    pub fn frame(self) -> Frame {
        let [parameter, low] = self.length.to_le_bytes();
        Frame {
            service: self.service,
            tag: self.tag,
            opcode: self.op,
            parameter,
            data: u32::from_le_bytes([low, self.flags, self.slot, self.reserved]),
        }
    }
}

/// The AP's request operations, by sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `erase_session_seeds_for_UUID` 0x2d7e088 (2).
    EraseSessionSeeds,
    /// `erase_all_xART_seeds` 0x2d7e174 (3).
    EraseAllSeeds,
    /// `fetch_xart_known_sessions` 0x2d7e23c (4).
    FetchKnownSessions,
    /// `setup_OS_UUID` 0x2d70a44 (8): the AP hands the SEP its OS UUID.
    SetupOsUuid,
    /// `lynx_authenticate` 0x2d70b80 (9), `lynx_get_cpsn` 0x2d70de0 (10),
    /// `lynx_get_pub_key` 0x2d70e6c (11), `lynx_get_app_hash` 0x2d70ef8 (32).
    Lynx(u8),
    /// `flush_cached_xart` 0x2d7128c (12).
    FlushCached,
    /// `xart_shtdwn_vol_unmount` 0x2d713c4 (13).
    ShutdownUnmount,
    /// `nonce_generate` 0x2d7171c and `snon_generate_with_slot` 0x2d7183c
    /// (15), `nonce_read` 0x2d717ac (16), `nonce_invalidate` 0x2d718cc (17).
    NonceGenerate,
    NonceRead,
    NonceInvalidate,
    /// `commit_hash` 0x2d71ae4 (18).
    CommitHash,
    /// `xart_disable_for_eacs` 0x2d714d0 (20).
    DisableForEacs,
    /// `bncn_generate` 0x2d71c7c (21).
    BootNonceGenerate,
    /// `commitEpochs` 0x2d71d80 (22), `getFullEpochs` 0x2d71ee4 (23).
    CommitEpochs,
    GetFullEpochs,
    /// `get_ap_slot_info` 0x2d72004 (24) .. `get_provisional_ap` 0x2d72454 (28).
    ApSlot(u8),
}

impl Operation {
    pub fn decode(op: u8) -> Result<Self, &'static str> {
        Ok(match op {
            2 => Self::EraseSessionSeeds,
            3 => Self::EraseAllSeeds,
            4 => Self::FetchKnownSessions,
            8 => Self::SetupOsUuid,
            9..=11 | 32 => Self::Lynx(op),
            12 => Self::FlushCached,
            13 => Self::ShutdownUnmount,
            15 => Self::NonceGenerate,
            16 => Self::NonceRead,
            17 => Self::NonceInvalidate,
            18 => Self::CommitHash,
            20 => Self::DisableForEacs,
            21 => Self::BootNonceGenerate,
            22 => Self::CommitEpochs,
            23 => Self::GetFullEpochs,
            24..=28 => Self::ApSlot(op),
            _ => return Err("xART request operation is outside the recovered AP senders"),
        })
    }
}

/// The failure reply to an AP request on `xars`: its service and tag with
/// the `ENOTSUP` status and no result.
pub fn unsupported(frame: Frame) -> Frame {
    XartMessage {
        op: UNSUPPORTED,
        length: 0,
        flags: 0,
        slot: 0,
        reserved: 0,
        ..XartMessage::from_frame(frame)
    }
    .frame()
}

/// The SEP's xART state.
pub struct Xart {
    os_uuid: Option<Vec<u8>>,
    store: Nonces<Box<dyn Backend>>,
    /// The AP unmounted the xART volume for shutdown, or disabled xART for
    /// Erase All Content and Settings: the anti-replay state is frozen.
    frozen: Option<&'static str>,
}

impl Xart {
    pub fn new(store: Nonces<Box<dyn Backend>>) -> Self {
        Self {
            os_uuid: None,
            store,
            frozen: None,
        }
    }

    /// The OS UUID the AP handed over with `setup_OS_UUID`, if any.
    pub fn os_uuid(&self) -> Option<&[u8]> {
        self.os_uuid.as_deref()
    }

    pub fn store_mut(&mut self) -> &mut Nonces<Box<dyn Backend>> {
        &mut self.store
    }

    fn live(&self) -> Result<(), &'static str> {
        match self.frozen {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Answer one AP request on the slave instance. Master traffic from
    /// the AP is a reply to a SEP-initiated operation, none of which this
    /// implementation sends. The reply carries the
    /// request's service and tag, status 0 and the result length. A refused
    /// slave request is answered `ENOTSUP` unless its store commit may have
    /// happened.
    pub fn request(
        &mut self,
        frame: Frame,
        payload: &mut dyn Payload,
        entropy: &mut dyn Entropy,
    ) -> Result<Frame, Refusal> {
        let mut committed = false;
        self.serve(frame, payload, entropy, &mut committed)
            .map_err(|reason| {
                if committed || frame.service != SLAVE_ID || frame.tag == 0 {
                    Refusal::unanswerable(reason)
                } else {
                    Refusal::answered(reason, Answer::frame(unsupported(frame)))
                }
            })
    }

    /// `committed` is set before any store mutation, whose failure may
    /// still have reached durable storage.
    fn serve(
        &mut self,
        frame: Frame,
        payload: &mut dyn Payload,
        entropy: &mut dyn Entropy,
        committed: &mut bool,
    ) -> Result<Frame, &'static str> {
        let message = XartMessage::from_frame(frame);
        if message.service == MASTER_ID {
            return Err("xART master reply has no outstanding SEP-initiated request");
        }
        if message.service != SLAVE_ID {
            return Err("xART request is not addressed to an xART instance");
        }
        if message.tag == 0 {
            return Err("xART request lacks its command-pool tag");
        }
        let length = usize::from(message.length);
        if length > MAX_PAYLOAD {
            return Err("xART request payload exceeds its 0x8000-byte buffer");
        }
        let operation = Operation::decode(message.op)?;
        if matches!(
            operation,
            Operation::SetupOsUuid
                | Operation::FlushCached
                | Operation::ShutdownUnmount
                | Operation::DisableForEacs
                | Operation::NonceGenerate
                | Operation::NonceRead
                | Operation::NonceInvalidate
                | Operation::GetFullEpochs
        ) && (message.flags != 0 || message.reserved != 0 || message.slot != 0)
        {
            if matches!(operation, Operation::NonceGenerate | Operation::NonceRead)
                && message.slot == SANDCAT_SLOT_REQUEST
            {
                return Err("xART nonce slots exist only on boards with a Sandcat SEP nub");
            }
            return Err("xART request flags, slot or reserved fields are not modeled");
        }
        let result = match operation {
            Operation::SetupOsUuid => {
                if length != UUID_BYTES {
                    return Err("xART OS UUID request is not one 16-byte UUID");
                }
                let mut uuid = alloc::vec![0; length];
                payload.input(&mut uuid)?;
                self.os_uuid = Some(uuid);
                0
            }
            Operation::FlushCached => {
                if length != 1 {
                    return Err("xART flush request is not one Boolean");
                }
                payload.input(&mut [0])?;
                self.store.flush()?;
                0
            }
            Operation::ShutdownUnmount | Operation::DisableForEacs => {
                if length != 0 {
                    return Err("xART volume request carries a payload");
                }
                self.frozen.get_or_insert(if message.op == 13 {
                    "the AP unmounted the xART volume for shutdown"
                } else {
                    "the AP disabled xART for Erase All Content and Settings"
                });
                0
            }
            Operation::NonceGenerate | Operation::NonceRead => {
                if length != 0 {
                    return Err("xART nonce generation or read carries an input payload");
                }
                self.live()?;
                let nonce = if message.op == 15 {
                    *committed = true;
                    self.store.generate(NONCE_SLOT, entropy)?
                } else {
                    self.store.read(NONCE_SLOT)?
                };
                payload.output(&nonce)?;
                NONCE_BYTES as u16
            }
            Operation::NonceInvalidate => {
                if length != 0 {
                    return Err("xART nonce invalidation carries a payload");
                }
                self.live()?;
                // Killing a nonce that was never generated leaves none,
                // which is what the AP asks for.
                if self.store.contains(NONCE_SLOT)? {
                    *committed = true;
                    self.store.invalidate(NONCE_SLOT)?;
                }
                0
            }
            Operation::GetFullEpochs => {
                if length != 0 {
                    return Err("xART epoch read carries an input payload");
                }
                payload.output(&[0; EPOCH_COUNT * EPOCH_SLOT_BYTES])?;
                (EPOCH_COUNT * EPOCH_SLOT_BYTES) as u16
            }
            Operation::BootNonceGenerate | Operation::ApSlot(_) => {
                return Err(
                    "xART boot nonces and AP slots exist only on boards with a Sandcat SEP nub",
                );
            }
            Operation::CommitHash => {
                return Err("xART commit-hash types are not recovered");
            }
            Operation::CommitEpochs => {
                return Err("xART epoch commit without a SEP epoch proposal");
            }
            Operation::EraseSessionSeeds
            | Operation::EraseAllSeeds
            | Operation::FetchKnownSessions => {
                return Err("xART session seeds are not recovered");
            }
            Operation::Lynx(_) => {
                return Err("xART Lynx operations need a Lynx secure element");
            }
        };
        Ok(XartMessage {
            op: 0,
            length: result,
            flags: 0,
            slot: 0,
            reserved: 0,
            ..message
        }
        .frame())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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

    fn request(service: u8, tag: u8, op: u8, length: u16) -> Frame {
        XartMessage {
            service,
            tag,
            op,
            length,
            flags: 0,
            slot: 0,
            reserved: 0,
        }
        .frame()
    }

    #[test]
    fn the_pair_meets_the_kernels_buffer_checks() {
        let [master, slave] = services();
        assert_eq!((master.name, slave.name), (0x7861_726d, 0x7861_7273));
        const PAGE: u32 = 0x4000;
        for service in [master, slave] {
            assert!(service.accepts(true, 0x8000, PAGE));
            assert!(service.accepts(false, 0x8000, PAGE));
            let [send_min, send_max, receive_min, receive_max] = service.capacities;
            for (min, max) in [(send_min, send_max), (receive_min, receive_max)] {
                assert!(u32::from(min) * PAGE <= 0x8000);
                assert!(u32::from(max) * PAGE >= 0x8000);
            }
        }
        assert!(super::super::endpoint::Catalog::new(services().to_vec()).is_ok());
    }

    #[test]
    fn the_message_fields_round_trip_through_the_frame() {
        let message = XartMessage {
            service: SLAVE_ID,
            tag: 3,
            op: 0x15,
            length: 0x1234,
            flags: 1,
            slot: 2,
            reserved: 0,
        };
        let frame = message.frame();
        assert_eq!(frame.mailbox().payload, 0x0002_0112_3415_0311);
        assert_eq!(XartMessage::from_frame(frame), message);
    }

    fn xart() -> Xart {
        let roots = super::super::keys::Roots::provisioned([1; 32], [2; 32], 0xa5a5_0002).unwrap();
        let backend: Box<dyn Backend> = Box::new(super::super::store::Volatile::default());
        Xart::new(Nonces::provision(&roots, backend).unwrap())
    }

    fn entropy(bytes: &mut [u8]) -> Result<(), &'static str> {
        bytes.fill(0x5a);
        Ok(())
    }

    fn ask(xart: &mut Xart, frame: Frame, buffers: &mut Buffers) -> Result<Frame, &'static str> {
        xart.request(frame, buffers, &mut entropy)
            .map_err(|refusal| refusal.reason)
    }

    #[test]
    fn the_os_uuid_is_recorded_and_answered_with_the_tag() {
        let mut xart = xart();
        let mut buffers = Buffers {
            input: (0..16).collect(),
            output: Vec::new(),
        };
        let reply = ask(&mut xart, request(SLAVE_ID, 2, 8, 16), &mut buffers).unwrap();
        assert_eq!(reply, request(SLAVE_ID, 2, 0, 0));
        assert_eq!(xart.os_uuid(), Some(&(0..16).collect::<Vec<u8>>()[..]));
        assert!(ask(&mut xart, request(SLAVE_ID, 2, 8, 0), &mut buffers).is_err());
        assert!(ask(&mut xart, request(SLAVE_ID, 2, 8, 15), &mut buffers).is_err());
    }

    #[test]
    fn the_nonce_is_generated_read_and_killed_in_the_store() {
        let mut xart = xart();
        let mut buffers = Buffers {
            input: vec![1],
            output: Vec::new(),
        };
        // The restore kills the nonce before one exists.
        ask(&mut xart, request(SLAVE_ID, 1, 17, 0), &mut buffers).unwrap();
        assert!(ask(&mut xart, request(SLAVE_ID, 1, 16, 0), &mut buffers).is_err());
        let generated = ask(&mut xart, request(SLAVE_ID, 1, 15, 0), &mut buffers).unwrap();
        assert_eq!(XartMessage::from_frame(generated).length, 20);
        assert_eq!(buffers.output, [0x5a; 20]);
        buffers.output.clear();
        ask(&mut xart, request(SLAVE_ID, 1, 16, 0), &mut buffers).unwrap();
        assert_eq!(buffers.output, [0x5a; 20]);
        ask(&mut xart, request(SLAVE_ID, 1, 17, 0), &mut buffers).unwrap();
        assert!(ask(&mut xart, request(SLAVE_ID, 1, 16, 0), &mut buffers).is_err());
        // A Sandcat slot request refuses on a board without Sandcat.
        let slotted = XartMessage {
            slot: 1,
            ..XartMessage::from_frame(request(SLAVE_ID, 1, 15, 0))
        };
        assert!(ask(&mut xart, slotted.frame(), &mut buffers).is_err());
        // A flush takes one Boolean; the volume freezes at unmount.
        ask(&mut xart, request(SLAVE_ID, 1, 12, 1), &mut buffers).unwrap();
        assert!(ask(&mut xart, request(SLAVE_ID, 1, 12, 0), &mut buffers).is_err());
        ask(&mut xart, request(SLAVE_ID, 1, 13, 0), &mut buffers).unwrap();
        assert!(ask(&mut xart, request(SLAVE_ID, 1, 15, 0), &mut buffers).is_err());
    }

    #[test]
    fn unrecovered_and_malformed_requests_refuse() {
        let mut xart = xart();
        let mut buffers = Buffers {
            input: vec![0; 64],
            output: Vec::new(),
        };
        for op in [2, 3, 4, 9, 10, 11, 18, 21, 22, 24, 28, 32] {
            assert!(
                ask(&mut xart, request(SLAVE_ID, 1, op, 0), &mut buffers).is_err(),
                "{op}"
            );
        }
        for op in [0, 1, 5, 14, 19, 0x21, 0xff] {
            assert!(Operation::decode(op).is_err(), "{op}");
        }
        // Untagged, oversized and misaddressed requests.
        assert!(ask(&mut xart, request(SLAVE_ID, 0, 8, 16), &mut buffers).is_err());
        assert!(ask(&mut xart, request(SLAVE_ID, 1, 8, 0x8001), &mut buffers).is_err());
        assert!(ask(&mut xart, request(0x12, 1, 8, 16), &mut buffers).is_err());
        assert!(ask(&mut xart, request(MASTER_ID, 1, 8, 16), &mut buffers).is_err());
        for (flags, slot, reserved) in [(1, 0, 0), (0, 2, 0), (0, 0, 1)] {
            let frame = XartMessage {
                flags,
                slot,
                reserved,
                ..XartMessage::from_frame(request(SLAVE_ID, 1, 8, 16))
            }
            .frame();
            assert!(ask(&mut xart, frame, &mut buffers).is_err());
        }
        for op in [15, 16, 23] {
            assert!(ask(&mut xart, request(SLAVE_ID, 1, op, 1), &mut buffers).is_err());
        }
        assert!(buffers.output.is_empty());
        assert!(xart.os_uuid().is_none());
    }

    #[test]
    fn a_full_epoch_read_answers_eight_empty_slots_and_a_commit_refuses() {
        let mut xart = xart();
        let mut buffers = Buffers {
            input: vec![0; 16],
            output: Vec::new(),
        };
        let reply = ask(&mut xart, request(SLAVE_ID, 6, 23, 0), &mut buffers).unwrap();
        assert_eq!(reply, request(SLAVE_ID, 6, 0, 32));
        assert_eq!(buffers.output, [0; 32]);
        // The AP commits only a SEP proposal, and none was made.
        let commit = xart
            .request(request(SLAVE_ID, 7, 22, 0), &mut buffers, &mut entropy)
            .unwrap_err();
        assert_eq!(
            commit.answer,
            Some(Answer::frame(request(SLAVE_ID, 7, UNSUPPORTED, 0)))
        );
        // A slotted or flagged read is outside the AP's sender.
        let slotted = XartMessage {
            slot: 1,
            ..XartMessage::from_frame(request(SLAVE_ID, 8, 23, 0))
        };
        assert!(ask(&mut xart, slotted.frame(), &mut buffers).is_err());
    }

    #[test]
    fn refusals_are_answered_enotsup_only_on_the_slave_before_any_commit() {
        let mut xart = xart();
        let mut buffers = Buffers {
            input: Vec::new(),
            output: Vec::new(),
        };
        let refused = |xart: &mut Xart, frame, buffers: &mut Buffers| {
            xart.request(frame, buffers, &mut entropy).unwrap_err()
        };
        // An unrecovered operation and a short read are answered ENOTSUP.
        for frame in [request(SLAVE_ID, 2, 18, 0), request(SLAVE_ID, 3, 8, 16)] {
            assert_eq!(
                refused(&mut xart, frame, &mut buffers).answer,
                Some(Answer::frame(unsupported(frame)))
            );
        }
        // Master and untagged frames have no request to answer.
        for frame in [request(MASTER_ID, 2, 8, 16), request(SLAVE_ID, 0, 8, 16)] {
            assert_eq!(refused(&mut xart, frame, &mut buffers).answer, None);
        }
        // Reading a never-generated nonce has no effect and is answered.
        assert!(
            refused(&mut xart, request(SLAVE_ID, 4, 16, 0), &mut buffers)
                .answer
                .is_some()
        );
    }

    #[test]
    fn uncertain_commits_cannot_be_acknowledged_by_flush_or_idempotent_invalidate() {
        use alloc::rc::Rc;
        use core::cell::Cell;
        struct Failing {
            inner: super::super::store::Volatile,
            fail: Rc<Cell<bool>>,
        }
        impl Backend for Failing {
            fn load(&mut self) -> Result<Option<super::super::store::Head>, &'static str> {
                self.inner.load()
            }
            fn commit(
                &mut self,
                expected: u64,
                head: super::super::store::Head,
            ) -> Result<(), &'static str> {
                self.inner.commit(expected, head)?;
                if self.fail.get() {
                    Err("commit acknowledgement lost")
                } else {
                    Ok(())
                }
            }
        }
        let fail = Rc::new(Cell::new(false));
        let roots = super::super::keys::Roots::provisioned([1; 32], [2; 32], 0xa5a5_0002).unwrap();
        let backend: Box<dyn Backend> = Box::new(Failing {
            inner: super::super::store::Volatile::default(),
            fail: fail.clone(),
        });
        let mut xart = Xart::new(Nonces::provision(&roots, backend).unwrap());
        let mut buffers = Buffers {
            input: vec![0],
            output: Vec::new(),
        };
        fail.set(true);
        // The nonce may be durable: neither success nor failure is answered.
        assert_eq!(
            xart.request(request(SLAVE_ID, 1, 15, 0), &mut buffers, &mut entropy),
            Err(Refusal::unanswerable("commit acknowledgement lost"))
        );
        assert!(buffers.output.is_empty());
        for (op, length) in [(17, 0), (12, 1), (16, 0), (15, 0)] {
            assert!(ask(&mut xart, request(SLAVE_ID, 1, op, length), &mut buffers).is_err());
        }
        fail.set(false);
        let reopened = Nonces::open(&roots, xart.store.into_backend()).unwrap();
        assert_eq!(reopened.read(0).unwrap(), [0x5a; NONCE_BYTES]);
    }
}
