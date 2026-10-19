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
//! the tag, byte 2 the operation (the status in a reply), bytes 3..5 the
//! little-endian payload length, byte 5 flags and byte 6 a slot.
//! `_xmsgSendLocked` 0x2d7eba8 tags an AP request with its command-pool
//! index plus one (0x2d7ed40..0x2d7ed48), copies at most 0x8000 input bytes
//! into the AP-to-SEP buffer, and waits for the reply with that tag. A reply
//! status of zero is success and its length (at most 0x8000) is the count of
//! result bytes the AP copies from the SEP-to-AP buffer (0x2d7ef20..0x2d7ef5c);
//! any other status is returned to the caller as its error.
//! `_xmsgReceived` 0x2d7e7e4 matches replies by tag (0x2d7e8a4..0x2d7e8d0).
//!
//! The operations are the AP's own senders (their `_block_invoke` bodies set
//! byte 2). Each is implemented here or refuses, naming what it needs; none
//! is answered with an invented success. The anti-replay operations need the
//! persistent SEP store and refuse until it is installed.
use super::{endpoint::Service, message::Frame};
use alloc::vec::Vec;

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

/// What a request needs from the SEP's DMA path: its input bytes, and where
/// to put its result.
pub trait Payload {
    fn input(&mut self, bytes: &mut [u8]) -> Result<(), &'static str>;
    fn output(&mut self, bytes: &[u8]) -> Result<(), &'static str>;
}

/// The SEP's xART state.
#[derive(Default)]
pub struct Xart {
    os_uuid: Option<Vec<u8>>,
}

impl Xart {
    pub fn new() -> Self {
        Self::default()
    }

    /// The OS UUID the AP handed over with `setup_OS_UUID`, if any.
    pub fn os_uuid(&self) -> Option<&[u8]> {
        self.os_uuid.as_deref()
    }

    /// Answer one AP request on either instance. The reply carries the
    /// request's service and tag, status 0 and the result length.
    pub fn request(
        &mut self,
        frame: Frame,
        payload: &mut dyn Payload,
    ) -> Result<Frame, &'static str> {
        let message = XartMessage::from_frame(frame);
        if message.service != MASTER_ID && message.service != SLAVE_ID {
            return Err("xART request is not addressed to an xART instance");
        }
        if message.tag == 0 {
            return Err("xART request lacks its command-pool tag");
        }
        let length = usize::from(message.length);
        if length > MAX_PAYLOAD {
            return Err("xART request payload exceeds its 0x8000-byte buffer");
        }
        let result = match Operation::decode(message.op)? {
            Operation::SetupOsUuid => {
                if length == 0 {
                    return Err("xART OS UUID request carries no UUID");
                }
                let mut uuid = alloc::vec![0; length];
                payload.input(&mut uuid)?;
                self.os_uuid = Some(uuid);
                0
            }
            Operation::EraseSessionSeeds
            | Operation::EraseAllSeeds
            | Operation::FetchKnownSessions => {
                return Err("xART session seeds need the persistent SEP store");
            }
            Operation::NonceGenerate
            | Operation::NonceRead
            | Operation::NonceInvalidate
            | Operation::BootNonceGenerate
            | Operation::CommitHash => {
                return Err("xART nonces and commitments need the persistent SEP store");
            }
            Operation::CommitEpochs | Operation::GetFullEpochs | Operation::ApSlot(_) => {
                return Err("xART epochs and AP slots need the persistent SEP store");
            }
            Operation::FlushCached | Operation::ShutdownUnmount | Operation::DisableForEacs => {
                return Err("xART volume lifecycle needs the persistent SEP store");
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

    #[test]
    fn the_os_uuid_is_recorded_and_answered_with_the_tag() {
        let mut xart = Xart::new();
        let mut buffers = Buffers {
            input: (0..16).collect(),
            output: Vec::new(),
        };
        let reply = xart
            .request(request(SLAVE_ID, 2, 8, 16), &mut buffers)
            .unwrap();
        assert_eq!(reply, request(SLAVE_ID, 2, 0, 0));
        assert_eq!(xart.os_uuid(), Some(&(0..16).collect::<Vec<u8>>()[..]));
        assert!(
            xart.request(request(SLAVE_ID, 2, 8, 0), &mut buffers)
                .is_err()
        );
    }

    #[test]
    fn unimplemented_and_malformed_requests_refuse() {
        let mut xart = Xart::new();
        let mut buffers = Buffers {
            input: vec![0; 64],
            output: Vec::new(),
        };
        for op in [
            2, 3, 4, 9, 10, 11, 12, 13, 15, 16, 17, 18, 20, 21, 22, 23, 24, 28, 32,
        ] {
            assert!(
                xart.request(request(SLAVE_ID, 1, op, 0), &mut buffers)
                    .is_err(),
                "{op}"
            );
        }
        for op in [0, 1, 5, 14, 19, 0x21, 0xff] {
            assert!(Operation::decode(op).is_err(), "{op}");
        }
        // Untagged, oversized and misaddressed requests.
        assert!(
            xart.request(request(SLAVE_ID, 0, 8, 16), &mut buffers)
                .is_err()
        );
        assert!(
            xart.request(request(SLAVE_ID, 1, 8, 0x8001), &mut buffers)
                .is_err()
        );
        assert!(xart.request(request(0x12, 1, 8, 16), &mut buffers).is_err());
        assert!(buffers.output.is_empty());
    }
}
