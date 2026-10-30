//! The SEP control endpoint (service 0), seen from the SEP.
//!
//! `AppleSEPControl` (26A434 kernel file offsets) owns the AP side. Requests
//! are eight-byte frames {service 0, tag, opcode, parameter, data}. A
//! *tagged* request (tag != 0, allocated from the endpoint's command pool by
//! `_cmsgSend` 0x2d8540c..0x2d85424) waits for a reply carrying the same tag:
//! `_cmsgAction` 0x2d84dec..0x2d84f58 finds the pool entry by tag and copies
//! the whole reply word over the request. The caller then reads the reply's
//! parameter byte as the SEP status and its data word as the result
//! (`_cmsgSend` 0x2d85648..0x2d856b8). Tag-0 frames are notifications in
//! either direction and are never answered.
//!
//! The opcodes below are the AP's own senders: `cmsgNOP` 0x2d8571c (0),
//! `cmsgSET_OOL_IN`/`OUT` 0x2d85754/0x2d858b0 (4 then 2, 5 then 3; parameter
//! is the owning service), `cmsgTTYIN` 0x2d85a0c (10), `cmsgSLEEP` 0x2d85a4c
//! (12, parameter = sleep type), `cmsgWAKE` 0x2d85a8c (13), the nap wake word
//! of `_wakeSEPFromNap` 0x2d6af98 (constant 0x000e0000 at 0x733750: tag-0
//! opcode 14), `cmsgNAP_OK` 0x2d85b20 (tag-0 18), `cmsgNAP` 0x2d85b78 (tag-0
//! 19), `cmsgSECMODE_REQUEST` 0x2d85bd0 (20), `cmsgSELF_TEST` 0x2d85c40 (24),
//! the relay DMA commands of `_cmsgSET_DMA_CMD` 0x2d85ca0 and
//! `cmsgSET_DMA_IN`/`OUT` (25..32), `cmsgERASE_INSTALL` 0x2d863a4 (37),
//! `cmsgL4_PANIC`/`cmsgSEPOS_PANIC` 0x2d863e0/0x2d86420 (38/39),
//! `cmsgAP_SLEEP_READY` 0x2d85ac8 (tag-0 42) and
//! `cmsgGET_ENTROPY_FOR_XNU_PRNG` 0x2d85194 (54). Any other request opcode is
//! outside the recovered ABI and refuses; it is never answered with success.
use super::message::{self, Frame};
use crate::Result;
use stela_contracts::refuse;

pub const NOP: u8 = 0;
pub const SET_OOL_IN_ADDRESS: u8 = 2;
#[cfg(test)]
pub const SET_OOL_OUT_ADDRESS: u8 = 3;
pub const SET_OOL_IN_LENGTH: u8 = 4;
pub const SET_OOL_OUT_LENGTH: u8 = 5;
pub const TTY_IN: u8 = 10;
pub const SLEEP: u8 = 12;
pub const WAKE: u8 = 13;
pub const WAKE_FROM_NAP: u8 = 14;
pub const NAP_OK: u8 = 18;
pub const NAP: u8 = 19;
pub const SECURITY_MODE: u8 = 20;
pub const SELF_TEST: u8 = 24;
const RELAY_DMA_FIRST: u8 = 25;
const RELAY_DMA_LAST: u8 = 32;
pub const ERASE_INSTALL: u8 = 37;
pub const L4_PANIC: u8 = 38;
pub const SEPOS_PANIC: u8 = 39;
pub const AP_SLEEP_READY: u8 = 42;
pub const ENTROPY: u8 = 54;

/// SEP-originated tag-0 notifications. `_cmsgAction` 0x2d84e98..0x2d85084
/// dispatches 13 (schedule OS active through a thread call), 16 (wrapping
/// active), 17 (the SEP asks to nap; the AP answers 18, after which
/// `_sendMessageGated` 0x2d6ac78..0x2d6ac8c marks it napping), 21 (OS
/// active) and 41 (a SEP information word). `_doorbellAction`
/// 0x2d681cc..0x2d681f8 consumes opcode 15 (or 21) as the acknowledgement
/// that `_wakeSEPFromNap` waits for.
pub const NAP_AWAKE: u8 = 15;
pub const OS_ACTIVE: u8 = 21;

/// The reply's status byte. `_cmsgSend` 0x2d8568c..0x2d856b8 maps 1 and 2
/// through the table at kernel file 0x733bf0 to kIOReturnBadArgument and
/// kIOReturnAborted, and any larger value to kIOReturnDeviceError.
/// `cmsgGET_ENTROPY_FOR_XNU_PRNG` 0x2d851f4..0x2d85230 treats 2 as a
/// retryable failure and panics on any other nonzero status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Success = 0,
    DeviceError = 3,
}

/// A decoded AP request. Tagged requests must carry a nonzero tag and
/// notifications tag zero; the AP's senders never mix them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    Nop,
    /// One step of an OOL registration (opcodes 2..5), owner in `parameter`.
    Ool,
    TtyIn(u8),
    Sleep(u8),
    Wake,
    WakeFromNap,
    NapOk,
    Nap,
    SecurityMode,
    SelfTest,
    /// Relay DMA (`pcie-up-interrupts` boards only) opcode.
    RelayDma(u8),
    EraseInstall,
    Panic,
    ApSleepReady,
    Entropy,
}

impl Request {
    pub fn decode(frame: Frame) -> Result<Self> {
        if frame.service != message::CONTROL {
            return Err(refuse!("SEP control request is not addressed to service 0"));
        }
        let request = match frame.opcode {
            NOP => Self::Nop,
            SET_OOL_IN_ADDRESS..=SET_OOL_OUT_LENGTH => Self::Ool,
            TTY_IN => Self::TtyIn(frame.parameter),
            SLEEP => Self::Sleep(frame.parameter),
            WAKE => Self::Wake,
            WAKE_FROM_NAP => Self::WakeFromNap,
            NAP_OK => Self::NapOk,
            NAP => Self::Nap,
            SECURITY_MODE => Self::SecurityMode,
            SELF_TEST => Self::SelfTest,
            RELAY_DMA_FIRST..=RELAY_DMA_LAST => Self::RelayDma(frame.opcode),
            ERASE_INSTALL => Self::EraseInstall,
            L4_PANIC | SEPOS_PANIC => Self::Panic,
            AP_SLEEP_READY => Self::ApSleepReady,
            ENTROPY => Self::Entropy,
            _ => {
                return Err(refuse!(
                    "SEP control opcode is outside the recovered AP ABI"
                ));
            }
        };
        if request.tagged() != (frame.tag != 0) {
            return Err(if request.tagged() {
                refuse!("SEP control request needs a command-pool tag")
            } else {
                refuse!("SEP control notification must use tag zero")
            });
        }
        Ok(request)
    }

    /// Whether the AP waits for a tagged reply.
    pub fn tagged(self) -> bool {
        !matches!(
            self,
            Self::WakeFromNap | Self::NapOk | Self::Nap | Self::ApSleepReady
        )
    }
}

/// The reply to a tagged request: the request's own tag and opcode, with the
/// status in the parameter byte and the result in the data word. The AP does
/// not check the reply opcode; echoing it keeps the reply self-describing.
pub fn reply(request: Frame, status: Status, data: u32) -> Frame {
    Frame {
        service: message::CONTROL,
        tag: request.tag,
        opcode: request.opcode,
        parameter: status as u8,
        data,
    }
}

/// A SEP-originated tag-0 notification.
pub fn notification(opcode: u8, data: u32) -> Frame {
    Frame {
        service: message::CONTROL,
        tag: 0,
        opcode,
        parameter: 0,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(tag: u8, opcode: u8, parameter: u8) -> Frame {
        Frame {
            service: message::CONTROL,
            tag,
            opcode,
            parameter,
            data: 0,
        }
    }

    #[test]
    fn the_ap_senders_decode_with_their_tag_discipline() {
        for (opcode, request) in [
            (NOP, Request::Nop),
            (SET_OOL_IN_LENGTH, Request::Ool),
            (SET_OOL_OUT_ADDRESS, Request::Ool),
            (TTY_IN, Request::TtyIn(7)),
            (SLEEP, Request::Sleep(7)),
            (WAKE, Request::Wake),
            (SECURITY_MODE, Request::SecurityMode),
            (SELF_TEST, Request::SelfTest),
            (26, Request::RelayDma(26)),
            (ERASE_INSTALL, Request::EraseInstall),
            (SEPOS_PANIC, Request::Panic),
            (ENTROPY, Request::Entropy),
        ] {
            assert_eq!(Request::decode(frame(3, opcode, 7)), Ok(request));
            assert!(Request::decode(frame(0, opcode, 7)).is_err());
        }
        for (opcode, request) in [
            (WAKE_FROM_NAP, Request::WakeFromNap),
            (NAP_OK, Request::NapOk),
            (NAP, Request::Nap),
            (AP_SLEEP_READY, Request::ApSleepReady),
        ] {
            assert_eq!(Request::decode(frame(0, opcode, 0)), Ok(request));
            assert!(Request::decode(frame(1, opcode, 0)).is_err());
        }
        // Opcodes the AP never sends, and SEP-originated ones, refuse.
        for opcode in [1, 6, 15, 17, 21, 41, 55, 0xff] {
            assert!(Request::decode(frame(1, opcode, 0)).is_err());
            assert!(Request::decode(frame(0, opcode, 0)).is_err());
        }
        assert!(
            Request::decode(Frame {
                service: 1,
                ..frame(1, NOP, 0)
            })
            .is_err()
        );
    }

    #[test]
    fn replies_echo_tag_and_opcode_with_status_in_the_parameter_byte() {
        let request = frame(9, ENTROPY, 0);
        let answer = reply(request, Status::Success, 0x1234_5678);
        assert_eq!(answer.mailbox().payload, 0x1234_5678_0036_0900);
        assert_eq!(notification(OS_ACTIVE, 0).mailbox().payload, 0x0015_0000);
    }
}
