//! The recovered SEPROM command prefix, behind the common ASC mailbox.
//!
//! `AppleSEPBooter::bootSEP` 0x2d738d4..0x2d74030, `_bootAction`
//! 0x2d72ca8..0x2d7309c and `generateROMNonce` 0x2d74030..0x2d742c4
//! (26A434 kernel file offsets). See docs/research/sep.md.
//!
//! Stela hands off a running ROM in state 1, with no nonce. BootTz0
//! initializes native private state, inaccessible to AP DMA, and reaches
//! state 2 immediately. No Apple firmware is executed. Image acceptance,
//! resume, ART, TMM and patches remain explicit refusals; no sepOS active
//! or discovery notification can be manufactured by this prefix.
use super::super::asc::{Firmware, Message};
use super::{
    Entropy,
    message::{self, Frame},
};
use alloc::{boxed::Box, vec::Vec};

const PING: u8 = 1;
const STATUS: u8 = 2;
const GENERATE_NONCE: u8 = 3;
const NONCE_WORD: u8 = 4;
const BOOT_TZ0: u8 = 5;
const BOOT_IMAGE: u8 = 6;
const SEPART: u8 = 7;
const RESUME: u8 = 8;
const RANDOM: u8 = 16;
const CAPTURE_IBIC: u8 = 30;
const IBIC_WORD: u8 = 31;
const TMM: u8 = 36;
const PATCH: u8 = 37;
const PONG: u8 = 101;
const STATUS_VALUE: u8 = 210;
const NONCE_GENERATED: u8 = 103;
const NONCE_VALUE: u8 = 104;
const TZ0_READY: u8 = 105;
const RANDOM_VALUE: u8 = 116;
/// `_bootAction` 0x2d72e78 tolerates error opcode 0 with data 30,
/// meaning capture-iBIC unsupported; `_captureiBICKCV` 0x2d73568 skips
/// retrieval unless it receives opcode 130 (key available).
const IBIC_UNAVAILABLE: u8 = 0;
const NONCE_BYTES: usize = 20;
const NONCE_BITS: u32 = (NONCE_BYTES * 8) as u32;
const WORD_BYTES: usize = 4;
const IMAGE_PAGE_SHIFT: u32 = 12;
const FIRMWARE_SEPI: u8 = 0;
const FIRMWARE_RSEP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Rom = 1,
    Tz0 = 2,
}

/// A boot image address delivered by opcode 6. This is a SEP IOVA, not a PA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageRequest {
    pub address: u64,
    pub parameter: u8,
}

pub struct Rom {
    entropy: Box<dyn Entropy>,
    started: bool,
    state: State,
    nonce: Option<[u8; NONCE_BYTES]>,
    image: Option<ImageRequest>,
}

impl Rom {
    pub fn new(entropy: Box<dyn Entropy>) -> Self {
        Self {
            entropy,
            started: false,
            state: State::Rom,
            nonce: None,
            image: None,
        }
    }

    /// The SEP's entropy source, which sepOS keeps using once it is active.
    pub fn entropy(&mut self) -> &mut dyn Entropy {
        &mut *self.entropy
    }

    pub fn image_request(&self) -> Option<ImageRequest> {
        self.image
    }

    /// The transfer boundary measured and accepted the delivered container
    /// under Stela's own trust policy; clear the pending request so SEPROM
    /// stops offering it. Acceptance and the reply are the firmware engine's
    /// decision, not a ROM command effect.
    pub fn accept_image(&mut self) {
        self.image = None;
    }

    fn command(&mut self, frame: Frame) -> Result<Option<Frame>, &'static str> {
        if !self.started {
            return Err("SEPROM has not started");
        }
        if self.image.is_some() {
            return Err("SEPROM image authentication is pending; sepOS is not active");
        }
        if frame.service != message::ROM {
            return Err(match frame.service {
                message::CONTROL => "SEP control service requires authenticated native sepOS",
                message::DISCOVERY => "SEP discovery requires authenticated native sepOS",
                message::BOOT => "SEP shared-memory/timebase boot protocol is not modeled",
                _ => "SEP application service is not modeled",
            });
        }
        let reply = |opcode, parameter, data| {
            Some(Frame {
                service: message::ROM,
                // The AP's ROM handler does not check reply tags. Echo is a
                // Stela transport choice, not a recovered ROM requirement.
                tag: frame.tag,
                opcode,
                parameter,
                data,
            })
        };
        match frame.opcode {
            PING | STATUS | GENERATE_NONCE | RANDOM | CAPTURE_IBIC
                if frame.parameter != 0 || frame.data != 0 =>
            {
                Err("SEPROM command has unsupported parameter or data")
            }
            PING => Ok(reply(PONG, 0, 0)),
            STATUS => Ok(reply(STATUS_VALUE, 0, self.state as u32)),
            GENERATE_NONCE => {
                let mut nonce = [0; NONCE_BYTES];
                self.entropy.fill(&mut nonce)?;
                self.nonce = Some(nonce);
                Ok(reply(NONCE_GENERATED, 0, NONCE_BITS))
            }
            NONCE_WORD => {
                if frame.data != 0 {
                    return Err("SEPROM nonce-word data must be zero");
                }
                let nonce = self
                    .nonce
                    .as_ref()
                    .ok_or("SEPROM nonce has not been generated")?;
                let start = usize::from(frame.parameter) * WORD_BYTES;
                let bytes = nonce
                    .get(start..start + WORD_BYTES)
                    .ok_or("SEPROM nonce word index is out of range")?;
                Ok(reply(
                    NONCE_VALUE,
                    0,
                    u32::from_le_bytes(bytes.try_into().expect("one word")),
                ))
            }
            RANDOM => {
                // m1n1 src/sep.c: opcode 16 -> 116 with 32 entropy bits.
                let mut bytes = [0; WORD_BYTES];
                self.entropy.fill(&mut bytes)?;
                Ok(reply(RANDOM_VALUE, 0, u32::from_le_bytes(bytes)))
            }
            CAPTURE_IBIC => Ok(reply(IBIC_UNAVAILABLE, 0, u32::from(CAPTURE_IBIC))),
            IBIC_WORD => Err("Stela's SEPROM exposes no Apple iBIC key"),
            BOOT_TZ0 => {
                if self.state != State::Rom
                    || frame.data != 0
                    || ![FIRMWARE_SEPI, FIRMWARE_RSEP].contains(&frame.parameter)
                {
                    return Err("SEPROM BootTz0 state, firmware type or data is unsupported");
                }
                self.state = State::Tz0;
                Ok(reply(TZ0_READY, 0, 0))
            }
            BOOT_IMAGE => {
                if self.state != State::Tz0 {
                    return Err("SEPROM image load before BootTz0");
                }
                // The lower parameter nibble is the firmware type. Slot
                // support in the upper nibble is a Sandcat protocol, not
                // evidence that this ROM can authenticate a slotted image.
                if ![FIRMWARE_SEPI, FIRMWARE_RSEP].contains(&frame.parameter) || frame.data == 0 {
                    return Err("SEPROM image type, slot or address is unsupported");
                }
                self.image = Some(ImageRequest {
                    address: u64::from(frame.data) << IMAGE_PAGE_SHIFT,
                    parameter: frame.parameter,
                });
                // Accepted for DMA inspection only. No boot-acceptance
                // reply: the board's transfer boundary must surface the
                // authentication refusal after reading through dart-sep.
                Ok(None)
            }
            SEPART => Err("SEPROM SEPART validation is not modeled"),
            RESUME => Err("SEPROM resume requires persisted authenticated sepOS state"),
            TMM => Err("SEPROM TMM manifest authentication is not modeled"),
            PATCH => Err("SEPROM patch authentication is not modeled"),
            _ => Err("SEPROM command is not modeled"),
        }
    }
}

impl Firmware for Rom {
    fn start(&mut self, _: &mut Vec<Message>) -> Result<(), &'static str> {
        if self.started {
            return Err("SEPROM restart is not modeled");
        }
        self.started = true;
        Ok(())
    }

    fn receive(&mut self, message: Message, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        let frame = Frame::from_mailbox(message)?;
        if let Some(reply) = self.command(frame)? {
            outbox.push(reply.mailbox());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Sequence(u8);
    impl Entropy for Sequence {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), &'static str> {
            for byte in bytes {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    fn booted() -> Rom {
        let mut rom = Rom::new(Box::new(Sequence(1)));
        let mut replies = Vec::new();
        rom.start(&mut replies).unwrap();
        assert!(replies.is_empty(), "SEPROM sends no RTKit HELLO");
        rom
    }

    fn send(
        rom: &mut Rom,
        opcode: u8,
        parameter: u8,
        data: u32,
    ) -> Result<Vec<Frame>, &'static str> {
        let mut outbox = Vec::new();
        rom.receive(
            Frame {
                service: message::ROM,
                tag: 1,
                opcode,
                parameter,
                data,
            }
            .mailbox(),
            &mut outbox,
        )?;
        Ok(outbox
            .into_iter()
            .map(|m| Frame::from_mailbox(m).unwrap())
            .collect())
    }

    #[test]
    fn native_rom_status_tz0_and_image_never_claim_sepos_is_booted() {
        let mut rom = booted();
        let status = send(&mut rom, STATUS, 0, 0).unwrap()[0];
        assert_eq!((status.opcode, status.data), (210, 1));
        assert!(send(&mut rom, BOOT_IMAGE, 0, 1).is_err());
        assert!(rom.image_request().is_none());
        assert!(send(&mut rom, BOOT_TZ0, 2, 0).is_err());
        assert_eq!(send(&mut rom, STATUS, 0, 0).unwrap()[0].data, 1);
        // `_bootAction` accepts Tz0 at opcode 105, not the SEPART reply 107.
        assert_eq!(send(&mut rom, BOOT_TZ0, 1, 0).unwrap()[0].opcode, 105);
        assert_eq!(send(&mut rom, STATUS, 0, 0).unwrap()[0].data, 2);
        assert!(send(&mut rom, BOOT_TZ0, 0, 0).is_err());
        assert!(send(&mut rom, BOOT_IMAGE, 0x21, 1).is_err());
        assert!(send(&mut rom, BOOT_IMAGE, 1, 0).is_err());
        assert!(send(&mut rom, BOOT_IMAGE, 1, 0x12345).unwrap().is_empty());
        assert_eq!(
            rom.image_request(),
            Some(ImageRequest {
                address: 0x1234_5000,
                parameter: 1
            })
        );
        assert!(send(&mut rom, STATUS, 0, 0).is_err());
        assert!(rom.start(&mut Vec::new()).is_err());
    }

    #[test]
    fn nonce_generation_has_a_lifetime_and_five_little_endian_words() {
        let mut rom = booted();
        assert!(send(&mut rom, NONCE_WORD, 0, 0).is_err());
        let generated = send(&mut rom, GENERATE_NONCE, 0, 0).unwrap();
        assert_eq!(
            (generated[0].opcode, generated[0].data),
            (NONCE_GENERATED, 160)
        );
        for word in 0..5 {
            let reply = send(&mut rom, NONCE_WORD, word, 0).unwrap();
            let first = 1 + 4 * u32::from(word);
            assert_eq!(
                reply[0].data,
                first | (first + 1) << 8 | (first + 2) << 16 | (first + 3) << 24
            );
        }
        assert!(send(&mut rom, NONCE_WORD, 5, 0).is_err());
        assert!(send(&mut rom, NONCE_WORD, 0, 1).is_err());
        send(&mut rom, GENERATE_NONCE, 0, 0).unwrap();
        assert_eq!(
            send(&mut rom, NONCE_WORD, 0, 0).unwrap()[0].data,
            0x1817_1615
        );
        assert_eq!(send(&mut rom, RANDOM, 0, 0).unwrap()[0].data, 0x2c2b_2a29);
    }

    #[test]
    fn entropy_failure_does_not_replace_the_previous_nonce_or_send_a_reply() {
        struct Partial;
        impl Entropy for Partial {
            fn fill(&mut self, bytes: &mut [u8]) -> Result<(), &'static str> {
                bytes[0] = 99;
                Err("entropy unavailable")
            }
        }
        let mut rom = booted();
        send(&mut rom, GENERATE_NONCE, 0, 0).unwrap();
        let before = send(&mut rom, NONCE_WORD, 0, 0).unwrap();
        rom.entropy = Box::new(Partial);
        assert_eq!(
            send(&mut rom, GENERATE_NONCE, 0, 0),
            Err("entropy unavailable")
        );
        assert_eq!(send(&mut rom, NONCE_WORD, 0, 0).unwrap(), before);
        assert!(send(&mut rom, RANDOM, 0, 0).is_err());
    }

    #[test]
    fn unmodeled_security_operations_and_services_are_not_echoed() {
        let mut rom = booted();
        let unavailable = send(&mut rom, CAPTURE_IBIC, 0, 0).unwrap()[0];
        assert_eq!((unavailable.opcode, unavailable.data), (0, 30));
        assert_ne!(
            unavailable.opcode, 130,
            "130 tells the AP to retrieve iBIC key words"
        );
        assert_eq!(send(&mut rom, PING, 0, 0).unwrap()[0].opcode, PONG);
        for opcode in [SEPART, RESUME, IBIC_WORD, TMM, PATCH, 255] {
            assert!(send(&mut rom, opcode, 0, 0).is_err());
        }
        assert!(send(&mut rom, PING, 1, 0).is_err());
        for service in [message::CONTROL, message::DISCOVERY, message::BOOT, 0x12] {
            let mut replies = Vec::new();
            assert!(
                rom.receive(
                    Frame {
                        service,
                        tag: 1,
                        opcode: 1,
                        parameter: 0,
                        data: 0
                    }
                    .mailbox(),
                    &mut replies
                )
                .is_err()
            );
            assert!(replies.is_empty());
        }
    }
}
