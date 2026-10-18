//! SEP payload frames, distinct from the ASC endpoint word.
//!
//! `AppleSEPManager::_sendMessageGated`, kernel file 0x2d6ac90..0x2d6ad14:
//! four byte fields followed by a data word, sent on ASC endpoint zero.
use super::super::asc::Message;

pub const TRANSPORT: u8 = 0;
pub const CONTROL: u8 = 0;
pub const DISCOVERY: u8 = 0xfd;
pub const BOOT: u8 = 0xfe;
pub const ROM: u8 = 0xff;
const TAG_SHIFT: u32 = 8;
const OPCODE_SHIFT: u32 = 16;
const PARAMETER_SHIFT: u32 = 24;
const DATA_SHIFT: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    pub service: u8,
    pub tag: u8,
    pub opcode: u8,
    pub parameter: u8,
    pub data: u32,
}

impl Frame {
    pub const fn from_payload(payload: u64) -> Self {
        Self {
            service: payload as u8,
            tag: (payload >> TAG_SHIFT) as u8,
            opcode: (payload >> OPCODE_SHIFT) as u8,
            parameter: (payload >> PARAMETER_SHIFT) as u8,
            data: (payload >> DATA_SHIFT) as u32,
        }
    }

    pub fn from_mailbox(message: Message) -> Result<Self, &'static str> {
        if message.endpoint != TRANSPORT {
            return Err("SEP messages require ASC endpoint zero; service ID is in the payload");
        }
        Ok(Self::from_payload(message.payload))
    }

    pub const fn mailbox(self) -> Message {
        Message {
            endpoint: TRANSPORT,
            payload: self.service as u64
                | (self.tag as u64) << TAG_SHIFT
                | (self.opcode as u64) << OPCODE_SHIFT
                | (self.parameter as u64) << PARAMETER_SHIFT
                | (self.data as u64) << DATA_SHIFT,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sep_service_is_in_the_payload_not_the_asc_endpoint() {
        let frame = Frame::from_mailbox(Message {
            endpoint: 0,
            payload: 0x1234_5678_ab06_01ff,
        })
        .unwrap();
        assert_eq!(frame.service, ROM);
        assert_eq!(frame.tag, 1);
        assert_eq!(frame.opcode, 6);
        assert_eq!(frame.parameter, 0xab);
        assert_eq!(frame.data, 0x1234_5678);
        assert_eq!(frame.mailbox().payload, 0x1234_5678_ab06_01ff);
        assert!(
            Frame::from_mailbox(Message {
                endpoint: ROM,
                payload: 0
            })
            .is_err()
        );
    }
}
