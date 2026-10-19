//! The emulated sepOS active phase. Stela is the SEP, with its own keys.
//!
//! Once SEPROM accepts the delivered container under Stela's trust policy
//! (see [`super::firmware`]), this phase speaks the AP-facing boot-completion
//! protocol. `AppleSEPBooter::bootSEP` 0x2d73ddc..0x2d73e68 maps the aggregate
//! shared-memory buffer and sends its slave address and size on service 0xfe;
//! the SEP then notifies the control endpoint that the OS is active. That
//! notification drives `AppleSEPManager::notifyOSActive` 0x2d6c998 and
//! `_notifyOSActiveGated` 0x2d6b38c, which publishes `sepBootedOnce`
//! (0x2d6b558) and advances the manager to its booted state.
//! docs/research/sep.md owns the recovered contract.
//!
//! Application services (`sks`, `pnon`, `xars`/`xarm`, `scrd`, ...) are **not**
//! advertised here. Their discovery capacities and request/reply ABIs are not
//! recovered; a guessed advertisement would mislead the kernel into creating a
//! nub it then blocks on. Unmodeled inbound control traffic refuses explicitly
//! rather than fake a reply.
use super::super::asc::Message;
use super::{
    message::{self, Frame},
    shared::Region,
};
use alloc::vec::Vec;

/// Control endpoint (service 0) tag-0 opcodes, from
/// `AppleSEPControl::_cmsgAction` 0x2d84d90: 13 schedules OS-active, 16
/// announces wrapping-active, 17 requests an AP reply, 21 notifies OS-active
/// directly, 41 publishes a 32-bit field. The emulated SEP sends 21 once its
/// shared memory has been mapped.
const NOTIFY_OS_ACTIVE: u8 = 21;

#[derive(Default)]
pub struct SepOs {
    region: Option<Region>,
    os_active_sent: bool,
}

impl SepOs {
    pub fn new() -> Self {
        Self::default()
    }

    /// The shared-memory aggregate the AP mapped for the SEP, once received.
    pub fn region(&self) -> Option<Region> {
        self.region
    }

    /// Whether the SEP has reported its OS active to the control endpoint.
    pub fn os_active_sent(&self) -> bool {
        self.os_active_sent
    }

    /// Dispatch an AP-sent frame in the active phase. Boot (0xfe) records the
    /// shared-memory region and reports OS active once; other inbound traffic
    /// is not modeled and refuses, since replying would require ABIs that are
    /// not yet recovered.
    pub fn receive(&mut self, frame: Frame, outbox: &mut Vec<Message>) -> Result<(), &'static str> {
        match frame.service {
            message::BOOT => {
                let region = Region::from_message(frame.mailbox())?;
                self.region = Some(region);
                if !self.os_active_sent {
                    outbox.push(
                        Frame {
                            service: message::CONTROL,
                            tag: 0,
                            opcode: NOTIFY_OS_ACTIVE,
                            parameter: 0,
                            data: 0,
                        }
                        .mailbox(),
                    );
                    self.os_active_sent = true;
                }
                Ok(())
            }
            message::CONTROL => {
                Err("SEP control request handling is not modeled in the active phase")
            }
            message::DISCOVERY => {
                Err("SEP discovery is advertised by the SEP, not received from the AP")
            }
            message::ROM => Err("SEPROM commands are not valid once sepOS is active"),
            _ => Err("SEP application service is not modeled"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shm(address: u64, pages: u16) -> Message {
        Frame {
            service: message::BOOT,
            tag: 0,
            opcode: pages as u8,
            parameter: (pages >> 8) as u8,
            data: (address >> 12) as u32,
        }
        .mailbox()
    }

    #[test]
    fn mapping_shared_memory_reports_os_active_exactly_once() {
        let mut os = SepOs::new();
        assert!(!os.os_active_sent());
        let mut outbox = Vec::new();
        os.receive(
            Frame::from_mailbox(shm(0x1234_5000, 0x20)).unwrap(),
            &mut outbox,
        )
        .unwrap();
        assert_eq!(
            os.region(),
            Some(Region {
                address: 0x1234_5000,
                bytes: 0x20 << 12,
            })
        );
        assert_eq!(outbox.len(), 1);
        let active = Frame::from_mailbox(outbox[0]).unwrap();
        assert_eq!(
            (active.service, active.tag, active.opcode),
            (message::CONTROL, 0, NOTIFY_OS_ACTIVE)
        );
        assert!(os.os_active_sent());
        // A second shared-memory frame (wake remap) does not re-announce.
        let mut again = Vec::new();
        os.receive(
            Frame::from_mailbox(shm(0x2000_0000, 0x10)).unwrap(),
            &mut again,
        )
        .unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn unmodeled_inbound_traffic_refuses_without_faking_a_reply() {
        let mut os = SepOs::new();
        let mut outbox = Vec::new();
        for service in [message::CONTROL, message::DISCOVERY, message::ROM, 0x12] {
            assert!(
                os.receive(
                    Frame {
                        service,
                        tag: 1,
                        opcode: 0,
                        parameter: 0,
                        data: 0,
                    },
                    &mut outbox,
                )
                .is_err()
            );
        }
        assert!(outbox.is_empty());
        // A malformed shared-memory frame (zero length) is refused.
        assert!(
            os.receive(Frame::from_mailbox(shm(0x1000, 0)).unwrap(), &mut outbox)
                .is_err()
        );
    }
}
