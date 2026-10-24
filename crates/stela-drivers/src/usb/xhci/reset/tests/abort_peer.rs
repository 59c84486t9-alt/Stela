//! Actual xHC command/status/data TD peer for the narrow UAS task-management cut.
//! It decodes DMA wire bytes and emits native transfer events, never host results.
use super::*;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Fault {
    #[default]
    None,
    Response(u8),
    ShortResponse,
    WrongTag,
    OldStatus,
    Timeout,
    ShortCommand,
}
#[derive(Default)]
pub(super) struct State {
    pub(super) hold_command_event: bool,
    fault: Fault,
    requests: Vec<Vec<u8>>,
    pending_at_request: Vec<usize>,
    pending_at_response: Vec<usize>,
}
impl Hardware {
    pub(crate) fn uas_abort_fault(&mut self, fault: Fault) {
        self.uas_abort.fault = fault;
    }
    pub(crate) fn uas_hold_command_event(&mut self) {
        self.uas_abort.hold_command_event = true;
    }
    pub(crate) fn uas_abort_requests(&self) -> &[Vec<u8>] {
        &self.uas_abort.requests
    }
    pub(crate) fn uas_abort_pending_observations(&self) -> (&[usize], &[usize]) {
        (
            &self.uas_abort.pending_at_request,
            &self.uas_abort.pending_at_response,
        )
    }
    pub(crate) fn uas_pending_data(&self) -> usize {
        self.pending
            .keys()
            .filter(|(_, dci, _)| matches!(dci, 7 | 8))
            .count()
    }
    pub(super) fn abort_task_iu(&mut self, slot: u8, stream: u16, td: &Td, iu: &[u8]) {
        assert_eq!(stream, 0, "TMF command must use the ordinary command pipe");
        assert_eq!(iu.len(), 16);
        assert_eq!(iu[0], 5);
        assert_eq!(iu[1], 0);
        assert_eq!(iu[4], 1, "only ABORT TASK is implemented by this peer");
        assert_eq!(iu[5], 0);
        let task = self
            .task
            .as_ref()
            .expect("TMF without an actual active CDB");
        assert!(task.hang);
        let original = task.tag;
        assert_eq!(iu[6..8], original.to_be_bytes());
        assert_eq!(iu[8..16], task.lun);
        let tag = u16::from_be_bytes(iu[2..4].try_into().unwrap());
        assert_ne!(tag, 0);
        assert_ne!(tag, original);
        let status_stream = if self.speed >= SUPER_SPEED { tag } else { 0 };
        let status = self
            .pending
            .get(&(slot, 5, status_stream))
            .expect("TMF status TD must precede command")
            .clone();
        let pending = self.uas_pending_data();
        self.uas_abort.pending_at_request.push(pending);
        self.uas_abort.requests.push(iu.to_vec());
        self.pending.remove(&(slot, 2, 0));
        let short = self.uas_abort.fault == Fault::ShortCommand;
        self.event(
            td.trb,
            if short {
                SHORT_PACKET << 24 | 1
            } else {
                SUCCESS << 24
            },
            TRANSFER_EVENT,
            slot,
            2,
        );
        if self.uas_abort.fault == Fault::Timeout {
            return;
        }
        let mut reply = vec![4, 0, (tag >> 8) as u8, tag as u8, 0, 0, 0, 0];
        match self.uas_abort.fault {
            Fault::Response(code) => reply[7] = code,
            Fault::ShortResponse => {
                reply.pop();
            }
            Fault::WrongTag => reply[2..4].copy_from_slice(&original.to_be_bytes()),
            Fault::OldStatus => {
                reply = vec![
                    3,
                    0,
                    (original >> 8) as u8,
                    original as u8,
                    0,
                    0,
                    0x40,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ];
            }
            _ => {}
        }
        // A genuine FUNCTION COMPLETE retires only the device's task record.
        // It does not consume, write, complete or remove any xHC data TD.
        if self.uas_abort.fault == Fault::None {
            self.task = None;
            self.device_task = false;
        }
        let pending = self.uas_pending_data();
        self.uas_abort.pending_at_response.push(pending);
        self.pending.remove(&(slot, 5, status_stream));
        copy(status.buffer, &reply);
        self.event(
            status.trb,
            SHORT_PACKET << 24 | (status.length - reply.len()) as u32,
            TRANSFER_EVENT,
            slot,
            5,
        );
    }
}
