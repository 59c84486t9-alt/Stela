//! Independent immediate endpoint4 receive, not queued behind registration.
use super::super::platform::owner::Completion;
use super::{
    resources::{WaitKey, Wake},
    wire,
};
use alloc::rc::Rc;
use core::cell::RefCell;
use stela_contracts::bus::Access;

#[derive(Default)]
pub(super) struct Inbox {
    pub alive: bool,
    pub buffer_expected: bool,
    pub buffer: Option<wire::Buffer>,
    pub waiter: Option<WaitKey>,
    pub ack: bool,
    pub refresh: bool,
}
#[derive(Clone)]
pub struct Receiver(pub(super) Rc<RefCell<Inbox>>);
impl Receiver {
    /// Transport must preserve this actual endpoint session. The source wire
    /// has no nonce: a stale same-kind ACK cannot be authenticated by geometry.
    pub fn receive(
        &self,
        payload: u64,
        wake: &mut impl Wake,
        access: &mut Access<'_>,
    ) -> Completion<()> {
        if !self.0.borrow().alive {
            return Completion::Refused("IOReporting endpoint session is not live");
        }
        match wire::kind(payload) {
            0 => {
                let buffer = match wire::buffer(payload) {
                    Ok(b) => b,
                    Err(e) => return Completion::Refused(e),
                };
                let mut inbox = self.0.borrow_mut();
                if !inbox.buffer_expected || inbox.buffer.is_some() {
                    return Completion::Refused("unsolicited/replacement IOReporting AP buffer");
                }
                if buffer.bus == 0
                    || buffer.bytes < wire::REQUEST_BYTES
                    || buffer.bus.checked_add(buffer.bytes).is_none()
                {
                    return Completion::Refused("IOReporting AP allocation geometry is incomplete");
                }
                inbox.buffer = Some(buffer);
                inbox.buffer_expected = false;
                Completion::Retired {
                    value: (),
                    refusal: None,
                }
            }
            1 => {
                let result = wake.queue_refresh(access);
                if matches!(&result, Completion::Retired { .. }) {
                    self.0.borrow_mut().refresh = true;
                }
                result
            }
            2 => {
                let key = match self.0.borrow().waiter.clone() {
                    Some(key) => key,
                    None => {
                        return Completion::Refused(
                            "IOReporting publication ACK has no actual armed waiter",
                        );
                    }
                };
                let result = wake.publication_ack(&key, access);
                if matches!(&result, Completion::Retired { .. }) {
                    let mut inbox = self.0.borrow_mut();
                    inbox.ack = true;
                    inbox.waiter = None;
                }
                result
            }
            _ => Completion::Refused("unsupported IOReporting AP message kind"),
        }
    }
}
