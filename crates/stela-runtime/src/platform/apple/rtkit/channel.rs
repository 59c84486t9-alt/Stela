//! Cooperative native mailbox ownership over one actual RTKit endpoint slot.
//! The AP drives start/receive through RTKit; the native service owns the other
//! half. Payloads are transferred, never echoed, synthesized or interpreted.
use super::Endpoint;
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::RefCell;

struct State {
    transport_alive: bool,
    service_alive: bool,
    started: bool,
    incoming: VecDeque<u64>,
    outgoing: VecDeque<u64>,
}

/// Move this actual endpoint half into the chosen RTKit slot. Retained stop or
/// disable preserves both queues; RTKit controls when polling/input may occur.
/// Reset remains unqualified until the owning service releases its resources.
pub struct NativeEndpoint(Rc<RefCell<State>>);

/// The same endpoint's native mailbox, retained by its service backend. No
/// public constructor accepts received payloads or replaces the shared queues.
pub struct Mailbox(Rc<RefCell<State>>);

/// Create one paired transport allocation; this does not enable an endpoint,
/// run its service, allocate AP memory or grant any device completion.
pub fn channel() -> (NativeEndpoint, Mailbox) {
    let state = Rc::new(RefCell::new(State {
        transport_alive: true,
        service_alive: true,
        started: false,
        incoming: VecDeque::new(),
        outgoing: VecDeque::new(),
    }));
    (NativeEndpoint(Rc::clone(&state)), Mailbox(state))
}

impl Mailbox {
    /// Actual unread AP messages retained by this paired transport. No payload
    /// or scheduling/arrival authority is created by this read-only query.
    pub fn pending_input(&self) -> bool {
        let state = self.0.borrow();
        state.transport_alive && !state.incoming.is_empty()
    }
    /// Actual endpoint-control start observed by the transport, not readiness
    /// of the protocol behind it. A disabled endpoint may retain queued work.
    pub fn started(&self) -> bool {
        let state = self.0.borrow();
        state.transport_alive && state.started
    }

    /// Commit one native-to-AP mailbox payload. The backend retires this exact
    /// operation after success; retries must not append it a second time.
    pub fn send(&mut self, payload: u64) -> Result<(), &'static str> {
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| "native mailbox is borrowed")?;
        if !state.transport_alive {
            return Err("native mailbox transport was abandoned");
        }
        state
            .outgoing
            .try_reserve(1)
            .map_err(|_| "native mailbox output allocation failed")?;
        state.outgoing.push_back(payload);
        Ok(())
    }

    /// Consume one payload that RTKit actually delivered from the AP. None is
    /// an empty inbox; it is never a fabricated acknowledgement or command.
    pub fn receive(&mut self) -> Result<Option<u64>, &'static str> {
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| "native mailbox is borrowed")?;
        if !state.transport_alive {
            return Err("native mailbox transport was abandoned");
        }
        Ok(state.incoming.pop_front())
    }
}

impl Endpoint for NativeEndpoint {
    fn start(&mut self, _: &mut Vec<u64>) -> Result<(), &'static str> {
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| "native mailbox is borrowed")?;
        if !state.service_alive {
            return Err("native mailbox service was abandoned");
        }
        state.started = true;
        Ok(())
    }

    fn receive(&mut self, payload: u64, _: &mut Vec<u64>) -> Result<(), &'static str> {
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| "native mailbox is borrowed")?;
        if !state.service_alive {
            return Err("native mailbox service was abandoned");
        }
        if !state.started {
            return Err("native mailbox input precedes endpoint start");
        }
        state
            .incoming
            .try_reserve(1)
            .map_err(|_| "native mailbox input allocation failed")?;
        state.incoming.push_back(payload);
        Ok(())
    }

    fn poll(&mut self, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        let mut state = self
            .0
            .try_borrow_mut()
            .map_err(|_| "native mailbox is borrowed")?;
        if !state.started {
            return if state.service_alive {
                Ok(())
            } else {
                Err("native mailbox service was abandoned")
            };
        }
        outbox
            .try_reserve(state.outgoing.len())
            .map_err(|_| "RTKit output allocation failed")?;
        outbox.extend(state.outgoing.drain(..));
        if state.service_alive {
            Ok(())
        } else {
            Err("native mailbox service was abandoned")
        }
    }
}

impl Drop for NativeEndpoint {
    fn drop(&mut self) {
        self.0.borrow_mut().transport_alive = false;
    }
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        self.0.borrow_mut().service_alive = false;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Firmware, Message, RtKit, SystemEndpoints};
    use super::*;
    use alloc::{boxed::Box, vec};

    #[test]
    fn native_mailbox_preserves_both_directions_without_echo_or_replay() {
        let (mut endpoint, mut mailbox) = channel();
        let mut output = Vec::new();
        mailbox.send(0x1234).unwrap();
        endpoint.poll(&mut output).unwrap();
        assert!(output.is_empty());
        assert!(!mailbox.started());
        assert!(endpoint.receive(9, &mut output).is_err());
        assert_eq!(mailbox.receive(), Ok(None));
        endpoint.start(&mut output).unwrap();
        assert!(mailbox.started());
        endpoint.receive(9, &mut output).unwrap();
        assert!(output.is_empty());
        assert_eq!(mailbox.receive(), Ok(Some(9)));
        assert_eq!(mailbox.receive(), Ok(None));
        endpoint.poll(&mut output).unwrap();
        assert_eq!(output, [0x1234]);
        endpoint.poll(&mut output).unwrap();
        assert_eq!(output, [0x1234]);
        assert!(endpoint.check_reset().is_err());
        drop(endpoint);
        assert!(!mailbox.started());
        assert!(mailbox.send(7).is_err());
        assert!(mailbox.receive().is_err());
    }

    #[test]
    fn actual_rtkit_enable_and_disable_gate_the_paired_system_mailbox() {
        let (endpoint, mut mailbox) = channel();
        let mut kit = RtKit::with_system_endpoints(
            Vec::new(),
            SystemEndpoints {
                trace: None,
                reporting: Some(Box::new(endpoint)),
            },
            crate::builds::DEFAULT.rtkit_version,
        )
        .unwrap();
        let mut output = Vec::new();
        kit.start(&mut output).unwrap();
        let receive = |kit: &mut RtKit, endpoint, payload| {
            kit.receive(Message { endpoint, payload }, &mut Vec::new())
        };
        receive(&mut kit, 0, 2 << 52 | 12 | 12 << 16).unwrap();
        receive(&mut kit, 0, 8 << 52 | 1 << 51).unwrap();
        mailbox.send(0x4567).unwrap();
        output.clear();
        kit.poll(&mut output).unwrap();
        assert!(output.is_empty());
        receive(&mut kit, 0, 5 << 52 | 4 << 32 | 2).unwrap();
        kit.poll(&mut output).unwrap();
        assert_eq!(
            output,
            vec![Message {
                endpoint: 4,
                payload: 0x4567
            }]
        );
        receive(&mut kit, 4, 0x89ab).unwrap();
        assert_eq!(mailbox.receive(), Ok(Some(0x89ab)));
        receive(&mut kit, 0, 5 << 52 | 4 << 32 | 1).unwrap();
        mailbox.send(0xcdef).unwrap();
        output.clear();
        kit.poll(&mut output).unwrap();
        assert!(output.is_empty());
        assert!(receive(&mut kit, 4, 0x89ab).is_err());
        receive(&mut kit, 0, 5 << 52 | 4 << 32 | 2).unwrap();
        kit.poll(&mut output).unwrap();
        assert_eq!(
            output,
            vec![Message {
                endpoint: 4,
                payload: 0xcdef
            }]
        );
    }

    #[test]
    fn abandoned_service_keeps_committed_output_and_refuses_new_input() {
        let (mut endpoint, mut mailbox) = channel();
        let mut output = Vec::new();
        endpoint.start(&mut output).unwrap();
        mailbox.send(123).unwrap();
        drop(mailbox);
        assert!(endpoint.receive(9, &mut output).is_err());
        assert!(endpoint.start(&mut output).is_err());
        assert!(endpoint.poll(&mut output).is_err());
        assert_eq!(output, [123]);
        assert!(endpoint.poll(&mut output).is_err());
        assert_eq!(output, [123]);
    }
}
