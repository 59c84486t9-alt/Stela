//! One application-service request, as a native service sees it: the OOL
//! bytes it reads and writes, and how a request it refuses is answered.
//!
//! A refusal carries the service protocol's own failure answer. Graceful
//! mode sends it and strict mode stops instead (docs/design/runtime.md
//! "Unsupported operations"). Once a request may have taken effect, such as
//! a durable commit whose acknowledgement was lost, a failure answer would
//! be as untrue as a success, so that refusal carries none and the AP
//! client's own timeout runs.
use super::message::Frame;
use alloc::vec::Vec;

/// A request's OOL buffers: input is read in order from the start of the
/// AP-to-SEP buffer, and the result is written at the start of the
/// SEP-to-AP one.
pub trait Payload {
    fn input(&mut self, bytes: &mut [u8]) -> Result<(), &'static str>;
    fn output(&mut self, bytes: &[u8]) -> Result<(), &'static str>;
}

/// The protocol's failure answer to a request: its reply frame and the
/// SEP-to-AP bytes, if any, that precede it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub frame: Frame,
    pub output: Vec<u8>,
}

impl Answer {
    /// A failure answered by its reply frame alone.
    pub fn frame(frame: Frame) -> Self {
        Self {
            frame,
            output: Vec::new(),
        }
    }
}

/// A request the service did not complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub reason: &'static str,
    /// The failure answer, or `None` when the request may have taken effect.
    pub answer: Option<Answer>,
}

impl Refusal {
    pub fn answered(reason: &'static str, answer: Answer) -> Self {
        Self {
            reason,
            answer: Some(answer),
        }
    }

    pub fn unanswerable(reason: &'static str) -> Self {
        Self {
            reason,
            answer: None,
        }
    }
}
