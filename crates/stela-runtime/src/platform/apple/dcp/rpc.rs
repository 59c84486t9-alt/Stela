//! The coprocessor side of the DCP link ([`super::link`]): bring-up, the
//! AP's calls into the coprocessor, the callbacks the coprocessor makes into
//! the AP (on its own streams or nested inside the AP's calls) and their
//! answers, through the shared region the AP announces.
//!
//! Every stream is a stack. The AP opens one of its streams with a call
//! (`opens` set); while the coprocessor serves it, the method may call the
//! AP back on the same stream, writing into that stream's other buffer, and
//! the AP, serving that callback on the same thread, may call in again
//! without opening anything (`rpc_nested_callee` 0x3d7d6a4 and
//! `link_get_stream_by_thread_id_gated` 0x3d7d134, which reuses the
//! thread's stream). The coprocessor's own callbacks open its streams the
//! same way. Each side allocates its payloads in its buffer of the stream
//! as a stack at the announced alignment, and frees them when answered.
//!
//! A method is a [`Service`] whose [`Step`] either returns the call's
//! output or makes a callback first and continues with the AP's output.
//! Anything the AP does that its own library would not (a call on a stream
//! that is not waiting for one, an answer nobody waits for, a payload
//! outside its buffer, a length that disagrees with its header) refuses by
//! name rather than being repaired.
//! Accepted calls and taken callbacks are held native owners until their
//! entire transfer commits. A DMA retry never re-runs a method, takes another
//! callback or consumes a continuation before its reply read succeeds. An
//! external reply wait owns a stream but is not runnable DMA. Unsafe endpoint
//! restart/cancellation refuses rather than discarding those effects.
use super::link::{
    self, ALIGNMENT, HEADER_BYTES, Header, Owner, RegionHeader, Rpc, STREAM_BYTES, STREAMS, Stream,
    Word,
};
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// The bus addresses the coprocessor reaches through its DART.
pub trait Bus {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), &'static str>;
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), &'static str>;
}

/// How a method continues with the AP's output of its callback.
pub type Continuation<S> = Box<dyn FnOnce(&mut S, &[u8]) -> Result<Step<S>, &'static str>>;
/// What a top-level callback does with the AP's output.
pub type Finish<S> = Box<dyn FnOnce(&mut S, &[u8]) -> Result<(), &'static str>>;

/// The next step of a method the coprocessor serves.
pub enum Step<S> {
    /// The call's output, exactly as long as the AP's header says.
    Return(Vec<u8>),
    /// Call the AP back first.
    Call {
        tag: [u8; 4],
        input: Vec<u8>,
        output: u32,
        then: Continuation<S>,
    },
}

/// A callback the coprocessor makes on its own initiative.
pub struct Callback<S> {
    pub tag: [u8; 4],
    pub input: Vec<u8>,
    pub output: u32,
    pub then: Finish<S>,
}

/// The methods the coprocessor serves.
pub trait Service: Sized + 'static {
    /// Begin the AP's call `tag` with `input`; its output is `output` bytes.
    /// A refusal leaves architectural effects uncommitted. An accepted Step
    /// transfers native result ownership to the link before any output DMA.
    fn call(&mut self, tag: [u8; 4], input: &[u8], output: u32)
    -> Result<Step<Self>, &'static str>;
    /// Whether the service has a callback to make.
    fn callback_pending(&self) -> bool {
        false
    }
    /// The callback the coprocessor makes next, once the link is up.
    fn take_callback(&mut self) -> Option<Callback<Self>> {
        None
    }
}

/// A callback in flight: where the coprocessor wrote it and what continues.
struct Outgoing<S> {
    offset: u32,
    header: Header,
    slot: u32,
    resume: Resume<S>,
}

enum Resume<S> {
    Method(Continuation<S>),
    Callback(Finish<S>),
    /// The continuation ran once and refused; preserve its in-flight identity.
    Refused(&'static str),
}

/// One entry of a stream's stack.
enum Frame<S> {
    /// An AP call being served, and the callback it waits on, if any.
    Serving {
        call: Rpc,
        header: Header,
        waiting: Option<Outgoing<S>>,
    },
    /// A callback the coprocessor opened this stream with.
    Calling(Outgoing<S>),
}

impl<S> Frame<S> {
    fn waiting(&self) -> bool {
        matches!(
            self,
            Frame::Serving {
                waiting: Some(_),
                ..
            } | Frame::Calling(_)
        )
    }
}

#[derive(Default)]
struct Lane<S> {
    frames: Vec<Frame<S>>,
    /// The top of the coprocessor's allocations in its buffer of the stream.
    cursor: u32,
}

/// The link's bring-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Hello sent; the AP has not announced its region.
    Hello,
    /// Region known and ready sent.
    Up { region: u64 },
}

/// Native method/callback ownership survives retryable transport DMA.
enum Pending<S> {
    Method {
        stream: Stream,
        step: Step<S>,
    },
    Callback {
        stream: Stream,
        callback: Callback<S>,
    },
}

/// The coprocessor end of one link.
pub struct Link<S> {
    service: S,
    /// The DART window base the AP's 32-bit DVAs lie in, when it restricts
    /// them (`truncate-dvas`).
    window: Option<u64>,
    /// The interface version it announces and hashes into its ready CRC.
    version: u32,
    phase: Phase,
    heap: Option<RegionHeader>,
    /// Words from the AP waiting for the DMA step.
    incoming: VecDeque<u64>,
    pending: Option<Pending<S>>,
    pending_input: bool,
    lanes: [Lane<S>; 2 * STREAMS as usize],
}

fn lane_index(stream: Stream) -> usize {
    let side = match stream.owner {
        Owner::Ap => 0,
        Owner::Dcp => STREAMS as usize,
    };
    side + usize::from(stream.index)
}

fn align(bytes: u32) -> Option<u32> {
    bytes.checked_next_multiple_of(u32::from(ALIGNMENT))
}

impl<S: Service> Link<S> {
    /// A link announcing interface `version` (the build's
    /// `dcp_link_version`).
    pub fn new(service: S, window: Option<u64>, version: u32) -> Self {
        Self {
            service,
            window,
            version,
            phase: Phase::Hello,
            heap: None,
            incoming: VecDeque::new(),
            pending: None,
            pending_input: false,
            lanes: core::array::from_fn(|_| Lane {
                frames: Vec::new(),
                cursor: 0,
            }),
        }
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    pub fn service_mut(&mut self) -> &mut S {
        &mut self.service
    }

    /// The heap the AP lent the coprocessor, once announced.
    #[cfg(test)]
    pub fn heap(&self) -> Option<RegionHeader> {
        self.heap
    }

    pub fn is_up(&self) -> bool {
        matches!(self.phase, Phase::Up { .. })
    }

    /// The endpoint started: the coprocessor says hello.
    pub fn start(&mut self) -> Result<u64, &'static str> {
        if !self.incoming.is_empty()
            || self.pending.is_some()
            || self.lanes.iter().any(|lane| !lane.frames.is_empty())
            || self.is_up() && self.service.callback_pending()
        {
            return Err("DCP link restart with unfinished RPC ownership");
        }
        self.phase = Phase::Hello;
        self.heap = None;
        Ok(Word::Hello {
            version: u64::from(self.version),
        }
        .encode())
    }

    pub fn retained_idle(&self) -> bool {
        self.incoming.is_empty()
            && self.pending.is_none()
            && self.lanes.iter().all(|lane| lane.frames.is_empty())
            && !self.service.callback_pending()
    }

    /// Lose a cold-reset link session only after every accepted input,
    /// continuation and callback has relinquished ownership. Guest RAM is
    /// not erased and no completion word is synthesized.
    pub(super) fn reset(&mut self) -> Result<(), &'static str> {
        if !self.retained_idle() {
            return Err("DCP physical reset with unfinished RPC ownership");
        }
        self.phase = Phase::Hello;
        self.heap = None;
        self.pending_input = false;
        for lane in &mut self.lanes {
            lane.cursor = 0;
        }
        Ok(())
    }

    /// A word from the AP, served at the next DMA step.
    pub fn receive(&mut self, word: u64) {
        self.incoming.push_back(word);
    }

    /// Whether the DMA step has work.
    pub fn pending(&self) -> bool {
        self.pending.is_some()
            || !self.incoming.is_empty()
            || self.is_up() && self.free_stream().is_some() && self.service.callback_pending()
    }

    /// The bus address of a DVA the AP gave the coprocessor.
    fn bus(&self, dva: u64) -> u64 {
        match self.window {
            Some(base) if dva < base => base + dva,
            _ => dva,
        }
    }

    /// Serve every waiting word and start any callback the service has,
    /// pushing the words the coprocessor sends to `outbox`.
    pub fn dma(&mut self, bus: &mut dyn Bus, outbox: &mut Vec<u64>) -> Result<(), &'static str> {
        if self.pending.is_some() {
            self.flush_pending(bus, outbox)?;
        }
        while let Some(word) = self.incoming.front().copied() {
            self.serve(bus, word, outbox)?;
            if self.pending.is_some() {
                self.pending_input = true;
                self.flush_pending(bus, outbox)?;
            } else {
                self.incoming.pop_front();
            }
        }
        while self.is_up()
            && let Some(index) = self.free_stream()
            && let Some(callback) = self.service.take_callback()
        {
            self.pending = Some(Pending::Callback {
                stream: Stream {
                    owner: Owner::Dcp,
                    index,
                },
                callback,
            });
            self.pending_input = false;
            self.flush_pending(bus, outbox)?;
        }
        Ok(())
    }

    fn flush_pending(
        &mut self,
        bus: &mut dyn Bus,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        self.commit_pending(bus, outbox)?;
        if self.pending_input {
            self.incoming.pop_front().expect("accepted RPC input");
            self.pending_input = false;
        }
        Ok(())
    }

    fn free_stream(&self) -> Option<u8> {
        (0..STREAMS).find(|&index| {
            self.lanes[lane_index(Stream {
                owner: Owner::Dcp,
                index,
            })]
            .frames
            .is_empty()
        })
    }

    fn region(&self) -> Result<u64, &'static str> {
        match self.phase {
            Phase::Up { region } => Ok(region),
            Phase::Hello => Err("DCP link RPC before the AP announced its region"),
        }
    }

    fn serve(
        &mut self,
        bus: &mut dyn Bus,
        word: u64,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        match Word::decode(word)? {
            Word::Region { dva } => {
                if self.lanes.iter().any(|lane| !lane.frames.is_empty()) {
                    return Err("DCP link region re-announced with calls in flight");
                }
                let region = self.bus(dva);
                let mut bytes = [0; RegionHeader::BYTES];
                bus.read(region, &mut bytes)?;
                self.heap = Some(RegionHeader::parse(&bytes)?);
                for lane in &mut self.lanes {
                    lane.cursor = 0;
                }
                self.phase = Phase::Up { region };
                outbox.push(
                    Word::Ready {
                        crc: link::interface_crc(self.version),
                        alignment: ALIGNMENT,
                    }
                    .encode(),
                );
                Ok(())
            }
            Word::Hello { .. } => Err("DCP link hello came from the AP"),
            Word::Ready { .. } => {
                Err("DCP link ready came from the AP, which only the owner-1 side sends")
            }
            Word::Rpc(rpc) if rpc.answer => self.answered(bus, rpc),
            Word::Rpc(rpc) => self.called(bus, rpc),
        }
    }

    /// The AP called a method.
    fn called(&mut self, bus: &mut dyn Bus, call: Rpc) -> Result<(), &'static str> {
        let region = self.region()?;
        let lane = &self.lanes[lane_index(call.stream)];
        let fresh = call.stream.owner == Owner::Ap && lane.frames.is_empty();
        if call.opens != fresh {
            return Err(if call.opens {
                "DCP link call opens a stream already in use"
            } else {
                "DCP link call nests in a stream that waits for no callback"
            });
        }
        if !fresh && !lane.frames.last().is_some_and(Frame::waiting) {
            return Err("DCP link call nests in a stream that waits for no callback");
        }
        let length = u32::from(call.length);
        if length < HEADER_BYTES || u32::from(call.offset) + length > STREAM_BYTES {
            return Err("DCP link call payload lies outside its stream buffer");
        }
        let payload = region + call.stream.buffer_of(Owner::Ap) + u64::from(call.offset);
        let mut bytes = [0; HEADER_BYTES as usize];
        bus.read(payload, &mut bytes)?;
        let header = Header::parse(&bytes);
        if header.length() != Some(call.length) {
            return Err("DCP link call length differs from its header");
        }
        let mut input = vec![0; header.input as usize];
        bus.read(payload + u64::from(HEADER_BYTES), &mut input)?;
        self.lanes[lane_index(call.stream)]
            .frames
            .push(Frame::Serving {
                call,
                header,
                waiting: None,
            });
        let step = match self.service.call(header.tag, &input, header.output) {
            Ok(step) => step,
            Err(error) => {
                self.lanes[lane_index(call.stream)].frames.pop();
                return Err(error);
            }
        };
        self.pending = Some(Pending::Method {
            stream: call.stream,
            step,
        });
        Ok(())
    }

    /// Validate and publish a native result. All fallible checks
    /// and DMA precede stream-stack changes and the corresponding mailbox word.
    fn commit_pending(
        &mut self,
        bus: &mut dyn Bus,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        let region = self.region()?;
        let pending = self.pending.as_ref().expect("pending RPC work");
        if let Pending::Method {
            stream,
            step: Step::Return(output),
        } = pending
        {
            let lane = &self.lanes[lane_index(*stream)];
            let Some(Frame::Serving {
                call,
                header,
                waiting: None,
            }) = lane.frames.last()
            else {
                return Err("DCP link method continued outside the call it serves");
            };
            if output.len() != header.output as usize {
                return Err("DCP method output size differs from the AP's header");
            }
            let at = region
                + stream.buffer_of(Owner::Ap)
                + u64::from(call.offset)
                + u64::from(HEADER_BYTES + header.input);
            bus.write(at, output)?;
            let (stream, answer) = (*stream, call.answer());
            self.lanes[lane_index(stream)].frames.pop();
            self.pending = None;
            outbox.push(Word::Rpc(answer).encode());
            return Ok(());
        }
        let (stream, opens, tag, input, output) = match pending {
            Pending::Method {
                stream,
                step: Step::Call {
                    tag, input, output, ..
                },
            } => (*stream, false, *tag, input, *output),
            Pending::Callback { stream, callback } => (
                *stream,
                true,
                callback.tag,
                &callback.input,
                callback.output,
            ),
            _ => unreachable!("return handled above"),
        };
        let header = Header {
            tag,
            input: u32::try_from(input.len()).map_err(|_| "DCP callback input exceeds a stream")?,
            output,
        };
        let length = header
            .length()
            .ok_or("DCP callback exceeds a message length")?;
        let slot = align(u32::from(length)).ok_or("DCP callback exceeds a stream")?;
        let lane = &self.lanes[lane_index(stream)];
        let offset = lane.cursor;
        if offset + slot > STREAM_BYTES {
            return Err("DCP callback overflows its stream buffer");
        }
        match lane.frames.last() {
            Some(Frame::Serving { waiting: None, .. }) if !opens => (),
            None if opens => (),
            _ => return Err("DCP callback made on a stream not serving its caller"),
        }
        let at = region + stream.buffer_of(Owner::Dcp) + u64::from(offset);
        bus.write(at, &header.bytes())?;
        bus.write(at + u64::from(HEADER_BYTES), input)?;
        let resume = match self.pending.take().expect("published RPC callback") {
            Pending::Method {
                step: Step::Call { then, .. },
                ..
            } => Resume::Method(then),
            Pending::Callback { callback, .. } => Resume::Callback(callback.then),
            _ => unreachable!("callback publication"),
        };
        let outgoing = Outgoing {
            offset,
            header,
            slot,
            resume,
        };
        let lane = &mut self.lanes[lane_index(stream)];
        lane.cursor += slot;
        if opens {
            lane.frames.push(Frame::Calling(outgoing));
        } else if let Some(Frame::Serving { waiting, .. }) = lane.frames.last_mut() {
            *waiting = Some(outgoing);
        }
        outbox.push(
            Word::Rpc(Rpc {
                answer: false,
                stream,
                opens,
                offset: offset as u16,
                length,
                token: 0,
            })
            .encode(),
        );
        Ok(())
    }

    /// The AP answered a callback.
    fn answered(&mut self, bus: &mut dyn Bus, answer: Rpc) -> Result<(), &'static str> {
        let region = self.region()?;
        if answer.offset != 0 || answer.length != 0 {
            return Err("DCP link answer carries a payload");
        }
        let lane = &self.lanes[lane_index(answer.stream)];
        let outgoing = match lane.frames.last() {
            Some(Frame::Serving {
                waiting: Some(outgoing),
                ..
            }) => outgoing,
            Some(Frame::Calling(outgoing)) => outgoing,
            _ => return Err("DCP link answer on a stream that waits for none"),
        };
        if let Resume::Refused(reason) = outgoing.resume {
            return Err(reason);
        }
        let mut output = vec![0; outgoing.header.output as usize];
        let at = region
            + answer.stream.buffer_of(Owner::Dcp)
            + u64::from(outgoing.offset)
            + u64::from(HEADER_BYTES + outgoing.header.input);
        bus.read(at, &mut output)?;
        // Read the complete AP reply before consuming any one-shot owner.
        // Leave its identity/allocation in place until native completion
        // succeeds, including a terminal native refusal after invocation.
        let lane = &mut self.lanes[lane_index(answer.stream)];
        let outgoing = match lane.frames.last_mut() {
            Some(Frame::Serving {
                waiting: Some(outgoing),
                ..
            }) => outgoing,
            Some(Frame::Calling(outgoing)) => outgoing,
            _ => unreachable!("validated callback owner"),
        };
        let resume = core::mem::replace(
            &mut outgoing.resume,
            Resume::Refused("DCP callback native continuation did not complete"),
        );
        let result = match resume {
            Resume::Method(then) => then(&mut self.service, &output).map(Some),
            Resume::Callback(then) => then(&mut self.service, &output).map(|()| None),
            Resume::Refused(_) => unreachable!("refusal checked before reply DMA"),
        };
        match result {
            Ok(step) => {
                let lane = &mut self.lanes[lane_index(answer.stream)];
                let outgoing = match lane.frames.last_mut() {
                    Some(Frame::Serving { waiting, .. }) => {
                        waiting.take().expect("waiting callback")
                    }
                    Some(Frame::Calling(_)) => match lane.frames.pop().expect("calling frame") {
                        Frame::Calling(outgoing) => outgoing,
                        _ => unreachable!(),
                    },
                    _ => unreachable!("validated reply owner"),
                };
                lane.cursor -= outgoing.slot;
                if let Some(step) = step {
                    self.pending = Some(Pending::Method {
                        stream: answer.stream,
                        step,
                    });
                }
                Ok(())
            }
            Err(reason) => {
                let lane = &mut self.lanes[lane_index(answer.stream)];
                let outgoing = match lane.frames.last_mut() {
                    Some(Frame::Serving {
                        waiting: Some(outgoing),
                        ..
                    }) => outgoing,
                    Some(Frame::Calling(outgoing)) => outgoing,
                    _ => unreachable!("retained refused callback"),
                };
                outgoing.resume = Resume::Refused(reason);
                Err(reason)
            }
        }
    }
}

#[cfg(test)]
mod tests;
