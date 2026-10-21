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
//! Accepted calls and taken callbacks are retained native owners until their
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
    pub fn new(service: S, window: Option<u64>) -> Self {
        Self {
            service,
            window,
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
            version: u64::from(link::VERSION),
        }
        .encode())
    }

    pub fn retained_idle(&self) -> bool {
        self.incoming.is_empty()
            && self.pending.is_none()
            && self.lanes.iter().all(|lane| lane.frames.is_empty())
            && !self.service.callback_pending()
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
                        crc: link::interface_crc(),
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

    /// Validate and publish a retained native result. All fallible checks
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
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::String;

    const WINDOW: u64 = 0x8_0000_0000;
    const REGION_DVA: u64 = 0x4000;
    const REGION: u64 = WINDOW + REGION_DVA;

    /// Bus memory as a sparse byte map.
    #[derive(Default)]
    struct Memory(BTreeMap<u64, u8>);

    impl Bus for Memory {
        fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
            for (n, byte) in buffer.iter_mut().enumerate() {
                *byte = *self.0.get(&(address + n as u64)).ok_or("unmapped")?;
            }
            Ok(())
        }
        fn write(&mut self, address: u64, data: &[u8]) -> Result<(), &'static str> {
            for (n, &byte) in data.iter().enumerate() {
                self.0.insert(address + n as u64, byte);
            }
            Ok(())
        }
    }

    impl Memory {
        fn mapped() -> Self {
            let mut memory = Memory::default();
            memory
                .write(REGION, &vec![0; link::REGION_BYTES as usize])
                .unwrap();
            let mut header = [0; 16];
            header[12] = 4;
            memory.write(REGION, &header).unwrap();
            memory
        }
    }

    /// A401 calls D120 back and returns its byte; A100 returns its input
    /// plus one; anything else refuses. Records what ran.
    #[derive(Default)]
    struct Test {
        log: Vec<String>,
        callbacks: Vec<Callback<Test>>,
    }

    impl Service for Test {
        fn call(
            &mut self,
            tag: [u8; 4],
            input: &[u8],
            output: u32,
        ) -> Result<Step<Self>, &'static str> {
            self.log
                .push(String::from(core::str::from_utf8(&tag).unwrap()));
            match &tag {
                b"A401" => Ok(Step::Call {
                    tag: *b"D120",
                    input: Vec::new(),
                    output: 4,
                    then: Box::new(|_, answer| {
                        let mut out = vec![0; 4];
                        out[0] = answer[0];
                        Ok(Step::Return(out))
                    }),
                }),
                b"A100" => Ok(Step::Return(vec![input[0] + 1; output as usize])),
                _ => Err("refused"),
            }
        }
        fn callback_pending(&self) -> bool {
            !self.callbacks.is_empty()
        }
        fn take_callback(&mut self) -> Option<Callback<Self>> {
            self.callbacks.pop()
        }
    }

    fn up(memory: &mut Memory) -> Link<Test> {
        let mut link = Link::new(Test::default(), Some(WINDOW));
        assert_eq!(link.start().unwrap(), 0x100 | 211 << 16);
        link.receive(Word::Region { dva: REGION_DVA }.encode());
        let mut out = Vec::new();
        link.dma(memory, &mut out).unwrap();
        assert_eq!(
            out,
            [Word::Ready {
                crc: 0x15a5_c96b,
                alignment: ALIGNMENT
            }
            .encode()]
        );
        link
    }

    /// The AP writes a call into `writer`'s buffer of `stream` at `offset`.
    fn ap_call(
        memory: &mut Memory,
        stream: Stream,
        offset: u16,
        tag: &[u8; 4],
        input: &[u8],
        output: u32,
        opens: bool,
    ) -> u64 {
        let header = Header {
            tag: *tag,
            input: input.len() as u32,
            output,
        };
        let at = REGION + stream.buffer_of(Owner::Ap) + u64::from(offset);
        memory.write(at, &header.bytes()).unwrap();
        memory.write(at + 12, input).unwrap();
        Word::Rpc(Rpc {
            answer: false,
            stream,
            opens,
            offset,
            length: header.length().unwrap(),
            token: 0,
        })
        .encode()
    }

    fn rpc(word: u64) -> Rpc {
        match Word::decode(word).unwrap() {
            Word::Rpc(rpc) => rpc,
            other => panic!("{other:?}"),
        }
    }

    const AP0: Stream = Stream {
        owner: Owner::Ap,
        index: 0,
    };

    struct Fault<'a> {
        memory: &'a mut Memory,
        read: Option<u64>,
        write: Option<u64>,
    }
    impl Bus for Fault<'_> {
        fn read(&mut self, at: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
            if self.read == Some(at) {
                return Err("injected read fault");
            }
            self.memory.read(at, bytes)
        }
        fn write(&mut self, at: u64, bytes: &[u8]) -> Result<(), &'static str> {
            if self.write == Some(at) {
                return Err("injected write fault");
            }
            self.memory.write(at, bytes)
        }
    }

    #[derive(Default)]
    struct Effects {
        calls: usize,
        continues: usize,
        takes: usize,
        finishes: usize,
        callbacks: usize,
        refuse_finish: bool,
    }
    impl Service for Effects {
        fn call(
            &mut self,
            tag: [u8; 4],
            input: &[u8],
            output: u32,
        ) -> Result<Step<Self>, &'static str> {
            match &tag {
                b"RETN" => {
                    self.calls += 1;
                    Ok(Step::Return(input.iter().rev().copied().collect()))
                }
                b"NEST" | b"FAIL" | b"SIZE" => {
                    self.calls += 1;
                    Ok(Step::Call {
                        tag: *b"BACK",
                        input: vec![4; 4],
                        output: if &tag == b"SIZE" { 0x1_0000 } else { output },
                        then: Box::new(move |service, reply| {
                            service.continues += 1;
                            if &tag == b"FAIL" {
                                return Err("native continuation refused");
                            }
                            Ok(Step::Return(reply.iter().rev().copied().collect()))
                        }),
                    })
                }
                _ => Err("unsupported effect"),
            }
        }
        fn callback_pending(&self) -> bool {
            self.callbacks != 0
        }
        fn take_callback(&mut self) -> Option<Callback<Self>> {
            if self.callbacks == 0 {
                return None;
            }
            self.callbacks -= 1;
            self.takes += 1;
            Some(Callback {
                tag: *b"EVNT",
                input: vec![6, 7, 8, 9],
                output: 4,
                then: Box::new(|service, reply| {
                    assert_eq!(reply, &[1, 2, 3, 4]);
                    service.finishes += 1;
                    if service.refuse_finish {
                        return Err("native finish refused");
                    }
                    Ok(())
                }),
            })
        }
    }
    fn effects_up(memory: &mut Memory) -> Link<Effects> {
        let mut link = Link::new(Effects::default(), Some(WINDOW));
        link.start().unwrap();
        link.receive(Word::Region { dva: REGION_DVA }.encode());
        link.dma(memory, &mut Vec::new()).unwrap();
        link
    }

    #[test]
    fn request_header_and_body_read_faults_retain_only_unaccepted_input() {
        for address in [REGION + 0x40, REGION + 0x40 + 12] {
            let mut memory = Memory::mapped();
            let mut link = effects_up(&mut memory);
            link.receive(ap_call(
                &mut memory,
                AP0,
                0x40,
                b"RETN",
                &[1, 2, 3, 4],
                4,
                true,
            ));
            let mut out = Vec::new();
            assert_eq!(
                link.dma(
                    &mut Fault {
                        memory: &mut memory,
                        read: Some(address),
                        write: None
                    },
                    &mut out
                ),
                Err("injected read fault")
            );
            assert_eq!(link.service().calls, 0);
            assert!(link.pending() && !link.retained_idle() && out.is_empty());
            link.dma(&mut memory, &mut out).unwrap();
            assert_eq!(link.service().calls, 1);
            assert_eq!(out.len(), 1);
            let mut result = [0; 4];
            memory.read(REGION + 0x40 + 16, &mut result).unwrap();
            assert_eq!(result, [4, 3, 2, 1]);
            assert!(link.retained_idle());
        }
        let mut memory = Memory::mapped();
        let mut link = Link::new(Effects::default(), Some(WINDOW));
        link.start().unwrap();
        link.receive(Word::Region { dva: REGION_DVA }.encode());
        assert!(
            link.dma(
                &mut Fault {
                    memory: &mut memory,
                    read: Some(REGION),
                    write: None
                },
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(link.heap().is_none() && !link.is_up());
        let mut out = Vec::new();
        link.dma(&mut memory, &mut out).unwrap();
        assert!(link.heap().is_some() && link.is_up());
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn return_dma_fault_and_restart_refusal_preserve_the_accepted_service_result() {
        let mut memory = Memory::mapped();
        let mut link = effects_up(&mut memory);
        let heap = link.heap();
        let mut request = rpc(ap_call(
            &mut memory,
            AP0,
            0x40,
            b"RETN",
            &[1, 2, 3, 4],
            4,
            true,
        ));
        request.token = 0xa5b3;
        link.receive(Word::Rpc(request).encode());
        let mut out = Vec::new();
        for _ in 0..2 {
            assert_eq!(
                link.dma(
                    &mut Fault {
                        memory: &mut memory,
                        read: None,
                        write: Some(REGION + 0x50)
                    },
                    &mut out
                ),
                Err("injected write fault")
            );
            assert_eq!(link.service().calls, 1);
            assert!(out.is_empty());
            assert_eq!(
                link.start(),
                Err("DCP link restart with unfinished RPC ownership")
            );
            assert_eq!(link.heap(), heap);
            assert!(link.is_up() && !link.retained_idle());
        }
        link.dma(&mut memory, &mut out).unwrap();
        assert_eq!(out, [Word::Rpc(request.answer()).encode()]);
        assert_eq!(link.service().calls, 1);
        assert!(link.retained_idle());
        out.clear();
        link.dma(&mut memory, &mut out).unwrap();
        assert!(out.is_empty());
        link.start().unwrap();
        assert!(link.heap().is_none());
    }

    #[test]
    fn nested_callback_write_read_and_continued_return_faults_never_replay_native_effects() {
        for callback_write in [REGION + 0x60000, REGION + 0x60000 + 12] {
            let mut memory = Memory::mapped();
            let mut link = effects_up(&mut memory);
            link.receive(ap_call(
                &mut memory,
                AP0,
                0x40,
                b"NEST",
                &[1, 2, 3, 4],
                4,
                true,
            ));
            let mut out = Vec::new();
            assert!(
                link.dma(
                    &mut Fault {
                        memory: &mut memory,
                        read: None,
                        write: Some(callback_write)
                    },
                    &mut out
                )
                .is_err()
            );
            assert_eq!((link.service().calls, link.service().continues), (1, 0));
            assert_eq!(link.lanes[0].cursor, 0);
            assert!(out.is_empty());
            link.dma(&mut memory, &mut out).unwrap();
            let callback = rpc(out.pop().unwrap());
            assert!(!callback.opens);
            assert_eq!(link.lanes[0].cursor, 0x40);
            assert!(!link.retained_idle());
            assert!(link.start().is_err());
            memory.write(REGION + 0x60000 + 16, &[1, 2, 3, 4]).unwrap();
            link.receive(Word::Rpc(callback.answer()).encode());
            assert!(
                link.dma(
                    &mut Fault {
                        memory: &mut memory,
                        read: Some(REGION + 0x60000 + 16),
                        write: None
                    },
                    &mut out
                )
                .is_err()
            );
            assert_eq!(link.service().continues, 0);
            assert_eq!(link.lanes[0].cursor, 0x40);
            for _ in 0..2 {
                assert!(
                    link.dma(
                        &mut Fault {
                            memory: &mut memory,
                            read: None,
                            write: Some(REGION + 0x50)
                        },
                        &mut out
                    )
                    .is_err()
                );
                assert_eq!(link.service().continues, 1);
                assert_eq!(link.service().calls, 1);
                assert_eq!(link.lanes[0].cursor, 0);
                assert!(out.is_empty());
            }
            link.dma(&mut memory, &mut out).unwrap();
            assert_eq!(out.len(), 1);
            assert!(rpc(out[0]).answer && rpc(out[0]).opens);
            assert_eq!((link.service().calls, link.service().continues), (1, 1));
            assert!(link.retained_idle());
        }
    }

    #[test]
    fn unsolicited_callback_identity_survives_both_write_phases_and_reply_read_failure() {
        let stream = Stream {
            owner: Owner::Dcp,
            index: 0,
        };
        for write in [REGION + 0x40000, REGION + 0x40000 + 12] {
            let mut memory = Memory::mapped();
            let mut link = effects_up(&mut memory);
            link.service_mut().callbacks = 1;
            let mut out = Vec::new();
            assert!(
                link.dma(
                    &mut Fault {
                        memory: &mut memory,
                        read: None,
                        write: Some(write)
                    },
                    &mut out
                )
                .is_err()
            );
            assert_eq!(link.service().takes, 1);
            assert_eq!(link.service().callbacks, 0);
            assert!(out.is_empty());
            assert!(!link.retained_idle() && link.pending());
            assert!(link.start().is_err());
            link.dma(&mut memory, &mut out).unwrap();
            let callback = rpc(out.pop().unwrap());
            assert_eq!(callback.stream, stream);
            assert!(callback.opens);
            assert_eq!(link.service().takes, 1);
            assert!(!link.pending() && !link.retained_idle());
            memory.write(REGION + 0x40000 + 16, &[1, 2, 3, 4]).unwrap();
            link.receive(Word::Rpc(callback.answer()).encode());
            assert!(
                link.dma(
                    &mut Fault {
                        memory: &mut memory,
                        read: Some(REGION + 0x40000 + 16),
                        write: None
                    },
                    &mut out
                )
                .is_err()
            );
            assert_eq!(link.service().finishes, 0);
            assert_eq!(link.lanes[lane_index(stream)].cursor, 0x40);
            link.dma(&mut memory, &mut out).unwrap();
            assert_eq!(link.service().finishes, 1);
            assert!(link.retained_idle());
            assert!(out.is_empty());
            link.dma(&mut memory, &mut out).unwrap();
            assert_eq!(link.service().takes, 1);
        }
    }

    #[test]
    fn native_continuation_refusals_retain_identity_without_false_completion_or_reexecution() {
        for top_level in [false, true] {
            let mut memory = Memory::mapped();
            let mut link = effects_up(&mut memory);
            let mut out = Vec::new();
            let reply_at = if top_level {
                link.service_mut().callbacks = 1;
                link.service_mut().refuse_finish = true;
                REGION + 0x40000 + 16
            } else {
                link.receive(ap_call(
                    &mut memory,
                    AP0,
                    0x40,
                    b"FAIL",
                    &[1, 2, 3, 4],
                    4,
                    true,
                ));
                REGION + 0x60000 + 16
            };
            link.dma(&mut memory, &mut out).unwrap();
            let callback = rpc(out.pop().unwrap());
            memory.write(reply_at, &[1, 2, 3, 4]).unwrap();
            link.receive(Word::Rpc(callback.answer()).encode());
            for _ in 0..2 {
                assert_eq!(
                    link.dma(&mut memory, &mut out),
                    Err(if top_level {
                        "native finish refused"
                    } else {
                        "native continuation refused"
                    })
                );
                assert_eq!(link.service().finishes + link.service().continues, 1);
                assert!(!link.retained_idle() && out.is_empty());
                assert!(link.start().is_err());
                assert_eq!(link.lanes[lane_index(callback.stream)].cursor, 0x40);
            }
        }
    }

    #[test]
    fn earlier_ack_stays_committed_when_a_later_input_faults_and_invalid_native_size_keeps_ownership()
     {
        let mut memory = Memory::mapped();
        let mut link = effects_up(&mut memory);
        let ap1 = Stream {
            owner: Owner::Ap,
            index: 1,
        };
        link.receive(ap_call(
            &mut memory,
            AP0,
            0x40,
            b"RETN",
            &[1, 2, 3, 4],
            4,
            true,
        ));
        link.receive(ap_call(
            &mut memory,
            ap1,
            0x40,
            b"RETN",
            &[5, 6, 7, 8],
            4,
            true,
        ));
        let mut out = Vec::new();
        assert!(
            link.dma(
                &mut Fault {
                    memory: &mut memory,
                    read: Some(REGION + ap1.buffer_of(Owner::Ap) + 0x40),
                    write: None
                },
                &mut out
            )
            .is_err()
        );
        assert_eq!(out.len(), 1);
        assert_eq!(rpc(out[0]).stream, AP0);
        assert_eq!(link.service().calls, 1);
        out.clear();
        link.dma(&mut memory, &mut out).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(rpc(out[0]).stream, ap1);
        assert_eq!(link.service().calls, 2);
        out.clear();
        link.receive(ap_call(
            &mut memory,
            AP0,
            0x40,
            b"SIZE",
            &[1, 2, 3, 4],
            4,
            true,
        ));
        for _ in 0..2 {
            assert_eq!(
                link.dma(&mut memory, &mut out),
                Err("DCP callback exceeds a message length")
            );
            assert_eq!(link.service().calls, 3);
            assert!(out.is_empty());
            assert!(link.start().is_err());
        }
    }

    #[test]
    fn a_call_is_answered_with_its_output_in_place() {
        let mut memory = Memory::mapped();
        let mut link = up(&mut memory);
        let mut out = Vec::new();
        link.receive(ap_call(&mut memory, AP0, 0x40, b"A100", &[7], 3, true));
        link.dma(&mut memory, &mut out).unwrap();
        let word = out[0];
        assert_eq!(word & 0xffff_ffff_0000, 0);
        assert_eq!(word, 2 | 0x40 | 1 << 9);
        let mut output = [0; 3];
        memory.read(REGION + 0x40 + 13, &mut output).unwrap();
        assert_eq!(output, [8; 3]);
    }

    #[test]
    fn a_method_calls_back_nested_and_the_ap_nests_a_call_inside_the_callback() {
        let mut memory = Memory::mapped();
        let mut link = up(&mut memory);
        let mut out = Vec::new();
        link.receive(ap_call(&mut memory, AP0, 0, b"A401", &[], 4, true));
        link.dma(&mut memory, &mut out).unwrap();
        // D120 is nested on AP stream 0, written into the coprocessor's
        // buffer of it (0x60000), not opening anything.
        let callback = rpc(out.pop().unwrap());
        assert!(!callback.answer && !callback.opens);
        assert_eq!(
            (callback.stream, callback.offset, callback.length),
            (AP0, 0, 16)
        );
        let mut header = [0; 12];
        memory.read(REGION + 0x60000, &mut header).unwrap();
        assert_eq!(&Header::parse(&header).tag, b"D120");
        // Serving D120, the AP calls A100 on the same stream above A401.
        link.receive(ap_call(&mut memory, AP0, 0x40, b"A100", &[1], 1, false));
        link.dma(&mut memory, &mut out).unwrap();
        assert!(rpc(out.pop().unwrap()).answer);
        // The AP answers D120 with 1; A401 then returns it.
        memory.write(REGION + 0x60000 + 12, &[1, 0, 0, 0]).unwrap();
        link.receive(Word::Rpc(callback.answer()).encode());
        link.dma(&mut memory, &mut out).unwrap();
        let answer = rpc(out.pop().unwrap());
        assert!(answer.answer && answer.opens);
        let mut result = [0; 4];
        memory.read(REGION + 12, &mut result).unwrap();
        assert_eq!(result, [1, 0, 0, 0]);
        assert_eq!(link.service().log, ["A401", "A100"]);
        // The stream is free again: a fresh call opens it.
        link.receive(ap_call(&mut memory, AP0, 0, b"A100", &[0], 1, true));
        link.dma(&mut memory, &mut out).unwrap();
    }

    #[test]
    fn a_callback_opens_a_coprocessor_stream_and_finishes_on_its_answer() {
        let mut memory = Memory::mapped();
        let mut link = up(&mut memory);
        link.service_mut().callbacks.push(Callback {
            tag: *b"D000",
            input: vec![1, 2, 3, 4],
            output: 4,
            then: Box::new(|service, answer| {
                service.log.push(alloc::format!("D000={}", answer[0]));
                Ok(())
            }),
        });
        assert!(link.pending());
        let mut out = Vec::new();
        link.dma(&mut memory, &mut out).unwrap();
        let call = rpc(out.pop().unwrap());
        let dcp0 = Stream {
            owner: Owner::Dcp,
            index: 0,
        };
        assert!(call.opens && call.stream == dcp0);
        assert_eq!(Word::Rpc(call).encode() & 0x100, 0x100);
        // The AP nests a call in the callback, in its buffer of the
        // coprocessor's stream (0x20000).
        link.receive(ap_call(&mut memory, dcp0, 0, b"A100", &[4], 1, false));
        link.dma(&mut memory, &mut out).unwrap();
        let mut byte = [0];
        memory.read(REGION + 0x20000 + 13, &mut byte).unwrap();
        assert_eq!(byte, [5]);
        memory.write(REGION + 0x40000 + 16, &[9, 0, 0, 0]).unwrap();
        link.receive(Word::Rpc(call.answer()).encode());
        link.dma(&mut memory, &mut out).unwrap();
        assert_eq!(link.service().log, ["A100", "D000=9"]);
    }

    #[test]
    fn protocol_violations_refuse_by_name_without_consuming_the_input() {
        let mut memory = Memory::mapped();
        let mut out = Vec::new();
        let mut early = Link::new(Test::default(), None);
        let word = ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, true);
        early.receive(word);
        assert!(early.dma(&mut memory, &mut out).is_err());
        assert_eq!(early.incoming.front(), Some(&word));
        for case in 0..4 {
            let mut link = up(&mut memory);
            let word = match case {
                0 => ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, false),
                1 => {
                    Word::Rpc(rpc(ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, true)).answer())
                        .encode()
                }
                2 => {
                    let mut bad = rpc(ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, true));
                    bad.length += 1;
                    Word::Rpc(bad).encode()
                }
                _ => ap_call(&mut memory, AP0, 0x40, b"A999", &[], 0, true),
            };
            link.receive(word);
            let result = link.dma(&mut memory, &mut out);
            assert!(result.is_err());
            if case == 3 {
                assert_eq!(result, Err("refused"));
            }
            assert_eq!(link.incoming.front(), Some(&word));
            assert!(out.is_empty());
        }
    }

    #[test]
    fn an_untruncated_dva_is_used_as_is() {
        let link = Link::new(Test::default(), Some(WINDOW));
        assert_eq!(link.bus(0x8_1000_0000), 0x8_1000_0000);
        assert_eq!(link.bus(0x1000_0000), 0x8_1000_0000);
        assert_eq!(Link::new(Test::default(), None).bus(0x1000), 0x1000);
    }
}
