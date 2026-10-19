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
    pub fn start(&mut self) -> u64 {
        self.phase = Phase::Hello;
        Word::Hello {
            version: u64::from(link::VERSION),
        }
        .encode()
    }

    /// A word from the AP, served at the next DMA step.
    pub fn receive(&mut self, word: u64) {
        self.incoming.push_back(word);
    }

    /// Whether the DMA step has work.
    pub fn pending(&self) -> bool {
        !self.incoming.is_empty()
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
        while let Some(word) = self.incoming.pop_front() {
            self.serve(bus, word, outbox)?;
        }
        while self.is_up()
            && let Some(index) = self.free_stream()
            && let Some(callback) = self.service.take_callback()
        {
            let stream = Stream {
                owner: Owner::Dcp,
                index,
            };
            let header = Header {
                tag: callback.tag,
                input: u32::try_from(callback.input.len())
                    .map_err(|_| "DCP callback input exceeds a stream")?,
                output: callback.output,
            };
            self.send_call(
                bus,
                stream,
                true,
                header,
                &callback.input,
                Resume::Callback(callback.then),
                outbox,
            )?;
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
            Word::Rpc(rpc) if rpc.answer => self.answered(bus, rpc, outbox),
            Word::Rpc(rpc) => self.called(bus, rpc, outbox),
        }
    }

    /// The AP called a method.
    fn called(
        &mut self,
        bus: &mut dyn Bus,
        call: Rpc,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
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
        self.step(bus, call.stream, step, outbox)
    }

    /// Carry the served call at the top of `stream` one step on.
    fn step(
        &mut self,
        bus: &mut dyn Bus,
        stream: Stream,
        step: Step<S>,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        let region = self.region()?;
        let lane = &mut self.lanes[lane_index(stream)];
        let Some(Frame::Serving { call, header, .. }) = lane.frames.last() else {
            return Err("DCP link method continued outside the call it serves");
        };
        let (call, header) = (*call, *header);
        match step {
            Step::Return(output) => {
                if output.len() != header.output as usize {
                    return Err("DCP method output size differs from the AP's header");
                }
                let at = region
                    + stream.buffer_of(Owner::Ap)
                    + u64::from(call.offset)
                    + u64::from(HEADER_BYTES + header.input);
                bus.write(at, &output)?;
                lane.frames.pop();
                outbox.push(Word::Rpc(call.answer()).encode());
                Ok(())
            }
            Step::Call {
                tag,
                input,
                output,
                then,
            } => {
                let callback = Header {
                    tag,
                    input: u32::try_from(input.len())
                        .map_err(|_| "DCP callback input exceeds a stream")?,
                    output,
                };
                self.send_call(
                    bus,
                    stream,
                    false,
                    callback,
                    &input,
                    Resume::Method(then),
                    outbox,
                )
            }
        }
    }

    /// Write a callback into the coprocessor's buffer of `stream` and send it.
    #[allow(clippy::too_many_arguments)]
    fn send_call(
        &mut self,
        bus: &mut dyn Bus,
        stream: Stream,
        opens: bool,
        header: Header,
        input: &[u8],
        resume: Resume<S>,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        let region = self.region()?;
        let length = header
            .length()
            .ok_or("DCP callback exceeds a message length")?;
        let slot = align(u32::from(length)).ok_or("DCP callback exceeds a stream")?;
        let lane = &mut self.lanes[lane_index(stream)];
        let offset = lane.cursor;
        if offset + slot > STREAM_BYTES {
            return Err("DCP callback overflows its stream buffer");
        }
        let at = region + stream.buffer_of(Owner::Dcp) + u64::from(offset);
        bus.write(at, &header.bytes())?;
        bus.write(at + u64::from(HEADER_BYTES), input)?;
        lane.cursor += slot;
        let outgoing = Outgoing {
            offset,
            header,
            slot,
            resume,
        };
        match lane.frames.last_mut() {
            Some(Frame::Serving { waiting, .. }) if !opens && waiting.is_none() => {
                *waiting = Some(outgoing)
            }
            None if opens => lane.frames.push(Frame::Calling(outgoing)),
            _ => return Err("DCP callback made on a stream not serving its caller"),
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
    fn answered(
        &mut self,
        bus: &mut dyn Bus,
        answer: Rpc,
        outbox: &mut Vec<u64>,
    ) -> Result<(), &'static str> {
        let region = self.region()?;
        if answer.offset != 0 || answer.length != 0 {
            return Err("DCP link answer carries a payload");
        }
        let lane = &mut self.lanes[lane_index(answer.stream)];
        let outgoing = match lane.frames.last_mut() {
            Some(Frame::Serving { waiting, .. }) => waiting.take(),
            Some(Frame::Calling(_)) => match lane.frames.pop() {
                Some(Frame::Calling(outgoing)) => Some(outgoing),
                _ => None,
            },
            None => None,
        }
        .ok_or("DCP link answer on a stream that waits for none")?;
        lane.cursor -= outgoing.slot;
        let mut output = vec![0; outgoing.header.output as usize];
        let at = region
            + answer.stream.buffer_of(Owner::Dcp)
            + u64::from(outgoing.offset)
            + u64::from(HEADER_BYTES + outgoing.header.input);
        bus.read(at, &mut output)?;
        match outgoing.resume {
            Resume::Method(then) => {
                let step = then(&mut self.service, &output)?;
                self.step(bus, answer.stream, step, outbox)
            }
            Resume::Callback(then) => then(&mut self.service, &output),
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
        assert_eq!(link.start(), 0x100 | 211 << 16);
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
    fn protocol_violations_refuse_by_name() {
        let mut memory = Memory::mapped();
        let mut out = Vec::new();
        // An RPC before the region.
        let mut early = Link::new(Test::default(), None);
        // (Above the region header, which AP stream 0's buffer begins with.)
        early.receive(ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, true));
        assert!(early.dma(&mut memory, &mut out).is_err());
        let mut link = up(&mut memory);
        // A nested call on an idle stream, and an answer nobody waits for.
        link.receive(ap_call(&mut memory, AP0, 0, b"A100", &[0], 1, false));
        assert!(link.dma(&mut memory, &mut out).is_err());
        link.receive(
            Word::Rpc(rpc(ap_call(&mut memory, AP0, 0, b"A100", &[0], 1, true)).answer()).encode(),
        );
        assert!(link.dma(&mut memory, &mut out).is_err());
        // A length that disagrees with the header.
        let mut bad = rpc(ap_call(&mut memory, AP0, 0, b"A100", &[0], 1, true));
        bad.length += 1;
        link.receive(Word::Rpc(bad).encode());
        assert!(link.dma(&mut memory, &mut out).is_err());
        // A method the service refuses.
        link.receive(ap_call(&mut memory, AP0, 0, b"A999", &[], 0, true));
        assert_eq!(link.dma(&mut memory, &mut out), Err("refused"));
    }

    #[test]
    fn an_untruncated_dva_is_used_as_is() {
        let link = Link::new(Test::default(), Some(WINDOW));
        assert_eq!(link.bus(0x8_1000_0000), 0x8_1000_0000);
        assert_eq!(link.bus(0x1000_0000), 0x8_1000_0000);
        assert_eq!(Link::new(Test::default(), None).bus(0x1000), 0x1000);
    }
}
