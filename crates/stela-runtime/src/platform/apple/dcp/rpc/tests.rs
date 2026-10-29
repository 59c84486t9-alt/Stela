use super::*;
use alloc::collections::BTreeMap;
use alloc::string::String;

const WINDOW: u64 = 0x8_0000_0000;
const VERSION: u32 = stela_formats::builds::DEFAULT.dcp_link_version;
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
    let mut link = Link::new(Test::default(), Some(WINDOW), VERSION);
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
    let mut link = Link::new(Effects::default(), Some(WINDOW), VERSION);
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
    let mut link = Link::new(Effects::default(), Some(WINDOW), VERSION);
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
fn earlier_ack_stays_committed_when_a_later_input_faults_and_invalid_native_size_keeps_ownership() {
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
    let mut early = Link::new(Test::default(), None, VERSION);
    let word = ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, true);
    early.receive(word);
    assert!(early.dma(&mut memory, &mut out).is_err());
    assert_eq!(early.incoming.front(), Some(&word));
    for case in 0..4 {
        let mut link = up(&mut memory);
        let word = match case {
            0 => ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, false),
            1 => Word::Rpc(rpc(ap_call(&mut memory, AP0, 0x40, b"A100", &[0], 1, true)).answer())
                .encode(),
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
    let link = Link::new(Test::default(), Some(WINDOW), VERSION);
    assert_eq!(link.bus(0x8_1000_0000), 0x8_1000_0000);
    assert_eq!(link.bus(0x1000_0000), 0x8_1000_0000);
    assert_eq!(
        Link::new(Test::default(), None, VERSION).bus(0x1000),
        0x1000
    );
}
