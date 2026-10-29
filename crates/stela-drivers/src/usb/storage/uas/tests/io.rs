// SPDX-License-Identifier: GPL-2.0-only
//! Ticket completion and transfer ordering for the synchronous model.
use super::*;

impl Io for Model {
    type Ticket = Ticket;
    fn ready(&mut self) -> Result<(), BlockError> {
        if self.state.borrow().fault == Fault::EndpointUnavailable {
            Err(BlockError::Unsupported("model attachment retired"))
        } else {
            Ok(())
        }
    }
    fn streams(&self) -> Option<u16> {
        self.state.borrow().streams
    }
    fn now(&self) -> u64 {
        self.clock.get()
    }
    fn pause(&self) {
        self.clock.set(self.clock.get() + 1_000_000);
    }
    fn submit(
        &mut self,
        pipe: Pipe,
        tag: u16,
        address: u64,
        length: usize,
    ) -> Result<Ticket, BlockError> {
        let mut s = self.state.borrow_mut();
        assert!(!s.active.iter().any(|t| t.pipe == pipe));
        s.next += 1;
        let t = Ticket {
            pipe,
            id: s.next,
            address,
            length,
            stream: if pipe != Pipe::Command && s.streams.is_some() {
                tag
            } else {
                0
            },
        };
        if let Some(count) = s.streams {
            assert!((1..=count).contains(&tag));
        }
        s.events.push(Event::Post(pipe));
        s.active.push(t);
        match pipe {
            Pipe::Command => {
                assert!(s.active.iter().any(|t| t.pipe == Pipe::Status));
                let bytes = Self::bytes(&s, &t);
                assert_eq!(bytes[0], COMMAND_IU);
                assert_eq!(bytes.len(), 32 + usize::from(bytes[6]));
                s.tag = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
                assert_ne!(s.tag, 0);
                if let Some(target) = &mut s.target {
                    let reply = target.prepare(&bytes);
                    s.requested = reply.requested;
                    s.input = reply.input;
                    s.reply = Some(reply);
                } else {
                    match bytes[16] {
                        0x35 => s.requested = 0,
                        0x28 | 0x2a | 0x2e => {
                            s.input = bytes[16] == 0x28;
                            s.requested =
                                usize::from(u16::from_be_bytes(bytes[23..25].try_into().unwrap()))
                                    * 512;
                        }
                        0xaa | 0xae => {
                            s.input = false;
                            s.requested = u32::from_be_bytes(bytes[22..26].try_into().unwrap())
                                as usize
                                * 512;
                        }
                        0x8a | 0x8e => {
                            s.input = false;
                            s.requested = u32::from_be_bytes(bytes[26..30].try_into().unwrap())
                                as usize
                                * 512;
                        }
                        0x9c => {
                            s.input = false;
                            s.requested =
                                usize::from(u16::from_be_bytes(bytes[28..30].try_into().unwrap()))
                                    * 512;
                        }
                        0x7f => {
                            s.input = false;
                            assert!(matches!(
                                u16::from_be_bytes(bytes[24..26].try_into().unwrap()),
                                0x0b..=0x0d
                            ));
                            s.requested = u32::from_be_bytes(bytes[44..48].try_into().unwrap())
                                as usize
                                * 512;
                        }
                        0 => assert_eq!(s.requested, 0),
                        other => panic!("unmodeled actual CDB {other:#x}"),
                    }
                }
                s.history.push(bytes.clone());
                s.command = Some(bytes);
                if s.streams.is_some() {
                    for active in &s.active {
                        if active.pipe != Pipe::Command {
                            assert_eq!(active.stream, s.tag);
                        }
                    }
                    if s.requested != 0 {
                        let direction = if s.input { Pipe::Input } else { Pipe::Output };
                        let data = s
                            .active
                            .iter()
                            .find(|t| t.pipe == direction)
                            .expect("stream data must precede command");
                        assert_eq!(data.length, s.requested);
                    }
                }
                s.ready = s.streams.is_some();
                s.data_done = false;
                s.terminal_sent = false;
            }
            Pipe::Input | Pipe::Output => {
                if s.streams.is_some() {
                    assert!(
                        !s.active.iter().any(|t| t.pipe == Pipe::Command),
                        "stream data posted after command"
                    );
                } else {
                    assert!(s.ready);
                    assert_eq!(pipe == Pipe::Input, s.input);
                    assert_eq!(length, s.requested);
                }
                assert!(s.active.iter().any(|t| t.pipe == Pipe::Status));
            }
            _ => {}
        }
        if (s.fault == Fault::SubmitStatus && pipe == Pipe::Status)
            || (s.fault == Fault::SubmitCommand && pipe == Pipe::Command)
            || (s.fault == Fault::SubmitData && matches!(pipe, Pipe::Input | Pipe::Output))
        {
            return Err(BlockError::Timeout);
        }
        Ok(t)
    }
    fn completed(&mut self, t: &Ticket) -> Option<Result<usize, BlockError>> {
        let mut s = self.state.borrow_mut();
        assert!(s.active.iter().any(|current| current.id == t.id));
        if s.fault == Fault::Timeout {
            return None;
        }
        let result = match t.pipe {
            Pipe::Command
                if s.fault == Fault::CommandLast
                    && (!s.terminal_sent || s.requested != 0 && !s.data_done) =>
            {
                None
            }
            Pipe::Command => Some(Ok(if s.fault == Fault::ShortCommand {
                t.length - 1
            } else {
                t.length
            })),
            Pipe::Status => {
                s.command.as_ref()?;
                let mut bytes = vec![0; 16];
                bytes[0] = STATUS_IU;
                bytes[2..4].copy_from_slice(&s.tag.to_be_bytes());
                if s.streams.is_some() && s.fault == Fault::WrongReady {
                    bytes.truncate(4);
                    bytes[0] = READ_READY_IU;
                } else if let Some(sense) = s.reply.as_ref().and_then(|reply| reply.sense) {
                    bytes[6] = 2;
                    bytes[14..16].copy_from_slice(&18u16.to_be_bytes());
                    bytes.resize(34, 0);
                    bytes[16] = 0x70;
                    bytes[18] = (sense >> 16) as u8;
                    bytes[23] = 10;
                    bytes[28] = (sense >> 8) as u8;
                    bytes[29] = sense as u8;
                } else if s.requested != 0 && !s.ready {
                    bytes.truncate(4);
                    bytes[0] = if s.input ^ (s.fault == Fault::WrongReady) {
                        READ_READY_IU
                    } else {
                        WRITE_READY_IU
                    };
                    s.ready = true;
                } else if s.requested != 0
                    && !s.data_done
                    && !matches!(
                        s.fault,
                        Fault::ErrorAfterReady | Fault::CancelError | Fault::StatusBeforeData
                    )
                {
                    return None;
                } else if matches!(s.fault, Fault::ErrorAfterReady | Fault::CancelError)
                    || s.fault == Fault::FlushError && s.command.as_ref().unwrap()[16] == 0x35
                {
                    bytes[6] = 2;
                    bytes[14..16].copy_from_slice(&18u16.to_be_bytes());
                    bytes.resize(34, 0);
                    bytes[16] = 0x70;
                    bytes[18] = 2;
                    bytes[23] = 10;
                    bytes[28] = 0x3a;
                }
                if s.fault == Fault::WrongTag
                    || s.reply.as_ref().is_some_and(|reply| reply.wrong_tag)
                {
                    bytes[2..4].copy_from_slice(&s.tag.wrapping_add(1).to_be_bytes());
                }
                if s.fault == Fault::MalformedStatus {
                    // An IU ID Linux uas_stat_cmplt logs as bogus.
                    bytes[0] = 0x7f;
                }
                if bytes[0] == STATUS_IU {
                    s.terminal_sent = true;
                }
                Self::write(&s, t, &bytes);
                Some(Ok(bytes.len()))
            }
            Pipe::Input | Pipe::Output => {
                if s.fault == Fault::StatusBeforeData && !s.terminal_sent {
                    return None;
                }
                if matches!(s.fault, Fault::ErrorAfterReady | Fault::CancelError) {
                    return None;
                }
                let count = if let Some(reply) = &s.reply {
                    if t.pipe == Pipe::Input {
                        reply.data.len().min(t.length)
                    } else {
                        t.length
                    }
                } else if s.fault == Fault::ShortData {
                    t.length - 1
                } else {
                    t.length
                };
                if t.pipe == Pipe::Input {
                    let data = s
                        .reply
                        .as_ref()
                        .map_or_else(|| vec![0x6d; count], |reply| reply.data[..count].to_vec());
                    Self::write(&s, t, &data);
                } else {
                    s.written = Self::bytes(&s, t)[..count].to_vec();
                    let command = s.command.clone().unwrap();
                    let written = s.written.clone();
                    if let Some(target) = &mut s.target {
                        target.write(&command, written);
                    }
                }
                s.data_done = true;
                Some(Ok(count))
            }
        };
        if result.is_some() {
            s.active.retain(|current| current.id != t.id);
            s.events.push(Event::Complete(t.pipe));
        }
        result
    }
    fn cancel(&mut self, pipe: Pipe) -> Result<(), BlockError> {
        let mut s = self.state.borrow_mut();
        s.events.push(Event::Cancel(pipe));
        if s.fault == Fault::CancelError && matches!(pipe, Pipe::Input | Pipe::Output) {
            return Err(BlockError::Timeout);
        }
        s.active.retain(|current| current.pipe != pipe);
        Ok(())
    }
}
