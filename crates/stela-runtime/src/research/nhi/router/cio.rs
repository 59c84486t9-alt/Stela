//! Original CIO router-header callbacks, not a router capability image.
//!
//! The 26A434 T8112 firmware's per-word callback at 0x1104d4 owns these
//! masks, kept route fields and events. Its two event destinations are
//! distinct original task queues. The CIO owner must supply all
//! initial state and atomically keep generated events; no ready state,
//! register defaults, event completion or Configuration backend is implied.
use alloc::vec::Vec;

const ROUTE_SELECTOR: u32 = 7 << 20;
const ROUTE_COMMIT: u32 = 1 << 31;
const ROUTE_HIGH: u32 = 0x00ff_ffff;
const ADAPTER_CHANGE: u32 = 0xf000;
const RETAINED_VERSION: u32 = 0xff00_0000;
const UUID_ALIAS: u16 = 0x174;
const LIMIT_MASK: u32 = 0x3fff;
const LIMIT_CONTROL: u32 = 0xc000_c000;

/// Original 0x110458 read callback after the registered RAM word has been
/// read. Limits are controller +0x274a/+0x274c values; `read_control`
/// reads the mapped CIO control resource at the supplied byte offset.
/// No register bank or live-device default is provided. TMU words have their
/// own registered owner and must not fall through to this RAM callback.
pub fn read_registered_word(
    offset: u16,
    retained: u32,
    limits: [u16; 2],
    read_control: impl FnOnce(u16) -> Result<u32, &'static str>,
) -> Result<u32, &'static str> {
    match offset {
        0x3a..=0x3d => read_control(0x30 + (offset - 0x3a) * 4),
        0x47 => Ok((retained & LIMIT_CONTROL)
            | u32::from(limits[0]).min(LIMIT_MASK)
            | (u32::from(limits[1]).min(LIMIT_MASK) << 16)),
        0..=0x1a | 0x35..=0x1f0 => Ok(retained),
        _ => Err("CIO router read requires its separately registered owner"),
    }
}

/// Controller fields at +0x3a8/+0x3ac/+0x3b0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingRoute {
    pub high: u32,
    pub low: u32,
    pub state: u32,
}

/// Required state. There is no Default or capability
/// constructor: a nine-word header is not the complete configuration bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    pub header: [u32; 9],
    pub uuid_aliases: [u32; 2],
    pub pending_route: PendingRoute,
    /// Controller +0x3b4, updated from word4's low byte.
    pub adapter_count: u32,
}

/// An original internal task event, never a wire notification or an ACK.
/// Route goes to the controller queue; the other two go to its connection
/// queue. Each original queue record has this event ID and zero data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Route,
    AdapterChange,
    Sleep,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    Controller,
    Connection,
}
impl Event {
    pub const fn id(self) -> u32 {
        match self {
            Self::Route => 0xba,
            Self::AdapterChange => 0xbc,
            Self::Sleep => 0x37,
        }
    }
    pub const fn task(self) -> Task {
        match self {
            Self::Route => Task::Controller,
            Self::AdapterChange | Self::Sleep => Task::Connection,
        }
    }
}

pub struct Header {
    state: State,
}
impl Header {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    fn word(state: &State, offset: u16) -> Result<u32, &'static str> {
        match offset {
            0..=8 => Ok(state.header[usize::from(offset)]),
            UUID_ALIAS..=0x175 => Ok(state.uuid_aliases[usize::from(offset - UUID_ALIAS)]),
            _ => Err("CIO router word requires its actual registered callback"),
        }
    }

    pub fn read(&self, offset: u16, count: usize) -> Result<Vec<u32>, &'static str> {
        (0..count)
            .map(|i| {
                let offset = Self::offset(offset, i)?;
                Self::word(&self.state, offset)
            })
            .collect()
    }

    fn offset(first: u16, index: usize) -> Result<u16, &'static str> {
        let index = u16::try_from(index).map_err(|_| "CIO router span overflows its address")?;
        first
            .checked_add(index)
            .ok_or("CIO router span overflows its address")
    }

    /// Execute a span in original per-word order. `enqueue` must keep the
    /// whole event batch or refuse without effects. It must not execute the
    /// events inline: their owner observes the committed state afterwards.
    /// Missing callbacks, the original zero route-selector invariant
    /// and queue refusals preserve every word and kept controller field.
    pub fn write(
        &mut self,
        offset: u16,
        data: &[u32],
        enqueue: impl FnOnce(&[Event]) -> Result<(), &'static str>,
    ) -> Result<(), &'static str> {
        let mut next = self.state;
        let mut events = Vec::new();
        for (index, &value) in data.iter().enumerate() {
            let offset = Self::offset(offset, index)?;
            let old = Self::word(&next, offset)?;
            let stored = match offset {
                0 | 6..=8 => old,
                1 => (old & !ROUTE_SELECTOR) | (value & ROUTE_SELECTOR),
                2 => value,
                3 => {
                    if value & ROUTE_COMMIT != 0 && old & ROUTE_COMMIT == 0 {
                        if next.header[1] & ROUTE_SELECTOR != 0 {
                            return Err("CIO original route commit requires a zero route-selector");
                        }
                        next.pending_route = PendingRoute {
                            high: value & ROUTE_HIGH,
                            low: next.header[2],
                            state: 0,
                        };
                        events.push(Event::Route);
                    }
                    value & (ROUTE_COMMIT | ROUTE_HIGH)
                }
                4 => {
                    next.adapter_count = value & 0xff;
                    if (value ^ old) & ADAPTER_CHANGE != 0 {
                        events.push(Event::AdapterChange);
                    }
                    (old & RETAINED_VERSION) | (value & 0xffff)
                }
                5 => {
                    if value & 1 != 0 && old & 1 == 0 {
                        events.push(Event::Sleep);
                    }
                    value
                }
                UUID_ALIAS..=0x175 => {
                    let index = usize::from(offset - UUID_ALIAS);
                    next.header[7 + index] = value;
                    next.uuid_aliases[index] = value;
                    continue;
                }
                _ => unreachable!(), // Self::word validated this offset.
            };
            next.header[usize::from(offset)] = stored;
        }
        if !events.is_empty() {
            enqueue(&events)?;
        }
        self.state = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Distinct test state exercises preserved bits and kept values. This
    // is not an original/default capability image or a production profile.
    fn state() -> State {
        State {
            header: [
                0x11,
                0x0002_001b,
                0x1234_5678,
                0,
                0x20ab_000a,
                0,
                0x22,
                0x33,
                0x44,
            ],
            uuid_aliases: [0x55, 0x66],
            pending_route: PendingRoute {
                high: 0xa1,
                low: 0xa2,
                state: 0xa3,
            },
            adapter_count: 0xa4,
        }
    }

    #[test]
    fn original_read_callback_uses_live_registers_and_limits() {
        for (word, address, value) in [
            (0x3a, 0x30, 0x1234_5678),
            (0x3b, 0x34, 0x8765_4321),
            (0x3c, 0x38, 0xabcd_ef01),
            (0x3d, 0x3c, 0x0123_4567),
        ] {
            assert_eq!(
                read_registered_word(word, !0, [0xffff; 2], |actual| {
                    assert_eq!(actual, address);
                    Ok(value)
                }),
                Ok(value)
            );
            assert_eq!(
                read_registered_word(word, 0, [0; 2], |_| Err("CIO is powered off")),
                Err("CIO is powered off")
            );
        }
        assert_eq!(
            read_registered_word(0x47, 0xaaaa_5555, [0x1234, 0x5678], |_| panic!()),
            Ok(0xbfff_5234)
        );
        assert_eq!(
            read_registered_word(0x47, !0, [0x4000, 0x3fff], |_| panic!()),
            Ok(!0)
        );
        assert_eq!(
            read_registered_word(0x47, !0, [0, 0], |_| panic!()),
            Ok(0xc000_c000)
        );
        for offset in [0, 0x1a, 0x35, 0x1f0] {
            assert_eq!(
                read_registered_word(offset, 0x8765_4321, [0; 2], |_| panic!()),
                Ok(0x8765_4321)
            );
        }
        for offset in [0x1b, 0x34, 0x1f1, u16::MAX] {
            assert!(read_registered_word(offset, 0, [0; 2], |_| panic!()).is_err());
        }
    }

    #[test]
    fn original_callback_masks_read_only_words_and_uuid_aliases() {
        let mut h = Header::new(state());
        for offset in [0, 6, 7, 8] {
            let before = *h.state();
            h.write(offset, &[!0], |_| panic!("read-only write queued an event"))
                .unwrap();
            assert_eq!(*h.state(), before);
        }
        h.write(1, &[!0], |_| panic!()).unwrap();
        assert_eq!(h.state().header[1], 0x0072_001b);
        h.write(UUID_ALIAS, &[0xabcd_ef98, 0xabcd_ef99], |_| panic!())
            .unwrap();
        assert_eq!(h.read(7, 2).unwrap(), vec![0xabcd_ef98, 0xabcd_ef99]);
        assert_eq!(
            h.read(UUID_ALIAS, 2).unwrap(),
            vec![0xabcd_ef98, 0xabcd_ef99]
        );
        h.write(7, &[0, 0], |_| panic!()).unwrap();
        assert_eq!(h.read(7, 2).unwrap(), h.read(UUID_ALIAS, 2).unwrap());
    }

    #[test]
    fn original_route_commit_captures_the_preceding_word_once() {
        let mut h = Header::new(state());
        let mut events = Vec::new();
        h.write(2, &[0xabcd_ef01, 0xff23_4567], |batch| {
            events.extend_from_slice(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            h.state().pending_route,
            PendingRoute {
                high: 0x23_4567,
                low: 0xabcd_ef01,
                state: 0,
            }
        );
        assert_eq!(h.state().header[3], 0x8023_4567);
        assert_eq!(events, vec![Event::Route]);
        let captured = h.state().pending_route;
        h.write(2, &[0xdead_beef, !0], |_| {
            panic!("repeated commit queued another route")
        })
        .unwrap();
        assert_eq!(h.state().pending_route, captured);
        assert_eq!(h.state().header[3], 0x80ff_ffff);
        h.write(3, &[0x7fff_ffff], |_| panic!()).unwrap();
        assert_eq!(h.state().header[3], 0x00ff_ffff);
        h.write(3, &[0x8000_1234], |batch| {
            events.extend_from_slice(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(h.state().pending_route.low, 0xdead_beef);
        assert_eq!(h.state().pending_route.high, 0x1234);
        assert_eq!(events, vec![Event::Route, Event::Route]);
    }

    #[test]
    fn events_follow_source_word_and_edge_order() {
        let mut h = Header::new(state());
        let mut events = Vec::new();
        h.write(4, &[!0, 0x101], |batch| {
            events.extend_from_slice(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(h.state().header[4], 0x2000_ffff);
        assert_eq!(h.state().adapter_count, 0xff);
        assert_eq!(events, vec![Event::AdapterChange, Event::Sleep]);
        h.write(4, &[0x123, 0x101], |batch| {
            events.extend_from_slice(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(h.state().header[4], 0x2000_0123);
        assert_eq!(h.state().adapter_count, 0x23);
        assert_eq!(
            events,
            vec![Event::AdapterChange, Event::Sleep, Event::AdapterChange]
        );
        h.write(5, &[0], |_| panic!()).unwrap();
        h.write(5, &[1], |batch| {
            events.extend_from_slice(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(events.last(), Some(&Event::Sleep));
        assert_eq!(
            [
                Event::Route.id(),
                Event::AdapterChange.id(),
                Event::Sleep.id()
            ],
            [0xba, 0xbc, 0x37]
        );
        assert_eq!(Event::Route.task(), Task::Controller);
        assert_eq!(Event::AdapterChange.task(), Task::Connection);
        assert_eq!(Event::Sleep.task(), Task::Connection);
    }

    #[test]
    fn refused_event_batch_retries_without_partial_header_or_route_effects() {
        let initial = state();
        let mut h = Header::new(initial);
        let data = [0xabcd_ef01, 0xff23_4567, !0, 1];
        for _ in 0..2 {
            assert_eq!(
                h.write(2, &data, |batch| {
                    assert_eq!(batch, [Event::Route, Event::AdapterChange, Event::Sleep]);
                    Err("CIO connection event queue is full")
                }),
                Err("CIO connection event queue is full")
            );
            assert_eq!(*h.state(), initial);
        }
        let mut accepted = Vec::new();
        h.write(2, &data, |batch| {
            accepted.extend_from_slice(batch);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            accepted,
            vec![Event::Route, Event::AdapterChange, Event::Sleep]
        );
        assert_eq!(h.state().header[2], data[0]);
        assert_eq!(h.state().pending_route.low, data[0]);
        assert_eq!(h.state().adapter_count, 0xff);
        h.write(2, &data, |_| panic!("retry duplicated accepted events"))
            .unwrap();
    }

    #[test]
    fn missing_callbacks_and_route_invariant_refuse_the_entire_span() {
        let mut h = Header::new(state());
        let initial = *h.state();
        assert!(h.write(8, &[1, 2], |_| panic!()).is_err());
        assert!(h.write(UUID_ALIAS, &[1, 2, 3], |_| panic!()).is_err());
        assert!(h.write(u16::MAX, &[1, 2], |_| panic!()).is_err());
        assert_eq!(*h.state(), initial);
        assert!(h.read(8, 2).is_err());
        assert!(h.read(9, 1).is_err());
        h.write(1, &[ROUTE_SELECTOR], |_| panic!()).unwrap();
        let before = *h.state();
        assert!(h.write(2, &[0x1234, ROUTE_COMMIT], |_| panic!()).is_err());
        assert_eq!(*h.state(), before);
    }
}
