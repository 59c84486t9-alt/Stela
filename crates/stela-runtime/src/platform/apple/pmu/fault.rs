//! Retained history and the original AP's complete-snapshot acknowledgement.
//!
//! mac13j26A434 `_readFaultLog` (VA 9d59cf4..9d59edc) reads the declared
//! log, then writes it back outside scratch. Extended-long SPMI transports it
//! in at most eight-byte chunks. This establishes the captured snapshot and
//! ordered chunk/retry forms, not arbitrary W1C masks, physical reset state or
//! concurrent fault arrivals.
use super::Window;
use alloc::vec::Vec;

/// The extended-long opcode carries a three-bit length-minus-one.
const CHUNK_BYTES: usize = 8;

#[derive(Debug, Clone)]
pub(super) struct FaultHistory {
    pub window: Window,
    initial: Vec<u8>,
}

impl FaultHistory {
    pub fn new(window: Window, initial: Vec<u8>) -> Result<Self, &'static str> {
        if window.bytes == 0
            // The original driver's declared fault-log count is one byte.
            || window.bytes > u16::from(u8::MAX)
            || u32::from(window.base) + u32::from(window.bytes) > 0x10000
            || initial.len() != usize::from(window.bytes)
        {
            return Err(
                "PMU fault history requires a byte-sized count, valid extent and all initial bytes",
            );
        }
        Ok(Self { window, initial })
    }
}

struct Snapshot {
    bytes: Vec<u8>,
    /// The actual prefix consumed by successful SPMI commands.
    acknowledged: usize,
    /// The next chunk, including a possible whole-provider retry from base.
    next: usize,
}

pub(super) struct FaultLog {
    pub window: Window,
    pending: Vec<u8>,
    reading: Vec<u8>,
    captured: Option<Snapshot>,
}

impl From<FaultHistory> for FaultLog {
    fn from(history: FaultHistory) -> Self {
        Self {
            window: history.window,
            pending: history.initial,
            reading: Vec::new(),
            captured: None,
        }
    }
}

impl FaultLog {
    pub fn check_read(&self) -> Result<(), &'static str> {
        if self.captured.as_ref().is_some_and(|snapshot| {
            snapshot.acknowledged != 0 && snapshot.acknowledged < self.pending.len()
        }) {
            return Err("PMU fault visibility during a partial acknowledgement is unqualified");
        }
        Ok(())
    }

    pub fn byte(&self, offset: u16) -> u8 {
        self.pending[usize::from(offset)]
    }

    /// Capture the complete logical read or its contiguous extended-long
    /// chunks. Unknown read shapes remain non-clearing but supply no ACK proof.
    pub fn capture(&mut self, address: u16, bytes: usize) {
        if address == self.window.base && bytes == self.pending.len() {
            self.reading.clear();
            self.captured = Some(Snapshot {
                bytes: self.pending.clone(),
                acknowledged: 0,
                next: 0,
            });
            return;
        }
        let offset = usize::from(address.wrapping_sub(self.window.base));
        if offset == 0 && bytes == CHUNK_BYTES.min(self.pending.len()) {
            self.reading.clear();
            self.captured = None;
        } else if self.reading.is_empty()
            || offset != self.reading.len()
            || bytes != CHUNK_BYTES.min(self.pending.len() - self.reading.len())
        {
            self.reading.clear();
            return;
        }
        self.reading
            .extend_from_slice(&self.pending[offset..offset + bytes]);
        if self.reading.len() == self.pending.len() {
            self.captured = Some(Snapshot {
                bytes: core::mem::take(&mut self.reading),
                acknowledged: 0,
                next: 0,
            });
        }
    }

    pub fn check_acknowledge(&self, address: u16, bytes: &[u8]) -> Result<(), &'static str> {
        let Some(snapshot) = &self.captured else {
            return Err("PMU fault acknowledge requires a complete captured snapshot");
        };
        let offset = usize::from(address.wrapping_sub(self.window.base));
        let whole = offset == 0 && bytes.len() == self.pending.len();
        let chunk = (offset == snapshot.next || offset == 0)
            && offset < self.pending.len()
            && bytes.len() == CHUNK_BYTES.min(self.pending.len() - offset);
        if !(whole || chunk)
            || self.pending[..snapshot.acknowledged]
                .iter()
                .any(|&byte| byte != 0)
            || self.pending[snapshot.acknowledged..] != snapshot.bytes[snapshot.acknowledged..]
            || bytes != &snapshot.bytes[offset..offset + bytes.len()]
        {
            return Err("PMU fault acknowledge differs from the ordered captured snapshot");
        }
        Ok(())
    }

    /// Each preflighted command consumes only its actual byte prefix. Retaining
    /// the completed snapshot admits the source driver's exact retry after a
    /// lost response, without inventing new pending events or clearing new bits.
    pub fn acknowledge(&mut self, address: u16, bytes: usize) {
        let snapshot = self
            .captured
            .as_mut()
            .expect("fault acknowledgement preflight");
        let offset = usize::from(address - self.window.base);
        let end = offset + bytes;
        self.pending[offset..end].fill(0);
        snapshot.acknowledged = snapshot.acknowledged.max(end);
        snapshot.next = end;
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Configuration, Pmu, RtcClock, RtcEpoch, SlaveError, SpmiSlave, tests::maverick,
    };
    use super::*;

    fn with_fault_history(initial: Vec<u8>) -> Pmu {
        let config = Configuration::new(
            alloc::vec![Window {
                base: 0x8000,
                bytes: 0x1000
            }],
            Some(maverick()),
            1,
        )
        .unwrap()
        .with_fault_history(
            Window {
                base: 0x1000,
                bytes: 10,
            },
            initial,
        )
        .unwrap();
        Pmu::with_clock(
            config,
            RtcClock::new(RtcEpoch {
                counter: 100,
                ticks: 0,
            })
            .unwrap(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn off_to_wake_source_is_a_second_independent_snapshot_owner() {
        // J514sAP Chapel: fault log <0x2200 7>, off-to-wake source <0x281c 2>.
        let log = Window {
            base: 0x2200,
            bytes: 7,
        };
        let wake = Window {
            base: 0x281c,
            bytes: 2,
        };
        let base = || {
            Configuration::new(
                alloc::vec![Window {
                    base: 0x8000,
                    bytes: 0x2800
                }],
                None,
                0,
            )
            .unwrap()
            .with_fault_history(log, alloc::vec![0x11; 7])
            .unwrap()
        };
        for (window, bytes) in [
            (log, 7),
            (
                Window {
                    base: 0x2206,
                    bytes: 2,
                },
                2,
            ),
            (
                Window {
                    base: 0x9000,
                    bytes: 2,
                },
                2,
            ),
            (
                Window {
                    base: 0x281c,
                    bytes: 0,
                },
                0,
            ),
        ] {
            assert!(
                base()
                    .with_wake_source_history(window, alloc::vec![0; bytes])
                    .is_err()
            );
        }
        assert!(
            base()
                .with_wake_source_history(wake, alloc::vec![0; 1])
                .is_err()
        );
        let config = base()
            .with_wake_source_history(wake, alloc::vec![0x04, 0x80])
            .unwrap();
        assert!(
            config
                .clone()
                .with_wake_source_history(wake, alloc::vec![0; 2])
                .is_err()
        );
        let mut pmu = Pmu::configured(config, None).unwrap();
        // An acknowledgement needs its own owner's captured snapshot.
        let mut log_bytes = [0; 7];
        pmu.read(0x2200, &mut log_bytes, 0).unwrap();
        assert!(matches!(
            pmu.write(0x281c, &[0x04, 0x80], 0),
            Err(SlaveError::Unsupported(_))
        ));
        let mut source = [0; 2];
        pmu.read(0x281c, &mut source, 0).unwrap();
        assert_eq!(source, [0x04, 0x80]);
        // `_readOff2WakeSource` writes back what it read.
        pmu.write(0x281c, &source, 0).unwrap();
        pmu.read(0x281c, &mut source, 0).unwrap();
        assert_eq!(source, [0, 0]);
        pmu.read(0x2200, &mut log_bytes, 0).unwrap();
        assert_eq!(log_bytes, [0x11; 7]);
        pmu.write(0x2200, &log_bytes, 0).unwrap();
        pmu.read(0x2200, &mut log_bytes, 0).unwrap();
        assert_eq!(log_bytes, [0; 7]);
    }

    #[test]
    fn fault_snapshot_acknowledgement_preserves_canonical_shadow_and_supports_exact_retries() {
        let initial = alloc::vec![0x19, 0x80, 0, 0x41, 0, 0, 0, 0x10, 0, 1];
        let mut pmu = with_fault_history(initial.clone());
        let mut snapshot = [0; 10];
        pmu.read(0x1000, &mut snapshot, 100).unwrap();
        assert_eq!(snapshot.as_slice(), initial);
        // The driver owns any shadow copy. It remains ordinary canonical
        // scratch storage, independent of acknowledgement of the actual latch.
        pmu.write(0x867b, &snapshot, 101).unwrap();
        pmu.write(0x1000, &snapshot, 102).unwrap();
        let mut shadow = [0; 10];
        pmu.read(0x867b, &mut shadow, 103).unwrap();
        assert_eq!(shadow, snapshot);
        // A lost response may make the original provider retry this exact
        // captured acknowledgement. It cannot create another event.
        pmu.write(0x1000, &snapshot, 104).unwrap();
        pmu.read(0x1000, &mut snapshot, 104).unwrap();
        assert_eq!(snapshot, [0; 10]);
        pmu.write(0x1000, &snapshot, 105).unwrap();
        assert_eq!(pmu.clock.published_ticks().unwrap(), 0);
    }

    #[test]
    fn unknown_fault_writes_refuse_before_latch_clock_snapshot_or_destination_effects() {
        let mut pmu = with_fault_history(alloc::vec![0xa5; 10]);
        let mut partial = [0; 9];
        pmu.read(0x1000, &mut partial, 100).unwrap();
        assert!(matches!(
            pmu.write(0x1000, &[0xa5; 10], 200),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(pmu.clock.check(100).unwrap(), 0); // No publication at200.
        let mut snapshot = [0; 10];
        pmu.read(0x1000, &mut snapshot, 100).unwrap();
        for (address, data) in [
            (0x1000, &[0xff; 10][..]),
            (0x1001, &[0xa5; 9]),
            (0x1000, &[0xa5; 9]),
        ] {
            assert!(matches!(
                pmu.write(address, data, 200),
                Err(SlaveError::Unsupported(_))
            ));
        }
        assert_eq!(pmu.clock.check(100).unwrap(), 0);
        let mut invalid_read = [0x55; 11];
        assert_eq!(
            pmu.read(0x1000, &mut invalid_read, 200),
            Err(SlaveError::Nack)
        );
        assert_eq!(invalid_read, [0x55; 11]);
        assert_eq!(pmu.write(0x1000, &[0xa5; 11], 200), Err(SlaveError::Nack));
        // A refused access did not consume or replace the prior full snapshot.
        pmu.write(0x1000, &snapshot, 100).unwrap();
        pmu.read(0x1000, &mut snapshot, 100).unwrap();
        assert_eq!(snapshot, [0; 10]);
        assert!(!pmu.interrupt().asserted());

        // Even a mapped neighbouring storage byte must not be modified by an
        // unqualified transfer spanning two distinct semantic owners.
        let config = Configuration::new(
            alloc::vec![Window {
                base: 0x100a,
                bytes: 1
            }],
            None,
            0,
        )
        .unwrap()
        .with_fault_history(
            Window {
                base: 0x1000,
                bytes: 10,
            },
            alloc::vec![0xa5; 10],
        )
        .unwrap();
        let mut adjacent = Pmu::configured(config, None).unwrap();
        adjacent.read(0x1000, &mut snapshot, 0).unwrap();
        assert!(matches!(
            adjacent.write(0x1000, &[0xff; 11], 0),
            Err(SlaveError::Unsupported(_))
        ));
        let mut neighbour = [0xff];
        adjacent.read(0x100a, &mut neighbour, 0).unwrap();
        assert_eq!(neighbour, [0]);
        adjacent.write(0x1000, &snapshot, 0).unwrap();
    }

    #[test]
    fn fault_acknowledgement_time_refusal_does_not_consume_history_or_snapshot() {
        let mut pmu = with_fault_history(alloc::vec![1; 10]);
        let mut snapshot = [0; 10];
        pmu.read(0x1000, &mut snapshot, 101).unwrap();
        assert!(matches!(
            pmu.write(0x1000, &snapshot, 100),
            Err(SlaveError::Unsupported(_))
        ));
        pmu.write(0x1000, &snapshot, 101).unwrap();
        pmu.read(0x1000, &mut snapshot, 102).unwrap();
        assert_eq!(snapshot, [0; 10]);
    }

    #[test]
    fn fault_owner_requires_complete_initial_history_and_disjoint_semantics() {
        let bare = || Configuration::new(Vec::new(), None, 0).unwrap();
        for (window, initial) in [
            (Window { base: 0, bytes: 0 }, Vec::new()),
            (
                Window {
                    base: 0xffff,
                    bytes: 2,
                },
                alloc::vec![0; 2],
            ),
            (
                Window {
                    base: 0x1000,
                    bytes: 10,
                },
                alloc::vec![0; 9],
            ),
            (
                Window {
                    base: 0x1000,
                    bytes: 256,
                },
                alloc::vec![0; 256],
            ),
        ] {
            assert!(bare().with_fault_history(window, initial).is_err());
        }
        let log = Window {
            base: 0x1000,
            bytes: 10,
        };
        let configured = || bare().with_fault_history(log, alloc::vec![0; 10]).unwrap();
        assert!(
            configured()
                .with_fault_history(log, alloc::vec![0; 10])
                .is_err()
        );
        assert!(configured().with_unqualified_identity(log).is_err());
        assert!(
            bare()
                .with_unqualified_identity(log)
                .unwrap()
                .with_fault_history(log, alloc::vec![0; 10])
                .is_err()
        );
        assert!(
            Configuration::new(
                alloc::vec![Window {
                    base: 0x1005,
                    bytes: 10
                }],
                None,
                0
            )
            .unwrap()
            .with_fault_history(log, alloc::vec![0; 10])
            .is_err()
        );
        assert!(
            Configuration::new(Vec::new(), Some(maverick()), 1)
                .unwrap()
                .with_fault_history(
                    Window {
                        base: 0x1400,
                        bytes: 10
                    },
                    alloc::vec![0; 10]
                )
                .is_err()
        );
        let edge = bare()
            .with_fault_history(
                Window {
                    base: u16::MAX,
                    bytes: 1,
                },
                alloc::vec![0x80],
            )
            .unwrap();
        let mut edge = Pmu::configured(edge, None).unwrap();
        let mut snapshot = [0];
        edge.read(u16::MAX, &mut snapshot, 0).unwrap();
        assert_eq!(snapshot, [0x80]);
        edge.write(u16::MAX, &snapshot, 0).unwrap();
        edge.read(u16::MAX, &mut snapshot, 0).unwrap();
        assert_eq!(snapshot, [0]);
    }

    #[test]
    fn source_fault_counts_and_eight_byte_transport_keep_exact_partial_progress_and_retries() {
        for count in [1u16, 8, 9, 10, 16, 255] {
            let initial: Vec<_> = (0..count).map(|index| index as u8 | 0x80).collect();
            let config = Configuration::new(Vec::new(), None, 0)
                .unwrap()
                .with_fault_history(
                    Window {
                        base: 0x1000,
                        bytes: count,
                    },
                    initial.clone(),
                )
                .unwrap();
            let mut pmu = Pmu::configured(config, None).unwrap();
            let mut snapshot = alloc::vec![0; usize::from(count)];
            for (index, chunk) in snapshot.chunks_mut(8).enumerate() {
                pmu.read(0x1000 + (index * 8) as u16, chunk, 0).unwrap();
                if count > 8 && index == 0 {
                    assert!(matches!(
                        pmu.write(0x1000, chunk, 0),
                        Err(SlaveError::Unsupported(_))
                    ));
                }
            }
            assert_eq!(snapshot, initial);
            if count > 8 {
                assert!(matches!(
                    pmu.write(0x1008, &snapshot[8..], 0),
                    Err(SlaveError::Unsupported(_))
                ));
            }
            for (index, chunk) in snapshot.chunks(8).enumerate() {
                let address = 0x1000 + (index * 8) as u16;
                pmu.write(address, chunk, 0).unwrap();
                // A source-provider retry starts at the log base. Earlier
                // committed commands remain consumed; their exact replay is
                // idempotent and cannot clear anything newly invented.
                if index == 0 {
                    if count > 8 {
                        let mut competing_read = [0x55];
                        assert!(matches!(
                            pmu.read(0x1000, &mut competing_read, 0),
                            Err(SlaveError::Unsupported(_))
                        ));
                        assert_eq!(competing_read, [0x55]);
                    }
                    let mut wrong = chunk.to_vec();
                    wrong[0] ^= 1;
                    assert!(matches!(
                        pmu.write(address, &wrong, 0),
                        Err(SlaveError::Unsupported(_))
                    ));
                    pmu.write(address, chunk, 0).unwrap();
                }
            }
            // A whole logical retry after a lost final response is likewise
            // bounded by that same captured snapshot.
            pmu.write(0x1000, &snapshot, 0).unwrap();
            pmu.read(0x1000, &mut snapshot, 0).unwrap();
            assert!(snapshot.iter().all(|&byte| byte == 0));
        }
    }

    #[test]
    fn original_ten_byte_fault_sequence_retires_real_spmi_chunks_and_keeps_failed_tail_unconsumed()
    {
        use crate::platform::apple::spmi::Spmi;
        use alloc::{boxed::Box, rc::Rc};
        use core::cell::RefCell;
        use stela_contracts::bus::Access;
        use stela_contracts::bus::MmioDevice;
        use stela_contracts::bus::MmioError;
        use stela_contracts::bus::Width;
        use stela_contracts::interrupt::AicInput;
        use stela_contracts::interrupt::InterruptLatch;
        struct ObservedPmu(Rc<RefCell<Pmu>>);
        impl SpmiSlave for ObservedPmu {
            fn read(&mut self, address: u16, data: &mut [u8], now: u64) -> Result<(), SlaveError> {
                self.0.borrow_mut().read(address, data, now)
            }
            fn write(&mut self, address: u16, data: &[u8], now: u64) -> Result<(), SlaveError> {
                self.0.borrow_mut().write(address, data, now)
            }
        }
        const REQUEST: u64 = 4;
        const RESPONSE: u64 = 8;
        const RESPONSE_PENDING: u64 = 0x60 + 6 * 4; // Actual Gen1 vector192.
        const ACK: u64 = 1 << 15;
        let initial: Vec<_> = (0..10).map(|index| 0x80 + index).collect();
        let configuration = Configuration::new(Vec::new(), None, 0)
            .unwrap()
            .with_fault_history(
                Window {
                    base: 0x1000,
                    bytes: 10,
                },
                initial.clone(),
            )
            .unwrap();
        let owner = Rc::new(RefCell::new(Pmu::configured(configuration, None).unwrap()));
        let pending = || {
            let owner = owner.borrow();
            let fault = &owner.histories[0];
            (0..10).map(|offset| fault.byte(offset)).collect::<Vec<_>>()
        };
        let mut controller = Spmi::with_configuration(
            AicInput::new(0, 228),
            stela_soc_data::spmi::Configuration::new(
                stela_soc_data::spmi::Profile::Gen1,
                192,
                [256, 256],
            )
            .unwrap(),
        );
        controller
            .attach(15, Box::new(ObservedPmu(owner.clone())))
            .unwrap();
        let mut interrupts = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut interrupts);
        let put = |controller: &mut Spmi, access: &mut Access<'_>, value: u32| {
            controller
                .write(REQUEST, Width::Word, u64::from(value), access)
                .unwrap();
        };
        let pop = |controller: &mut Spmi, access: &mut Access<'_>| {
            controller.read(RESPONSE, Width::Word, access).unwrap()
        };
        let mut snapshot = Vec::new();
        for (address, bytes, last) in [(0x1000u32, 8usize, false), (0x1008, 2, true)] {
            put(
                &mut controller,
                &mut access,
                address << 16 | u32::from(last) << 15 | 15 << 8 | 0x38 | (bytes - 1) as u32,
            );
            let response = pop(&mut controller, &mut access);
            assert_ne!(response & ACK, 0);
            assert_eq!(response >> 16, (1 << bytes) - 1);
            for word in 0..bytes.div_ceil(4) {
                let data = (pop(&mut controller, &mut access) as u32).to_le_bytes();
                snapshot.extend_from_slice(&data[..(bytes - word * 4).min(4)]);
            }
        }
        assert_eq!(snapshot, initial);
        let first = 0x1000 << 16 | 15 << 8 | 0x37;
        put(&mut controller, &mut access, first);
        for word in snapshot[..8].as_chunks::<4>().0 {
            put(&mut controller, &mut access, u32::from_le_bytes(*word));
        }
        assert_ne!(pop(&mut controller, &mut access) & ACK, 0);
        assert_eq!(pending(), [0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x89]);
        controller
            .write(RESPONSE_PENDING, Width::Word, 1, &mut access)
            .unwrap();
        put(
            &mut controller,
            &mut access,
            0x1008 << 16 | 1 << 15 | 15 << 8 | 0x31,
        );
        assert!(matches!(
            controller.write(REQUEST, Width::Word, 0xffff, &mut access),
            Err(MmioError::Unsupported { .. })
        ));
        assert_eq!(pending(), [0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x89]);
        assert!(controller.read(RESPONSE, Width::Word, &mut access).is_err());
        assert_eq!(
            controller.read(RESPONSE_PENDING, Width::Word, &mut access),
            Ok(0)
        );
        // The failed final word remains unconsumed; retry that actual payload,
        // without another header or replaying the already retired prefix.
        put(&mut controller, &mut access, 0x8988);
        assert_ne!(pop(&mut controller, &mut access) & ACK, 0);
        assert_eq!(pending(), [0; 10]);
        assert_eq!(
            controller.read(RESPONSE_PENDING, Width::Word, &mut access),
            Ok(1)
        );
    }

    #[test]
    fn inside_scratch_fault_history_keeps_one_storage_owner_and_source_zero_clear() {
        let config = Configuration::new(
            alloc::vec![Window {
                base: 0x8000,
                bytes: 16
            }],
            None,
            0,
        )
        .unwrap();
        assert!(
            config
                .clone()
                .with_fault_history(
                    Window {
                        base: 0x8004,
                        bytes: 4
                    },
                    alloc::vec![0; 4]
                )
                .is_err()
        );
        let mut pmu = Pmu::configured(config, None).unwrap();
        pmu.write(0x8000, &[0xa5; 16], 0).unwrap();
        let mut faults = [0; 4];
        pmu.read(0x8004, &mut faults, 0).unwrap();
        assert_eq!(faults, [0xa5; 4]);
        pmu.write(0x8004, &[0; 4], 0).unwrap();
        let mut scratch = [0; 16];
        pmu.read(0x8000, &mut scratch, 0).unwrap();
        assert_eq!(
            scratch,
            [
                0xa5, 0xa5, 0xa5, 0xa5, 0, 0, 0, 0, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5
            ]
        );
    }
}
