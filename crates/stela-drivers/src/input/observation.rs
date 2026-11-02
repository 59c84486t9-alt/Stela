//! Single-poll input observations, retaining actual logical-source identity.
//! Source is an Rc object produced inside the real transport/client owner. Its
//! fields/order/status are observations, never native or kernel permissions.
//! The global input owner separately retains the SAME actual physical owner;
//! this module never stores an owning backedge to it or an entered root loan.
use super::Input;
use crate::usb::hid::descriptor::{DecodeError, Descriptor, Frame};
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;
pub use stela_driver_base::input_observation::{
    Capabilities, Event, FailureDisposition, FailureOrigin, FailureRetention, InitialState,
    KeyState, Knowledge, SwitchState,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    UsbInterface { interface: u8 },
    IshClient { client: u32 },
    I2cHid,
    Virtio,
    Ps2Keyboard,
    Ps2Pointer,
}

/// Source-owned upstream grouping policy, not hardware permission. Unknown
/// policy must remain Unknown; no caller may assume absent quirks mean false.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HidGrouping {
    pub multi_input: bool,
    pub input_per_application: bool,
    pub no_input_sync: bool,
}
#[derive(Clone, Debug)]
pub enum Format {
    Hid {
        descriptor: Rc<Descriptor>,
        grouping: Knowledge<HidGrouping>,
    },
    Linux {
        capabilities: Capabilities,
    },
    /// Actual negotiated raw mode only; NOT qualification of original
    /// atkbd remap/repeat/force-release/platform policy.
    ScanSet2,
}
#[derive(Clone, Debug)]
pub struct Description {
    pub origin: Origin,
    pub format: Format,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCause {
    Removed,
    TransportFailed,
    ProducerDropped,
    OrderExhausted,
    ObservationClosed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Producing,
    Stopped(StopCause),
}
#[derive(Debug)]
struct State {
    description: Description,
    initial: InitialState,
    status: Cell<Status>,
    next_order: Cell<u64>,
}
/// Actual logical endpoint object identity, not a counter-minted source ID.
/// Clones retain metadata/status only. HostInput binding retains the real
/// physical/client graph too and checks membership under its source owner.
#[derive(Clone, Debug)]
pub struct Source(Rc<State>);
impl Source {
    pub fn same_object(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
    pub fn description(&self) -> &Description {
        &self.0.description
    }
    pub fn initial_state(&self) -> InitialState {
        self.0.initial.clone()
    }
    pub fn status(&self) -> Status {
        self.0.status.get()
    }
    /// Next report order; only an observation frontier, never delivery proof.
    pub fn producer_frontier(&self) -> u64 {
        self.0.next_order.get()
    }
}

/// This field belongs to the actual transport/logical client that decodes its
/// reports, never an InputDevice-wide substitute for multiple real clients.
/// No Source constructor or numeric lookup is exposed outside this crate.
pub(crate) struct Producer {
    source: Source,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishError {
    Stopped(StopCause),
    OrderExhausted,
}
impl Producer {
    pub(crate) fn new(description: Description, initial: InitialState) -> Self {
        Self {
            source: Source(Rc::new(State {
                description,
                initial,
                status: Cell::new(Status::Producing),
                next_order: Cell::new(0),
            })),
        }
    }
    pub(crate) fn source(&self) -> Source {
        self.source.clone()
    }
    /// Only genuine complete source snapshots may call this; an empty local
    /// decoder-held vector, config capability bit or reset ACK is not one.
    #[cfg(test)]
    pub(crate) fn observe_initial(&mut self, state: InitialState) -> Result<Change, PublishError> {
        self.check()?;
        Ok(Change::InitialObserved {
            source: self.source(),
            initial: state,
            next_order: self.source.producer_frontier(),
        })
    }
    fn check(&self) -> Result<(), PublishError> {
        match self.source.status() {
            Status::Producing => Ok(()),
            Status::Stopped(cause) => Err(PublishError::Stopped(cause)),
        }
    }
    pub(crate) fn report(&mut self, payload: Payload) -> Result<Report, RefusedReport> {
        if let Err(error) = self.check() {
            return Err(RefusedReport { error, payload });
        }
        let order = self.source.producer_frontier();
        let Some(next) = order.checked_add(1) else {
            self.source
                .0
                .status
                .set(Status::Stopped(StopCause::OrderExhausted));
            return Err(RefusedReport {
                error: PublishError::OrderExhausted,
                payload,
            });
        };
        self.source.0.next_order.set(next);
        Ok(Report {
            source: self.source(),
            order,
            payload,
        })
    }
    /// Closes future production only. Already accepted ordered prefixes must
    /// be drained or explicitly quarantined before original device unregister.
    pub(crate) fn stop(&mut self, cause: StopCause) -> Option<Change> {
        if self.source.status() != Status::Producing {
            return None;
        }
        self.source.0.status.set(Status::Stopped(cause));
        Some(Change::Stopped {
            source: self.source(),
            cause,
            next_order: self.source.producer_frontier(),
        })
    }
}
impl Drop for Producer {
    fn drop(&mut self) {
        if self.source.status() == Status::Producing {
            self.source
                .0
                .status
                .set(Status::Stopped(StopCause::ProducerDropped));
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidOrigin {
    InputReport,
    /// Proven GET_REPORT/initial snapshot, not a synthetic live key edge.
    InitialSnapshot,
    /// Actual ISH host/aggregate framing facts; no clock, policy or identity grant.
    IshInput {
        hostif_command: u8,
        flags: u8,
        aggregate_total_size: Option<u16>,
        aggregate_flags: Option<u8>,
    },
    CorrectedLength {
        reported_length: u16,
        read_length: u16,
    },
}
#[derive(Clone, Debug)]
pub enum Payload {
    /// The SAME Translator/descriptor-decoded frame. The mapper, not a flat
    /// Keyboard/Consumer event list, resolves collections and original sync.
    Hid { frame: Frame, origin: HidOrigin },
    /// Malformed source reports retain bytes and exact decoder cause.
    HidRejected { bytes: Vec<u8>, error: DecodeError },
    /// Original signed Linux code/value order, including actual SYN events.
    /// A poll boundary never creates a SYN that the source did not provide.
    Linux { events: Vec<Event> },
    /// Same raw scan-set-2 byte prefix; this envelope creates no SYN, key
    /// mapping, repeat or Pause pulse. Original policy may remain unknown.
    ScanSet2 { bytes: Vec<u8> },
}
#[derive(Clone, Debug)]
pub struct Report {
    pub source: Source,
    pub order: u64,
    pub payload: Payload,
}
#[derive(Clone, Debug)]
pub enum Change {
    Added(Source),
    InitialObserved {
        source: Source,
        initial: InitialState,
        next_order: u64,
    },
    Stopped {
        source: Source,
        cause: StopCause,
        next_order: u64,
    },
}
#[derive(Clone, Debug)]
pub struct RefusedReport {
    pub error: PublishError,
    pub payload: Payload,
}
#[derive(Clone, Debug)]
pub enum Item {
    Change(Change),
    Report(Report),
    PublishRefused {
        source: Source,
        refusal: RefusedReport,
    },
}
#[derive(Debug, Default)]
pub struct Batch {
    pub items: Vec<Item>,
}
impl Batch {
    pub(crate) fn publish(&mut self, producer: &mut Producer, payload: Payload) {
        let source = producer.source();
        self.items.push(match producer.report(payload) {
            Ok(report) => Item::Report(report),
            Err(refusal) => Item::PublishRefused { source, refusal },
        });
    }
    pub fn append(&mut self, other: &mut Self) {
        self.items.append(&mut other.items);
    }
}
/// Completed decoded prefixes survive an error. Do not clear this on transport
/// invalidation or replay reports already returned in an earlier poll.
#[derive(Debug)]
pub struct NativePoll<E> {
    pub inputs: Vec<Input>,
    pub observations: Batch,
    pub first_error: Option<E>,
    pub later_errors: Vec<E>,
}
impl<E> Default for NativePoll<E> {
    fn default() -> Self {
        Self {
            inputs: Vec::new(),
            observations: Batch::default(),
            first_error: None,
            later_errors: Vec::new(),
        }
    }
}
impl<E> NativePoll<E> {
    pub fn record_error(&mut self, error: E) {
        if self.first_error.is_none() {
            self.first_error = Some(error);
        } else {
            self.later_errors.push(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn producer() -> Producer {
        // Private metadata-only fixture. This supplies no native owner/grant.
        Producer::new(
            Description {
                origin: Origin::Virtio,
                format: Format::Linux {
                    capabilities: Capabilities {
                        keys: vec![238],
                        switches: vec![],
                    },
                },
            },
            InitialState::unknown(),
        )
    }
    fn payload(value: i32) -> Payload {
        Payload::Linux {
            events: vec![Event {
                kind: 1,
                code: 238,
                value,
            }],
        }
    }
    #[test]
    fn equal_labels_do_not_alias_actual_source_objects() {
        let a = producer();
        let b = producer();
        assert!(!a.source().same_object(&b.source()));
        assert!(a.source().same_object(&a.source()));
    }
    #[test]
    fn ordered_prefix_survives_close_and_refusal_keeps_payload() {
        let mut producer = producer();
        let mut batch = Batch::default();
        batch.publish(&mut producer, payload(1));
        batch.items.push(Item::Change(
            producer.stop(StopCause::ObservationClosed).unwrap(),
        ));
        batch.publish(&mut producer, payload(0));
        assert!(matches!(
            &batch.items[0],
            Item::Report(Report { order: 0, .. })
        ));
        assert!(matches!(
            &batch.items[1],
            Item::Change(Change::Stopped { next_order: 1, .. })
        ));
        let Item::PublishRefused { refusal, .. } = &batch.items[2] else {
            panic!("missing typed refusal")
        };
        assert_eq!(
            refusal.error,
            PublishError::Stopped(StopCause::ObservationClosed)
        );
        let Payload::Linux { events } = &refusal.payload else {
            panic!("lost original payload")
        };
        assert_eq!(events[0].value, 0);
        assert_eq!(producer.source().producer_frontier(), 1);
    }
    #[test]
    fn initial_snapshots_are_owned_at_their_actual_frontier() {
        let mut producer = producer();
        let original = producer.source();
        producer.report(payload(1)).unwrap();
        let first = producer
            .observe_initial(InitialState {
                keys: Knowledge::Observed(vec![KeyState {
                    code: 238,
                    pressed: true,
                }]),
                switches: Knowledge::NotApplicable,
            })
            .unwrap();
        producer.report(payload(0)).unwrap();
        let second = producer
            .observe_initial(InitialState {
                keys: Knowledge::Observed(vec![KeyState {
                    code: 238,
                    pressed: false,
                }]),
                switches: Knowledge::NotApplicable,
            })
            .unwrap();
        assert_eq!(original.initial_state(), InitialState::unknown());
        let Change::InitialObserved {
            initial: a,
            next_order: 1,
            ..
        } = first
        else {
            panic!("wrong first frontier")
        };
        let Change::InitialObserved {
            initial: b,
            next_order: 2,
            ..
        } = second
        else {
            panic!("wrong second frontier")
        };
        assert_eq!(
            a.keys,
            Knowledge::Observed(vec![KeyState {
                code: 238,
                pressed: true
            }])
        );
        assert_eq!(
            b.keys,
            Knowledge::Observed(vec![KeyState {
                code: 238,
                pressed: false
            }])
        );
    }
    #[test]
    fn exhausted_order_refuses_without_wrapping_or_losing_payload() {
        let mut producer = producer();
        producer.source.0.next_order.set(u64::MAX);
        let refusal = producer.report(payload(2)).unwrap_err();
        assert_eq!(refusal.error, PublishError::OrderExhausted);
        assert_eq!(producer.source().producer_frontier(), u64::MAX);
        assert_eq!(
            producer.source().status(),
            Status::Stopped(StopCause::OrderExhausted)
        );
        let Payload::Linux { events } = refusal.payload else {
            panic!("lost payload")
        };
        assert_eq!(events[0].value, 2);
    }
}

#[cfg(test)]
mod failure_custody_tests {
    use super::*;
    use crate::input::ps2::{Error as Ps2Error, ErrorKind, ObservedResponse, Port};
    use core::cell::Cell;
    struct ModelOwner(Rc<Cell<usize>>);
    impl Drop for ModelOwner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    #[test]
    fn recoverable_then_fatal_preserves_exact_typed_cause_and_same_model_owner() {
        // Private data/retention model only; no native input/KernelOwner grant.
        let drops = Rc::new(Cell::new(0));
        let owner = Rc::new(ModelOwner(drops.clone()));
        let first: Ps2Error = ErrorKind::UnsupportedScanCode(0x133).into();
        let mut fatal: Ps2Error = ErrorKind::Frame {
            port: Port::Keyboard,
            status: 0xc0,
        }
        .into();
        fatal.response = Some(ObservedResponse {
            port: Port::Keyboard,
            data: 0x5a,
        });
        fatal.recovery_error = Some(ErrorKind::KeyboardSequence);
        fatal.recovery_response = Some(ObservedResponse {
            port: Port::Keyboard,
            data: 0xa5,
        });
        let mut ledger = FailureRetention::new();
        let mut retained = Vec::new();
        for (terminal, closed, error) in [(false, false, first), (true, true, fatal)] {
            let disposition = ledger.observe(terminal, closed);
            if disposition.retains_cause() {
                retained.push((disposition, error, owner.clone()));
            }
        }
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].0, FailureDisposition::RetainFirst);
        assert_eq!(retained[1].0, FailureDisposition::RetainTerminal);
        assert!(matches!(
            retained[0].1.kind,
            ErrorKind::UnsupportedScanCode(0x133)
        ));
        assert!(matches!(
            retained[1].1.kind,
            ErrorKind::Frame {
                port: Port::Keyboard,
                status: 0xc0
            }
        ));
        assert_eq!(
            retained[1].1.response,
            Some(ObservedResponse {
                port: Port::Keyboard,
                data: 0x5a
            })
        );
        assert!(matches!(
            retained[1].1.recovery_error,
            Some(ErrorKind::KeyboardSequence)
        ));
        assert_eq!(
            retained[1].1.recovery_response,
            Some(ObservedResponse {
                port: Port::Keyboard,
                data: 0xa5
            })
        );
        assert!(Rc::ptr_eq(&retained[0].2, &retained[1].2));
        drop(owner);
        assert_eq!(drops.get(), 0);
        // No native/C effect ever started in this private model; exact model
        // references may retire normally, unlike a production retained graph.
        drop(retained);
        assert_eq!(drops.get(), 1);
    }
    #[test]
    fn first_led_terminal_pass_is_not_replaced_by_later_needs_reset_status() {
        let mut ledger = FailureRetention::new();
        let origin = FailureOrigin::GuestLed;
        let original: Ps2Error = ErrorKind::KeyboardSequence.into();
        assert_eq!(ledger.observe(true, false), FailureDisposition::RetainFirst);
        for _ in 0..10000 {
            assert_eq!(
                ledger.observe(true, true),
                FailureDisposition::RepeatedStoppedStatus
            );
        }
        assert_eq!(origin, FailureOrigin::GuestLed);
        assert!(matches!(original.kind, ErrorKind::KeyboardSequence));
        assert_eq!(ledger.repeated_stopped_passes(), 10000);
    }
}
