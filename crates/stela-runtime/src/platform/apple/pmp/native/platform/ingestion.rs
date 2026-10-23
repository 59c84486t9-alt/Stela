//! Generic native counter ingestion and postprocessing over actual Frames receipts.
//!
//! Original26A434 T8112 PMP SHA256 b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//! capture101a780..101ab30, postprocess101ab30..101b074, query101b29c,
//! delta/scaling101b2c4..101b3d0, extract101b8fc..101ba6c.
//! Fresh static ledger: pmgr/counter-ingestion-r1. No firmware executes here.
//! Copied/Retained inputs bind storage, not hardware events, lifecycle or an ACK.
//! This is the generic base; specialized DCS/AMCC/AGX/ANE surrounding hooks
//! remain separate owners. Provider and auxiliary operations have no default
//! success implementation; their actual owners retain any inner partial work.
mod arithmetic;
mod model;
use super::super::counters::{Copied, Frame, Frames, Retained};
use super::owner::{Completion, CounterContext, EffectValue};
use super::{CounterReference, Descriptor, Ordinal};
use crate::platform::apple::bus::Access;
use alloc::{collections::VecDeque, rc::Rc, vec, vec::Vec};
pub use arithmetic::{Delta, Pair, Statistics};
pub use model::{Auxiliary, Configuration, Frequency};

const TIME_MASK: u64 = (1 << 54) - 1;
/// Pure original101b974 field arithmetic over supplied frame data; no copy,
/// event or arrival authority is created by this helper.
pub fn extract_field(cells: &[Frame], start: u32, width: u32) -> Result<u64, Error> {
    extract(cells, start, width)
}
pub fn delta(buffer_index: u32, flags: u32, pairs: [Pair; 2], periods: (u32, u64)) -> Delta {
    arithmetic::delta(buffer_index, flags, pairs, periods)
}
pub fn scaled_delta(
    buffer_index: u32,
    reference: CounterReference,
    pairs: [Pair; 2],
    periods: (u32, u64),
) -> Result<Delta, Error> {
    arithmetic::scaled(buffer_index, reference, pairs, periods)
}

#[derive(Clone, Debug)]
pub struct Request {
    owner: Rc<()>,
    serial: u64,
    cursor: u64,
}
impl Request {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.serial == other.serial
            && self.cursor == other.cursor
    }
}
/// Actual resource calls. Numeric IDs are typed descriptor selectors, never
/// native code addresses. Snapshot returns require the real fixed provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    ProviderValue {
        slot: u32,
        index: u32,
    },
    ProviderTuple {
        slot: u32,
        index: u32,
    },
    Clock,
    /// Actual101ba6c provider-cache read: consume only if that real bank/index
    /// has not been consumed in the source manager cycle. A repeated timestamp
    /// read returns the retained tuple and must never consume the PTD twice.
    ExtendedFrame {
        bank: u32,
        index: u32,
    },
    State,
    ExtendedCount {
        bank: u32,
    },
    /// Retained result of actual provider initialization(+40), not a new
    /// initialization call during Postprocess or a nominal scale fallback.
    InitializedScale {
        reference: u32,
        slot: u32,
        index: u32,
    },
    StateChanged {
        source: u32,
        previous: u32,
        current: u32,
    },
    /// Full reached101b464 control tail, including101bb08 transitions, member
    /// reads/writes and auxiliary PTD consumes. Backend must retain its own inner
    /// cursor; absent/unknown configured callbacks must explicitly refuse.
    ControlTail {
        ordinal: Ordinal,
        context: CounterContext,
        /// Actual retained P294 activation from this ingestion operation.
        /// P10 activity in `context` is a distinct source operand.
        activation: u32,
        descriptors: Vec<Auxiliary>,
    },
    /// Actual source-derived coefficient rows after101c2e4 initialization/update.
    /// This is observed provider/configuration data, never completion authority.
    Coefficients {
        row: u32,
        source: Frequency,
    },
    OutputLayout {
        source: u32,
    },
    PublishInteger {
        entry: u32,
        value: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Word(u64),
    Pair(Pair),
    Complete,
    Layout {
        start: u32,
        count: u32,
    },
    Coefficients {
        active: Vec<u32>,
        inactive: Vec<u32>,
        extra: Vec<u32>,
    },
}
pub trait Backend {
    fn call(
        &mut self,
        request: &Request,
        call: &Call,
        access: &mut Access<'_>,
    ) -> Completion<Value>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Contract(&'static str),
    Refused(&'static str),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Busy { deadline: Option<u64> },
    Complete(EffectValue),
}
#[derive(Clone, Copy, Debug)]
enum Target {
    Base(usize),
    Integer(usize),
    Frequency(usize, usize),
}
#[derive(Clone, Debug)]
enum Op {
    Decode(CounterReference, Target),
    ProviderWord {
        target: Target,
    },
    ProviderClock {
        target: Target,
        value: u64,
    },
    Tuple {
        reference: CounterReference,
        target: Target,
        next: u32,
        total: u32,
        pair: Option<Pair>,
    },
    Integer {
        reference: CounterReference,
        target: Target,
        next: u32,
        sum: u64,
    },
    Call(Call),
    SetState,
    StateCurrent(u32),
    Timestamp {
        target: Target,
        value: u64,
    },
    ExtendedCount {
        reference: CounterReference,
        target: Target,
    },
    Tail,
    Increment,
    Post,
}
struct Batch {
    serial: u64,
    cursor: u64,
    ops: VecDeque<Op>,
    context: CounterContext,
    activation: u32,
    ordinal: Ordinal,
    value: Option<Value>,
}
enum FrameInput {
    Copied(Copied),
    Retained(Retained),
}
impl FrameInput {
    fn layout(&self) -> super::super::counters::Layout {
        match self {
            Self::Copied(input) => input.layout(),
            Self::Retained(input) => input.layout(),
        }
    }
    fn cells<'a>(&self, frames: &'a Frames) -> Result<&'a [Frame], Error> {
        match self {
            Self::Copied(input) => frames.cells(input),
            Self::Retained(input) => frames.retained_cells(input),
        }
        .map_err(Error::Contract)
    }
}
/// Retained native software counter buffers; zeros are explicit initializer
/// state, never observations of hardware. A real frame storage view remains owned
/// throughout Capture/Postprocess and is revalidated before every advance.
pub struct Owner<B: Backend> {
    identity: Rc<()>,
    serial: u64,
    backend: B,
    config: Configuration,
    receipt: Option<FrameInput>,
    awaiting_post: bool,
    batch: Option<Batch>,
    fault: Option<&'static str>,
    base: [[Pair; 2]; 6],
    integer: [[Pair; 2]; 2],
    frequency: Vec<[[Pair; 2]; 2]>,
    products: EffectValue,
    activation_util: Vec<u32>,
    evaluated_util: Vec<u32>,
    metrics: [[u32; 3]; 2],
    rates: [[u32; 3]; 2],
    integer_rates: [u32; 2],
    stats: [[Statistics; 3]; 2],
    accumulated: u64,
    ratio: u32,
}
impl<B: Backend> Owner<B> {
    pub fn initialized_software(config: Configuration, backend: B) -> Self {
        let n = config.frequencies.len();
        let histogram_shift = config.histogram_shift;
        Self {
            identity: Rc::new(()),
            serial: 0,
            backend,
            config,
            receipt: None,
            awaiting_post: false,
            batch: None,
            fault: None,
            base: [[Pair::default(); 2]; 6],
            integer: [[Pair::default(); 2]; 2],
            frequency: vec![[[Pair::default(); 2]; 2]; n],
            products: EffectValue::Hook {
                buffer_index: 0,
                state_index: 0,
                previous_state_index: 0,
            },
            activation_util: vec![0; n],
            evaluated_util: vec![0; n],
            metrics: [[0; 3]; 2],
            rates: [[0; 3]; 2],
            integer_rates: [0; 2],
            stats: core::array::from_fn(|_| {
                core::array::from_fn(|_| Statistics::initialized(32, histogram_shift))
            }),
            accumulated: 0,
            ratio: 0,
        }
    }
    pub fn ordinal(&self) -> Ordinal {
        self.config.ordinal
    }
    /// Actual initialized source P268/P270 software cells, not elapsed host time.
    pub fn periods(&self) -> (u32, u64) {
        self.config.periods
    }
    /// Source101c54c STR XZR,[P+10] on enable-from-zero resets P14 along
    /// with the parent's activity. This mutates software data only; it grants
    /// no activation, provider completion, frame/event or arrival authority.
    /// The actual activation owner calls this at that store's retained cursor,
    /// before its later real provider/PTD effects. Existing buffers are kept.
    pub fn apply_source_activation_reset(&mut self) -> Result<(), Error> {
        self.idle()?;
        let (_, state, previous) = self.products();
        self.products = EffectValue::Hook {
            buffer_index: 0,
            state_index: state,
            previous_state_index: previous,
        };
        self.awaiting_post = false;
        Ok(())
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    /// Read only through the retained actual storage view. This grants no
    /// Capture-completion, arrival or hardware-event authority to a wrapper.
    pub fn cells<'a>(&self, frames: &'a Frames) -> Result<&'a [Frame], Error> {
        self.receipt
            .as_ref()
            .ok_or(Error::Contract("generic retained frame storage absent"))?
            .cells(frames)
    }
    pub fn metrics(&self) -> [[u32; 3]; 2] {
        self.metrics
    }
    pub fn rates(&self) -> [[u32; 3]; 2] {
        self.rates
    }
    pub fn utilities(&self) -> (&[u32], &[u32]) {
        (&self.activation_util, &self.evaluated_util)
    }
    pub fn integer_rates(&self) -> [u32; 2] {
        self.integer_rates
    }
    pub fn ratio(&self) -> u32 {
        self.ratio
    }
    pub fn statistics(&self) -> &[[Statistics; 3]; 2] {
        &self.stats
    }
    ///101b29c queries the rate array only for evaluated1. Selector/kind are
    /// bounded native descriptor indices; no successful zero for invalid input.
    pub fn query(&self, evaluated: u32, selector: u32, kind: u32) -> Result<u32, Error> {
        if selector >= 2 || kind >= 3 {
            return Err(Error::Contract(
                "generic counter query outside2x3 rate array",
            ));
        }
        Ok(if evaluated == 1 {
            self.rates[selector as usize][kind as usize]
        } else {
            0
        })
    }
    pub fn begin_capture(
        &mut self,
        frames: &Frames,
        copied: Copied,
        d: &Descriptor,
        context: CounterContext,
        activation: u32,
    ) -> Result<(), Error> {
        self.begin_capture_input(frames, FrameInput::Copied(copied), d, context, activation)
    }
    /// Source101a7b0/101a7b8 skips bulk for zero counter count or zero P10.
    /// Read the same retained
    /// software storage without copying, consuming, or mutating Frames progress.
    /// Initial software cells remain explicitly distinguishable from samples.
    pub fn begin_retained_capture(
        &mut self,
        frames: &Frames,
        retained: Retained,
        d: &Descriptor,
        context: CounterContext,
        activation: u32,
    ) -> Result<(), Error> {
        self.idle()?;
        if context.activity != 0 && d.counter_slice().is_some() {
            return Err(Error::Contract(
                "generic retained input requires source bulk-copy skip",
            ));
        }
        self.begin_capture_input(
            frames,
            FrameInput::Retained(retained),
            d,
            context,
            activation,
        )
    }
    fn begin_capture_input(
        &mut self,
        frames: &Frames,
        input: FrameInput,
        d: &Descriptor,
        context: CounterContext,
        activation: u32,
    ) -> Result<(), Error> {
        self.idle()?;
        if context.buffer_index != self.products().0 {
            return Err(Error::Contract(
                "generic Capture buffer index differs from retained owner",
            ));
        }
        let layout = input.layout();
        if layout.ordinal != d.ordinal().index() as u32 || d.ordinal() != self.config.ordinal {
            return Err(Error::Contract(
                "generic ingestion receipt/descriptor ordinal mismatch",
            ));
        }
        match d.counter_slice() {
            Some(slice) if layout.start != slice.start || layout.count != slice.count => {
                return Err(Error::Contract("generic ingestion receipt slice mismatch"));
            }
            None if layout.count != 0 => {
                return Err(Error::Contract(
                    "generic no-counter descriptor received a nonempty frame slice",
                ));
            }
            _ => {}
        }
        input.cells(frames)?;
        self.receipt = Some(input);
        self.awaiting_post = true;
        self.products = EffectValue::Hook {
            buffer_index: context.buffer_index,
            state_index: context.state_index,
            previous_state_index: context.previous_state_index,
        };
        let mut ops = VecDeque::new();
        if context.pending == 1 && context.evaluated == 0 {
            ops.push_back(Op::Tail);
        } else {
            if let Some(controller) = d.controller() {
                let current = context.current_packet.0[(controller / 16) as usize]
                    >> ((controller % 16) * 4)
                    & 15;
                ops.push_back(Op::StateCurrent(current as u32));
            } else if d.mode() == 0 && d.state_provider().is_some() {
                ops.push_back(Op::Call(Call::State));
                ops.push_back(Op::SetState);
            }
            for (i, row) in self.config.frequencies.iter().enumerate() {
                for k in 0..2 {
                    if row.references[k].kind != 0 {
                        ops.push_back(Op::Decode(row.references[k], Target::Frequency(i, k)))
                    }
                }
            }
            for i in 0..6 {
                let r = self.config.references[i];
                if r.kind != 0 {
                    ops.push_back(Op::Decode(r, Target::Base(i)))
                }
            }
            for i in 0..2 {
                let r = self.config.references[6 + i];
                if r.kind == 0 {
                    break;
                }
                if r.kind == 4 {
                    ops.push_back(Op::Call(Call::Clock));
                    ops.push_back(Op::Integer {
                        reference: r,
                        target: Target::Integer(i),
                        next: u32::MAX,
                        sum: 0,
                    });
                } else {
                    ops.push_back(Op::Integer {
                        reference: r,
                        target: Target::Integer(i),
                        next: 0,
                        sum: 0,
                    });
                }
            }
            ops.push_back(Op::Tail);
            ops.push_back(Op::Increment);
        }
        self.begin(ops, context, activation, d.ordinal())
    }
    pub fn begin_postprocess(
        &mut self,
        frames: &Frames,
        d: &Descriptor,
        context: CounterContext,
        activation: u32,
    ) -> Result<(), Error> {
        self.idle()?;
        if !self.awaiting_post {
            return Err(Error::Contract(
                "generic Postprocess has no unreplayed Capture",
            ));
        }
        if d.ordinal() != self.config.ordinal {
            return Err(Error::Contract("generic postprocess descriptor mismatch"));
        }
        self.cells(frames)?;
        if self.products
            != (EffectValue::Hook {
                buffer_index: context.buffer_index,
                state_index: context.state_index,
                previous_state_index: context.previous_state_index,
            })
        {
            return Err(Error::Contract(
                "generic postprocess hook products differ from retained Capture",
            ));
        }
        let mut ops = VecDeque::new();
        for (i, r) in self.config.references.iter().enumerate() {
            if r.kind == 3 {
                ops.push_back(Op::Call(Call::InitializedScale {
                    reference: i as u32,
                    slot: r.provider,
                    index: r.start,
                }));
            }
        }
        if self.config.references[6].kind == 4 {
            for i in 0..self.config.frequencies.len() {
                ops.push_back(Op::Call(Call::Coefficients {
                    row: i as u32,
                    source: self.config.frequencies[i].clone(),
                }));
            }
        }
        if self.config.output_source != 0 {
            ops.push_back(Op::Call(Call::OutputLayout {
                source: self.config.output_source,
            }));
        }
        ops.push_back(Op::Post);
        self.awaiting_post = false;
        self.begin(ops, context, activation, d.ordinal())
    }
    fn idle(&self) -> Result<(), Error> {
        if self.serial == u64::MAX {
            return Err(Error::Contract("generic ingestion serial exhausted"));
        }
        if self.batch.is_some() || self.fault.is_some() {
            Err(Error::Contract(
                "generic ingestion retained or faulted operation",
            ))
        } else {
            Ok(())
        }
    }
    fn begin(
        &mut self,
        ops: VecDeque<Op>,
        context: CounterContext,
        activation: u32,
        ordinal: Ordinal,
    ) -> Result<(), Error> {
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or(Error::Contract("generic ingestion serial exhausted"))?;
        self.batch = Some(Batch {
            serial: self.serial,
            cursor: 0,
            ops,
            context,
            activation,
            ordinal,
            value: None,
        });
        Ok(())
    }
    fn products(&self) -> (u32, u32, u32) {
        match self.products {
            EffectValue::Hook {
                buffer_index,
                state_index,
                previous_state_index,
            } => (buffer_index, state_index, previous_state_index),
            _ => unreachable!(),
        }
    }
    fn store(&mut self, target: Target, pair: Pair) {
        let parity = (self.products().0 & 1) as usize;
        match target {
            Target::Base(i) => self.base[i][parity] = pair,
            Target::Integer(i) => self.integer[i][parity] = pair,
            Target::Frequency(i, k) => self.frequency[i][k][parity] = pair,
        }
    }
    fn pair(value: Option<Value>) -> Result<Pair, Error> {
        match value {
            Some(Value::Pair(pair)) => Ok(pair),
            _ => Err(Error::Contract("generic actual provider tuple absent")),
        }
    }
    fn word(value: Option<Value>) -> Result<u64, Error> {
        match value {
            Some(Value::Word(word)) => Ok(word),
            _ => Err(Error::Contract("generic actual provider value absent")),
        }
    }
    pub fn advance(&mut self, frames: &Frames, access: &mut Access<'_>) -> Result<Progress, Error> {
        if let Some(reason) = self.fault {
            return Err(Error::Contract(reason));
        }
        let mut b = self
            .batch
            .take()
            .ok_or(Error::Contract("generic ingestion operation absent"))?;
        let result = self.run(&mut b, frames, access);
        if let Err(Error::Contract(reason)) = result {
            self.fault = Some(reason)
        }
        if !b.ops.is_empty() || result.is_err() {
            self.batch = Some(b)
        }
        result
    }
    fn run(
        &mut self,
        b: &mut Batch,
        frames: &Frames,
        access: &mut Access<'_>,
    ) -> Result<Progress, Error> {
        let cells = self.cells(frames)?;
        while let Some(op) = b.ops.pop_front() {
            let next = b
                .cursor
                .checked_add(1)
                .ok_or(Error::Contract("generic ingestion cursor exhausted"))?;
            match op {
                Op::Call(ref call) => {
                    let request = Request {
                        owner: self.identity.clone(),
                        serial: b.serial,
                        cursor: b.cursor,
                    };
                    match self.backend.call(&request, call, access) {
                        Completion::Busy { deadline } => {
                            b.ops.push_front(op);
                            return Ok(Progress::Busy { deadline });
                        }
                        Completion::Refused(reason) => {
                            b.ops.push_front(op);
                            return Err(Error::Refused(reason));
                        }
                        Completion::Retired { value, refusal } => {
                            let shape = matches!(
                                (call, &value),
                                (Call::Coefficients { .. }, Value::Coefficients { .. })
                                    | (Call::OutputLayout { .. }, Value::Layout { .. })
                                    | (
                                        Call::ProviderTuple { .. } | Call::ExtendedFrame { .. },
                                        Value::Pair(_)
                                    )
                                    | (
                                        Call::ProviderValue { .. }
                                            | Call::Clock
                                            | Call::State
                                            | Call::ExtendedCount { .. }
                                            | Call::InitializedScale { .. },
                                        Value::Word(_)
                                    )
                                    | (
                                        Call::StateChanged { .. }
                                            | Call::ControlTail { .. }
                                            | Call::PublishInteger { .. },
                                        Value::Complete
                                    )
                            );
                            if !shape {
                                return Err(Error::Contract(
                                    "generic actual callback result shape mismatch",
                                ));
                            }
                            match (call, &value) {
                                (
                                    Call::Coefficients { row, .. },
                                    Value::Coefficients {
                                        active,
                                        inactive,
                                        extra,
                                    },
                                ) => {
                                    let f = &mut self.config.frequencies[*row as usize];
                                    if active.is_empty()
                                        || active.len() > 16
                                        || inactive.len() != active.len()
                                        || extra.len() != active.len()
                                    {
                                        return Err(Error::Contract(
                                            "generic actual coefficient state counts differ or exceed nibble profile",
                                        ));
                                    }
                                    f.active = active.clone();
                                    f.inactive = inactive.clone();
                                    f.extra = extra.clone();
                                    f.qualified = true;
                                }
                                (Call::OutputLayout { .. }, Value::Layout { start, count }) => {
                                    if *count > 2 {
                                        return Err(Error::Contract(
                                            "generic integer output range exceeds two source descriptors",
                                        ));
                                    }
                                    self.config.output_start = *start;
                                    self.config.output_count = *count;
                                }
                                (Call::StateChanged { .. }, Value::Complete) => {}
                                (Call::InitializedScale { reference, .. }, Value::Word(scale)) => {
                                    self.config.references[*reference as usize].scale =
                                        *scale as u32
                                }
                                (
                                    Call::ControlTail { .. } | Call::PublishInteger { .. },
                                    Value::Complete,
                                ) => {}
                                _ => b.value = Some(value),
                            };
                            b.cursor = next;
                            if let Some(reason) = refusal {
                                return Err(Error::Refused(reason));
                            }
                            continue;
                        }
                    }
                }

                Op::Decode(r, t) => match r.kind {
                    1 => {
                        b.ops.push_front(Op::ProviderWord { target: t });
                        b.ops.push_front(Op::Call(Call::ProviderValue {
                            slot: r.provider,
                            index: r.start,
                        }));
                    }
                    2 => {
                        let value = if b.context.activity != 0 {
                            extract(cells, r.start, r.width)?
                        } else {
                            0
                        };
                        let tick = if b.context.evaluated == 1 {
                            b.context.evaluation_tick
                        } else {
                            cells
                                .first()
                                .ok_or(Error::Contract(
                                    "inactive generic descriptor needs retained first frame",
                                ))?
                                .metadata
                                & TIME_MASK
                        };
                        self.store(t, Pair { value, tick });
                    }
                    3 => {
                        let total = if r.flags & 12 != 0 {
                            ((r.flags >> 1) & 7).max(1)
                        } else {
                            1
                        };
                        b.ops.push_front(Op::Tuple {
                            reference: r,
                            target: t,
                            next: 0,
                            total,
                            pair: None,
                        });
                    }
                    _ => {
                        return Err(Error::Contract(
                            "generic extract descriptor kind unsupported",
                        ));
                    }
                },
                Op::ProviderWord { target } => {
                    let value = Self::word(b.value.take())?;
                    b.ops.push_front(Op::ProviderClock { target, value });
                    b.ops.push_front(Op::Call(Call::Clock));
                }
                Op::ProviderClock { target, value } => {
                    let tick = Self::word(b.value.take())?;
                    self.store(target, Pair { value, tick });
                }
                Op::Tuple {
                    reference,
                    target,
                    next,
                    total,
                    pair,
                } => {
                    if next != 0 {
                        let p = Self::pair(b.value.take())?;
                        let old =
                            pair.ok_or(Error::Contract("generic tuple partial state absent"))?;
                        let sum = Pair {
                            value: old.value.wrapping_add(p.value),
                            tick: if next == 1 { p.tick } else { old.tick },
                        };
                        if next == total {
                            self.store(target, sum)
                        } else {
                            b.ops.push_front(Op::Tuple {
                                reference,
                                target,
                                next: next + 1,
                                total,
                                pair: Some(sum),
                            });
                            b.ops.push_front(Op::Call(Call::ProviderTuple {
                                slot: reference.provider,
                                index: reference.start.wrapping_add(next),
                            }));
                        }
                    } else {
                        b.ops.push_front(Op::Tuple {
                            reference,
                            target,
                            next: 1,
                            total,
                            pair: Some(Pair::default()),
                        });
                        b.ops.push_front(Op::Call(Call::ProviderTuple {
                            slot: reference.provider,
                            index: reference.start,
                        }));
                    }
                }
                Op::Integer {
                    reference: r,
                    target,
                    next,
                    sum,
                } => {
                    if next == u32::MAX {
                        let tick = Self::word(b.value.take())?;
                        let parity = (self.products().0 & 1) as usize;
                        if let Target::Integer(i) = target {
                            self.integer[i][parity].tick = tick
                        } else {
                            return Err(Error::Contract("generic integer target mismatch"));
                        }
                    } else if r.kind == 1 {
                        b.ops.push_front(Op::Decode(r, target));
                    } else if r.kind == 2 {
                        let index = r.start / 64;
                        if next == 0 {
                            match r.provider {
                                0 => {
                                    let value = cells
                                        .get(index as usize)
                                        .ok_or(Error::Contract(
                                            "generic integer frame outside receipt",
                                        ))?
                                        .value;
                                    self.finish_integer(b, target, index, value, cells)?
                                }
                                2 => {
                                    b.ops.push_front(Op::Integer {
                                        reference: r,
                                        target,
                                        next: 1,
                                        sum: 0,
                                    });
                                    b.ops.push_front(Op::Call(Call::ExtendedFrame {
                                        bank: 1,
                                        index,
                                    }));
                                }
                                3 => {
                                    b.ops.push_front(Op::ExtendedCount {
                                        reference: r,
                                        target,
                                    });
                                    b.ops.push_front(Op::Call(Call::ExtendedCount { bank: 1 }));
                                }
                                _ => self.finish_integer(b, target, index, 0, cells)?,
                            }
                        } else {
                            let pair = Self::pair(b.value.take())?;
                            let sum = sum.wrapping_add(pair.value);
                            let index = index.wrapping_add((next - 1) * 8);
                            let count = if r.provider == 3 {
                                self.config.extended_count
                            } else {
                                index + 1
                            };
                            if r.provider == 3 && index.wrapping_add(8) < count {
                                b.ops.push_front(Op::Integer {
                                    reference: r,
                                    target,
                                    next: next + 1,
                                    sum,
                                });
                                b.ops.push_front(Op::Call(Call::ExtendedFrame {
                                    bank: 1,
                                    index: index + 8,
                                }));
                            } else {
                                self.finish_integer(b, target, r.start / 64, sum, cells)?
                            }
                        }
                    } else {
                        return Err(Error::Contract(
                            "generic integer descriptor kind unsupported",
                        ));
                    }
                }
                Op::SetState => {
                    let current = Self::word(b.value.take())? as u32;
                    let old = self.products().1;
                    b.ops.push_front(Op::StateCurrent(current));
                    if self.config.state_trace != 0 && current != old {
                        b.ops.push_front(Op::Call(Call::StateChanged {
                            source: self.config.state_trace,
                            previous: old,
                            current,
                        }));
                    }
                }
                Op::StateCurrent(current) => {
                    let (p, old, _) = self.products();
                    self.products = EffectValue::Hook {
                        buffer_index: p,
                        state_index: current,
                        previous_state_index: old,
                    };
                }
                Op::Timestamp { target, value } => {
                    let tick = Self::pair(b.value.take())?.tick & TIME_MASK;
                    self.store(target, Pair { value, tick });
                }
                Op::ExtendedCount {
                    reference: r,
                    target,
                } => {
                    let count = Self::word(b.value.take())?;
                    if count > u64::from(u32::MAX) {
                        return Err(Error::Contract("generic extended frame count exceeds W32"));
                    }
                    self.config.extended_count = count as u32;
                    let index = r.start / 64;
                    if index < self.config.extended_count {
                        b.ops.push_front(Op::Integer {
                            reference: r,
                            target,
                            next: 1,
                            sum: 0,
                        });
                        b.ops
                            .push_front(Op::Call(Call::ExtendedFrame { bank: 1, index }));
                    } else {
                        self.finish_integer(b, target, index, 0, cells)?
                    }
                }
                Op::Tail => {
                    if self.config.auxiliary {
                        b.ops.push_front(Op::Call(Call::ControlTail {
                            ordinal: b.ordinal,
                            activation: b.activation,
                            context: CounterContext {
                                buffer_index: self.products().0,
                                state_index: self.products().1,
                                previous_state_index: self.products().2,
                                ..b.context
                            },
                            descriptors: self.config.auxiliaries.clone(),
                        }));
                    }
                }
                Op::Increment => {
                    let (p, s, old) = self.products();
                    self.products = EffectValue::Hook {
                        buffer_index: p.wrapping_add(1),
                        state_index: s,
                        previous_state_index: old,
                    }
                }
                Op::Post => self.post(b)?,
            }
            b.cursor = next;
        }
        Ok(Progress::Complete(self.products))
    }
    fn finish_integer(
        &mut self,
        b: &mut Batch,
        target: Target,
        index: u32,
        value: u64,
        cells: &[Frame],
    ) -> Result<(), Error> {
        let tick = if b.context.evaluated == 1 {
            b.context.evaluation_tick
        } else {
            b.ops.push_front(Op::Timestamp { target, value });
            b.ops
                .push_front(Op::Call(Call::ExtendedFrame { bank: 1, index }));
            return Ok(());
        };
        let _ = cells;
        self.store(target, Pair { value, tick });
        Ok(())
    }
    fn post(&mut self, b: &mut Batch) -> Result<(), Error> {
        let (index, _, previous) = self.products();
        let periods = self.config.periods;
        for (i, row) in self.config.frequencies.iter().enumerate() {
            let a = if row.references[0].kind == 0 {
                if b.activation == 1 { 100 } else { 0 }
            } else {
                let d = arithmetic::delta(
                    index,
                    row.references[0].flags,
                    self.frequency[i][0],
                    periods,
                );
                d.value.wrapping_mul(100).checked_div(d.ticks).unwrap_or(0) as u32
            };
            let e = if row.references[1].kind == 0 {
                if b.context.evaluated == 1 { 100 } else { 0 }
            } else {
                let d = arithmetic::delta(
                    index,
                    row.references[1].flags,
                    self.frequency[i][1],
                    periods,
                );
                (if d.ticks == 0 {
                    0
                } else {
                    let value = if row.invert {
                        d.ticks.saturating_sub(d.value)
                    } else {
                        d.value
                    };
                    value.wrapping_mul(100) / d.ticks
                }) as u32
            };
            self.activation_util[i] = a;
            self.evaluated_util[i] = e;
        }
        if self.config.references[6].kind == 4 {
            let d = arithmetic::delta(
                index,
                self.config.references[6].flags,
                self.integer[0],
                periods,
            );
            let mut sum = 0u64;
            for (i, row) in self.config.frequencies.iter().enumerate() {
                if !row.qualified {
                    return Err(Error::Contract(
                        "generic actual initialized coefficient row absent",
                    ));
                }
                let state = previous as usize;
                if state >= row.active.len() {
                    return Err(Error::Contract(
                        "generic prior controller state outside coefficient row",
                    ));
                }
                let group = row.group as usize;
                if group >= 2 {
                    return Err(Error::Contract(
                        "generic frequency group outside2x3 metric descriptors",
                    ));
                }
                let mut extra = 0u32;
                for k in 0..2 {
                    let reference = self.config.references[group * 3 + k];
                    if reference.kind != 0 {
                        extra = extra.wrapping_add(
                            (arithmetic::scaled(
                                index,
                                reference,
                                self.base[group * 3 + k],
                                periods,
                            )?
                            .value
                                >> 20) as u32,
                        )
                    }
                }
                let first =
                    arithmetic::percent(d.micros.wrapping_mul(u64::from(self.activation_util[i])))
                        .wrapping_mul(u64::from(row.active[state]));
                let second =
                    arithmetic::percent(d.micros.wrapping_mul(u64::from(self.evaluated_util[i])))
                        .wrapping_mul(u64::from(row.inactive[state]));
                sum = sum
                    .wrapping_add(first.wrapping_add(second).wrapping_shl(row.shift & 63))
                    .wrapping_add(u64::from(extra).wrapping_mul(u64::from(row.extra[state])));
            }
            self.accumulated = self.accumulated.wrapping_add(sum);
            self.integer[0][(!index & 1) as usize].value = self.accumulated;
        }
        for i in 0..2 {
            let r = self.config.references[6 + i];
            if r.kind == 0 {
                break;
            }
            let d = arithmetic::scaled(index, r, self.integer[i], periods)?;
            self.integer_rates[i] = d.value.checked_div(d.micros).unwrap_or(0) as u32;
        }
        for g in 0..2 {
            let mut any = false;
            for k in 0..3 {
                let r = self.config.references[g * 3 + k];
                if r.kind == 0 {
                    if k == 2 && any {
                        self.metrics[g][2] = self.metrics[g][0].wrapping_add(self.metrics[g][1]);
                        self.rates[g][2] = self.rates[g][0].wrapping_add(self.rates[g][1]);
                        self.stats[g][2].record(self.rates[g][2] >> 10)
                    }
                    continue;
                }
                let d = arithmetic::scaled(index, r, self.base[g * 3 + k], periods)?;
                self.metrics[g][k] = d.value as u32;
                let rate = (d
                    .value
                    .wrapping_mul(1_000_000)
                    .checked_div(d.micros)
                    .unwrap_or(0)
                    >> 20) as u32;
                self.rates[g][k] = rate;
                self.stats[g][k].record(rate >> 10);
                any = true;
            }
        }
        if self.config.has_ratio {
            self.ratio = self.metrics[1][2]
                .wrapping_mul(100)
                .checked_div(self.metrics[0][2])
                .unwrap_or(0);
        }
        let mut written = 0;
        for i in 0..2 {
            if written >= self.config.output_count {
                break;
            }
            if self.config.references[6 + i].kind == 4 {
                b.ops.push_back(Op::Call(Call::PublishInteger {
                    entry: self.config.output_start.wrapping_add(written),
                    value: self.accumulated,
                }));
                written += 1;
            }
        }
        Ok(())
    }
}
fn extract(cells: &[Frame], start: u32, width: u32) -> Result<u64, Error> {
    let frame = cells.get((start / 64) as usize).ok_or(Error::Contract(
        "generic bitfield outside actual copied slice",
    ))?;
    let mask = u64::MAX.wrapping_shr(width.wrapping_neg() & 63);
    Ok(frame.value.wrapping_shr(start & 63) & mask)
}

#[cfg(test)]
mod tests {
    use super::super::super::counters::{Claim, CopyStep};
    use super::super::super::power::DeviceTable;
    use super::*;
    use crate::platform::apple::{
        bus::{LifecycleState, MmioDevice, Width},
        interrupt::InterruptLatch,
        ptd::{
            Geometry, Ptd, Range, UPDATE_OFFSET,
            transport::notifications::{LocalNotifications, NativeProfile},
        },
    };
    use core::cell::Cell;
    struct TestBackend {
        calls: Vec<(Request, Call)>,
        busy: bool,
        refuse_tail: bool,
        retired_tail: bool,
        bad: bool,
    }
    impl TestBackend {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                busy: false,
                refuse_tail: false,
                retired_tail: false,
                bad: false,
            }
        }
    }
    impl Backend for TestBackend {
        fn call(&mut self, r: &Request, c: &Call, _: &mut Access<'_>) -> Completion<Value> {
            self.calls.push((r.clone(), c.clone()));
            if self.busy {
                self.busy = false;
                return Completion::Busy { deadline: Some(9) };
            }
            if matches!(c, Call::ControlTail { .. }) && self.refuse_tail {
                self.refuse_tail = false;
                return Completion::Refused("authored missing auxiliary effect");
            }
            let value = if self.bad {
                Value::Complete
            } else {
                match c {
                    Call::ProviderTuple { index, .. } => Value::Pair(Pair {
                        value: u64::from(100 + index),
                        tick: 2000 + u64::from(*index),
                    }),
                    Call::ProviderValue { index, .. } => Value::Word(300 + u64::from(*index)),
                    Call::ExtendedFrame { index, .. } => Value::Pair(Pair {
                        value: 400 + u64::from(*index),
                        tick: 3000 + u64::from(*index),
                    }),
                    Call::ExtendedCount { .. } => Value::Word(24),
                    Call::Clock => Value::Word(700),
                    Call::State => Value::Word(2),
                    Call::InitializedScale { .. } => Value::Word(0),
                    Call::Coefficients { .. } => Value::Coefficients {
                        active: vec![2; 3],
                        inactive: vec![3; 3],
                        extra: vec![4; 3],
                    },
                    Call::OutputLayout { .. } => Value::Layout {
                        start: 240,
                        count: 1,
                    },
                    _ => Value::Complete,
                }
            };
            let refusal = if matches!(c, Call::ControlTail { .. }) && self.retired_tail {
                self.retired_tail = false;
                Some("authored retired auxiliary refusal")
            } else {
                None
            };
            Completion::Retired { value, refusal }
        }
    }
    fn setup() -> (Frames, LocalNotifications, InterruptLatch) {
        let range = Range {
            id: 9,
            start: 16,
            count: 144,
            name: "authored generic source packet".into(),
        };
        let live = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let local = Ptd::initialized_local_profile(
            NativeProfile::T8112,
            Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap(),
            core::slice::from_ref(&range),
            live,
        )
        .unwrap()
        .1;
        let ids = [
            1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
        ];
        let counts = [0, 14, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let raw: Vec<_> = ids
            .into_iter()
            .zip(counts)
            .flat_map(|(id, count)| {
                let mut w = [0u32; 31];
                w[0] = id;
                w[3] = count;
                w.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        let table = DeviceTable::from_properties(&raw, &[0; 8], None).unwrap();
        let frames = Frames::initialized(
            Claim::new(local.clone(), range, Rc::new(Cell::new(true))),
            &table,
            &[0xa5; 144],
        )
        .unwrap();
        (frames, local, InterruptLatch::new())
    }
    fn copied(
        frames: &mut Frames,
        local: &LocalNotifications,
        ordinal: u32,
        value: u64,
        latch: &mut InterruptLatch,
    ) -> Copied {
        let layout = frames.layout(ordinal).unwrap();
        if layout.count != 0 {
            local
                .bank()
                .clone()
                .write(
                    UPDATE_OFFSET + u64::from(layout.start) * 8,
                    Width::Double,
                    value,
                    &mut Access::new(0, 77, latch),
                )
                .unwrap();
        }
        let capture = frames.capture_pending(&Access::new(0, 99, latch)).unwrap();
        frames.begin_copy(&capture, ordinal, u128::MAX).unwrap();
        while frames.step(&mut Access::new(0, 100, latch)).unwrap() != CopyStep::Complete {}
        frames.finish_copy().unwrap()
    }
    fn context() -> CounterContext {
        CounterContext {
            selected: 1,
            evaluation_tick: 500,
            current_packet: super::super::super::Packets([0x403, 0, 0x403, 0, 0, 0]),
            activity: 1,
            buffer_index: 0,
            state_index: 0,
            previous_state_index: 0,
            evaluated: 1,
            pending: 0,
        }
    }
    fn descriptor(i: usize) -> Descriptor {
        super::super::profile::tests::fixture().descriptors[i].clone()
    }
    fn run(
        owner: &mut Owner<TestBackend>,
        frames: &Frames,
        latch: &mut InterruptLatch,
    ) -> Result<Progress, Error> {
        owner.advance(frames, &mut Access::new(0, 100, latch))
    }
    #[test]
    fn actual_copied_frames_drive_bitfields_buffers_rates_and_query() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(1);
        let receipt = copied(&mut frames, &local, 1, 70 | (100 << 32), &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        let mut c = context();
        o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
        assert_eq!(
            run(&mut o, &frames, &mut latch),
            Ok(Progress::Complete(EffectValue::Hook {
                buffer_index: 1,
                state_index: 0,
                previous_state_index: 0
            }))
        );
        assert_eq!(
            o.base[3][0],
            Pair {
                value: 70,
                tick: 500
            }
        );
        assert_eq!(o.base[4][0].value, 100);
        assert_eq!(o.cells(&frames).unwrap()[0].value, 70 | (100 << 32));
        c.buffer_index = 1;
        o.begin_postprocess(&frames, &d, c, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(o.metrics()[1], [560, 800, 1360]);
        assert_eq!(o.query(1, 1, 0), Ok(76));
        assert_eq!(o.query(0, 1, 0), Ok(0));
        assert!(o.query(1, 2, 0).is_err());
        assert_eq!(o.backend.calls.len(), 0);
        assert!(o.begin_postprocess(&frames, &d, c, 1).is_err());
    }
    #[test]
    fn source_zero_activity_reads_retained_storage_without_copying_or_consuming_pending_entries() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(1);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        let c = CounterContext {
            activity: 0,
            ..context()
        };
        let before = frames.progress();
        local
            .bank()
            .clone()
            .write(
                UPDATE_OFFSET + 16 * 8,
                Width::Double,
                123,
                &mut Access::new(0, 1, &mut latch),
            )
            .unwrap();
        o.begin_retained_capture(&frames, frames.retain_cells(1).unwrap(), &d, c, 1)
            .unwrap();
        assert!(matches!(
            run(&mut o, &frames, &mut latch),
            Ok(Progress::Complete(_))
        ));
        assert_eq!(frames.progress(), before);
        assert!(
            o.cells(&frames)
                .unwrap()
                .iter()
                .all(|f| !f.copied && f.value == 0)
        );
        assert_eq!(
            o.base[3][0],
            Pair {
                value: 0,
                tick: c.evaluation_tick
            }
        );
        assert_eq!(
            local
                .bank()
                .clone()
                .consume_entry(16, &mut Access::new(0, 2, &mut latch))
                .unwrap()
                .value,
            123
        );
        let products = o.products();
        let next = CounterContext {
            buffer_index: products.0,
            ..c
        };
        copied(&mut frames, &local, 1, 456, &mut latch);
        assert!(o.cells(&frames).is_err());
        assert!(o.begin_postprocess(&frames, &d, next, 1).is_err());
        assert_eq!(o.products(), products);
    }
    #[test]
    fn source_no_counter_slice_skips_bulk_and_invalid_retained_constructors_preserve_state() {
        let (frames, _, _) = setup();
        let d = descriptor(2);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        let c = context();
        o.begin_retained_capture(&frames, frames.retain_cells(2).unwrap(), &d, c, 1)
            .unwrap();
        assert!(o.cells(&frames).unwrap().is_empty());
        assert_eq!(frames.progress().completed_copies, 0);
        let (frames, _, _) = setup();
        let d = descriptor(1);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        assert!(
            o.begin_retained_capture(&frames, frames.retain_cells(1).unwrap(), &d, context(), 1)
                .is_err()
        );
        assert!(o.receipt.is_none());
        assert!(!o.awaiting_post);
        assert_eq!(o.products().0, 0);
        o.serial = u64::MAX;
        assert!(
            o.begin_retained_capture(
                &frames,
                frames.retain_cells(1).unwrap(),
                &d,
                CounterContext {
                    activity: 0,
                    ..context()
                },
                1
            )
            .is_err()
        );
        assert!(o.receipt.is_none());
        assert_eq!(frames.progress().consumed, 0);
    }
    #[test]
    fn provider_tuple_sums_and_auxiliary_refusal_retain_exact_prefix() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(4);
        let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
        let mut cfg = Configuration::t8112(&d).unwrap();
        cfg.references[0].flags = 6;
        let mut backend = TestBackend::new();
        backend.refuse_tail = true;
        let mut o = Owner::initialized_software(cfg, backend);
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        assert_eq!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Refused("authored missing auxiliary effect"))
        );
        assert_eq!(
            o.base[0][0],
            Pair {
                value: 102 + 103 + 104,
                tick: 2002
            }
        );
        let n = o.backend.calls.len();
        let request = o.backend.calls.last().unwrap().0.clone();
        assert_eq!(o.products().0, 0);
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(o.products().0, 1);
        assert_eq!(o.backend.calls.len(), n + 1);
        assert!(request.same_operation(&o.backend.calls[n].0));
    }
    #[test]
    fn auxiliary_tail_keeps_activation_distinct_from_activity() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(4);
        let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
        let mut backend = TestBackend::new();
        backend.refuse_tail = true;
        let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
        o.begin_capture(&frames, receipt, &d, context(), 7).unwrap();
        assert!(matches!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Refused(_))
        ));
        let Call::ControlTail {
            context, activation, ..
        } = &o.backend.calls.last().unwrap().1
        else {
            panic!("the actual auxiliary tail was not reached");
        };
        assert_eq!((*activation, context.activity), (7, 1));
    }
    #[test]
    fn retired_callback_refusal_never_replays_and_stale_receipts_never_read() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(4);
        let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
        let mut backend = TestBackend::new();
        backend.retired_tail = true;
        let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        assert!(run(&mut o, &frames, &mut latch).is_err());
        let n = o.backend.calls.len();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(o.backend.calls.len(), n);
        let c = CounterContext {
            buffer_index: 1,
            ..context()
        };
        o.begin_postprocess(&frames, &d, c, 1).unwrap();
        let _new = copied(&mut frames, &local, 4, 1, &mut latch);
        assert!(matches!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Contract(_))
        ));
        assert_eq!(o.backend.calls.len(), n);
        assert!(o.cells(&frames).is_err());
    }
    #[test]
    fn actual_tuple_callback_shape_and_cursor_exhaustion_fail_before_fabrication() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(4);
        let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
        let mut backend = TestBackend::new();
        backend.bad = true;
        let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        assert_eq!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Contract(
                "generic actual callback result shape mismatch"
            ))
        );
        assert_eq!(o.products().0, 0);
        let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        o.batch.as_mut().unwrap().cursor = u64::MAX;
        assert!(matches!(
            run(&mut o, &frames, &mut latch),
            Err(Error::Contract(_))
        ));
        assert!(o.backend.calls.is_empty());
    }
    #[test]
    fn inactive_primary_timestamp_uses_actual_retained_frame_metadata() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(1);
        let receipt = copied(&mut frames, &local, 1, 41, &mut latch);
        let expected = frames.cells(&receipt).unwrap()[0].metadata & TIME_MASK;
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        let mut c = context();
        c.evaluated = 0;
        c.evaluation_tick = 9999;
        o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(o.base[3][0].tick, expected);
        assert_ne!(expected, 9999);
    }
    #[test]
    fn constructor_preflight_keeps_receipt_products_and_pending_post_intact() {
        let (mut frames, local, mut latch) = setup();
        let mut d = descriptor(1);
        let receipt = copied(&mut frames, &local, 1, 42, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        d.counters = None;
        assert_eq!(
            o.begin_capture(&frames, receipt, &d, context(), 1),
            Err(Error::Contract(
                "generic no-counter descriptor received a nonempty frame slice"
            ))
        );
        assert!(o.receipt.is_none());
        assert!(!o.awaiting_post);
        assert_eq!(o.products().0, 0);
        d = descriptor(1);
        let receipt = copied(&mut frames, &local, 1, 43, &mut latch);
        o.serial = u64::MAX;
        assert_eq!(
            o.begin_capture(&frames, receipt, &d, context(), 1),
            Err(Error::Contract("generic ingestion serial exhausted"))
        );
        assert!(o.receipt.is_none());
        assert!(!o.awaiting_post);
        assert_eq!(o.products().0, 0);
        o.serial = 0;
        let receipt = copied(&mut frames, &local, 1, 44, &mut latch);
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        o.serial = u64::MAX;
        let products = o.products();
        let c = CounterContext {
            buffer_index: 1,
            ..context()
        };
        assert_eq!(
            o.begin_postprocess(&frames, &d, c, 1),
            Err(Error::Contract("generic ingestion serial exhausted"))
        );
        assert_eq!(o.products(), products);
        assert!(o.awaiting_post);
        assert!(o.cells(&frames).is_ok());
    }
    #[test]
    fn type4_coefficients_and_actual_output_range_precede_duration_publication() {
        let (mut frames, local, mut latch) = setup();
        let mut d = descriptor(2);
        d.raw[4] = 18;
        let receipt = copied(&mut frames, &local, 2, 0, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        let c = context();
        o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        let (_, state, previous) = o.products();
        let c = CounterContext {
            buffer_index: 1,
            state_index: state,
            previous_state_index: previous,
            ..c
        };
        o.begin_postprocess(&frames, &d, c, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert!(o.config.frequencies[0].qualified);
        let calls = &o.backend.calls;
        let coefficients = calls
            .iter()
            .position(|(_, c)| matches!(c, Call::Coefficients { .. }))
            .unwrap();
        let layout = calls
            .iter()
            .position(|(_, c)| matches!(c, Call::OutputLayout { source: 18 }))
            .unwrap();
        let publish = calls
            .iter()
            .position(|(_, c)| matches!(c, Call::PublishInteger { entry: 240, .. }))
            .unwrap();
        assert!(coefficients < layout && layout < publish);
    }
    #[test]
    fn source_activation_store_resets_only_capture_index_without_frame_authority() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(1);
        let receipt = copied(&mut frames, &local, 1, 42, &mut latch);
        let mut o =
            Owner::initialized_software(Configuration::t8112(&d).unwrap(), TestBackend::new());
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        let old = o.base;
        assert_eq!(o.ordinal(), d.ordinal());
        o.apply_source_activation_reset().unwrap();
        assert_eq!(o.products().0, 0);
        assert_eq!(o.base, old);
        assert_eq!(o.cells(&frames).unwrap()[0].value, 42);
        assert!(!o.awaiting_post);
        assert_eq!(extract_field(o.cells(&frames).unwrap(), 0, 0).unwrap(), 42);
        assert!(o.backend.calls.is_empty());
    }
    #[test]
    fn extended_integer_source_preserves_sum_and_actual_timestamp() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(1);
        let receipt = copied(&mut frames, &local, 1, 1, &mut latch);
        let mut config = Configuration::t8112(&d).unwrap();
        config.references[6] = CounterReference {
            kind: 2,
            provider: 3,
            start: 0,
            width: 0,
            flags: 0,
            scale: 0,
        };
        let mut o = Owner::initialized_software(config, TestBackend::new());
        let c = CounterContext {
            evaluated: 0,
            ..context()
        };
        o.begin_capture(&frames, receipt, &d, c, 1).unwrap();
        run(&mut o, &frames, &mut latch).unwrap();
        assert_eq!(
            o.integer[0][0],
            Pair {
                value: 400 + 408 + 416,
                tick: 3000
            }
        );
        let calls: Vec<_> = o
            .backend
            .calls
            .iter()
            .filter_map(|(_, c)| {
                if let Call::ExtendedFrame { index, .. } = c {
                    Some(*index)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(calls, vec![0, 8, 16, 0]);
    }
    #[test]
    fn actual_provider_busy_and_foreign_frame_owner_preserve_identity() {
        let (mut frames, local, mut latch) = setup();
        let d = descriptor(4);
        let receipt = copied(&mut frames, &local, 4, 0, &mut latch);
        let (mut foreign, local2, mut latch2) = setup();
        let other = copied(&mut foreign, &local2, 4, 0, &mut latch2);
        let mut backend = TestBackend::new();
        backend.busy = true;
        let mut o = Owner::initialized_software(Configuration::t8112(&d).unwrap(), backend);
        assert!(o.begin_capture(&frames, other, &d, context(), 1).is_err());
        o.begin_capture(&frames, receipt, &d, context(), 1).unwrap();
        assert_eq!(
            run(&mut o, &frames, &mut latch),
            Ok(Progress::Busy { deadline: Some(9) })
        );
        let request = o.backend.calls[0].0.clone();
        run(&mut o, &frames, &mut latch).unwrap();
        assert!(request.same_operation(&o.backend.calls[1].0));
    }
}
#[cfg(all(test, feature = "std"))]
mod original_tests {
    #[test]
    #[ignore = "requires original T8112 PMP via STELA_TEST_PMP_T8112"]
    fn original_t8112_ingestion_and_postprocess_operands_match_source() {
        use sha2::{Digest, Sha256};
        let b = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&b)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let w =
            |a: usize| u32::from_le_bytes(b[a - 0xfff000..a - 0xfff000 + 4].try_into().unwrap());
        for (a, word) in [
            (0x101a7b0, 0x340000c8),
            (0x101a7b4, 0xb9401268),
            (0x101a7b8, 0x34000088),
            (0x101c54c, 0xf9000a7f),
            (0x101a824, 0x29092274),
            (0x101aa94, 0x11000508),
            (0x101aa98, 0xb9001668),
            (0x101ba3c, 0xf9415808),
            (0x101ba4c, 0x9240d508),
            (0x101b9a4, 0x8a080148),
            (0x101b2c8, 0x370000c1),
            (0x101b31c, 0x6ee18400),
            (0x101b358, 0x92406548),
            (0x101b364, 0x9b087d28),
            (0x101b38c, 0x7100053f),
            (0x101b2b4, 0xb943c900),
            (0x101adf4, 0xf9002a69),
            (0x101afb0, 0x2a1f03e9),
            (0x1006f7c, 0xf9001008),
        ] {
            assert_eq!(w(a), word, "{a:x}");
        }
    }
}
