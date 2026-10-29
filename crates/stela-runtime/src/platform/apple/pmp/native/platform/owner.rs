//! The generic platform lifecycle owner. `Owner` runs initialize, start, stop,
//! selection, evaluation cycles and counter hooks as kept operations over
//! a `Backend` that supplies the effects, using the `Observation`,
//! `Effect` and `Completion` vocabulary defined here.
use super::super::{
    Packets,
    counters::Captured,
    power::policy::{ConstraintState, Resolution},
};
use super::{Descriptor, Evaluation, Hook, McSelection, Ordinal, Packed, Profile, Slice};
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use stela_contracts::bus::Access;

pub mod controllers;

/// An immutable pending snapshot. Numeric bits are observations only.
/// The built-in adapter keeps Frames' non-Clone owner-bound capture.
pub trait Pending {
    fn bits(&self, start: u32, count: u32) -> Result<u128, &'static str>;
}
impl Pending for Captured {
    fn bits(&self, start: u32, count: u32) -> Result<u128, &'static str> {
        Captured::bits(self, start, count)
            .map_err(|_| "actual native PTD snapshot does not cover platform slice")
    }
}
#[derive(Clone, Debug)]
pub struct Request {
    owner: Rc<()>,
    serial: u64,
    operation: u64,
}
impl Request {
    pub fn same_operation(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.owner, &other.owner)
            && self.serial == other.serial
            && self.operation == other.operation
    }
    pub fn serial(&self) -> u64 {
        self.serial
    }
    pub fn operation(&self) -> u64 {
        self.operation
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum Completion<T> {
    Busy {
        deadline: Option<u64>,
    },
    Refused(&'static str),
    /// The source operation retired. Preserve any committed prefix
    /// before returning its refusal and never replay it on the next advance.
    Retired {
        value: T,
        refusal: Option<&'static str>,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    Clock,
    PolicyPackets,
    ProviderStates {
        ordinal: Ordinal,
        source_object: u64,
    },
    Observer {
        ordinal: Ordinal,
        address: u64,
    },
    ///10115f0 consumes a PTD entry; return ENTRY VALUE low32,
    /// never the metadata timestamp or a synthesized source time.
    ConsumeFreshnessValue {
        ordinal: Ordinal,
        entry: u32,
    },
    /// Source SOC-device request payload, resolved through its PTD
    /// request-index→registry-ordinal map (1010ecc..1010f00).
    DeviceRequest {
        ordinal: Ordinal,
    },
    /// Source control-counter flags before software100a020 mutation.
    CounterControls,
    ///100e9bc..e9fc diagnostic result from the cycle trace owner.
    DispatchControl,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Tick(u64),
    Packets(Packets),
    ObserverWord(u32),
    ConsumedValueLow32(u32),
    ProviderStateCount(u32),
    Payload(u64),
    Controls(Vec<ControlFlags>),
    DispatchControl {
        trace_enabled: u32,
        trace_result: Option<u32>,
    },
}
/// Raw source transition flags, not arrival, activation or completion values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlFlags {
    pub ordinal: Ordinal,
    pub low: u8,
    pub high: u8,
}

/// Software operands kept across capture/postprocess hooks. Numeric
/// selection is data; only the borrowed owner-bound Snapshot can authorize copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterContext {
    pub selected: u128,
    /// P2b0 from evaluation, independent of later manager Clock reads.
    pub evaluation_tick: u64,
    /// Manager six-word packet, separately observed from its
    /// real owner. This is not constructed from selection, Captured or requests.
    pub current_packet: Packets,
    pub activity: u32,
    pub buffer_index: u32,
    pub state_index: u32,
    pub previous_state_index: u32,
    pub evaluated: u32,
    pub pending: u8,
}
/// Native hook arithmetic products (P14/P48/P4c), never readiness,
/// activation, evaluated state, arrival, BUSY-clear or an ACK capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectValue {
    Complete,
    Hook {
        buffer_index: u32,
        state_index: u32,
        previous_state_index: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Full source init hook, including provider/resource binds. The
    /// separate pure software constructor does not assert this effect ran.
    Initialize {
        ordinal: Ordinal,
        source_va: u64,
    },
    Start {
        ordinal: Ordinal,
        source_va: u64,
    },
    Stop {
        ordinal: Ordinal,
        source_va: u64,
    },
    /// Full retained101c550..101cb58 tail after its software activation store:
    /// counter bind/clear, PTD notifications, provider actions, observer RMW,
    /// trace/refresh and optional extra hooks. Missing inner effects must refuse;
    /// backend keeps its inner cursor under this same operation identity.
    Activation {
        ordinal: Ordinal,
        enable: bool,
        previous: u32,
        tick: u64,
    },
    /// Actual101b3d0 with null destination on activity wrap. Desired bits do
    /// not prove any selected PTD consume retired.
    DiscardCounters {
        ordinal: Ordinal,
        slice: Slice,
        selected: u128,
    },
    ///101cbf4 full real vote/notification path, including cfg38 requirement
    /// table, extra controller votes, floor vote and optional trace. Logical
    /// tuple is policy DATA, never controller settlement or a raw code write.
    Refresh {
        ordinal: Ordinal,
        mode: u32,
        logical: Packed,
        activation: u32,
        evaluated: u32,
        state_index: u32,
        tick: u64,
    },
    Hook {
        ordinal: Ordinal,
        hook: Hook,
        source_va: u64,
        output: Evaluation,
        counters: CounterContext,
    },
    ///101bb08 precedes P2a2 clear. No successful absent callback is supplied.
    RequestTrace {
        ordinal: Ordinal,
        source_id: u32,
        previous: u32,
        target: u32,
    },
    ResetControl {
        ordinal: Ordinal,
    },
}

/// Reached manager operations around the platform hooks. The fixed backend owns
/// the configured controller list, its saved nibble vector and the shared G540
/// provider-cache read masks. Source addresses document order, never dispatch keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerEffect {
    ///100f8cc..100f934: for cfg28 controller records, resolve the index
    /// map, save bits19:16, OR0xf0000 into each word; then clear32 bytes at G540.
    /// A zero-count skip requires the source configuration, not absence.
    BeforeCapture,
    ///100f990..100f9e8: restore each saved nibble with a word RMW after
    /// all Capture hooks and a fresh clock observation100f97c..100f990.
    RestoreControllers,
    ///100fa18..100fb14: process actual24-byte accumulator descriptors, intersect
    /// each mask with eligible, extract its logical nibble from the kept
    /// current packet (sp+a0, not the separately cleared G540 scratch) and invoke
    /// both counter callbacks(+50, arguments selector/0 then selector/1),
    /// accumulating their u32 results into the selected16-byte bucket.
    AccumulateCounters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagerContext {
    pub output: Evaluation,
    pub tick: u64,
    pub current_packet: Packets,
}

/// Backend has no default implementation. Every reached inner source effect
/// must finish, remain Busy, or refuse with its committed inner cursor kept.
/// Source VAs are provenance only: dispatch uses typed effects/layout, never
/// a source call-site address. Capture must belong to this fixed backend
/// Frames owner and remain associated through both passes and copies.
/// It owns time/counters/observer/provider/workqueue resources; it must
/// not derive observations or completion from requested bits or these effects.
pub trait Backend {
    type Snapshot: Pending;
    fn observe(
        &mut self,
        request: &Request,
        observation: Observation,
        snapshot: Option<&Self::Snapshot>,
        access: &mut Access<'_>,
    ) -> Completion<Value>;
    fn capture_pending(
        &mut self,
        request: &Request,
        slice: Slice,
        access: &mut Access<'_>,
    ) -> Completion<Self::Snapshot>;
    fn manager_effect(
        &mut self,
        request: &Request,
        effect: ManagerEffect,
        profile: &Profile,
        context: ManagerContext,
        snapshot: Option<&Self::Snapshot>,
        access: &mut Access<'_>,
    ) -> Completion<()>;
    fn effect(
        &mut self,
        request: &Request,
        effect: &Effect,
        descriptor: &Descriptor,
        snapshot: Option<&Self::Snapshot>,
        access: &mut Access<'_>,
    ) -> Completion<EffectValue>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Busy { deadline: Option<u64> },
    Idle,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Contract(&'static str),
    Backend(&'static str),
}

/// Private native software fields with explicit original zero initialization.
/// No caller can mark readiness/evaluated state, clear BUSY or invent ACK.
#[derive(Clone, Debug)]
struct State {
    activation: u32,
    evaluated: u32,
    activity: u32,
    adjacent: u32,
    pending: u8,
    changed: u8,
    freshness_arm: u8,
    parent_gate: u8,
    hysteresis_left: u32,
    selected: u128,
    tick: u64,
    logical: Packed,
    source_states: u32,
    state_index: u32,
    previous_state_index: u32,
    interpolation: Option<super::Interpolation>,
}
impl State {
    fn initialized(d: &Descriptor, descriptors: &[Descriptor]) -> Self {
        //1019f50..9fa0: aggregates and passive leaves derive this gate from
        // the parent descriptor. No unconditional PMGR requirement.
        let gate_candidate =
            d.aggregate != 0 || (d.counters.is_none() && d.observer_write & 1 == 0);
        let parent_gate = u8::from(
            gate_candidate
                && d.parent.is_some_and(|p| {
                    let parent = &descriptors[p.index()];
                    parent.aggregate == 0
                        && (parent.counters.is_some() || parent.observer_write == 1)
                }),
        );
        Self {
            activation: 0,
            evaluated: 0,
            activity: 0,
            adjacent: 0,
            pending: 0,
            changed: 0,
            freshness_arm: 0,
            parent_gate,
            hysteresis_left: 0,
            selected: 0,
            tick: 0,
            logical: Packed::default(),
            source_states: d.controller_states,
            state_index: 0,
            previous_state_index: 0,
            interpolation: d.interpolation.clone(),
        }
    }
}
#[derive(Clone, Debug)]
enum Op {
    Observe(Observation),
    Capture,
    Effect(Effect),
    ProviderStates(Ordinal),
    Initialized,
    Started,
    Stopped,
    Policy(Resolution),
    Activate {
        ordinal: Ordinal,
        enable: bool,
    },
    Selection(u64),
    Evaluate(Ordinal),
    ObserverDecision {
        ordinal: Ordinal,
        previous: u32,
        pending: u8,
    },
    FreshDecision {
        ordinal: Ordinal,
        previous: u32,
        pending: u8,
    },
    Commit {
        ordinal: Ordinal,
        eligible: u32,
        previous: u32,
        pending: u8,
    },
    Output {
        ordinal: Ordinal,
        previous: u32,
        pending: u8,
    },
    Dispatch,
    Manager(ManagerEffect),
    PrepareHook {
        ordinal: Ordinal,
        hook: Hook,
        output: Evaluation,
    },
    Packet(Ordinal),
    StorePacket {
        ordinal: Ordinal,
        packed: Packed,
        index: Option<u32>,
    },
    ControlFlags,
    DispatchControl,
    RetainPackets,
    ClearControl(Ordinal),
}
struct Batch<S> {
    serial: u64,
    cursor: u64,
    ops: VecDeque<Op>,
    tick: Option<u64>,
    snapshot: Option<S>,
    current_packet: Option<Packets>,
    value: Option<Value>,
    output: Evaluation,
}

/// Generic-platform lifecycle owner. Eligibility remains observable
/// even when later effects refuse, but no effect-completion token is minted.
pub struct Owner<B: Backend> {
    identity: Rc<()>,
    backend: B,
    profile: Profile,
    states: Vec<State>,
    batch: Option<Batch<B::Snapshot>>,
    serial: u64,
    selected: u64,
    initialized: bool,
    started: bool,
    completed: Option<Evaluation>,
    refusal: Option<&'static str>,
    forced_capture: u64,
    trace: bool,
    fault: Option<&'static str>,
}
impl<B: Backend> Owner<B> {
    pub fn initialized_software(profile: Profile, backend: B) -> Self {
        let states = profile
            .descriptors
            .iter()
            .map(|d| State::initialized(d, &profile.descriptors))
            .collect();
        Self {
            identity: Rc::new(()),
            backend,
            profile,
            states,
            batch: None,
            serial: 0,
            selected: 0,
            initialized: false,
            started: false,
            completed: None,
            refusal: None,
            forced_capture: 0,
            trace: false,
            fault: None,
        }
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    /// Backing identity only; no lifecycle or completion is granted.
    pub(in crate::platform::apple::pmp::native) fn identity(&self) -> Rc<()> {
        self.identity.clone()
    }
    pub fn backend(&self) -> &B {
        &self.backend
    }
    pub fn evaluated(&self, ordinal: Ordinal) -> u32 {
        self.states[ordinal.index()].evaluated
    }
    pub fn activation(&self, ordinal: Ordinal) -> u32 {
        self.states[ordinal.index()].activation
    }
    pub fn pending_control(&self, ordinal: Ordinal) -> u8 {
        self.states[ordinal.index()].pending
    }
    pub fn logical_request(&self, ordinal: Ordinal) -> Packed {
        self.states[ordinal.index()].logical
    }
    pub fn selected(&self) -> u64 {
        self.selected
    }
    pub fn last_evaluation(&self) -> Option<Evaluation> {
        self.completed
    }
    pub fn refusal(&self) -> Option<&'static str> {
        self.refusal
    }
    pub fn committed_prefix(&self) -> Option<u64> {
        self.batch.as_ref().map(|b| b.cursor)
    }
    fn begin(&mut self, ops: VecDeque<Op>) -> Result<(), Error> {
        if self.batch.is_some() || self.fault.is_some() {
            return Err(Error::Contract(
                "native platform operation already retained or faulted",
            ));
        }
        self.serial = self
            .serial
            .checked_add(1)
            .ok_or(Error::Contract("native platform serial exhausted"))?;
        self.batch = Some(Batch {
            serial: self.serial,
            cursor: 0,
            ops,
            tick: None,
            snapshot: None,
            current_packet: None,
            value: None,
            output: Evaluation::default(),
        });
        self.refusal = None;
        Ok(())
    }
    pub fn begin_initialize(&mut self) -> Result<(), Error> {
        if self.initialized {
            return Err(Error::Contract(
                "native platform resources already initialized",
            ));
        }
        let mut ops = VecDeque::new();
        for d in &self.profile.descriptors {
            ops.push_back(Op::Effect(Effect::Initialize {
                ordinal: d.ordinal,
                source_va: d.hook_va(Hook::Initialize),
            }));
            if let Some(source_object) = d.provider {
                ops.push_back(Op::Observe(Observation::ProviderStates {
                    ordinal: d.ordinal,
                    source_object,
                }));
                ops.push_back(Op::ProviderStates(d.ordinal));
            }
        }
        ops.push_back(Op::Initialized);
        self.begin(ops)
    }
    pub fn begin_start(&mut self) -> Result<(), Error> {
        if !self.initialized || self.started {
            return Err(Error::Contract(
                "native platform start requires initialized stopped resources",
            ));
        }
        let mut ops = VecDeque::new();
        for d in &self.profile.descriptors {
            ops.push_back(Op::Effect(Effect::Start {
                ordinal: d.ordinal,
                source_va: d.hook_va(Hook::Start),
            }));
        }
        ops.push_back(Op::Started);
        self.begin(ops)
    }
    pub fn begin_stop(&mut self) -> Result<(), Error> {
        if !self.started {
            return Err(Error::Contract("native platform resources are not started"));
        }
        let mut ops = VecDeque::new();
        for d in &self.profile.descriptors {
            ops.push_back(Op::Observe(Observation::Clock));
            ops.push_back(Op::Activate {
                ordinal: d.ordinal,
                enable: false,
            });
            ops.push_back(Op::Effect(Effect::Stop {
                ordinal: d.ordinal,
                source_va: d.hook_va(Hook::Stop),
            }));
        }
        ops.push_back(Op::Stopped);
        self.begin(ops)
    }
    /// Resolution is pure source policy. Its two packet-pair constraints must
    /// be checked against a backend observation before activation.
    pub fn begin_selection(&mut self, resolution: Resolution) -> Result<(), Error> {
        if !self.started {
            return Err(Error::Contract(
                "native selection requires actual source starts",
            ));
        }
        self.begin(
            [
                Op::Observe(Observation::Clock),
                Op::Observe(Observation::PolicyPackets),
                Op::Policy(resolution),
            ]
            .into(),
        )
    }
    pub fn begin_cycle(&mut self) -> Result<(), Error> {
        if !self.started {
            return Err(Error::Contract(
                "native evaluation requires actual source starts",
            ));
        }
        let bits = self.selected & self.profile.enabled;
        let mut ops = VecDeque::from([
            Op::Observe(Observation::Clock),
            Op::Observe(Observation::DispatchControl),
            Op::DispatchControl,
            Op::Observe(Observation::PolicyPackets),
            Op::RetainPackets,
            Op::Capture,
        ]);
        for mask in [
            bits & !self.profile.aggregates,
            bits & self.profile.aggregates,
        ] {
            for i in 0..18 {
                let ordinal = Ordinal::new(i).unwrap();
                if mask & ordinal.bit() != 0 {
                    ops.push_back(Op::Evaluate(ordinal));
                }
            }
        }
        ops.push_back(Op::Dispatch);
        self.completed = None;
        self.begin(ops)
    }
    pub fn begin_device_request(&mut self, ordinal: Ordinal) -> Result<(), Error> {
        if !self.started {
            return Err(Error::Contract(
                "native device request requires started owners",
            ));
        }
        self.begin(
            [
                Op::Observe(Observation::Clock),
                Op::Observe(Observation::DeviceRequest { ordinal }),
                Op::Packet(ordinal),
            ]
            .into(),
        )
    }
    pub fn begin_counter_controls(&mut self) -> Result<(), Error> {
        if !self.started {
            return Err(Error::Contract(
                "native counter controls require started owners",
            ));
        }
        self.begin([Op::Observe(Observation::CounterControls), Op::ControlFlags].into())
    }
    pub fn begin_reset_control(&mut self, ordinal: Ordinal) -> Result<(), Error> {
        self.begin(
            [
                Op::Effect(Effect::ResetControl { ordinal }),
                Op::ClearControl(ordinal),
            ]
            .into(),
        )
    }
    /// Native10045c4/1004d70 is a pure source control transformation. Neither
    /// output is an arrival bitmap or successful hardware callback receipt.
    pub fn apply_mc_control(
        &mut self,
        control: u32,
        override_word: u32,
    ) -> Result<McSelection, Error> {
        if self.batch.is_some() || self.fault.is_some() {
            return Err(Error::Contract(
                "native selection mutation during retained operation",
            ));
        }
        let d = &mut self.profile.descriptors[1];
        let control = McSelection::control_word(control, override_word, 3);
        let refs = core::array::from_fn(|i| super::CounterReference::local(i as u32 * 32, 32));
        let result = McSelection::resolve(d.selection.bits(), 2, d.raw[3], 2, control, &refs)
            .map_err(Error::Contract)?;
        d.selection.replace(result.desired);
        Ok(result)
    }
    ///10129f0..1012a20 after the registry ID lookup resolves ordinal.
    /// This changes only source-enabled policy; it cannot activate, evaluate,
    /// finish an effect or publish an ACK. The callback owner keeps its ID.
    pub fn apply_source_enable(&mut self, ordinal: Ordinal, value: u32) -> Result<(), Error> {
        if self.batch.is_some() || self.fault.is_some() {
            return Err(Error::Contract(
                "native source enable mutation during retained operation",
            ));
        }
        if value == 0 {
            self.profile.enabled &= !ordinal.bit();
        } else {
            self.profile.enabled |= ordinal.bit();
        }
        Ok(())
    }
    /// Keep a native software configuration write; no activation/current or
    /// readiness setter exists. The source writer/registry owns authorization.
    pub fn apply_configuration(
        &mut self,
        ordinal: Ordinal,
        value: super::Configuration,
    ) -> Result<(), Error> {
        if self.batch.is_some() || self.fault.is_some() {
            return Err(Error::Contract(
                "native configuration mutation during retained operation",
            ));
        }
        let d = &mut self.profile.descriptors[ordinal.index()];
        match value {
            super::Configuration::Hysteresis(v) => d.hysteresis = v,
            super::Configuration::PeriodShift(v) => d.period_shift = v,
            super::Configuration::FreshnessCheck(v) => d.freshness_check = v,
            super::Configuration::AggregateResetFlag(v) => d.aggregate_reset_flag = v,
        }
        Ok(())
    }
    fn prepend(batch: &mut Batch<B::Snapshot>, ops: impl IntoIterator<Item = Op>) {
        let v: Vec<_> = ops.into_iter().collect();
        for op in v.into_iter().rev() {
            batch.ops.push_front(op);
        }
    }
    fn tick(batch: &Batch<B::Snapshot>) -> Result<u64, Error> {
        batch
            .tick
            .ok_or(Error::Contract("native source clock observation absent"))
    }
    fn refresh(&self, ordinal: Ordinal, tick: u64) -> Op {
        let s = &self.states[ordinal.index()];
        let d = &self.profile.descriptors[ordinal.index()];
        Op::Effect(Effect::Refresh {
            ordinal,
            mode: d.mode,
            logical: s.logical,
            activation: s.activation,
            evaluated: s.evaluated,
            state_index: s.state_index,
            tick,
        })
    }
    fn evaluate(&mut self, batch: &mut Batch<B::Snapshot>, ordinal: Ordinal) -> Result<(), Error> {
        let d = &self.profile.descriptors[ordinal.index()];
        let tick = Self::tick(batch)?;
        let previous = self.states[ordinal.index()].evaluated;
        let pending = self.states[ordinal.index()].pending;
        let updates = if let Some(slice) = d.counters {
            batch
                .snapshot
                .as_ref()
                .ok_or(Error::Contract("native manager pending capture absent"))?
                .bits(slice.start, slice.count)
                .map_err(Error::Contract)?
        } else {
            0
        };
        let parent = d.parent.map(|p| self.states[p.index()].evaluated);
        let s = &mut self.states[ordinal.index()];
        s.tick = tick;
        let eligible;
        if d.aggregate != 0 {
            if previous == 0 && d.aggregate_reset_flag & 1 == 0 {
                s.activity = 0;
                s.adjacent = 0;
            }
            eligible = u32::from(d.aggregate & batch.output.eligible != 0);
            if eligible == 1 && d.counters.is_some() {
                s.selected = d.selection.bits() & updates;
                if s.selected != 0 {
                    s.activity = s.activity.wrapping_add(1);
                }
            }
        } else if d.counters.is_none() {
            if previous == 0 {
                s.adjacent = 0;
            }
            let gate = s.parent_gate != 1 || parent == Some(1);
            if let Some(address) = d.observer.filter(|_| gate) {
                Self::prepend(
                    batch,
                    [
                        Op::Observe(Observation::Observer { ordinal, address }),
                        Op::ObserverDecision {
                            ordinal,
                            previous,
                            pending,
                        },
                    ],
                );
                return Ok(());
            }
            eligible = u32::from(gate && d.observer.is_none());
        } else {
            s.selected = d.selection.bits() & updates;
            if s.selected & 255 == 0 {
                eligible = if d.hysteresis != 0 && s.hysteresis_left != 0 {
                    s.hysteresis_left -= 1;
                    1
                } else {
                    0
                };
            } else {
                if d.hysteresis != 0 {
                    s.hysteresis_left = d.hysteresis;
                }
                if previous == 1 {
                    s.activity = s.activity.wrapping_add(1);
                    eligible = 1;
                    if s.activity == 0 {
                        Self::prepend(
                            batch,
                            [
                                Op::Effect(Effect::DiscardCounters {
                                    ordinal,
                                    slice: d.counters.unwrap(),
                                    selected: s.selected,
                                }),
                                Op::Commit {
                                    ordinal,
                                    eligible,
                                    previous,
                                    pending,
                                },
                            ],
                        );
                        return Ok(());
                    }
                } else {
                    s.activity = 0;
                    s.adjacent = 0;
                    if d.freshness_check == 1 && s.selected >> 8 == 0 && s.freshness_arm == 1 {
                        Self::prepend(
                            batch,
                            [
                                Op::Observe(Observation::ConsumeFreshnessValue {
                                    ordinal,
                                    entry: d.counters.unwrap().start,
                                }),
                                Op::FreshDecision {
                                    ordinal,
                                    previous,
                                    pending,
                                },
                            ],
                        );
                        return Ok(());
                    }
                    s.activity = 1;
                    eligible = 1;
                }
            }
        }
        Self::prepend(
            batch,
            [Op::Commit {
                ordinal,
                eligible,
                previous,
                pending,
            }],
        );
        Ok(())
    }
    fn commit(
        &mut self,
        batch: &mut Batch<B::Snapshot>,
        ordinal: Ordinal,
        eligible: u32,
        previous: u32,
        pending: u8,
    ) -> Result<(), Error> {
        let d = &self.profile.descriptors[ordinal.index()];
        let tick = Self::tick(batch)?;
        let s = &mut self.states[ordinal.index()];
        s.changed = u8::from(
            (d.aggregate != 0 || d.counters.is_some() || d.observer_write == 1)
                && eligible != s.evaluated,
        );
        s.evaluated = eligible;
        let mut refresh = s.changed != 0;
        if let Some(interpolation) = s.interpolation.as_mut()
            && let Some(target) = interpolation.advance(d.times().1)
        {
            let controller = d.controller.ok_or(Error::Contract(
                "native interpolation controller join absent",
            ))?;
            s.logical.set(controller, target);
            refresh = true;
        }
        let output = Op::Output {
            ordinal,
            previous,
            pending,
        };
        if refresh {
            Self::prepend(batch, [self.refresh(ordinal, tick), output]);
        } else {
            Self::prepend(batch, [output]);
        }
        Ok(())
    }
    fn packet(&mut self, batch: &mut Batch<B::Snapshot>, ordinal: Ordinal) -> Result<(), Error> {
        let payload = match batch.value.take() {
            Some(Value::Payload(v)) => v,
            _ => return Err(Error::Contract("native device request payload absent")),
        };
        let d = &self.profile.descriptors[ordinal.index()];
        let s = &mut self.states[ordinal.index()];
        let mut packed = Packed::default();
        let mut index = None;
        match d.mode {
            1 => {
                let interpolation = s.interpolation.as_mut().ok_or(Error::Contract(
                    "native mode1 interpolation initialization absent",
                ))?;
                let target = interpolation.request(payload);
                packed.set(
                    d.controller
                        .ok_or(Error::Contract("native mode1 controller absent"))?,
                    target,
                );
            }
            2 => {
                let requested = payload as u32 & 31;
                let target = if s.source_states > requested {
                    requested
                } else {
                    s.source_states.wrapping_sub(1)
                };
                if let Some(controller) = d.controller {
                    packed.set(controller, target);
                } else {
                    //1010fd4: a controller-less mode2 keeps its state-table
                    // index for the cfg38 requirement row rather than a nibble.
                    index = Some(target);
                }
            }
            _ => {
                s.logical = packed;
                Self::prepend(batch, [self.refresh(ordinal, Self::tick(batch)?)]);
                return Ok(());
            }
        }
        for (index, controller) in d.other_controllers.iter().enumerate() {
            let Some(controller) = controller else { break };
            packed.set(*controller, ((payload >> (32 + 4 * index)) & 15) as u32);
        }
        packed.0[0] = (packed.0[0] & !15) | ((payload >> 48) & 15);
        let mut ops = Vec::new();
        if let Some(target) = index
            && d.request_trace_id != 0
            && target != s.state_index
        {
            ops.push(Op::Effect(Effect::RequestTrace {
                ordinal,
                source_id: d.request_trace_id,
                previous: s.state_index,
                target,
            }));
        }
        ops.push(Op::StorePacket {
            ordinal,
            packed,
            index,
        });
        Self::prepend(batch, ops);
        Ok(())
    }
    /// Advance a prefix. A refused operation cannot be replaced with
    /// a different batch, backend or snapshot. Busy resumes the same request.
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        if let Some(reason) = self.fault {
            return Err(Error::Contract(reason));
        }
        let Some(mut batch) = self.batch.take() else {
            return Ok(Progress::Idle);
        };
        let result = self.advance_batch(&mut batch, access);
        if let Err(Error::Contract(reason)) = result {
            self.fault = Some(reason);
        }
        if !batch.ops.is_empty() || result.is_err() {
            self.batch = Some(batch);
        }
        result
    }
    fn advance_batch(
        &mut self,
        batch: &mut Batch<B::Snapshot>,
        access: &mut Access<'_>,
    ) -> Result<Progress, Error> {
        while let Some(op) = batch.ops.pop_front() {
            // Reserve the next operation identity before any external operation
            // can retire. Exhaustion must never execute an unrecordable effect.
            let next_cursor = batch.cursor.checked_add(1).ok_or(Error::Contract(
                "native platform operation cursor exhausted",
            ))?;
            let request = Request {
                owner: self.identity.clone(),
                serial: batch.serial,
                operation: batch.cursor,
            };
            let mut retired_refusal = None;
            match &op {
                Op::Observe(observation) => {
                    match self.backend.observe(
                        &request,
                        *observation,
                        batch.snapshot.as_ref(),
                        access,
                    ) {
                        Completion::Busy { deadline } => {
                            batch.ops.push_front(op);
                            return Ok(Progress::Busy { deadline });
                        }
                        Completion::Refused(reason) => {
                            batch.ops.push_front(op);
                            self.refusal = Some(reason);
                            return Err(Error::Backend(reason));
                        }
                        Completion::Retired { value, refusal } => {
                            if let Value::Tick(tick) = value {
                                batch.tick = Some(tick);
                            } else {
                                batch.value = Some(value);
                            }
                            retired_refusal = refusal;
                        }
                    }
                }
                Op::Manager(effect) => {
                    match self.backend.manager_effect(
                        &request,
                        *effect,
                        &self.profile,
                        ManagerContext {
                            output: batch.output,
                            tick: Self::tick(batch)?,
                            current_packet: batch.current_packet.ok_or(Error::Contract(
                                "native actual manager six-word packet absent",
                            ))?,
                        },
                        batch.snapshot.as_ref(),
                        access,
                    ) {
                        Completion::Busy { deadline } => {
                            batch.ops.push_front(op);
                            return Ok(Progress::Busy { deadline });
                        }
                        Completion::Refused(reason) => {
                            batch.ops.push_front(op);
                            self.refusal = Some(reason);
                            return Err(Error::Backend(reason));
                        }
                        Completion::Retired { value: (), refusal } => {
                            retired_refusal = refusal;
                        }
                    }
                }
                Op::Capture => {
                    match self
                        .backend
                        .capture_pending(&request, self.profile.packet, access)
                    {
                        Completion::Busy { deadline } => {
                            batch.ops.push_front(op);
                            return Ok(Progress::Busy { deadline });
                        }
                        Completion::Refused(reason) => {
                            batch.ops.push_front(op);
                            self.refusal = Some(reason);
                            return Err(Error::Backend(reason));
                        }
                        Completion::Retired { value, refusal } => {
                            batch.snapshot = Some(value);
                            retired_refusal = refusal;
                        }
                    }
                }
                Op::Effect(effect) => {
                    let ordinal = match effect {
                        Effect::Initialize { ordinal, .. }
                        | Effect::Start { ordinal, .. }
                        | Effect::Stop { ordinal, .. }
                        | Effect::Activation { ordinal, .. }
                        | Effect::DiscardCounters { ordinal, .. }
                        | Effect::Refresh { ordinal, .. }
                        | Effect::Hook { ordinal, .. }
                        | Effect::ResetControl { ordinal }
                        | Effect::RequestTrace { ordinal, .. } => *ordinal,
                    };
                    match self.backend.effect(
                        &request,
                        effect,
                        &self.profile.descriptors[ordinal.index()],
                        batch.snapshot.as_ref(),
                        access,
                    ) {
                        Completion::Busy { deadline } => {
                            batch.ops.push_front(op);
                            return Ok(Progress::Busy { deadline });
                        }
                        Completion::Refused(reason) => {
                            batch.ops.push_front(op);
                            self.refusal = Some(reason);
                            return Err(Error::Backend(reason));
                        }
                        Completion::Retired { value, refusal } => {
                            match (effect, value) {
                                (
                                    Effect::Hook {
                                        hook: Hook::Capture | Hook::Postprocess,
                                        ..
                                    },
                                    EffectValue::Hook {
                                        buffer_index,
                                        state_index,
                                        previous_state_index,
                                    },
                                ) => {
                                    let s = &mut self.states[ordinal.index()];
                                    s.adjacent = buffer_index;
                                    s.state_index = state_index;
                                    s.previous_state_index = previous_state_index;
                                }
                                (
                                    Effect::Hook {
                                        hook: Hook::Capture | Hook::Postprocess,
                                        ..
                                    },
                                    _,
                                ) => {
                                    return Err(Error::Contract(
                                        "native counter hook software products absent",
                                    ));
                                }
                                (_, EffectValue::Complete) => {}
                                _ => {
                                    return Err(Error::Contract(
                                        "native backend returned hook products for a different effect",
                                    ));
                                }
                            }
                            retired_refusal = refusal;
                        }
                    }
                }
                Op::ProviderStates(ordinal) => {
                    let count = match batch.value.take() {
                        Some(Value::ProviderStateCount(v)) => v,
                        _ => return Err(Error::Contract("native provider count result absent")),
                    };
                    if count > 32 {
                        return Err(Error::Contract(
                            "native provider state count exceeds request encoding",
                        ));
                    }
                    self.states[ordinal.index()].source_states = count;
                }
                Op::Initialized => self.initialized = true,
                Op::Started => self.started = true,
                Op::Stopped => self.started = false,
                Op::Policy(resolution) => {
                    let packets = match batch.value.take() {
                        Some(Value::Packets(p)) => p,
                        _ => {
                            batch.ops.push_front(op);
                            return Err(Error::Contract(
                                "native source policy packet snapshot absent",
                            ));
                        }
                    };
                    if resolution.check_packets(packets) != ConstraintState::WithinConstraints {
                        // Source leaves old accepted selection intact. A fresh
                        // snapshot is required on each retry.
                        Self::prepend(batch, [Op::Observe(Observation::PolicyPackets), op]);
                        return Ok(Progress::Busy { deadline: None });
                    }
                    let mut ops = Vec::new();
                    let changed = self.selected ^ resolution.resolved();
                    for i in 0..18 {
                        let ordinal = Ordinal::new(i).unwrap();
                        if changed & ordinal.bit() != 0 {
                            ops.push(Op::Activate {
                                ordinal,
                                enable: resolution.resolved() & ordinal.bit() != 0,
                            });
                        }
                    }
                    ops.push(Op::Selection(resolution.resolved()));
                    Self::prepend(batch, ops);
                }
                Op::Activate { ordinal, enable } => {
                    let s = &mut self.states[ordinal.index()];
                    let previous = s.activation;
                    if (*enable && previous == 0) || (!*enable && previous == 1) {
                        s.activation = u32::from(*enable);
                        s.evaluated = 0;
                        if *enable {
                            s.activity = 0;
                            s.adjacent = 0;
                        }
                    }
                    //100f1ac calls the routine even for already inactive rows:
                    // its counter/notification tail must still execute.
                    Self::prepend(
                        batch,
                        [Op::Effect(Effect::Activation {
                            ordinal: *ordinal,
                            enable: *enable,
                            previous,
                            tick: Self::tick(batch)?,
                        })],
                    );
                }
                Op::Selection(bits) => self.selected = *bits,
                Op::Evaluate(ordinal) => self.evaluate(batch, *ordinal)?,
                Op::ObserverDecision {
                    ordinal,
                    previous,
                    pending,
                } => {
                    let value = match batch.value.take() {
                        Some(Value::ObserverWord(v)) => v,
                        _ => return Err(Error::Contract("native observer word result absent")),
                    };
                    Self::prepend(
                        batch,
                        [Op::Commit {
                            ordinal: *ordinal,
                            eligible: u32::from(value & 0xf0 == 0xf0),
                            previous: *previous,
                            pending: *pending,
                        }],
                    );
                }
                Op::FreshDecision {
                    ordinal,
                    previous,
                    pending,
                } => {
                    let stamp = match batch.value.take() {
                        Some(Value::ConsumedValueLow32(v)) => v,
                        _ => {
                            return Err(Error::Contract(
                                "native consumed entry value low32 absent",
                            ));
                        }
                    };
                    let d = &self.profile.descriptors[ordinal.index()];
                    let fresh = (Self::tick(batch)? as u32).wrapping_sub(stamp)
                        <= d.times().0.wrapping_add(24);
                    let s = &mut self.states[ordinal.index()];
                    if fresh || s.pending == 1 {
                        s.activity = s.activity.wrapping_add(1);
                    }
                    let commit = Op::Commit {
                        ordinal: *ordinal,
                        eligible: u32::from(fresh),
                        previous: *previous,
                        pending: *pending,
                    };
                    if s.activity == 0 {
                        Self::prepend(
                            batch,
                            [
                                Op::Effect(Effect::DiscardCounters {
                                    ordinal: *ordinal,
                                    slice: d.counters.unwrap(),
                                    selected: s.selected,
                                }),
                                commit,
                            ],
                        );
                    } else {
                        Self::prepend(batch, [commit]);
                    }
                }
                Op::Commit {
                    ordinal,
                    eligible,
                    previous,
                    pending,
                } => self.commit(batch, *ordinal, *eligible, *previous, *pending)?,
                Op::Output {
                    ordinal,
                    previous,
                    pending,
                } => {
                    if self.states[ordinal.index()].evaluated == 1 {
                        batch.output.eligible |= ordinal.bit();
                    } else if *previous == 1 {
                        batch.output.falling |= ordinal.bit();
                    }
                    if *pending != 0 {
                        batch.output.prior_pending |= ordinal.bit();
                    }
                }
                Op::Dispatch => {
                    self.completed = Some(batch.output);
                    let mut ops = Vec::new();
                    ops.push(Op::Manager(ManagerEffect::BeforeCapture));
                    for (mask, hook) in [
                        (
                            batch.output.eligible
                                | batch.output.prior_pending
                                | self.forced_capture,
                            Hook::Capture,
                        ),
                        (
                            batch.output.eligible | self.forced_capture,
                            Hook::Postprocess,
                        ),
                        (
                            if self.trace {
                                batch.output.eligible | batch.output.falling
                            } else {
                                0
                            },
                            Hook::Trace,
                        ),
                    ] {
                        if hook == Hook::Postprocess {
                            ops.push(Op::Observe(Observation::Clock));
                            ops.push(Op::Manager(ManagerEffect::RestoreControllers));
                        } else if hook == Hook::Trace {
                            ops.push(Op::Manager(ManagerEffect::AccumulateCounters));
                        }
                        for d in &self.profile.descriptors {
                            if mask & d.ordinal.bit() != 0 {
                                ops.push(Op::PrepareHook {
                                    ordinal: d.ordinal,
                                    hook,
                                    output: batch.output,
                                });
                            }
                        }
                    }
                    Self::prepend(batch, ops);
                }
                Op::PrepareHook {
                    ordinal,
                    hook,
                    output,
                } => {
                    let s = &self.states[ordinal.index()];
                    let counters = CounterContext {
                        selected: s.selected,
                        evaluation_tick: s.tick,
                        current_packet: batch.current_packet.ok_or(Error::Contract(
                            "native actual manager six-word packet absent",
                        ))?,
                        activity: s.activity,
                        buffer_index: s.adjacent,
                        state_index: s.state_index,
                        previous_state_index: s.previous_state_index,
                        evaluated: s.evaluated,
                        pending: s.pending,
                    };
                    Self::prepend(
                        batch,
                        [Op::Effect(Effect::Hook {
                            ordinal: *ordinal,
                            hook: *hook,
                            output: *output,
                            source_va: self.profile.descriptors[ordinal.index()].hook_va(*hook),
                            counters,
                        })],
                    );
                }
                Op::Packet(ordinal) => self.packet(batch, *ordinal)?,
                Op::StorePacket {
                    ordinal,
                    packed,
                    index,
                } => {
                    let s = &mut self.states[ordinal.index()];
                    if let Some(index) = index {
                        s.previous_state_index = s.state_index;
                        s.state_index = *index;
                    }
                    s.logical = *packed;
                    Self::prepend(batch, [self.refresh(*ordinal, Self::tick(batch)?)]);
                }
                Op::DispatchControl => {
                    let (enabled, result) = match batch.value.take() {
                        Some(Value::DispatchControl {
                            trace_enabled,
                            trace_result,
                        }) => (trace_enabled, trace_result),
                        _ => {
                            return Err(Error::Contract(
                                "native cycle diagnostic observation absent",
                            ));
                        }
                    };
                    self.trace = if enabled == 0 {
                        false
                    } else {
                        result.ok_or(Error::Contract(
                            "native enabled cycle trace has no actual return",
                        ))? != 0x80000007
                    };
                }
                Op::RetainPackets => {
                    batch.current_packet = Some(match batch.value.take() {
                        Some(Value::Packets(packets)) => packets,
                        _ => {
                            return Err(Error::Contract(
                                "native actual manager packet observation absent",
                            ));
                        }
                    });
                }
                Op::ControlFlags => {
                    let flags = match batch.value.take() {
                        Some(Value::Controls(x)) => x,
                        _ => {
                            return Err(Error::Contract(
                                "native source counter control flags absent",
                            ));
                        }
                    };
                    for flag in flags {
                        if (flag.low | flag.high) & 1 != 0 {
                            self.states[flag.ordinal.index()].pending = 1;
                        }
                    }
                }
                Op::ClearControl(ordinal) => self.states[ordinal.index()].pending = 0,
            }
            batch.cursor = next_cursor;
            if let Some(reason) = retired_refusal {
                self.refusal = Some(reason);
                return Err(Error::Backend(reason));
            }
        }
        self.refusal = None;
        Ok(Progress::Idle)
    }
}

#[cfg(test)]
mod tests {
    use super::super::profile::tests::fixture;
    use super::*;
    use alloc::vec;
    use stela_contracts::interrupt::InterruptLatch;
    struct Snapshot(u128, u128);
    impl Pending for Snapshot {
        fn bits(&self, start: u32, count: u32) -> Result<u128, &'static str> {
            let x = if start < 128 {
                self.0 >> (start - 16)
            } else {
                self.1 >> (start - 128)
            };
            Ok(if count == 128 {
                x
            } else {
                x & ((1u128 << count) - 1)
            })
        }
    }
    struct TestBackend {
        calls: Vec<(Request, Effect)>,
        reads: Vec<(Request, Observation)>,
        captures: u32,
        manager: Vec<(Request, ManagerEffect, usize, usize, ManagerContext)>,
        snapshot: (u128, u128),
        tick: u64,
        observer: u32,
        stamp: u32,
        payload: u64,
        busy: bool,
        refuse: bool,
        after: bool,
        hook_buffer: Option<u32>,
        bad_hook: bool,
        controls: Vec<ControlFlags>,
        packets: Packets,
    }
    impl TestBackend {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                reads: Vec::new(),
                captures: 0,
                manager: Vec::new(),
                snapshot: (0, 0),
                tick: 1000,
                observer: 0xf0,
                stamp: 1000,
                payload: 0,
                busy: false,
                refuse: false,
                after: false,
                hook_buffer: None,
                bad_hook: false,
                controls: Vec::new(),
                packets: Packets([0x403, 0, 0x403, 0, 0, 0]),
            }
        }
    }
    impl Backend for TestBackend {
        type Snapshot = Snapshot;
        fn observe(
            &mut self,
            request: &Request,
            observation: Observation,
            snapshot: Option<&Self::Snapshot>,
            _: &mut Access<'_>,
        ) -> Completion<Value> {
            self.reads.push((request.clone(), observation));
            Completion::Retired {
                value: match observation {
                    Observation::Clock => Value::Tick(self.tick),
                    Observation::PolicyPackets => Value::Packets(self.packets),
                    Observation::ProviderStates { .. } => Value::ProviderStateCount(8),
                    Observation::Observer { .. } => Value::ObserverWord(self.observer),
                    Observation::ConsumeFreshnessValue { .. } => {
                        assert!(snapshot.is_some());
                        Value::ConsumedValueLow32(self.stamp)
                    }
                    Observation::DeviceRequest { .. } => Value::Payload(self.payload),
                    Observation::CounterControls => Value::Controls(self.controls.clone()),
                    Observation::DispatchControl => Value::DispatchControl {
                        trace_enabled: 0,
                        trace_result: None,
                    },
                },
                refusal: None,
            }
        }
        fn capture_pending(
            &mut self,
            _: &Request,
            _: Slice,
            _: &mut Access<'_>,
        ) -> Completion<Snapshot> {
            self.captures += 1;
            Completion::Retired {
                value: Snapshot(self.snapshot.0, self.snapshot.1),
                refusal: None,
            }
        }
        fn manager_effect(
            &mut self,
            request: &Request,
            effect: ManagerEffect,
            _: &Profile,
            context: ManagerContext,
            snapshot: Option<&Self::Snapshot>,
            _: &mut Access<'_>,
        ) -> Completion<()> {
            assert!(snapshot.is_some());
            self.manager.push((
                request.clone(),
                effect,
                self.calls.len(),
                self.reads.len(),
                context,
            ));
            Completion::Retired {
                value: (),
                refusal: None,
            }
        }
        fn effect(
            &mut self,
            request: &Request,
            effect: &Effect,
            _: &Descriptor,
            snapshot: Option<&Self::Snapshot>,
            _: &mut Access<'_>,
        ) -> Completion<EffectValue> {
            if matches!(effect, Effect::DiscardCounters { .. }) {
                assert!(snapshot.is_some());
            }
            self.calls.push((request.clone(), effect.clone()));
            if self.busy {
                self.busy = false;
                return Completion::Busy { deadline: Some(22) };
            }
            if self.refuse {
                self.refuse = false;
                return Completion::Refused("authored unavailable native effect");
            }
            let refusal = if self.after {
                self.after = false;
                Some("authored retired effect refusal")
            } else {
                None
            };
            let value = match effect {
                Effect::Hook {
                    hook: Hook::Capture | Hook::Postprocess,
                    counters,
                    ..
                } if !self.bad_hook => EffectValue::Hook {
                    buffer_index: self.hook_buffer.unwrap_or(counters.buffer_index),
                    state_index: counters.state_index,
                    previous_state_index: counters.previous_state_index,
                },
                _ => EffectValue::Complete,
            };
            Completion::Retired { value, refusal }
        }
    }
    fn step(o: &mut Owner<TestBackend>) -> Result<Progress, Error> {
        let mut latch = InterruptLatch::new();
        o.advance(&mut Access::new(0, 1, &mut latch))
    }
    fn owner() -> Owner<TestBackend> {
        let mut o = Owner::initialized_software(fixture(), TestBackend::new());
        o.begin_initialize().unwrap();
        assert_eq!(step(&mut o), Ok(Progress::Idle));
        o.begin_start().unwrap();
        step(&mut o).unwrap();
        o
    }
    fn selection(o: &mut Owner<TestBackend>, bits: u64) {
        let p = super::super::super::power::policy::Policy::t8112(table(), None).unwrap();
        o.begin_selection(p.resolve(bits).unwrap()).unwrap();
        step(o).unwrap();
    }
    fn table() -> super::super::super::power::DeviceTable {
        let raw: Vec<u8> = [
            1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
        ]
        .into_iter()
        .map(|id| {
            let mut r = [0u32; 31];
            r[0] = id;
            r
        })
        .flat_map(|r| r.into_iter().flat_map(u32::to_le_bytes))
        .collect();
        super::super::super::power::DeviceTable::from_properties(
            &raw,
            &0x3fff0u64.to_le_bytes(),
            None,
        )
        .unwrap()
    }
    fn ordinal(i: u8) -> Ordinal {
        Ordinal::new(i).unwrap()
    }
    #[test]
    fn manager_stages_bracket_hooks_and_cursor_exhaustion_precedes_backend() {
        let mut o = owner();
        selection(&mut o, 1 << 8);
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        let stages = &o.backend.manager;
        assert_eq!(stages.len(), 3);
        assert_eq!(stages[0].1, ManagerEffect::BeforeCapture);
        assert_eq!(stages[1].1, ManagerEffect::RestoreControllers);
        assert_eq!(stages[2].1, ManagerEffect::AccumulateCounters);
        assert!(
            stages
                .iter()
                .all(|stage| stage.4.current_packet == o.backend.packets)
        );
        let captures = &o.backend.calls[stages[0].2..stages[1].2];
        assert!(!captures.is_empty());
        assert!(captures.iter().all(|(_, e)| matches!(
            e,
            Effect::Hook {
                hook: Hook::Capture,
                ..
            }
        )));
        let posts = &o.backend.calls[stages[1].2..stages[2].2];
        assert!(!posts.is_empty());
        assert!(posts.iter().all(|(_, e)| matches!(
            e,
            Effect::Hook {
                hook: Hook::Postprocess,
                ..
            }
        )));
        assert_eq!(o.backend.reads[stages[1].3 - 1].1, Observation::Clock);
        let initial_tick = o.states[8].tick;
        assert!(captures.iter().all(|(_, e)| matches!(e, Effect::Hook { counters, .. } if counters.evaluation_tick == initial_tick && counters.current_packet == o.backend.packets)));
        o.begin_counter_controls().unwrap();
        o.batch.as_mut().unwrap().cursor = u64::MAX;
        let before = o.backend.reads.len();
        assert_eq!(
            step(&mut o),
            Err(Error::Contract(
                "native platform operation cursor exhausted"
            ))
        );
        assert_eq!(o.backend.reads.len(), before);
    }

    #[test]
    fn both_passes_share_one_snapshot_and_aggregate_uses_current_leaf_ordinals() {
        let mut o = owner();
        selection(&mut o, 1 << 8);
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        let out = o.last_evaluation().unwrap();
        assert_eq!(out.eligible & 0xf, 0xf);
        assert_ne!(out.eligible & (1 << 8), 0);
        assert_eq!(o.backend.captures, 1);
        assert_eq!(o.evaluated(ordinal(4)), 0);
        assert_eq!(o.activation(ordinal(4)), 1);
        let hooks: Vec<_> = o
            .backend
            .calls
            .iter()
            .filter_map(|(_, e)| {
                if let Effect::Hook { ordinal, hook, .. } = e {
                    Some((ordinal.index(), *hook))
                } else {
                    None
                }
            })
            .collect();
        let split = hooks.iter().position(|x| x.1 == Hook::Postprocess).unwrap();
        assert!(hooks[..split].iter().all(|x| x.1 == Hook::Capture));
        selection(&mut o, 0);
        assert_eq!(o.evaluated(ordinal(8)), 0);
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.last_evaluation().unwrap().eligible, 0);
    }
    #[test]
    fn observer_parent_hysteresis_and_freshness_use_exact_branches() {
        let mut o = owner();
        selection(&mut o, 1 << 9);
        o.backend.observer = 0xe0;
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(9)), 0);
        o.backend.observer = 0xf0;
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(9)), 1);
        o.states[9].parent_gate = 1;
        o.states[1].evaluated = 0;
        let reads = o.backend.reads.len();
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(9)), 0);
        assert!(
            !o.backend.reads[reads..]
                .iter()
                .any(|x| matches!(x.1, Observation::Observer { .. }))
        );
        let i = 4;
        o.profile.descriptors[i].selection =
            super::super::CounterSelection::initialized(Vec::new(), 1).unwrap();
        o.profile.descriptors[i].hysteresis = 2;
        o.backend.snapshot.1 = 1;
        o.states[i].freshness_arm = 1;
        o.backend.stamp = 900;
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(4)), 1);
        o.backend.snapshot.1 = 0;
        for expected in [1, 1, 0] {
            o.begin_cycle().unwrap();
            step(&mut o).unwrap();
            assert_eq!(o.evaluated(ordinal(4)), expected);
        }
        o.backend.snapshot.1 = 1;
        o.backend.stamp = 0;
        o.states[i].pending = 1;
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(4)), 0);
        assert_eq!(o.states[i].activity, 1);
        assert_ne!(o.last_evaluation().unwrap().prior_pending & (1 << i), 0);
    }
    #[test]
    fn wrap_discard_and_retired_refusal_preserve_source_prefix_and_request_identity() {
        let mut o = owner();
        selection(&mut o, 1 << 8);
        o.profile.descriptors[4].selection =
            super::super::CounterSelection::initialized(Vec::new(), 1).unwrap();
        o.states[4].evaluated = 1;
        o.states[4].activity = u32::MAX;
        o.backend.snapshot.1 = 1;
        o.backend.busy = true;
        o.begin_cycle().unwrap();
        assert_eq!(step(&mut o), Ok(Progress::Busy { deadline: Some(22) }));
        let cursor = o.committed_prefix();
        let request = o.backend.calls.last().unwrap().0.clone();
        assert_eq!(o.states[4].activity, 0);
        assert!(o.begin_cycle().is_err());
        step(&mut o).unwrap();
        let calls: Vec<_> = o
            .backend
            .calls
            .iter()
            .filter(|(_, e)| matches!(e, Effect::DiscardCounters { .. }))
            .collect();
        assert_eq!(calls.len(), 2);
        assert!(request.same_operation(&calls[1].0));
        assert!(cursor.is_some());
        o.backend.after = true;
        o.begin_cycle().unwrap();
        assert!(step(&mut o).is_err());
        let n = o.backend.calls.len();
        step(&mut o).unwrap();
        assert!(
            !o.backend.calls[n..]
                .iter()
                .any(|(r, _)| r.same_operation(&o.backend.calls[n - 1].0))
        );
    }
    #[test]
    fn refusal_does_not_admit_init_start_selection_or_pending_reset() {
        let mut o = Owner::initialized_software(fixture(), TestBackend::new());
        o.backend.refuse = true;
        o.begin_initialize().unwrap();
        assert!(step(&mut o).is_err());
        assert!(o.begin_start().is_err());
        assert!(!o.initialized);
        step(&mut o).unwrap();
        o.begin_start().unwrap();
        step(&mut o).unwrap();
        let p = super::super::super::power::policy::Policy::t8112(table(), None).unwrap();
        o.backend.refuse = true;
        o.begin_selection(p.resolve(1 << 8).unwrap()).unwrap();
        assert!(step(&mut o).is_err());
        assert_eq!(o.selected(), 0);
        assert_eq!(o.activation(ordinal(0)), 1);
        assert_eq!(o.evaluated(ordinal(0)), 0);
        step(&mut o).unwrap();
        assert_ne!(o.selected(), 0);
        o.backend.controls = vec![ControlFlags {
            ordinal: ordinal(8),
            low: 1,
            high: 0,
        }];
        o.begin_counter_controls().unwrap();
        step(&mut o).unwrap();
        o.backend.refuse = true;
        o.begin_reset_control(ordinal(8)).unwrap();
        assert!(step(&mut o).is_err());
        assert_eq!(o.pending_control(ordinal(8)), 1);
        step(&mut o).unwrap();
        assert_eq!(o.pending_control(ordinal(8)), 0);
    }
    #[test]
    fn actual_packet_observation_drives_isp_mode1_tuple_and_periodic_refresh() {
        let mut o = owner();
        selection(&mut o, 1 << 8);
        o.backend.payload = (1000 << 16) | 363;
        o.begin_device_request(ordinal(8)).unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.logical_request(ordinal(8)).nibble(1), Some(1));
        o.states[8].interpolation.as_mut().unwrap().advance(489);
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.logical_request(ordinal(8)).nibble(1), Some(0));
        assert!(o.backend.calls.iter().any(|(_,e)|matches!(e,Effect::Refresh{ordinal,logical,..}if ordinal.index()==8&&logical.nibble(1)==Some(0))));
        o.backend.payload = 31 | (4 << 32);
        o.begin_device_request(ordinal(4)).unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.states[4].state_index, 7);
        assert_eq!(o.logical_request(ordinal(4)).nibble(1), Some(4));
    }
    #[test]
    fn stop_deactivates_before_each_actual_stop_and_keeps_inactive_tail_effects() {
        let mut o = owner();
        selection(&mut o, 1 << 8);
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert_eq!(o.evaluated(ordinal(8)), 1);
        o.backend.refuse = true;
        let n = o.backend.calls.len();
        o.begin_stop().unwrap();
        assert!(step(&mut o).is_err());
        assert_eq!(o.activation(ordinal(0)), 0);
        assert_eq!(o.evaluated(ordinal(0)), 0);
        assert!(
            !o.backend.calls[n..]
                .iter()
                .any(|(_, e)| matches!(e, Effect::Stop { .. }))
        );
        step(&mut o).unwrap();
        assert_eq!(o.activation(ordinal(8)), 0);
        assert_eq!(o.evaluated(ordinal(8)), 0);
        assert!(!o.started);
        let tail: Vec<_> = o.backend.calls[n..]
            .iter()
            .filter_map(|(_, e)| match e {
                Effect::Activation {
                    ordinal,
                    enable: false,
                    ..
                } => Some((ordinal.index(), 0)),
                Effect::Stop { ordinal, .. } => Some((ordinal.index(), 1)),
                _ => None,
            })
            .collect();
        assert_eq!(tail.len(), 37); //one refused activation plus18 kept pairs
        assert_eq!(tail[0], tail[1]);
        for (i, pair) in tail[1..].as_chunks::<2>().0.iter().enumerate() {
            assert_eq!(*pair, [(i, 0), (i, 1)]);
        }
    }
    #[test]
    fn actual_hook_products_feed_next_stage_and_absent_products_cannot_succeed() {
        let mut o = owner();
        selection(&mut o, 1 << 8);
        o.backend.hook_buffer = Some(7);
        let n = o.backend.calls.len();
        o.begin_cycle().unwrap();
        step(&mut o).unwrap();
        assert!(o.backend.calls[n..].iter().any(|(_,e)|matches!(e,Effect::Hook{hook:Hook::Postprocess,counters,..}if counters.buffer_index==7)));
        o.backend.bad_hook = true;
        o.begin_cycle().unwrap();
        assert!(matches!(
            step(&mut o),
            Err(Error::Contract(
                "native counter hook software products absent"
            ))
        ));
        assert!(o.begin_cycle().is_err());
        assert!(step(&mut o).is_err());
    }
    #[test]
    fn source_enable_and_configuration_are_policy_data_without_activation_authority() {
        let mut o = owner();
        o.apply_source_enable(ordinal(8), 5).unwrap();
        assert_eq!(o.activation(ordinal(8)), 0);
        assert_eq!(o.evaluated(ordinal(8)), 0);
        o.apply_configuration(ordinal(4), super::super::Configuration::Hysteresis(2))
            .unwrap();
        assert_eq!(o.profile.descriptors[4].hysteresis, 2);
        assert_eq!(
            super::super::Configuration::Hysteresis(0).source_offset(),
            0x260
        );
        o.apply_configuration(ordinal(4), super::super::Configuration::PeriodShift(32))
            .unwrap();
        assert_eq!(o.profile.descriptors[4].times(), (170, 7));
        selection(&mut o, 1 << 8);
        o.apply_source_enable(ordinal(8), 0).unwrap();
        o.begin_cycle().unwrap();
        assert!(o.apply_source_enable(ordinal(8), 1).is_err());
        step(&mut o).unwrap();
        assert_eq!(o.last_evaluation().unwrap().eligible, 0);
        assert_eq!(o.activation(ordinal(8)), 1);
    }
}
