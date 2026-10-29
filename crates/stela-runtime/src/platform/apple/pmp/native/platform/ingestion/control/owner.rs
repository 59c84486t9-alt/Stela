//! The auxiliary control owner. It holds the `SoftwareImage` and the
//! source-order cursor, and runs the control tail, lifecycle transitions,
//! auxiliary configuration and slot reset as kept operations that resume
//! after Busy.
use super::super::super::super::counters::{CaptureIdentity, Captured, Frames, Retained};
use super::super::super::owner::Completion;
use super::super::{Call, Error, Request, Value};
use super::model::{half, put_half, put_word, word};
use super::packed;
use super::{
    Caller, Configuration, FlagsMethod, Identity, Operation, ResourceRequest, ResourceValue,
    Resources, SoftwareImage,
};
use crate::platform::apple::ptd::transport::notifications::LocalNotifications;
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::Cell;
use stela_contracts::Refusal;
use stela_contracts::bus::Access;
use stela_contracts::refuse;

/// Identity of the actual101cff0 context allocation. Cloning carries
/// that identity, not permission to mark registration complete or set flags.
#[derive(Clone)]
pub struct AuxiliaryBinding {
    identity: Identity,
    slot: usize,
    source: u32,
    registered: Rc<Cell<bool>>,
}
impl AuxiliaryBinding {
    pub fn slot(&self) -> usize {
        self.slot
    }
    pub fn source(&self) -> u32 {
        self.source
    }
    pub fn registered(&self) -> bool {
        self.registered.get()
    }
    pub(in crate::platform::apple::pmp::native) fn same(&self, other: &Self) -> bool {
        self.identity.same(&other.identity)
            && self.slot == other.slot
            && self.source == other.source
            && Rc::ptr_eq(&self.registered, &other.registered)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Signature {
    Tail(Box<Call>, u32),
    Transition {
        slot: usize,
        mode: u32,
        activation: u32,
    },
    ConfigureAuxiliary {
        slot: usize,
        flags: u16,
        thresholds: u16,
        period: u32,
        activation: u32,
    },
}
#[derive(Clone, Copy)]
enum After {
    Registered(usize),
    Nothing,
    SavedFlags(usize, usize),
    Packed(usize),
    Member(usize, usize),
    ExtendedPacked(usize),
    ExtendedMember(usize, usize),
    Applied(usize, u16, bool),
}
#[derive(Clone)]
enum Step {
    ConfigureAuxiliary(usize, u16, u16, u32),
    Slot(usize),
    Transition(usize, u32),
    Mode(usize, u32),
    Save(usize, usize),
    ResetFlag(usize),
    Packed(usize),
    PackedValue(usize, u64, bool),
    Timer(usize),
    Member(usize, usize),
    ExtendedMember(usize, usize, u64),
    Correction(usize, usize, u32),
    FinishMembers(usize),
    Compare(usize),
    Apply(usize, usize, u16, bool),
    Resource(Operation, After),
}
struct Storage {
    retained: Retained,
    capture: CaptureIdentity,
}
struct Pending {
    caller: Caller,
    signature: Signature,
    sequence: u64,
    cursor: u64,
    activation: u32,
    storage: Option<Storage>,
    steps: VecDeque<Step>,
    scratch: u32,
    reduction: u32,
}
struct Completed {
    caller: Caller,
    signature: Signature,
}

/// Software control storage and source-order cursor. No method marks a
/// provider ready, installs a copied hardware image, consumes a second Frames
/// receipt, or acknowledges a native command. Registration/configuration
/// producers of member byte0, saved flags and timer limits remain separate.
/// The lifecycle operation a source call belongs to, and its step within
/// it: the activation path's reset and restore calls differ only here.
#[derive(Clone, Copy)]
pub struct SourceStep<'a> {
    pub request: &'a super::super::super::owner::Request,
    pub step: u64,
}

/// One auxiliary slot's source configuration operands.
#[derive(Clone, Copy)]
pub struct AuxiliaryConfiguration {
    pub slot: usize,
    pub flags: u16,
    pub thresholds: u16,
    pub period: u32,
    pub activation: u32,
}

pub struct Owner {
    configuration: Configuration,
    image: SoftwareImage,
    identity: Identity,
    auxiliary: [AuxiliaryBinding; 4],
    last_reset: [Option<super::super::super::super::interrupts::AuxiliaryReset>; 4],
    resources: Option<Identity>,
    local: Option<LocalNotifications>,
    sequence: u64,
    pending: Option<Pending>,
    completed: Option<Completed>,
    last_tail: Option<Request>,
    last_transition: Option<(super::super::super::owner::Request, u64)>,
    fault: Option<Refusal>,
}
impl Owner {
    pub fn initialized_software(
        configuration: Configuration,
        image: SoftwareImage,
    ) -> Result<Self, Error> {
        image.check(&configuration)?;
        let identity = Identity::new();
        let auxiliary = core::array::from_fn(|slot| AuxiliaryBinding {
            identity: identity.clone(),
            slot,
            source: configuration.rows[slot].words[1],
            registered: Rc::new(Cell::new(false)),
        });
        Ok(Self {
            configuration,
            image,
            identity,
            auxiliary,
            last_reset: core::array::from_fn(|_| None),
            resources: None,
            local: None,
            sequence: 0,
            pending: None,
            completed: None,
            last_tail: None,
            last_transition: None,
            fault: None,
        })
    }
    pub fn image(&self) -> &SoftwareImage {
        &self.image
    }
    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }
    pub fn pending_step(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| p.cursor)
    }
    pub fn refusal(&self) -> Option<&Refusal> {
        self.fault.as_ref()
    }

    /// Context identity only. The root may keep it in the registration
    /// resource closure before configure_auxiliary; it grants no admission.
    pub fn auxiliary_binding(&self, slot: usize) -> Result<AuxiliaryBinding, Error> {
        self.auxiliary
            .get(slot)
            .cloned()
            .ok_or(Error::Contract(refuse!(
                "auxiliary binding slot exceeds source geometry"
            )))
    }
    /// Read-only query; initial software flags alone cannot make this Some.
    pub fn registered_auxiliary(&self, slot: usize) -> Result<Option<AuxiliaryBinding>, Error> {
        let binding = self.auxiliary_binding(slot)?;
        Ok(binding.registered().then_some(binding))
    }
    /// Actual101d02c store, admitted only by a live same-allocation callback
    /// receipt produced AFTER that callback's disable retired. Replay returns
    /// its result without reasserting a flag already consumed later.
    pub fn reset_slot(
        &mut self,
        reset: &super::super::super::super::interrupts::AuxiliaryReset,
    ) -> Completion<()> {
        let slot = reset.slot();
        let Some(binding) = self.auxiliary.get(slot) else {
            return Completion::Refused(refuse!(
                "auxiliary reset slot exceeds actual control owner"
            ));
        };
        if let Err(reason) = reset.validate(binding) {
            return Completion::Refused(reason);
        }
        if let Some(previous) = &self.last_reset[slot] {
            match reset.after(previous) {
                Err(reason) => return Completion::Refused(reason),
                Ok(false) => {
                    return Completion::Retired {
                        value: (),
                        refusal: None,
                    };
                }
                Ok(true) => {}
            }
        }
        self.image.slots[slot].raw[0] = 1;
        self.last_reset[slot] = Some(reset.clone());
        Completion::Retired {
            value: (),
            refusal: None,
        }
    }

    /// Actual101ced0 configuration producer. Inputs are source software
    /// configuration, never measured readiness. The typed resource must keep
    /// callback registration before the source transition can advance.
    pub fn configure_auxiliary(
        &mut self,
        step: SourceStep<'_>,
        configuration: AuxiliaryConfiguration,
        resources: &mut impl Resources,
        access: &mut Access<'_>,
    ) -> Completion<Value> {
        let SourceStep {
            request,
            step: source_step,
        } = step;
        let AuxiliaryConfiguration {
            slot,
            flags,
            thresholds,
            period,
            activation,
        } = configuration;
        if slot >= 4 {
            return Completion::Refused(refuse!("auxiliary configuration exceeds source slots"));
        }
        let caller = Caller::Transition(request.clone(), source_step);
        let signature = Signature::ConfigureAuxiliary {
            slot,
            flags,
            thresholds,
            period,
            activation,
        };
        match self.resume(&caller, &signature, resources) {
            Err(error) => return Completion::Refused(reason(error)),
            Ok(true) => return retired(),
            Ok(false) => {}
        }
        if self.pending.is_none() {
            if let Some((last, step)) = &self.last_transition
                && (request.serial(), request.operation(), source_step)
                    <= (last.serial(), last.operation(), *step)
            {
                return Completion::Refused(refuse!(
                    "auxiliary configuration source cursor is stale"
                ));
            }
            if let Err(error) = self.begin(
                caller,
                signature,
                activation,
                None,
                Some(Step::ConfigureAuxiliary(slot, flags, thresholds, period)),
            ) {
                return Completion::Refused(reason(error));
            }
        }
        self.advance(None, resources, access)
    }

    /// Current manager capture and the outer ingestion's activation
    /// operand are required. CounterContext.activity is P10, not activation
    /// P294. The root caller must forward the same reached source operation.
    pub fn call(
        &mut self,
        request: &Request,
        call: &Call,
        frames: &Frames,
        captured: &Captured,
        resources: &mut impl Resources,
        access: &mut Access<'_>,
    ) -> Completion<Value> {
        let result = (|| {
            let Call::ControlTail {
                ordinal,
                descriptors,
                activation,
                ..
            } = call
            else {
                return Err(Error::Contract(refuse!(
                    "auxiliary owner received a foreign ingestion call"
                )));
            };
            if *ordinal != self.configuration.ordinal || descriptors != &self.configuration.rows {
                return Err(Error::Contract(refuse!(
                    "auxiliary call differs from retained complete source rows"
                )));
            }
            frames
                .check_bank(resources.notifications())
                .map_err(Error::Contract)?;
            let capture = frames.capture_identity(captured).map_err(Error::Contract)?;
            let caller = Caller::Tail(request.clone());
            let signature = Signature::Tail(Box::new(call.clone()), *activation);
            if self.resume(&caller, &signature, resources)? {
                return Ok(true);
            }
            if let Some(last) = &self.last_tail
                && (!Rc::ptr_eq(&last.owner, &request.owner)
                    || (request.serial, request.cursor) <= (last.serial, last.cursor))
            {
                return Err(Error::Contract(refuse!(
                    "auxiliary ingestion caller is foreign or stale"
                )));
            }
            // This is a read-only view, never another bulk copy or consume.
            let retained = frames
                .retain_cells(ordinal.index() as u32)
                .map_err(Error::Contract)?;
            frames.retained_cells(&retained).map_err(Error::Contract)?;
            let layout = retained.layout();
            if self
                .configuration
                .slice
                .is_some_and(|slice| slice.start != layout.start || slice.count != layout.count)
                || (self.configuration.slice.is_none() && layout.count != 0)
            {
                return Err(Error::Contract(refuse!(
                    "auxiliary retained storage differs from source descriptor geometry"
                )));
            }
            self.begin(
                caller,
                signature,
                *activation,
                Some(Storage { retained, capture }),
                if self.image.flags & 4 != 0 {
                    Some(Step::Slot(0))
                } else {
                    None
                },
            )?;
            Ok(false)
        })();
        match result {
            Err(e) => Completion::Refused(reason(e)),
            Ok(true) => retired(),
            Ok(false) => self.advance(Some(frames), resources, access),
        }
    }

    /// One actual101bb08 call within a lifecycle operation. Source
    /// step distinguishes the activation path's reset/restore invocations;
    /// it is an operation cursor, never a native address or completion flag.
    /// Modes0/1/2 change only the source software/controller effects.
    pub fn transition(
        &mut self,
        step: SourceStep<'_>,
        slot: usize,
        mode: u32,
        activation: u32,
        resources: &mut impl Resources,
        access: &mut Access<'_>,
    ) -> Completion<Value> {
        let SourceStep {
            request,
            step: source_step,
        } = step;
        let result = (|| {
            if slot >= 4 || mode > 2 {
                return Err(Error::Contract(refuse!(
                    "auxiliary transition exceeds source slots or modes"
                )));
            }
            let caller = Caller::Transition(request.clone(), source_step);
            let signature = Signature::Transition {
                slot,
                mode,
                activation,
            };
            if self.resume(&caller, &signature, resources)? {
                return Ok(true);
            }
            if let Some((last, step)) = &self.last_transition
                && (request.serial(), request.operation(), source_step)
                    <= (last.serial(), last.operation(), *step)
            {
                return Err(Error::Contract(refuse!(
                    "auxiliary lifecycle transition is stale or already retired"
                )));
            }
            self.begin(
                caller,
                signature,
                activation,
                None,
                Some(Step::Transition(slot, mode)),
            )?;
            Ok(false)
        })();
        match result {
            Err(e) => Completion::Refused(reason(e)),
            Ok(true) => retired(),
            Ok(false) => self.advance(None, resources, access),
        }
    }
    fn resume(
        &self,
        caller: &Caller,
        signature: &Signature,
        resources: &impl Resources,
    ) -> Result<bool, Error> {
        if let Some(reason) = self.fault.clone() {
            return Err(Error::Refused(reason));
        }
        if self
            .resources
            .as_ref()
            .is_some_and(|id| !id.same(resources.identity()))
            || self
                .local
                .as_ref()
                .is_some_and(|local| !local.owns(resources.notifications().bank()))
        {
            return Err(Error::Contract(refuse!(
                "auxiliary actual resource owners were replaced"
            )));
        }
        if let Some(p) = &self.pending {
            if !p.caller.same(caller) || &p.signature != signature {
                return Err(Error::Contract(refuse!(
                    "auxiliary retained source operation cannot be replaced"
                )));
            }
        } else if let Some(done) = &self.completed
            && done.caller.same(caller)
        {
            if &done.signature != signature {
                return Err(Error::Contract(refuse!(
                    "auxiliary retired operation changed its operands"
                )));
            }
            return Ok(true);
        }
        Ok(false)
    }
    fn begin(
        &mut self,
        caller: Caller,
        signature: Signature,
        activation: u32,
        storage: Option<Storage>,
        first: Option<Step>,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Ok(());
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::Contract(refuse!(
            "auxiliary operation sequence exhausted"
        )))?;
        self.sequence = sequence;
        self.pending = Some(Pending {
            caller,
            signature,
            sequence,
            cursor: 0,
            activation,
            storage,
            steps: first.into_iter().collect(),
            scratch: self.image.scratch,
            reduction: 0x4000,
        });
        Ok(())
    }
    fn prepend(&mut self, steps: impl IntoIterator<Item = Step>) {
        let steps: Vec<_> = steps.into_iter().collect();
        for step in steps.into_iter().rev() {
            self.pending.as_mut().unwrap().steps.push_front(step);
        }
    }
    fn cells<'a>(
        &self,
        frames: &'a Frames,
    ) -> Result<&'a [super::super::super::super::counters::Frame], Error> {
        let storage = self
            .pending
            .as_ref()
            .and_then(|p| p.storage.as_ref())
            .ok_or(Error::Contract(refuse!(
                "auxiliary local field has no actual retained storage"
            )))?;
        frames
            .retained_cells(&storage.retained)
            .map_err(Error::Contract)
    }
    fn advance(
        &mut self,
        frames: Option<&Frames>,
        resources: &mut impl Resources,
        access: &mut Access<'_>,
    ) -> Completion<Value> {
        if self.resources.is_none() {
            self.resources = Some(resources.identity().clone());
            self.local = Some(resources.notifications().clone());
        }
        loop {
            let validation = (|| {
                let p = self.pending.as_ref().unwrap();
                if let Some(storage) = &p.storage {
                    let frames = frames.ok_or(Error::Contract(refuse!(
                        "auxiliary Frames borrow is absent"
                    )))?;
                    frames
                        .validate_capture_identity(&storage.capture)
                        .map_err(Error::Contract)?;
                    frames
                        .retained_cells(&storage.retained)
                        .map_err(Error::Contract)?;
                }
                p.cursor
                    .checked_add(1)
                    .ok_or(Error::Contract(refuse!("auxiliary inner cursor exhausted")))
            })();
            let next = match validation {
                Ok(n) => n,
                Err(e) => return Completion::Refused(reason(e)),
            };
            let Some(step) = self.pending.as_ref().unwrap().steps.front().cloned() else {
                let p = self.pending.take().unwrap();
                match &p.caller {
                    Caller::Tail(request) => self.last_tail = Some(request.clone()),
                    Caller::Transition(request, step) => {
                        self.last_transition = Some((request.clone(), *step))
                    }
                }
                self.completed = Some(Completed {
                    caller: p.caller,
                    signature: p.signature,
                });
                return retired();
            };
            if let Step::Resource(operation, after) = step {
                let p = self.pending.as_ref().unwrap();
                let request = ResourceRequest {
                    identity: self.identity.clone(),
                    sequence: p.sequence,
                    step: p.cursor,
                };
                match resources.call(&request, operation, access) {
                    Completion::Busy { deadline } => return Completion::Busy { deadline },
                    Completion::Refused(reason) => return Completion::Refused(reason),
                    Completion::Retired { value, refusal } => {
                        self.pending.as_mut().unwrap().steps.pop_front();
                        self.pending.as_mut().unwrap().cursor = next;
                        if let Err(e) = self.after(after, value) {
                            let text = reason(e);
                            self.fault = Some(text.clone()); // The call already retired; never replay it.
                            return Completion::Refused(text);
                        }
                        if let Some(reason) = refusal {
                            return Completion::Refused(reason);
                        }
                    }
                }
            } else {
                // Plan/check before removing this step. No failed local lookup
                // may silently skip a required source field or provider.
                match self.software(step, frames) {
                    Ok(steps) => {
                        self.pending.as_mut().unwrap().steps.pop_front();
                        self.pending.as_mut().unwrap().cursor = next;
                        self.prepend(steps);
                    }
                    Err(e) => return Completion::Refused(reason(e)),
                }
            }
        }
    }
    fn after(&mut self, after: After, value: ResourceValue) -> Result<(), Error> {
        match (after, value) {
            (After::Registered(slot), ResourceValue::Complete) => {
                self.auxiliary[slot].registered.set(true)
            }
            (After::Nothing, ResourceValue::Complete) => {}
            (After::SavedFlags(slot, member), ResourceValue::Word(value)) => {
                self.image.slots[slot].members[member][20] = value as u8 & 1;
                self.image.slots[slot].members[member][21] = (value >> 8) as u8 & 1;
                self.prepend([Step::Resource(
                    Operation::Flags {
                        provider: self.configuration.rows[slot].words[0],
                        member: member as u32,
                        method: FlagsMethod::Store58,
                        value: 0x101,
                    },
                    After::Nothing,
                )]);
            }
            (After::Packed(slot), ResourceValue::Word(value)) => {
                let offset = self.configuration.rows[slot].words[6] as u16;
                let old = word(&self.image.slots[slot].raw, 12);
                put_word(
                    &mut self.image.slots[slot].raw,
                    12,
                    packed::mapped(old, value, offset),
                );
            }
            (After::Member(slot, member), ResourceValue::Word(value)) => {
                let offset = self.configuration.rows[slot].members[member][4] as u16;
                put_half(
                    &mut self.image.slots[slot].members[member],
                    16,
                    packed::member_word(value, offset),
                );
            }
            (After::ExtendedPacked(slot), ResourceValue::Pair(pair)) => {
                self.prepend([Step::PackedValue(slot, pair.value, true)]);
            }
            (After::ExtendedMember(slot, member), ResourceValue::Pair(pair)) => {
                self.prepend([Step::ExtendedMember(slot, member, pair.value)]);
            }
            (After::Applied(slot, mask, enable), ResourceValue::Complete) => {
                let members = &mut self.image.slots[slot].members;
                let mut any = 0;
                for member in members {
                    for (i, flag) in member[1..3].iter_mut().enumerate() {
                        if mask & (1 << (8 * i)) != 0 {
                            *flag = u8::from(enable);
                        }
                        any |= *flag;
                    }
                }
                if (any & 1 != 0) == enable {
                    self.prepend([Step::Resource(
                        Operation::Signal {
                            source: self.configuration.rows[slot].words[1],
                            enable,
                        },
                        After::Nothing,
                    )]);
                }
            }
            _ => {
                return Err(Error::Contract(refuse!(
                    "auxiliary actual resource result shape mismatch"
                )));
            }
        }
        Ok(())
    }
    fn software(&mut self, step: Step, frames: Option<&Frames>) -> Result<Vec<Step>, Error> {
        let mut out = Vec::new();
        match step {
            Step::ConfigureAuxiliary(slot, flags, thresholds, period) => {
                let state = &mut self.image.slots[slot];
                if period != 0 {
                    state.timer[2] = period;
                }
                for (member, raw) in state
                    .members
                    .iter_mut()
                    .zip(&self.configuration.rows[slot].members)
                {
                    if raw[0] != 0 {
                        member[..5].copy_from_slice(&[1, 0, 0, 0, 0]);
                    }
                }
                for i in 0..2 {
                    state.raw[1 + i] |= (flags >> (8 * i)) as u8;
                    state.raw[3 + i] |= (thresholds >> (8 * i)) as u8;
                }
                if state.raw[1] | state.raw[2] != 0 {
                    // Raw native pointer bytes remain provenance only; the
                    // context is the same-owner AuxiliaryBinding.
                    put_word(&mut state.raw, 24, slot as u32);
                    out.push(Step::Resource(
                        Operation::RegisterAuxiliary {
                            slot,
                            source: self.configuration.rows[slot].words[1],
                        },
                        After::Registered(slot),
                    ));
                    if self.pending.as_ref().unwrap().activation == 1 {
                        out.push(Step::Transition(slot, 0));
                    }
                }
            }
            Step::Slot(slot) if slot < 4 => {
                if self.image.slots[slot].raw[0] == 1 {
                    out.extend([
                        Step::Transition(slot, 1),
                        Step::Save(slot, 0),
                        Step::ResetFlag(slot),
                    ]);
                }
                out.extend([Step::Packed(slot), Step::Timer(slot), Step::Slot(slot + 1)]);
            }
            Step::Slot(_) => {}
            Step::Transition(slot, mode) => {
                if word(&self.image.slots[slot].raw, 8) != mode {
                    let s = &mut self.image.slots[slot];
                    if mode == 0 || mode == 2 {
                        for member in &mut s.members {
                            put_half(member, 16, 0);
                        }
                        s.timer[0] = 0;
                        s.timer[1] = 0;
                    } else {
                        s.timer[0] = s.timer[2];
                        s.timer[1] = s.timer[2];
                    }
                    let base = if mode == 1 { 3 } else { 1 };
                    for member in &mut s.members {
                        member[3] = s.raw[base];
                        member[4] = s.raw[base + 1];
                    }
                    if self.pending.as_ref().unwrap().activation == 1 {
                        if mode == 0 {
                            let mask = u16::from(s.raw[1]) | (u16::from(s.raw[2]) << 8);
                            out.push(Step::Apply(slot, 0, mask, false));
                        } else {
                            out.push(Step::Compare(slot));
                        }
                    }
                    out.push(Step::Mode(slot, mode));
                }
            }
            Step::Mode(slot, mode) => put_word(&mut self.image.slots[slot].raw, 8, mode),
            Step::Save(slot, member) => {
                let row = &self.configuration.rows[slot];
                if member < row.members.len() {
                    if row.members[member][0] == 1 {
                        out.push(Step::Resource(
                            Operation::Flags70 {
                                provider: row.words[0],
                                member: member as u32,
                            },
                            After::SavedFlags(slot, member),
                        ));
                    }
                    out.push(Step::Save(slot, member + 1));
                }
            }
            Step::ResetFlag(slot) => self.image.slots[slot].raw[0] = 0,
            Step::Packed(slot) => {
                let r = &self.configuration.rows[slot].words;
                match r[2] {
                    0 => {}
                    1 => out.push(Step::Resource(
                        Operation::Packed400 { provider: r[0] },
                        After::Packed(slot),
                    )),
                    2 if r[3] == 4 => out.push(Step::Resource(
                        Operation::ExtendedFrame {
                            bank: 2,
                            index: r[4] >> 6,
                        },
                        After::ExtendedPacked(slot),
                    )),
                    2 => {
                        let frames = frames.ok_or(Error::Contract(refuse!(
                            "auxiliary local Frames borrow absent"
                        )))?;
                        let value = self
                            .cells(frames)?
                            .get((r[4] >> 6) as usize)
                            .ok_or(Error::Contract(refuse!(
                                "auxiliary local packed field exceeds actual retained cells"
                            )))?
                            .value;
                        out.push(Step::PackedValue(slot, value, false));
                    }
                    _ => {
                        return Err(Error::Refused(refuse!(
                            "auxiliary packed source kind is unqualified"
                        )));
                    }
                }
            }
            Step::PackedValue(slot, value, extended) => {
                let r = &self.configuration.rows[slot].words;
                let raw = packed::local_field(value, r[4], r[5]);
                let p = self.pending.as_mut().unwrap();
                let (scratch, value) = packed::local(p.scratch, raw, r[5], extended, r[6] as u16);
                p.scratch = scratch;
                put_word(&mut self.image.slots[slot].raw, 12, value);
            }
            Step::Timer(slot) => {
                let timer = &mut self.image.slots[slot].timer;
                if timer[1] != 0 {
                    timer[0] = timer[0].wrapping_add(1);
                    if timer[0] >= timer[1] {
                        self.pending.as_mut().unwrap().reduction = 0x4000;
                        out.extend([Step::Member(slot, 0), Step::FinishMembers(slot)]);
                    }
                }
            }
            Step::Member(slot, member) => {
                let r = &self.configuration.rows[slot];
                if member < r.members.len() {
                    match r.members[member][0] {
                        0 => {}
                        1 => out.push(Step::Resource(
                            Operation::Member28 {
                                provider: r.words[0],
                                member: member as u32,
                            },
                            After::Member(slot, member),
                        )),
                        2 => out.push(Step::Resource(
                            Operation::ExtendedFrame {
                                bank: 2,
                                index: r.members[member][2] >> 6,
                            },
                            After::ExtendedMember(slot, member),
                        )),
                        _ => {
                            return Err(Error::Refused(refuse!(
                                "auxiliary member class is unqualified"
                            )));
                        }
                    }
                    out.push(Step::Member(slot, member + 1));
                }
            }
            Step::ExtendedMember(slot, member, value) => {
                let row = self.configuration.rows[slot].members[member];
                let value = packed::extended_field(value, row[2], row[3]);
                let target = &mut self.image.slots[slot].members[member];
                let old = half(target, 18);
                put_half(target, 16, value as u16);
                put_half(target, 18, (value as u16 & !0x7fff) | (old & 0x7fff));
                if value & 0x8000 != 0 {
                    out.push(Step::Correction(slot, member, value));
                }
            }
            Step::Correction(slot, member, raw) => {
                let r = &self.configuration.rows[slot];
                if r.words[10] != 0 || r.words[11] != 0 {
                    return Err(Error::Refused(refuse!(
                        "auxiliary correction list requires actual paired scalar owners"
                    )));
                }
                let value =
                    (raw as u16 as i16 as i32).wrapping_add(i32::from(r.members[member][4] as u16));
                let signed = packed::signed15(value as u32);
                let target = &mut self.image.slots[slot].members[member];
                put_half(target, 18, value as u16 | 0x8000);
                let limits = [word(target, 8), word(target, 12)];
                target[20] = packed::threshold(signed, limits[0]);
                target[21] = packed::threshold(signed, limits[1]);
                let p = self.pending.as_mut().unwrap();
                let max = packed::signed15(p.reduction).max(signed);
                p.reduction = 0x10_0000 | u32::from(max as u16);
            }
            Step::FinishMembers(slot) => {
                self.image.slots[slot].timer[0] = 0;
                let reduction = self.pending.as_ref().unwrap().reduction;
                if reduction & 0x10_0000 != 0 {
                    let target = &mut self.image.slots[slot].raw;
                    let value = (word(target, 12) & 0xffef_8000) | (reduction & 0x10_7fff);
                    put_word(target, 12, value);
                }
            }
            Step::Compare(slot) => {
                let mut enable = 0u16;
                let mut disable = 0u16;
                for (raw, member) in self.configuration.rows[slot]
                    .members
                    .iter()
                    .zip(&self.image.slots[slot].members)
                {
                    if raw[0] == 0 {
                        continue;
                    }
                    for i in 0..2 {
                        if member[1 + i] & 1 == 0 && member[3 + i] & 1 != 0 {
                            enable |= 1 << (8 * i);
                        }
                        if member[1 + i] & 1 != 0 && member[3 + i] & 1 == 0 {
                            disable |= 1 << (8 * i);
                        }
                    }
                }
                if enable != 0 {
                    out.push(Step::Apply(slot, 0, enable, true));
                }
                if disable != 0 {
                    out.push(Step::Apply(slot, 0, disable, false));
                }
            }
            Step::Apply(slot, member, mask, enable) => {
                let r = &self.configuration.rows[slot];
                if member < r.members.len() {
                    if r.members[member][0] != 0 && self.image.slots[slot].members[member][0] == 1 {
                        if mask & 0x101 != 0 {
                            out.push(Step::Resource(
                                Operation::Flags {
                                    provider: r.words[0],
                                    member: member as u32,
                                    value: mask,
                                    method: if enable {
                                        FlagsMethod::Enable60
                                    } else {
                                        FlagsMethod::Disable68
                                    },
                                },
                                After::Applied(slot, mask, enable),
                            ));
                        } else {
                            // Even a zero mask still reaches source fanout/signal evaluation.
                            let any = self.image.slots[slot]
                                .members
                                .iter()
                                .fold(0, |v, m| v | m[1] | m[2]);
                            if (any & 1 != 0) == enable {
                                out.push(Step::Resource(
                                    Operation::Signal {
                                        source: r.words[1],
                                        enable,
                                    },
                                    After::Nothing,
                                ));
                            }
                        }
                    }
                    out.push(Step::Apply(slot, member + 1, mask, enable));
                }
            }
            Step::Resource(..) => unreachable!(),
        }
        Ok(out)
    }
}
fn reason(error: Error) -> Refusal {
    match error {
        Error::Contract(reason) | Error::Refused(reason) => reason,
    }
}
fn retired() -> Completion<Value> {
    Completion::Retired {
        value: Value::Complete,
        refusal: None,
    }
}

#[cfg(test)]
mod tests;
