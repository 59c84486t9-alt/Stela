//! The auxiliary control owner. It holds the `SoftwareImage` and the
//! source-order cursor, and runs the control tail, lifecycle transitions,
//! auxiliary configuration and slot reset as retained operations that resume
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
use crate::platform::apple::bus::Access;
use crate::platform::apple::ptd::transport::notifications::LocalNotifications;
use alloc::{boxed::Box, collections::VecDeque, rc::Rc, vec::Vec};
use core::cell::Cell;

/// Retained identity of the actual101cff0 context allocation. Cloning carries
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

/// Actual software control storage and source-order cursor. No method marks a
/// provider ready, installs a copied hardware image, consumes a second Frames
/// receipt, or acknowledges a native command. Registration/configuration
/// producers of member byte0, saved flags and timer limits remain separate.
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
    fault: Option<&'static str>,
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
    pub fn refusal(&self) -> Option<&'static str> {
        self.fault
    }

    /// Context identity only. The root may retain it in the actual registration
    /// resource closure before configure_auxiliary; it grants no admission.
    pub fn auxiliary_binding(&self, slot: usize) -> Result<AuxiliaryBinding, Error> {
        self.auxiliary.get(slot).cloned().ok_or(Error::Contract(
            "auxiliary binding slot exceeds source geometry",
        ))
    }
    /// Read-only query; initial software flags alone cannot make this Some.
    pub fn registered_auxiliary(&self, slot: usize) -> Result<Option<AuxiliaryBinding>, Error> {
        let binding = self.auxiliary_binding(slot)?;
        Ok(binding.registered().then_some(binding))
    }
    /// Actual101d02c store, admitted only by a live same-allocation callback
    /// receipt produced AFTER that callback's disable retired. Replay returns
    /// its retained result without reasserting a flag already consumed later.
    pub fn reset_slot(
        &mut self,
        reset: &super::super::super::super::interrupts::AuxiliaryReset,
    ) -> Completion<()> {
        let slot = reset.slot();
        let Some(binding) = self.auxiliary.get(slot) else {
            return Completion::Refused("auxiliary reset slot exceeds actual control owner");
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
    /// configuration, never measured readiness. The typed resource must retain
    /// actual callback registration before the source transition can advance.
    #[allow(clippy::too_many_arguments)]
    pub fn configure_auxiliary(
        &mut self,
        request: &super::super::super::owner::Request,
        source_step: u64,
        slot: usize,
        flags: u16,
        thresholds: u16,
        period: u32,
        activation: u32,
        resources: &mut impl Resources,
        access: &mut Access<'_>,
    ) -> Completion<Value> {
        if slot >= 4 {
            return Completion::Refused("auxiliary configuration exceeds source slots");
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
                return Completion::Refused("auxiliary configuration source cursor is stale");
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

    /// Actual current manager capture and the outer ingestion's activation
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
                return Err(Error::Contract(
                    "auxiliary owner received a foreign ingestion call",
                ));
            };
            if *ordinal != self.configuration.ordinal || descriptors != &self.configuration.rows {
                return Err(Error::Contract(
                    "auxiliary call differs from retained complete source rows",
                ));
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
                return Err(Error::Contract(
                    "auxiliary ingestion caller is foreign or stale",
                ));
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
                return Err(Error::Contract(
                    "auxiliary retained storage differs from source descriptor geometry",
                ));
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

    /// One actual101bb08 call within a retained lifecycle operation. Source
    /// step distinguishes the activation path's reset/restore invocations;
    /// it is an operation cursor, never a native address or completion flag.
    /// Modes0/1/2 change only the actual source software/controller effects.
    // Keep source operands separate from the retained caller cursor and actual
    // resource/access owners so this boundary mirrors one source invocation.
    #[allow(clippy::too_many_arguments)]
    pub fn transition(
        &mut self,
        request: &super::super::super::owner::Request,
        source_step: u64,
        slot: usize,
        mode: u32,
        activation: u32,
        resources: &mut impl Resources,
        access: &mut Access<'_>,
    ) -> Completion<Value> {
        let result = (|| {
            if slot >= 4 || mode > 2 {
                return Err(Error::Contract(
                    "auxiliary transition exceeds source slots or modes",
                ));
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
                return Err(Error::Contract(
                    "auxiliary lifecycle transition is stale or already retired",
                ));
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
        if let Some(reason) = self.fault {
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
            return Err(Error::Contract(
                "auxiliary actual resource owners were replaced",
            ));
        }
        if let Some(p) = &self.pending {
            if !p.caller.same(caller) || &p.signature != signature {
                return Err(Error::Contract(
                    "auxiliary retained source operation cannot be replaced",
                ));
            }
        } else if let Some(done) = &self.completed
            && done.caller.same(caller)
        {
            if &done.signature != signature {
                return Err(Error::Contract(
                    "auxiliary retired operation changed its operands",
                ));
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
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Contract("auxiliary operation sequence exhausted"))?;
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
            .ok_or(Error::Contract(
                "auxiliary local field has no actual retained storage",
            ))?;
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
                    let frames =
                        frames.ok_or(Error::Contract("auxiliary Frames borrow is absent"))?;
                    frames
                        .validate_capture_identity(&storage.capture)
                        .map_err(Error::Contract)?;
                    frames
                        .retained_cells(&storage.retained)
                        .map_err(Error::Contract)?;
                }
                p.cursor
                    .checked_add(1)
                    .ok_or(Error::Contract("auxiliary inner cursor exhausted"))
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
                            self.fault = Some(text); // The actual call already retired; never replay it.
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
                return Err(Error::Contract(
                    "auxiliary actual resource result shape mismatch",
                ));
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
                    // actual context is the same-owner AuxiliaryBinding.
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
                        let frames = frames
                            .ok_or(Error::Contract("auxiliary local Frames borrow absent"))?;
                        let value = self
                            .cells(frames)?
                            .get((r[4] >> 6) as usize)
                            .ok_or(Error::Contract(
                                "auxiliary local packed field exceeds actual retained cells",
                            ))?
                            .value;
                        out.push(Step::PackedValue(slot, value, false));
                    }
                    _ => {
                        return Err(Error::Refused(
                            "auxiliary packed source kind is unqualified",
                        ));
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
                        _ => return Err(Error::Refused("auxiliary member class is unqualified")),
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
                    return Err(Error::Refused(
                        "auxiliary correction list requires actual paired scalar owners",
                    ));
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
fn reason(error: Error) -> &'static str {
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
mod tests {
    use super::super::super::super::super::{
        Packets,
        counters::{Claim, CopyStep},
        power::DeviceTable,
    };
    use super::super::super::{Auxiliary, Pair};
    use super::*;
    use crate::platform::apple::{
        bus::{LifecycleState, MmioDevice, Width},
        interrupt::InterruptLatch,
        ptd::{
            Geometry, Ptd, Range, UPDATE_OFFSET,
            transport::notifications::{LocalNotifications, NativeProfile},
        },
    };
    use alloc::{vec, vec::Vec};
    use core::cell::Cell;

    fn descriptor(ordinal: usize) -> super::super::super::Descriptor {
        super::super::super::super::profile::tests::fixture().descriptors()[ordinal].clone()
    }
    fn request(serial: u64) -> Request {
        Request {
            owner: Rc::new(()),
            serial,
            cursor: 17,
        }
    }
    fn call(configuration: &Configuration) -> Call {
        Call::ControlTail {
            ordinal: configuration.ordinal,
            context: super::super::super::super::owner::CounterContext {
                selected: 8,
                evaluation_tick: 100,
                current_packet: Packets([0; 6]),
                activity: 1,
                buffer_index: 1,
                state_index: 0,
                previous_state_index: 0,
                evaluated: 1,
                pending: 0,
            },
            descriptors: configuration.rows.clone(),
            activation: 0,
        }
    }
    fn setup() -> (Frames, LocalNotifications, InterruptLatch) {
        let range = Range {
            id: 9,
            start: 16,
            count: 144,
            name: "authored source frames".into(),
        };
        let extra = Range {
            id: 30,
            start: 200,
            count: 8,
            name: "authored shared bank2".into(),
        };
        let live = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let (_, local) = Ptd::initialized_local_profile(
            NativeProfile::T8112,
            Geometry::new((0x23b3c0000, 0x20000), (0x23b3d0000, 0x4000)).unwrap(),
            &[range.clone(), extra],
            live,
        )
        .unwrap();
        let ids = [
            1, 2, 16, 17, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 18,
        ];
        let counts = [0, 14, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let bytes: Vec<_> = ids
            .into_iter()
            .zip(counts)
            .flat_map(|(id, count)| {
                let mut words = [0u32; 31];
                words[0] = id;
                words[3] = count;
                words.into_iter().flat_map(u32::to_le_bytes)
            })
            .collect();
        let table = DeviceTable::from_properties(&bytes, &[0; 8], None).unwrap();
        let frames = Frames::initialized(
            Claim::new(local.clone(), range, Rc::new(Cell::new(true))),
            &table,
            &[0xa5; 144],
        )
        .unwrap();
        (frames, local, InterruptLatch::new())
    }
    fn publish(local: &LocalNotifications, entry: u32, value: u64, latch: &mut InterruptLatch) {
        local
            .bank()
            .clone()
            .write(
                UPDATE_OFFSET + u64::from(entry) * 8,
                Width::Double,
                value,
                &mut Access::new(0, 101, latch),
            )
            .unwrap();
    }
    fn capture(
        frames: &mut Frames,
        local: &LocalNotifications,
        ordinal: u32,
        value: u64,
        latch: &mut InterruptLatch,
    ) -> Captured {
        publish(
            local,
            frames.layout(ordinal).unwrap().start + 3,
            value,
            latch,
        );
        let captured = frames.capture_pending(&Access::new(0, 102, latch)).unwrap();
        frames.begin_copy(&captured, ordinal, u128::MAX).unwrap();
        while frames.step(&mut Access::new(0, 103, latch)).unwrap() != CopyStep::Complete {}
        let _actual_copy = frames.finish_copy().unwrap();
        captured
    }
    struct Actual {
        identity: Identity,
        local: LocalNotifications,
        calls: Vec<(ResourceRequest, Operation)>,
        busy: bool,
        retired_error: bool,
        malformed: bool,
        cache: [Option<Pair>; 8],
        consumes: u32,
    }
    impl Actual {
        fn new(local: LocalNotifications) -> Self {
            Self {
                identity: Identity::new(),
                local,
                calls: Vec::new(),
                busy: false,
                retired_error: false,
                malformed: false,
                cache: [None; 8],
                consumes: 0,
            }
        }
    }
    impl Resources for Actual {
        fn identity(&self) -> &Identity {
            &self.identity
        }
        fn notifications(&self) -> &LocalNotifications {
            &self.local
        }
        fn call(
            &mut self,
            request: &ResourceRequest,
            operation: Operation,
            access: &mut Access<'_>,
        ) -> Completion<ResourceValue> {
            self.calls.push((request.clone(), operation));
            if core::mem::take(&mut self.busy) {
                return Completion::Busy {
                    deadline: Some(200),
                };
            }
            let value = if self.malformed {
                ResourceValue::Pair(Pair::default())
            } else {
                match operation {
                    Operation::Flags70 { .. } => ResourceValue::Word(0x101),
                    Operation::Member28 { .. } => ResourceValue::Word(0x8000_ffff),
                    Operation::Packed400 { .. } => ResourceValue::Word(0x800a_7ffe),
                    Operation::ExtendedFrame { bank, index } => {
                        assert_eq!(bank, 2);
                        let slot = &mut self.cache[index as usize];
                        if slot.is_none() {
                            let entry = self
                                .local
                                .bank()
                                .consume_entry(200 + index, access)
                                .unwrap();
                            *slot = Some(Pair {
                                value: entry.value,
                                tick: entry.metadata >> 10,
                            });
                            self.consumes += 1;
                        }
                        ResourceValue::Pair(slot.unwrap())
                    }
                    _ => ResourceValue::Complete,
                }
            };
            Completion::Retired {
                value,
                refusal: if core::mem::take(&mut self.retired_error) {
                    Some("authored retirement with refusal")
                } else {
                    None
                },
            }
        }
    }
    fn invoke(
        owner: &mut Owner,
        request: &Request,
        call: &Call,
        frames: &Frames,
        captured: &Captured,
        resources: &mut Actual,
        latch: &mut InterruptLatch,
    ) -> Completion<Value> {
        owner.call(
            request,
            call,
            frames,
            captured,
            resources,
            &mut Access::new(0, 104, latch),
        )
    }
    fn complete(result: Completion<Value>) {
        assert_eq!(
            result,
            Completion::Retired {
                value: Value::Complete,
                refusal: None
            }
        );
    }
    #[test]
    fn selected_t8112_local_tails_preserve_actual_frames_without_another_consume() {
        for ordinal in 4..=7 {
            let (mut frames, local, mut latch) = setup();
            let captured = capture(
                &mut frames,
                &local,
                ordinal,
                0x8aa3_8bb2_8cc1_8dd0,
                &mut latch,
            );
            let configuration = Configuration::t8112(&descriptor(ordinal as usize)).unwrap();
            let input = call(&configuration);
            let mut owner = Owner::initialized_software(
                configuration.clone(),
                SoftwareImage::zeroed(&configuration),
            )
            .unwrap();
            let mut resources = Actual::new(local);
            let before = frames.progress();
            let req = request(1);
            complete(invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch,
            ));
            assert_eq!(word(&owner.image.slots[0].raw, 12), 0x0010_0dd0);
            if ordinal == 5 {
                assert_eq!(word(&owner.image.slots[1].raw, 12), 0x0011_0cc0);
                assert_eq!(word(&owner.image.slots[2].raw, 12), 0x0012_0bb0);
            }
            assert!(resources.calls.is_empty()); // Timer limits are explicit software0, not hardware readiness.
            assert_eq!(frames.progress(), before);
            complete(invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch,
            ));
            assert_eq!(frames.progress(), before);
        }
    }
    #[test]
    fn retired_member_flag_read_is_not_replayed_before_masked_write_and_period_read() {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(&mut frames, &local, 4, 0x8ab3, &mut latch);
        let configuration = Configuration::t8112(&descriptor(4)).unwrap();
        let input = call(&configuration);
        let mut image = SoftwareImage::zeroed(&configuration);
        image.slots[0].raw[0] = 1;
        image.slots[0].timer[2] = 1;
        let mut owner = Owner::initialized_software(configuration, image).unwrap();
        let mut resources = Actual::new(local);
        resources.retired_error = true;
        let req = request(1);
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch
            ),
            Completion::Refused(_)
        ));
        assert_eq!(resources.calls.len(), 1);
        assert_eq!(
            resources.calls[0].1,
            Operation::Flags70 {
                provider: 0,
                member: 8
            }
        );
        assert_eq!(owner.image.slots[0].members[8][20..22], [1, 1]);
        complete(invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch,
        ));
        assert_eq!(
            resources
                .calls
                .iter()
                .map(|(_, op)| *op)
                .collect::<Vec<_>>(),
            vec![
                Operation::Flags70 {
                    provider: 0,
                    member: 8
                },
                Operation::Flags {
                    provider: 0,
                    member: 8,
                    method: FlagsMethod::Store58,
                    value: 0x101
                },
                Operation::Member28 {
                    provider: 0,
                    member: 8
                },
            ]
        );
        assert_eq!(owner.image.slots[0].raw[0], 0);
        assert_eq!(word(&owner.image.slots[0].raw, 8), 1);
        assert_eq!(half(&owner.image.slots[0].members[8], 16), 0xffff);
        assert_eq!(owner.image.slots[0].timer, [0, 1, 1]);
    }
    #[test]
    fn busy_keeps_identity_and_rejects_new_capture_foreign_bank_or_changed_call() {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(&mut frames, &local, 4, 0x8ab3, &mut latch);
        let cfg = Configuration::t8112(&descriptor(4)).unwrap();
        let input = call(&cfg);
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[0].raw[0] = 1;
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local.clone());
        resources.busy = true;
        let req = request(1);
        assert_eq!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch
            ),
            Completion::Busy {
                deadline: Some(200)
            }
        );
        let first = resources.calls[0].0.clone();
        let mut changed = input.clone();
        if let Call::ControlTail { context, .. } = &mut changed {
            context.activity = 0;
        }
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &changed,
                &frames,
                &captured,
                &mut resources,
                &mut latch
            ),
            Completion::Refused(_)
        ));
        assert_eq!(resources.calls.len(), 1);
        complete(invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch,
        ));
        assert!(first.same_operation(&resources.calls[1].0));
        let (_, foreign, _) = setup();
        let mut foreign_resources = Actual::new(foreign);
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut foreign_resources,
                &mut latch
            ),
            Completion::Refused(_)
        ));

        let mut next = req.clone();
        next.serial = 2;
        let captured2 = frames
            .capture_pending(&Access::new(0, 105, &mut latch))
            .unwrap();
        complete(invoke(
            &mut owner,
            &next,
            &input,
            &frames,
            &captured2,
            &mut resources,
            &mut latch,
        ));
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured2,
                &mut resources,
                &mut latch
            ),
            Completion::Refused(_)
        ));
    }
    fn extended_configuration() -> Configuration {
        let mut rows = vec![
            Auxiliary {
                words: [0; 14],
                members: Vec::new()
            };
            4
        ];
        rows[0].words[2] = 2;
        rows[0].words[3] = 4;
        rows[0].words[4] = 192;
        rows[0].words[5] = 16;
        rows[0].words[7] = 1;
        rows[0].members.push([2, 0, 192, 16, 0]);
        Configuration::declared(&descriptor(4), &rows).unwrap()
    }
    #[test]
    fn packed_and_member_reads_share_one_actual_bank2_consumption() {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(&mut frames, &local, 4, 0x1234, &mut latch);
        publish(&local, 203, 0x8001, &mut latch);
        let configuration = extended_configuration();
        let input = call(&configuration);
        let mut image = SoftwareImage::zeroed(&configuration);
        image.slots[0].timer = [0, 1, 1];
        put_word(&mut image.slots[0].members[0], 12, 1);
        let mut owner = Owner::initialized_software(configuration, image).unwrap();
        let mut resources = Actual::new(local);
        let req = request(1);
        let progress = frames.progress();
        complete(invoke(
            &mut owner,
            &req,
            &input,
            &frames,
            &captured,
            &mut resources,
            &mut latch,
        ));
        assert_eq!(resources.consumes, 1);
        assert_eq!(resources.calls.len(), 2);
        assert_eq!(half(&owner.image.slots[0].members[0], 16), 0x8001);
        assert_eq!(half(&owner.image.slots[0].members[0], 18), 0x8001);
        assert_eq!(owner.image.slots[0].members[0][20..22], [1, 0]);
        assert_eq!(word(&owner.image.slots[0].raw, 12), 0x0011_0001);
        assert_eq!(frames.progress(), progress);
    }
    #[test]
    fn unknown_actual_correction_pointer_refuses_after_its_read_without_reconsumption() {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(&mut frames, &local, 4, 1, &mut latch);
        publish(&local, 203, 0x8001, &mut latch);
        let mut cfg = extended_configuration();
        cfg.rows[0].words[10] = 0x1234;
        let input = call(&cfg);
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[0].timer = [0, 1, 1];
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local);
        let req = request(1);
        for _ in 0..2 {
            assert!(matches!(
                invoke(
                    &mut owner,
                    &req,
                    &input,
                    &frames,
                    &captured,
                    &mut resources,
                    &mut latch
                ),
                Completion::Refused(
                    "auxiliary correction list requires actual paired scalar owners"
                )
            ));
        }
        assert_eq!(resources.calls.len(), 2);
        assert_eq!(resources.consumes, 1);
        assert_eq!(half(&owner.image.slots[0].members[0], 16), 0x8001);
        assert_eq!(owner.image.slots[0].timer[0], 1); // The later timer clear was not reached.
    }
    #[test]
    fn malformed_retired_resource_result_is_latched_without_replay() {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(&mut frames, &local, 4, 0, &mut latch);
        let cfg = Configuration::t8112(&descriptor(4)).unwrap();
        let input = call(&cfg);
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[0].raw[0] = 1;
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local);
        resources.malformed = true;
        let req = request(1);
        for _ in 0..2 {
            assert!(matches!(
                invoke(
                    &mut owner,
                    &req,
                    &input,
                    &frames,
                    &captured,
                    &mut resources,
                    &mut latch
                ),
                Completion::Refused(_)
            ));
        }
        assert_eq!(resources.calls.len(), 1);
        assert_eq!(
            owner.refusal(),
            Some("auxiliary actual resource result shape mismatch")
        );
    }
    #[test]
    fn activation_transitions_fan_out_flags_then_signal_in_source_order() {
        let (_, local, mut latch) = setup();
        let cfg = Configuration::t8112(&descriptor(4)).unwrap();
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[0].raw[1] = 1;
        image.slots[0].raw[3] = 1;
        image.slots[0].timer[2] = 3;
        for member in &mut image.slots[0].members {
            member[2] = 1;
        }
        image.slots[0].members[8][0] = 1;
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local);
        let req = request(1);
        owner
            .begin(
                Caller::Tail(req.clone()),
                Signature::Transition {
                    slot: 0,
                    mode: 1,
                    activation: 1,
                },
                1,
                None,
                Some(Step::Transition(0, 1)),
            )
            .unwrap();
        complete(owner.advance(None, &mut resources, &mut Access::new(0, 1, &mut latch)));
        assert_eq!(
            resources
                .calls
                .iter()
                .map(|(_, op)| *op)
                .collect::<Vec<_>>(),
            vec![
                Operation::Flags {
                    provider: 0,
                    member: 8,
                    method: FlagsMethod::Enable60,
                    value: 1
                },
                Operation::Signal {
                    source: 64,
                    enable: true
                },
                Operation::Flags {
                    provider: 0,
                    member: 8,
                    method: FlagsMethod::Disable68,
                    value: 0x100
                },
            ]
        );
        assert!(
            owner.image.slots[0]
                .members
                .iter()
                .all(|member| member[1..3] == [1, 0])
        );
        assert_eq!(owner.image.slots[0].timer, [3, 3, 3]);
        owner
            .begin(
                Caller::Tail(req),
                Signature::Transition {
                    slot: 0,
                    mode: 0,
                    activation: 1,
                },
                1,
                None,
                Some(Step::Transition(0, 0)),
            )
            .unwrap();
        complete(owner.advance(None, &mut resources, &mut Access::new(0, 2, &mut latch)));
        assert_eq!(
            resources.calls[3].1,
            Operation::Flags {
                provider: 0,
                member: 8,
                method: FlagsMethod::Disable68,
                value: 1
            }
        );
        assert_eq!(
            resources.calls[4].1,
            Operation::Signal {
                source: 64,
                enable: false
            }
        );
        assert_eq!(word(&owner.image.slots[0].raw, 8), 0);
        assert_eq!(owner.image.slots[0].timer, [0, 0, 3]);
    }
    #[test]
    fn compiled_empty_amcc_still_performs_reached_state_and_timer_transitions() {
        let (_, local, mut latch) = setup();
        let cfg = Configuration::t8112(&descriptor(1)).unwrap();
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[2].timer[2] = 9;
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local);
        let req = request(1);
        owner
            .begin(
                Caller::Tail(req.clone()),
                Signature::Transition {
                    slot: 2,
                    mode: 1,
                    activation: 1,
                },
                1,
                None,
                Some(Step::Transition(2, 1)),
            )
            .unwrap();
        complete(owner.advance(None, &mut resources, &mut Access::new(0, 1, &mut latch)));
        assert_eq!(word(&owner.image.slots[2].raw, 8), 1);
        assert_eq!(owner.image.slots[2].timer, [9, 9, 9]);
        owner
            .begin(
                Caller::Tail(req),
                Signature::Transition {
                    slot: 2,
                    mode: 2,
                    activation: 1,
                },
                1,
                None,
                Some(Step::Transition(2, 2)),
            )
            .unwrap();
        complete(owner.advance(None, &mut resources, &mut Access::new(0, 2, &mut latch)));
        assert_eq!(word(&owner.image.slots[2].raw, 8), 2);
        assert_eq!(owner.image.slots[2].timer, [0, 0, 9]);
        assert!(resources.calls.is_empty());
    }
    #[test]
    fn captured_identity_is_retained_across_busy_and_does_not_follow_new_observation() {
        let (mut frames, local, mut latch) = setup();
        let captured = capture(&mut frames, &local, 4, 1, &mut latch);
        let cfg = Configuration::t8112(&descriptor(4)).unwrap();
        let input = call(&cfg);
        let mut image = SoftwareImage::zeroed(&cfg);
        image.slots[0].raw[0] = 1;
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local);
        resources.busy = true;
        let req = request(1);
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &captured,
                &mut resources,
                &mut latch
            ),
            Completion::Busy { .. }
        ));
        let next = frames
            .capture_pending(&Access::new(0, 105, &mut latch))
            .unwrap();
        assert!(matches!(
            invoke(
                &mut owner,
                &req,
                &input,
                &frames,
                &next,
                &mut resources,
                &mut latch
            ),
            Completion::Refused(_)
        ));
        assert_eq!(resources.calls.len(), 1);
    }
    #[test]
    fn source_configure_retains_registration_prefix_and_does_not_register_thresholds_alone() {
        let (_, local, mut latch) = setup();
        let cfg = Configuration::t8112(&descriptor(4)).unwrap();
        let mut image = SoftwareImage::zeroed(&cfg);
        put_word(&mut image.slots[0].raw, 8, 1);
        image.slots[0].members[8][..5].fill(7);
        let mut owner = Owner::initialized_software(cfg, image).unwrap();
        let mut resources = Actual::new(local);
        let req = request(1);
        owner
            .begin(
                Caller::Tail(req.clone()),
                Signature::ConfigureAuxiliary {
                    slot: 0,
                    flags: 0,
                    thresholds: 0xffff,
                    period: 7,
                    activation: 1,
                },
                1,
                None,
                Some(Step::ConfigureAuxiliary(0, 0, 0xffff, 7)),
            )
            .unwrap();
        complete(owner.advance(None, &mut resources, &mut Access::new(0, 1, &mut latch)));
        assert!(resources.calls.is_empty());
        assert_eq!(owner.image.slots[0].raw[1..5], [0, 0, 255, 255]);
        assert_eq!(owner.image.slots[0].members[8][..5], [1, 0, 0, 0, 0]);
        assert_eq!(owner.image.slots[0].timer[2], 7);
        assert!(owner.registered_auxiliary(0).unwrap().is_none());
        owner
            .begin(
                Caller::Tail(req),
                Signature::ConfigureAuxiliary {
                    slot: 0,
                    flags: 0x200,
                    thresholds: 0,
                    period: 0,
                    activation: 1,
                },
                1,
                None,
                Some(Step::ConfigureAuxiliary(0, 0x200, 0, 0)),
            )
            .unwrap();
        resources.busy = true;
        assert!(matches!(
            owner.advance(None, &mut resources, &mut Access::new(0, 2, &mut latch)),
            Completion::Busy { .. }
        ));
        assert!(!owner.auxiliary_binding(0).unwrap().registered());
        assert_eq!(word(&owner.image.slots[0].raw, 8), 1);
        resources.retired_error = true;
        assert!(matches!(
            owner.advance(None, &mut resources, &mut Access::new(0, 3, &mut latch)),
            Completion::Refused(_)
        ));
        assert!(owner.registered_auxiliary(0).unwrap().unwrap().registered());
        assert_eq!(word(&owner.image.slots[0].raw, 8), 1); // Transition is still owed.
        complete(owner.advance(None, &mut resources, &mut Access::new(0, 4, &mut latch)));
        assert_eq!(word(&owner.image.slots[0].raw, 8), 0);
        assert_eq!(owner.image.slots[0].timer[2], 7); // Input0 preserves source period.
        assert_eq!(
            resources.calls[0].1,
            Operation::RegisterAuxiliary {
                slot: 0,
                source: 64
            }
        );
        assert!(resources.calls[0].0.same_operation(&resources.calls[1].0));
        assert_eq!(
            resources
                .calls
                .iter()
                .filter(|(_, op)| matches!(op, Operation::RegisterAuxiliary { .. }))
                .count(),
            2
        ); // Busy then one actual retirement.
    }

    #[test]
    fn actual_auxiliary_callback_binds_same_control_and_preserves_busy_reset_and_replay() {
        use super::super::super::super::super::interrupts as irq;
        use alloc::boxed::Box;
        use core::cell::RefCell;
        struct Device(irq::Placement);
        impl irq::Device for Device {
            fn placement(&self) -> irq::Placement {
                self.0
            }
            fn read(&mut self, offset: u64, _: &mut Access<'_>) -> Result<u32, irq::Error> {
                Ok(match offset {
                    4 => 512,
                    0x14 => 0xa4,
                    0xc000 => 0x10040,
                    _ => panic!("unexpected authored IRQ read"),
                })
            }
            fn write(&mut self, offset: u64, _: u32, _: &mut Access<'_>) -> Result<(), irq::Error> {
                assert_eq!(offset, 0x14);
                Ok(()) // Current-source disable has no extra MMIO.
            }
            fn order(&mut self, _: &mut Access<'_>) -> Result<(), irq::Error> {
                Ok(())
            }
            fn irq_pending(&mut self, _: &mut Access<'_>) -> Result<bool, irq::Error> {
                Ok(false)
            }
        }
        struct Target(
            Rc<RefCell<Owner>>,
            Rc<RefCell<Vec<irq::AuxiliaryReset>>>,
            bool,
        );
        impl irq::AuxiliaryTarget for Target {
            fn reset_slot(
                &mut self,
                reset: &irq::AuxiliaryReset,
                _: &mut Access<'_>,
            ) -> Completion<()> {
                self.1.borrow_mut().push(reset.clone());
                if core::mem::take(&mut self.2) {
                    return Completion::Busy { deadline: None };
                }
                self.0.borrow_mut().reset_slot(reset)
            }
        }
        let (_, local, mut latch) = setup();
        let d = descriptor(4);
        let cfg = Configuration::t8112(&d).unwrap();
        let control = Rc::new(RefCell::new(
            Owner::initialized_software(cfg.clone(), SoftwareImage::zeroed(&cfg)).unwrap(),
        ));
        let binding = control.borrow().auxiliary_binding(0).unwrap();
        let receipts = Rc::new(RefCell::new(Vec::new()));
        let p = irq::Placement::t8112(0).unwrap();
        let mut irq = irq::Owner::t8112(
            p,
            Box::new(Device(p)),
            irq::SoftwareConfiguration::default(),
        )
        .unwrap();
        irq.initialize(&mut Access::new(0, 1, &mut latch)).unwrap();
        // Retain actual native registration in the typed source resource.
        struct Register<'a> {
            actual: Actual,
            native: &'a mut irq::Owner,
            handler: Option<Box<dyn irq::Handler>>,
        }
        impl Resources for Register<'_> {
            fn identity(&self) -> &Identity {
                self.actual.identity()
            }
            fn notifications(&self) -> &LocalNotifications {
                self.actual.notifications()
            }
            fn call(
                &mut self,
                req: &ResourceRequest,
                op: Operation,
                a: &mut Access<'_>,
            ) -> Completion<ResourceValue> {
                if let Operation::RegisterAuxiliary { source, .. } = op {
                    self.native
                        .register(source, self.handler.take().unwrap())
                        .unwrap();
                    Completion::Retired {
                        value: ResourceValue::Complete,
                        refusal: None,
                    }
                } else {
                    self.actual.call(req, op, a)
                }
            }
        }
        let handler = irq::AuxiliaryHandler::t8112(
            &d,
            0,
            binding.clone(),
            Target(control.clone(), receipts.clone(), true),
        )
        .unwrap();
        let mut resource = Register {
            actual: Actual::new(local),
            native: &mut irq,
            handler: Some(Box::new(handler)),
        };
        control
            .borrow_mut()
            .begin(
                Caller::Tail(request(1)),
                Signature::ConfigureAuxiliary {
                    slot: 0,
                    flags: 1,
                    thresholds: 0,
                    period: 3,
                    activation: 0,
                },
                0,
                None,
                Some(Step::ConfigureAuxiliary(0, 1, 0, 3)),
            )
            .unwrap();
        complete(control.borrow_mut().advance(
            None,
            &mut resource,
            &mut Access::new(0, 2, &mut latch),
        ));
        assert!(binding.registered());
        drop(resource);
        irq.begin_dispatch(false).unwrap();
        assert!(matches!(
            irq.advance_dispatch(&mut Access::new(0, 3, &mut latch)),
            Completion::Busy { .. }
        ));
        assert_eq!(irq.snapshot().current_enabled, 0);
        assert_eq!(control.borrow().image.slots[0].raw[0], 0);
        assert!(matches!(
            irq.advance_dispatch(&mut Access::new(0, 4, &mut latch)),
            Completion::Retired {
                value: irq::Outcome::Dispatched {
                    registered: true,
                    ..
                },
                refusal: None
            }
        ));
        assert_eq!(control.borrow().image.slots[0].raw[0], 1);
        assert_eq!(receipts.borrow().len(), 2);
        let reset = receipts.borrow()[1].clone();
        let mut foreign =
            Owner::initialized_software(cfg.clone(), SoftwareImage::zeroed(&cfg)).unwrap();
        assert!(matches!(foreign.reset_slot(&reset), Completion::Refused(_)));
        control
            .borrow_mut()
            .software(Step::ResetFlag(0), None)
            .unwrap();
        assert!(matches!(
            control.borrow_mut().reset_slot(&reset),
            Completion::Retired { .. }
        ));
        assert_eq!(control.borrow().image.slots[0].raw[0], 0); // Replay cannot reassert consumed flag.
        irq.begin_dispatch(false).unwrap();
        assert!(matches!(
            control.borrow_mut().reset_slot(&reset),
            Completion::Refused(_)
        ));
        assert_eq!(control.borrow().image.slots[0].timer[2], 3);
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original26A434 T8112 PMP via STELA_TEST_PMP_T8112"]
    fn original_selected_control_rows_and_call_operands_match_immutable_pmp() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let read = |va: usize| {
            u32::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap())
        };
        for (ordinal, base) in [
            (1, 0x1046ab8usize),
            (4, 0x10477d0),
            (5, 0x1047b08),
            (6, 0x1047e18),
            (7, 0x1048410),
        ] {
            let cfg = Configuration::t8112(&descriptor(ordinal)).unwrap();
            for (i, row) in cfg.rows().iter().enumerate() {
                assert_eq!(
                    row.words,
                    core::array::from_fn(|j| read(base + 0x160 + 56 * i + 4 * j))
                );
                let pointer = u64::from(row.words[8]) | (u64::from(row.words[9]) << 32);
                for (m, member) in row.members.iter().enumerate() {
                    assert_eq!(
                        *member,
                        core::array::from_fn(|j| read(pointer as usize + 20 * m + 4 * j))
                    );
                }
            }
        }
        assert_eq!(read(0x101b518), 0xf9403908); // Actual provider+70, not PMGR state.
        assert_eq!(read(0x101b548), 0xf9402d48); // Actual provider+58.
        assert_eq!(read(0x101bb90), 0xf900011f); // Zero two timers, preserve third.
        assert_eq!(read(0x101bc88), 0xb9000a93); // Commit mode after reached effects.
    }
}
