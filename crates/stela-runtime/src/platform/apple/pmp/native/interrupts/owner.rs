use super::super::platform::owner::Completion;
use super::{Device, Error, Outcome, Placement, SPECIAL, SoftwareConfiguration, refused};
use crate::platform::apple::bus::Access;
use alloc::{boxed::Box, rc::Rc, vec::Vec};
use core::cell::Cell;

/// Actual handler invocation, pinned to the sole consumed hardware event.
/// Cloning this value grants no right to create another dispatch operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    pub source: u32,
    pub word: Option<u32>,
    pub generation: u64,
}
/// An actual retained callback/context owner. Busy/Refused must preserve its
/// own completed prefix. Retired-with-refusal prevents callback replay while
/// the interrupt owner still owes its reached reenable/order/line operations.
pub trait Handler {
    fn call(
        &mut self,
        event: Event,
        signals: &mut Signals<'_>,
        access: &mut Access<'_>,
    ) -> Completion<()>;
}
struct Entry {
    source: u32,
    flag: bool,
    handler: Option<Box<dyn Handler>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub source: u32,
    pub flag: bool,
    pub has_handler: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub source_count: Option<u32>,
    pub current: u32,
    pub current_enabled: u8,
    pub special_active: bool,
    pub fault: Option<Error>,
}

#[derive(Clone)]
pub struct Signal {
    owner: Rc<()>,
    serial: u64,
}
struct SignalWork {
    request: Signal,
    source: u32,
    enable: bool,
    cursor: u8,
    previous: bool,
}
struct SignalDone {
    request: Signal,
    previous: bool,
}
struct Nested {
    generation: u64,
    step: u64,
    work: SignalWork,
}
struct NestedDone {
    generation: u64,
    step: u64,
    source: u32,
    enable: bool,
    previous: bool,
}
struct Core {
    identity: Rc<()>,
    live_generation: Rc<Cell<u64>>,
    device: Box<dyn Device>,
    config: SoftwareConfiguration,
    count: Option<u32>,
    initialized: bool,
    current: u32,
    current_enabled: u8,
    special_active: bool,
    fault: Option<Error>,
    nested: Option<Nested>,
    nested_done: Option<NestedDone>,
}
impl Core {
    fn check(&self) -> Result<u32, Error> {
        if let Some(error) = self.fault {
            return Err(error);
        }
        if !self.initialized {
            return Err(Error::Refused(
                "native interrupt software initialization has not retired",
            ));
        }
        self.count.ok_or(Error::Refused(
            "native interrupt software initialization has not retired",
        ))
    }
    fn retain<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if let Err(error @ Error::Uncertain(_)) = result {
            self.fault = Some(error);
        }
        result
    }
    fn read(&mut self, offset: u64, access: &mut Access<'_>) -> Result<u32, Error> {
        let result = self.device.read(offset, access);
        self.retain(result)
    }
    fn write(&mut self, offset: u64, value: u32, access: &mut Access<'_>) -> Result<(), Error> {
        let result = self.device.write(offset, value, access);
        self.retain(result)
    }
    fn order(&mut self, access: &mut Access<'_>) -> Result<(), Error> {
        let result = self.device.order(access);
        self.retain(result)
    }
    fn irq_pending(&mut self, access: &mut Access<'_>) -> Result<bool, Error> {
        let result = self.device.irq_pending(access);
        self.retain(result)
    }
    fn mask_offset(source: u32, enable: bool) -> u64 {
        u64::from(if enable { 0x6600u32 } else { 0x6400 }) + u64::from((source >> 5) * 4)
    }
    // Exact10263f8(w3=1,w4=0) signal route. Every successful inner operation
    // advances before the next possible refusal; an uncertain MMIO never retries.
    fn signal(&mut self, work: &mut SignalWork, access: &mut Access<'_>) -> Result<bool, Error> {
        let count = self.check()?;
        loop {
            match work.cursor {
                0 => {
                    if work.source == SPECIAL || work.source >= count {
                        work.previous = false;
                        work.cursor = 4;
                    } else if self.current == work.source {
                        work.previous = self.current_enabled & 1 != 0;
                        self.current_enabled = u8::from(work.enable);
                        work.cursor = 4;
                    } else {
                        work.cursor = 1;
                    }
                }
                1 => {
                    if self.config.routing_flags & 1 == 0 && work.enable {
                        self.write(0x2000 + 4 * u64::from(work.source), 1, access)?;
                    }
                    work.cursor = 2;
                }
                2 => {
                    let value = self.read(Self::mask_offset(work.source, work.enable), access)?;
                    work.previous = value & 1u32.wrapping_shl(work.source & 31) == 0;
                    work.cursor = 3;
                }
                3 => {
                    self.write(
                        Self::mask_offset(work.source, work.enable),
                        1u32.wrapping_shl(work.source & 31),
                        access,
                    )?;
                    work.cursor = 4;
                }
                _ => return Ok(work.previous),
            }
        }
    }
}

/// Mutable borrowing context of the sole native controller during its actual
/// callback. This shares current-source P68/P70 with foreground Signal. A
/// callback must retain its own operation prefix before returning Busy; use
/// begin_signal/advance_signal outside callbacks for an owner-issued token.
pub struct Signals<'a> {
    core: &'a mut Core,
    generation: u64,
    event: Event,
}
impl Signals<'_> {
    pub(super) fn reset_receipt(
        &self,
        binding: &super::super::platform::ingestion::control::AuxiliaryBinding,
        event: Event,
    ) -> Result<super::AuxiliaryReset, Error> {
        self.core.check()?;
        if !binding.registered()
            || event != self.event
            || event.word.is_none()
            || binding.source() != event.source
            || self.core.live_generation.get() != event.generation
            || !self.core.nested_done.as_ref().is_some_and(|done| {
                done.generation == event.generation
                    && done.step == 0
                    && done.source == event.source
                    && !done.enable
            })
        {
            return Err(Error::Refused(
                "auxiliary reset requires same live actual callback and retired disable/registration",
            ));
        }
        Ok(super::AuxiliaryReset::retired(
            binding.clone(),
            event,
            self.core.identity.clone(),
            self.core.live_generation.clone(),
        ))
    }
    pub fn current(&self) -> u32 {
        self.core.current
    }
    /// A stable monotonically increasing callback source cursor retains its
    /// target/read/write prefix across an effect-free refusal or callback Busy.
    pub fn set(
        &mut self,
        step: u64,
        source: u32,
        enable: bool,
        access: &mut Access<'_>,
    ) -> Result<bool, Error> {
        if let Some(done) = &self.core.nested_done {
            if (self.generation, step) <= (done.generation, done.step) {
                return if (self.generation, step, source, enable)
                    == (done.generation, done.step, done.source, done.enable)
                {
                    Ok(done.previous)
                } else {
                    Err(Error::Refused(
                        "native callback signal cursor is stale or changed",
                    ))
                };
            }
        }
        if let Some(work) = &self.core.nested {
            if (
                work.generation,
                work.step,
                work.work.source,
                work.work.enable,
            ) != (self.generation, step, source, enable)
            {
                return Err(Error::Refused(
                    "native callback signal retains another actual operation",
                ));
            }
        } else {
            self.core.nested = Some(Nested {
                generation: self.generation,
                step,
                work: SignalWork {
                    request: Signal {
                        owner: Rc::new(()),
                        serial: 0,
                    },
                    source,
                    enable,
                    cursor: 0,
                    previous: false,
                },
            });
        }
        let mut pending = self.core.nested.take().unwrap();
        match self.core.signal(&mut pending.work, access) {
            Ok(previous) => {
                self.core.nested_done = Some(NestedDone {
                    generation: self.generation,
                    step,
                    source,
                    enable,
                    previous,
                });
                Ok(previous)
            }
            Err(error) => {
                self.core.nested = Some(pending);
                Err(error)
            }
        }
    }
}

#[derive(Clone, Copy)]
enum EventStage {
    Read,
    Clear,
    Activate,
    Callback,
    ReenableTarget,
    ReenableMask,
    Order,
    ClearCurrent,
    Line,
}
struct EventWork {
    event: Event,
    stage: EventStage,
    entry: Option<usize>,
    registered: bool,
    special: bool,
}

/// Sole configured native RTKit IRQ registry/controller. It owns actual mapped
/// device and callback resources; it never manufactures hardware events. Init
/// and dispatch retain completed prefixes. None of its outcomes is an ACK.
pub struct Owner {
    core: Core,
    identity: Rc<()>,
    serial: u64,
    signal: Option<SignalWork>,
    signal_done: Option<SignalDone>,
    init_stage: u8,
    init_control: u32,
    entries: Vec<Entry>,
    event: Option<EventWork>,
    event_generation: u64,
}
impl Owner {
    pub fn t8112(
        placement: Placement,
        device: Box<dyn Device>,
        configuration: SoftwareConfiguration,
    ) -> Result<Self, Error> {
        if placement != Placement::t8112(placement.relocation)? || device.placement() != placement {
            return Err(Error::Refused(
                "native interrupt owner mapping differs from actual relocated source placement",
            ));
        }
        let identity = Rc::new(());
        Ok(Self {
            core: Core {
                identity: identity.clone(),
                live_generation: Rc::new(Cell::new(0)),
                device,
                config: configuration,
                count: None,
                initialized: false,
                current: u32::MAX,
                current_enabled: 0,
                special_active: false,
                fault: None,
                nested: None,
                nested_done: None,
            },
            identity,
            serial: 0,
            signal: None,
            signal_done: None,
            init_stage: 0,
            init_control: 0,
            entries: Vec::new(),
            event: None,
            event_generation: 0,
        })
    }
    /// Actual selected source initialize operation1 (1026008..102618c).
    /// Software P28/P8c is declared separately; no reset hardware word is supplied.
    pub fn initialize(&mut self, access: &mut Access<'_>) -> Result<u32, Error> {
        if let Some(error) = self.core.fault {
            return Err(error);
        }
        loop {
            match self.init_stage {
                0 => {
                    if self.core.config.routing_flags & 1 == 0 {
                        self.init_control = self.core.read(0x14, access)?;
                    }
                    self.init_stage = 1;
                }
                1 => {
                    if self.core.config.routing_flags & 1 == 0 {
                        self.core.write(0x14, self.init_control | 1, access)?;
                    }
                    self.init_stage = 2;
                }
                2 => {
                    self.core.count = Some(self.core.read(4, access)? & 0x7ff);
                    self.init_stage = 3;
                }
                3 => {
                    // Source allocates19 buckets, current/active cells, and a
                    // special callback pair. Reserve actual host storage now;
                    // this is software allocation, not observed IRQ readiness.
                    self.entries.try_reserve(19).map_err(|_| {
                        Error::Refused("native interrupt registry allocation failed")
                    })?;
                    self.core.initialized = true;
                    self.init_stage = 4;
                }
                _ => return self.core.check(),
            }
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            source_count: self.core.count,
            current: self.core.current,
            current_enabled: self.core.current_enabled,
            special_active: self.core.special_active,
            fault: self.core.fault,
        }
    }
    pub fn registrations(&self) -> impl Iterator<Item = Registration> + '_ {
        self.entries.iter().map(|e| Registration {
            source: e.source,
            flag: e.flag,
            has_handler: e.handler.is_some(),
        })
    }
    fn mutable_registry(&self) -> Result<(), Error> {
        self.core.check()?;
        if self.event.is_some() || self.signal.is_some() {
            return Err(Error::Refused(
                "native interrupt operation retains its callback/registry binding",
            ));
        }
        Ok(())
    }
    /// Actual+38 registration. The real handler contains its sole retained
    /// context; replacing it preserves the existing source flag cell. Register
    /// keys are not constrained to the hardware count by10262b4.
    pub fn register(&mut self, source: u32, handler: Box<dyn Handler>) -> Result<(), Error> {
        self.mutable_registry()?;
        if let Some(entry) = self.entries.iter_mut().find(|e| e.source == source) {
            entry.handler = Some(handler);
        } else {
            self.entries
                .try_reserve(1)
                .map_err(|_| Error::Refused("native interrupt registration allocation failed"))?;
            self.entries.push(Entry {
                source,
                flag: false,
                handler: Some(handler),
            });
        }
        Ok(())
    }
    /// Actual+48 mode update1026328. Bits8..11 gate the store of bit9;
    /// a missing entry is allocated only when bit9 is set. Low8 controls the
    /// returned source status AFTER that prefix:0 returns0, nonzero8000000b.
    /// Preserve this status separately from controller/command completion.
    /// The source retains an existing handler rather than deleting it.
    pub fn configure_registration(&mut self, source: u32, flags: u32) -> Result<u32, Error> {
        self.mutable_registry()?;
        if source == SPECIAL {
            return Ok(0x8000_0001);
        }
        if flags & 0xf00 != 0 {
            if let Some(entry) = self.entries.iter_mut().find(|e| e.source == source) {
                entry.flag = flags & 0x200 != 0;
            } else if flags & 0x200 != 0 {
                self.entries.try_reserve(1).map_err(|_| {
                    Error::Refused("native interrupt registration mode allocation failed")
                })?;
                self.entries.push(Entry {
                    source,
                    flag: true,
                    handler: None,
                });
            }
        }
        Ok(if flags & 0xff == 0 { 0 } else { 0x8000_000b })
    }
    /// Begin once at the actual reached source Signal cursor. Keep this token
    /// in the root ResourceRequest adapter until advance_signal retires; do not
    /// issue a new token to retry the same consuming/write operation.
    pub fn begin_signal(&mut self, source: u32, enable: bool) -> Result<Signal, Error> {
        self.core.check()?;
        if self.signal.is_some() || self.event.is_some() {
            return Err(Error::Refused(
                "native interrupt operation already retained; callback must use its Signals context",
            ));
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Refused(
            "native interrupt signal generation exhausted",
        ))?;
        let request = Signal {
            owner: self.identity.clone(),
            serial,
        };
        self.serial = serial;
        self.signal = Some(SignalWork {
            request: request.clone(),
            source,
            enable,
            cursor: 0,
            previous: false,
        });
        Ok(request)
    }
    pub fn advance_signal(
        &mut self,
        request: &Signal,
        access: &mut Access<'_>,
    ) -> Completion<Outcome> {
        if !Rc::ptr_eq(&request.owner, &self.identity) {
            return refused(Error::Refused("foreign native interrupt signal token"));
        }
        if let Some(work) = &mut self.signal {
            if work.request.serial != request.serial {
                return refused(Error::Refused("stale native interrupt signal token"));
            }
            match self.core.signal(work, access) {
                Err(error) => return refused(error),
                Ok(previous) => {
                    self.signal_done = Some(SignalDone {
                        request: work.request.clone(),
                        previous,
                    });
                    self.signal = None;
                }
            }
        }
        match &self.signal_done {
            Some(done) if done.request.serial == request.serial => Completion::Retired {
                value: Outcome::Signal {
                    previous: done.previous,
                },
                refusal: None,
            },
            _ => refused(Error::Refused(
                "native interrupt signal token has no retained operation",
            )),
        }
    }
    /// Begin one actual native interrupt entry (normal or source special route).
    /// Invoke only from the actual native CPU/device route. This declaration
    /// creates no event; normal poll must consume the real IACK word first.
    pub fn begin_dispatch(&mut self, special: bool) -> Result<(), Error> {
        self.core.check()?;
        if self.event.is_some() || self.signal.is_some() {
            return Err(Error::Refused(
                "native interrupt foreground operation already retained",
            ));
        }
        let generation = self.event_generation.checked_add(1).ok_or(Error::Refused(
            "native interrupt event generation exhausted",
        ))?;
        self.event_generation = generation;
        self.core.live_generation.set(generation);
        self.event = Some(EventWork {
            event: Event {
                source: SPECIAL,
                word: None,
                generation,
            },
            stage: if special {
                EventStage::Activate
            } else {
                EventStage::Read
            },
            entry: if special {
                self.entries.iter().position(|e| e.source == SPECIAL)
            } else {
                None
            },
            registered: false,
            special,
        });
        Ok(())
    }
    pub fn advance_dispatch(&mut self, access: &mut Access<'_>) -> Completion<Outcome> {
        if let Err(error) = self.core.check() {
            return refused(error);
        }
        loop {
            let Some(work) = self.event.as_ref() else {
                return refused(Error::Refused(
                    "native interrupt dispatch has no actual retained entry",
                ));
            };
            let stage = work.stage;
            let source = work.event.source;
            let result: Result<(), Error> = (|| {
                match stage {
                    EventStage::Read => {
                        // Selected target1: source uses (target<<14)+8000.
                        let word = self.core.read(0xc000, access)?;
                        let work = self.event.as_mut().unwrap();
                        work.event.word = Some(word);
                        if word & 0x70000 != 0x10000 {
                            return Ok(());
                        }
                        work.event.source = word & 0x3ff;
                        work.entry = self
                            .entries
                            .iter()
                            .position(|e| e.source == work.event.source);
                        work.stage = EventStage::Clear;
                    }
                    EventStage::Clear => {
                        let work = self.event.as_ref().unwrap();
                        if work.entry.is_some_and(|i| self.entries[i].flag) {
                            self.core.write(
                                0x6200 + u64::from((source >> 5) * 4),
                                1u32.wrapping_shl(source & 31),
                                access,
                            )?;
                        }
                        self.event.as_mut().unwrap().stage = EventStage::Activate;
                    }
                    EventStage::Activate => {
                        let work = self.event.as_mut().unwrap();
                        if work.special {
                            self.core.special_active = true;
                        } else {
                            self.core.current = source;
                            self.core.current_enabled = 1;
                        }
                        work.registered = work
                            .entry
                            .is_some_and(|i| self.entries[i].handler.is_some());
                        work.stage = EventStage::Callback;
                    }
                    EventStage::Callback => return Ok(()),
                    EventStage::ReenableTarget => {
                        if source >= self.core.check()? {
                            //1026404..2c returns without the w4 completion tail.
                            self.event.as_mut().unwrap().stage = EventStage::Line;
                            return Ok(());
                        }
                        if self.core.current_enabled & 1 != 0
                            && self.core.config.routing_flags & 1 == 0
                        {
                            self.core.write(0x2000 + u64::from(source) * 4, 1, access)?;
                        }
                        self.event.as_mut().unwrap().stage = EventStage::ReenableMask;
                    }
                    EventStage::ReenableMask => {
                        if self.core.current_enabled & 1 != 0 && source < self.core.check()? {
                            self.core.write(
                                Core::mask_offset(source, true),
                                1u32.wrapping_shl(source & 31),
                                access,
                            )?;
                        }
                        self.event.as_mut().unwrap().stage = EventStage::Order;
                    }
                    EventStage::Order => {
                        self.core.order(access)?;
                        self.event.as_mut().unwrap().stage = EventStage::ClearCurrent;
                    }
                    EventStage::ClearCurrent => {
                        self.core.current = u32::MAX;
                        self.event.as_mut().unwrap().stage = EventStage::Line;
                    }
                    EventStage::Line => return Ok(()),
                }
                Ok(())
            })();
            if let Err(error) = result {
                return refused(error);
            }
            let work = self.event.as_ref().unwrap();
            if matches!(stage, EventStage::Read)
                && work.event.word.is_some_and(|v| v & 0x70000 != 0x10000)
            {
                let word = work.event.word.unwrap();
                self.event = None;
                return Completion::Retired {
                    value: Outcome::OtherEvent { word },
                    refusal: None,
                };
            }
            if matches!(stage, EventStage::Callback) {
                let work = self.event.as_ref().unwrap();
                let result = match work.entry {
                    Some(index) => match self.entries[index].handler.as_mut() {
                        Some(handler) => handler.call(
                            work.event,
                            &mut Signals {
                                core: &mut self.core,
                                generation: work.event.generation,
                                event: work.event,
                            },
                            access,
                        ),
                        None => {
                            if !work.special {
                                self.core.current_enabled = 0;
                            }
                            Completion::Retired {
                                value: (),
                                refusal: None,
                            }
                        }
                    },
                    None => {
                        if !work.special {
                            self.core.current_enabled = 0;
                        }
                        Completion::Retired {
                            value: (),
                            refusal: None,
                        }
                    }
                };
                match result {
                    Completion::Busy { deadline } => return Completion::Busy { deadline },
                    Completion::Refused(reason) => return Completion::Refused(reason),
                    Completion::Retired { refusal, .. } => {
                        if self.core.nested.is_some() {
                            self.core.fault = Some(Error::Refused(
                                "native callback retired with an unfinished signal prefix",
                            ));
                            return refused(self.core.fault.unwrap());
                        }
                        let work = self.event.as_mut().unwrap();
                        if work.special {
                            self.core.special_active = false;
                            let registered = work.registered;
                            self.event = None;
                            return Completion::Retired {
                                value: Outcome::Special { registered },
                                refusal,
                            };
                        }
                        work.stage = EventStage::ReenableTarget;
                        if let Some(reason) = refusal {
                            return Completion::Refused(reason);
                        }
                    }
                }
            }
            if matches!(stage, EventStage::Line) {
                let more = match self.core.irq_pending(access) {
                    Ok(more) => more,
                    Err(error) => return refused(error),
                };
                let work = self.event.take().unwrap();
                return Completion::Retired {
                    value: Outcome::Dispatched {
                        source: work.event.source,
                        registered: work.registered,
                        more,
                    },
                    refusal: None,
                };
            }
        }
    }
    /// Source operations4/5 require snapshot-enabled P8c and genuine saved
    /// target/mask/control words. This owner does not invent those observations.
    /// A future suspend owner must retain the count target words, count>>5 mask
    /// words and control+14 around1026058..10260f0 in source order.
    pub fn snapshot_lifecycle_requirement(&self) -> Result<(), Error> {
        self.core.check()?;
        Err(Error::Refused(if self.core.config.save_flags & 1 == 0 {
            "source native IRQ snapshot lifecycle is disabled (returns8000000b)"
        } else {
            "native IRQ snapshot lifecycle requires actual retained target/mask/control word storage"
        }))
    }
}
