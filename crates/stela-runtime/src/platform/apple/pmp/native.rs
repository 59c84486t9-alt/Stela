//! PMP startup/exit ownership on the local PTD object.
//! Original t6000pmp file91b4..9f04, c750..ce68 and9f04..a50c order the
//! effects below. Device-specific effects require owned resources;
//! neither this coordinator nor the ping endpoint supplies their settlement.
use alloc::{rc::Rc, vec::Vec};
use core::cell::Cell;
use {
    super::super::ptd::transport::notifications::LocalNotifications, stela_contracts::bus::Access,
    stela_contracts::bus::MmioError, stela_soc_data::ptd::Range,
};

pub mod cache;
pub mod counters;
pub mod dma;
pub mod interrupts;
pub mod memory;
pub mod platform;
pub mod power;
pub mod publication;
pub mod registry;
pub mod reporting;
pub mod scheduler;
pub mod services;
pub mod trace;
mod transport;
pub use publication::Target as PublicationTarget;

/// Resource inventory kept by the backend, not an Apple SKU count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inventory {
    /// Native owner+5f8; bounds the exit writes to the ACK range.
    pub power_groups: u32,
}

/// Original packet state at native owner+320..348. Refresh must obtain all six
/// words from the device/callback owners, including their busy waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packets(pub [u64; 6]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Pmgr,
    Dpe,
    Device,
    SocDevice,
}

/// Source-required backend effects. Each operation includes the complete loop
/// over the backend's immutable inventory, source masks and optional
/// resources. Returning retired requires its real effects, never FIFO enqueue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// c8e0..cafc: install shared-bank update targets on source devices.
    BindPacketSource(Family),
    /// cb28..cb64: source register+200 RMW sets bit0.
    EnableDirectPublishers,
    /// cb68..cc48: pass the six-word packet state to each observer.
    NotifyPacketObservers,
    /// cc48..cc60: optional fast-die owner start (3d758).
    StartFastDie,
    /// cc60..cc6c: clear the native owner's four accounting masks.
    ClearAccountingMasks,
    /// cc6c..cccc: control-loop start methods with source filter guards.
    StartControlLoops,
    /// cccc..ccec: aggregate interrupt object's enable method.
    EnableAggregateInterrupt,
    /// ccec..cd68: unmasked per-device interrupt objects' enable methods.
    EnableDeviceInterrupts,
    /// cd68..ce04: configured device register RMWs and power IRQ enables.
    EnablePowerActions,
    /// ce04..ce54: unmasked event interrupt enable methods.
    EnableEventInterrupts,
    /// ce68..cf8c: monitor objects' stop methods in all four families.
    StopPacketMonitors(Family),
    /// 9f20..9f70: unmasked completion interrupt disable methods.
    DisableCompletionInterrupts,
    /// 9f70..9fb8: direct source+4/+c RMW or selected object's method60.
    DisableDirectDelivery,
    /// 9fb8..9fd8: aggregate interrupt object's disable method.
    DisableAggregateInterrupt,
    /// 9fd8..a054: unmasked per-device interrupt disable methods.
    DisableDeviceInterrupts,
    /// a054..a064,a300..a348: disable event IRQs from index1, preserving index0.
    DisableEventInterruptsExceptFirst,
    /// a1cc..a218: source register+200 RMW clears bit0.
    DisableDirectPublishers,
    /// a218..a2bc: timed observer stop and callback retirement.
    StopPacketObservers,
    /// a2bc..a2d0: optional fast-die owner stop (3d5b8).
    StopFastDie,
    /// a3d0..a434: control-loop stop methods with source filter guards.
    StopControlLoops,
    /// a454..a4d0: per-device stop method58 or register-bit0 clear RMW.
    DisablePowerActions,
    /// a4d0..a4f8: release run state and keep counter sample.
    ReleaseRunStateAndSampleCounter,
}

/// A request belongs to this coordinator, transition and operation.
/// Equal numeric serials on a different owner are not interchangeable tokens.
#[derive(Clone)]
pub struct Request {
    owner: Rc<()>,
    serial: u64,
    operation: usize,
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
    pub fn operation(&self) -> usize {
        self.operation
    }
}

/// A backend keeps any reached internal prefix/busy wait under the same request
/// until it retires. Retired-with-refusal records effects before returning the
/// refusal; the coordinator resumes the following operation, never replays it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Busy { deadline: Option<u64> },
    Retired { refusal: Option<&'static str> },
    Refused(&'static str),
}
pub enum Refresh {
    Busy {
        deadline: Option<u64>,
    },
    Retired {
        packets: Packets,
        refusal: Option<&'static str>,
    },
    Refused(&'static str),
}

/// Native resource owner, moved into the coordinator and never replaced
/// during a transition. Implementations must keep original masks, callback
/// registrations, device/clock/memory owners and partial effects across busy or
/// refusal. No default implementation or successful unavailable resource exists.
pub trait Resources {
    fn inventory(&self) -> Inventory;
    /// Original2b514 plus the source timer accounting before packet publication:
    /// invoke each device, wait its BUSY result, obtain state, and
    /// refresh the complete packet state. No request-derived ACK.
    fn refresh_power_states(&mut self, request: &Request, access: &mut Access<'_>) -> Refresh;
    /// cb68..cbd0 takes a fresh six-word snapshot through the native
    /// callback or kept packet owner after publisher binding. It is not a
    /// second device reprogramming pass or a copy of the earlier PTD payload.
    fn snapshot_observer_packets(&mut self, request: &Request, access: &mut Access<'_>) -> Refresh;
    /// Bind operations receive a target keeping this exact PTD owner; observer
    /// operations receive the frozen six-word refresh result. Backends
    /// must refuse missing native effects rather than report retirement.
    fn effect(
        &mut self,
        request: &Request,
        effect: Effect,
        target: Option<&PublicationTarget>,
        packets: &Packets,
        access: &mut Access<'_>,
    ) -> Step;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Dormant,
    Starting,
    Active,
    Stopping,
}
#[derive(Debug)]
pub enum Error {
    Contract(&'static str),
    Backend(&'static str),
    Mmio(MmioError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Busy { deadline: Option<u64> },
    Idle,
}

#[derive(Clone, Copy)]
enum Value {
    Packet(usize),
    Constant(u64),
}
#[derive(Clone, Copy)]
enum Operation {
    Refresh,
    SnapshotObservers,
    Publish { entry: u32, value: Value },
    Route { entry: u32, route: u8 },
    Enable { offset: u64, mask: u32 },
    Resource(Effect),
}
struct Transition {
    serial: u64,
    cursor: usize,
    operations: Vec<Operation>,
    packets: Option<Packets>,
}

/// Explicitly initialized Stela native service coordinator. Construction owns
/// real transport/resources but does not assert firmware execution/readiness.
/// `begin_startup`/`begin_exit` keep an ordered effect batch through completion;
/// no reset, cancellation, replacement backend or generic mark-ready API exists.
#[must_use]
pub struct Owner<B> {
    identity: Rc<()>,
    local: LocalNotifications,
    resources: B,
    ranges: [Option<Range>; 15],
    inventory: Inventory,
    phase: Phase,
    serial: u64,
    transition: Option<Transition>,
    packets: Option<Packets>,
    refusal: Option<&'static str>,
    publisher_epoch: Option<Rc<Cell<bool>>>,
    service_alive: Rc<Cell<bool>>,
    memory_claimed: bool,
    registry_claimed: bool,
    counter_frames_claimed: bool,
    provider_frames_claimed: bool,
    manager_masks_claimed: bool,
    cache_claimed: bool,
}
impl<B: Resources> Owner<B> {
    /// `selected_ids` is the original pm-ptd-ranges array, not range ordinals or
    /// AP AIC numbers. All nonzero IDs resolve on this local bank.
    pub fn initialized(
        local: LocalNotifications,
        selected_ids: [u32; 15],
        resources: B,
    ) -> Result<Self, Error> {
        let all = local.bank().ranges();
        let mut ranges: [Option<Range>; 15] = core::array::from_fn(|_| None);
        for (index, id) in selected_ids.into_iter().enumerate() {
            if id == 0 {
                continue;
            }
            if selected_ids[..index].contains(&id) {
                return Err(Error::Contract("PMP selected range identity is duplicated"));
            }
            ranges[index] = Some(
                all.iter()
                    .find(|r| r.id == id)
                    .ok_or(Error::Contract(
                        "PMP selected range has no actual PTD owner",
                    ))?
                    .clone(),
            );
        }
        for index in [0, 1, 2, 3, 10, 11, 12, 13] {
            if ranges[index].is_none() {
                return Err(Error::Contract(
                    "PMP startup requires a missing selected range",
                ));
            }
        }
        if ranges[1].as_ref().unwrap().count != 1 || ranges[2].as_ref().unwrap().count != 4 {
            return Err(Error::Contract(
                "PMP STATUS/packet geometry is not qualified",
            ));
        }
        let inventory = resources.inventory();
        if inventory.power_groups > ranges[11].as_ref().unwrap().count {
            return Err(Error::Contract(
                "PMP actual power groups exceed ACK ownership",
            ));
        }
        local.claim_pmp_recipient().map_err(Error::Contract)?;
        Ok(Self {
            identity: Rc::new(()),
            local,
            resources,
            ranges,
            inventory,
            phase: Phase::Dormant,
            serial: 0,
            transition: None,
            packets: None,
            refusal: None,
            publisher_epoch: None,
            service_alive: Rc::new(Cell::new(true)),
            memory_claimed: false,
            registry_claimed: false,
            counter_frames_claimed: false,
            provider_frames_claimed: false,
            manager_masks_claimed: false,
            cache_claimed: false,
        })
    }
    /// The original class1 callback/mutex slot belongs to this native
    /// owner for its whole lifetime, including ordinary startup/exit cycles.
    /// Dropping a claim never reopens it or releases remote allocations.
    pub fn claim_memory_services(&mut self) -> Result<memory::Claim, Error> {
        if self.memory_claimed {
            return Err(Error::Contract("PMP memory class slot is already admitted"));
        }
        self.memory_claimed = true;
        Ok(memory::Claim::new(
            self.identity.clone(),
            self.service_alive.clone(),
        ))
    }
    /// Native class3 waiter and class4 unsolicited callback share this kept
    /// registry owner, but are distinct original endpoint callback slots.
    pub fn claim_registry_services(&mut self) -> Result<registry::Claim, Error> {
        if self.registry_claimed {
            return Err(Error::Contract(
                "PMP registry class slots are already admitted",
            ));
        }
        self.registry_claimed = true;
        Ok(registry::Claim::new(
            self.identity.clone(),
            self.service_alive.clone(),
        ))
    }
    pub fn notifications(&self) -> &LocalNotifications {
        &self.local
    }
    /// One kept frame-buffer owner for this SOC-DEV-PKT range.
    /// No startup, counter producer, event completion or ACK is supplied.
    pub fn claim_counter_frames(&mut self) -> Result<counters::Claim, Error> {
        if self.counter_frames_claimed {
            return Err(Error::Contract(
                "PMP counter frame owner is already admitted",
            ));
        }
        let range = self.ranges[9]
            .as_ref()
            .ok_or(Error::Contract(
                "PMP counter frames require the actual selected SOC-DEV-PKT range",
            ))?
            .clone();
        self.counter_frames_claimed = true;
        Ok(counters::Claim::new(
            self.local.clone(),
            range,
            self.service_alive.clone(),
        ))
    }
    /// One shared101ba6c provider cache for source-selected slots4..7.
    /// Counts/storage still require their source block-row product;
    /// this unique claim supplies only the same live native/PTD ownership.
    pub fn claim_provider_frames(&mut self) -> Result<platform::counter_cache::Claim, Error> {
        if self.provider_frames_claimed {
            return Err(Error::Contract(
                "PMP provider-frame owner is already admitted",
            ));
        }
        let ranges = core::array::from_fn(|i| self.ranges[i + 4].clone());
        self.provider_frames_claimed = true;
        Ok(platform::counter_cache::Claim::new(
            self.identity.clone(),
            self.local.clone(),
            ranges,
            self.service_alive.clone(),
        ))
    }
    /// One source manager G540 storage binding on this native recipient.
    /// This supplies ownership only, never controller geometry or reset effects.
    pub fn claim_manager_read_masks(
        &mut self,
    ) -> Result<platform::counter_cache::ManagerClaim, Error> {
        if self.manager_masks_claimed {
            return Err(Error::Contract(
                "PMP manager read-mask owner is already admitted",
            ));
        }
        self.manager_masks_claimed = true;
        Ok(platform::counter_cache::ManagerClaim::new(
            self.identity.clone(),
            self.local.clone(),
            self.service_alive.clone(),
        ))
    }
    pub fn resources(&self) -> &B {
        &self.resources
    }
    /// One MC service on this native recipient. The registry-resolved range
    /// IDs must identify directional ranges on this same PTD object.
    /// Dropping the service cannot reopen the claim or authorize a reset.
    pub fn claim_cache_services(
        &mut self,
        request_id: u32,
        response_id: u32,
    ) -> Result<cache::service::Claim, Error> {
        if self.cache_claimed || request_id == response_id {
            return Err(Error::Contract("PMP cache service ownership is duplicated"));
        }
        let ranges = self.local.bank().ranges();
        let range = |id| {
            ranges
                .iter()
                .find(|r| r.id == id)
                .cloned()
                .ok_or(Error::Contract(
                    "PMP cache service requires actual resolved PTD ranges",
                ))
        };
        let request = range(request_id)?;
        let response = range(response_id)?;
        self.cache_claimed = true;
        Ok(cache::service::Claim::new(
            self.local.clone(),
            request,
            response,
            self.service_alive.clone(),
        ))
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn refusal(&self) -> Option<&'static str> {
        self.refusal
    }
    pub fn committed_prefix(&self) -> usize {
        self.transition.as_ref().map_or(0, |t| t.cursor)
    }
    pub fn pending_operations(&self) -> usize {
        self.transition
            .as_ref()
            .map_or(0, |t| t.operations.len() - t.cursor)
    }

    pub fn begin_startup(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Dormant || self.transition.is_some() {
            return Err(Error::Contract(
                "PMP startup conflicts with an actual retained transition",
            ));
        }
        let mut ops = Vec::new();
        ops.push(Operation::Refresh);
        for index in 0..4 {
            ops.push(Operation::Publish {
                entry: self.range(2).start + u32::try_from(index).unwrap(),
                value: Value::Packet(index),
            });
        }
        for (index, route) in [(0, 0), (3, 1), (10, 4), (12, 5), (13, 6), (14, 7)] {
            if let Some(range) = &self.ranges[index] {
                transport::route_and_enable(&mut ops, range, route);
            }
        }
        for family in [Family::Pmgr, Family::Dpe, Family::Device, Family::SocDevice] {
            ops.push(Operation::Resource(Effect::BindPacketSource(family)));
        }
        ops.push(Operation::Resource(Effect::EnableDirectPublishers));
        ops.push(Operation::SnapshotObservers);
        for effect in [
            Effect::NotifyPacketObservers,
            Effect::StartFastDie,
            Effect::ClearAccountingMasks,
            Effect::StartControlLoops,
            Effect::EnableAggregateInterrupt,
            Effect::EnableDeviceInterrupts,
            Effect::EnablePowerActions,
            Effect::EnableEventInterrupts,
        ] {
            ops.push(Operation::Resource(effect));
        }
        ops.push(Operation::Publish {
            entry: self.range(1).start,
            value: Value::Constant(1),
        });
        self.begin(ops, Phase::Starting, None)
    }
    pub fn begin_exit(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Active || self.transition.is_some() {
            return Err(Error::Contract(
                "PMP exit conflicts with an actual retained transition",
            ));
        }
        let packets = self.packets.ok_or(Error::Contract(
            "PMP exit has no actual retained packet state",
        ))?;
        let mut ops = Vec::new();
        for family in [Family::Pmgr, Family::Dpe, Family::Device, Family::SocDevice] {
            ops.push(Operation::Resource(Effect::StopPacketMonitors(family)));
        }
        for effect in [
            Effect::DisableCompletionInterrupts,
            Effect::DisableDirectDelivery,
            Effect::DisableAggregateInterrupt,
            Effect::DisableDeviceInterrupts,
            Effect::DisableEventInterruptsExceptFirst,
        ] {
            ops.push(Operation::Resource(effect));
        }
        for range in self.ranges.iter().flatten() {
            transport::disable(&mut ops, range);
        }
        for effect in [
            Effect::DisableDirectPublishers,
            Effect::StopPacketObservers,
            Effect::StopFastDie,
        ] {
            ops.push(Operation::Resource(effect));
        }
        for index in 0..self.inventory.power_groups {
            ops.push(Operation::Publish {
                entry: self.range(11).start + index,
                value: Value::Constant(0),
            });
        }
        ops.push(Operation::Resource(Effect::StopControlLoops));
        ops.push(Operation::Publish {
            entry: self.range(1).start,
            value: Value::Constant(0),
        });
        ops.push(Operation::Resource(Effect::DisablePowerActions));
        ops.push(Operation::Resource(Effect::ReleaseRunStateAndSampleCounter));
        self.begin(ops, Phase::Stopping, Some(packets))
    }
    fn range(&self, index: usize) -> &Range {
        self.ranges[index].as_ref().unwrap()
    }
    fn begin(
        &mut self,
        operations: Vec<Operation>,
        phase: Phase,
        packets: Option<Packets>,
    ) -> Result<(), Error> {
        let serial = self
            .serial
            .checked_add(1)
            .ok_or(Error::Contract("PMP transition serial exhausted"))?;
        self.serial = serial;
        self.phase = phase;
        self.refusal = None;
        if phase == Phase::Starting {
            self.publisher_epoch = Some(Rc::new(Cell::new(true)));
        }
        self.transition = Some(Transition {
            serial,
            cursor: 0,
            operations,
            packets,
        });
        Ok(())
    }
    pub fn advance(&mut self, access: &mut Access<'_>) -> Result<Progress, Error> {
        let life = self.local.bank().lifecycle_state();
        if life.reset || !life.powered || !life.clocked || life.quiesced {
            return Err(Error::Contract(
                "PMP actual PTD/resource owner is paused or reset",
            ));
        }
        self.refusal = None;
        loop {
            let Some(t) = &self.transition else {
                return Ok(Progress::Idle);
            };
            let Some(operation) = t.operations.get(t.cursor).copied() else {
                let t = self.transition.take().unwrap();
                self.packets = t.packets;
                self.phase = if self.phase == Phase::Starting {
                    Phase::Active
                } else {
                    Phase::Dormant
                };
                return Ok(Progress::Idle);
            };
            let request = Request {
                owner: self.identity.clone(),
                serial: t.serial,
                operation: t.cursor,
            };
            let packets = t.packets;
            let step = match operation {
                Operation::Refresh | Operation::SnapshotObservers => {
                    match if matches!(operation, Operation::Refresh) {
                        self.resources.refresh_power_states(&request, access)
                    } else {
                        self.resources.snapshot_observer_packets(&request, access)
                    } {
                        Refresh::Busy { deadline } => Step::Busy { deadline },
                        Refresh::Refused(reason) => Step::Refused(reason),
                        Refresh::Retired { packets, refusal } => {
                            self.transition.as_mut().unwrap().packets = Some(packets);
                            Step::Retired { refusal }
                        }
                    }
                }
                Operation::Resource(effect) => {
                    let packets = packets.ok_or(Error::Contract(
                        "PMP resource operation has no actual refreshed state",
                    ))?;
                    let target = if let Effect::BindPacketSource(family) = effect {
                        let index = match family {
                            Family::Pmgr => 4,
                            Family::Dpe => 5,
                            Family::Device => 6,
                            Family::SocDevice => 9,
                        };
                        self.ranges[index].as_ref().map(|range| {
                            PublicationTarget::new(
                                self.local.clone(),
                                range.clone(),
                                self.publisher_epoch.as_ref().unwrap().clone(),
                            )
                        })
                    } else {
                        None
                    };
                    self.resources
                        .effect(&request, effect, target.as_ref(), &packets, access)
                }
                _ => {
                    transport::apply(&self.local, operation, packets, access)?;
                    Step::Retired { refusal: None }
                }
            };
            match step {
                Step::Busy { deadline } => return Ok(Progress::Busy { deadline }),
                Step::Refused(reason) => {
                    self.refusal = Some(reason);
                    return Err(Error::Backend(reason));
                }
                Step::Retired { refusal } => {
                    self.transition.as_mut().unwrap().cursor += 1;
                    if self.phase == Phase::Stopping && self.pending_operations() == 0 {
                        self.publisher_epoch.as_ref().unwrap().set(false);
                    }
                    if let Some(reason) = refusal {
                        self.refusal = Some(reason);
                        return Err(Error::Backend(reason));
                    }
                }
            }
        }
    }
}

impl<B> Drop for Owner<B> {
    fn drop(&mut self) {
        // Poison escaped native API targets, never synthesize exit effects,
        // reset the bank, clear STATUS or cancel hardware/DMA work.
        self.service_alive.set(false);
        if let Some(epoch) = &self.publisher_epoch {
            epoch.set(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use {
        crate::platform::apple::ptd::Ptd, stela_contracts::bus::Lifecycle,
        stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
        stela_contracts::bus::Width, stela_contracts::interrupt::InterruptLatch,
    };

    const IDS: [u32; 15] = [1, 2, 3, 4, 5, 6, 7, 0, 0, 9, 10, 11, 12, 13, 0];
    const PACKETS: Packets = Packets([
        0x0123456789abcdef,
        0xfedcba9876543210,
        7,
        0x8000000000000001,
        99,
        101,
    ]);
    const OBSERVER_PACKETS: Packets = Packets([42, 43, 44, 45, 46, 47]);

    fn life() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    fn local() -> LocalNotifications {
        let ranges: Vec<_> = [
            (1, 0, 1),
            (2, 1, 1),
            (3, 8, 4),
            (4, 12, 4),
            (5, 16, 16),
            (6, 32, 16),
            (7, 48, 16),
            (9, 64, 184),
            (10, 248, 8),
            (11, 256, 8),
            (12, 264, 40),
            (13, 304, 11),
        ]
        .into_iter()
        .map(|(id, start, count)| Range {
            id,
            start,
            count,
            name: format!("source range{id}"),
        })
        .collect();
        Ptd::initialized_local(384, &ranges, life()).unwrap().1
    }
    struct Backend {
        groups: u32,
        refresh_busy: bool,
        refresh_calls: Vec<Request>,
        observer_snapshot: bool,
        calls: Vec<(Effect, Request)>,
        targets: Vec<PublicationTarget>,
        before: Option<Effect>,
        after: Option<Effect>,
        busy: Option<Effect>,
    }
    impl Backend {
        fn new() -> Self {
            Self {
                groups: 3,
                refresh_busy: false,
                refresh_calls: Vec::new(),
                observer_snapshot: false,
                calls: Vec::new(),
                targets: Vec::new(),
                before: None,
                after: None,
                busy: None,
            }
        }
    }
    impl Resources for Backend {
        fn inventory(&self) -> Inventory {
            Inventory {
                power_groups: self.groups,
            }
        }
        fn refresh_power_states(&mut self, request: &Request, _: &mut Access<'_>) -> Refresh {
            self.refresh_calls.push(request.clone());
            if core::mem::take(&mut self.refresh_busy) {
                Refresh::Busy { deadline: Some(17) }
            } else {
                self.observer_snapshot = false;
                Refresh::Retired {
                    packets: PACKETS,
                    refusal: None,
                }
            }
        }
        fn snapshot_observer_packets(&mut self, _: &Request, _: &mut Access<'_>) -> Refresh {
            self.observer_snapshot = true;
            Refresh::Retired {
                packets: OBSERVER_PACKETS,
                refusal: None,
            }
        }
        fn effect(
            &mut self,
            request: &Request,
            effect: Effect,
            target: Option<&PublicationTarget>,
            packets: &Packets,
            _: &mut Access<'_>,
        ) -> Step {
            assert_eq!(
                *packets,
                if self.observer_snapshot {
                    OBSERVER_PACKETS
                } else {
                    PACKETS
                }
            );
            self.calls.push((effect, request.clone()));
            if self.before == Some(effect) {
                self.before = None;
                return Step::Refused("actual device effect unavailable");
            }
            if self.busy == Some(effect) {
                self.busy = None;
                return Step::Busy { deadline: Some(31) };
            }
            if let Effect::BindPacketSource(_) = effect {
                self.targets.push(target.unwrap().clone());
            }
            if self.after == Some(effect) {
                self.after = None;
                return Step::Retired {
                    refusal: Some("later native callback refused"),
                };
            }
            Step::Retired { refusal: None }
        }
    }
    fn step(
        owner: &mut Owner<Backend>,
        latch: &mut InterruptLatch,
        now: u64,
    ) -> Result<Progress, Error> {
        owner.advance(&mut Access::new(0, now, latch))
    }
    fn latest(local: &LocalNotifications, entry: u32) -> Option<u64> {
        local
            .bank()
            .requests()
            .iter()
            .rfind(|r| r.entry == entry)
            .map(|r| r.value)
    }

    #[test]
    fn refresh_busy_precedes_actual_publication_and_all_source_effects_precede_status() {
        let local = local();
        let mut backend = Backend::new();
        backend.refresh_busy = true;
        backend.busy = Some(Effect::EnableEventInterrupts);
        let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
        assert!(owner.notifications().owns(local.bank()));
        let mut latch = InterruptLatch::new();
        owner.begin_startup().unwrap();
        assert_eq!(
            step(&mut owner, &mut latch, 1).unwrap(),
            Progress::Busy { deadline: Some(17) }
        );
        assert_eq!(owner.committed_prefix(), 0);
        assert!(local.bank().requests().is_empty());
        assert_eq!(
            step(&mut owner, &mut latch, 17).unwrap(),
            Progress::Busy { deadline: Some(31) }
        );
        assert_eq!(owner.phase(), Phase::Starting);
        assert_eq!(latest(&local, 1), None);
        for entry in 8..12 {
            assert_eq!(
                latest(&local, entry),
                Some(PACKETS.0[usize::try_from(entry - 8).unwrap()])
            );
        }
        assert_eq!(owner.resources().targets.len(), 4);
        for (target, start, count) in owner
            .resources()
            .targets
            .iter()
            .zip([16, 32, 48, 64])
            .zip([16, 16, 16, 184])
            .map(|((t, s), c)| (t, s, c))
        {
            assert!(target.owns(&local));
            assert_eq!(target.range().start, start);
            assert_eq!(target.range().count, count);
        }
        let requests = local.bank().requests();
        assert_eq!(requests.len(), 4);
        assert!(owner.begin_exit().is_err());
        assert_eq!(step(&mut owner, &mut latch, 31).unwrap(), Progress::Idle);
        assert_eq!(owner.phase(), Phase::Active);
        assert_eq!(latest(&local, 1), Some(1));
        assert_eq!(local.bank().requests()[..4], requests);
        assert_eq!(owner.resources().refresh_calls.len(), 2);
        assert!(
            owner.resources().refresh_calls[0].same_operation(&owner.resources().refresh_calls[1])
        );
        let busy: Vec<_> = owner
            .resources()
            .calls
            .iter()
            .filter(|(e, _)| *e == Effect::EnableEventInterrupts)
            .collect();
        assert_eq!(busy.len(), 2);
        assert!(busy[0].1.same_operation(&busy[1].1));
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn actual_routes_masks_and_device_targets_share_bank_without_ordinal_ap_wires() {
        let local = local();
        let mut bank = local.bank().clone();
        let mut latch = InterruptLatch::new();
        // Unselected neighbor survives route RMW and W1S control.
        bank.write(
            0x18400,
            Width::Word,
            0x30,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        bank.write(0x18200, Width::Word, 2, &mut Access::new(0, 0, &mut latch))
            .unwrap();
        let mut owner = Owner::initialized(local.clone(), IDS, Backend::new()).unwrap();
        owner.begin_startup().unwrap();
        step(&mut owner, &mut latch, 9).unwrap();
        for (first, last, route) in [
            (0u32, 0u32, 0u64),
            (12, 15, 1),
            (248, 255, 4),
            (264, 303, 5),
            (304, 314, 6),
        ] {
            for entry in first..=last {
                let word = bank
                    .read(
                        0x18400 + u64::from(entry / 8) * 4,
                        Width::Word,
                        &mut Access::new(0, 9, &mut latch),
                    )
                    .unwrap();
                assert_eq!(word >> ((entry % 8) * 4) & 0xf, route);
                transport::publish(&local, entry, 123, &mut Access::new(0, 9, &mut latch)).unwrap();
                assert_eq!(local.asserted(), (1 << 3) | (1 << route));
                bank.consume_entry(entry, &mut Access::new(0, 9, &mut latch))
                    .unwrap();
                assert_eq!(local.asserted(), 1 << 3);
            }
        }
        assert_eq!(
            bank.read(0x18400, Width::Word, &mut Access::new(0, 9, &mut latch))
                .unwrap()
                & 0xf0,
            0x30
        );
        assert_eq!(local.asserted(), 1 << 3); // STATUS pending on the separately enabled route3.
        let target = &owner.resources().targets[0];
        target
            .publish(15, 55, &mut Access::new(0, 10, &mut latch))
            .unwrap();
        assert_eq!(latest(&local, 31), Some(55));
        let prefix = bank.requests();
        assert!(
            target
                .publish(16, 99, &mut Access::new(0, 11, &mut latch))
                .is_err()
        );
        assert_eq!(bank.requests(), prefix);
        assert!(!target.owns(&self::local()));
        assert!(latch.take_aic_inputs().is_empty());
    }

    #[test]
    fn every_backend_refusal_preserves_prefix_and_post_effect_refusal_never_replays() {
        let effects = [
            Effect::BindPacketSource(Family::Pmgr),
            Effect::BindPacketSource(Family::Dpe),
            Effect::BindPacketSource(Family::Device),
            Effect::BindPacketSource(Family::SocDevice),
            Effect::EnableDirectPublishers,
            Effect::NotifyPacketObservers,
            Effect::StartFastDie,
            Effect::ClearAccountingMasks,
            Effect::StartControlLoops,
            Effect::EnableAggregateInterrupt,
            Effect::EnableDeviceInterrupts,
            Effect::EnablePowerActions,
            Effect::EnableEventInterrupts,
        ];
        for effect in effects {
            let local = local();
            let mut backend = Backend::new();
            backend.before = Some(effect);
            let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
            let mut latch = InterruptLatch::new();
            owner.begin_startup().unwrap();
            assert!(matches!(
                step(&mut owner, &mut latch, 1),
                Err(Error::Backend(_))
            ));
            let cursor = owner.committed_prefix();
            let prefix = local.bank().requests();
            assert_eq!(latest(&local, 1), None);
            assert_eq!(owner.refusal(), Some("actual device effect unavailable"));
            assert!(owner.begin_startup().is_err());
            let mut bank = local.bank().clone();
            bank.set_lifecycle(
                LifecycleState {
                    clocked: false,
                    ..life()
                },
                &mut Access::new(0, 2, &mut latch),
            );
            assert!(matches!(
                step(&mut owner, &mut latch, 2),
                Err(Error::Contract(_))
            ));
            assert_eq!(owner.committed_prefix(), cursor);
            assert_eq!(local.bank().requests(), prefix);
            bank.set_lifecycle(life(), &mut Access::new(0, 3, &mut latch));
            step(&mut owner, &mut latch, 3).unwrap();
            assert_eq!(owner.phase(), Phase::Active);
            assert_eq!(local.bank().requests()[..prefix.len()], prefix);
            let calls: Vec<_> = owner
                .resources()
                .calls
                .iter()
                .filter(|(e, _)| *e == effect)
                .collect();
            assert_eq!(calls.len(), 2);
            assert!(calls[0].1.same_operation(&calls[1].1));
        }
        let local = local();
        let mut backend = Backend::new();
        backend.after = Some(Effect::EnableEventInterrupts);
        let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
        let mut latch = InterruptLatch::new();
        owner.begin_startup().unwrap();
        assert!(step(&mut owner, &mut latch, 1).is_err());
        assert_eq!(owner.pending_operations(), 1);
        assert_eq!(latest(&local, 1), None);
        step(&mut owner, &mut latch, 2).unwrap();
        assert_eq!(latest(&local, 1), Some(1));
        assert_eq!(
            owner
                .resources()
                .calls
                .iter()
                .filter(|(e, _)| *e == Effect::EnableEventInterrupts)
                .count(),
            1
        );
    }

    #[test]
    fn exit_zeroes_only_actual_ack_groups_then_status_before_retained_cleanup_tail() {
        let local = local();
        let mut backend = Backend::new();
        backend.before = Some(Effect::DisablePowerActions);
        let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
        let memory = owner.claim_memory_services().unwrap();
        assert!(owner.claim_memory_services().is_err());
        let registry = owner.claim_registry_services().unwrap();
        assert!(owner.claim_registry_services().is_err());
        let counter_frames = owner.claim_counter_frames().unwrap();
        assert!(owner.claim_counter_frames().is_err());
        let mut latch = InterruptLatch::new();
        owner.begin_startup().unwrap();
        step(&mut owner, &mut latch, 1).unwrap();
        let stale = owner.resources().targets[0].clone();
        owner.begin_exit().unwrap();
        assert!(step(&mut owner, &mut latch, 2).is_err());
        assert_eq!(owner.phase(), Phase::Stopping);
        assert_eq!(latest(&local, 1), Some(0));
        for entry in 256..259 {
            assert_eq!(latest(&local, entry), Some(0));
        }
        assert_eq!(latest(&local, 259), None);
        let prefix = local.bank().requests();
        let requests = prefix.len();
        assert!(owner.begin_startup().is_err());
        assert!(owner.begin_exit().is_err());
        step(&mut owner, &mut latch, 3).unwrap();
        assert_eq!(owner.phase(), Phase::Dormant);
        assert!(memory.check().is_ok());
        assert!(registry.check().is_ok());
        assert!(counter_frames.check().is_ok());
        assert_eq!(local.bank().requests().len(), requests);
        assert_eq!(local.bank().requests(), prefix);
        assert!(
            stale
                .publish(0, 55, &mut Access::new(0, 3, &mut latch))
                .is_err()
        );
        owner.begin_startup().unwrap();
        step(&mut owner, &mut latch, 4).unwrap();
        let resumed = local.bank().requests();
        assert!(
            stale
                .publish(0, 55, &mut Access::new(0, 4, &mut latch))
                .is_err()
        );
        assert_eq!(local.bank().requests(), resumed);
        owner
            .resources()
            .targets
            .last()
            .unwrap()
            .publish(0, 77, &mut Access::new(0, 4, &mut latch))
            .unwrap();
        assert_eq!(latest(&local, 64), Some(77));
        assert!(latch.take_aic_inputs().is_empty());
        assert!(memory.check().is_ok());
        drop(owner);
        assert!(memory.check().is_err());
        assert!(registry.check().is_err());
        assert!(counter_frames.check().is_err());
        drop(memory);
        assert!(Owner::initialized(local, IDS, Backend::new()).is_err());
    }

    #[test]
    fn constructor_validates_actual_selected_ids_inventory_and_request_identity() {
        let local = local();
        let prefix = local.bank().requests();
        let mut invalid = IDS;
        invalid[3] = 999;
        assert!(Owner::initialized(local.clone(), invalid, Backend::new()).is_err());
        invalid = IDS;
        invalid[4] = 1;
        assert!(Owner::initialized(local.clone(), invalid, Backend::new()).is_err());
        invalid = IDS;
        invalid[1] = 0;
        assert!(Owner::initialized(local.clone(), invalid, Backend::new()).is_err());
        let mut backend = Backend::new();
        backend.groups = 9;
        assert!(Owner::initialized(local.clone(), IDS, backend).is_err());
        assert_eq!(local.bank().requests(), prefix);
        let mut first = Owner::initialized(local.clone(), IDS, Backend::new()).unwrap();
        drop(first.claim_memory_services().unwrap());
        assert!(first.claim_memory_services().is_err());
        drop(first.claim_registry_services().unwrap());
        assert!(first.claim_registry_services().is_err());
        assert!(Owner::initialized(local.clone(), IDS, Backend::new()).is_err());
        let mut second = Owner::initialized(self::local(), IDS, Backend::new()).unwrap();
        let mut latch = InterruptLatch::new();
        first.begin_startup().unwrap();
        second.begin_startup().unwrap();
        step(&mut first, &mut latch, 1).unwrap();
        step(&mut second, &mut latch, 1).unwrap();
        let a = &first.resources().refresh_calls[0];
        let b = &second.resources().refresh_calls[0];
        assert_eq!(a.serial(), b.serial());
        assert_eq!(a.operation(), b.operation());
        assert!(!a.same_operation(b));
        let abandoned = first.resources().targets[0].clone();
        let retained = local.bank().requests();
        drop(first);
        assert!(
            abandoned
                .publish(0, 5, &mut Access::new(0, 2, &mut latch))
                .is_err()
        );
        assert_eq!(local.bank().requests(), retained);
        assert_eq!(latest(&local, 1), Some(1));
        assert!(Owner::initialized(local.clone(), IDS, Backend::new()).is_err());
        let late = self::local();
        transport::publish(&late, 1, 1, &mut Access::new(0, 2, &mut latch)).unwrap();
        assert!(Owner::initialized(late, IDS, Backend::new()).is_err());
    }

    #[test]
    fn exit_failure_boundaries_preserve_real_ack_and_status_order() {
        for (effect, ack, status) in [
            (Effect::DisableCompletionInterrupts, None, Some(1)),
            (Effect::StopFastDie, None, Some(1)),
            (Effect::StopControlLoops, Some(0), Some(1)),
            (Effect::ReleaseRunStateAndSampleCounter, Some(0), Some(0)),
        ] {
            let local = local();
            let mut backend = Backend::new();
            backend.after = Some(effect);
            let mut owner = Owner::initialized(local.clone(), IDS, backend).unwrap();
            let mut latch = InterruptLatch::new();
            owner.begin_startup().unwrap();
            step(&mut owner, &mut latch, 1).unwrap();
            owner.begin_exit().unwrap();
            assert!(step(&mut owner, &mut latch, 2).is_err());
            assert_eq!(latest(&local, 256), ack);
            assert_eq!(latest(&local, 1), status);
            let prefix = local.bank().requests();
            step(&mut owner, &mut latch, 3).unwrap();
            assert_eq!(owner.phase(), Phase::Dormant);
            assert_eq!(local.bank().requests()[..prefix.len()], prefix);
            assert_eq!(
                owner
                    .resources()
                    .calls
                    .iter()
                    .filter(|(e, _)| *e == effect)
                    .count(),
                1
            );
        }
    }
}
