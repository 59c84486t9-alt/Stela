//! Actual shared native type2/target1 interrupt-controller storage and wires.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!1026280/102628c/10263f8,1026194 and10326a0 pin this native protocol.
//! Generic AIC register facts (paired readback, SW/HW OR, automatic claim mask)
//! are independently retained from local Asahi aic.md and AIC2 header comments;
//! no reference implementation is copied. Fresh evidence: native-irq-device-r1.
//!
//! This is NEW Stela software hardware state, never measured Apple reset state.
//! All words and relocation are explicit. Real peripheral owners must retain
//! their electrical input handles. No request, enable or ACK creates an input.
use super::{Device, Error, Placement, Route};
use alloc::{
    rc::{Rc, Weak},
    vec::Vec,
};
use core::{any::Any, cell::RefCell};
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction,
    stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError, stela_contracts::bus::Width,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arbitration {
    /// Native priority/reset arbitration is unqualified. Multiple deliverable
    /// sources refuse IACK before changing any mask, rather than picking one.
    RefuseAmbiguous,
}
/// Every initial modeled register word is explicitly declared by its caller.
/// No Default or Apple-reset constructor exists. INFO+4 is the declared count
/// word; upper bits are zero by this NEW software profile, not an observation.
pub struct Configuration {
    pub relocation: u64,
    pub source_count: u32,
    pub control: u32,
    pub masks: Vec<u32>,
    pub targets: Vec<u32>,
    pub software_pending: Vec<u32>,
    pub arbitration: Arbitration,
}
#[derive(Clone)]
pub struct ProducerIdentity(Weak<dyn Any>);
impl ProducerIdentity {
    /// Retain the allocation identity of the actual peripheral model. This
    /// does not prove any source-ID/event meaning; root must qualify that route.
    /// Weak ownership avoids a peripheral->wire->peripheral allocation cycle.
    pub fn for_owner<T: Any>(owner: &Rc<T>) -> Self {
        let erased: Rc<dyn Any> = owner.clone();
        Self(Rc::downgrade(&erased))
    }
    fn same(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.0, &other.0)
    }
    fn alive(&self) -> bool {
        self.0.upgrade().is_some()
    }
}
struct Input {
    producer: ProducerIdentity,
    lease: Weak<()>,
    level: bool,
}
impl Input {
    fn active_owner(&self) -> bool {
        self.producer.alive() && self.lease.upgrade().is_some()
    }
}
struct Storage {
    placement: Placement,
    count: u32,
    control: u32,
    masks: Vec<u32>,
    targets: Vec<u32>,
    software: Vec<u32>,
    inputs: Vec<Option<Input>>,
    arbitration: Arbitration,
    applied_sequence: u64,
    ordered_sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputSnapshot {
    pub registered: bool,
    pub producer_alive: bool,
    pub line_alive: bool,
    /// Retained last level, not a current observation after owner abandonment.
    pub last_level: Option<bool>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub placement: Placement,
    pub source_count: u32,
    pub control: u32,
    pub masks: Vec<u32>,
    pub targets: Vec<u32>,
    pub software_pending: Vec<u32>,
    pub inputs: Vec<InputSnapshot>,
    pub applied_sequence: u64,
    pub ordered_sequence: u64,
}
/// Alias factory for one actual storage allocation. Clones share this state;
/// there is no separate AP AIC/PTD register image or duplicated IRQ queue.
#[derive(Clone)]
pub struct Controller(Rc<RefCell<Storage>>);
#[derive(Clone)]
pub struct DeviceView(Rc<RefCell<Storage>>, Placement);
#[derive(Clone)]
pub struct RouteView(Rc<RefCell<Storage>>);
/// Sole source wire capability. It is deliberately not Clone. A producer must
/// change it only when its actual model effect changes this electrical level.
/// Dropping it is not a deassert/reset; subsequent relevant accesses refuse.
pub struct HardwareLine {
    storage: Weak<RefCell<Storage>>,
    producer: ProducerIdentity,
    lease: Rc<()>,
    source: u32,
}
impl Controller {
    pub fn new_software(configuration: Configuration) -> Result<Self, Error> {
        let Configuration {
            relocation,
            source_count,
            control,
            masks,
            targets,
            software_pending,
            arbitration,
        } = configuration;
        let placement = Placement::t8112(relocation)?;
        if placement.address & 3 != 0 {
            return Err(Error::Refused(
                "native controller relocated aperture must retain Word alignment",
            ));
        }
        // The selected original event path extracts only ten source bits. No
        // larger source count is advertised without a qualified encoding.
        if source_count > 1024 || control & !1 != 0 {
            return Err(Error::Refused(
                "native controller source count or control fields are unqualified",
            ));
        }
        let groups = (source_count as usize).div_ceil(32);
        if masks.len() != groups
            || software_pending.len() != groups
            || targets.len() != source_count as usize
        {
            return Err(Error::Refused(
                "native controller declared words have incomplete source geometry",
            ));
        }
        // Only the selected native CPU target1 is modeled. Other target/IRQ
        // configuration fields require their real routes and effects first.
        if targets.iter().any(|word| *word != 1) {
            return Err(Error::Refused(
                "native controller target/configuration fields outside target1 are unqualified",
            ));
        }
        if source_count & 31 != 0 {
            let valid = (1u32 << (source_count & 31)) - 1;
            if masks[groups - 1] & !valid != 0 || software_pending[groups - 1] & !valid != 0 {
                return Err(Error::Refused(
                    "native controller declares bits outside implemented source count",
                ));
            }
        }
        let inputs = (0..source_count).map(|_| None).collect();
        Ok(Self(Rc::new(RefCell::new(Storage {
            placement,
            count: source_count,
            control,
            masks,
            targets,
            software: software_pending,
            inputs,
            arbitration,
            applied_sequence: 0,
            ordered_sequence: 0,
        }))))
    }
    pub fn placement(&self) -> Placement {
        self.0.borrow().placement
    }
    pub fn device(&self) -> DeviceView {
        DeviceView(self.0.clone(), self.placement())
    }
    pub fn route(&self) -> RouteView {
        RouteView(self.0.clone())
    }
    pub fn same_device(&self, view: &DeviceView) -> bool {
        Rc::ptr_eq(&self.0, &view.0)
    }
    pub fn same_route(&self, view: &RouteView) -> bool {
        Rc::ptr_eq(&self.0, &view.0)
    }
    /// Registration retains actual peripheral allocation identity and its
    /// supplied real initial model level. Binding itself creates no event.
    /// Abandoned/duplicate source bindings cannot silently reset retained state.
    pub fn bind_source(
        &self,
        source: u32,
        producer: &ProducerIdentity,
        actual_initial_level: bool,
    ) -> Result<HardwareLine, Error> {
        if !producer.alive() {
            return Err(Error::Refused("native source producer owner is absent"));
        }
        let mut s = self
            .0
            .try_borrow_mut()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?;
        let input = s.inputs.get_mut(source as usize).ok_or(Error::Refused(
            "native source binding exceeds declared source count",
        ))?;
        if input.is_some() {
            return Err(Error::Refused(
                "native source already has a retained binding; replacement/reset is unqualified",
            ));
        }
        let lease = Rc::new(());
        *input = Some(Input {
            producer: producer.clone(),
            lease: Rc::downgrade(&lease),
            level: actual_initial_level,
        });
        Ok(HardwareLine {
            storage: Rc::downgrade(&self.0),
            producer: producer.clone(),
            lease,
            source,
        })
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let s = self
            .0
            .try_borrow()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?;
        Ok(Snapshot {
            placement: s.placement,
            source_count: s.count,
            control: s.control,
            masks: s.masks.clone(),
            targets: s.targets.clone(),
            software_pending: s.software.clone(),
            inputs: s
                .inputs
                .iter()
                .map(|input| match input {
                    Some(input) => InputSnapshot {
                        registered: true,
                        producer_alive: input.producer.alive(),
                        line_alive: input.lease.upgrade().is_some(),
                        last_level: Some(input.level),
                    },
                    None => InputSnapshot {
                        registered: false,
                        producer_alive: false,
                        line_alive: false,
                        last_level: None,
                    },
                })
                .collect(),
            applied_sequence: s.applied_sequence,
            ordered_sequence: s.ordered_sequence,
        })
    }
}
impl HardwareLine {
    pub fn source(&self) -> u32 {
        self.source
    }
    pub fn set_level(&mut self, producer: &ProducerIdentity, asserted: bool) -> Result<(), Error> {
        if !self.producer.same(producer) || !producer.alive() {
            return Err(Error::Refused(
                "native hardware line producer identity is foreign or abandoned",
            ));
        }
        let storage = self.storage.upgrade().ok_or(Error::Refused(
            "native hardware line controller has been abandoned",
        ))?;
        let mut s = storage
            .try_borrow_mut()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?;
        let input = s
            .inputs
            .get(self.source as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::Refused(
                "native hardware line has no retained source binding",
            ))?;
        if !input.producer.same(producer)
            || !Weak::ptr_eq(&input.lease, &Rc::downgrade(&self.lease))
        {
            return Err(Error::Refused(
                "native hardware line capability differs from retained binding",
            ));
        }
        if input.level != asserted {
            let next = s.next_sequence()?;
            s.inputs[self.source as usize].as_mut().unwrap().level = asserted;
            s.applied_sequence = next;
        }
        Ok(())
    }
}
impl Storage {
    fn next_sequence(&self) -> Result<u64, Error> {
        self.applied_sequence.checked_add(1).ok_or(Error::Refused(
            "native controller applied sequence exhausted",
        ))
    }
    fn check_word(&self, offset: u64) -> Result<(), Error> {
        if offset & 3 != 0
            || offset
                .checked_add(4)
                .is_none_or(|end| end > self.placement.bytes)
        {
            return Err(Error::Refused(
                "native controller word exceeds actual aperture/alignment",
            ));
        }
        Ok(())
    }
    fn group(&self, offset: u64, base: u64) -> Option<usize> {
        offset
            .checked_sub(base)
            .filter(|delta| *delta < self.masks.len() as u64 * 4)
            .map(|delta| (delta / 4) as usize)
    }
    fn validate_bits(&self, group: usize, bits: u32) -> Result<(), Error> {
        if self.count & 31 != 0
            && group + 1 == self.masks.len()
            && bits & !((1u32 << (self.count & 31)) - 1) != 0
        {
            return Err(Error::Refused(
                "native controller write includes unimplemented source bits",
            ));
        }
        Ok(())
    }
    fn require_inputs(&self, group: usize, bits: u32) -> Result<(), Error> {
        self.validate_bits(group, bits)?;
        for bit in 0..32 {
            if bits & (1u32 << bit) != 0 {
                let source = group * 32 + bit;
                if !self.inputs[source]
                    .as_ref()
                    .is_some_and(Input::active_owner)
                {
                    return Err(Error::Refused(
                        "native source requires its actual live peripheral owner and line",
                    ));
                }
            }
        }
        Ok(())
    }
    fn candidates(&self) -> Result<(Option<u32>, bool), Error> {
        if self.control & 1 == 0 {
            return Ok((None, false));
        }
        let mut selected = None;
        let mut multiple = false;
        for source in 0..self.count {
            let group = source as usize / 32;
            let bit = 1u32 << (source & 31);
            if self.masks[group] & bit != 0 {
                continue;
            }
            let input = self.inputs[source as usize]
                .as_ref()
                .filter(|input| input.active_owner())
                .ok_or(Error::Refused(
                    "native unmasked source has no actual live peripheral input",
                ))?;
            if input.level || self.software[group] & bit != 0 {
                if selected.is_some() {
                    multiple = true;
                } else {
                    selected = Some(source);
                }
            }
        }
        Ok((selected, multiple))
    }
    fn pending(&self) -> Result<bool, Error> {
        self.candidates().map(|(source, _)| source.is_some())
    }
    fn read(&mut self, offset: u64) -> Result<u32, Error> {
        self.check_word(offset)?;
        match offset {
            4 => return Ok(self.count),
            0x14 => return Ok(self.control),
            0xc000 => {
                let (source, multiple) = self.candidates()?;
                if multiple && self.arbitration == Arbitration::RefuseAmbiguous {
                    return Err(Error::Refused(
                        "native IRQ priority among multiple actual pending sources is unqualified",
                    ));
                }
                let Some(source) = source else {
                    // NEW model's explicit no-deliverable-event word. Every
                    // relevant input was resolved first; unknown is an error.
                    return Ok(0);
                };
                let next = self.next_sequence()?;
                self.masks[source as usize / 32] |= 1u32 << (source & 31);
                self.applied_sequence = next;
                return Ok(0x10000 | source);
            }
            _ => {}
        }
        if offset >= 0x2000 && offset < 0x2000 + u64::from(self.count) * 4 {
            return Ok(self.targets[((offset - 0x2000) / 4) as usize]);
        }
        for base in [0x6000, 0x6200] {
            if let Some(group) = self.group(offset, base) {
                return Ok(self.software[group]);
            }
        }
        for base in [0x6400, 0x6600] {
            if let Some(group) = self.group(offset, base) {
                return Ok(self.masks[group]);
            }
        }
        Err(Error::Refused(
            "native controller read register has no qualified modeled effect",
        ))
    }
    fn write(&mut self, offset: u64, value: u32) -> Result<(), Error> {
        self.check_word(offset)?;
        let next = self.next_sequence()?;
        if offset == 0x14 {
            if value & !1 != 0 {
                return Err(Error::Refused(
                    "native control fields beyond enable bit0 are unqualified",
                ));
            }
            self.control = value;
        } else if offset >= 0x2000 && offset < 0x2000 + u64::from(self.count) * 4 {
            if value != 1 {
                return Err(Error::Refused(
                    "native IRQ targets/configuration outside target1 are unqualified",
                ));
            }
            self.targets[((offset - 0x2000) / 4) as usize] = value;
        } else if let Some(group) = self.group(offset, 0x6000) {
            self.validate_bits(group, value)?;
            self.software[group] |= value;
        } else if let Some(group) = self.group(offset, 0x6200) {
            self.validate_bits(group, value)?;
            self.software[group] &= !value;
        } else if let Some(group) = self.group(offset, 0x6400) {
            self.validate_bits(group, value)?;
            self.masks[group] |= value;
        } else if let Some(group) = self.group(offset, 0x6600) {
            self.require_inputs(group, value)?;
            self.masks[group] &= !value;
        } else {
            return Err(Error::Refused(
                "native controller write register has no qualified modeled effect",
            ));
        }
        self.applied_sequence = next;
        Ok(())
    }
    fn order(&mut self) {
        // This storage serializes applied MMIO effects through the same borrow.
        // The boundary covers only its actual applied words, not another
        // peripheral's unfinished callback, RAM drain, readiness or cache flush.
        self.ordered_sequence = self.applied_sequence;
    }
}
impl Device for DeviceView {
    fn placement(&self) -> Placement {
        self.1
    }
    fn read(&mut self, offset: u64, _: &mut Access<'_>) -> Result<u32, Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?
            .read(offset)
    }
    fn write(&mut self, offset: u64, value: u32, _: &mut Access<'_>) -> Result<(), Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?
            .write(offset, value)
    }
    fn order(&mut self, _: &mut Access<'_>) -> Result<(), Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?
            .order();
        Ok(())
    }
    fn irq_pending(&mut self, _: &mut Access<'_>) -> Result<bool, Error> {
        self.0
            .try_borrow()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?
            .pending()
    }
}
impl Route for RouteView {
    fn order(&mut self, _: &mut Access<'_>) -> Result<(), Error> {
        self.0
            .try_borrow_mut()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?
            .order();
        Ok(())
    }
    fn irq_pending(&mut self, _: &mut Access<'_>) -> Result<bool, Error> {
        self.0
            .try_borrow()
            .map_err(|_| Error::Refused("native controller storage is currently borrowed"))?
            .pending()
    }
}
fn mmio_error(offset: u64, width: Width, direction: Direction, error: Error) -> MmioError {
    match error {
        Error::Uncertain(error) => error,
        Error::Refused(reason) => MmioError::Unsupported {
            device: "native PMP interrupt controller",
            offset,
            width,
            direction,
            reason,
        },
    }
}
impl MmioDevice for DeviceView {
    fn name(&self) -> &'static str {
        "native PMP interrupt controller"
    }
    fn read(
        &mut self,
        offset: u64,
        width: Width,
        access: &mut Access<'_>,
    ) -> Result<u64, MmioError> {
        if width != Width::Word {
            return Err(mmio_error(
                offset,
                width,
                Direction::Read,
                Error::Refused("native controller supports qualified Word accesses only"),
            ));
        }
        Device::read(self, offset, access)
            .map(u64::from)
            .map_err(|e| mmio_error(offset, width, Direction::Read, e))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        if width != Width::Word || value > u64::from(u32::MAX) {
            return Err(mmio_error(
                offset,
                width,
                Direction::Write,
                Error::Refused("native controller requires an exact qualified Word value"),
            ));
        }
        Device::write(self, offset, value as u32, access)
            .map_err(|e| mmio_error(offset, width, Direction::Write, e))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        Completion, Event, Handler, Outcome, Owner, Signals, SoftwareConfiguration,
    };
    use super::*;
    use alloc::{boxed::Box, vec};
    use core::cell::Cell;
    use stela_contracts::interrupt::InterruptLatch;

    // Authored NEW profile, deliberately not a production/reset default.
    fn configuration(count: u32) -> Configuration {
        let groups = (count as usize).div_ceil(32);
        let mut masks = vec![u32::MAX; groups];
        if count & 31 != 0 {
            masks[groups - 1] = (1u32 << (count & 31)) - 1;
        }
        Configuration {
            relocation: 0x8000,
            source_count: count,
            control: 0,
            masks,
            targets: vec![1; count as usize],
            software_pending: vec![0; groups],
            arbitration: Arbitration::RefuseAmbiguous,
        }
    }
    fn read(view: &mut DeviceView, offset: u64, a: &mut Access<'_>) -> u32 {
        Device::read(view, offset, a).unwrap()
    }
    fn write(view: &mut DeviceView, offset: u64, value: u32, a: &mut Access<'_>) {
        Device::write(view, offset, value, a).unwrap();
    }

    #[test]
    fn explicit_new_geometry_refuses_unknown_fields_and_preserves_source_widths() {
        let mut c = configuration(33);
        c.masks[1] = 2;
        assert!(Controller::new_software(c).is_err());
        c = configuration(33);
        c.targets.pop();
        assert!(Controller::new_software(c).is_err());
        c = configuration(33);
        c.software_pending.clear();
        assert!(Controller::new_software(c).is_err());
        c = configuration(1);
        c.control = 0x10000001;
        assert!(Controller::new_software(c).is_err());
        c = configuration(1);
        c.targets[0] = 0;
        assert!(Controller::new_software(c).is_err());
        c = configuration(1025);
        assert!(Controller::new_software(c).is_err());
        c = configuration(1);
        c.relocation = u64::MAX;
        assert!(Controller::new_software(c).is_err());
        c = configuration(1);
        c.relocation = 1;
        assert!(Controller::new_software(c).is_err());
        let empty = Controller::new_software(configuration(0)).unwrap();
        assert_eq!(empty.snapshot().unwrap().source_count, 0);
        assert!(empty.snapshot().unwrap().inputs.is_empty());
    }

    #[test]
    fn same_storage_views_apply_mask_pairs_and_real_level_claim_without_clearing_input() {
        let controller = Controller::new_software(configuration(65)).unwrap();
        let mut a_view = controller.device();
        let mut b_view = controller.device();
        let mut route = controller.route();
        assert!(
            controller.same_device(&a_view)
                && controller.same_device(&b_view)
                && controller.same_route(&route)
        );
        let owner = Rc::new(Cell::new(false));
        let producer = ProducerIdentity::for_owner(&owner);
        let mut line = controller.bind_source(64, &producer, owner.get()).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 1, &mut latch);
        write(&mut a_view, 0x14, 1, &mut a);
        write(&mut b_view, 0x6608, 1, &mut a);
        assert!(!route.irq_pending(&mut a).unwrap()); // Enabling created no input.
        assert_eq!(read(&mut a_view, 0x6408, &mut a), 0);
        assert_eq!(read(&mut b_view, 0x6608, &mut a), 0);
        owner.set(true);
        line.set_level(&producer, owner.get()).unwrap();
        assert!(Device::irq_pending(&mut a_view, &mut a).unwrap());
        assert_eq!(read(&mut b_view, 0xc000, &mut a), 0x10040);
        assert_eq!(read(&mut a_view, 0x6408, &mut a), 1); // Actual claim masked source.
        assert!(!route.irq_pending(&mut a).unwrap());
        assert_eq!(
            controller.snapshot().unwrap().inputs[64].last_level,
            Some(true)
        );
        write(&mut a_view, 0x6208, 1, &mut a); // Does not clear electrical level.
        write(&mut b_view, 0x6608, 1, &mut a);
        assert!(route.irq_pending(&mut a).unwrap());
        owner.set(false);
        line.set_level(&producer, owner.get()).unwrap();
        assert!(!route.irq_pending(&mut a).unwrap());
        assert_eq!(read(&mut a_view, 0xc000, &mut a), 0); // Known-empty, no unknown inputs.
        Route::order(&mut route, &mut a).unwrap();
        let snapshot = controller.snapshot().unwrap();
        assert_eq!(snapshot.applied_sequence, snapshot.ordered_sequence);
    }

    #[test]
    fn software_pending_is_owned_mmio_state_orred_with_hardware_and_clear_does_not_deassert() {
        let controller = Controller::new_software(configuration(1)).unwrap();
        let mut view = controller.device();
        let owner = Rc::new(Cell::new(false));
        let producer = ProducerIdentity::for_owner(&owner);
        let mut line = controller.bind_source(0, &producer, false).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 2, &mut latch);
        write(&mut view, 0x14, 1, &mut a);
        write(&mut view, 0x6600, 1, &mut a);
        write(&mut view, 0x6000, 1, &mut a);
        assert_eq!(read(&mut view, 0x6200, &mut a), 1);
        assert!(Device::irq_pending(&mut view, &mut a).unwrap());
        assert_eq!(read(&mut view, 0xc000, &mut a), 0x10000);
        assert_eq!(read(&mut view, 0x6000, &mut a), 1); // Claim is not SW clear.
        owner.set(true);
        line.set_level(&producer, owner.get()).unwrap();
        write(&mut view, 0x6200, 1, &mut a);
        write(&mut view, 0x6600, 1, &mut a);
        assert_eq!(read(&mut view, 0x6000, &mut a), 0);
        assert!(Device::irq_pending(&mut view, &mut a).unwrap());
        owner.set(false);
        line.set_level(&producer, owner.get()).unwrap();
        assert!(!Device::irq_pending(&mut view, &mut a).unwrap());
    }

    #[test]
    fn absent_foreign_abandoned_and_dropped_line_owners_cannot_become_zero_inputs() {
        let controller = Controller::new_software(configuration(2)).unwrap();
        let mut view = controller.device();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 3, &mut latch);
        let before = controller.snapshot().unwrap();
        assert!(Device::write(&mut view, 0x6600, 1, &mut a).is_err());
        assert_eq!(controller.snapshot().unwrap(), before);
        let actual = Rc::new(Cell::new(false));
        let producer = ProducerIdentity::for_owner(&actual);
        let other = Rc::new(Cell::new(false));
        let foreign = ProducerIdentity::for_owner(&other);
        let mut line = controller.bind_source(0, &producer, false).unwrap();
        assert!(line.set_level(&foreign, true).is_err());
        assert_eq!(
            controller.snapshot().unwrap().inputs[0].last_level,
            Some(false)
        );
        assert!(controller.bind_source(0, &producer, false).is_err());
        write(&mut view, 0x14, 1, &mut a);
        write(&mut view, 0x6600, 1, &mut a);
        drop(actual);
        assert!(Device::irq_pending(&mut view, &mut a).is_err());
        assert!(line.set_level(&producer, false).is_err());
        write(&mut view, 0x6400, 1, &mut a); // A real mask still gates an unknown input.
        assert!(!Device::irq_pending(&mut view, &mut a).unwrap());
        assert!(Device::write(&mut view, 0x6600, 1, &mut a).is_err());
        let mut line2 = controller.bind_source(1, &foreign, true).unwrap();
        write(&mut view, 0x6600, 2, &mut a);
        line2.set_level(&foreign, false).unwrap();
        drop(line2);
        assert!(Device::irq_pending(&mut view, &mut a).is_err());
        assert!(!controller.snapshot().unwrap().inputs[1].line_alive);
        drop(view);
        drop(controller);
        assert!(line.set_level(&producer, true).is_err());
        let abandoned = Controller::new_software(configuration(1)).unwrap();
        let mut wire = abandoned.bind_source(0, &foreign, false).unwrap();
        drop(abandoned);
        assert!(matches!(
            wire.set_level(&foreign, true),
            Err(Error::Refused(
                "native hardware line controller has been abandoned"
            ))
        ));
    }

    #[test]
    fn multiple_actual_inputs_assert_line_but_ambiguous_claim_refuses_atomically() {
        let controller = Controller::new_software(configuration(2)).unwrap();
        let mut view = controller.device();
        let owner0 = Rc::new(Cell::new(true));
        let id0 = ProducerIdentity::for_owner(&owner0);
        let owner1 = Rc::new(Cell::new(true));
        let id1 = ProducerIdentity::for_owner(&owner1);
        let mut line0 = controller.bind_source(0, &id0, true).unwrap();
        let _line1 = controller.bind_source(1, &id1, true).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 4, &mut latch);
        write(&mut view, 0x14, 1, &mut a);
        write(&mut view, 0x6600, 3, &mut a);
        assert!(Device::irq_pending(&mut view, &mut a).unwrap());
        let before = controller.snapshot().unwrap();
        assert!(matches!(
            Device::read(&mut view, 0xc000, &mut a),
            Err(Error::Refused(
                "native IRQ priority among multiple actual pending sources is unqualified"
            ))
        ));
        assert_eq!(controller.snapshot().unwrap(), before);
        owner0.set(false);
        line0.set_level(&id0, owner0.get()).unwrap();
        assert_eq!(read(&mut view, 0xc000, &mut a), 0x10001);
    }

    #[test]
    fn boundary_source_and_bad_width_register_bits_are_checked_before_any_effect() {
        let controller = Controller::new_software(configuration(1024)).unwrap();
        let mut view = controller.device();
        let owner = Rc::new(Cell::new(true));
        let producer = ProducerIdentity::for_owner(&owner);
        let _line = controller.bind_source(1023, &producer, true).unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 5, &mut latch);
        write(&mut view, 0x14, 1, &mut a);
        write(&mut view, 0x667c, 1 << 31, &mut a);
        assert_eq!(read(&mut view, 0xc000, &mut a), 0x103ff);
        let before = controller.snapshot().unwrap();
        for offset in [0, 0x10, 0x20000, u64::MAX, 0x6401] {
            assert!(Device::write(&mut view, offset, 1, &mut a).is_err());
        }
        assert!(Device::write(&mut view, 0x2000, 0, &mut a).is_err());
        assert!(Device::write(&mut view, 0x14, 3, &mut a).is_err());
        for width in [Width::Byte, Width::Half, Width::Double] {
            assert!(MmioDevice::read(&mut view, 4, width, &mut a).is_err());
            assert!(MmioDevice::write(&mut view, 0x6400, width, 1, &mut a).is_err());
        }
        assert_eq!(controller.snapshot().unwrap(), before);
        let partial = Controller::new_software(configuration(33)).unwrap();
        let mut p = partial.device();
        let before = partial.snapshot().unwrap();
        assert!(Device::write(&mut p, 0x6404, 2, &mut a).is_err());
        assert_eq!(partial.snapshot().unwrap(), before);
    }

    #[test]
    fn actual_owner_initialization_signal_and_dispatch_use_the_shared_controller_resource() {
        struct Peripheral {
            level: bool,
            line: Option<HardwareLine>,
        }
        fn effect(owner: &Rc<RefCell<Peripheral>>, id: &ProducerIdentity, level: bool) {
            let mut model = owner.borrow_mut();
            model.level = level;
            let actual = model.level;
            model.line.as_mut().unwrap().set_level(id, actual).unwrap();
        }
        struct Callback {
            model: Rc<RefCell<Peripheral>>,
            id: ProducerIdentity,
            calls: Rc<Cell<u32>>,
        }
        impl Handler for Callback {
            fn call(
                &mut self,
                event: Event,
                _: &mut Signals<'_>,
                _: &mut Access<'_>,
            ) -> Completion<()> {
                assert_eq!(event.source, 64);
                self.calls.set(self.calls.get() + 1);
                effect(&self.model, &self.id, false);
                Completion::Retired {
                    value: (),
                    refusal: None,
                }
            }
        }
        let controller = Controller::new_software(configuration(512)).unwrap();
        let model = Rc::new(RefCell::new(Peripheral {
            level: false,
            line: None,
        }));
        let id = ProducerIdentity::for_owner(&model);
        model.borrow_mut().line = Some(controller.bind_source(64, &id, false).unwrap());
        let calls = Rc::new(Cell::new(0));
        let mut native = Owner::t8112(
            controller.placement(),
            Box::new(controller.device()),
            SoftwareConfiguration::default(),
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 6, &mut latch);
        assert_eq!(native.initialize(&mut a), Ok(512));
        native
            .register(
                64,
                Box::new(Callback {
                    model: model.clone(),
                    id: id.clone(),
                    calls: calls.clone(),
                }),
            )
            .unwrap();
        let signal = native.begin_signal(64, true).unwrap();
        assert_eq!(
            native.advance_signal(&signal, &mut a),
            Completion::Retired {
                value: Outcome::Signal { previous: false },
                refusal: None
            }
        );
        assert!(!controller.route().irq_pending(&mut a).unwrap());
        assert!(!model.borrow().level);
        assert_eq!(calls.get(), 0);
        effect(&model, &id, true);
        assert!(controller.route().irq_pending(&mut a).unwrap());
        native.begin_dispatch(false).unwrap();
        assert_eq!(
            native.advance_dispatch(&mut a),
            Completion::Retired {
                value: Outcome::Dispatched {
                    source: 64,
                    registered: true,
                    more: false
                },
                refusal: None
            }
        );
        assert_eq!(calls.get(), 1);
        assert!(!model.borrow().level);
        assert_eq!(controller.snapshot().unwrap().software_pending, vec![0; 16]);
        assert_eq!(controller.snapshot().unwrap().masks[2] & 1, 0); // Reenabled only after callback effect.
    }

    #[test]
    fn actual_driver_retains_unmask_prefix_until_the_real_producer_is_bound() {
        let controller = Controller::new_software(configuration(65)).unwrap();
        let mut native = Owner::t8112(
            controller.placement(),
            Box::new(controller.device()),
            SoftwareConfiguration::default(),
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        let mut a = Access::new(0, 7, &mut latch);
        native.initialize(&mut a).unwrap();
        let signal = native.begin_signal(64, true).unwrap();
        assert!(matches!(
            native.advance_signal(&signal, &mut a),
            Completion::Refused("native source requires its actual live peripheral owner and line")
        ));
        assert_eq!(controller.snapshot().unwrap().applied_sequence, 2); // control enable, then actual target store.
        assert_eq!(controller.snapshot().unwrap().masks[2], 1);
        let actual = Rc::new(Cell::new(false));
        let producer = ProducerIdentity::for_owner(&actual);
        let _line = controller.bind_source(64, &producer, actual.get()).unwrap();
        assert_eq!(
            native.advance_signal(&signal, &mut a),
            Completion::Retired {
                value: Outcome::Signal { previous: false },
                refusal: None
            }
        );
        assert_eq!(controller.snapshot().unwrap().applied_sequence, 3); // Only owed mask clear, no target/read replay.
        assert_eq!(controller.snapshot().unwrap().masks[2], 0);
    }

    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires original26A434 T8112 PMP via STELA_TEST_PMP_T8112"]
    fn original_selected_native_register_offsets_and_event_claim_operands_match() {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(std::env::var("STELA_TEST_PMP_T8112").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c"
        );
        let w = |va: usize| {
            u32::from_le_bytes(bytes[va - 0xfff000..va - 0xfff000 + 4].try_into().unwrap())
        };
        assert_eq!(w(0x10326ac), 0x12002908); // Original count read masks11bits; new profile additionally bounds event encoding.
        assert_eq!(w(0x10262a4), 0x528c000a); // Actual SWset6000.
        assert_eq!(w(0x10261b4), 0x528c4019); // Actual SWclear6200.
        assert_eq!(w(0x1026478), 0x528cc008); // Maskclear6600.
        assert_eq!(w(0x1026480), 0x528c8008); // Maskset6400.
        assert_eq!(w(0x10261e4), 0x92402776); // Event source low10.
        assert_eq!(w(0x10261f4), 0x12100b68); // Type bits70000.
        assert_eq!(w(0x1026248), 0xd538c108); // Native ISR_EL1, no AP AIC/PTD alias.
    }
}
