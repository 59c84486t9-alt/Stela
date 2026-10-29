//! Shared native type2/target1 interrupt-controller storage and wires.
//!
//! Original26A434 T8112 PMP SHA256
//! b39ef494f808c6db0a2c4feab42497e466d270b0935b2e1e948dadf0b510716c:
//!1026280/102628c/10263f8,1026194 and10326a0 pin this native protocol.
//! Generic AIC register facts (paired readback, SW/HW OR, automatic claim mask)
//! are independently kept from local Asahi aic.md and AIC2 header comments;
//! no reference implementation is copied. Fresh evidence: native-irq-device-r1.
//!
//! This is NEW Stela software hardware state, never measured Apple reset state.
//! All words and relocation are explicit. Real peripheral owners must keep
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
    /// Native priority/reset arbitration is unchecked. Multiple deliverable
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
    /// Keep the allocation identity of the peripheral model. This
    /// does not prove any source-ID/event meaning; root must check that route.
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
    /// Last level, not a current observation after owner abandonment.
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
/// Alias factory for one storage allocation. Clones share this state;
/// there is no separate AP AIC/PTD register image or duplicated IRQ queue.
#[derive(Clone)]
pub struct Controller(Rc<RefCell<Storage>>);
#[derive(Clone)]
pub struct DeviceView(Rc<RefCell<Storage>>, Placement);
#[derive(Clone)]
pub struct RouteView(Rc<RefCell<Storage>>);
/// Sole source wire capability. It is not Clone. A producer must
/// change it only when its model effect changes this electrical level.
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
        // larger source count is advertised without a checked encoding.
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
    /// Registration keeps peripheral allocation identity and its
    /// supplied real initial model level. Binding itself creates no event.
    /// Abandoned/duplicate source bindings cannot silently reset kept state.
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
        // The boundary covers only its applied words, not another
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
mod tests;
