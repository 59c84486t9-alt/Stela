// SPDX-License-Identifier: GPL-2.0-or-later
extern crate std;
use super::*;
use crate::bus::dma::{
    mapping::DomainMapping,
    memory::{PageBacking, PageGeometry, PinnedPages},
    pages::DmaPages,
};
use alloc::boxed::Box;
use core::{
    cell::UnsafeCell,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::sync::Mutex;
#[repr(align(4096))]
struct Storage([u8; 4096]);
struct Backing {
    ram: Box<UnsafeCell<Storage>>,
    drops: Arc<AtomicUsize>,
}
// SAFETY: isolated model's stable owned RAM accessed only through raw pointers.
unsafe impl Send for Backing {}
// SAFETY: fixture serializes mutations; no safe references to payload escape.
unsafe impl Sync for Backing {}
// SAFETY: exact aligned owned CPU storage; physical labels are model only.
unsafe impl PageBacking for Backing {
    fn cpu_base(&self) -> NonNull<u8> {
        // SAFETY: Box and UnsafeCell retain stable allocated storage.
        unsafe { NonNull::new_unchecked(core::ptr::addr_of_mut!((*self.ram.get()).0).cast()) }
    }
    fn physical_pages(&self) -> &[u64] {
        &[0x800000]
    }
    fn page_shift(&self) -> u8 {
        12
    }
    fn cache_attribute(&self) -> CacheAttribute {
        CacheAttribute::WriteBack
    }
}
impl Drop for Backing {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}
struct Pages(Arc<AtomicUsize>);
impl PageSource for Pages {
    fn page_geometry(&self) -> Result<PageGeometry, MemoryError> {
        PageGeometry::base_only(12)
    }
    fn allocate(
        &self,
        bytes: usize,
        alignment: usize,
        attribute: CacheAttribute,
    ) -> Result<PinnedPages, MemoryError> {
        assert_eq!(
            (bytes, alignment, attribute),
            (32, 4096, CacheAttribute::WriteBack)
        );
        PinnedPages::new(
            Box::new(Backing {
                ram: Box::new(UnsafeCell::new(Storage([0; 4096]))),
                drops: self.0.clone(),
            }),
            bytes,
            alignment,
        )
    }
}
struct Mapping {
    token: DomainMapping,
    pages: DmaPages,
}
#[derive(Default)]
struct DomainState {
    next: u64,
    mappings: Vec<Mapping>,
    reads: Vec<(u64, usize)>,
    cpu_syncs: usize,
    unmaps: usize,
    deny: bool,
    deny_drain: bool,
    drains: usize,
}
struct Domain(Mutex<DomainState>);
// SAFETY: isolated synchronous model retains exact pages/token; no actual IOMMU.
unsafe impl DmaDomain for Domain {
    unsafe fn map(
        &self,
        pages: &DmaPages,
        direction: Direction,
        _: u64,
    ) -> Result<DomainMapping, DmaError> {
        assert_eq!(direction, Direction::FromDevice);
        let mut state = self.0.lock().unwrap();
        state.next += 1;
        let token = DomainMapping {
            id: state.next,
            address: 0x200000 + state.next * 4096,
            bytes: pages.bytes(),
        };
        state.mappings.push(Mapping {
            token,
            pages: pages.clone(),
        });
        Ok(token)
    }
    unsafe fn unmap(&self, token: DomainMapping) -> Result<(), DmaError> {
        let mut state = self.0.lock().unwrap();
        let index = state
            .mappings
            .iter()
            .position(|m| m.token == token)
            .ok_or(DmaError::Unmapped)?;
        state.mappings.remove(index);
        state.unmaps += 1;
        Ok(())
    }
    unsafe fn sync_for_device(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        Ok(())
    }
    unsafe fn sync_for_cpu(
        &self,
        _: DomainMapping,
        _: Range<usize>,
        _: Direction,
    ) -> Result<(), DmaError> {
        self.0.lock().unwrap().cpu_syncs += 1;
        panic!("continuous sensor DMA never grants exclusive CPU ownership")
    }
    unsafe fn drain_posted_writes(&self) -> Result<(), DmaError> {
        let mut state = self.0.lock().unwrap();
        if state.deny_drain {
            return Err(DmaError::DrainUnavailable);
        }
        state.drains += 1;
        Ok(())
    }
    unsafe fn read_coherent_u32(
        &self,
        token: DomainMapping,
        offset: usize,
        direction: Direction,
    ) -> Result<u32, DmaError> {
        let mut state = self.0.lock().unwrap();
        if state.deny {
            return Err(DmaError::CoherenceUnavailable);
        }
        assert_eq!(direction, Direction::FromDevice);
        let mapping = state
            .mappings
            .iter()
            .find(|m| m.token == token)
            .ok_or(DmaError::Unmapped)?;
        let cpu = mapping
            .pages
            .as_single()
            .unwrap()
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap();
        let pointer = cpu.address(offset, 4).unwrap();
        // SAFETY: exact retained model mapping, natural u32 alignment and bounds.
        let value = unsafe { pointer.as_ptr().cast::<u32>().read_volatile() };
        state.reads.push((token.id, offset));
        Ok(value)
    }
}
impl Domain {
    fn write(&self, id: u64, word: usize, value: u32) {
        let state = self.0.lock().unwrap();
        let mapping = state.mappings.iter().find(|m| m.token.id == id).unwrap();
        let cpu = mapping
            .pages
            .as_single()
            .unwrap()
            .cpu_mapping(CacheAttribute::WriteBack)
            .unwrap();
        // SAFETY: serialized device model writing its actual retained allocation.
        unsafe {
            cpu.address(word * 4, 4)
                .unwrap()
                .as_ptr()
                .cast::<u32>()
                .write_volatile(value)
        };
    }
}
struct Time(AtomicU64);
impl Timer for Arc<Time> {
    fn now_us(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
    fn relax(&self) {
        self.0.fetch_add(500_000, Ordering::Relaxed);
    }
}
struct RegisterState {
    acs: u32,
    response: u32,
    writes: Vec<(usize, u32)>,
    master: bool,
    quiescent: bool,
    respond: bool,
    fail: Option<usize>,
    identity: bool,
    light: u32,
    hpd: u32,
    time: Arc<Time>,
    command_delay: u64,
    response_delay: u64,
}
struct Model(Arc<Mutex<RegisterState>>);
impl Registers for Model {
    fn check_authority(&mut self) -> Result<(), Error> {
        if self.0.lock().unwrap().identity {
            Ok(())
        } else {
            Err(Error::PciAuthority)
        }
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        let s = self.0.lock().unwrap();
        Ok(match offset {
            P2C_ACS => s.acs,
            P2C_RESPONSE => {
                s.time.0.fetch_add(s.response_delay, Ordering::Relaxed);
                s.response
            }
            P2C_DISCOVERY => 8,
            C2P_LIGHT => s.light,
            C2P_PRESENCE => s.hpd,
            P2C_INTERRUPT => 0,
            _ => return Err(Error::RegisterUnavailable(offset)),
        })
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let mut s = self.0.lock().unwrap();
        s.writes.push((offset, value));
        if s.fail == Some(offset) {
            return Err(Error::RegisterRejected(offset));
        }
        if offset == C2P_COMMAND {
            s.time.0.fetch_add(s.command_delay, Ordering::Relaxed);
        }
        if offset == C2P_COMMAND && s.respond {
            let enabled = value & 15 == 1;
            s.response = ((value >> 16) & 63) << 16
                | u32::from(if enabled {
                    SENSOR_ENABLED
                } else {
                    SENSOR_DISABLED
                }) << 4;
        }
        Ok(())
    }
    fn set_bus_master(&mut self, enabled: bool) -> Result<(), Error> {
        self.check_authority()?;
        self.0.lock().unwrap().master = enabled;
        Ok(())
    }
    unsafe fn mark_quiescent(&mut self) {
        self.0.lock().unwrap().quiescent = true;
    }
}
type Fixture = (
    Controller<Model, Arc<Time>>,
    Arc<Mutex<RegisterState>>,
    Arc<Domain>,
    Pages,
);
fn fixture(sensors: &[Sensor]) -> Fixture {
    let time = Arc::new(Time(AtomicU64::new(0)));
    let registers = Arc::new(Mutex::new(RegisterState {
        acs: 2 | sensors
            .iter()
            .fold(0, |mask, s| mask | (1 << (*s as u8 + 4))),
        response: 0,
        writes: Vec::new(),
        master: false,
        quiescent: false,
        respond: true,
        fail: None,
        identity: true,
        light: 12345,
        hpd: 0xa1000000,
        time: time.clone(),
        command_delay: 0,
        response_delay: 0,
    }));
    let domain = Arc::new(Domain(Mutex::new(DomainState::default())));
    // SAFETY: isolated register+domain/page model, no native device authority.
    let controller =
        unsafe { Controller::claim(Model(registers.clone()), time, domain.clone()) }.unwrap();
    (
        controller,
        registers,
        domain,
        Pages(Arc::new(AtomicUsize::new(0))),
    )
}
#[derive(Default)]
struct Sink(Vec<(Sensor, Vec<u8>)>);
impl ReportSink for Sink {
    fn input(&mut self, sensor: Sensor, report: &InputReport) {
        self.0.push((sensor, report.wire_bytes().to_vec()));
    }
}
#[test]
fn full_sensor_inventory_continuous_reports_and_acknowledged_lifecycle() {
    let (mut controller, registers, domain, pages) = fixture(&SENSORS);
    controller.initialize(&pages).unwrap();
    assert_eq!(controller.state(), State::Running);
    assert!(controller.available(Sensor::OperatingMode));
    let writes = registers.lock().unwrap().writes.clone();
    assert_eq!(writes.len(), 21);
    for (index, sensor) in SENSORS.iter().enumerate() {
        assert_eq!(
            writes[index * 3],
            (C2P_ADDRESS_LOW, (0x201000 + index * 4096) as u32)
        );
        assert_eq!(writes[index * 3 + 1], (C2P_ADDRESS_HIGH, 0));
        assert_eq!(
            writes[index * 3 + 2],
            (C2P_COMMAND, command_word(*sensor, true))
        );
        domain.write(index as u64 + 1, 0, (-123456i32) as u32);
        domain.write(index as u64 + 1, 1, 0x12345678);
        domain.write(index as u64 + 1, 2, 3000);
        domain.write(index as u64 + 1, 3, 0xffff_fa00);
    }
    let mut sink = Sink::default();
    assert_eq!(controller.poll(&mut sink), Ok(6));
    assert_eq!(
        sink.0.iter().map(|(_, b)| b.len()).collect::<Vec<_>>(),
        [15, 15, 19, 7, 4, 19]
    );
    assert_eq!(&sink.0[0].1[3..7], &(-123i32).to_le_bytes());
    assert_eq!(&sink.0[3].1[3..], &12345u32.to_le_bytes());
    assert_eq!(&sink.0[4].1, &[5, 1, 3, 1]);
    assert_eq!(&sink.0[5].1[7..11], &0x12345678u32.to_le_bytes());
    assert_eq!(registers.lock().unwrap().writes, writes); // no stop/read/restart
    assert_eq!(domain.0.lock().unwrap().cpu_syncs, 0);
    domain.write(1, 0, 999000);
    assert_eq!(
        &controller
            .get_input_report(Sensor::Accelerometer, 1)
            .unwrap()
            .wire_bytes()[3..7],
        &999i32.to_le_bytes()
    );
    controller.suspend().unwrap();
    assert_eq!(
        controller.sensor_state(Sensor::HumanPresence),
        Some(SensorState::Enabled)
    );
    assert_eq!(
        controller.get_input_report(Sensor::Gyroscope, 2),
        Err(Error::NotReady)
    );
    controller.resume().unwrap();
    controller.stop().unwrap();
    assert!(!registers.lock().unwrap().master);
    controller.resume().unwrap();
    controller.shutdown().unwrap();
    assert_eq!(domain.0.lock().unwrap().unmaps, 7);
    assert_eq!(pages.0.load(Ordering::Relaxed), 7);
}
#[test]
fn command_encodings_and_response_fields_are_exact() {
    assert_eq!(command_word(Sensor::AmbientLight, true), 0xc8139011);
    assert_eq!(command_word(Sensor::AmbientColor, true), 0xc8161011);
    assert_eq!(command_word(Sensor::HumanPresence, false), 0x00101012);
    assert!(Controller::<Model, Arc<Time>>::response_matches(
        0x00160040,
        Sensor::AmbientColor,
        SENSOR_ENABLED
    ));
    for wrong in [0x00160041, 0x00150040, 0x00160050] {
        assert!(!Controller::<Model, Arc<Time>>::response_matches(
            wrong,
            Sensor::AmbientColor,
            SENSOR_ENABLED
        ));
    }
}
#[test]
fn continuous_coherence_refusal_occurs_before_dma_publication() {
    let (mut controller, registers, domain, pages) = fixture(&[Sensor::Gyroscope]);
    domain.0.lock().unwrap().deny = true;
    assert_eq!(
        controller.initialize(&pages),
        Err(Error::Dma(DmaError::CoherenceUnavailable))
    );
    assert!(registers.lock().unwrap().writes.is_empty());
    drop(controller);
    assert_eq!(pages.0.load(Ordering::Relaxed), 1);
    assert_eq!(domain.0.lock().unwrap().unmaps, 1);
}
#[test]
fn timeout_retains_iova_and_late_enable_is_completed_without_replay_before_stop() {
    let (mut controller, registers, domain, pages) = fixture(&[Sensor::Gyroscope]);
    registers.lock().unwrap().respond = false;
    assert!(matches!(
        controller.initialize(&pages),
        Err(Error::Timeout {
            sensor: Sensor::Gyroscope,
            expected: 4,
            ..
        })
    ));
    assert_eq!(controller.state(), State::Faulted);
    assert_eq!(domain.0.lock().unwrap().unmaps, 0);
    assert_eq!(pages.0.load(Ordering::Relaxed), 0);
    {
        let mut r = registers.lock().unwrap();
        r.response = 0x00010040;
        r.respond = true;
    }
    let original = controller.first_error();
    controller.shutdown().unwrap();
    assert_eq!(controller.first_error(), original);
    let commands = registers
        .lock()
        .unwrap()
        .writes
        .iter()
        .filter(|(offset, _)| *offset == C2P_COMMAND)
        .map(|(_, value)| value & 15)
        .collect::<Vec<_>>();
    assert_eq!(commands, [1, 2]);
    assert_eq!(domain.0.lock().unwrap().unmaps, 1);
}
#[test]
fn stale_response_cannot_grant_new_enable_or_release_unknown_dma() {
    let (mut controller, registers, domain, pages) = fixture(&[Sensor::Gyroscope]);
    registers.lock().unwrap().response = 0x00010040;
    assert_eq!(
        controller.initialize(&pages),
        Err(Error::StaleResponse {
            sensor: Sensor::Gyroscope,
            expected: 4
        })
    );
    assert!(registers.lock().unwrap().writes.is_empty());
    drop(controller);
    assert_eq!(domain.0.lock().unwrap().unmaps, 1);
    assert_eq!(pages.0.load(Ordering::Relaxed), 1);
}
#[test]
fn authority_loss_and_failed_command_write_never_fabricate_reports_or_completion() {
    let (mut controller, registers, domain, pages) = fixture(&[Sensor::AmbientColor]);
    registers.lock().unwrap().fail = Some(C2P_COMMAND);
    assert_eq!(
        controller.initialize(&pages),
        Err(Error::RegisterRejected(C2P_COMMAND))
    );
    assert_eq!(
        controller.sensor_state(Sensor::AmbientColor),
        Some(SensorState::Uncertain)
    );
    assert_eq!(
        controller.get_input_report(Sensor::AmbientColor, 4),
        Err(Error::NeedsReset)
    );
    registers.lock().unwrap().identity = false;
    assert_eq!(controller.stop(), Err(Error::PciAuthority));
    drop(controller);
    assert_eq!(domain.0.lock().unwrap().unmaps, 0);
    assert_eq!(pages.0.load(Ordering::Relaxed), 0); // deliberate quarantine
}

#[test]
fn failed_fabric_drain_retains_every_published_mapping_and_first_error() {
    let (mut controller, registers, domain, pages) = fixture(&[Sensor::Gyroscope]);
    controller.initialize(&pages).unwrap();
    domain.0.lock().unwrap().deny_drain = true;
    assert_eq!(
        controller.shutdown(),
        Err(Error::Dma(DmaError::DrainUnavailable))
    );
    assert_eq!(
        controller.first_error(),
        Some(Error::Dma(DmaError::DrainUnavailable))
    );
    assert!(!registers.lock().unwrap().master);
    assert_eq!(domain.0.lock().unwrap().unmaps, 0);
    registers.lock().unwrap().identity = false;
    assert_eq!(controller.stop(), Err(Error::PciAuthority));
    assert_eq!(
        controller.first_error(),
        Some(Error::Dma(DmaError::DrainUnavailable))
    );
    drop(controller);
    assert_eq!(pages.0.load(Ordering::Relaxed), 0);
}

#[test]
fn late_successful_publication_and_response_reads_do_not_grant_completion() {
    for delay_command in [true, false] {
        let (mut controller, registers, domain, pages) = fixture(&[Sensor::Gyroscope]);
        {
            let mut registers = registers.lock().unwrap();
            if delay_command {
                registers.command_delay = RESPONSE_TIMEOUT_US + 1;
            } else {
                registers.response_delay = RESPONSE_TIMEOUT_US / 2 + 1;
            }
        }
        assert!(matches!(
            controller.initialize(&pages),
            Err(Error::Timeout {
                sensor: Sensor::Gyroscope,
                expected: 4,
                ..
            })
        ));
        assert_eq!(
            controller.sensor_state(Sensor::Gyroscope),
            Some(SensorState::Uncertain)
        );
        assert_eq!(domain.0.lock().unwrap().unmaps, 0);
        drop(controller);
        assert_eq!(pages.0.load(Ordering::Relaxed), 0);
    }
}
#[test]
fn control_feature_and_input_reports_reflect_programmed_state_and_poll_event() {
    let (mut controller, _, _, pages) = fixture(&[Sensor::Gyroscope]);
    controller.initialize(&pages).unwrap();
    let mut feature = [0; 21];
    assert_eq!(
        controller.get_feature_report(Sensor::Gyroscope, 2, &mut feature),
        Ok(15)
    );
    assert_eq!(&feature[..9], &[2, 0, 1, 1, 1, 200, 0, 0, 0]);
    let report = controller.get_input_report(Sensor::Gyroscope, 2).unwrap();
    assert_eq!(&report.wire_bytes()[..3], &[2, 1, 4]);
    assert_eq!(
        controller.set_report(Sensor::Gyroscope, 2, &feature),
        Err(Error::UnsupportedSetReport)
    );
    controller.shutdown().unwrap();
}

#[test]
fn actual_acs_dialect_is_required_and_unknown_advertisements_remain_visible() {
    for dialect in [0, 1, 3, 15] {
        let (controller, registers, domain, _) = fixture(&[Sensor::Gyroscope]);
        registers.lock().unwrap().acs = (1 << 5) | dialect;
        // SAFETY: same exclusively owned model, no hardware accessed/published.
        let result = unsafe { Controller::claim(controller.registers, controller.timer, domain) };
        assert!(
            matches!(result,Err(Error::UnsupportedDialect(actual)) if u32::from(actual)==dialect)
        );
        assert!(registers.lock().unwrap().writes.is_empty());
    }
    let (mut controller, registers, _, pages) = fixture(&[Sensor::Gyroscope]);
    registers.lock().unwrap().acs |= 1 << 31;
    controller.acs = Some(registers.lock().unwrap().acs);
    assert_eq!(controller.advertised_sensor_mask(), (1 << 1) | (1 << 27));
    controller.initialize(&pages).unwrap();
    controller.shutdown().unwrap();
}

#[test]
fn unadvertised_control_request_does_not_poison_live_sensor_delivery() {
    let (mut controller, _, _, pages) = fixture(&[Sensor::Gyroscope]);
    controller.initialize(&pages).unwrap();
    assert_eq!(
        controller.get_input_report(Sensor::Magnetometer, 3),
        Err(Error::SensorAbsent(Sensor::Magnetometer))
    );
    assert_eq!(controller.state(), State::Running);
    assert_eq!(controller.first_error(), None);
    assert!(controller.get_input_report(Sensor::Gyroscope, 2).is_ok());
    controller.shutdown().unwrap();
}
