use super::*;
use crate::bus::pci::regs;
use crate::bus::pci::{
    Address,
    owned::tests::{Counters, fixture},
    requester::FunctionRole,
};
use alloc::sync::Arc;
use alloc::{collections::VecDeque, rc::Rc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    sync::atomic::Ordering,
};

#[derive(Debug)]
struct Hardware {
    identity: Identity,
    base: u64,
    words: [u32; WINDOW_BYTES / 4],
    writes: Vec<(usize, u32)>,
    calls: usize,
    fail: Option<(usize, bool)>,
    reject: Option<usize>,
    rx: VecDeque<u8>,
    commands: Vec<u32>,
    next_read: u8,
    stop: bool,
    stuck_disable: bool,
}
#[derive(Debug)]
struct Model {
    hardware: Rc<RefCell<Hardware>>,
    drops: Rc<Cell<usize>>,
}
impl Drop for Model {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}
impl Hardware {
    fn begin(&mut self) -> Result<bool, Error> {
        self.calls += 1;
        if self.fail == Some((self.calls, false)) {
            return Err(Error::Io);
        }
        Ok(self.fail == Some((self.calls, true)))
    }
}
// SAFETY: isolated owned register model and a distinct drop-counted
// resource guard. No hardware, other process or asynchronous borrower exists.
unsafe impl Registers for Model {
    fn identity(&mut self) -> Result<Identity, Error> {
        let mut h = self.hardware.borrow_mut();
        let late = h.begin()?;
        if late {
            Err(Error::Identity)
        } else {
            Ok(h.identity)
        }
    }
    fn physical_base(&self) -> u64 {
        self.hardware.borrow().base
    }
    fn read32(&mut self, offset: usize) -> Result<u32, Error> {
        let mut h = self.hardware.borrow_mut();
        let late = h.begin()?;
        let value = h.words[offset / 4];
        if late { Err(Error::Io) } else { Ok(value) }
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error> {
        let mut h = self.hardware.borrow_mut();
        let late = h.begin()?;
        h.writes.push((offset, value));
        if h.reject != Some(offset) {
            h.words[offset / 4] = value;
        }
        if late { Err(Error::Io) } else { Ok(()) }
    }
}
// SAFETY: isolated model aperture; command/FIFO/status effects are
// independent of the production engine. There is no real DMA or IRQ.
unsafe impl ChildAccess for Model {
    fn child_read32(&mut self, offset: usize) -> u32 {
        let mut h = self.hardware.borrow_mut();
        match offset {
            0xfc => 0x4457_0140,
            0xf4 => 2 | (1 << 7) | (2 << 2) | (3 << 16) | (3 << 8),
            0xf8 => 0x3131_312a,
            0x9c => {
                if h.stuck_disable {
                    1
                } else {
                    h.words[0x6c / 4] & 1
                }
            }
            0x70 => 1 << 2,
            0x74 => 0,
            0x78 => h.rx.len() as u32,
            0x10 => u32::from(h.rx.pop_front().expect("actual queued RX byte")),
            0x34 => {
                if h.stop {
                    1 << 9
                } else {
                    0
                }
            }
            0x40 | 0x60 => {
                h.stop = false;
                0
            }
            _ => h.words[offset / 4],
        }
    }
    fn child_write32(&mut self, offset: usize, value: u32) {
        let mut h = self.hardware.borrow_mut();
        assert!(offset < PRIVATE && offset.is_multiple_of(4));
        h.words[offset / 4] = value;
        if matches!(offset, 0x30 | 0x88 | 0xcc) {
            assert_eq!(value, 0, "PIO never publishes IRQ/DMA");
        }
        if offset == 0x10 {
            assert_ne!(h.words[0x6c / 4] & 1, 0);
            h.commands.push(value);
            if value & (1 << 8) != 0 {
                let byte = h.next_read;
                h.rx.push_back(byte);
                h.next_read = byte.wrapping_add(1);
            }
            if value & (1 << 9) != 0 {
                h.stop = true;
            }
        }
    }
}
#[derive(Clone)]
struct Time(Rc<Cell<u64>>);
impl crate::bus::i2c::Timer for Time {
    fn now_us(&self) -> u64 {
        self.0.get()
    }
    fn relax(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }
}
fn timing() -> crate::bus::i2c::Config {
    crate::bus::i2c::Config {
        timing: crate::bus::i2c::Timing {
            speed: crate::bus::i2c::Speed::Standard,
            scl_high: 120,
            scl_low: 130,
            sda_hold: Some(28),
        },
        timeout_us: 100,
        recovery_timeout_us: 50,
    }
}
type ModelResources = (Model, Rc<RefCell<Hardware>>, Rc<Cell<usize>>);
fn model(device: u16, base: u64, caps: u32) -> ModelResources {
    let mut words = [0xa5a5_a5a5; WINDOW_BYTES / 4];
    words[CAPS / 4] = caps;
    let hardware = Rc::new(RefCell::new(Hardware {
        identity: Identity {
            vendor: 0x8086,
            device,
            subsystem_vendor: 0x1234,
            subsystem_device: 0x5678,
        },
        base,
        words,
        writes: Vec::new(),
        calls: 0,
        fail: None,
        reject: None,
        rx: VecDeque::new(),
        commands: Vec::new(),
        next_read: 0x31,
        stop: false,
        stuck_disable: false,
    }));
    let drops = Rc::new(Cell::new(0));
    (
        Model {
            hardware: hardware.clone(),
            drops: drops.clone(),
        },
        hardware,
        drops,
    )
}
pub(super) type NativeFixture = (Function<OwnedConfig>, Mapping, Arc<Counters>, Arc<Counters>);
fn native_fixture() -> NativeFixture {
    native_fixture_for(0x9d60)
}
pub(super) fn native_fixture_for(device: u16) -> NativeFixture {
    let address = Address {
        segment: 0x1234,
        bus: 2,
        device: 3,
        function: 0,
    };
    let (mut config, config_counts) = fixture(address);
    let (window, bar_counts) = fixture(Address {
        function: 1,
        ..address
    });
    let mapping = window.into_mapping();
    let physical = mapping.physical_span().unwrap().start();
    assert!(physical <= u64::from(u32::MAX));
    config.write32(0, u32::from(device) << 16 | 0x8086);
    config.write32(8, 0x1180_0000);
    config.write16(
        regs::COMMAND,
        regs::COMMAND_MEMORY | regs::COMMAND_INTX_DISABLE,
    );
    // A real owned RAM mapping stands in for the exclusive BAR.
    // Its CPU pointer and symbolic physical address are distinct.
    config.write32(0x10, physical as u32 | 4);
    config.write32(0x14, 0);
    config.write32(0x2c, 0x1237_152d);
    let pointer = mapping.address(0, WINDOW_BYTES).unwrap().cast::<u32>();
    assert_ne!(pointer.as_ptr() as u64, physical);
    // SAFETY: fixture's isolated original RAM resource has no device,
    // asynchronous worker or other register owner.
    unsafe { pointer.as_ptr().add(CAPS / 4).write_volatile(0) };
    (
        Function::new(address, config).unwrap(),
        mapping,
        config_counts,
        bar_counts,
    )
}
pub(super) fn stop_fixture(function: Function<OwnedConfig>) -> StoppedRequester {
    // SAFETY: owned fixture storage is drained, exclusively kept
    // and not exposed as any production device/coherency validation.
    match unsafe { StoppedRequester::from_stopped_pci(function, FunctionRole::Physical) } {
        Ok(stopped) => stopped,
        Err((error, _)) => panic!("valid stopped fixture: {error:?}"),
    }
}
pub(super) fn release_native(
    resources: NativeResources,
    config_counts: &Counters,
    bar_counts: &Counters,
) {
    let (function, mut mapping) = resources;
    let mut config = function.into_config().into_mapping();
    // SAFETY: the original isolated resources have no remaining register,
    // device or worker users after the synchronous owner was consumed.
    unsafe { mapping.retire() }.unwrap();
    // SAFETY: the model device is stopped and drained, so nothing still uses what this
    // releases.
    unsafe { config.retire() }.unwrap();
    for counts in [config_counts, bar_counts] {
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 1);
        assert_eq!(counts.resource_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counts.platform_drops.load(Ordering::Relaxed), 1);
    }
}
#[test]
fn native_i2c_unavailable_or_unrepresentable_clock_returns_untouched_original_resources() {
    for rate in [0, u64::MAX, u64::MAX / 2 / 100 + 1] {
        let (function, mapping, config_counts, bar_counts) = native_fixture();
        let before = {
            let pointer = mapping.address(0, WINDOW_BYTES).unwrap();
            // SAFETY: original stopped, exclusively held fixture aperture.
            unsafe { core::slice::from_raw_parts(pointer.as_ptr(), WINDOW_BYTES) }.to_vec()
        };
        let requester = stop_fixture(function);
        // SAFETY: same stopped owner/mapping; failed time admission
        // must return them before private reset/remap or child accesses.
        let failure = unsafe {
            I2c::attach_native(
                requester,
                mapping,
                crate::Clock {
                    ticks_per_microsecond: rate,
                },
                timing(),
            )
        }
        .err()
        .unwrap();
        assert_eq!(
            failure.error,
            AttachError::I2c(crate::bus::i2c::ErrorKind::InvalidConfiguration.into())
        );
        let resources = failure.unmodified.expect("original unchanged owners");
        let pointer = resources.1.address(0, WINDOW_BYTES).unwrap();
        assert_eq!(
            // SAFETY: these original owners still keep the aperture.
            unsafe { core::slice::from_raw_parts(pointer.as_ptr(), WINDOW_BYTES) },
            before
        );
        release_native(resources, &config_counts, &bar_counts);
    }
}

#[test]
fn concrete_native_registers_use_owned_mapping_and_acknowledged_reset_release() {
    let (function, mapping, config_counts, bar_counts) = native_fixture();
    let physical = mapping.physical_span().unwrap().start();
    // SAFETY: stopped exclusively owned RAM fixture and its mapping.
    let registers = match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
        Ok(registers) => registers,
        Err((error, _)) => panic!("valid mapped owner: {error:?}"),
    };
    let mut owner = match Controller::initialize(registers) {
        Ok(owner) => owner,
        Err((error, _)) => panic!("valid private core: {error:?}"),
    };
    assert_eq!(owner.profile().device(), 0x9d60);
    let registers = owner.registers.as_mut().unwrap();
    assert_eq!(registers.read32(RESET), Ok(7));
    assert_eq!(registers.read32(REMAP_LOW), Ok(physical as u32));
    assert_eq!(registers.read32(REMAP_HIGH), Ok((physical >> 32) as u32));
    assert_eq!(registers.read32(WINDOW_BYTES), Err(Error::Mapping));
    assert_eq!(registers.write32(1, 0), Err(Error::Mapping));
    for counts in [&config_counts, &bar_counts] {
        assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
        assert_eq!(counts.resource_drops.load(Ordering::Relaxed), 0);
    }
    // SAFETY: private core only; no child was published.
    let retired = unsafe { owner.retire() }.unwrap();
    release_native(retired.into_resources(), &config_counts, &bar_counts);
}
#[test]
fn concrete_native_live_and_uncertain_child_owners_keep_original_platform_resources() {
    for stage in 0..4 {
        let (function, mapping, config_counts, bar_counts) = native_fixture();
        if stage >= 2 {
            let pointer = mapping.address(0, PRIVATE).unwrap().cast::<u32>();
            // SAFETY: no user has claimed these isolated registers;
            // source component words and frozen enable status are hardware
            // observations, independent of the production engine.
            unsafe {
                pointer.as_ptr().add(0xfc / 4).write_volatile(0x4457_0140);
                pointer
                    .as_ptr()
                    .add(0xf4 / 4)
                    .write_volatile(2 | (1 << 7) | (2 << 2) | (3 << 16) | (3 << 8));
                pointer.as_ptr().add(0xf8 / 4).write_volatile(0x3131_312a);
                pointer
                    .as_ptr()
                    .add(0x9c / 4)
                    .write_volatile(u32::from(stage == 2));
            }
        }
        // SAFETY: same stopped owner and isolated BAR fixture.
        let registers = match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
            Ok(registers) => registers,
            Err((error, _)) => panic!("valid mapped owner: {error:?}"),
        };
        let owner = match Controller::initialize(registers) {
            Ok(owner) => owner,
            Err((error, _)) => panic!("valid private core: {error:?}"),
        };
        if stage == 0 {
            drop(owner);
        } else {
            // SAFETY: exact isolated source clock/timing fixture. This
            // exercises real volatile NativeRegisters and the DW
            // constructor, not the generic protocol Register model.
            let child = unsafe { owner.into_i2c(Time(Rc::new(Cell::new(0))), timing()) };
            match stage {
                1 => assert!(matches!(
                    child.err().unwrap().kind,
                    crate::bus::i2c::ErrorKind::ComponentType(0)
                )),
                2 => assert_eq!(
                    child.err().unwrap().kind,
                    crate::bus::i2c::ErrorKind::Timeout(crate::bus::i2c::Phase::Disable)
                ),
                3 => drop(child.unwrap()),
                _ => unreachable!(),
            }
        }
        for counts in [&config_counts, &bar_counts] {
            assert_eq!(counts.unmaps.load(Ordering::Relaxed), 0);
            assert_eq!(counts.resource_drops.load(Ordering::Relaxed), 0);
            assert_eq!(counts.platform_drops.load(Ordering::Relaxed), 0);
        }
    }
}

#[test]
fn concrete_native_rejections_return_exact_unmodified_mapping_and_config_owners() {
    for scenario in 0..5 {
        let (mut function, mut mapping, config_counts, bar_counts) = native_fixture();
        match scenario {
            0 => function.config().write32(0x10, 0x1234_0004),
            1 => function.config().write32(0x10, 1),
            2 => function
                .config()
                .write16(regs::COMMAND, regs::COMMAND_INTX_DISABLE),
            3 => function.config().write32(0x14, u32::MAX),
            4 => {
                // SAFETY: no register user/engine exists; the retired
                // mapping must not be silently resurrected by the adapter.
                unsafe { mapping.retire() }.unwrap();
            }
            _ => unreachable!(),
        }
        // SAFETY: same isolated stopped fixture, invalid BAR
        // metadata or decode. Rejection must not produce any MMIO effect.
        let (error, resources) =
            match unsafe { NativeRegisters::claim(stop_fixture(function), mapping) } {
                Err(rejected) => rejected,
                Ok(_) => panic!("invalid resources admitted"),
            };
        assert_eq!(
            error,
            if scenario == 2 {
                Error::Configuration
            } else {
                Error::Mapping
            }
        );
        assert_eq!(config_counts.unmaps.load(Ordering::Relaxed), 0);
        if scenario != 4 {
            release_native(resources, &config_counts, &bar_counts);
        } else {
            let (function, mapping) = resources;
            assert!(mapping.address(0, 4).is_err());
            drop(mapping);
            let mut mapping = function.into_config().into_mapping();
            // SAFETY: same original no-user RAM fixture.
            unsafe { mapping.retire() }.unwrap();
            assert_eq!(config_counts.unmaps.load(Ordering::Relaxed), 1);
            assert_eq!(bar_counts.unmaps.load(Ordering::Relaxed), 1);
        }
    }
}

#[test]
fn exact_nine_profiles_program_source_reset_and_full_physical_remap() {
    for device in [
        0x9d60, 0x9d61, 0x9d62, 0x9d63, 0x9d64, 0x9d65, 0xa160, 0xa161, 0xa162,
    ] {
        for base in [0x8000_0000, 0x1_0000_0000, 0x7fff_e123_4000] {
            for caps in [0, 1 << 8] {
                let (registers, h, drops) = model(device, base, caps);
                let owner = Controller::initialize(registers).unwrap();
                assert_eq!(owner.profile().device(), device);
                assert_eq!(owner.profile().input_clock_hz(), 120_000_000);
                assert_eq!(owner.profile().source_sda_hold_ns(), 230);
                assert_eq!(
                    h.borrow().writes,
                    [
                        (RESET, 0),
                        (RESET, 7),
                        (REMAP_LOW, base as u32),
                        (REMAP_HIGH, (base >> 32) as u32)
                    ]
                );
                assert_eq!(drops.get(), 0);
                // SAFETY: no child was published; model has no async users.
                let retired = unsafe { owner.retire() }.unwrap();
                assert_eq!(h.borrow().writes.last(), Some(&(RESET, 0)));
                drop(retired.registers);
                assert_eq!(drops.get(), 1);
            }
        }
    }
}
#[test]
fn metadata_refusals_return_unmodified_resources_without_register_writes() {
    for (device, base, caps) in [
        (0x9d5f, 0x8000_0000, 0),
        (0xa163, 0x8000_0000, 0),
        (0x9d60, 0, 0),
        (0x9d60, 0x8000_0001, 0),
        (0x9d60, 0x8000_0000, 0x10),
        (0x9d60, 0x8000_0000, 0x20),
        (0x9d60, 0x8000_0000, u32::MAX),
    ] {
        let (registers, h, drops) = model(device, base, caps);
        let (_, registers) = Controller::initialize(registers).err().unwrap();
        assert!(registers.is_some());
        assert!(h.borrow().writes.is_empty());
        assert_eq!(drops.get(), 0);
        drop(registers);
        assert_eq!(drops.get(), 1);
    }
}
#[test]
fn every_access_fault_preserves_original_failure_and_post_effect_owners() {
    for call in 1..=10 {
        for after in [false, true] {
            let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
            h.borrow_mut().fail = Some((call, after));
            let (error, returned) = Controller::initialize(registers).err().unwrap();
            assert!(matches!(error, Error::Io | Error::Identity));
            assert_eq!(returned.is_some(), call <= 2);
            assert_eq!(drops.get(), 0);
            if let Some(registers) = returned {
                drop(registers);
                assert_eq!(drops.get(), 1);
            } else {
                assert_eq!(
                    drops.get(),
                    0,
                    "uncertain real register owner must stay retained"
                );
            }
            assert_eq!(
                h.borrow().calls,
                call,
                "no retry after the first uncertain effect"
            );
        }
    }
}
#[test]
fn ignored_program_and_retirement_writes_do_not_release_owners() {
    for offset in [RESET, REMAP_LOW, REMAP_HIGH] {
        let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
        h.borrow_mut().reject = Some(offset);
        let (error, returned) = Controller::initialize(registers).err().unwrap();
        assert!(matches!(error, Error::Register { offset: actual, .. } if actual == offset));
        assert!(returned.is_none());
        assert_eq!(drops.get(), 0);
    }
    let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
    let owner = Controller::initialize(registers).unwrap();
    h.borrow_mut().reject = Some(RESET);
    // SAFETY: no child was published; reset failure must quarantine.
    assert!(unsafe { owner.retire() }.is_err());
    assert_eq!(drops.get(), 0);
    let (registers, _, drops) = model(0x9d60, 0x1_2345_0000, 0);
    drop(Controller::initialize(registers).unwrap());
    assert_eq!(drops.get(), 0, "live Drop is not acknowledged retirement");
}
#[test]
fn real_designware_child_drives_combined_pio_and_acknowledged_retirement() {
    use crate::bus::i2c::{Address, Bus, Operation};
    let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
    let owner = Controller::initialize(registers).unwrap();
    // SAFETY: literal timing belongs to this modeled source clock and
    // finite peer; no guessed production board permission is supplied.
    let mut bus =
        unsafe { owner.into_i2c(Time(Rc::new(Cell::new(u64::MAX - 10))), timing()) }.unwrap();
    let mut bytes = [0; 2];
    bus.transaction(
        Address::SevenBit(0x2c),
        &mut [Operation::Write(&[0x80, 0x55]), Operation::Read(&mut bytes)],
    )
    .unwrap();
    assert_eq!(bytes, [0x31, 0x32]);
    assert_eq!(
        h.borrow().commands,
        [0x80, 0x55, (1 << 8) | (1 << 10), (1 << 8) | (1 << 9)]
    );
    assert_eq!(h.borrow().words[0x30 / 4], 0);
    assert_eq!(h.borrow().words[0xcc / 4], 0);
    assert_eq!(h.borrow().words[0x88 / 4], 0);
    assert_eq!(drops.get(), 0);
    let (retired, _) = bus.shutdown().unwrap();
    assert_eq!(h.borrow().writes.last(), Some(&(RESET, 0)));
    drop(retired.registers);
    assert_eq!(drops.get(), 1);
}
#[test]
fn real_child_init_shutdown_and_live_drop_failures_keep_platform_grants() {
    for stage in 0..3 {
        let (registers, h, drops) = model(0x9d60, 0x1_2345_0000, 0);
        let owner = Controller::initialize(registers).unwrap();
        if stage == 0 {
            h.borrow_mut().stuck_disable = true;
        }
        // SAFETY: same isolated literal timing and model owner.
        let result = unsafe { owner.into_i2c(Time(Rc::new(Cell::new(0))), timing()) };
        if stage == 0 {
            assert!(result.is_err());
        } else {
            let bus = result.unwrap();
            if stage == 1 {
                h.borrow_mut().stuck_disable = true;
                assert!(bus.shutdown().is_err());
            } else {
                drop(bus);
            }
        }
        assert_eq!(
            drops.get(),
            0,
            "failed/live child never releases root/mapping authority"
        );
    }
}
#[test]
#[ignore = "oracle: STELA_LPSS_PROFILE_ORACLE"]
fn unchanged_source_all_pci_i2c_profiles_and_property_groups() {
    extern crate std;
    let trace = std::fs::read_to_string(
        std::env::var("STELA_LPSS_PROFILE_ORACLE").expect("source profile trace path"),
    )
    .unwrap();
    let mut expected = Vec::new();
    for line in trace.lines() {
        let values: Vec<u32> = line
            .split(',')
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(values.len(), 5);
        let device = u16::try_from(values[0]).unwrap();
        assert!(
            !expected.contains(&device),
            "donor profile ID is not unique"
        );
        expected.push(device);
        let profile = Profile::select(Identity {
            vendor: 0x8086,
            device,
            subsystem_vendor: 0,
            subsystem_device: 0,
        })
        .unwrap();
        assert_eq!(profile.input_clock_hz(), values[1]);
        assert_eq!(profile.source_sda_hold_ns(), values[2]);
        assert_eq!(profile.source_sda_fall_ns().unwrap_or(u32::MAX), values[3]);
        assert_eq!(profile.source_scl_fall_ns().unwrap_or(u32::MAX), values[4]);
        // Execute private native reset/remap for every source profile,
        // with a high remap address independent of CPU storage.
        let (registers, _, _) = model(device, 0x1_2345_0000, 0);
        let owner = Controller::initialize(registers).unwrap();
        assert_eq!(owner.profile(), profile);
        // SAFETY: isolated register model, no child or DMA publication.
        drop(unsafe { owner.retire() }.unwrap().registers);
    }
    assert_eq!(expected.len(), 190);
    expected.sort_unstable();
    for device in 0..=u16::MAX {
        for vendor in [0x8086, 0x1022, 0xffff] {
            let identity = Identity {
                vendor,
                device,
                subsystem_vendor: 0,
                subsystem_device: 0,
            };
            assert_eq!(
                Profile::select(identity).is_ok(),
                vendor == 0x8086 && expected.binary_search(&device).is_ok()
            );
        }
    }
}

#[test]
#[ignore = "oracle: STELA_LPSS_ORACLE"]
fn unchanged_source_reset_remap_effects() {
    extern crate std;
    let trace =
        std::fs::read_to_string(std::env::var("STELA_LPSS_ORACLE").expect("source trace path"))
            .unwrap();
    let mut cases = 0;
    for line in trace.lines() {
        let fields: Vec<_> = line.split(',').collect();
        let type_field: u32 = fields[0].parse().unwrap();
        let absent: u32 = fields[1].parse().unwrap();
        let old: u32 = fields[2].parse().unwrap();
        let base: u64 = fields[3].parse().unwrap();
        let (registers, h, drops) = model(0x9d60, base, type_field << 4 | absent << 8);
        h.borrow_mut().words[RESET / 4] = old;
        if type_field == 0 {
            let owner = Controller::initialize(registers).unwrap();
            let actual: Vec<_> = h
                .borrow()
                .writes
                .iter()
                .map(|(offset, value)| alloc::format!("{}:{}", offset - PRIVATE, value))
                .collect();
            assert_eq!(actual, fields[4..]);
            // SAFETY: pure source model, no child/IRQ/DMA publication.
            drop(unsafe { owner.retire() }.unwrap().registers);
        } else {
            let (error, returned) = Controller::initialize(registers).err().unwrap();
            assert_eq!(error, Error::Unsupported);
            assert!(h.borrow().writes.is_empty());
            drop(returned);
        }
        assert_eq!(drops.get(), 1);
        cases += 1;
    }
    assert_eq!(cases, 6144);
}
