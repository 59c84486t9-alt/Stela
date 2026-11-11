//! Registers read without the devices' lock, and the USB schedule a write
//! that did not reach it leaves to its work.
use super::*;
use stela_engine::machine::engine::LockedMemory;

const CPM: u64 = 0x2_1100_0000;
const ENERGY: u64 = 0x2_1200_0000;

/// Every passive word reads what the model reads, after each write, and
/// only 64-bit reads of described, readable words are passive.
#[test]
fn passive_reads_equal_the_models_and_leave_the_rest_to_it() {
    let mut d = AppleDevices::new();
    assert!(d.passive_registers().is_none());
    d.add_cpm_power(CPM, true).unwrap();
    d.add_cpu_energy(ENERGY, true).unwrap();
    let passive = d.passive_registers().expect("CPM and energy words");
    let words: Vec<u64> = Cpm::new(true)
        .offsets()
        .into_iter()
        .map(|offset| CPM + offset)
        .chain([ENERGY, ENERGY + 8, ENERGY + 0x80])
        .collect();
    let enable = CPM + stela_soc_data::cpm::COUNTER_ENABLE;
    for (n, &physical) in words.iter().enumerate() {
        if physical == enable {
            assert_eq!(passive.read(physical, 8), None);
            assert!(d.read(0, physical, 8, 0).is_err());
            continue;
        }
        assert_eq!(passive.read(physical, 8), Some(0), "{physical:#x}");
        let value = 0x8000_0000_0000_0001 | (n as u64) << 8;
        d.write(0, physical, 8, value, 0).unwrap();
        assert_eq!(passive.read(physical, 8), Some(value), "{physical:#x}");
        assert_eq!(d.read(0, physical, 8, 0), Ok(value));
        assert_eq!(passive.read(physical, 4), None);
        assert_eq!(passive.read(physical + 4, 8), None);
    }
    // An undescribed word between described ones refuses the locked way.
    assert_eq!(passive.read(CPM + 0x4004, 8), None);
    assert_eq!(passive.read(ENERGY + 0x10, 8), None);
}

struct Locked<'a>(&'a mut Ram);
impl LockedMemory for Locked<'_> {
    fn under(
        &mut self,
        _: stela_engine::machine::mmu::MemoryLocks,
    ) -> &mut dyn stela_engine::machine::engine::Memory {
        self.0
    }
}

/// A USB master with work runs after a write to another device; one
/// without keeps its state as the full step would.
#[test]
fn a_write_elsewhere_runs_the_usb_schedule_only_with_work() {
    let mut d = AppleDevices::new();
    let dart = d
        .add_dart(
            Range {
                physical: 0x382f00000,
                bytes: 0x4000,
            },
            16,
            None,
            None,
        )
        .unwrap();
    let phy = add_usb_phy(&mut d);
    let placement = usb_placement();
    d.add_usb(&placement, dart).unwrap();
    release_usb_phy(&mut d, &phy);
    d.add_cpm_power(CPM, false).unwrap();
    let base = placement.ranges[0].0;
    let mut ram = Ram::new(0x800000000, 0x10000);
    let settle = |d: &mut AppleDevices, ram: &mut Ram| {
        d.write(0, CPM + 0x250, 8, 1, 0).unwrap();
        d.settle_write(0, 0, &mut Locked(ram)).transfer
    };
    // Nothing to do: the write elsewhere settles, as a full step does.
    assert!(settle(&mut d, &mut ram).is_ok());
    assert!(d.transfer(0, &mut ram, 0).is_ok());
    // An event ring to load through the still disabled DART stream: the
    // schedule has work, so the write elsewhere runs it and its refusal.
    let table = 0x800008000u64;
    ram.put_u64(table, 0x800009000);
    ram.put_u64(table + 8, 16);
    d.write(0, base + 0x468, 4, 1, 0).unwrap();
    d.write(0, base + 0x470, 4, table as u32 as u64, 0).unwrap();
    d.write(0, base + 0x474, 4, table >> 32, 0).unwrap();
    let error = settle(&mut d, &mut ram).unwrap_err();
    assert!(
        matches!(error, DeviceError::TransferRefused(ref reason) if reason.to_string().starts_with("USB device advance:")),
        "{error:?}"
    );
}

/// Host cost of a CLPC counter read through a shared board, locked and
/// passive, and of a write elsewhere's transfer with a USB master, full and
/// with the schedule left to its work: `cargo test --release -p stela-soc
/// --lib machine::tests::passive::access_costs -- --ignored --nocapture`.
#[test]
#[ignore = "manual: opt-in"]
fn access_costs() {
    extern crate std;
    use stela_engine::machine::engine::{Hub, Kick, ScalarRead, SharedDevices};
    use stela_engine::machine::{Devices, Lines};
    struct Quiet;
    impl Kick for Quiet {
        fn kick(&self, _: usize) {}
    }
    /// The board without its passive registers: every read takes the lock.
    struct Locked(AppleDevices);
    impl Devices for Locked {
        fn read(&mut self, cpu: usize, at: u64, bytes: u8, now: u64) -> Result<u64, DeviceError> {
            self.0.read(cpu, at, bytes, now)
        }
        fn write(
            &mut self,
            cpu: usize,
            at: u64,
            bytes: u8,
            value: u64,
            now: u64,
        ) -> Result<(), DeviceError> {
            self.0.write(cpu, at, bytes, value, now)
        }
        fn read_scalar(&mut self, cpu: usize, at: u64, bytes: u8, now: u64) -> ScalarRead {
            self.0.read_scalar(cpu, at, bytes, now)
        }
        fn lines(&mut self, cpu: usize, now: u64) -> Lines {
            self.0.lines(cpu, now)
        }
        fn pins(&mut self, cpu: usize) -> Option<Lines> {
            self.0.pins(cpu)
        }
        fn dma_deadline(&self) -> Option<u64> {
            self.0.dma_deadline()
        }
    }
    let board = || {
        let mut d = AppleDevices::new();
        let dart = d
            .add_dart(
                Range {
                    physical: 0x382f00000,
                    bytes: 0x4000,
                },
                16,
                None,
                None,
            )
            .unwrap();
        let phy = add_usb_phy(&mut d);
        d.add_usb(&usb_placement(), dart).unwrap();
        release_usb_phy(&mut d, &phy);
        d.add_cpm_power(CPM, false).unwrap();
        d
    };
    const N: u64 = 200_000;
    let time = |f: &mut dyn FnMut(u64)| {
        let start = std::time::Instant::now();
        for n in 0..N {
            f(n);
        }
        start.elapsed().as_nanos() as u64 / N
    };
    let counter = CPM + 0x4000;
    let mut locked = SharedDevices::new(Locked(board()), Hub::new(8, Quiet)).worker();
    let mut passive = SharedDevices::new(board(), Hub::new(8, Quiet)).worker();
    let locked_ns = time(&mut |n| {
        assert!(matches!(
            locked.read_scalar(1, counter, 8, n),
            ScalarRead::Served(Ok(_))
        ));
    });
    let passive_ns = time(&mut |n| {
        assert!(matches!(
            passive.read_scalar(1, counter, 8, n),
            ScalarRead::Served(Ok(_))
        ));
    });
    let mut d = board();
    let mut ram = Ram::new(0x800000000, 0x10000);
    let full_ns = time(&mut |n| {
        d.write(0, CPM + 0x250, 8, n, n).unwrap();
        d.transfer(0, &mut ram, n).unwrap();
    });
    let settled_ns = time(&mut |n| {
        d.write(0, CPM + 0x250, 8, n, n).unwrap();
        d.settle_write(0, n, &mut Locked2(&mut ram))
            .transfer
            .unwrap();
    });
    std::println!(
        "CPM counter read: locked {locked_ns} ns, passive {passive_ns} ns; \
         write elsewhere + transfer: full {full_ns} ns, USB left to its work {settled_ns} ns"
    );
}

struct Locked2<'a>(&'a mut Ram);
impl LockedMemory for Locked2<'_> {
    fn under(
        &mut self,
        _: stela_engine::machine::mmu::MemoryLocks,
    ) -> &mut dyn stela_engine::machine::engine::Memory {
        self.0
    }
}

/// A cluster's described words read passively as the model reads them,
/// a state command included once it completes; other words stay locked.
#[test]
fn cluster_words_read_passively_as_the_model_reads_them() {
    const CLUSTER: u64 = 0x2_1300_0000;
    let mut d = AppleDevices::new();
    d.add_cpu_cluster(CLUSTER, &[(0x206a8, 5)], 18, 4, true, &[1])
        .unwrap();
    let passive = d.passive_registers().expect("cluster words");
    let command = CLUSTER + 0x20020;
    assert_eq!(passive.read(CLUSTER + 0x206a8, 8), Some(5));
    // A state change: the SET request is not kept.
    d.write(0, command, 8, (1 << 25) | 3, 0).unwrap();
    assert_eq!(passive.read(command, 8), Some(3));
    assert_eq!(d.read(0, command, 8, 0), Ok(3));
    // A refused command changes neither.
    assert!(d.write(0, command, 8, 4, 0).is_err());
    assert_eq!(passive.read(command, 8), Some(3));
    for physical in [
        CLUSTER + 0x20400,
        CLUSTER + 0x20588,
        CLUSTER + 0x78000 + 0x10,
        CLUSTER + 0x7ffe8,
    ] {
        d.write(0, physical, 8, 0x77, 0).unwrap();
        assert_eq!(passive.read(physical, 8), Some(0x77), "{physical:#x}");
        assert_eq!(d.read(0, physical, 8, 0), Ok(0x77));
    }
    // Undescribed words and other widths read the locked way.
    assert_eq!(passive.read(CLUSTER + 0x20028, 8), None);
    assert!(d.read(0, CLUSTER + 0x20028, 8, 0).is_err());
    assert_eq!(passive.read(command, 4), None);
}

/// Another PE's load of a core counter reads, without the lock, the value
/// the core's own MSR wrote, and slots past the layout stay locked.
#[test]
fn core_counter_loads_read_the_msr_view_passively() {
    use stela_compiler::aarch64::system::registers::Encoding;
    const IMPL: u64 = 0x2_1010_0000;
    let mut d = AppleDevices::new();
    let layout = stela_soc_data::core_counters::layout(0x8112).unwrap();
    d.add_core_counters(1, IMPL, layout).unwrap();
    let passive = d.passive_registers().expect("counter slots");
    let registers = d.local_registers(1).expect("PE 1's counters");
    // AON slot 1 is S3_7_C15_C2_3; memory-stall slot 2 is S3_1_C15_C10_3.
    registers.register(Encoding::new(3, 7, 15, 2, 3), Some(41));
    registers.register(Encoding::new(3, 1, 15, 10, 3), Some(42));
    assert_eq!(passive.read(IMPL + 0x4010, 8), Some(41));
    assert_eq!(passive.read(IMPL + 0x6040, 8), Some(42));
    assert_eq!(d.read(0, IMPL + 0x4010, 8, 0), Ok(41));
    // The T8112 has three AON and four stall slots.
    assert_eq!(passive.read(IMPL + 0x4030, 8), None);
    assert_eq!(passive.read(IMPL + 0x6050, 8), None);
    assert_eq!(passive.read(IMPL + 0x4008, 8), None);
}
