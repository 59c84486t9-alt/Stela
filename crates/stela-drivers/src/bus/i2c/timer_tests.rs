//! Actual native-clock admission must precede all controller/provider accesses.
use super::*;
use crate::bus::{
    dma::{DmaAllocator, RegionAllocator},
    lpss, smbus, spi,
};
use alloc::{boxed::Box, rc::Rc, vec};
use core::cell::Cell;

struct NoIo(Rc<Cell<usize>>);
impl Drop for NoIo {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
impl Registers for NoIo {
    fn read32(&mut self, _: usize) -> u32 {
        panic!("register read before timing admission")
    }
    fn write32(&mut self, _: usize, _: u32) {
        panic!("register write before timing admission")
    }
}
impl smbus::i801::Registers for NoIo {
    fn read8(&mut self, _: u8) -> u8 {
        panic!("I801 read before timing admission")
    }
    fn write8(&mut self, _: u8, _: u8) {
        panic!("I801 write before timing admission")
    }
}
impl smbus::piix4::Registers for NoIo {
    fn read8(&mut self, _: u8) -> u8 {
        panic!("PIIX4 read before timing admission")
    }
    fn write8(&mut self, _: u8, _: u8) {
        panic!("PIIX4 write before timing admission")
    }
}
// SAFETY: trapped exclusive model providers; invalid admission must never call
// any device operation. No physical or external asynchronous user exists.
unsafe impl spi::amd::Registers for NoIo {
    fn profile(&self) -> spi::amd::Profile {
        panic!("profile access before admission")
    }
    fn read8(&mut self, _: usize) -> Result<u8, spi::amd::IoError> {
        panic!("SPI read before admission")
    }
    fn write8(&mut self, _: usize, _: u8) -> Result<(), spi::amd::IoError> {
        panic!("SPI write before admission")
    }
    fn read32(&mut self, _: usize) -> Result<u32, spi::amd::IoError> {
        panic!("SPI read before admission")
    }
    fn write32(&mut self, _: usize, _: u32) -> Result<(), spi::amd::IoError> {
        panic!("SPI write before admission")
    }
}
// SAFETY: same trapped explicit model; descriptor/extent callbacks also trap.
unsafe impl spi::pxa2xx::Registers for NoIo {
    fn description(&self) -> spi::pxa2xx::Description {
        panic!("description before admission")
    }
    fn bytes(&self) -> usize {
        panic!("extent before admission")
    }
    fn read32(&mut self, _: usize) -> Result<u32, spi::pxa2xx::IoError> {
        panic!("SSP read before admission")
    }
    fn write32(&mut self, _: usize, _: u32) -> Result<(), spi::pxa2xx::IoError> {
        panic!("SSP write before admission")
    }
}
// SAFETY: trapped retained LPSS resource model, never a hardware mapping.
unsafe impl lpss::Registers for NoIo {
    fn identity(&mut self) -> Result<lpss::Identity, lpss::Error> {
        panic!("identity before admission")
    }
    fn physical_base(&self) -> u64 {
        panic!("base before admission")
    }
    fn read32(&mut self, _: usize) -> Result<u32, lpss::Error> {
        panic!("private read before admission")
    }
    fn write32(&mut self, _: usize, _: u32) -> Result<(), lpss::Error> {
        panic!("private write before admission")
    }
}
// SAFETY: trapped exclusive firmware mailbox model; no request was published.
unsafe impl amd_mp2::Registers for NoIo {
    fn read32(&mut self, _: usize) -> Result<u32, amd_mp2::IoError> {
        panic!("mailbox read before admission")
    }
    fn write32(&mut self, _: usize, _: u32) -> Result<(), amd_mp2::IoError> {
        panic!("mailbox write before admission")
    }
    fn read_payload(&mut self, _: &mut [u8]) -> Result<(), amd_mp2::IoError> {
        panic!("payload read before admission")
    }
    fn write_payload(&mut self, _: &[u8]) -> Result<(), amd_mp2::IoError> {
        panic!("payload write before admission")
    }
}
fn no_io() -> (NoIo, Rc<Cell<usize>>) {
    let drops = Rc::new(Cell::new(0));
    (NoIo(drops.clone()), drops)
}
fn clock(rate: u64) -> Clock {
    Clock {
        ticks_per_microsecond: rate,
    }
}
const BUDGET: u64 = 1000;

#[test]
fn native_unavailable_overflow_and_half_period_clocks_refuse_designware_and_smbus_before_io() {
    for rate in [0, u64::MAX, u64::MAX / 2 / BUDGET + 1] {
        let (r, d) = no_io();
        let config = Config {
            timing: Timing {
                speed: Speed::Standard,
                scl_high: 100,
                scl_low: 100,
                sda_hold: None,
            },
            timeout_us: BUDGET,
            recovery_timeout_us: 100,
        };
        assert_eq!(
            DesignWare::new(r, clock(rate), config).err().unwrap().kind,
            ErrorKind::InvalidConfiguration
        );
        assert_eq!(d.get(), 1);
        let (r, d) = no_io();
        let info = smbus::i801::ControllerInfo::from_pci_id(0x8086, 0x7e22).unwrap();
        let config = smbus::i801::Config {
            timeout_us: BUDGET,
            recovery_timeout_us: 100,
            use_block_buffer: true,
        };
        assert_eq!(
            smbus::i801::I801::new(r, clock(rate), info, 1, config)
                .err()
                .unwrap()
                .kind,
            smbus::ErrorKind::InvalidConfiguration
        );
        assert_eq!(d.get(), 1);
        let (r, d) = no_io();
        let info = smbus::piix4::ControllerInfo::from_pci_id(0x8086, 0x7113, 0).unwrap();
        let config = smbus::piix4::Config {
            timeout_us: BUDGET,
            poll_interval_us: 50,
        };
        assert_eq!(
            smbus::piix4::Piix4::new(r, clock(rate), info, config)
                .err()
                .unwrap()
                .kind,
            smbus::ErrorKind::InvalidConfiguration
        );
        assert_eq!(d.get(), 1);
    }
}

#[test]
fn invalid_native_spi_and_mp2_clocks_return_exact_original_unmodified_owners() {
    for rate in [0, u64::MAX, u64::MAX / 2 / BUDGET + 1] {
        let (r, d) = no_io();
        let error = spi::amd::Controller::new(r, clock(rate), BUDGET)
            .err()
            .unwrap();
        assert_eq!(error.0, spi::amd::ErrorKind::Configuration);
        assert_eq!(error.2.ticks_per_microsecond, rate);
        assert_eq!(d.get(), 0);
        drop(error);
        assert_eq!(d.get(), 1);
        let (r, d) = no_io();
        let error = spi::pxa2xx::Controller::new(r, clock(rate), BUDGET)
            .err()
            .unwrap();
        assert_eq!(error.0, spi::pxa2xx::ErrorKind::Configuration);
        assert_eq!(error.2.ticks_per_microsecond, rate);
        assert_eq!(d.get(), 0);
        drop(error);
        assert_eq!(d.get(), 1);
        let (r, d) = no_io();
        // SAFETY: trapped explicit retained model, no device or pending child.
        let error = unsafe { lpss::spi::Spi::attach(r, clock(rate), 1, BUDGET) }
            .err()
            .unwrap();
        assert_eq!(error.0, lpss::spi::Error::Configuration);
        assert!(error.1.is_some());
        assert_eq!(d.get(), 0);
        drop(error);
        assert_eq!(d.get(), 1);
        let backing = Box::leak(vec![0u64; 1024].into_boxed_slice());
        let address = backing.as_mut_ptr() as u64;
        // SAFETY: actual zeroed private model RAM remains pinned for this process.
        let mut allocator =
            unsafe { RegionAllocator::new(address..address + backing.len() as u64 * 8) };
        let buffer = allocator.allocate(amd_mp2::MAX_LENGTH, 8).unwrap();
        let physical = buffer.physical();
        let (r, d) = no_io();
        // SAFETY: isolated stopped mailbox model, retained private coherent RAM;
        // invalid time must return every owner before publishing anything.
        let error = unsafe {
            amd_mp2::Controller::claim(
                r,
                clock(rate),
                buffer,
                [Some(amd_mp2::Speed::Khz400), None],
                BUDGET,
            )
        }
        .err()
        .unwrap();
        assert_eq!(error.0, amd_mp2::ErrorKind::Configuration);
        assert_eq!(error.1.1.ticks_per_microsecond, rate);
        assert_eq!(error.1.2.physical(), physical);
        assert_eq!(d.get(), 0);
        drop(error);
        assert_eq!(d.get(), 1);
    }
}

#[test]
fn default_microsecond_timer_markers_preserve_existing_wrapping_models() {
    struct Time(Cell<u64>);
    impl Timer for Time {
        fn now_us(&self) -> u64 {
            self.0.get()
        }
    }
    let time = Time(Cell::new(u64::MAX - 3));
    let marker = time.start();
    time.0.set(2);
    assert_eq!(time.elapsed_us(marker), 6);
    assert_eq!(time.check_duration(u64::MAX / 2), Ok(()));
    assert_eq!(
        time.check_duration(u64::MAX / 2 + 1),
        Err(crate::ClockError::DurationTooLong)
    );
    assert_eq!(
        Timer::check_duration(&clock(0), 1),
        Err(crate::ClockError::Uncalibrated)
    );
    assert_eq!(
        Timer::check_duration(&clock(u64::MAX), 2),
        Err(crate::ClockError::DurationOverflow)
    );
}
