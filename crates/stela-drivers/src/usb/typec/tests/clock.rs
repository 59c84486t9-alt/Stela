//! Native calibration/maximum-budget rejection must precede all device effects.
use super::super::{
    mux::{self, PowerOperation, ResourceError},
    tps6598x,
    ucsi::{self, TransportError},
};
use crate::{
    Clock,
    bus::i2c::{self, Address, Operation},
};
use core::num::NonZeroU16;

struct NoIo;
impl i2c::Bus for NoIo {
    fn transaction(
        &mut self,
        _address: Address,
        _operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::Error> {
        panic!("invalid native clock reached I2C")
    }
}
impl mux::Power for NoIo {
    fn set(&mut self, _operation: PowerOperation) -> Result<(), ResourceError> {
        panic!("invalid native clock changed power")
    }
}
impl mux::pmc::scu::Registers for NoIo {
    fn read32(&mut self, _offset: usize) -> Result<u32, mux::pmc::scu::RegisterError> {
        panic!("invalid native clock reached IPC read")
    }
    fn write32(&mut self, _offset: usize, _value: u32) -> Result<(), mux::pmc::scu::RegisterError> {
        panic!("invalid native clock published IPC")
    }
}
impl ucsi::Transport for NoIo {
    fn read_version(&mut self) -> Result<u16, TransportError> {
        panic!("invalid native clock reached PPM")
    }
    fn poll_cci(&mut self) -> Result<u32, TransportError> {
        panic!("invalid native clock polled PPM")
    }
    fn read_message_in(&mut self, _bytes: &mut [u8]) -> Result<(), TransportError> {
        panic!("invalid native clock read PPM message")
    }
    fn write_message_out(&mut self, _bytes: &[u8]) -> Result<(), TransportError> {
        panic!("invalid native clock wrote PPM message")
    }
    fn write_control(&mut self, _control: u64) -> Result<(), TransportError> {
        panic!("invalid native clock published PPM command")
    }
}
fn invalid(budget: u64, case: usize) -> Clock {
    Clock {
        ticks_per_microsecond: match case {
            0 => 0,
            1 => u64::MAX,
            2 => ((1u64 << 63) - 1) / budget + 1,
            _ => unreachable!(),
        },
    }
}

#[test]
fn native_ucsi_rejects_zero_overflow_and_half_period_clock_before_even_version_refresh() {
    for case in 0..3 {
        assert!(matches!(
            ucsi::Controller::new(NoIo, invalid(10_000_000, case)),
            Err(ucsi::Error::TimerBudget {
                microseconds: 10_000_000
            })
        ));
    }
}
#[test]
fn native_ccg_rejects_invalid_clock_before_hpi_control_or_interrupt_ack() {
    for case in 0..3 {
        assert!(matches!(
            ucsi::ccg::Ccg::start(
                NoIo,
                Address::SevenBit(0x20),
                NonZeroU16::new(32).unwrap(),
                &invalid(100_000, case)
            ),
            Err(ucsi::ccg::StartError::TimerBudget {
                microseconds: 100_000
            })
        ));
    }
}
#[test]
fn native_tps_rejects_invalid_clock_before_identity_or_any_pd_task() {
    for case in 0..3 {
        let mut pd =
            tps6598x::Tps6598x::new(NoIo, Address::SevenBit(0x20), invalid(1_000_000, case));
        assert_eq!(
            pd.initialize(None, None),
            Err(tps6598x::Error::TimerBudget {
                microseconds: 1_000_000
            })
        );
        assert!(!pd.ready());
        assert!(pd.identity().is_none());
    }
}
#[test]
fn native_ps8830_rejects_invalid_clock_before_supplies_clock_reset_or_registers() {
    for case in 0..3 {
        let mut retimer =
            mux::ps8830::Ps8830::new(NoIo, Address::SevenBit(0x20), NoIo, invalid(60_000, case));
        assert_eq!(
            retimer.initialize(),
            Err(mux::Error::TimerBudget {
                microseconds: 60_000
            })
        );
    }
}
#[test]
fn native_scu_rejects_invalid_clock_before_status_payload_or_publish() {
    for case in 0..3 {
        let mut ipc = mux::pmc::scu::Scu::new(NoIo, invalid(10_000_000, case));
        assert_eq!(
            ipc.command(1, 0, &[], &mut []),
            Err(mux::pmc::scu::Error::TimerBudget {
                microseconds: 10_000_000
            })
        );
        assert!(ipc.last_receipt().is_none());
    }
}
