//! The check every model's plain reads ([`MmioDevice::plain_read`]) pass: a
//! read served again while its model's epoch holds gives what the model
//! gives, and leaving plain reads out changes nothing else the model does.
use crate::bus::{Access, Bus, MmioDevice, Width};
use alloc::boxed::Box;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use stela_contracts::interrupt::InterruptLatch;

/// Where the checked model is mapped.
const BASE: u64 = 0x1_0000_0000;

/// One access the check makes besides plain reads.
pub(crate) enum Op {
    /// A write of one of the values.
    Write(u64, Width, &'static [u64]),
    /// A read that is not plain.
    Read(u64, Width),
    /// The model's advance with time.
    Advance,
}

/// Drive bus models from `make` through random sequences of `ops` and of the
/// plain reads `plain`, which must be plain. One model takes the plain reads
/// and the other none: their every other result and wire stay the same. A
/// plain read's value while the model's epoch holds the count it held at an
/// earlier plain read of the same register is that earlier value, whatever
/// the reading PE and the time.
pub(crate) fn check(
    make: impl Fn() -> Box<dyn MmioDevice>,
    len: u64,
    plain: &[(u64, Width)],
    ops: &[Op],
) {
    let bus = || {
        let mut bus = Bus::new();
        let device = bus.add(make());
        bus.map(device, BASE, len, 0).unwrap();
        bus
    };
    let mut served = 0;
    for seed in 1..=32u64 {
        let (mut read, mut left) = (bus(), bus());
        let (mut read_wires, mut left_wires) = (InterruptLatch::new(), InterruptLatch::new());
        let mut kept: Vec<Option<(Arc<AtomicU64>, u64, u64)>> = alloc::vec![None; plain.len()];
        let mut random = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        for now in 0..512u64 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let pick = (random >> 8) as usize % (ops.len() + plain.len());
            let value = (random >> 40) as usize;
            if let Some(index) = pick.checked_sub(ops.len()) {
                let (offset, width) = plain[index];
                let (epoch, seen) = read
                    .plain_epoch(BASE + offset, width)
                    .unwrap_or_else(|| panic!("{offset:#x} {width:?} is not plain"));
                let cpu = value % 4;
                let got = read.read(
                    BASE + offset,
                    width,
                    &mut Access::new(cpu, now, &mut read_wires),
                );
                assert_eq!(
                    epoch.load(Ordering::SeqCst),
                    seen,
                    "{offset:#x} moved the epoch"
                );
                if let Some((epoch, seen, value)) = &kept[index]
                    && epoch.load(Ordering::SeqCst) == *seen
                {
                    assert_eq!(got, Ok(*value), "{offset:#x} at seed {seed} step {now}");
                    served += 1;
                }
                kept[index] = got.ok().map(|value| (epoch, seen, value));
                continue;
            }
            let (a, b) = match ops[pick] {
                Op::Write(offset, width, values) => {
                    let data = values[value % values.len()];
                    (
                        read.write(
                            BASE + offset,
                            width,
                            data,
                            &mut Access::new(0, now, &mut read_wires),
                        )
                        .map(|()| 0),
                        left.write(
                            BASE + offset,
                            width,
                            data,
                            &mut Access::new(0, now, &mut left_wires),
                        )
                        .map(|()| 0),
                    )
                }
                Op::Read(offset, width) => (
                    read.read(
                        BASE + offset,
                        width,
                        &mut Access::new(0, now, &mut read_wires),
                    ),
                    left.read(
                        BASE + offset,
                        width,
                        &mut Access::new(0, now, &mut left_wires),
                    ),
                ),
                Op::Advance => (
                    read.advance(&mut Access::new(0, now, &mut read_wires))
                        .map(|next| next.unwrap_or(u64::MAX)),
                    left.advance(&mut Access::new(0, now, &mut left_wires))
                        .map(|next| next.unwrap_or(u64::MAX)),
                ),
            };
            assert_eq!(a, b, "seed {seed} step {now}");
            assert_eq!(
                format!("{read_wires:?}"),
                format!("{left_wires:?}"),
                "seed {seed} step {now}"
            );
        }
    }
    assert!(served > 0, "no plain read was served again");
}
