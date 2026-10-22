//! Actual PTD effects, never service replies inferred from a resource request.
use super::{Error, Operation, Packets, Value};
use crate::platform::apple::{
    bus::{Access, MmioDevice, Width},
    ptd::{Range, UPDATE_OFFSET, transport::notifications::LocalNotifications},
};
use alloc::vec::Vec;

pub(super) fn publish(
    local: &LocalNotifications,
    entry: u32,
    value: u64,
    access: &mut Access<'_>,
) -> Result<(), Error> {
    local
        .bank()
        .clone()
        .write(
            UPDATE_OFFSET + u64::from(entry) * 8,
            Width::Double,
            value,
            access,
        )
        .map_err(Error::Mmio)
}

fn masks(ops: &mut Vec<Operation>, range: &Range, base: u64) {
    let end = range.start + range.count;
    let mut start = range.start;
    while start < end {
        let word = start / 32;
        let count = (32 - start % 32).min(end - start);
        let mask = u32::MAX >> (32 - count) << (start % 32);
        ops.push(Operation::Enable {
            offset: base + u64::from(word) * 4,
            mask,
        });
        start += count;
    }
}

pub(super) fn route_and_enable(ops: &mut Vec<Operation>, range: &Range, route: u8) {
    for entry in range.start..range.start + range.count {
        ops.push(Operation::Route { entry, route });
    }
    masks(ops, range, 0x18200);
}
pub(super) fn disable(ops: &mut Vec<Operation>, range: &Range) {
    masks(ops, range, 0x18300);
}

pub(super) fn apply(
    local: &LocalNotifications,
    operation: Operation,
    packets: Option<Packets>,
    access: &mut Access<'_>,
) -> Result<(), Error> {
    let mut bank = local.bank().clone();
    match operation {
        Operation::Publish { entry, value } => {
            let value = match value {
                Value::Constant(value) => value,
                Value::Packet(index) => {
                    packets
                        .ok_or(Error::Contract("PMP publication has no refreshed state"))?
                        .0[index]
                }
            };
            publish(local, entry, value, access)
        }
        Operation::Route { entry, route } => {
            let offset = 0x18400 + u64::from(entry / 8) * 4;
            let shift = (entry % 8) * 4;
            let old = bank
                .read(offset, Width::Word, access)
                .map_err(Error::Mmio)?;
            let value = (old & !(0xf << shift)) | u64::from(route) << shift;
            bank.write(offset, Width::Word, value, access)
                .map_err(Error::Mmio)
        }
        Operation::Enable { offset, mask } => bank
            .write(offset, Width::Word, u64::from(mask), access)
            .map_err(Error::Mmio),
        _ => Err(Error::Contract(
            "PMP transport received a resource operation",
        )),
    }
}
