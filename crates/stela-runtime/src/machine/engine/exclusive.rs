//! Exclusive loads and stores and CLREX, which the engine performs against
//! the PE's Exclusives monitor (Arm `AArch64_SetExclusiveMonitors` and
//! `AArch64_ExclusiveMonitorsPass`). The monitor holds the physical
//! Exclusives reservation granule (CTR_EL0.ERG: 64 bytes) of the last
//! exclusive load; a store-exclusive to that granule passes once and clears
//! it, as do CLREX and exception return. On one PE the local and global
//! monitors coincide; `IsExclusiveVA` is TRUE.
use super::{Devices, Host, Machine, RamTables, RequirementKind, Step, Translated};
use crate::machine::{
    cpu::Exception,
    debug,
    exception::Class,
    mmu::{self, Access, MemoryType},
};
use stela_compiler::aarch64::{
    Register,
    exclusive::{Data, Kind, Operand},
};

/// CTR_EL0.ERG = 4: sixteen words.
pub const RESERVATION_GRANULE: u64 = 64;
/// Single-copy-atomicity granule of FEAT_LSE2: an unaligned exclusive that
/// stays inside it does not fault.
const ATOMICITY_GRANULE: u64 = 16;

impl<H: Host, D: Devices> Machine<H, D> {
    pub(super) fn exclusive(&mut self, operand: Operand) -> Step {
        let Operand::Transfer {
            element_bytes,
            base,
            data,
            kind,
        } = operand
        else {
            self.cpu.monitor = None;
            return self.next();
        };
        let pc = self.cpu.pc;
        let address = self.read_register(base);
        if base == Register::Sp && self.stack_alignment_checked() && !address.is_multiple_of(16) {
            self.take(Exception::synchronous(Class::SpAlignment, 0, pc));
            return Ok(());
        }
        let registers = match data {
            Data::Scalar(register) => [Some(register), None],
            Data::Pair(pair) => pair.map(Some),
        };
        let count = registers.iter().flatten().count() as u64;
        let size = u64::from(element_bytes) * count;
        let store = matches!(kind, Kind::Store { .. });
        // Arm `AArch64_UnalignedAccessFaults` for exclusives with FEAT_LSE2:
        // an access crossing a 16-byte granule faults.
        let aligned = address.is_multiple_of(size);
        if !aligned && (address % ATOMICITY_GRANULE) + size > ATOMICITY_GRANULE {
            return self.alignment_fault(address, store);
        }
        let controls = self.cpu.controls(self.cpu.regime());
        let translation = match mmu::translate(
            &controls,
            address,
            if store { Access::Write } else { Access::Read },
            self.cpu.requester(),
            &mut RamTables(&mut self.host),
        ) {
            Translated::Mapped(translation) => translation,
            Translated::Fault(fault) => {
                let exception = self.data_abort_exception(address, fault, store, false);
                self.take(exception);
                return Ok(());
            }
            Translated::Unsupported(unsupported) => {
                return Err(self.unsupported(RequirementKind::Translation(unsupported)));
            }
        };
        // An unaligned access to Device memory faults. Exclusives to Device
        // memory are IMPLEMENTATION DEFINED; the engine performs them when
        // the memory is RAM (as with the MMU off) and refuses device
        // registers.
        if translation.memory == MemoryType::Device && !aligned {
            return self.alignment_fault(address, store);
        }
        let access = debug::Access {
            address,
            size,
            read: !store,
            write: store,
            maintenance: false,
            el: self.cpu.pstate.el,
        };
        if let Some(exception) = self.watchpoint_exception(&access, pc) {
            self.take(exception);
            return Ok(());
        }
        let physical = translation.physical;
        let granule = physical & !(RESERVATION_GRANULE - 1);
        let mut bytes = [0u8; 16];
        let bytes = &mut bytes[..size as usize];
        match kind {
            Kind::Load { .. } => {
                if !self.host.read_ram(physical, bytes) {
                    return Err(self.unsupported(RequirementKind::Native(
                        "an exclusive load of a device register",
                    )));
                }
                self.cpu.monitor = Some(granule);
                for (index, register) in registers.iter().enumerate() {
                    if let Some(register) = register {
                        let start = index * usize::from(element_bytes);
                        let mut value = [0u8; 8];
                        value[..usize::from(element_bytes)]
                            .copy_from_slice(&bytes[start..start + usize::from(element_bytes)]);
                        self.write_register(*register, u64::from_le_bytes(value));
                    }
                }
            }
            Kind::Store { status, .. } => {
                let last = (physical + size - 1) & !(RESERVATION_GRANULE - 1);
                let passed = self.cpu.monitor == Some(granule) && last == granule;
                self.cpu.monitor = None;
                if passed {
                    for (index, register) in registers.iter().enumerate() {
                        if let Some(register) = register {
                            let start = index * usize::from(element_bytes);
                            let value = self.read_register(*register).to_le_bytes();
                            bytes[start..start + usize::from(element_bytes)]
                                .copy_from_slice(&value[..usize::from(element_bytes)]);
                        }
                    }
                    if !self.host.write_ram(physical, bytes) {
                        return Err(self.unsupported(RequirementKind::Native(
                            "an exclusive store to a device register",
                        )));
                    }
                }
                self.write_register(status, u64::from(!passed));
            }
        }
        self.next()
    }
}
