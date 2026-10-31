//! Exclusive loads and stores and CLREX, which the engine performs against
//! the PE's Exclusives monitor (Arm `AArch64_SetExclusiveMonitors` and
//! `AArch64_ExclusiveMonitorsPass`). The monitor holds the physical
//! Exclusives reservation granule (CTR_EL0.ERG: 64 bytes) of the last
//! exclusive load; a store-exclusive to that granule passes once and clears
//! it, as do CLREX and exception return. The local and global monitors
//! coincide; another observer's write to the granule clears it
//! (`processors`), or, with PEs on their own host cores, the store passes
//! only while RAM holds what the load read (`parallel`). `IsExclusiveVA` is
//! TRUE. With FEAT_MTE2 a load, and a
//! store that passes, is tag checked unless its base is SP.
use super::{Devices, Host, Machine, RamTables, RequirementKind, Step, Translated, tags::TagCheck};
use crate::machine::{
    cpu::{Exception, RESERVATION_GRANULE, Reservation},
    debug,
    exception::Class,
    mmu::{self, Access, MemoryType, alignment},
};
use stela_compiler::aarch64::{
    Register,
    exclusive::{Data, Kind, Operand},
};

impl<H: Host, D: Devices> Machine<H, D> {
    /// The monitor native code left in the frame becomes the PE's own: its
    /// granule as RAM holds it now, but for the value the load read.
    pub(super) fn adopt_native_monitor(&mut self) {
        let bytes = core::mem::take(&mut self.cpu.state.exclusive_bytes);
        if bytes == 0 {
            return;
        }
        let address = self.cpu.state.exclusive_address;
        let controls = self.cpu.controls(self.cpu.regime());
        let requester = self.cpu.requester();
        let tables = &mut RamTables(&mut self.host);
        let Translated::Mapped(translation) =
            mmu::translate(&controls, address, Access::Read, requester, tables)
        else {
            return;
        };
        let granule = translation.physical & !(RESERVATION_GRANULE - 1);
        let mut reservation = Reservation {
            granule,
            bytes: [0; RESERVATION_GRANULE as usize],
        };
        if self.host.read_ram(granule, &mut reservation.bytes) {
            let offset = (translation.physical - granule) as usize;
            let value = self.cpu.state.exclusive_value.to_le_bytes();
            reservation.bytes[offset..offset + bytes as usize]
                .copy_from_slice(&value[..bytes as usize]);
            self.cpu.monitor = Some(reservation);
        }
    }

    pub(super) fn exclusive(&mut self, operand: Operand) -> Step {
        self.adopt_native_monitor();
        // Serialized PEs share one host core: the snapshot monitor below
        // observes every other PE's write between slices (`observe_writes`).
        if self.canonical_memory_serves() {
            return self.shared_exclusive(operand);
        }
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
        // with SCTLR_ELx.A clear, only an access crossing a 16-byte granule
        // faults.
        let aligned = address.is_multiple_of(size);
        let controls = self.cpu.controls(self.cpu.regime());
        let shape = alignment::Shape {
            kind: alignment::Kind::Exclusive,
            bytes: size,
            pair: count == 2,
        };
        if alignment::before_translation(controls.sctlr, address, shape) {
            return self.alignment_fault(address, store);
        }
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
        let tag_checked = base != Register::Sp;
        let physical = translation.physical;
        let granule = physical & !(RESERVATION_GRANULE - 1);
        let mut bytes = [0u8; 16];
        let bytes = &mut bytes[..size as usize];
        match kind {
            Kind::Load { .. } => {
                if tag_checked && self.exclusive_tag_fault(&access)? {
                    return Ok(());
                }
                let mut reservation = Reservation {
                    granule,
                    bytes: [0; RESERVATION_GRANULE as usize],
                };
                if !self.host.read_ram(physical, bytes)
                    || !self.host.read_ram(granule, &mut reservation.bytes)
                {
                    return Err(self.unsupported(RequirementKind::Native(
                        "an exclusive load of a device register",
                    )));
                }
                if self.parallel.is_some() {
                    // Other PEs write concurrently: the loaded value, which a
                    // store-exclusive later compares, is read single-copy
                    // atomically.
                    self.atomic_read_ram(physical, bytes)?;
                    let offset = (physical - granule) as usize;
                    reservation.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
                }
                self.cpu.monitor = Some(reservation);
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
                let passed = self
                    .cpu
                    .monitor
                    .is_some_and(|reservation| reservation.granule == granule)
                    && last == granule;
                let reservation = self.cpu.monitor.take();
                if passed && tag_checked && self.exclusive_tag_fault(&access)? {
                    return Ok(());
                }
                let mut stored = passed;
                if passed {
                    for (index, register) in registers.iter().enumerate() {
                        if let Some(register) = register {
                            let start = index * usize::from(element_bytes);
                            let value = self.read_register(*register).to_le_bytes();
                            bytes[start..start + usize::from(element_bytes)]
                                .copy_from_slice(&value[..usize::from(element_bytes)]);
                        }
                    }
                    if self.parallel.is_some() {
                        // The monitor passes while RAM still holds what the
                        // exclusive load read (see `parallel`).
                        let offset = (physical - granule) as usize;
                        let mut expected = [0u8; 16];
                        let expected = &mut expected[..bytes.len()];
                        expected.copy_from_slice(
                            &reservation.expect("passed").bytes[offset..offset + bytes.len()],
                        );
                        stored = self
                            .host
                            .compare_exchange_ram(physical, expected, bytes)
                            .ok_or_else(|| {
                                self.unsupported(RequirementKind::Native(
                                    "an exclusive store the host cannot compare and exchange",
                                ))
                            })?;
                    } else if !self.host.write_ram(physical, bytes) {
                        return Err(self.unsupported(RequirementKind::Native(
                            "an exclusive store to a device register",
                        )));
                    }
                }
                self.write_register(status, u64::from(!stored));
            }
        }
        self.next()
    }

    /// Read `buffer.len()` bytes of RAM at `physical` single-copy atomically,
    /// as a compare-and-exchange of zero with zero that fails, or stores the
    /// zero RAM already held.
    fn atomic_read_ram(&mut self, physical: u64, buffer: &mut [u8]) -> Result<(), super::Stop> {
        buffer.fill(0);
        let mut zero = [0u8; 16];
        let zero = &mut zero[..buffer.len()];
        self.host
            .compare_exchange_ram(physical, buffer, zero)
            .map(drop)
            .ok_or_else(|| {
                self.unsupported(RequirementKind::Native(
                    "an exclusive load the host cannot read atomically",
                ))
            })
    }

    /// Take the Tag Check fault of an exclusive access, if it has one.
    fn exclusive_tag_fault(&mut self, access: &debug::Access) -> Result<bool, super::Stop> {
        let requester = self.cpu.requester();
        match self.tag_check(access, requester, None)? {
            TagCheck::Failed(exception) => {
                self.take(exception);
                Ok(true)
            }
            TagCheck::Passed | TagCheck::Untranslated => Ok(false),
        }
    }
}
