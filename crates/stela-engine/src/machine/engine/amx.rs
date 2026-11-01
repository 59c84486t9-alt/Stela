//! AMX block exits: one Apple AMX instruction against the PE's AMX unit and
//! translated guest memory, with the reference model of
//! `stela_compiler::amx::model`. The ABI and its evidence are in
//! `docs/design/system.md#apple-extensions` and `machine::amx`.
use super::{Devices, FETCH_PAGE, Host, Machine, RequirementKind, Step};
use crate::machine::{
    amx,
    cpu::Exception,
    exception::Class,
    mmu::{self, Access, Outcome as Translated},
};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, vec::Vec};
use stela_compiler::{
    GuestAddress,
    amx::{
        AmxOperand, AmxOperation, decode,
        model::{self, AmxError, AmxMemory, MemoryFault},
    },
};

/// ISS of the exception for an AMX instruction while `AMX_CTL_EL1` bit 63 is
/// clear: ESR 0xfe000003 (Asahi Linux, "Apple Instructions"). 26A434 XNU's
/// handler for this class and subtype enables AMX on a faulting `set` and
/// retries it (`0xfffffe000bd778b4`).
pub const DISABLED_ISS: u32 = 3;

/// Why a transfer stopped, beyond the address the model reports.
enum Failure {
    Fault(mmu::Fault),
    Translation(mmu::Unsupported),
    Device { physical: u64 },
}

/// Guest virtual memory for the model. Each call translates every 4 KiB
/// piece first and touches memory only when all are mapped RAM.
struct Translate<'a, H: Host, D: Devices> {
    machine: &'a mut Machine<H, D>,
    failure: Option<Failure>,
}

impl<H: Host, D: Devices> Translate<'_, H, D> {
    /// (physical, length) pieces of `address..address+bytes`.
    fn pieces(
        &mut self,
        address: u64,
        bytes: usize,
        write: bool,
    ) -> Result<Vec<(u64, usize)>, MemoryFault> {
        let access = if write { Access::Write } else { Access::Read };
        let mut pieces = Vec::new();
        let mut done = 0;
        while done < bytes {
            let virtual_address = address.wrapping_add(done as u64);
            let page_left = (FETCH_PAGE - (virtual_address & (FETCH_PAGE - 1))) as usize;
            let length = page_left.min(bytes - done);
            match self.machine.translate_data(virtual_address, access) {
                Translated::Mapped(translation) => pieces.push((translation.physical, length)),
                Translated::Fault(fault) => {
                    self.failure = Some(Failure::Fault(fault));
                    return Err(MemoryFault {
                        address: virtual_address,
                        write,
                    });
                }
                Translated::Unsupported(unsupported) => {
                    self.failure = Some(Failure::Translation(unsupported));
                    return Err(MemoryFault {
                        address: virtual_address,
                        write,
                    });
                }
            }
            done += length;
        }
        Ok(pieces)
    }

    fn device(&mut self, physical: u64, address: u64, write: bool) -> MemoryFault {
        self.failure = Some(Failure::Device { physical });
        MemoryFault { address, write }
    }
}

impl<H: Host, D: Devices> AmxMemory for Translate<'_, H, D> {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault> {
        let pieces = self.pieces(address, destination.len(), false)?;
        let mut offset = 0;
        for (physical, length) in pieces {
            let range = offset..offset + length;
            if !self
                .machine
                .host
                .read_ram(physical, &mut destination[range])
            {
                return Err(self.device(physical, address.wrapping_add(offset as u64), false));
            }
            offset += length;
        }
        Ok(())
    }

    fn write(&mut self, address: u64, source: &[u8]) -> Result<(), MemoryFault> {
        let pieces = self.pieces(address, source.len(), true)?;
        // Probe every piece so that nothing is written unless all are RAM.
        let mut offset = 0;
        let mut probe = [0u8; 1];
        for &(physical, length) in &pieces {
            if !self.machine.host.read_ram(physical, &mut probe)
                || !self
                    .machine
                    .host
                    .read_ram(physical + length as u64 - 1, &mut probe)
            {
                return Err(self.device(physical, address.wrapping_add(offset as u64), true));
            }
            offset += length;
        }
        let mut offset = 0;
        for (physical, length) in pieces {
            if !self
                .machine
                .host
                .write_ram(physical, &source[offset..offset + length])
            {
                return Err(self.device(physical, address.wrapping_add(offset as u64), true));
            }
            offset += length;
        }
        Ok(())
    }
}

impl<H: Host, D: Devices> Machine<H, D> {
    /// Refuse an AMX case whose hardware behavior is not established.
    fn refuse_amx(&self, word: u32, detail: &str) -> Step {
        Err(self.unsupported(RequirementKind::Instruction {
            word,
            detail: format!("AMX: {detail}"),
        }))
    }

    /// Execute the AMX word at the PC.
    pub(super) fn amx(&mut self, word: u32) -> Step {
        let pc = self.cpu.pc;
        let instruction = match decode(GuestAddress(pc), word) {
            Ok(Some(instruction)) => instruction,
            Ok(None) => {
                return Err(self.unsupported(RequirementKind::Native(
                    "AMX exit at a word outside the AMX space",
                )));
            }
            Err(error) => return self.refuse_amx(word, &error.to_string()),
        };
        if let Some(step) = self.hacr_guest(word, crate::machine::hacr::Operation::Amx) {
            return step;
        }
        let operation = instruction.operation;
        let Some(generation) = self.cpu.amx.generation() else {
            return self.refuse_amx(word, amx::UNQUALIFIED_GENERATION);
        };
        if !self.cpu.amx.enabled(amx::governing(
            if self.cpu.regime() == crate::machine::cpu::TranslationRegime::El20 {
                2
            } else {
                1
            },
        )) {
            if operation == AmxOperation::Unallocated {
                return self.refuse_amx(
                    word,
                    "unallocated operation while AMX_CTL_EL1 is clear: which exception wins is unknown",
                );
            }
            self.take(Exception::synchronous(
                Class::ImplementationDefined,
                DISABLED_ISS,
                pc,
            ));
            return Ok(());
        }
        let live = self.cpu.amx.live();
        match operation {
            AmxOperation::Unallocated => return self.undefined(),
            AmxOperation::Set if live => {
                return self.refuse_amx(word, "set while state is live: syndrome unknown");
            }
            AmxOperation::Set => {
                self.cpu.amx.start();
                return self.next();
            }
            AmxOperation::Clear if live => {
                self.cpu.amx.clear();
                return self.next();
            }
            AmxOperation::Clear => {
                return self.refuse_amx(word, "clr without live state: behavior unknown");
            }
            _ if !live => {
                return self.refuse_amx(word, "operation without live state: behavior unknown");
            }
            _ => {}
        }
        let operand = match instruction.operand {
            AmxOperand::Register(index) if index < 31 => self.cpu.state.x[usize::from(index)],
            AmxOperand::Register(_) | AmxOperand::None => 0,
        };
        let mut registers = self.cpu.amx.registers.take().expect("live above");
        let mut memory = Translate {
            machine: self,
            failure: None,
        };
        let result =
            model::execute_for(generation, &mut registers, operation, operand, &mut memory);
        let failure = memory.failure.take();
        self.cpu.amx.registers = Some(registers);
        match result {
            Ok(()) => self.next(),
            Err(AmxError::Alignment { address, write, .. }) => self.alignment_fault(address, write),
            Err(AmxError::Memory(MemoryFault { address, write })) => match failure {
                Some(Failure::Fault(fault)) => self.data_abort(address, fault, write, false),
                Some(Failure::Translation(unsupported)) => {
                    Err(self.unsupported(RequirementKind::Translation(unsupported)))
                }
                Some(Failure::Device { physical }) => {
                    Err(self.unsupported(RequirementKind::Device {
                        physical,
                        write,
                        detail: "AMX transfer outside RAM".into(),
                    }))
                }
                None => unreachable!("every memory fault records its failure"),
            },
            Err(AmxError::Unsupported { detail }) => self.refuse_amx(word, detail),
            Err(AmxError::Enablement | AmxError::Undefined) => {
                unreachable!("set, clr and unallocated operations are handled above")
            }
        }
    }
}

#[cfg(test)]
mod tests;
