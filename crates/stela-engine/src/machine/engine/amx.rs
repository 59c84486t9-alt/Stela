//! AMX block exits: one Apple AMX instruction against the PE's AMX unit and
//! translated guest memory, with the reference model of
//! `stela_compiler::amx::model`. The ABI and its evidence are in
//! `machine::amx`.
use super::{Devices, FETCH_PAGE, Host, Machine, RequirementKind, Step};
use crate::machine::{
    amx,
    cpu::Exception,
    exception::Class,
    mmu::{self, Access, Outcome as Translated},
};
use alloc::format;
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use stela_compiler::{
    GuestAddress,
    amx::{
        AmxOperand, AmxOperation, decode,
        model::{self, AmxError, AmxMemory, MemoryFault},
        native::Native,
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
    Device {
        physical: u64,
    },
    /// More pages than [`PIECES`]: no transfer of the model reaches this.
    Span,
}

/// The pages one transfer can touch: it moves at most four 64-byte rows,
/// which lie in at most two 4 KiB pages.
const PIECES: usize = 2;

/// Guest virtual memory for the model. Each call translates every 4 KiB
/// piece first and touches memory only when all are mapped RAM.
struct Translate<'a, H: Host, D: Devices> {
    machine: &'a mut Machine<H, D>,
    failure: Option<Failure>,
}

impl<H: Host, D: Devices> Translate<'_, H, D> {
    /// (physical, length) pieces of `address..address+bytes`, and how many
    /// there are; without a heap allocation, which every transfer made.
    fn pieces(
        &mut self,
        address: u64,
        bytes: usize,
        write: bool,
    ) -> Result<([(u64, usize); PIECES], usize), MemoryFault> {
        let access = if write { Access::Write } else { Access::Read };
        let mut pieces = [(0, 0); PIECES];
        let mut count = 0;
        let mut done = 0;
        while done < bytes {
            let virtual_address = address.wrapping_add(done as u64);
            let page_left = (FETCH_PAGE - (virtual_address & (FETCH_PAGE - 1))) as usize;
            let length = page_left.min(bytes - done);
            if count == PIECES {
                self.failure = Some(Failure::Span);
                return Err(MemoryFault {
                    address: virtual_address,
                    write,
                });
            }
            match self.machine.translate_data(virtual_address, access) {
                Translated::Mapped(translation) => {
                    pieces[count] = (translation.physical, length);
                    count += 1;
                }
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
        Ok((pieces, count))
    }

    fn device(&mut self, physical: u64, address: u64, write: bool) -> MemoryFault {
        self.failure = Some(Failure::Device { physical });
        MemoryFault { address, write }
    }
}

impl<H: Host, D: Devices> AmxMemory for Translate<'_, H, D> {
    fn read(&mut self, address: u64, destination: &mut [u8]) -> Result<(), MemoryFault> {
        let (pieces, count) = self.pieces(address, destination.len(), false)?;
        let mut offset = 0;
        for &(physical, length) in &pieces[..count] {
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
        let (pieces, count) = self.pieces(address, source.len(), true)?;
        let pieces = &pieces[..count];
        // Probe every piece so that nothing is written unless all are RAM.
        let mut offset = 0;
        let mut probe = [0u8; 1];
        for &(physical, length) in pieces {
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
        for &(physical, length) in pieces {
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
    /// The PE's live AMX registers for native moves
    /// (`stela_compiler::x86_64::amx_transfer::Cell`), or zero where [`Self::amx`]
    /// would not run a move on them: no qualified generation, AMX disabled
    /// for the governing EL, HACR_EL2 not letting it run, or no live state.
    /// Each of these changes only at an instruction that leaves native code,
    /// and native code is entered with the anchor read again.
    /// Fill the PE's cell (`Anchor::Amx`) as native code is entered: the
    /// register file it may use, the routine, generation and host paths.
    pub(super) fn enter_amx_cell(&mut self) {
        let registers = self.amx_registers();
        let generation = self.cpu.amx.generation();
        let native = Native::select(self.target);
        let cell = &mut self.cpu.amx.native;
        cell.registers = registers;
        cell.routine = stela_compiler::x86_64::amx_routine::routine as *const () as usize as u64;
        cell.generation = generation;
        cell.native = native;
    }

    /// Add what native code completed to the statistics as it returns.
    pub(super) fn leave_amx_cell(&mut self) {
        let cell = &mut self.cpu.amx.native;
        self.statistics.amx_moves[0] += core::mem::take(&mut cell.moves);
        let before = self.statistics.amx_operations[0];
        self.statistics.amx_operations[0] += core::mem::take(&mut cell.calls);
        if before >> 16 != self.statistics.amx_operations[0] >> 16 {
            self.fold_amx_kernels();
        }
    }

    /// Move the cell's per-operation counts into the statistics.
    pub(super) fn fold_amx_kernels(&mut self) {
        let cell = &mut self.cpu.amx.native;
        let statistics = &mut self.statistics;
        for (total, count) in statistics
            .amx_kernels
            .as_flattened_mut()
            .iter_mut()
            .zip(cell.kernels.as_flattened_mut())
        {
            *total += core::mem::take(count);
        }
        for (total, count) in statistics
            .amx_sampled
            .as_flattened_mut()
            .as_flattened_mut()
            .iter_mut()
            .zip(cell.sampled.as_flattened_mut().as_flattened_mut())
        {
            *total += core::mem::take(count);
        }
    }

    pub(super) fn amx_registers(&self) -> u64 {
        let unit = &self.cpu.amx;
        let Some(registers) = unit.registers.as_deref() else {
            return 0;
        };
        let kernel_el = if self.cpu.regime() == crate::machine::cpu::TranslationRegime::El20 {
            2
        } else {
            1
        };
        let runs = unit.generation().is_some()
            && unit.live()
            && unit.enabled(amx::governing(kernel_el))
            && (self.cpu.pstate.el == 2 || self.cpu.in_host() || {
                let hacr = self.cpu.read(super::SystemRegister::HACR_EL2);
                hacr == 0
                    || matches!(
                        crate::machine::hacr::guest(
                            hacr,
                            crate::machine::hacr::Operation::Amx,
                            crate::machine::hacr::Context {
                                el: self.cpu.pstate.el,
                                guarded: self.cpu.pstate.guarded,
                            },
                        ),
                        crate::machine::hacr::Outcome::Runs
                    )
            });
        if runs {
            registers as *const stela_compiler::amx::AmxRegisters as u64
        } else {
            0
        }
    }

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
        // Arithmetic a host path covers completes without the model, which
        // stays its definition and the fallback (`amx::native`).
        if !operation.accesses_memory()
            && let Some(registers) = self.cpu.amx.registers.as_deref_mut()
            && Native::select(self.target).execute(generation, registers, operation, operand)
        {
            return self.next();
        }
        if stela_compiler::x86_64::amx_transfer::lowers(operation) {
            self.statistics.amx_moves[1] += 1;
        } else if stela_compiler::x86_64::amx_routine::calls(operation) {
            self.statistics.amx_operations[1] += 1;
        }
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
                Some(Failure::Span) => {
                    self.refuse_amx(word, "transfer over more than two 4 KiB pages")
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
