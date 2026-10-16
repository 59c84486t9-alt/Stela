//! Apple AMX state for a hosted guest thread and completion of AMX block exits.
//!
//! In hosted execution Stela is the guest's operating system, so each guest
//! thread owns its AMX registers beside its TSD: `set` allocates a zeroed
//! register file, `clr` discards it, and every other operation runs against it.
//! A context switch needs no AMX work because the state never leaves its
//! thread's [`crate::thread::Context`]. The system-mode ABI, where the guest
//! kernel saves and restores the registers itself under `AMX_CTL_EL1`, is
//! documented in `docs/design/runtime.md#apple-amx`.
//!
//! `fma32`/`fms32`/`fma64`/`fms64` with every lane enabled run as native
//! kernels when the target admits a kernel tier; every other operation, and
//! every target without one, runs the reference model. Memory is direct RAM,
//! bounded by the profile's user range.
use crate::{execution::platform::Mapping, memory::DIRECT_RAM_USER_END};
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use anyhow::{Context as _, Result};
use serde::Serialize;
use stela_compiler::{
    GuestState, TargetCpu,
    amx::{
        AmxInstruction, AmxOperand, AmxOperation, AmxRegisters,
        model::{self, AmxError, AmxMemory, MemoryFault},
    },
    x86_64::amx::{Library, Tier, select},
};

/// Why an AMX instruction did not complete. Nothing was written: guest
/// registers, AMX state and memory are unchanged, and the PC stays on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Failure {
    /// An operation other than `set` while AMX is disabled. Hardware delivers
    /// an exception whose syndrome has not been researched.
    Disabled,
    /// `set` while enabled or `clr` while disabled: behavior not researched.
    Enablement { enabled: bool },
    /// The operand lies outside the hardware-compared domain of the model.
    Unsupported { detail: &'static str },
    /// The transfer touches memory outside the direct-RAM user range.
    Memory { address: u64, write: bool },
}

/// How an AMX instruction completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    Enabled,
    Disabled,
    Native(Tier),
    Model,
}

/// One guest thread's AMX state. Disabled threads hold no register file.
#[derive(Debug, Default)]
pub struct Thread {
    registers: Option<Box<AmxRegisters>>,
}

impl Thread {
    pub const fn new() -> Self {
        Self { registers: None }
    }

    pub fn enabled(&self) -> bool {
        self.registers.is_some()
    }

    pub fn registers(&self) -> Option<&AmxRegisters> {
        self.registers.as_deref()
    }

    /// Complete `instruction` with the guest's general-purpose operand.
    ///
    /// # Safety
    /// The caller holds the direct-RAM contract for the guest address space:
    /// every in-range guest address is host memory of this process.
    pub unsafe fn complete(
        &mut self,
        instruction: &AmxInstruction,
        state: &GuestState,
        kernels: Option<&Kernels>,
    ) -> core::result::Result<Completion, Failure> {
        match (instruction.operation, &mut self.registers) {
            (AmxOperation::Set, None) => {
                self.registers = Some(Box::new(AmxRegisters::zeroed()));
                return Ok(Completion::Enabled);
            }
            (AmxOperation::Clear, Some(_)) => {
                self.registers = None;
                return Ok(Completion::Disabled);
            }
            (AmxOperation::Set | AmxOperation::Clear, registers) => {
                return Err(Failure::Enablement {
                    enabled: registers.is_some(),
                });
            }
            (_, None) => return Err(Failure::Disabled),
            (_, Some(_)) => {}
        }
        let registers = self.registers.as_deref_mut().expect("enabled above");
        let operand = match instruction.operand {
            AmxOperand::Register(index) if index < 31 => state.x[usize::from(index)],
            AmxOperand::Register(_) | AmxOperand::None => 0,
        };
        if let Some(kernels) = kernels
            && let Some(kernel) = select(instruction.operation, operand)
        {
            let x = registers.x_operand((operand >> 10) & 0x1ff);
            let y = registers.y_operand(operand & 0x1ff);
            // SAFETY: `select` chose this kernel for the operation, and the
            // pointers meet its ABI: the 4 KiB Z grid and 64-byte X and Y.
            unsafe {
                kernels.call(
                    kernels.library.offset(kernel),
                    registers.z.as_mut_ptr().cast(),
                    &x,
                    &y,
                    (operand >> 20) & 63,
                )
            };
            return Ok(Completion::Native(kernels.library.tier));
        }
        model::execute(registers, instruction.operation, operand, &mut DirectRam)
            .map(|()| Completion::Model)
            .map_err(|error| match error {
                AmxError::Memory(MemoryFault { address, write }) => {
                    Failure::Memory { address, write }
                }
                AmxError::Unsupported { detail } => Failure::Unsupported { detail },
                AmxError::Enablement => unreachable!("set and clr are handled above"),
            })
    }
}

/// The native kernel library of the best tier the target admits, mapped RX.
#[derive(Debug)]
pub struct Kernels {
    library: Library,
    mapping: Mapping,
}

impl Kernels {
    /// `None` when no tier is both requested by `target` and admitted by the
    /// host; such threads use the model for every operation.
    pub fn new(target: TargetCpu) -> Result<Option<Self>> {
        let Some(tier) = [Tier::Avx512, Tier::Fma].into_iter().find(|tier| {
            target.supports(tier.requires()) && crate::platform::cpu::admitted(tier.requires())
        }) else {
            return Ok(None);
        };
        let library = Library::new(tier);
        let mapping = Mapping::new(&library.code).context("map AMX kernels")?;
        Ok(Some(Self { library, mapping }))
    }

    pub fn tier(&self) -> Tier {
        self.library.tier
    }

    /// # Safety
    /// `offset` starts a kernel in this library and `z` is a 4 KiB Z grid.
    unsafe fn call(&self, offset: usize, z: *mut u8, x: &[u8; 64], y: &[u8; 64], row: u64) {
        // SAFETY: as above; the library's kernels are leaf functions that
        // touch only their arguments and restore MXCSR.
        unsafe {
            self.mapping
                .call_amx_kernel(offset, z, x.as_ptr(), y.as_ptr(), row)
                .expect("hosted AMX kernel storage cannot fail")
        };
    }
}

/// Guest memory in the direct-RAM profile: guest addresses are host addresses
/// below [`DIRECT_RAM_USER_END`].
struct DirectRam;

impl DirectRam {
    fn check(address: u64, bytes: usize, write: bool) -> core::result::Result<(), MemoryFault> {
        let end = address.checked_add(bytes as u64);
        if address == 0 || end.is_none_or(|end| end > DIRECT_RAM_USER_END) {
            return Err(MemoryFault { address, write });
        }
        Ok(())
    }
}

impl AmxMemory for DirectRam {
    fn read(
        &mut self,
        address: u64,
        destination: &mut [u8],
    ) -> core::result::Result<(), MemoryFault> {
        Self::check(address, destination.len(), false)?;
        // SAFETY: the caller of `Thread::complete` holds the direct-RAM
        // contract for this in-range address.
        unsafe {
            core::ptr::copy_nonoverlapping(
                address as *const u8,
                destination.as_mut_ptr(),
                destination.len(),
            )
        };
        Ok(())
    }

    fn write(&mut self, address: u64, source: &[u8]) -> core::result::Result<(), MemoryFault> {
        Self::check(address, source.len(), true)?;
        // SAFETY: as for `read`.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), address as *mut u8, source.len())
        };
        Ok(())
    }
}

#[cfg(all(
    test,
    target_arch = "x86_64",
    any(target_os = "macos", target_os = "linux")
))]
mod tests {
    use super::*;
    use stela_compiler::{
        GuestAddress,
        amx::{AmxOperation::*, decode},
        x86_64::amx::Kernel,
    };

    fn instruction(operation: AmxOperation, register: u8) -> AmxInstruction {
        decode(GuestAddress(0x1000), operation.word(register))
            .unwrap()
            .unwrap()
    }

    fn state(x0: u64) -> GuestState {
        let mut state = GuestState::default();
        state.x[0] = x0;
        state
    }

    #[test]
    fn enablement_transitions_are_explicit() {
        let mut thread = Thread::new();
        let none = GuestState::default();
        unsafe {
            assert_eq!(
                thread.complete(&instruction(Fma32, 0), &none, None),
                Err(Failure::Disabled)
            );
            assert_eq!(
                thread.complete(&instruction(Clear, 0), &none, None),
                Err(Failure::Enablement { enabled: false })
            );
            assert_eq!(
                thread.complete(&instruction(Set, 0), &none, None),
                Ok(Completion::Enabled)
            );
            assert_eq!(thread.registers(), Some(&AmxRegisters::zeroed()));
            assert_eq!(
                thread.complete(&instruction(Set, 0), &none, None),
                Err(Failure::Enablement { enabled: true })
            );
            assert_eq!(
                thread.complete(&instruction(Clear, 0), &none, None),
                Ok(Completion::Disabled)
            );
        }
        assert!(!thread.enabled());
    }

    #[test]
    fn transfers_use_direct_ram_and_refuse_addresses_outside_it() {
        let mut thread = Thread::new();
        let source: [u8; 64] = core::array::from_fn(|index| index as u8);
        let mut destination = [0u8; 64];
        unsafe {
            thread
                .complete(&instruction(Set, 0), &GuestState::default(), None)
                .unwrap();
            // ldx row 3, then stx row 3 into another buffer.
            let row = 3u64 << 56;
            let load = state(source.as_ptr() as u64 | row);
            assert_eq!(
                thread.complete(&instruction(LoadX, 0), &load, None),
                Ok(Completion::Model)
            );
            let store = state(destination.as_mut_ptr() as u64 | row);
            thread
                .complete(&instruction(StoreX, 0), &store, None)
                .unwrap();
            assert_eq!(destination, source);
            for address in [0, DIRECT_RAM_USER_END - 32, (1 << 55) | 0x1000] {
                assert!(matches!(
                    thread.complete(&instruction(LoadZ, 0), &state(address), None),
                    Err(Failure::Memory { .. })
                ));
            }
            // X31 reads zero: a load from address zero faults.
            assert_eq!(
                thread.complete(&instruction(LoadY, 31), &GuestState::default(), None),
                Err(Failure::Memory {
                    address: 0,
                    write: false
                })
            );
        }
    }

    #[test]
    fn native_kernels_and_the_model_produce_the_same_state() {
        let Some(kernels) = Kernels::new(TargetCpu::detect()).unwrap() else {
            return;
        };
        let mut seed = 0x5851_f42d_4c95_7f2d_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for kernel in Kernel::ALL {
            let mut native = Thread::new();
            let mut model = Thread::new();
            unsafe {
                native
                    .complete(&instruction(Set, 0), &GuestState::default(), None)
                    .unwrap();
                model
                    .complete(&instruction(Set, 0), &GuestState::default(), None)
                    .unwrap();
            }
            let mut fill = AmxRegisters::zeroed();
            for byte in fill.as_bytes_mut() {
                *byte = next() as u8;
            }
            *native.registers.as_deref_mut().unwrap() = fill.clone();
            *model.registers.as_deref_mut().unwrap() = fill;
            for _ in 0..32 {
                let random = next();
                let operand = (random & 0x000f_ffff)
                    | ((random >> 20) & 63) << 20
                    | u64::from(kernel.product_only) << 27
                    | u64::from(kernel.shape == stela_compiler::x86_64::amx::Shape::Vector) << 63;
                let operation = instruction(kernel.operation(), 0);
                unsafe {
                    assert_eq!(
                        native.complete(&operation, &state(operand), Some(&kernels)),
                        Ok(Completion::Native(kernels.tier()))
                    );
                    assert_eq!(
                        model.complete(&operation, &state(operand), None),
                        Ok(Completion::Model)
                    );
                }
            }
            assert_eq!(native.registers(), model.registers(), "{kernel:?}");
        }
    }
}
