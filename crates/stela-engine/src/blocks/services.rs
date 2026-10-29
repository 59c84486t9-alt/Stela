//! Services borrowed for one run and the completion of the instructions that use them.
use super::{REGISTER_COUNT, ZERO_REGISTER_INDEX};
use crate::{memory, pauth, system};
use anyhow::{Result, ensure};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{
        PointerAuthentication, PointerAuthenticationKey, PointerAuthenticationModifier,
        PointerAuthenticationOperation,
    },
};

/// Services borrowed for one run; a missing service stops execution at the
/// instruction that needs it.
pub(crate) struct AuthenticatedMemory<'a> {
    pub(super) reader: &'a mut dyn memory::domain::MemoryReader,
    pub(super) controls: pauth::memory::Controls,
}

pub(super) struct PauthExecution<'a> {
    pub(super) context: &'a pauth::Context,
    pub(super) memory: Option<AuthenticatedMemory<'a>>,
}

impl<'a> PauthExecution<'a> {
    pub(super) fn keys_only(context: &'a pauth::Context) -> Self {
        Self {
            context,
            memory: None,
        }
    }
}

pub(super) struct RuntimeServices<'a> {
    pub(super) pointer_authentication: Option<PauthExecution<'a>>,
    pub(super) system: Option<&'a mut dyn system::execution::Dispatcher>,
}

impl<'a> RuntimeServices<'a> {
    pub(super) fn direct(pointer_authentication: Option<&'a pauth::Context>) -> Self {
        Self {
            pointer_authentication: pointer_authentication.map(PauthExecution::keys_only),
            system: None,
        }
    }

    pub(super) fn pauth_memory(
        context: &'a pauth::Context,
        reader: &'a mut dyn memory::domain::MemoryReader,
        controls: pauth::memory::Controls,
    ) -> Self {
        Self {
            pointer_authentication: Some(PauthExecution {
                context,
                memory: Some(AuthenticatedMemory { reader, controls }),
            }),
            system: None,
        }
    }

    pub(super) fn system(dispatcher: &'a mut dyn system::execution::Dispatcher) -> Self {
        Self {
            pointer_authentication: None,
            system: Some(dispatcher),
        }
    }
}

pub(super) fn serialize_instruction_execution() -> Result<()> {
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::{Ordering, compiler_fence};
        compiler_fence(Ordering::SeqCst);
        // CPUID is part of the x86-64 baseline, and leaf 0 serializes
        // execution.
        let _ = core::arch::x86_64::__cpuid(0);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }
    #[cfg(not(target_arch = "x86_64"))]
    anyhow::bail!("instruction synchronization requires the x86-64 runtime")
}

pub(super) fn runtime_pauth_key(key: PointerAuthenticationKey) -> stela_contracts::pauth::Key {
    match key {
        PointerAuthenticationKey::Ia => stela_contracts::pauth::Key::Ia,
        PointerAuthenticationKey::Ib => stela_contracts::pauth::Key::Ib,
        PointerAuthenticationKey::Da => stela_contracts::pauth::Key::Da,
        PointerAuthenticationKey::Db => stela_contracts::pauth::Key::Db,
    }
}

pub(super) fn pauth_modifier(
    registers: &GuestState,
    modifier: PointerAuthenticationModifier,
) -> Result<u64> {
    match modifier {
        PointerAuthenticationModifier::StackPointer => Ok(registers.sp),
        PointerAuthenticationModifier::Zero => Ok(0),
        PointerAuthenticationModifier::Register(index) => {
            ensure!(index < ZERO_REGISTER_INDEX, "invalid PAC modifier register");
            Ok(registers.x[usize::from(index)])
        }
    }
}

#[derive(Debug)]
pub(super) enum AuthenticatedLoadError {
    UndefinedOverlap,
    StackAlignment { stack_pointer: u64 },
    MemoryRequired,
    Read(memory::domain::MemoryFault),
}

impl core::fmt::Display for AuthenticatedLoadError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "authenticated load failed: {self:?}")
    }
}

impl core::error::Error for AuthenticatedLoadError {}

#[cfg(test)]
pub(super) fn complete_pauth(
    context: &pauth::Context,
    instruction: &PointerAuthentication,
    registers: &mut GuestState,
) -> Result<(GuestAddress, Option<bool>)> {
    complete_pauth_with_memory(context, instruction, registers, None)
}

pub(crate) fn complete_pauth_with_memory(
    context: &pauth::Context,
    instruction: &PointerAuthentication,
    registers: &mut GuestState,
    memory: Option<&mut AuthenticatedMemory<'_>>,
) -> Result<(GuestAddress, Option<bool>)> {
    use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
    const HINT_POINTER_REGISTER: usize = 17;
    const HINT_MODIFIER_REGISTER: usize = 16;
    match instruction.operation {
        PointerAuthenticationOperation::LinkRegister(_) => {
            anyhow::bail!("link-register authentication requires retained LR owners")
        }
        PointerAuthenticationOperation::Sign1716 { key } => {
            let value = context.sign(
                runtime_pauth_key(key),
                registers.x[HINT_POINTER_REGISTER],
                registers.x[HINT_MODIFIER_REGISTER],
            )?;
            registers.x[HINT_POINTER_REGISTER] = value;
            Ok((instruction.next_pc, None))
        }
        PointerAuthenticationOperation::Authenticate1716 { key } => {
            let result = context.authenticate_operation(
                runtime_pauth_key(key),
                registers.x[HINT_POINTER_REGISTER],
                registers.x[HINT_MODIFIER_REGISTER],
                false,
            )?;
            registers.x[HINT_POINTER_REGISTER] = result.pointer;
            Ok((instruction.next_pc, Some(result.authenticated)))
        }
        PointerAuthenticationOperation::SignIbSp => {
            let signed = context.sign_ib(registers.x[30], registers.sp)?;
            registers.x[30] = signed;
            Ok((instruction.next_pc, None))
        }
        PointerAuthenticationOperation::AuthenticateIbSp => {
            let result = context.authenticate_operation(
                stela_contracts::pauth::Key::Ib,
                registers.x[30],
                registers.sp,
                false,
            )?;
            registers.x[30] = result.pointer;
            Ok((instruction.next_pc, Some(result.authenticated)))
        }
        PointerAuthenticationOperation::ReturnIbSp | PointerAuthenticationOperation::ReturnIaSp => {
            let key = if instruction.operation == PointerAuthenticationOperation::ReturnIbSp {
                stela_contracts::pauth::Key::Ib
            } else {
                stela_contracts::pauth::Key::Ia
            };
            let result =
                context.authenticate_operation(key, registers.x[30], registers.sp, true)?;
            // Authenticated RET uses a temporary target. The signed LR stays in X30.
            Ok((GuestAddress(result.pointer), Some(result.authenticated)))
        }
        PointerAuthenticationOperation::Branch {
            key,
            target,
            modifier,
            link,
        } => {
            ensure!(
                target < REGISTER_COUNT,
                "invalid authenticated branch target register"
            );
            let pointer = if target == ZERO_REGISTER_INDEX {
                0
            } else {
                registers.x[usize::from(target)]
            };
            // Both operands may alias X30. Authentication uses their old values.
            let modifier = pauth_modifier(registers, modifier)?;
            let result =
                context.authenticate_operation(runtime_pauth_key(key), pointer, modifier, true)?;
            if link {
                // Nonfaulting authentication still performs the architectural
                // link write before instruction fetch checks its resulting target.
                // FPACCOMBINE failure has already returned above.
                registers.x[30] = instruction.next_pc.0;
            }
            Ok((GuestAddress(result.pointer), Some(result.authenticated)))
        }
        Sign {
            key,
            destination,
            modifier,
        }
        | Authenticate {
            key,
            destination,
            modifier,
        } => {
            ensure!(
                destination < REGISTER_COUNT,
                "invalid PAC destination register"
            );
            let pointer = if destination == ZERO_REGISTER_INDEX {
                0
            } else {
                registers.x[usize::from(destination)]
            };
            // Snapshot all inputs before any destination write, including Rd==Rn.
            let modifier = pauth_modifier(registers, modifier)?;
            let (value, authenticated) = if matches!(instruction.operation, Sign { .. }) {
                (
                    context.sign(runtime_pauth_key(key), pointer, modifier)?,
                    None,
                )
            } else {
                let result = context.authenticate_operation(
                    runtime_pauth_key(key),
                    pointer,
                    modifier,
                    false,
                )?;
                (result.pointer, Some(result.authenticated))
            };
            // XZR is discarded only after the operation/service has succeeded.
            if destination != ZERO_REGISTER_INDEX {
                registers.x[usize::from(destination)] = value;
            }
            Ok((instruction.next_pc, authenticated))
        }
        PointerAuthenticationOperation::Load(load) => {
            let memory = memory.ok_or(AuthenticatedLoadError::MemoryRequired)?;
            let mut authenticated = false;
            let read_flags = if load.writeback || load.base != ZERO_REGISTER_INDEX {
                stela_compiler::context::memory::flags::TAG_CHECKED
            } else {
                0
            };
            pauth::memory::complete(
                load,
                memory.controls,
                registers,
                |key, pointer| -> core::result::Result<u64, pauth::AuthenticationError> {
                    let key = match key {
                        stela_compiler::block::pauth_memory::DataKey::A => {
                            stela_contracts::pauth::Key::Da
                        }
                        stela_compiler::block::pauth_memory::DataKey::B => {
                            stela_contracts::pauth::Key::Db
                        }
                    };
                    let result = context.authenticate_operation(key, pointer, 0, true)?;
                    authenticated = result.authenticated;
                    Ok(result.pointer)
                },
                |address| {
                    memory
                        .reader
                        .read_scalar(
                            address,
                            size_of::<u64>() as u8,
                            read_flags,
                            instruction.instruction_pc.0,
                        )
                        .map(|value| value as u64)
                        .map_err(AuthenticatedLoadError::Read)
                },
            )
            .map_err(|fault| match fault {
                pauth::memory::Fault::InvalidOperands => anyhow::anyhow!("invalid LDRA operands"),
                pauth::memory::Fault::UndefinedOverlap => {
                    AuthenticatedLoadError::UndefinedOverlap.into()
                }
                pauth::memory::Fault::Authentication(error) => anyhow::Error::new(error),
                pauth::memory::Fault::StackAlignment { stack_pointer } => {
                    AuthenticatedLoadError::StackAlignment { stack_pointer }.into()
                }
                pauth::memory::Fault::Read { error, .. } => error.into(),
            })?;
            Ok((instruction.next_pc, Some(authenticated)))
        }
        PointerAuthenticationOperation::GenericCode(code) => {
            pauth::generic::complete(code, registers, |data, modifier| {
                context.generic_code(data, modifier)
            })
            .map_err(|fault| match fault {
                pauth::generic::Fault::InvalidOperands => anyhow::anyhow!("invalid PACGA operands"),
                pauth::generic::Fault::Compute(error) => error,
            })?;
            Ok((instruction.next_pc, None))
        }
        Strip { data, destination } => {
            ensure!(
                destination < REGISTER_COUNT,
                "invalid XPAC destination register"
            );
            let pointer = if destination == ZERO_REGISTER_INDEX {
                0
            } else {
                registers.x[usize::from(destination)]
            };
            // XPAC selects an address domain, not a key, so no key needs to
            // exist.
            let value = context.strip(
                if data {
                    stela_contracts::pauth::Key::Da
                } else {
                    stela_contracts::pauth::Key::Ia
                },
                pointer,
            )?;
            if destination != ZERO_REGISTER_INDEX {
                registers.x[usize::from(destination)] = value;
            }
            Ok((instruction.next_pc, None))
        }
    }
}
