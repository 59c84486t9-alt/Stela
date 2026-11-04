//! Pointer authentication instructions completed by the runtime PAuth service.
use super::{pauth_lr, pauth_memory};
use crate::{CompileError, GuestAddress};
use serde::Serialize;

/// Separate compiler-side key selector; never contains process key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PointerAuthenticationKey {
    Ia,
    Ib,
    Da,
    Db,
}

/// Register31 is SP only in the two-operand modifier field. The distinct Z
/// encoding denotes zero, while destination31 always denotes the discard XZR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerAuthenticationModifier {
    Register(u8),
    StackPointer,
    Zero,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerAuthenticationOperation {
    // Keep the existing descriptor representation.
    /// Exact HINT source identity: general PACIA X17,X16 remains distinct.
    Sign1716 {
        key: PointerAuthenticationKey,
    },
    Authenticate1716 {
        key: PointerAuthenticationKey,
    },
    LinkRegister(pauth_lr::Instruction),
    SignIbSp,
    AuthenticateIbSp,
    ReturnIbSp,
    Sign {
        key: PointerAuthenticationKey,
        destination: u8,
        modifier: PointerAuthenticationModifier,
    },
    Authenticate {
        key: PointerAuthenticationKey,
        destination: u8,
        modifier: PointerAuthenticationModifier,
    },
    Strip {
        data: bool,
        destination: u8,
    },
    ReturnIaSp,
    GenericCode(pauth_memory::GenericCode),
    Load(pauth_memory::Load),
    Branch {
        key: PointerAuthenticationKey,
        target: u8,
        modifier: PointerAuthenticationModifier,
        link: bool,
    },
}

impl PointerAuthenticationOperation {
    pub const fn is_return(self) -> bool {
        matches!(self, Self::ReturnIbSp | Self::ReturnIaSp)
            || matches!(self, Self::LinkRegister(instruction) if instruction.is_return())
    }

    pub const fn is_transfer(self) -> bool {
        self.is_return() || matches!(self, Self::Branch { .. })
    }

    pub const fn required_key(self) -> Option<PointerAuthenticationKey> {
        match self {
            Self::SignIbSp | Self::AuthenticateIbSp | Self::ReturnIbSp => {
                Some(PointerAuthenticationKey::Ib)
            }
            Self::ReturnIaSp => Some(PointerAuthenticationKey::Ia),
            Self::Sign { key, .. }
            | Self::Authenticate { key, .. }
            | Self::Sign1716 { key }
            | Self::Authenticate1716 { key }
            | Self::Branch { key, .. } => Some(key),
            Self::LinkRegister(instruction) => match instruction.key() {
                Some(pauth_lr::Key::Ia) => Some(PointerAuthenticationKey::Ia),
                Some(pauth_lr::Key::Ib) => Some(PointerAuthenticationKey::Ib),
                None => None,
            },
            Self::Load(load) => Some(match load.key {
                pauth_memory::DataKey::A => PointerAuthenticationKey::Da,
                pauth_memory::DataKey::B => PointerAuthenticationKey::Db,
            }),
            Self::Strip { .. } | Self::GenericCode(_) => None,
        }
    }
}

/// A helper request at an instruction that has not executed. The block commits
/// the instructions before it but performs no PAC operation or transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PointerAuthentication {
    pub operation: PointerAuthenticationOperation,
    pub instruction_pc: GuestAddress,
    pub next_pc: GuestAddress,
}

/// PAC/AUT (integer and HINT forms), XPAC, PACGA and authenticated loads. Keys
/// and the PAuth1/PAuth2/FPAC policy come from the runtime context.
/// FEAT_PAuth_LR forms need LR and PACM state, so key-only consumers refuse
/// them. GCS and dynamic controls are unsupported. Consumers re-validate the
/// descriptor against the source bytes.
pub fn decode_pointer_authentication(
    pc: GuestAddress,
    word: u32,
) -> Result<Option<PointerAuthentication>, CompileError> {
    use PointerAuthenticationKey::{Da, Db, Ia, Ib};
    use PointerAuthenticationModifier::{Register, StackPointer, Zero};
    use PointerAuthenticationOperation::{Authenticate, Sign, Strip};
    if !pc.0.is_multiple_of(4) {
        return Err(
            CompileError::new(crate::CompileErrorKind::MisalignedInstructionAddress)
                .at_instruction(pc, word),
        );
    }
    // The PAuth and PAuth_LR forms below occupy these encoding classes.
    // Reject other words before probing the exact forms and operand masks.
    if !matches!(word >> 24, 0x55 | 0x9a | 0xd5..=0xd7 | 0xda | 0xf3 | 0xf8) {
        return Ok(None);
    }
    let operation = if let Some(instruction) = pauth_lr::decode(word) {
        PointerAuthenticationOperation::LinkRegister(instruction)
    } else {
        match word {
            0xd503237f => PointerAuthenticationOperation::SignIbSp,
            0xd50323ff => PointerAuthenticationOperation::AuthenticateIbSp,
            0xd65f0fff => PointerAuthenticationOperation::ReturnIbSp,
            0xd65f0bff => PointerAuthenticationOperation::ReturnIaSp,
            0xd503211f => PointerAuthenticationOperation::Sign1716 { key: Ia },
            0xd503215f => PointerAuthenticationOperation::Sign1716 { key: Ib },
            0xd503219f => PointerAuthenticationOperation::Authenticate1716 { key: Ia },
            0xd50321df => PointerAuthenticationOperation::Authenticate1716 { key: Ib },
            0xd503233f => Sign {
                key: Ia,
                destination: 30,
                modifier: StackPointer,
            },
            0xd50323bf => Authenticate {
                key: Ia,
                destination: 30,
                modifier: StackPointer,
            },
            0xd503231f => Sign {
                key: Ia,
                destination: 30,
                modifier: Zero,
            },
            0xd503235f => Sign {
                key: Ib,
                destination: 30,
                modifier: Zero,
            },
            0xd503239f => Authenticate {
                key: Ia,
                destination: 30,
                modifier: Zero,
            },
            0xd50323df => Authenticate {
                key: Ib,
                destination: 30,
                modifier: Zero,
            },
            0xd50320ff => Strip {
                data: false,
                destination: 30,
            },
            _ if word & 0xffffc000 == 0xdac10000 => {
                let rn = ((word >> 5) & 31) as u8;
                let modifier = if word & (1 << 13) != 0 {
                    // The Z forms fix Rn=11111. Do not admit unallocated neighbors.
                    if rn != 31 {
                        return Ok(None);
                    }
                    Zero
                } else if rn == 31 {
                    StackPointer
                } else {
                    Register(rn)
                };
                let key = match (word >> 10) & 3 {
                    0 => Ia,
                    1 => Ib,
                    2 => Da,
                    _ => Db,
                };
                let destination = (word & 31) as u8;
                if word & (1 << 12) == 0 {
                    Sign {
                        key,
                        destination,
                        modifier,
                    }
                } else {
                    Authenticate {
                        key,
                        destination,
                        modifier,
                    }
                }
            }
            _ if word & 0xfffffbe0 == 0xdac143e0 => Strip {
                data: word & (1 << 10) != 0,
                destination: (word & 31) as u8,
            },
            _ if word & 0xfedff800 == 0xd61f0800 => {
                let rm = (word & 31) as u8;
                let modifier = if word & (1 << 24) == 0 {
                    if rm != 31 {
                        return Ok(None);
                    }
                    Zero
                } else if rm == 31 {
                    StackPointer
                } else {
                    Register(rm)
                };
                PointerAuthenticationOperation::Branch {
                    key: if word & (1 << 10) == 0 { Ia } else { Ib },
                    target: ((word >> 5) & 31) as u8,
                    modifier,
                    link: word & (1 << 21) != 0,
                }
            }
            _ => match pauth_memory::decode(word) {
                Some(pauth_memory::Instruction::GenericCode(code)) => {
                    PointerAuthenticationOperation::GenericCode(code)
                }
                Some(pauth_memory::Instruction::Load(load)) => {
                    PointerAuthenticationOperation::Load(load)
                }
                None => return Ok(None),
            },
        }
    };
    Ok(Some(PointerAuthentication {
        operation,
        instruction_pc: pc,
        next_pc: GuestAddress(
            pc.0.checked_add(4)
                .ok_or_else(|| CompileError::new(crate::CompileErrorKind::GuestAddressOverflow))?,
        ),
    }))
}
