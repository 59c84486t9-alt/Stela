//! Block chaining for the system-mode engine: a block's direct exit to a
//! static successor can be redirected through a thunk straight into the
//! successor's code, so the dispatcher runs once for a chain of blocks.
//!
//! The engine owns one [`ChainControl`] at a fixed host address. Before it
//! enters a block it sets `budget` to the chained transfers it allows,
//! `retired` to 0 and `block` to the entered block's index. Each thunk takes
//! one transfer from `budget` (or, when none is left, exits exactly as the
//! redirected exit would), adds the instructions of the block it leaves to
//! `retired` and names the block it enters in `block`. After the native
//! call returns, `block` is the block whose exit or fault ended the run.
//! Thunks clobber only RAX, RCX, RDX and flags, which every direct exit
//! already may.
use crate::{GuestAddress, block::ExitKind};
use alloc::vec::Vec;

/// Bytes in a direct exit: `movabs rax, target; mov edx, kind; ret`.
pub const DIRECT_EXIT_BYTES: usize = 16;
/// Bytes a redirection writes over the start of a direct exit.
pub const JUMP_BYTES: usize = 5;
/// Bytes in a [`thunk`].
pub const THUNK_BYTES: usize = 37 + DIRECT_EXIT_BYTES;

/// A direct exit to a static successor in a block's code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectExit {
    /// Its offset in the block's code.
    pub offset: usize,
    pub target: GuestAddress,
    pub kind: ExitKind,
}

/// The engine's chaining state, which thunks address absolutely.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChainControl {
    /// Chained transfers still allowed; wraps below zero when a thunk
    /// finds none left.
    pub budget: u64,
    /// Instructions of the blocks chained out of.
    pub retired: u64,
    /// The index of the block running.
    pub block: u64,
}

// `sub qword [rcx],1` addresses the budget at offset 0.
const _: () = assert!(core::mem::offset_of!(ChainControl, budget) == 0);
const RETIRED: u8 = core::mem::offset_of!(ChainControl, retired) as u8;
const BLOCK: u8 = core::mem::offset_of!(ChainControl, block) as u8;

/// A direct exit to `target` with `kind`, as every block emits it.
pub fn direct_exit(target: GuestAddress, kind: ExitKind) -> [u8; DIRECT_EXIT_BYTES] {
    let mut code = [0; DIRECT_EXIT_BYTES];
    code[..2].copy_from_slice(&[0x48, 0xb8]); // movabs rax,target
    code[2..10].copy_from_slice(&target.0.to_le_bytes());
    code[10] = 0xba; // mov edx,kind: zero-extends to the ABI's u64
    code[11..15].copy_from_slice(&(kind as u32).to_le_bytes());
    code[15] = 0xc3; // ret
    code
}

/// A thunk at host address `at` that chains a block of `retired`
/// instructions into block `block`, whose code is at `entry`, or takes the
/// direct exit to `target` with `kind` when `control` allows no transfer.
/// `None` when `entry` is out of a 32-bit jump's reach or an operand
/// exceeds its 32-bit field.
pub fn thunk(
    at: u64,
    control: u64,
    retired: u32,
    block: u32,
    entry: u64,
    target: GuestAddress,
    kind: ExitKind,
) -> Option<Vec<u8>> {
    let retired = i32::try_from(retired).ok()?;
    let block = i32::try_from(block).ok()?;
    let mut code = Vec::with_capacity(64);
    code.extend([0x48, 0xb9]); // movabs rcx,control
    code.extend(control.to_le_bytes());
    code.extend([0x48, 0x83, 0x29, 0x01]); // sub qword [rcx],1
    code.extend([0x72, 0]); // jb exit
    let skip = code.len();
    code.extend([0x48, 0x81, 0x41, RETIRED]); // add qword [rcx+retired],imm32
    code.extend(retired.to_le_bytes());
    code.extend([0x48, 0xc7, 0x41, BLOCK]); // mov qword [rcx+block],imm32
    code.extend(block.to_le_bytes());
    code.extend(jump(at + code.len() as u64, entry)?);
    code[skip - 1] = (code.len() - skip) as u8;
    code.extend(direct_exit(target, kind));
    debug_assert_eq!(code.len(), THUNK_BYTES);
    Some(code)
}

/// `jmp rel32` at host address `at` to `to`, or `None` out of reach.
pub fn jump(at: u64, to: u64) -> Option<[u8; JUMP_BYTES]> {
    let relative = i32::try_from(to.wrapping_sub(at + JUMP_BYTES as u64) as i64).ok()?;
    let mut code = [0xe9, 0, 0, 0, 0];
    code[1..].copy_from_slice(&relative.to_le_bytes());
    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn direct_exits_match_the_block_emitter() {
        let mut emitted = Vec::new();
        super::super::block::direct_exit(&mut emitted, GuestAddress(0x1234), ExitKind::Direct);
        assert_eq!(emitted, direct_exit(GuestAddress(0x1234), ExitKind::Direct));
    }

    #[test]
    fn thunks_count_name_and_jump_or_exit() {
        let code = thunk(
            0x1000,
            0x8877_6655_4433_2211,
            7,
            3,
            0x2000,
            GuestAddress(0xabc),
            ExitKind::Fallthrough,
        )
        .unwrap();
        let mut expected = vec![0x48, 0xb9, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        expected.extend([0x48, 0x83, 0x29, 0x01, 0x72, 21]);
        expected.extend([0x48, 0x81, 0x41, 0x08, 7, 0, 0, 0]);
        expected.extend([0x48, 0xc7, 0x41, 0x10, 3, 0, 0, 0]);
        // The jump ends 0x25 bytes into the thunk.
        expected.extend([0xe9]);
        expected.extend((0x2000i32 - 0x1025).to_le_bytes());
        expected.extend(direct_exit(GuestAddress(0xabc), ExitKind::Fallthrough));
        assert_eq!(code, expected);
        assert!(thunk(0, 0, 0, 0, 1 << 40, GuestAddress(0), ExitKind::Direct).is_none());
    }

    #[test]
    fn jumps_reach_32_bits_either_way() {
        assert_eq!(jump(0x1000, 0x1005), Some([0xe9, 0, 0, 0, 0]));
        assert_eq!(jump(0x1000, 0x1000), Some([0xe9, 0xfb, 0xff, 0xff, 0xff]));
        assert_eq!(jump(0, 1 << 32), None);
    }
}
