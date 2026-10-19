//! Blocks whose memory accesses go through the checked memory service.
use crate::{
    CompileError, GuestAddress, NativeBlock, TargetCpu,
    block::{Terminator, memory::CheckedOperation},
    extended,
};
use alloc::vec::Vec;

pub(crate) fn emit(
    instructions: &[(GuestAddress, CheckedOperation)],
    terminal: Option<&(GuestAddress, Terminator)>,
    fallthrough: GuestAddress,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let mut block = NativeBlock {
        x86_64_code: extended::context_wrapper(),
        source_map: Vec::new(),
    };
    let mut fixups = Vec::new();
    for (pc, instruction) in instructions {
        block.source_map.push((*pc, block.x86_64_code.len()));
        instruction.emit(&mut block.x86_64_code, *pc, target, &mut fixups)?;
    }
    if !fixups.is_empty() {
        return Err(CompileError(
            "checked GPR prefix unexpectedly branches".into(),
        ));
    }
    super::emit_terminal(
        &mut block.x86_64_code,
        &mut block.source_map,
        terminal,
        fallthrough,
        target,
        None,
    );
    Ok(block)
}
