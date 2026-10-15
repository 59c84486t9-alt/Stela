//! One owned contextual block invocation and explicit numerical completion.
//! This does not resolve successors, register code regions or persist artifacts.

use std::{marker::PhantomData, rc::Rc};

use anyhow::{Context, Result, ensure};
use stela_compiler::{
    GuestAddress, SOURCE_FINGERPRINT_MATERIAL, TargetCpu,
    block::{BlockExit, BlockProfile, ExitKind, MAX_BLOCK_INSTRUCTIONS},
    context::{CONTEXT_BLOCK_ABI, ExecutionContext},
    extended::{CONTEXT_WRAPPER_BYTES, block::ExtendedBlockProfile},
};
use stela_core::sha256;

pub use crate::floating::scalable::CompletionError;
use crate::{
    blocks::{ThreadState, scalable::validate_scalable_numerical_exit},
    execution::{MAX_NATIVE_BYTES, platform},
    floating,
};

use super::{ScalableState, context::ContextLoan};

const INSTRUCTION_BYTES: usize = size_of::<u32>();

/// Identity of this owned in-memory translation, distinct from existing leaf
/// and direct-RAM block ABIs. This is not a persistent-cache or image identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScalableBlockIdentity {
    pub source_sha256: String,
    pub native_sha256: String,
    pub compiler_source_sha256: String,
    pub guest_base: GuestAddress,
    pub abi: &'static str,
    pub target_cpu: String,
    pub profile: ExtendedBlockProfile,
}

/// Owns the exact consumed source and its immutable RX translation. The caller
/// retains application image/build identity and any source-registration lease.
#[derive(Debug)]
pub struct PreparedScalableBlock {
    identity: ScalableBlockIdentity,
    source: Box<[u8]>,
    source_map: Box<[(GuestAddress, usize)]>,
    native_bytes: usize,
    target: TargetCpu,
    mapping: platform::Mapping,
    _serialized: PhantomData<Rc<()>>,
}

impl PreparedScalableBlock {
    pub fn prepare(
        source: &[u8],
        base: GuestAddress,
        profile: ExtendedBlockProfile,
        target: TargetCpu,
    ) -> Result<Self> {
        ensure!(
            profile.services() == BlockProfile::Ordinary,
            "context block services are not integrated"
        );
        ensure!(
            source.len() <= MAX_BLOCK_INSTRUCTIONS * INSTRUCTION_BYTES,
            "context block exceeds the compiler instruction bound"
        );
        platform::ensure_supported()?;
        ensure!(target.supported(), "host lacks context-block requirements");
        let compiled =
            stela_compiler::extended::block::compile_for_profile(source, base, profile, target)?;
        ensure!(
            compiled.source_bytes > 0
                && compiled.source_bytes.is_multiple_of(INSTRUCTION_BYTES)
                && compiled.source_bytes <= source.len(),
            "invalid context block consumed extent"
        );
        let source: Box<[u8]> = source[..compiled.source_bytes].into();
        let native = compiled.native;
        ensure!(
            !native.x86_64_code.is_empty() && native.x86_64_code.len() <= MAX_NATIVE_BYTES,
            "context block native size exceeds execution bound"
        );
        ensure!(
            native.source_map.len() == source.len() / INSTRUCTION_BYTES,
            "context block source map extent mismatch"
        );
        let mut prior_offset = CONTEXT_WRAPPER_BYTES;
        for (index, &(pc, offset)) in native.source_map.iter().enumerate() {
            let expected = base
                .0
                .checked_add(u64::try_from(index * INSTRUCTION_BYTES)?)
                .context("context block source map address overflow")?;
            ensure!(
                pc.0 == expected
                    && offset >= prior_offset
                    && offset < native.x86_64_code.len()
                    && (index != 0 || offset == CONTEXT_WRAPPER_BYTES),
                "invalid context block source map"
            );
            prior_offset = offset;
        }
        let identity = ScalableBlockIdentity {
            source_sha256: sha256(&source),
            native_sha256: sha256(&native.x86_64_code),
            compiler_source_sha256: sha256(SOURCE_FINGERPRINT_MATERIAL.as_bytes()),
            guest_base: base,
            abi: CONTEXT_BLOCK_ABI,
            target_cpu: target.id(),
            profile,
        };
        let mapping = platform::Mapping::new(&native.x86_64_code)?;
        Ok(Self {
            identity,
            source,
            source_map: native.source_map.into_boxed_slice(),
            native_bytes: native.x86_64_code.len(),
            target,
            mapping,
            _serialized: PhantomData,
        })
    }

    pub fn identity(&self) -> &ScalableBlockIdentity {
        &self.identity
    }

    pub fn source(&self) -> &[u8] {
        &self.source
    }

    pub fn source_map(&self) -> &[(GuestAddress, usize)] {
        &self.source_map
    }

    pub fn native_bytes(&self) -> usize {
        self.native_bytes
    }

    /// Invoke exactly once and return the actual native BlockExit unchanged.
    /// The thread PC follows that exit, so a numerical exit retains the PC of
    /// its still-unexecuted instruction until complete_numerical succeeds.
    ///
    /// # Safety
    /// The caller must bind guest feature availability, effective SMCR controls,
    /// NumericalFeatures and required DIT to this exact prepared profile. Owned
    /// register views validate storage and mode, not those external controls.
    /// Source/generated bytes must be trusted and finite; register owners, RX
    /// code, context, native stack and live Rust references must remain disjoint.
    /// The contextual block compiler explicitly declines decoded memory effects
    /// until checked block memory entry exists, plus mode writes and unintegrated
    /// services. No signal recovery or unwind through native code is supplied.
    pub unsafe fn invoke(
        &self,
        state: &mut ThreadState,
        scalable: &mut ScalableState,
        context: &mut ExecutionContext,
    ) -> Result<BlockExit> {
        ensure!(
            context.has_supported_header(),
            "unsupported execution context"
        );
        ensure!(
            self.target.supported(),
            "context-block host requirements changed"
        );
        ensure!(
            state.pc == self.identity.guest_base,
            "context block invocation PC differs from prepared entry"
        );
        let profile = self.identity.profile.scalable();
        ensure!(
            scalable.vector_length() == profile.vector_length()
                && scalable.mode() == profile.mode(),
            "owned scalable state differs from prepared profile"
        );
        // SAFETY: The owner pins all register buffers during the synchronous
        // call. ContextLoan restores its pointers before that owner loan ends.
        let exit = unsafe {
            scalable.with_view(|view| {
                let mut loan = ContextLoan::scalable(context, view);
                profile.validate_view(loan.context(), view)?;
                self.mapping
                    .call_context_block(&mut state.registers, loan.context())
            })
        }?;
        let kind = ExitKind::try_from(exit.kind)
            .map_err(|_| anyhow::anyhow!("invalid context block exit kind"))?;
        ensure!(
            matches!(
                kind,
                ExitKind::Fallthrough
                    | ExitKind::Direct
                    | ExitKind::Indirect
                    | ExitKind::Call
                    | ExitKind::Return
                    | ExitKind::Trap
                    | ExitKind::ScalableNumerical
            ),
            "context block returned an unintegrated service exit"
        );
        if kind == ExitKind::ScalableNumerical {
            self.recover_numerical(exit)?;
        }
        state.pc = GuestAddress(exit.next_pc);
        Ok(exit)
    }

    /// Complete an exit matching this object's exact consumed numerical source.
    /// The caller sequences it after invocation; invocation lineage is not tracked.
    /// No prefix is invoked again. Re-fetch original source and
    /// validate current owned profile before any numerical effect. On failure
    /// PC stays at the numerical instruction; prior native prefix effects remain.
    /// The returned next PC is completion's result, not a synthetic native exit.
    pub fn complete_numerical(
        &self,
        state: &mut ThreadState,
        scalable: &mut ScalableState,
        exit: BlockExit,
    ) -> Result<GuestAddress, CompletionError> {
        let instruction = self.recover_numerical(exit)?;
        if state.pc != instruction.instruction_pc() {
            return Err(anyhow::anyhow!("numerical completion PC differs from native exit").into());
        }
        floating::scalable::complete(&mut state.registers, scalable, &instruction)?;
        state.pc = instruction.next_pc();
        Ok(state.pc)
    }

    fn recover_numerical(
        &self,
        exit: BlockExit,
    ) -> Result<stela_compiler::block::scalable::AdmittedScalableNumericalInstruction> {
        ensure!(
            exit.kind == ExitKind::ScalableNumerical as u64,
            "context block exit is not scalable numerical"
        );
        validate_scalable_numerical_exit(
            self.identity.guest_base,
            GuestAddress(exit.next_pc),
            self.source.len(),
            self.identity.guest_base.0,
            &self.source,
            self.identity.profile.scalable(),
            self.identity.profile.numerical_features(),
        )
    }
}

#[cfg(test)]
mod numerical22_tests;

#[cfg(test)]
mod sme_completion_tests;
