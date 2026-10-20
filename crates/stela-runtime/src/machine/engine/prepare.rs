//! Block preparation: what the engine compiles for the source window at an
//! entry PC, as a pure function of the window's bytes, the PC and a
//! [`Preparation`] (the chip, the x86 target and the block variant).
//!
//! The engine prepares every block it fetches through it, and so do the
//! threads that prepare blocks off the guest's path: the translation
//! store's provers and ahead-of-time translation of mapped images. A block
//! prepared anywhere is the block the engine would compile at that PC from
//! those bytes in that variant, which is what lets the store key it by its
//! page bytes and context alone.
use super::{FETCH_PAGE, INSTRUCTION, MAX_BLOCK_BYTES, PROFILE, is_floating_point};
use crate::{
    machine::chip::{AdmitTable, Check, Chip},
    translations::{self, Digest},
};
use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
use stela_compiler::{
    CompileError, GuestAddress, TargetCpu,
    block::{self, CompilationPlan, CompiledBlock},
    x86_64::{MemoryChecks, NativeSystem},
};

/// The bytes of the source window of a block at `pc`: to the end of its
/// fetch page, which no block leaves, and at most a block's.
pub fn window(pc: u64) -> usize {
    (FETCH_PAGE - (pc & (FETCH_PAGE - 1))).min(MAX_BLOCK_BYTES) as usize
}

/// How blocks of one variant are compiled.
#[derive(Debug, Clone)]
pub struct Preparation {
    chip: Chip,
    admit: Arc<AdmitTable>,
    target: TargetCpu,
    /// FP/SIMD enabled: otherwise a block ends before the first FP/SIMD
    /// instruction.
    fp: bool,
    checks: MemoryChecks,
    /// The PE has SME, and PSTATE.SM.
    scalable: Option<bool>,
    system: NativeSystem,
}

/// The inputs of a [`Preparation`], serializable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Description {
    pub chip: Chip,
    pub target: TargetCpu,
    pub fp: bool,
    pub checks: MemoryChecks,
    pub scalable: Option<bool>,
    pub system: NativeSystem,
}

/// What a source window prepares to.
#[derive(Debug)]
pub enum Prepared {
    /// The block, the bytes of the window the compiler was given, and the
    /// entry PCs its static successors (call continuations included) have.
    Block {
        compiled: CompiledBlock,
        input: usize,
        successors: Vec<u64>,
    },
    /// Its first instruction, an FP/SIMD or scalable one, has an access
    /// check the engine applies before it runs.
    Checked(u32),
    /// Its first instruction is an FP/SIMD one while FP/SIMD is trapped.
    FloatingPointTrap,
}

/// The first word of a window no block can be compiled from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refused {
    pub pc: u64,
    pub detail: String,
}

impl Preparation {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        chip: Chip,
        admit: Arc<AdmitTable>,
        target: TargetCpu,
        fp: bool,
        checks: MemoryChecks,
        scalable: Option<bool>,
        system: NativeSystem,
    ) -> Self {
        Self {
            chip,
            admit,
            target,
            fp,
            checks,
            scalable,
            system,
        }
    }

    /// What decides this preparation, for another process to make it again
    /// ([`Self::from_description`]).
    pub fn description(&self) -> Description {
        Description {
            chip: self.chip,
            target: self.target,
            fp: self.fp,
            checks: self.checks,
            scalable: self.scalable,
            system: self.system,
        }
    }

    pub fn from_description(description: &Description) -> Self {
        let Description {
            chip,
            target,
            fp,
            checks,
            scalable,
            system,
        } = *description;
        Self::new(
            chip,
            Arc::new(chip.admit_table()),
            target,
            fp,
            checks,
            scalable,
            system,
        )
    }
    /// Replace each word of `source` with the one the chip executes: a
    /// form the chip lacks compiles as the UDF or NOP it executes as.
    pub fn admit(&self, source: &mut [u8]) {
        for bytes in source.as_chunks_mut::<4>().0 {
            *bytes = self.admit.admit(u32::from_le_bytes(*bytes)).to_le_bytes();
        }
    }

    /// The entry context of blocks prepared with this in the page at
    /// `page`: everything besides their bytes and offset that shapes their
    /// compilation (`docs/design/runtime.md#persistent-translation-store`).
    pub fn context(&self, page: u64) -> Digest {
        let Self {
            chip,
            admit: _,
            target,
            fp,
            checks,
            scalable,
            system,
        } = self;
        let described = format!(
            "chip {chip:?} target {target:?} fp {fp} checks {checks:?} scalable {scalable:?} \
             system {system:?} class {:#x}",
            translations::address_class(page)
        );
        Digest::of(described.as_bytes())
    }

    /// Compile the admitted words `input` at `pc` as the engine compiles a
    /// block's consumed prefix.
    pub fn compile_input(&self, input: &[u8], pc: u64) -> Result<CompiledBlock, CompileError> {
        CompilationPlan::new(input, GuestAddress(pc), PROFILE, self.target)
            .and_then(|plan| plan.with_memory_checks(self.checks))
            .and_then(|plan| plan.with_zero_block(self.system.zero_block))
            .and_then(|plan| plan.with_cache_clean(self.system.cache_clean))
            .and_then(CompilationPlan::compile)
    }

    /// Prepare the block at `pc` from the admitted window `source`, which
    /// holds the bytes to the end of its fetch page (at most a block's),
    /// ending it at `limit` bytes, before a host breakpoint or trace point.
    pub fn prepare(&self, source: &[u8], pc: u64, limit: usize) -> Result<Prepared, Refused> {
        let word = |index: usize| {
            u32::from_le_bytes(source[index * 4..index * 4 + 4].try_into().expect("a word"))
        };
        let mut length = limit.min(source.len());
        if !self.fp {
            let first = source
                .as_chunks::<4>()
                .0
                .iter()
                .position(|word| is_floating_point(u32::from_le_bytes(*word)));
            match first {
                // CheckFPMREnabled comes before the FP access check.
                Some(0) if self.chip.checks(word(0)).contains(&Check::Fpmr) => {
                    return Ok(Prepared::Checked(word(0)));
                }
                Some(0) => return Ok(Prepared::FloatingPointTrap),
                Some(index) => length = length.min(index * 4),
                None => {}
            }
        }
        if let Some(streaming) = self.scalable {
            let first = source.as_chunks::<4>().0[..length / 4]
                .iter()
                .map(|word| u32::from_le_bytes(*word))
                .position(|word| {
                    let checks = self.chip.checks(word);
                    if streaming {
                        !checks.is_empty()
                    } else {
                        checks
                            .iter()
                            .any(|check| !matches!(check, Check::Fp | Check::FpAdvSimd))
                    }
                });
            match first {
                Some(0) => return Ok(Prepared::Checked(word(0))),
                Some(index) => length = index * 4,
                None => {}
            }
        }
        let refused = |at: u64, detail: String| Refused { pc: at, detail };
        let analysis =
            match block::analyze_with_profile(&source[..length], GuestAddress(pc), PROFILE) {
                Ok(analysis) => analysis,
                Err(error) if error.pc.0 > pc => {
                    length = (error.pc.0 - pc) as usize;
                    block::analyze_with_profile(&source[..length], GuestAddress(pc), PROFILE)
                        .map_err(|error| refused(error.pc.0, error.detail))?
                }
                Err(error) => return Err(refused(pc, error.detail)),
            };
        let consumed = analysis.source_bytes;
        let (compiled, input) = self.compile_prefix(&source[..consumed], pc)?;
        // A block a host refusal cut short falls through to the refused
        // word; a whole one has the analysis's static successors.
        let successors = if input < consumed {
            vec![pc + input as u64]
        } else {
            analysis
                .static_successors
                .iter()
                .map(|successor| successor.target.0)
                .collect()
        };
        Ok(Prepared::Block {
            compiled,
            input,
            successors,
        })
    }

    /// Compile the longest prefix of `source` the target can emit, and the
    /// bytes of it the compiler was given.
    fn compile_prefix(&self, source: &[u8], pc: u64) -> Result<(CompiledBlock, usize), Refused> {
        let refused = |error: CompileError| Refused {
            pc,
            detail: error.0,
        };
        match self.compile_input(source, pc) {
            Ok(compiled) => Ok((compiled, source.len())),
            Err(error) => {
                // A host-capability refusal names no PC; find the longest
                // prefix that compiles and report the first refused word.
                let words = source.len() / INSTRUCTION as usize;
                let (mut good, mut bad) = (0, words);
                while bad - good > 1 {
                    let middle = (good + bad) / 2;
                    if self.compile_input(&source[..middle * 4], pc).is_ok() {
                        good = middle;
                    } else {
                        bad = middle;
                    }
                }
                if good == 0 {
                    return Err(refused(error));
                }
                self.compile_input(&source[..good * 4], pc)
                    .map(|compiled| (compiled, good * 4))
                    .map_err(refused)
            }
        }
    }
}

/// A preparation of the test chip for the baseline target, as a process
/// profile compiles.
#[cfg(test)]
pub(crate) fn test_preparation() -> Preparation {
    let chip = crate::machine::test_chip();
    Preparation::new(
        chip,
        Arc::new(chip.admit_table()),
        TargetCpu::Baseline,
        true,
        MemoryChecks::DEFAULT,
        None,
        NativeSystem::NONE,
    )
}
