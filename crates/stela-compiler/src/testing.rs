//! [`crate::compile`] with the options most tests use.
use crate::{
    CompileError, GuestAddress, NativeBlock, Options, TargetCpu,
    aarch64::floating::features::NumericalFeatures,
    block::{BlockProfile, CompiledBlock, Features},
    scalable_context::ScalableProfile,
};

/// A leaf, which must end in RET X30, for the baseline host.
pub(crate) fn leaf(source: &[u8], base: GuestAddress) -> Result<NativeBlock, CompileError> {
    leaf_for(source, base, TargetCpu::Baseline)
}

pub(crate) fn leaf_for(
    source: &[u8],
    base: GuestAddress,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let options = Options::new(BlockProfile::new(Features::LEAF), target);
    crate::compile(source, base, &options).map(|block| block.native)
}

/// An ordinary block for the baseline host.
pub(crate) fn block(source: &[u8], base: GuestAddress) -> Result<CompiledBlock, CompileError> {
    block_for(source, base, BlockProfile::ORDINARY, TargetCpu::Baseline)
}

pub(crate) fn block_with(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
) -> Result<CompiledBlock, CompileError> {
    block_for(source, base, profile, TargetCpu::Baseline)
}

pub(crate) fn block_for(
    source: &[u8],
    base: GuestAddress,
    profile: BlockProfile,
    target: TargetCpu,
) -> Result<CompiledBlock, CompileError> {
    crate::compile(source, base, &Options::new(profile, target))
}

/// A context leaf for `scalable`.
pub(crate) fn context_leaf(
    source: &[u8],
    base: GuestAddress,
    scalable: ScalableProfile,
    target: TargetCpu,
) -> Result<NativeBlock, CompileError> {
    let options = Options::new(
        BlockProfile::new(Features::LEAF | Features::CONTEXT),
        target,
    )
    .with_scalable(scalable);
    crate::compile(source, base, &options).map(|block| block.native)
}

/// A context block for `scalable`, completing numerical forms for
/// `numerical`.
pub(crate) fn context_block(
    source: &[u8],
    base: GuestAddress,
    scalable: ScalableProfile,
    numerical: NumericalFeatures,
    target: TargetCpu,
) -> Result<CompiledBlock, CompileError> {
    let options = Options::new(BlockProfile::new(Features::CONTEXT), target)
        .with_scalable(scalable)
        .with_numerical_features(numerical);
    crate::compile(source, base, &options)
}

/// A context leaf's code with the execution requirements its plan derives.
pub(crate) struct PreparedLeaf {
    pub(crate) native: NativeBlock,
    pub(crate) execution_requirements:
        crate::aarch64::scalable::execution::ScalableExecutionRequirements,
}

pub(crate) fn prepared_context_leaf(
    source: &[u8],
    base: GuestAddress,
    scalable: ScalableProfile,
    target: TargetCpu,
) -> Result<PreparedLeaf, CompileError> {
    let options = Options::new(
        BlockProfile::new(Features::LEAF | Features::CONTEXT),
        target,
    )
    .with_scalable(scalable);
    let plan = crate::block::CompilationPlan::new(source, base, &options)?;
    let execution_requirements = plan
        .execution_requirements()
        .expect("a context leaf has execution requirements");
    Ok(PreparedLeaf {
        native: plan.compile()?.native,
        execution_requirements,
    })
}

/// The memory service a context leaf needs, from its plan alone.
pub(crate) fn context_leaf_memory(
    source: &[u8],
    base: GuestAddress,
    scalable: ScalableProfile,
    target: TargetCpu,
) -> Result<crate::context::memory::MemoryRequirements, CompileError> {
    let options = Options::new(
        BlockProfile::new(Features::LEAF | Features::CONTEXT),
        target,
    )
    .with_scalable(scalable);
    Ok(crate::block::CompilationPlan::new(source, base, &options)?
        .memory_requirements()
        .expect("a context leaf has memory requirements"))
}
