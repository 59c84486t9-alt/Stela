//! Single accumulation kernels are separate from true BF arithmetic.
mod accumulation;

pub(in crate::x86_64) use accumulation::emit;
