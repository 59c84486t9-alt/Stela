//! Streaming-vector mappings using the shared extended execution context.

pub(crate) mod address;
pub(crate) mod dot;
pub(crate) mod floating_copy;
pub(crate) mod integer_arithmetic;
pub(crate) mod integer_comparison;
pub(crate) mod integer_logic;
pub(crate) mod integer_predicate_move;
pub(crate) mod integer_products;
pub(crate) mod integer_saturation;
pub(crate) mod predicate;
pub(crate) mod predicate_generation;
pub(crate) mod predicate_logic;
pub(crate) mod rearrange;
pub(crate) mod rearrange_extract;
pub(crate) mod rearrange_widen;
pub(crate) mod reductions;
pub(crate) mod sign;
