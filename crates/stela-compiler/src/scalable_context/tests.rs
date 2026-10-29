use super::*;
use crate::{
    Lifter,
    aarch64::{
        Decoder,
        scalable::{
            ElementSize, ScalableMode, VectorLength,
            features::{ScalableFeature, ScalableFeatures},
            profile::ScalableControls,
        },
    },
    context::{ExecutionContext, ScalableStateView},
};
use alloc::string::ToString;
use alloc::{vec, vec::Vec};

/// x86 `ret`, which ends a context leaf's code.
const RET: u8 = 0xc3;

mod address;
mod boundaries;
mod checked_pair;
mod dot;
mod integer;
mod integer_bits;
mod integer_products;
mod memory_load;
mod memory_multi;
mod memory_store;
mod memory_structure;
mod movement;
mod predicate_generation;
mod predicate_logic;
mod predicate_move;
mod prefix_pair;
mod profile;
mod rearrange;
mod rearrange_extract;
mod reductions;
mod shifts;
mod sme2p1;
mod sme_integer;
mod sme_memory;
mod tables;

const RET_X30: u32 = 0xd65f_03c0;
const NOP: u32 = 0xd503_201f;
const AND_Z0_Z1_Z2: u32 = 0x0422_3020;
const MOVPRFX_Z0_Z1: u32 = 0x0420_bc20;
const RDSVL_X0_ONE: u32 = 0x04bf_5820;

fn profile(bytes: usize, streaming: bool) -> ScalableProfile {
    ScalableProfile::new(
        VectorLength::from_bytes(bytes).unwrap(),
        ScalableMode::new(streaming, false),
    )
}

fn words(input: &[u32]) -> Vec<u8> {
    input.iter().flat_map(|word| word.to_le_bytes()).collect()
}

const TABLE_LOOKUP: u32 = 0xc0cc0000;
const TABLE_SELECT: u32 = 0xc1208000;
const TABLE_ZIP_PAIR_Q: u32 = 0xc120d400;
const TABLE_ZIP_QUAD_Q: u32 = 0xc137e000;
