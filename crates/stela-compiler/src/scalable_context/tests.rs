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
use alloc::vec::Vec;

/// x86 `ret`, which ends a context leaf's code.
const RET: u8 = 0xc3;

mod address;
mod boundaries;
mod checked_pair;
mod dot;
mod family_preflight;
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

/// What a guest NOP lowers to inside a leaf.
const NOP_BODY: &[u8] = &[0x90];

/// A leaf of instructions from `pc`, then RET_X30: the context wrapper,
/// exactly each instruction's body in order, then the `ret` RET_X30 lowers to.
#[track_caller]
fn assert_bodies(native: &NativeBlock, pc: GuestAddress, bodies: &[&[u8]]) {
    assert_eq!(
        &native.x86_64_code[..CONTEXT_WRAPPER_BYTES],
        context_wrapper()
    );
    let mut map = vec![(pc, CONTEXT_WRAPPER_BYTES)];
    let mut end = CONTEXT_WRAPPER_BYTES;
    for (index, body) in (1..).zip(bodies) {
        assert_eq!(&native.x86_64_code[end..end + body.len()], *body);
        end += body.len();
        map.push((GuestAddress(pc.0 + 4 * index), end));
    }
    assert_eq!(native.source_map, map);
    assert_eq!(native.x86_64_code[end..], [RET]);
}

#[track_caller]
fn assert_single_body(native: &NativeBlock, pc: GuestAddress, body: &[u8]) {
    assert_bodies(native, pc, &[body]);
}

const TABLE_LOOKUP: u32 = 0xc0cc0000;
const TABLE_SELECT: u32 = 0xc1208000;
const TABLE_ZIP_PAIR_Q: u32 = 0xc120d400;
const TABLE_ZIP_QUAD_Q: u32 = 0xc137e000;
