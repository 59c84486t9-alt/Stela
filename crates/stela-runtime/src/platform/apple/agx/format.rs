//! Pixel and texture formats: channel conversions ([`pixel`]) shared by the
//! shader memory instructions, the tilebuffer, texture sampling and the PBE;
//! the formats of shader memory instructions ([`isa`]); texture, PBE and
//! sampler descriptors ([`descriptor`]); image layouts ([`layout`]); texel
//! formats ([`texel`]) and their block codecs ([`block`], [`bptc`],
//! [`astc`]) (docs/research/agx.md §5, FMT rows).

pub mod astc;
pub mod block;
pub mod bptc;
pub mod compression;
pub mod descriptor;
pub mod image;
pub mod isa;
pub mod layout;
pub mod pixel;
pub mod sample;
pub mod texel;
