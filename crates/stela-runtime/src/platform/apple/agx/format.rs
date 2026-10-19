//! Pixel and texture formats: channel conversions ([`pixel`]) shared by the
//! shader memory instructions, the tilebuffer, texture sampling and the PBE
//! (docs/research/agx.md §5, FMT rows).

pub mod isa;
pub mod pixel;
