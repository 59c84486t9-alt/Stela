// SPDX-License-Identifier: MIT OR Apache-2.0
// Portions copyright (c) 2006-2009 Graydon Hoare, 2009-2013 Mozilla Foundation,
// and 2016 Artyom Pavlov; distributed under the accompanying RustCrypto licenses.
//! RustCrypto's block-buffered SHA-1 interface over the host compressor.
use ::sha1::digest::{
    HashMarker, Output, Reset,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, UpdateCore,
    },
    typenum::{U20, U64},
};
use core::fmt;

/// SHA-1 with the host's usable compression backend.
pub type Sha1 = CoreWrapper<Sha1Core>;

/// SHA-1 chaining state; buffering and the public Digest API are RustCrypto's.
#[derive(Clone)]
pub struct Sha1Core {
    state: [u32; 5],
    blocks: u64,
}

impl Default for Sha1Core {
    fn default() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            blocks: 0,
        }
    }
}
impl HashMarker for Sha1Core {}
impl BlockSizeUser for Sha1Core {
    type BlockSize = U64;
}
impl BufferKindUser for Sha1Core {
    type BufferKind = Eager;
}
impl OutputSizeUser for Sha1Core {
    type OutputSize = U20;
}
impl Reset for Sha1Core {
    fn reset(&mut self) {
        *self = Self::default();
    }
}
impl UpdateCore for Sha1Core {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks = self.blocks.wrapping_add(blocks.len() as u64);
        compress(&mut self.state, blocks);
    }
}
impl FixedOutputCore for Sha1Core {
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let bit_len = self
            .blocks
            .wrapping_mul(64)
            .wrapping_add(buffer.get_pos() as u64)
            .wrapping_mul(8);
        buffer.len64_padding_be(bit_len, |block| {
            compress(&mut self.state, core::slice::from_ref(block))
        });
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
}
impl AlgorithmName for Sha1Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1")
    }
}
impl fmt::Debug for Sha1Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha1Core { ... }")
    }
}
fn compress(state: &mut [u32; 5], blocks: &[Block<Sha1Core>]) {
    #[cfg(target_arch = "x86_64")]
    if super::x86_64::sha_usable() {
        // SAFETY: complete blocks have 64-byte stride, the state is writable,
        // and the CPU and OS controls admit the kernel's SSE and SHA forms.
        unsafe {
            super::x86_64::sha1(state.as_mut_ptr(), blocks.as_ptr().cast(), blocks.len());
        }
        return;
    }
    ::sha1::compress(state, blocks);
}
