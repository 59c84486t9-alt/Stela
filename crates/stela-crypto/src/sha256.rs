// SPDX-License-Identifier: MIT OR Apache-2.0
// Portions copyright (c) 2006-2009 Graydon Hoare, 2009-2013 Mozilla Foundation,
// and 2016 Artyom Pavlov; distributed under the accompanying RustCrypto licenses.
//! RustCrypto's block-buffered SHA-256 interface over the host compressor.
use core::fmt;
use sha2::digest::{
    HashMarker, Output, Reset,
    block_buffer::Eager,
    core_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, CoreWrapper, FixedOutputCore,
        OutputSizeUser, UpdateCore,
    },
    typenum::{U32, U64},
};

/// SHA-256 with the host's usable compression backend.
pub type Sha256 = CoreWrapper<Sha256Core>;

/// SHA-256 chaining state; buffering and the public Digest API are RustCrypto's.
#[derive(Clone)]
pub struct Sha256Core {
    state: [u32; 8],
    blocks: u64,
}

impl Default for Sha256Core {
    fn default() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            blocks: 0,
        }
    }
}
impl HashMarker for Sha256Core {}
impl BlockSizeUser for Sha256Core {
    type BlockSize = U64;
}
impl BufferKindUser for Sha256Core {
    type BufferKind = Eager;
}
impl OutputSizeUser for Sha256Core {
    type OutputSize = U32;
}
impl Reset for Sha256Core {
    fn reset(&mut self) {
        *self = Self::default();
    }
}
impl UpdateCore for Sha256Core {
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.blocks = self.blocks.wrapping_add(blocks.len() as u64);
        compress(&mut self.state, blocks);
    }
}
impl FixedOutputCore for Sha256Core {
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
impl AlgorithmName for Sha256Core {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256")
    }
}
impl fmt::Debug for Sha256Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256Core { ... }")
    }
}
fn compress(state: &mut [u32; 8], blocks: &[Block<Sha256Core>]) {
    #[cfg(target_arch = "x86_64")]
    if super::x86_64::sha_usable() {
        // SAFETY: complete blocks have 64-byte stride, the state is writable,
        // and the CPU and OS controls admit the kernel's SSE and SHA forms.
        unsafe {
            super::x86_64::sha256(state.as_mut_ptr(), blocks.as_ptr().cast(), blocks.len());
        }
        return;
    }
    sha2::compress256(state, blocks);
}
