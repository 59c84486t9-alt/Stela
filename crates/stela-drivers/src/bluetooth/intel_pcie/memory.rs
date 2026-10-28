// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2024 Intel Corporation
//! Ring layout and DMA buffers of the Intel PCIe Bluetooth transport.
use super::{Error, Result};
use crate::bus::dma::{DmaAllocator, DmaBuffer};
pub(super) const TX_COUNT: usize = 32;
pub(super) const RX_COUNT: usize = 64;
pub(super) const BUFFER: usize = 4096;
pub(super) const TFD: usize = 0;
pub(super) const URBD0: usize = 512;
pub(super) const FRBD: usize = 640;
pub(super) const URBD1: usize = 1664;
pub(super) const TR_HEAD: usize = 1920;
pub(super) const TR_TAIL: usize = 2048;
pub(super) const CR_HEAD: usize = 2176;
pub(super) const CR_TAIL: usize = 2304;
pub(super) const CI: usize = 2432;
const POOL: usize = 2688;
const DEBUG_COUNT: usize = 16;
const DEBUG_BYTES: usize = 256 * 1024;
/// Every page is boot-lifetime reserved. Descriptor/index words are accessed
/// volatile while published; packet bytes are touched only with proven ownership.
pub(super) struct Memory {
    pub pool: DmaBuffer,
    pub tx: DmaBuffer,
    pub rx: DmaBuffer,
    pub debug: DmaBuffer,
    pub fragment: DmaBuffer,
}
fn put16(bytes: &mut [u8], at: usize, v: u16) {
    bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, v: u32) {
    bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, v: u64) {
    bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
impl Memory {
    pub fn new(dma: &mut dyn DmaAllocator) -> Result<Self> {
        let mut m = Self {
            pool: dma.allocate(POOL, 128).map_err(Error::Dma)?,
            tx: dma.allocate(TX_COUNT * BUFFER, 128).map_err(Error::Dma)?,
            rx: dma.allocate(RX_COUNT * BUFFER, 128).map_err(Error::Dma)?,
            debug: dma
                .allocate(DEBUG_COUNT * DEBUG_BYTES, 128)
                .map_err(Error::Dma)?,
            fragment: dma.allocate(208, 128).map_err(Error::Dma)?,
        };
        for b in [
            &mut m.pool,
            &mut m.tx,
            &mut m.rx,
            &mut m.debug,
            &mut m.fragment,
        ] {
            b.bytes_mut().fill(0);
        }
        let base = m.pool.physical();
        let fragment = m.fragment.physical();
        let c = &mut m.pool.bytes_mut()[CI..CI + 152];
        put16(c, 0, 1);
        put16(c, 2, 152);
        for (off, address) in [
            (16, base + TR_HEAD as u64),
            (24, base + TR_TAIL as u64),
            (32, base + CR_HEAD as u64),
            (40, base + CR_TAIL as u64),
            (56, base + TFD as u64),
            (64, base + URBD0 as u64),
            (80, base + FRBD as u64),
            (88, base + URBD1 as u64),
        ] {
            put64(c, off, address);
        }
        put16(c, 48, 2);
        put16(c, 50, 2);
        put32(c, 52, 4);
        put16(c, 72, TX_COUNT as u16);
        put16(c, 74, TX_COUNT as u16);
        put16(c, 96, RX_COUNT as u16);
        put16(c, 98, 1);
        put16(c, 100, RX_COUNT as u16);
        put16(c, 102, 1);
        put64(c, 112, fragment);
        put32(c, 120, 208);
        put32(c, 124, 0x10);
        let b = m.fragment.bytes_mut();
        put32(b, 0, 0xa5a5a5a5);
        put32(b, 4, 1);
        put32(b, 8, 196);
        put32(b, 12, DEBUG_COUNT as u32);
        for i in 0..DEBUG_COUNT {
            let address = m.debug.physical() + (i * DEBUG_BYTES) as u64;
            put32(b, 16 + i * 12, address as u32);
            put32(b, 20 + i * 12, (address >> 32) as u32);
            put32(b, 24 + i * 12, DEBUG_BYTES as u32);
        }
        Ok(m)
    }
    pub fn index(&self, array: usize, queue: usize) -> u16 {
        self.pool.read(array + queue * 2)
    }
    pub fn set_index(&mut self, array: usize, queue: usize, index: u16) {
        self.pool.write(array + queue * 2, index);
    }
    pub fn reset_indices(&mut self) {
        for array in [TR_HEAD, TR_TAIL, CR_HEAD, CR_TAIL] {
            for q in 0..2 {
                self.set_index(array, q, 0);
            }
        }
    }
    pub fn descriptor(&mut self, offset: usize, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            self.pool.write(offset + i, byte);
        }
    }
}
