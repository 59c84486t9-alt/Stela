// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Scalar publication boundaries in the aligned UCSI shared mailbox.
use core::ptr::NonNull;

/// # Safety
/// Base must be aligned to eight bytes and cover the live UCSI mailbox.
#[inline(always)]
pub(super) unsafe fn version(base: NonNull<u8>) -> u16 {
    // SAFETY: caller guarantees live aligned mapping of at least 16 bytes.
    u16::from_le(unsafe { base.as_ptr().cast::<u16>().read_volatile() })
}
/// # Safety
/// Same mapping contract as version. CCI is one firmware-published word;
/// bytewise loads could combine length/connector and completion generations.
#[inline(always)]
pub(super) unsafe fn cci(base: NonNull<u8>) -> u32 {
    // SAFETY: base + 4 is four-byte aligned within the guaranteed mapping.
    u32::from_le(unsafe { base.as_ptr().add(4).cast::<u32>().read_volatile() })
}
/// # Safety
/// Same mapping contract, with exclusive serialized CPU ownership of CONTROL.
#[inline(always)]
pub(super) unsafe fn control(base: NonNull<u8>, value: u64) {
    // SAFETY: base + 8 is eight-byte aligned within the guaranteed mapping.
    unsafe {
        base.as_ptr()
            .add(8)
            .cast::<u64>()
            .write_volatile(value.to_le())
    };
}
