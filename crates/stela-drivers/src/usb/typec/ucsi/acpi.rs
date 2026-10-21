// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2017 Intel Corporation
// Copyright (c) 2026 Stela contributors
//! Real UCSI ACPI shared-memory transport, following pinned Linux ucsi_acpi.c.
//! Discovery, mapping lifetime, AML execution and Notify dispatch are supplied
//! by the native platform. This module cannot create a platform attachment.

use super::{Transport, TransportError, Version};
mod access;
use core::{
    ptr::NonNull,
    sync::atomic::{Ordering, fence},
};

/// ACPI GUID byte order (little-endian first three GUID components).
pub const DSM_UUID: [u8; 16] = [
    0xc2, 0x98, 0x83, 0x6f, 0xa4, 0x7c, 0xe4, 0x11, 0xad, 0x36, 0x63, 0x10, 0x42, 0xb5, 0x00, 0x8f,
];

/// Evaluates this actual PNP0CA0 device's _DSM, with the specified UUID and
/// revision. The provider must retain its namespace handle and return real
/// firmware errors. Evaluation includes the required empty arguments package.
/// A missing result object must return `DsmNoResult`, as Linux rejects a null
/// `_DSM` object even when the AML evaluation status itself reports success.
pub trait Dsm {
    fn evaluate(
        &mut self,
        uuid: [u8; 16],
        revision: u64,
        function: u64,
    ) -> Result<(), TransportError>;
}

pub struct Mailbox<D: Dsm> {
    base: NonNull<u8>,
    bytes: usize,
    version: Option<Version>,
    dsm: D,
}

impl<D: Dsm> Mailbox<D> {
    /// # Safety
    /// `base` must be eight-byte aligned. `base..base+bytes` must be the
    /// device's real _CRS UCSI mailbox, mapped
    /// coherently as normal write-back memory for this object's lifetime. The
    /// caller retains the mapping lease and serializes CPU ownership; firmware
    /// may update it concurrently under the UCSI protocol. No Rust references
    /// may alias these bytes. `dsm` must evaluate this same physical device.
    pub unsafe fn new(base: NonNull<u8>, bytes: usize, dsm: D) -> Result<Self, TransportError> {
        if bytes < 16
            || (base.as_ptr() as usize) & 7 != 0
            || (base.as_ptr() as usize).checked_add(bytes).is_none()
        {
            return Err(TransportError::Mapping);
        }
        Ok(Self {
            base,
            bytes,
            version: None,
            dsm,
        })
    }
    fn bounds(&self, offset: usize, bytes: usize) -> Result<(), TransportError> {
        if offset.checked_add(bytes).is_none_or(|end| end > self.bytes) {
            return Err(TransportError::Bounds { offset, bytes });
        }
        Ok(())
    }
    fn read(&self, offset: usize, bytes: &mut [u8]) -> Result<(), TransportError> {
        self.bounds(offset, bytes.len())?;
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: constructor proves a live mapping; bounds checked above.
            *byte = unsafe { self.base.as_ptr().add(offset + index).read_volatile() };
        }
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), TransportError> {
        self.bounds(offset, bytes.len())?;
        for (index, byte) in bytes.iter().enumerate() {
            // SAFETY: constructor proves serialized ownership and live mapping.
            unsafe { self.base.as_ptr().add(offset + index).write_volatile(*byte) };
        }
        Ok(())
    }
    fn refresh(&mut self) -> Result<(), TransportError> {
        self.dsm.evaluate(DSM_UUID, 1, 2)?;
        fence(Ordering::SeqCst);
        Ok(())
    }
    fn version(&self) -> Result<Version, TransportError> {
        self.version.ok_or(TransportError::Unavailable)
    }
}

impl<D: Dsm> Transport for Mailbox<D> {
    fn read_version(&mut self) -> Result<u16, TransportError> {
        self.version = None;
        self.refresh()?;
        // SAFETY: constructor guarantees alignment and a live scalar region.
        let raw = unsafe { access::version(self.base) };
        // Preserve unknown version for the core's UnsupportedVersion error.
        if let Ok(version) = Version::new(raw) {
            self.bounds(0, version.mailbox_bytes())?;
            self.version = Some(version);
        } else {
            self.version = None;
        }
        Ok(raw)
    }
    fn poll_cci(&mut self) -> Result<u32, TransportError> {
        self.version()?;
        self.refresh()?;
        // SAFETY: constructor guarantees one aligned native-width CCI load.
        Ok(unsafe { access::cci(self.base) })
    }
    fn read_message_in(&mut self, bytes: &mut [u8]) -> Result<(), TransportError> {
        if bytes.len() > self.version()?.message_in_bytes() {
            return Err(TransportError::Bounds {
                offset: 16,
                bytes: bytes.len(),
            });
        }
        self.read(16, bytes)
    }
    fn write_message_out(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let version = self.version()?;
        if bytes.len() > version.message_out_bytes() {
            return Err(TransportError::Bounds {
                offset: version.message_out_offset(),
                bytes: bytes.len(),
            });
        }
        self.write(version.message_out_offset(), bytes)
    }
    fn write_control(&mut self, control: u64) -> Result<(), TransportError> {
        self.version()?;
        // SAFETY: constructor guarantees serialized, aligned scalar access.
        unsafe { access::control(self.base, control) };
        fence(Ordering::SeqCst);
        self.dsm.evaluate(DSM_UUID, 1, 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec::Vec};
    struct Firmware {
        base: NonNull<u8>,
        calls: Vec<u64>,
        fail: Option<u64>,
        controls: Vec<u64>,
    }
    impl Dsm for Firmware {
        fn evaluate(
            &mut self,
            uuid: [u8; 16],
            revision: u64,
            function: u64,
        ) -> Result<(), TransportError> {
            assert_eq!(uuid, DSM_UUID);
            assert_eq!(revision, 1);
            self.calls.push(function);
            if self.fail == Some(function) {
                return Err(TransportError::Dsm {
                    function,
                    status: 0x1234,
                });
            }
            if function == 1 {
                let mut bytes = [0; 8];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    // SAFETY: tests keep the backing allocation alive and use
                    // no aliasing reference during transport calls.
                    *byte = unsafe { self.base.as_ptr().add(8 + index).read_volatile() };
                }
                self.controls.push(u64::from_le_bytes(bytes));
            } else if function == 2 {
                // Simulate firmware updating CCI only when the real refresh
                // evaluation is requested, proving poll does not read stale RAM.
                for (index, byte) in 0x8000_0902u32.to_le_bytes().iter().enumerate() {
                    // SAFETY: same live test mapping, CCI bytes are in bounds.
                    unsafe { self.base.as_ptr().add(4 + index).write_volatile(*byte) };
                }
            } else {
                panic!("unexpected DSM function");
            }
            Ok(())
        }
    }
    fn mailbox(version: u16, size: usize) -> (Box<[u8]>, Mailbox<Firmware>) {
        let mut memory = vec![0; size].into_boxed_slice();
        memory[..2].copy_from_slice(&version.to_le_bytes());
        let base = NonNull::new(memory.as_mut_ptr()).unwrap();
        let firmware = Firmware {
            base,
            calls: Vec::new(),
            fail: None,
            controls: Vec::new(),
        };
        // SAFETY: the boxed allocation is stable and retained by each test;
        // test code accesses its bytes only between serialized transport calls.
        let mailbox = unsafe { Mailbox::new(base, size, firmware) }.unwrap();
        (memory, mailbox)
    }
    #[test]
    fn versions_use_actual_mailbox_layout_and_dsm_synchronization() {
        for (version, size, offset, outgoing) in [
            (0x0120, 48, 32, 16),
            (0x0200, 528, 272, 256),
            (0x0210, 528, 272, 256),
            (0x0300, 527, 272, 255),
        ] {
            let (mut memory, mut mailbox) = mailbox(version, size);
            assert_eq!(mailbox.poll_cci(), Err(TransportError::Unavailable));
            assert_eq!(mailbox.read_version().unwrap(), version);
            assert_eq!(mailbox.poll_cci().unwrap(), 0x8000_0902);
            memory[16..25].fill(0x3c);
            let mut input = [0; 9];
            mailbox.read_message_in(&mut input).unwrap();
            assert_eq!(input, [0x3c; 9]);
            mailbox.write_message_out(&vec![0xa5; outgoing]).unwrap();
            assert!(memory[offset..].iter().all(|byte| *byte == 0xa5));
            mailbox.write_control(0x1234_5678_9abc_def0).unwrap();
            assert_eq!(mailbox.dsm.controls, vec![0x1234_5678_9abc_def0]);
            assert_eq!(mailbox.dsm.calls, vec![2, 2, 1]);
            let before = memory.clone();
            assert!(mailbox.write_message_out(&vec![0; outgoing + 1]).is_err());
            assert_eq!(memory, before);
        }
    }
    #[test]
    fn short_mapping_unknown_version_and_real_firmware_failures_are_explicit() {
        let (_memory, mut short) = mailbox(0x0200, 527);
        assert_eq!(
            short.read_version(),
            Err(TransportError::Bounds {
                offset: 0,
                bytes: 528
            })
        );
        assert_eq!(short.poll_cci(), Err(TransportError::Unavailable));
        let (_memory, mut unknown) = mailbox(0x0400, 16);
        assert_eq!(unknown.read_version().unwrap(), 0x0400);
        assert_eq!(unknown.poll_cci(), Err(TransportError::Unavailable));
        let (_memory, mut mailbox) = mailbox(0x0120, 48);
        mailbox.read_version().unwrap();
        mailbox.dsm.fail = Some(1);
        assert_eq!(
            mailbox.write_control(1),
            Err(TransportError::Dsm {
                function: 1,
                status: 0x1234
            })
        );
        mailbox.dsm.fail = Some(2);
        assert_eq!(
            mailbox.poll_cci(),
            Err(TransportError::Dsm {
                function: 2,
                status: 0x1234
            })
        );
    }
    #[test]
    fn unaligned_mapping_is_rejected_before_any_firmware_evaluation() {
        let mut memory = vec![0; 64].into_boxed_slice();
        let aligned = NonNull::new(memory.as_mut_ptr()).unwrap();
        assert_eq!((aligned.as_ptr() as usize) & 7, 0);
        // SAFETY: adding one stays within this allocation; constructor must
        // reject the unaligned base without dereferencing or invoking DSM.
        let base = unsafe { NonNull::new_unchecked(aligned.as_ptr().add(1)) };
        let firmware = Firmware {
            base,
            calls: Vec::new(),
            fail: None,
            controls: Vec::new(),
        };
        assert!(matches!(
            unsafe { Mailbox::new(base, 48, firmware) },
            Err(TransportError::Mapping)
        ));
    }
    #[test]
    fn scalar_publication_preserves_all_cci_and_control_lanes() {
        #[repr(C, align(8))]
        struct Region([u8; 48]);
        let mut memory = Region([0; 48]);
        let base = NonNull::new(memory.0.as_mut_ptr()).unwrap();
        for cci in [0x8000_0902u32, 0x2000_0004, 0x9000_fffe, 0x0800_0000] {
            // SAFETY: this is a live, aligned, exclusively owned scalar region.
            unsafe {
                base.as_ptr()
                    .add(4)
                    .cast::<u32>()
                    .write_volatile(cci.to_le());
                assert_eq!(access::cci(base), cci);
                let control = (u64::from(cci) << 32) | 0x1234_5678;
                access::control(base, control);
                assert_eq!(
                    u64::from_le(base.as_ptr().add(8).cast::<u64>().read_volatile()),
                    control
                );
            }
        }
    }
}
