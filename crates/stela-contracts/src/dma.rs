//! Device DMA: guest RAM as bus masters and IOMMU table walks reach it (RAM
//! only, never device registers), and one stream's view of it through its
//! IOMMU.
use crate::bus::Access;

/// Guest RAM by physical address. The boolean methods serve callers that do
/// not resume a transfer. Stateful DMA owners use the progress methods to
/// retain any committed prefix, including a terminal coherence failure.
pub trait Memory {
    fn read(&mut self, physical: u64, buffer: &mut [u8]) -> bool;
    fn write(&mut self, physical: u64, data: &[u8]) -> bool;
    /// Validate actual physical RAM and access permission without transferring
    /// bytes. An unavailable range owner is an explicit refusal.
    fn check_range(&mut self, _physical: u64, _bytes: usize, _write: bool) -> Result<(), DmaError> {
        Err(DmaError::Unsupported(
            "DMA RAM range validation is unavailable",
        ))
    }
    /// Default atomic adapter for RAM owners whose boolean failure transfers
    /// nothing. Owners with partial effects must override this method.
    fn read_progress(&mut self, physical: u64, buffer: &mut [u8]) -> Result<(), TransferFault> {
        self.read(physical, buffer)
            .then_some(())
            .ok_or(TransferFault {
                error: DmaError::Memory,
                completed: 0,
            })
    }
    /// Same contract as `read_progress`, for the actual committed write prefix.
    fn write_progress(&mut self, physical: u64, data: &[u8]) -> Result<(), TransferFault> {
        self.write(physical, data)
            .then_some(())
            .ok_or(TransferFault {
                error: DmaError::Memory,
                completed: 0,
            })
    }
}

/// A fault after exactly `completed` bytes of this transfer. A nonzero prefix
/// must never be replayed merely because a later translation or writer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferFault {
    pub error: DmaError,
    pub completed: usize,
}

/// Why a DMA access did not reach memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// The IOMMU faulted it and reported the fault with this code.
    Fault(u32),
    /// A table or the target is not RAM.
    Memory,
    /// The stream uses a configuration the model does not implement.
    Unsupported(&'static str),
}

/// An IOMMU: the physical address a stream reaches at an I/O address.
pub trait Iommu {
    /// Bytes of one translation page; a translation covers one page.
    fn page(&self) -> u64;
    /// The physical address `stream` reaches at `iova` for a read or a
    /// write of the bytes up to `last` (inclusive, in the same page). The
    /// IOMMU reports a fault itself, through `access`.
    fn translate(
        &mut self,
        memory: &mut dyn Memory,
        stream: usize,
        iova: u64,
        last: u64,
        write: bool,
        access: &mut Access<'_>,
    ) -> Result<u64, DmaError>;
}

/// A bus master without an IOMMU: I/O addresses are physical addresses.
pub struct Physical;

impl Iommu for Physical {
    fn page(&self) -> u64 {
        0x1000
    }

    fn translate(
        &mut self,
        _memory: &mut dyn Memory,
        _stream: usize,
        iova: u64,
        _last: u64,
        _write: bool,
        _access: &mut Access<'_>,
    ) -> Result<u64, DmaError> {
        Ok(iova)
    }
}

/// One stream's I/O address space: transfers split at IOMMU pages, and stop
/// at the first page that faults or is not RAM.
pub struct Port<'a, 'b> {
    pub iommu: &'a mut dyn Iommu,
    pub stream: usize,
    pub memory: &'a mut dyn Memory,
    pub access: &'a mut Access<'b>,
}

impl Port<'_, '_> {
    pub fn read(&mut self, iova: u64, buffer: &mut [u8]) -> Result<(), DmaError> {
        self.read_progress(iova, buffer)
            .map_err(|fault| fault.error)
    }

    pub fn write(&mut self, iova: u64, data: &[u8]) -> Result<(), DmaError> {
        self.write_progress(iova, data).map_err(|fault| fault.error)
    }

    /// Walk every reached IOMMU page and check its actual RAM owner. This does
    /// not cache translations or authorize a later access after a remap.
    pub fn check(&mut self, iova: u64, bytes: usize, write: bool) -> Result<(), TransferFault> {
        self.each_page(iova, bytes, write, |memory, physical, range| {
            memory
                .check_range(physical, range.len(), write)
                .map_err(|error| TransferFault {
                    error,
                    completed: 0,
                })
        })
    }

    pub fn read_progress(&mut self, iova: u64, buffer: &mut [u8]) -> Result<(), TransferFault> {
        self.each_page(iova, buffer.len(), false, |memory, physical, range| {
            memory.read_progress(physical, &mut buffer[range])
        })
    }

    pub fn write_progress(&mut self, iova: u64, data: &[u8]) -> Result<(), TransferFault> {
        self.each_page(iova, data.len(), true, |memory, physical, range| {
            memory.write_progress(physical, &data[range])
        })
    }

    fn each_page(
        &mut self,
        iova: u64,
        bytes: usize,
        write: bool,
        mut transfer: impl FnMut(
            &mut dyn Memory,
            u64,
            core::ops::Range<usize>,
        ) -> Result<(), TransferFault>,
    ) -> Result<(), TransferFault> {
        let page = self.iommu.page();
        if page == 0 && bytes != 0 {
            return Err(TransferFault {
                error: DmaError::Unsupported("DMA IOMMU page size is zero"),
                completed: 0,
            });
        }
        let mut done = 0;
        while done < bytes {
            let fault = |error| TransferFault {
                error,
                completed: done,
            };
            let address = iova
                .checked_add(done as u64)
                .ok_or_else(|| fault(DmaError::Unsupported("DMA past the end of the I/O space")))?;
            let chunk = (page - address % page).min((bytes - done) as u64) as usize;
            let last = address
                .checked_add(chunk as u64 - 1)
                .ok_or_else(|| fault(DmaError::Unsupported("DMA past the end of the I/O space")))?;
            let physical = self
                .iommu
                .translate(self.memory, self.stream, address, last, write, self.access)
                .map_err(fault)?;
            if let Err(partial) = transfer(self.memory, physical, done..done + chunk) {
                // A violated owner contract makes the actual prefix unknown;
                // fail stopped instead of manufacturing replay authority.
                assert!(
                    partial.completed <= chunk,
                    "DMA RAM owner reported an invalid committed prefix"
                );
                return Err(TransferFault {
                    error: partial.error,
                    completed: done + partial.completed,
                });
            }
            done += chunk;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    #[cfg(test)]
    use crate::interrupt::InterruptLatch;
    #[cfg(not(feature = "std"))]
    use alloc::vec::Vec;

    /// RAM of `bytes.len()` bytes at `base`.
    pub struct Ram {
        pub base: u64,
        pub bytes: Vec<u8>,
    }

    impl Ram {
        pub fn new(base: u64, bytes: usize) -> Self {
            Self {
                base,
                bytes: alloc::vec![0; bytes],
            }
        }
        fn range(&self, physical: u64, bytes: usize) -> Option<core::ops::Range<usize>> {
            let start = usize::try_from(physical.checked_sub(self.base)?).ok()?;
            let end = start.checked_add(bytes)?;
            (end <= self.bytes.len()).then_some(start..end)
        }
        pub fn put_u64(&mut self, physical: u64, value: u64) {
            assert!(self.write(physical, &value.to_le_bytes()));
        }
    }

    impl Memory for Ram {
        fn check_range(&mut self, physical: u64, bytes: usize, _: bool) -> Result<(), DmaError> {
            self.range(physical, bytes)
                .map(|_| ())
                .ok_or(DmaError::Memory)
        }
        fn read(&mut self, physical: u64, buffer: &mut [u8]) -> bool {
            let Some(range) = self.range(physical, buffer.len()) else {
                return false;
            };
            buffer.copy_from_slice(&self.bytes[range]);
            true
        }
        fn write(&mut self, physical: u64, data: &[u8]) -> bool {
            let Some(range) = self.range(physical, data.len()) else {
                return false;
            };
            self.bytes[range].copy_from_slice(data);
            true
        }
    }

    /// Pages of 16 bytes, each mapped to the physical page `offset` bytes
    /// above it, except page `hole`.
    #[cfg(test)]
    struct Shift {
        offset: u64,
        hole: u64,
    }

    #[cfg(test)]
    impl Iommu for Shift {
        fn page(&self) -> u64 {
            16
        }
        fn translate(
            &mut self,
            _: &mut dyn Memory,
            _: usize,
            iova: u64,
            last: u64,
            _: bool,
            _: &mut Access<'_>,
        ) -> Result<u64, DmaError> {
            assert_eq!(iova / 16, last / 16, "a translation stays in its page");
            match iova / 16 == self.hole {
                true => Err(DmaError::Fault(1)),
                false => Ok(iova + self.offset),
            }
        }
    }

    #[test]
    fn port_transfers_split_at_pages_and_stop_at_faults() {
        let mut ram = Ram::new(0x1000, 0x100);
        let mut iommu = Shift {
            offset: 0x1000,
            hole: 5,
        };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let data: Vec<u8> = (0..40).collect();
        port.write(0x08, &data).unwrap();
        let mut back = [0; 40];
        port.read(0x08, &mut back).unwrap();
        assert_eq!(back[..], data[..]);
        assert_eq!(port.write(0x48, &data), Err(DmaError::Fault(1)));
        assert_eq!(port.read(0x200, &mut back), Err(DmaError::Memory));
        assert_eq!(ram.bytes[0x08..0x30], data[..]);
    }

    #[test]
    fn final_iova_byte_reaches_the_named_iommu_requirement_without_wrapping() {
        struct Refusing {
            calls: usize,
        }
        impl Iommu for Refusing {
            fn page(&self) -> u64 {
                0x1000
            }

            fn translate(
                &mut self,
                _: &mut dyn Memory,
                _: usize,
                iova: u64,
                last: u64,
                _: bool,
                _: &mut Access<'_>,
            ) -> Result<u64, DmaError> {
                assert_eq!((iova, last), (u64::MAX, u64::MAX));
                self.calls += 1;
                Err(DmaError::Unsupported("test IOMMU boundary requirement"))
            }
        }
        let mut iommu = Refusing { calls: 0 };
        let mut ram = Ram::new(u64::MAX, 1);
        ram.bytes[0] = 0x5a;
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let refused = Err(DmaError::Unsupported("test IOMMU boundary requirement"));
        assert_eq!(port.write(u64::MAX, &[0xa5]), refused);
        let mut buffer = [0x99];
        assert_eq!(port.read(u64::MAX, &mut buffer), refused);
        assert_eq!(buffer, [0x99]);
        assert_eq!(ram.bytes, [0x5a]);
        assert_eq!(iommu.calls, 2);
    }

    #[test]
    fn overflowing_dma_ranges_preserve_completed_chunks_at_the_iova_end() {
        let mut physical = Physical;
        let mut ram = Ram::new(u64::MAX - 1, 2);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut port = Port {
            iommu: &mut physical,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let refused = Err(DmaError::Unsupported("DMA past the end of the I/O space"));
        assert_eq!(port.write(u64::MAX - 1, &[0xa5, 0x5a, 0xff]), refused);
        let mut buffer = [0x99; 3];
        assert_eq!(port.read(u64::MAX - 1, &mut buffer), refused);
        assert_eq!(buffer, [0xa5, 0x5a, 0x99]);
        assert_eq!(ram.bytes, [0xa5, 0x5a]);
    }

    #[test]
    fn overflowing_chunk_end_refuses_before_translation_or_payload_bytes() {
        // The generic Iommu contract does not require power-of-two pages.
        // Its last page can therefore extend beyond the I/O address space.
        struct ThreeBytePage {
            calls: usize,
        }
        impl Iommu for ThreeBytePage {
            fn page(&self) -> u64 {
                3
            }

            fn translate(
                &mut self,
                _: &mut dyn Memory,
                _: usize,
                iova: u64,
                _: u64,
                _: bool,
                _: &mut Access<'_>,
            ) -> Result<u64, DmaError> {
                self.calls += 1;
                Ok(iova)
            }
        }
        let mut iommu = ThreeBytePage { calls: 0 };
        let mut ram = Ram::new(u64::MAX, 1);
        ram.bytes[0] = 0x5a;
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        let refused = Err(DmaError::Unsupported("DMA past the end of the I/O space"));
        assert_eq!(port.write(u64::MAX, &[0xa5, 0xff]), refused);
        let mut buffer = [0x99; 2];
        assert_eq!(port.read(u64::MAX, &mut buffer), refused);
        assert_eq!(buffer, [0x99; 2]);
        assert_eq!(ram.bytes, [0x5a]);
        assert_eq!(iommu.calls, 0);
    }
    #[test]
    fn progress_retains_prior_pages_and_terminal_writer_prefix() {
        struct Partial {
            calls: usize,
            bytes: [u8; 32],
        }
        impl Memory for Partial {
            fn read(&mut self, _: u64, _: &mut [u8]) -> bool {
                panic!("progress adapter bypassed")
            }
            fn write(&mut self, _: u64, _: &[u8]) -> bool {
                panic!("progress adapter bypassed")
            }
            fn read_progress(
                &mut self,
                physical: u64,
                output: &mut [u8],
            ) -> Result<(), TransferFault> {
                let start = (physical - 0x1000) as usize;
                let count = output.len().min(if start == 16 { 3 } else { output.len() });
                output[..count].copy_from_slice(&self.bytes[start..start + count]);
                if count == output.len() {
                    Ok(())
                } else {
                    Err(TransferFault {
                        error: DmaError::Memory,
                        completed: count,
                    })
                }
            }
            fn write_progress(&mut self, physical: u64, data: &[u8]) -> Result<(), TransferFault> {
                self.calls += 1;
                let start = (physical - 0x1000) as usize;
                let count = data.len().min(if start == 16 { 3 } else { data.len() });
                self.bytes[start..start + count].copy_from_slice(&data[..count]);
                if count == data.len() {
                    Ok(())
                } else {
                    Err(TransferFault {
                        error: DmaError::Memory,
                        completed: count,
                    })
                }
            }
        }
        let mut memory = Partial {
            calls: 0,
            bytes: [0; 32],
        };
        let mut iommu = Shift {
            offset: 0x1000,
            hole: u64::MAX,
        };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut memory,
            access: &mut access,
        };
        let expected = Err(TransferFault {
            error: DmaError::Memory,
            completed: 11,
        });
        assert_eq!(port.write_progress(8, &[0x5a; 24]), expected);
        let mut output = [0x99; 24];
        assert_eq!(port.read_progress(8, &mut output), expected);
        assert_eq!(&output[..11], &[0x5a; 11]);
        assert_eq!(&output[11..], &[0x99; 13]);
        assert_eq!(memory.calls, 2);
        assert_eq!(&memory.bytes[8..19], &[0x5a; 11]);
        assert_eq!(&memory.bytes[19..], &[0; 13]);
    }

    #[test]
    fn progress_counts_only_completed_pages_before_iommu_fault() {
        let mut ram = Ram::new(0x1000, 64);
        let mut iommu = Shift {
            offset: 0x1000,
            hole: 1,
        };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(
            port.write_progress(8, &[0xa5; 24]),
            Err(TransferFault {
                error: DmaError::Fault(1),
                completed: 8
            })
        );
        let mut output = [0x99; 24];
        assert_eq!(
            port.read_progress(8, &mut output),
            Err(TransferFault {
                error: DmaError::Fault(1),
                completed: 8
            })
        );
        assert_eq!(&output[..8], &[0xa5; 8]);
        assert_eq!(&output[8..], &[0x99; 16]);
    }
    #[test]
    fn map_admission_walks_actual_permissions_without_touching_ram() {
        let mut ram = Ram::new(0x1000, 48);
        ram.bytes.fill(0xa5);
        let mut iommu = Shift {
            offset: 0x1000,
            hole: 2,
        };
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        let mut port = Port {
            iommu: &mut iommu,
            stream: 0,
            memory: &mut ram,
            access: &mut access,
        };
        assert_eq!(port.check(8, 24, true), Ok(()));
        assert_eq!(
            port.check(8, 40, false),
            Err(TransferFault {
                error: DmaError::Fault(1),
                completed: 24
            })
        );
        assert_eq!(ram.bytes, [0xa5; 48]);
    }
}
