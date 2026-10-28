//! Actual repeated constant writes, not a saved-register image.
//!
//! Original RCfg1d dispatches4827c ->47e78 ->fc2c. Its own source assertion
//! names STRIDE_WRITE_ALL_AMCC_REGS. The top row supplies address/stride; the
//! continuation supplies count/value. Each target remains a checked physical
//! store using the ordinary exclusive write claims and retained prefix.
use super::{AddressFormat, Error, MAX_PHYSICAL, Packet, PhysicalWrite, Sram, Width};
use alloc::vec::Vec;

const TAG: u32 = 6;
const WIDE: u32 = 1 << 5;
const COUNT: u32 = 15 << 6;
const HIGH_ADDRESS: u32 = 0xff00_0000;
const STRIDE_LOW: u32 = 0x00ff_0000;

pub(super) fn decode(sram: &Sram, pc: usize) -> Result<Packet, Error> {
    let words = sram.words.get(pc..pc + 4).ok_or(Error::TruncatedPacket)?;
    let [header, address, stride, value] = *words.first_chunk::<4>().unwrap();
    if header & 0x1f != TAG || header & !(HIGH_ADDRESS | STRIDE_LOW | COUNT | WIDE | 31) != 0 {
        return Err(Error::StrideEncoding);
    }
    if header & WIDE != 0 {
        // All recovered direct emitters pass wide0. A single emitted value
        // word does not establish a doubleword store's upper half semantics.
        return Err(Error::UnqualifiedStrideWidth);
    }
    let (address_mask, stride_mask) = match sram.format {
        AddressFormat::HighWord => (255, 255),
        AddressFormat::Compact => (3, 3),
    };
    let high = header >> 24;
    let stride_low = (header >> 16) & 255;
    if high & !address_mask != 0 || stride_low & !stride_mask != 0 {
        return Err(Error::HighAddress);
    }
    // Original stores W21>>2 and repeats its low bits in the header. Admit
    // only the fully represented, word-aligned W32 stride. Do not recover
    // imaginary upper stride bits from the physical-address high field.
    if stride >> 30 != 0 || stride_low != ((stride << 2) & stride_mask) {
        return Err(Error::StrideEncoding);
    }
    let stride = u64::from(stride) << 2;
    let base = (u64::from(high) << 34) | (u64::from(address) << 2);
    let count = ((header & COUNT) >> 6) + 1;
    let last = base
        .checked_add(stride * u64::from(count - 1))
        .and_then(|address| address.checked_add(4))
        .ok_or(Error::PhysicalAddress)?;
    if last > MAX_PHYSICAL {
        return Err(Error::PhysicalAddress);
    }
    let writes = (0..count)
        .map(|index| PhysicalWrite {
            address: base + stride * u64::from(index),
            width: Width::Word,
            value: u64::from(value),
        })
        .collect::<Vec<_>>();
    Ok(Packet {
        writes,
        committed: 0,
        end: pc + 4,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::pmgr::sequencer::control::{test_fields, test_initial};
    use alloc::{boxed::Box, vec};
    use {
        crate::platform::apple::pmgr::sequencer::FinishError,
        crate::platform::apple::pmgr::sequencer::PacketCursor,
        crate::platform::apple::pmgr::sequencer::PacketKind,
        crate::platform::apple::pmgr::sequencer::RouteOutcome, stela_contracts::bus::Access,
        stela_contracts::bus::Bus, stela_contracts::bus::MmioDevice,
        stela_contracts::bus::MmioError, stela_contracts::interrupt::InterruptLatch,
    };

    fn cursor(
        base: u64,
        stride: u32,
        count: u32,
        value: u32,
        format: AddressFormat,
    ) -> PacketCursor {
        let mask = if format == AddressFormat::HighWord {
            255
        } else {
            3
        };
        let words = [
            TAG | ((count - 1) << 6)
                | (((base >> 34) as u32 & mask) << 24)
                | ((stride & mask) << 16),
            (base >> 2) as u32,
            stride >> 2,
            value,
            0,
        ];
        let mut cursor = PacketCursor::unknown();
        cursor.bind_initial_control(test_initial()).unwrap();
        let bytes = words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        cursor.install_sram(0x292f00000, &bytes, format).unwrap();
        cursor
    }
    #[test]
    fn original_stride_shape_uses_real_mounted_targets_and_keeps_a_refused_prefix() {
        // Same source shape as RCfg64 at5adc0/5add8: two physical channels,
        // repeated constant20080, spacing400000. Actual test registers supplied.
        let base = 0x20046c560;
        let mut cursor = cursor(base, 0x400000, 2, 0x20080, AddressFormat::HighWord);
        assert_eq!(cursor.packet_kind(), Ok(PacketKind::Write));
        let mut bus = Bus::new();
        struct Register(u32);
        impl MmioDevice for Register {
            fn name(&self) -> &'static str {
                "stride-test-register"
            }
            fn read(
                &mut self,
                offset: u64,
                width: Width,
                _: &mut Access<'_>,
            ) -> Result<u64, MmioError> {
                assert_eq!((offset, width), (0, Width::Word));
                Ok(u64::from(self.0))
            }
            fn write(
                &mut self,
                offset: u64,
                width: Width,
                value: u64,
                _: &mut Access<'_>,
            ) -> Result<(), MmioError> {
                assert_eq!((offset, width), (0, Width::Word));
                self.0 = value as u32;
                Ok(())
            }
        }
        let target = bus.add(Box::new(Register(0)));
        bus.map(target, base, 4, 0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        let claim = cursor.begin_write().unwrap();
        let write = cursor
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!((write.address, write.value), (base, 0x20080));
        bus.write(write.address, write.width, write.value, &mut access)
            .unwrap();
        cursor
            .finish_write::<()>(&claim, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(cursor.packet_progress(), Some((1, 2)));
        assert_eq!(bus.read(base, Width::Word, &mut access), Ok(0x20080));
        let claim = cursor.begin_write().unwrap();
        let write = cursor
            .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
            .unwrap();
        assert_eq!(write.address, base + 0x400000);
        let error = bus
            .write(write.address, write.width, write.value, &mut access)
            .unwrap_err();
        assert!(matches!(error, MmioError::Unmapped { .. }));
        assert_eq!(
            cursor.finish_write(&claim, RouteOutcome::NoEffect(error)),
            Err(FinishError::NoEffect(error))
        );
        assert_eq!(cursor.committed_writes(), 1);
        assert_eq!(cursor.packet_progress(), Some((1, 2)));
        let retry = cursor.begin_write().unwrap();
        assert_eq!(retry.write().address, base + 0x400000);
        let target = bus.add(Box::new(Register(0)));
        bus.map(target, base + 0x400000, 4, 0).unwrap();
        let actual = cursor
            .dispatch_write(&retry, &retry.qualify_context(test_fields()).unwrap())
            .unwrap();
        bus.write(actual.address, actual.width, actual.value, &mut access)
            .unwrap();
        assert_eq!(
            cursor.finish_write(
                &retry,
                RouteOutcome::Uncertain("target committed before route failed")
            ),
            Err(FinishError::Uncertain(
                "target committed before route failed"
            ))
        );
        assert_eq!(
            bus.read(base + 0x400000, Width::Word, &mut access),
            Ok(0x20080)
        );
        assert_eq!(cursor.begin_write().unwrap_err(), Error::UncertainEffects);
        assert_eq!(cursor.packet_progress(), Some((1, 2)));
    }
    #[test]
    fn compact_stride_count_and_repeated_address_are_not_collapsed() {
        let mut cursor = cursor(0x201000000, 0, 16, 7, AddressFormat::Compact);
        for index in 0..16 {
            let claim = cursor.begin_write().unwrap();
            let actual = cursor
                .dispatch_write(&claim, &claim.qualify_context(test_fields()).unwrap())
                .unwrap();
            assert_eq!((actual.address, actual.value), (0x201000000, 7));
            cursor
                .finish_write::<()>(&claim, RouteOutcome::Committed)
                .unwrap();
            assert_eq!(cursor.committed_writes(), index + 1);
        }
        assert_eq!(cursor.packet_kind(), Err(Error::UnqualifiedRetirement));
    }
    #[test]
    fn unknown_wide_reserved_duplicate_bits_and_overflow_refuse_before_any_store() {
        for (words, expected) in [
            (vec![TAG | WIDE, 0, 0, 1], Error::UnqualifiedStrideWidth),
            (vec![TAG | 0x400, 0, 0, 1], Error::StrideEncoding),
            (vec![TAG, 0, 1, 1], Error::StrideEncoding),
            (vec![TAG, 0, 0x40000000, 1], Error::StrideEncoding),
            (
                vec![TAG | 0xff000040, 0xffffffff, 0x100000, 1],
                Error::PhysicalAddress,
            ),
        ] {
            let mut cursor = PacketCursor::unknown();
            cursor.bind_initial_control(test_initial()).unwrap();
            cursor
                .install_sram(
                    0x292f00000,
                    &words
                        .into_iter()
                        .flat_map(u32::to_le_bytes)
                        .collect::<Vec<_>>(),
                    AddressFormat::HighWord,
                )
                .unwrap();
            assert_eq!(cursor.begin_write().unwrap_err(), expected);
            assert_eq!(cursor.committed_writes(), 0);
            assert_eq!(cursor.packet_progress(), None);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    #[ignore = "requires original J314s LLB and iBootData"]
    fn original_stride_opcode_handler_full_emitter_and_two_row_operands_are_pinned() {
        use sha2::{Digest, Sha256};
        let llb = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_LLB").unwrap()).unwrap();
        let data = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_IBOOTDATA").unwrap()).unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&llb)),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&data)),
            "6d38d4b30deedb1be526e36179205004957f10e23254392fc3645c63dfd2b095"
        );
        for (lo, hi, digest) in [
            (
                0xfc2c,
                0xfe6c,
                "631ac2a6556271e9c4874a8dad3044175fa8a6bb6aa9f3fb031ab41a80ea9e67",
            ),
            (
                0x4827c,
                0x48360,
                "e5096c584b3057bd1bce75c73ab0bfab2166c0a0ea24242b8f9806ff5cb9fd3a",
            ),
            (
                0x47e78,
                0x47f60,
                "dba3ed1a172f0f4177ec71dca6c60d59373c621f22fb7a81c4a296570b10ab8a",
            ),
            (
                0x23f9a0,
                0x23f9c0,
                "926675afb8614261d53590a9466a0eb83e3b3f639d7e74b51e7b5d4c9c5e2f53",
            ),
        ] {
            assert_eq!(hex::encode(Sha256::digest(&llb[lo..hi])), digest);
        }
        assert_eq!(
            &llb[0x20251a..0x202545],
            b"RECONFIG_OPCODE_STRIDE_WRITE_ALL_AMCC_REGS\0"
        );
        let word = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        assert_eq!((word(0x5adc0), word(0x5add8)), (0x1d0040, 0x1d0040));
        let quad = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        assert_eq!(
            (quad(0x5adc8), quad(0x5add0), quad(0x5ade0), quad(0x5ade8)),
            (0x20046c560, 0x400000, 2, 0x20080)
        );
        // These are actual named source input fields, not a heuristic mapping
        // of register save/restore data to tag6. No physical reset is inferred.
    }
}
