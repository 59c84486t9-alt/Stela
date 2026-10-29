//! Source-bounded AP firmware-SRAM transport, separate from PMIC execution.
//!
//! J314s26A434 LLB file15940..15c1c uploads through C830/C831/C833 in
//! sixteen-byte logical windows. Its 16138 helper splits these into consecutive
//! eight-byte SPMI commands. mac13j `_readMem`/`_writeMem` (VA9d592f8..597b8)
//! use the same low/high address and repeated data-window sequence for reads
//! and writes. This owner implements those sequences over kept
//! bytes. It supplies no PMIC reset, execution, ID, status or Ready value.
use alloc::vec::Vec;
use core::ops::Range;

const COMMAND_BYTES: usize = 8;

use stela_soc_data::pmu::FirmwareSram;
#[cfg(test)]
use stela_soc_data::pmu::FirmwareStartup;
use stela_soc_data::pmu::firmware::{FirmwareHistory, WINDOW_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy)]
enum Stream {
    Unaddressed,
    Low(u8),
    Window {
        cursor: usize,
        direction: Option<Direction>,
        tail: bool,
    },
    /// A source's short final window has completed. Its continuation/wrap is
    /// not specified by the AP consumer; require an explicit new address pair.
    Ended,
}

/// Private prepared effect. Never exposed as an external completion receipt.
pub(super) struct Transfer {
    pub(super) range: Range<usize>,
    next: Stream,
}

pub(super) struct FirmwareMemory {
    pub ports: FirmwareSram,
    bytes: Vec<u8>,
    stream: Stream,
}
impl From<FirmwareHistory> for FirmwareMemory {
    fn from(history: FirmwareHistory) -> Self {
        let (ports, initial) = history.into_parts();
        Self {
            ports,
            bytes: initial,
            stream: Stream::Unaddressed,
        }
    }
}
impl FirmwareMemory {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn forget_address(&mut self) {
        self.stream = Stream::Unaddressed;
    }

    pub fn claims(&self, address: u16, bytes: usize) -> bool {
        let end = u64::from(address).saturating_add(bytes.max(1) as u64);
        self.ports.windows().iter().any(|w| {
            u64::from(address) < u64::from(w.base) + u64::from(w.bytes) && u64::from(w.base) < end
        })
    }

    pub fn check_address(&self, address: u16, data: &[u8]) -> Result<Option<u8>, &'static str> {
        if address != self.ports.address_low && address != self.ports.address_high {
            return Ok(None);
        }
        if data.len() != 1 {
            return Err("PMU firmware address ports require separate one-byte writes");
        }
        if address == self.ports.address_high {
            let Stream::Low(low) = self.stream else {
                return Err("PMU firmware high address requires a fresh low address");
            };
            let cursor = usize::from(u16::from_le_bytes([low, data[0]]));
            if cursor >= self.bytes.len() {
                return Err("PMU firmware address is outside retained SRAM");
            }
        }
        Ok(Some(data[0]))
    }

    /// The complete logical window, or its exact eight-byte prefix/tail. A
    /// failed command keeps previous commands. A repeated partial prefix or
    /// a direction change without a new address pair refuses before effects.
    /// No lost-response retry semantics are inferred for completed windows.
    pub fn prepare(
        &self,
        address: u16,
        bytes: usize,
        direction: Direction,
    ) -> Result<Transfer, &'static str> {
        let Stream::Window {
            cursor,
            direction: previous,
            tail,
        } = self.stream
        else {
            return Err("PMU firmware data requires a complete explicit address pair");
        };
        if previous.is_some_and(|previous| previous != direction) {
            return Err("PMU firmware data direction requires a new address pair");
        }
        let (offset, limit) = match tail {
            false if address == self.ports.data => (0, usize::from(WINDOW_BYTES)),
            true if address == self.ports.data + COMMAND_BYTES as u16 => {
                (COMMAND_BYTES, COMMAND_BYTES)
            }
            _ => return Err("PMU firmware data command is out of order"),
        };
        if bytes == 0 || bytes > limit {
            return Err("PMU firmware data exceeds the qualified logical window");
        }
        let start = cursor + offset;
        let end = start + bytes;
        if end > self.bytes.len() {
            return Err("PMU firmware transfer exceeds retained SRAM");
        }
        let next = if offset == 0 && bytes == COMMAND_BYTES {
            Stream::Window {
                cursor,
                direction: Some(direction),
                tail: true,
            }
        } else if offset + bytes == usize::from(WINDOW_BYTES) {
            Stream::Window {
                cursor: end,
                direction: Some(direction),
                tail: false,
            }
        } else {
            Stream::Ended
        };
        Ok(Transfer {
            range: start..end,
            next,
        })
    }
    pub fn address(&mut self, address: u16, byte: u8) {
        self.stream = if address == self.ports.address_low {
            Stream::Low(byte)
        } else {
            let Stream::Low(low) = self.stream else {
                unreachable!("address preflight")
            };
            Stream::Window {
                cursor: usize::from(u16::from_le_bytes([low, byte])),
                direction: None,
                tail: false,
            }
        };
    }
    pub fn read(&mut self, transfer: Transfer, data: &mut [u8]) {
        data.copy_from_slice(&self.bytes[transfer.range]);
        self.stream = transfer.next;
    }
    pub fn write(&mut self, transfer: Transfer, data: &[u8]) {
        self.bytes[transfer.range].copy_from_slice(data);
        self.stream = transfer.next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use {
        crate::platform::apple::pmu::Pmu, crate::platform::apple::pmu::tests::maverick,
        crate::platform::apple::spmi::SlaveError, crate::platform::apple::spmi::SpmiSlave,
        stela_soc_data::pmu::Configuration,
    };

    const PORTS: FirmwareSram = FirmwareSram {
        address_low: 0xc830,
        address_high: 0xc831,
        data: 0xc833,
        bytes: 0x3000,
        chunk: 16,
    };
    fn pmu(initial: Vec<u8>) -> Pmu {
        Pmu::configured(
            Configuration::new(Vec::new(), Some(maverick()), 1)
                .unwrap()
                .with_firmware_sram(PORTS, initial)
                .unwrap()
                .with_unqualified_firmware_startup(FirmwareStartup::Maverick)
                .unwrap(),
            None,
        )
        .unwrap()
    }
    fn seek(pmu: &mut Pmu, address: u16, now: u64) {
        let [low, high] = address.to_le_bytes();
        pmu.write(PORTS.address_low, &[low], now).unwrap();
        pmu.write(PORTS.address_high, &[high], now).unwrap();
    }
    fn upload(pmu: &mut Pmu, bytes: &[u8], now: u64) {
        for window in bytes.chunks(16) {
            for (i, command) in window.chunks(8).enumerate() {
                pmu.write(PORTS.data + (i * 8) as u16, command, now)
                    .unwrap();
            }
        }
    }
    fn download(pmu: &mut Pmu, bytes: &mut [u8], now: u64) {
        for window in bytes.chunks_mut(16) {
            for (i, command) in window.chunks_mut(8).enumerate() {
                pmu.read(PORTS.data + (i * 8) as u16, command, now).unwrap();
            }
        }
    }

    #[test]
    fn upload_and_readback_use_retained_bytes_across_repeated_windows_and_short_final_tails() {
        for count in [
            1usize, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 0x2270, 0x2c78, 0x3000,
        ] {
            let initial: Vec<_> = (0..usize::from(PORTS.bytes))
                .map(|i| (i as u8).wrapping_mul(29))
                .collect();
            let image: Vec<_> = (0..count)
                .map(|i| (i as u8).wrapping_mul(37).wrapping_add(1))
                .collect();
            let mut owner = pmu(initial.clone());
            // Port presence does not imply an initial hardware cursor.
            assert!(matches!(
                owner.write(PORTS.data, &[0; 8], 0),
                Err(SlaveError::Unsupported(_))
            ));
            seek(&mut owner, 0, 0);
            upload(&mut owner, &image, 0);
            seek(&mut owner, 0, 0);
            let mut actual = alloc::vec![0; count];
            download(&mut owner, &mut actual, 0);
            assert_eq!(actual, image);
            // Untouched SRAM belongs to the same explicitly supplied resource.
            if count < usize::from(PORTS.bytes) {
                seek(&mut owner, count as u16, 0);
                let mut byte = [0];
                owner.read(PORTS.data, &mut byte, 0).unwrap();
                assert_eq!(byte[0], initial[count]);
            }
            // Upload/readback never runs the PMIC or makes a Ready value.
            assert!(matches!(
                owner.write(0xc806, &[1], 0),
                Err(SlaveError::Unsupported(_))
            ));
            let mut status = [0xa5];
            assert!(matches!(
                owner.read(0xc813, &mut status, 0),
                Err(SlaveError::Unsupported(_))
            ));
            assert_eq!(status, [0xa5]);
        }
    }

    #[test]
    fn failed_tail_preserves_real_prefix_and_refuses_ambiguous_retries_or_direction_changes() {
        let mut owner = pmu(alloc::vec![0xa5; usize::from(PORTS.bytes)]);
        seek(&mut owner, 0, 10);
        owner.write(PORTS.data, &[1; 8], 10).unwrap();
        assert!(matches!(
            owner.write(PORTS.data, &[2; 8], 10),
            Err(SlaveError::Unsupported(_))
        ));
        assert!(matches!(
            owner.write(PORTS.data + 8, &[2; 9], 20),
            Err(SlaveError::Unsupported(_))
        ));
        let mut read = [0x55; 8];
        assert!(matches!(
            owner.read(PORTS.data + 8, &mut read, 10),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(read, [0x55; 8]);
        // A backwards oscillator publication cannot consume the known tail.
        assert!(matches!(
            owner.write(PORTS.data + 8, &[2; 8], 9),
            Err(SlaveError::Unsupported(_))
        ));
        owner.write(PORTS.data + 8, &[2; 8], 10).unwrap();
        owner.write(PORTS.data, &[3; 16], 10).unwrap();
        assert!(matches!(
            owner.read(PORTS.data, &mut read, 10),
            Err(SlaveError::Unsupported(_))
        ));
        assert!(matches!(
            owner.write(PORTS.data, &[], 10),
            Err(SlaveError::Unsupported(_))
        ));
        seek(&mut owner, 0, 10);
        let mut actual = [0; 32];
        download(&mut owner, &mut actual, 10);
        assert_eq!(&actual[..8], &[1; 8]);
        assert_eq!(&actual[8..16], &[2; 8]);
        assert_eq!(&actual[16..], &[3; 16]);
    }

    #[test]
    fn address_pair_bounds_short_final_readdress_and_unknown_readback_are_atomic() {
        let mut owner = pmu(alloc::vec![0xa5; usize::from(PORTS.bytes)]);
        assert!(matches!(
            owner.write(PORTS.address_high, &[0], 0),
            Err(SlaveError::Unsupported(_))
        ));
        owner.write(PORTS.address_low, &[0xf9], 0).unwrap();
        assert!(matches!(
            owner.write(PORTS.address_high, &[0x30], 0),
            Err(SlaveError::Unsupported(_))
        ));
        owner.write(PORTS.address_high, &[0x2f], 0).unwrap();
        assert!(matches!(
            owner.write(PORTS.data, &[1; 8], 0),
            Err(SlaveError::Unsupported(_))
        ));
        owner.write(PORTS.data, &[1; 7], 0).unwrap();
        assert!(matches!(
            owner.write(PORTS.data, &[2], 0),
            Err(SlaveError::Unsupported(_))
        ));
        seek(&mut owner, 0x2ff9, 0);
        let mut actual = [0; 7];
        owner.read(PORTS.data, &mut actual, 0).unwrap();
        assert_eq!(actual, [1; 7]);
        let mut poison = [0x55; 2];
        assert!(matches!(
            owner.read(PORTS.address_low, &mut poison[..1], 0),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(poison, [0x55; 2]);
        assert!(matches!(
            owner.write(PORTS.address_low, &[0, 0], 0),
            Err(SlaveError::Unsupported(_))
        ));
        // Explicit readdress discards protocol position, never committed bytes.
        seek(&mut owner, 0, 0);
        owner.write(PORTS.data, &[4; 8], 0).unwrap();
        seek(&mut owner, 0, 0);
        owner.read(PORTS.data, &mut poison, 0).unwrap();
        assert_eq!(poison, [4; 2]);
        seek(&mut owner, 0x2fff, 0);
        assert!(matches!(
            owner.read(PORTS.data, &mut poison, 0),
            Err(SlaveError::Unsupported(_))
        ));
        assert_eq!(poison, [4; 2]);
        owner.read(PORTS.data, &mut poison[..1], 0).unwrap();
        assert_eq!(poison[0], 1);
    }

    #[test]
    fn all_sram_register_owners_and_initial_bytes_are_validated_before_construction() {
        let bare = || Configuration::new(Vec::new(), None, 0).unwrap();
        for ports in [
            FirmwareSram { bytes: 0, ..PORTS },
            FirmwareSram { chunk: 0, ..PORTS },
            FirmwareSram { chunk: 8, ..PORTS },
            FirmwareSram { chunk: 17, ..PORTS },
            FirmwareSram {
                address_high: PORTS.address_low,
                ..PORTS
            },
            FirmwareSram {
                address_low: PORTS.data + 15,
                ..PORTS
            },
            FirmwareSram {
                data: 0xfff1,
                ..PORTS
            },
        ] {
            assert!(
                bare()
                    .with_firmware_sram(ports, alloc::vec![0; usize::from(ports.bytes)])
                    .is_err()
            );
        }
        assert!(
            bare()
                .with_firmware_sram(PORTS, alloc::vec![0; 0x2fff])
                .is_err()
        );
        let initialized = || {
            bare()
                .with_firmware_sram(PORTS, alloc::vec![0; 0x3000])
                .unwrap()
        };
        assert!(
            initialized()
                .with_firmware_sram(PORTS, alloc::vec![0; 0x3000])
                .is_err()
        );
        for window in PORTS.windows() {
            assert!(
                Configuration::new(alloc::vec![window], None, 0)
                    .unwrap()
                    .with_firmware_sram(PORTS, alloc::vec![0; 0x3000])
                    .is_err()
            );
            assert!(initialized().with_unqualified_identity(window).is_err());
            assert!(
                bare()
                    .with_unqualified_identity(window)
                    .unwrap()
                    .with_firmware_sram(PORTS, alloc::vec![0; 0x3000])
                    .is_err()
            );
            assert!(
                initialized()
                    .with_fault_history(window, alloc::vec![0; usize::from(window.bytes)])
                    .is_err()
            );
            assert!(
                bare()
                    .with_fault_history(window, alloc::vec![0; usize::from(window.bytes)])
                    .unwrap()
                    .with_firmware_sram(PORTS, alloc::vec![0; 0x3000])
                    .is_err()
            );
        }
        let key_alias = FirmwareSram {
            address_low: 0x7001,
            ..PORTS
        };
        assert!(
            bare()
                .with_firmware_sram(key_alias, alloc::vec![0; 0x3000])
                .unwrap()
                .with_unqualified_firmware_startup(FirmwareStartup::Maverick)
                .is_err()
        );
        assert!(
            bare()
                .with_unqualified_firmware_startup(FirmwareStartup::Maverick)
                .unwrap()
                .with_firmware_sram(key_alias, alloc::vec![0; 0x3000])
                .is_err()
        );
        let conflicting_rtc = super::super::Rtc {
            upcount: PORTS.data,
            ..maverick()
        };
        assert!(
            Configuration::new(Vec::new(), Some(conflicting_rtc), 1)
                .unwrap()
                .with_firmware_sram(PORTS, alloc::vec![0; 0x3000])
                .is_err()
        );
        // No implicit wrap at the last representable data lane.
        let ports = FirmwareSram {
            data: 0xfff0,
            bytes: u16::MAX,
            ..PORTS
        };
        assert!(
            bare()
                .with_firmware_sram(ports, alloc::vec![0; 0xffff])
                .is_ok()
        );
    }

    #[test]
    fn real_gen1_fifo_retires_each_sram_chunk_and_does_not_consume_failed_tail() {
        use crate::platform::apple::spmi::Spmi;
        use alloc::{boxed::Box, rc::Rc};
        use core::cell::RefCell;
        use stela_contracts::bus::Access;
        use stela_contracts::bus::Lifecycle;
        use stela_contracts::bus::LifecycleState;
        use stela_contracts::bus::MmioDevice;
        use stela_contracts::bus::MmioError;
        use stela_contracts::bus::Width;
        use stela_contracts::interrupt::AicInput;
        use stela_contracts::interrupt::InterruptLatch;
        struct Observed(Rc<RefCell<Pmu>>);
        impl SpmiSlave for Observed {
            fn read(&mut self, address: u16, data: &mut [u8], now: u64) -> Result<(), SlaveError> {
                self.0.borrow_mut().read(address, data, now)
            }
            fn write(&mut self, address: u16, data: &[u8], now: u64) -> Result<(), SlaveError> {
                self.0.borrow_mut().write(address, data, now)
            }
        }
        let owner = Rc::new(RefCell::new(pmu(alloc::vec![0xa5; 0x3000])));
        seek(&mut owner.borrow_mut(), 0, 0);
        let mut controller = Spmi::with_configuration(
            AicInput::new(0, 228),
            stela_soc_data::spmi::Configuration::new(
                stela_soc_data::spmi::Profile::Gen1,
                192,
                [256, 256],
            )
            .unwrap(),
        );
        controller
            .attach(15, Box::new(Observed(owner.clone())))
            .unwrap();
        let mut interrupts = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut interrupts);
        let put = |controller: &mut Spmi, access: &mut Access<'_>, word: u32| {
            controller.write(4, Width::Word, u64::from(word), access)
        };
        // A completed command may leave a SRAM half-window.
        // Master clock/quiesce neither discards that state nor completes it.
        put(
            &mut controller,
            &mut access,
            u32::from(PORTS.data) << 16 | 15 << 8 | 0x37,
        )
        .unwrap();
        put(&mut controller, &mut access, 0x04030201).unwrap();
        put(&mut controller, &mut access, 0x08070605).unwrap();
        assert_ne!(
            controller.read(8, Width::Word, &mut access).unwrap() & (1 << 15),
            0
        );
        let running = LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        };
        let stopped = LifecycleState {
            clocked: false,
            quiesced: true,
            ..running
        };
        controller.check_lifecycle(stopped).unwrap();
        controller.set_lifecycle(stopped, &mut access);
        assert!(put(&mut controller, &mut access, 0).is_err());
        assert!(
            controller
                .check_lifecycle(LifecycleState {
                    reset: true,
                    ..running
                })
                .is_err()
        );
        controller.check_lifecycle(running).unwrap();
        controller.set_lifecycle(running, &mut access);
        put(
            &mut controller,
            &mut access,
            u32::from(PORTS.data + 8) << 16 | 1 << 15 | 15 << 8 | 0x37,
        )
        .unwrap();
        put(&mut controller, &mut access, 0x0c0b0a09).unwrap();
        put(&mut controller, &mut access, 0x100f0e0d).unwrap();
        assert_ne!(
            controller.read(8, Width::Word, &mut access).unwrap() & (1 << 15),
            0
        );
        assert_eq!(
            &owner.borrow().firmware.as_ref().unwrap().bytes[..16],
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
        );
        controller.write(0x78, Width::Word, 1, &mut access).unwrap();
        // Eight bytes remain: the first real command fits and the second does not.
        seek(&mut owner.borrow_mut(), 0x2ff8, 0);
        put(
            &mut controller,
            &mut access,
            u32::from(PORTS.data) << 16 | 15 << 8 | 0x37,
        )
        .unwrap();
        put(&mut controller, &mut access, 0x04030201).unwrap();
        put(&mut controller, &mut access, 0x08070605).unwrap();
        assert_ne!(
            controller.read(8, Width::Word, &mut access).unwrap() & (1 << 15),
            0
        );
        put(
            &mut controller,
            &mut access,
            u32::from(PORTS.data + 8) << 16 | 1 << 15 | 15 << 8 | 0x30,
        )
        .unwrap();
        assert!(matches!(
            put(&mut controller, &mut access, 0xff),
            Err(MmioError::Unsupported { .. })
        ));
        assert!(controller.read(8, Width::Word, &mut access).is_err());
        assert_eq!(controller.read(0x78, Width::Word, &mut access), Ok(0));
        // Failed final payload is still owned by the FIFO; repeating it cannot
        // claim success or change the committed SRAM prefix.
        assert!(matches!(
            put(&mut controller, &mut access, 0xff),
            Err(MmioError::Unsupported { .. })
        ));
        let retained = owner.borrow();
        let bytes = &retained.firmware.as_ref().unwrap().bytes;
        assert_eq!(&bytes[0x2ff8..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn unqualified_startup_routes_refuse_before_any_clock_storage_or_sram_effect() {
        let bare = || Configuration::new(Vec::new(), Some(maverick()), 1).unwrap();
        for profile in [FirmwareStartup::Maverick, FirmwareStartup::Monaco] {
            let mut owner = Pmu::configured(
                bare().with_unqualified_firmware_startup(profile).unwrap(),
                None,
            )
            .unwrap();
            for window in profile.windows() {
                let mut data = alloc::vec![0xa5; usize::from(window.bytes)];
                assert!(matches!(
                    owner.read(window.base, &mut data, 100),
                    Err(SlaveError::Unsupported(_))
                ));
                assert!(data.iter().all(|&byte| byte == 0xa5));
                assert!(matches!(
                    owner.write(window.base, &data, 100),
                    Err(SlaveError::Unsupported(_))
                ));
            }
            // Refused startup commands did not publish a later oscillator time.
            owner.read(maverick().upcount, &mut [0; 6], 0).unwrap();
            assert!(
                bare()
                    .with_unqualified_firmware_startup(profile)
                    .unwrap()
                    .with_unqualified_firmware_startup(profile)
                    .is_err()
            );
            for window in profile.windows() {
                let config = Configuration::new(alloc::vec![*window], None, 0).unwrap();
                assert!(config.with_unqualified_firmware_startup(profile).is_err());
                assert!(
                    bare()
                        .with_unqualified_firmware_startup(profile)
                        .unwrap()
                        .with_unqualified_identity(*window)
                        .is_err()
                );
                assert!(
                    bare()
                        .with_unqualified_identity(*window)
                        .unwrap()
                        .with_unqualified_firmware_startup(profile)
                        .is_err()
                );
            }
        }
        let mut owner = pmu(alloc::vec![0xa5; 0x3000]);
        seek(&mut owner, 0, 0);
        owner.write(PORTS.data, &[1; 8], 0).unwrap();
        assert!(matches!(
            owner.write(0xc804, &[0], 100),
            Err(SlaveError::Unsupported(_))
        ));
        owner.write(PORTS.data + 8, &[2; 8], 0).unwrap();
        seek(&mut owner, 0, 0);
        let mut actual = [0; 16];
        download(&mut owner, &mut actual, 0);
        assert_eq!(&actual[..8], &[1; 8]);
        assert_eq!(&actual[8..], &[2; 8]);
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_CRAM_J314S_LLB, STELA_TEST_PMGR_M1_KERNELCACHE"]
    fn original_images_full_producers_and_ap_sram_read_write_contract_are_pinned() {
        let data = std::fs::read(std::env::var("STELA_TEST_CRAM_J314S_LLB").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&data),
            "f45549025d8cb4aa5e1cdb6107a25f90999f6b96da0b31a2f3cfb90561653ae1"
        );
        for (offset, bytes, digest) in [
            (
                0x14ce04usize,
                56usize,
                "eab7c9ac45166ff21ebdc571a27f0328d66aeea4bd13c61c452eb6696dab0a6e",
            ), // getter-pointers-lengths
            (
                0x158c0usize,
                104usize,
                "9e017350c8188db8a1effd7df2f20ffbcc7f29e6fc704d882256ee1bfed3d5ee",
            ), // first-image-descriptor
            (
                0x15940usize,
                732usize,
                "b92ef5b60fe2d24ac8bf97718a7329168b78f99db576dcffea826a5fa7535dad",
            ), // first-upload-full
            (
                0x15c54usize,
                104usize,
                "4195007d40e095f2a783ffc5a480f4afda8c357ed6f58b046c4fb642253ad555",
            ), // second-image-descriptor
            (
                0x15cbcusize,
                780usize,
                "a296818ec53e81e9097badaa05ef9697f86a7ce9fef4c307ed3655466c2175a5",
            ), // second-upload-full
            (
                0x1605cusize,
                220usize,
                "5e2d4b1a36a61a75a8e59a3e5c35278710b3cde90b0417fc924c74e12ba036f3",
            ), // spmi-read-full
            (
                0x16138usize,
                476usize,
                "bdf9af136b5cc090b8356942b84ebfe6c06a98fcc9a9cbd3764cc2f44a9de56c",
            ), // spmi-write-retry-readback-full
            (
                0x1671cusize,
                288usize,
                "0d80d89e9efcea9ac4d4198dc14732709ada66057a80f295c5cb35acb4591223",
            ), // write-wrappers
            (
                0x18288usize,
                680usize,
                "6bc4ccad8da5a7204e55860969674d8132bb689f15cdec73da1edb90f39d3165",
            ), // configuration-unlock
            (
                0x155e20usize,
                952usize,
                "13ccaf408314d30bf54f172af3777535ae03ef9cad95a1df328d5d71a9ac8d61",
            ), // first-resource-descriptor
            (
                0x1561d8usize,
                952usize,
                "b79f680673b75800d39b2442418cb314c9d51b2dea1e68cf0667c8e8c18ad1c2",
            ), // second-resource-descriptor
            (
                0x1f9b20usize,
                8816usize,
                "1975a07b872c44e16804007fb812aec37a65b9aed9076ed5fa47b9964c775157",
            ), // first-fw
            (
                0x1fbd90usize,
                11384usize,
                "68879f00e937ba85942f3912e3ba6f77d6bd367bd8f6caede2f81cf3d99255a7",
            ), // second-fw
        ] {
            assert_eq!(stela_formats::sha256(&data[offset..offset + bytes]), digest);
        }
        // Positive original board records and the dispatch/container consumers.
        for (offset, bytes, digest) in [
            (
                0x5b75cusize,
                28usize,
                "f8859ac8d1dfe3c3a773d984f1525d576474d135abfe6bdda64ba3f082387025",
            ), // board-view-getter
            (
                0x168aa8usize,
                720usize,
                "04b761bf62b4b23eaff5e55816d05ec50c5e850f049685e53940efd7e5e0b5d4",
            ), // board-pmic-records
            (
                0x18f78usize,
                828usize,
                "8ca7a62d199f0eeeeae0c54d4b31acb046659f5c572c6502afb22543f597e883",
            ), // normal-two-loop-startup
            (
                0x18bb0usize,
                596usize,
                "186bdf41896cb49767690b01869598f9ff13c6760b3aebf80686b963340a495c",
            ), // uuid-container-to-upload-dispatch
            (
                0x18d18usize,
                236usize,
                "5555ac614788282f234e676b3ac0ed0e9c85702c39fe0e969d097ef12561af33",
            ), // native-service-header-fields
            (
                0x1a4d0usize,
                2276usize,
                "4ed5798c0adf84593f1ef9acf6322fca8a391243bc9fa414130758dc88068353",
            ), // full-runtime-descriptor-accessors
        ] {
            assert_eq!(stela_formats::sha256(&data[offset..offset + bytes]), digest);
        }
        let base = 0x1fc058000u64;
        let qword = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        for (i, name, resource, controller, sid) in [
            (0, "maverick_master", 0x155e20, 0u32, 15u32),
            (1, "maverick_slave", 0x155e20, 1, 14),
            (2, "monaco_0", 0x1561d8, 24, 15),
            (3, "monaco_1", 0x1561d8, 25, 15),
            (4, "monaco_2", 0x1561d8, 26, 15),
        ] {
            let record = 0x168aa8 + i * 0x78;
            let name_at = (qword(record) - base) as usize;
            assert_eq!(&data[name_at..name_at + name.len()], name.as_bytes());
            assert_eq!(qword(record + 0x20), base + resource);
            assert_eq!(qword(record + 0x30), base + resource + 0x3b8);
            assert_eq!(
                qword(record + 0x40),
                u64::from(controller) << 32 | u64::from(sid)
            );
        }
        let kc = std::fs::read(std::env::var("STELA_TEST_PMGR_M1_KERNELCACHE").unwrap()).unwrap();
        assert_eq!(
            stela_formats::sha256(&kc),
            "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
        );
        assert_eq!(
            stela_formats::sha256(&kc[0x2d552f8..0x2d552f8 + 1216]),
            "f6a80ac867c834d37f1e75c71a9f4b0d908ef3bac3193b1f0490019ae4c990fe"
        );
        // These exact encoded entries keep image descriptor/upload functions.
        // This fixture does not infer normal-entry reachability from their presence.
        for (offset, code) in [
            (0x155f68, 0x158c0u32),
            (0x156150, 0x15940),
            (0x156320, 0x15c54),
            (0x156508, 0x15cbc),
        ] {
            assert_eq!(
                u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()),
                code
            );
        }
        for (resource, signature, unlock, restore) in [
            (0x155e20usize, 0x65766144u32, 0x7001u32, 0x7000u32),
            (0x1561d8, 0x4f724561, 0x5000, 0x5004),
        ] {
            let word = |field| {
                u32::from_le_bytes(
                    data[resource + field..resource + field + 4]
                        .try_into()
                        .unwrap(),
                )
            };
            assert_eq!(word(0x3c), signature);
            assert_eq!(word(0x4c), unlock);
            assert_eq!(word(0x40), restore);
            assert_eq!(data[resource + 0x48], 0);
        }
        assert_eq!(
            &data[0x155f20..0x155f26],
            &[0x30, 0xc8, 0x31, 0xc8, 0x33, 0xc8]
        );
        assert_eq!(
            u32::from_le_bytes(data[0x155f28..0x155f2c].try_into().unwrap()),
            u32::from(PORTS.bytes)
        );
        assert_eq!(
            u32::from_le_bytes(data[0x155f30..0x155f34].try_into().unwrap()),
            u32::from(PORTS.chunk)
        );
        // Replay every original image byte through the AP-facing memory
        // owner; this proves transport/storage only, never PMIC execution/Ready.
        for (offset, bytes) in [(0x1f9b20, 0x2270usize), (0x1fbd90, 0x2c78)] {
            let image = &data[offset..offset + bytes];
            let mut owner = pmu(alloc::vec![0xa5; 0x3000]);
            seek(&mut owner, 0, 0);
            upload(&mut owner, image, 0);
            seek(&mut owner, 0, 0);
            let mut actual = alloc::vec![0; bytes];
            download(&mut owner, &mut actual, 0);
            assert_eq!(actual, image);
            assert_eq!(owner.firmware.as_ref().unwrap().bytes[bytes], 0xa5);
        }
    }
}
