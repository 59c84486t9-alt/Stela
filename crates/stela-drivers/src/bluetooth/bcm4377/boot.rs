// SPDX-License-Identifier: MIT
// Copyright (C) The Asahi Linux Contributors
//! Actual source window/OTP, opaque boot image DMA and RTI state transitions.
use super::*;
use crate::firmware::{ErrorKind, Requirement};
use identity::OTP_BYTES;
use memory::DMA_WINDOW_BYTES;

impl<P: Platform> Transport<P> {
    pub(super) fn validate_pci(platform: &mut P, identity: PciIdentity) -> Result<()> {
        for (offset, expected) in Self::pci_words(identity) {
            let observed = platform.read32(Space::Configuration, offset)?;
            if observed != expected {
                return Err(Error::Readback {
                    space: Space::Configuration,
                    offset,
                    observed,
                });
            }
        }
        Ok(())
    }
    fn pci_words(identity: PciIdentity) -> [(u32, u32); 3] {
        [
            (
                0,
                u32::from(identity.vendor) | u32::from(identity.device) << 16,
            ),
            (8, identity.class << 8 | u32::from(identity.revision)),
            (
                0x2c,
                u32::from(identity.subsystem_vendor) | u32::from(identity.subsystem_device) << 16,
            ),
        ]
    }
    fn config_write(&mut self, offset: u32, value: u32) -> Result<()> {
        self.write(Space::Configuration, offset, value)?;
        let observed = self.read(Space::Configuration, offset)?;
        if observed != value {
            return Err(Error::Readback {
                space: Space::Configuration,
                offset,
                observed,
            });
        }
        Ok(())
    }
    fn configure(&mut self) -> Result<()> {
        let pci = self.pci;
        for (offset, expected) in Self::pci_words(pci) {
            let observed = self.read(Space::Configuration, offset)?;
            if observed != expected {
                return Err(Error::Readback {
                    space: Space::Configuration,
                    offset,
                    observed,
                });
            }
        }
        let (window1, window2, core2) = self.chip.windows();
        for (offset, value) in [(0x80, window1), (0x70, window2), (0x74, 0x18011000)] {
            self.config_write(offset, value)?;
        }
        if let Some(value) = core2 {
            self.config_write(0x78, value)?;
        }
        self.config_write(0x84, 0x19000000)?;
        let mut control = self.read(Space::Configuration, 0x88)?;
        if control == u32::MAX {
            return Err(Error::Readback {
                space: Space::Configuration,
                offset: 0x88,
                observed: control,
            });
        }
        if self.chip == Chip::Bcm4387 {
            control &= !(1 << 19);
        }
        self.config_write(0x88, control | 1 << 16)?;
        let mut otp = [0; OTP_BYTES];
        self.snapshot.otp.clear();
        for (at, byte) in otp.iter_mut().enumerate() {
            let offset = self.chip.otp_offset() + at as u32;
            *byte = self.read_otp(offset)?;
        }
        let board = self.platform().board();
        self.identity = Some(Identity::parse(self.pci, board, otp)?);
        self.state = State::Configured;
        Ok(())
    }
    pub(super) fn start_inner(&mut self, provider: &dyn Provider) -> Result<()> {
        self.configure()?;
        self.refresh_snapshot()?;
        if self.snapshot.boot_stage != 0 || self.snapshot.rti_status != 0 {
            return Err(Error::Protocol {
                requirement: "fresh actual Broadcom BOOT0 and RTI0",
                observed: u64::from(self.snapshot.boot_stage) << 32
                    | u64::from(self.snapshot.rti_status),
            });
        }
        let image = self.load_named(provider, "bin")?;
        self.image = Some(image.into());
        self.check_budget()?;
        if image.bytes().len() > FIRMWARE_BYTES {
            return Err(Error::Unsupported(
                "Broadcom boot image exceeds declared 4MiB budget",
            ));
        }
        let buffer = self.firmware.as_mut().unwrap();
        buffer.write(0, image.bytes());
        let address = buffer.address();
        self.publish(self.firmware.as_ref().unwrap())?;
        self.check_budget()?;
        self.platform().arm_msi()?;
        self.check_budget()?;
        // The bound begins before any publication effect, including a delayed
        // register store followed by an otherwise immediate modeled boot ACK.
        let deadline = self.platform().now_us().saturating_add(5_000_000);
        for (offset, value) in [(0x590, 0), (0x594, 0), (0x598, DMA_WINDOW_BYTES as u32)] {
            self.write(Space::Bar0, offset, value)?;
        }
        self.write_bar2(0x200478, address as u32)?;
        self.write_bar2(0x20047c, (address >> 32) as u32)?;
        self.write_bar2(0x200480, image.bytes().len() as u32)?;
        self.write(Space::Bar0, 0x140, 0)?;
        self.wait_status(deadline, (0, 0), (2, 0), "actual Broadcom BOOT2")?;
        self.state = State::Firmware;

        let deadline = self.platform().now_us().saturating_add(1_000_000);
        self.write(Space::Bar0, 0x144, 1)?;
        self.wait_status(deadline, (2, 0), (2, 1), "actual Broadcom RTI1")?;
        self.publish(self.core())?;
        let deadline = self.platform().now_us().saturating_add(1_000_000);
        for (offset, value) in [
            (0x200494, 0),
            (0x200498, 0),
            (0x20049c, DMA_WINDOW_BYTES as u32),
        ] {
            self.write_bar2(offset, value)?;
        }
        let context = self.core().address();
        self.write_bar2(0x20048c, context as u32)?;
        self.write_bar2(0x200450, (context >> 32) as u32)?;
        self.write(Space::Bar0, 0x144, 2)?;
        self.wait_status(deadline, (2, 1), (2, 2), "actual Broadcom RTI2")?;
        self.state = State::Rti;
        self.open_rings()?;
        self.state = State::Active;
        Ok(())
    }
    pub(super) fn load_named<'p>(
        &mut self,
        provider: &'p dyn Provider,
        suffix: &str,
    ) -> Result<crate::firmware::Image<'p>> {
        let identity = self.identity.as_ref().unwrap();
        let hardware = identity.hardware_label();
        let revision = identity.revision_label();
        let target = identity.target(&hardware, &revision);
        let names = identity.names(suffix)?;
        let first = provider.load(Requirement {
            name: &names[0],
            target,
            minimum_bytes: 1,
        });
        match first {
            Ok(image) => Ok(image),
            Err(error) if error.kind == ErrorKind::Missing => {
                self.snapshot.firmware_errors.push(error);
                self.check_budget()?;
                provider
                    .load(Requirement {
                        name: &names[1],
                        target,
                        minimum_bytes: 1,
                    })
                    .map_err(Error::Firmware)
            }
            Err(error) => Err(Error::Firmware(error)),
        }
    }
    fn wait_status(
        &mut self,
        deadline: u64,
        prior: (u32, u32),
        expected: (u32, u32),
        requirement: &'static str,
    ) -> Result<()> {
        loop {
            if self.platform().now_us() >= deadline {
                return Err(Error::Timeout(requirement));
            }
            self.refresh_snapshot()?;
            if self.platform().now_us() >= deadline {
                return Err(Error::Timeout(requirement));
            }
            let observed = (self.snapshot.boot_stage, self.snapshot.rti_status);
            if observed == expected {
                return Ok(());
            }
            if observed != prior {
                return Err(Error::Protocol {
                    requirement,
                    observed: u64::from(self.snapshot.boot_stage) << 32
                        | u64::from(self.snapshot.rti_status),
                });
            }
            crate::waiting();
            core::hint::spin_loop();
        }
    }
}
