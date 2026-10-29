//! Native PMIC protected loader transactions, separate from execution/services.
//!
//! This is an explicitly created Stela loader, not a reconstruction of Apple
//! reset state. The original J314s LLB's 15940..15fc8, 18288..18514 and
//! 18d18..18e00 supply the AP sequence, key extents and image descriptor.
//! A successful transfer changes protection, staged configuration and
//! SRAM ownership. Starting requires a further native service/resource owner;
//! no upload, descriptor, key or status read manufactures that owner.
use super::{FirmwareStartup, firmware::FirmwareMemory};
use alloc::{vec, vec::Vec};
use core::ops::Range;
use sha2::Digest;
use stela_crypto::Sha256;
mod clock;
mod integrity;
use stela_soc_data::pmu::PmicEpoch;

const HEADER: usize = 0xc0;
const HEADER_BYTES: usize = 0x34;
const UUID_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Created,
    Stopped,
    Unlocked,
    Configured,
    FlagsCleared,
    ImageStopped,
    Uploading,
    Sealed,
    Locked,
}

/// Structural image information derived from bytes committed by AP commands.
/// The digest identifies those bytes, never authenticates them or establishes
/// execution, a physical PMIC ID, a supported firmware ABI or service readiness.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Image {
    bytes: usize,
    digest: [u8; 32],
    configuration: usize,
    version: usize,
    uuid: [u8; UUID_BYTES],
    metadata: u16,
}
impl Image {
    fn parse(bytes: &[u8], written: &[bool], metadata: u16) -> Result<Self, &'static str> {
        let end = written
            .iter()
            .rposition(|written| *written)
            .map_or(0, |last| last + 1);
        if end < HEADER + HEADER_BYTES
            || written[..end].iter().any(|written| !written)
            || end > bytes.len()
        {
            return Err(
                "PMIC loader requires a contiguous freshly written image span without holes",
            );
        }
        let bytes = &bytes[..end];
        let header = &bytes[HEADER..HEADER + HEADER_BYTES];
        let word = |offset| {
            u32::from_le_bytes(header[offset..offset + 4].try_into().expect("header word"))
        };
        if word(0) != u32::from_le_bytes(*b"uuid") {
            return Err("PMIC loader image has no qualified UUID descriptor");
        }
        let configuration = word(8) as usize;
        let version = word(12) as usize;
        let metadata_offset = word(0x30) as usize;
        if configuration >= end || version >= end || metadata_offset >= end {
            return Err("PMIC loader image descriptor lies outside committed bytes");
        }
        if metadata_offset > usize::from(u16::MAX) || metadata_offset as u16 != metadata {
            return Err("PMIC loader metadata does not match its image descriptor");
        }
        Ok(Self {
            bytes: end,
            digest: Sha256::digest(bytes).into(),
            configuration,
            version,
            uuid: header[0x10..0x20].try_into().expect("UUID"),
            metadata,
        })
    }
}

/// Every prepared mutation remains private to its loader transaction.
/// This is neither a completion token nor an externally supplied effect receipt.
pub(super) enum Write {
    Stop,
    Phase,
    Metadata(u16),
    Seal(Image),
}

pub(super) struct Loader {
    profile: FirmwareStartup,
    phase: Phase,
    metadata: Option<u16>,
    written: Vec<bool>,
    image: Option<Image>,
    clock: Option<clock::Clock>,
}
impl Loader {
    pub fn new(
        profile: FirmwareStartup,
        capacity: usize,
        epoch: Option<PmicEpoch>,
    ) -> Result<Self, &'static str> {
        Ok(Self {
            profile,
            phase: Phase::Created,
            metadata: None,
            written: vec![false; capacity],
            image: None,
            clock: epoch.map(clock::Clock::new).transpose()?,
        })
    }

    pub fn check_time(&self, now: u64) -> Result<(), &'static str> {
        self.clock.as_ref().map_or(Ok(()), |clock| clock.check(now))
    }
    pub fn prepare_time(&mut self, now: u64) -> Result<Option<clock::Advance<'_>>, &'static str> {
        self.clock
            .as_mut()
            .map(|clock| clock.prepare(now))
            .transpose()
    }

    fn control(&self) -> u16 {
        match self.profile {
            FirmwareStartup::Maverick => 0xc800,
            FirmwareStartup::Monaco => 0x2800,
        }
    }
    fn key(&self) -> (u16, [u8; 4], u16) {
        match self.profile {
            // LLB resource view +3c/+4c and +40/+48, not its +38 tag.
            FirmwareStartup::Maverick => (0x7001, 0x6576_6144u32.to_le_bytes(), 0x7000),
            FirmwareStartup::Monaco => (0x5000, 0x4f72_4561u32.to_le_bytes(), 0x5004),
        }
    }
    pub fn claims(&self, address: u16, bytes: usize) -> bool {
        let end = u64::from(address).saturating_add(bytes.max(1) as u64);
        self.profile.windows().iter().any(|window| {
            u64::from(address) < u64::from(window.base) + u64::from(window.bytes)
                && u64::from(window.base) < end
        })
    }
    pub fn read(&self, address: u16, bytes: usize) -> Result<Vec<u8>, &'static str> {
        let control = self.control();
        let value = match (address.wrapping_sub(control), bytes) {
            (4, 1)
                if matches!(
                    self.phase,
                    Phase::Configured
                        | Phase::FlagsCleared
                        | Phase::ImageStopped
                        | Phase::Uploading
                        | Phase::Sealed
                        | Phase::Locked
                ) =>
            {
                Some(match self.profile {
                    FirmwareStartup::Maverick => 0x49,
                    FirmwareStartup::Monaco => 0xc1,
                })
            }
            (4, 1) if self.phase == Phase::Stopped => Some(0),
            (5, 1)
                if matches!(
                    self.phase,
                    Phase::FlagsCleared
                        | Phase::ImageStopped
                        | Phase::Uploading
                        | Phase::Sealed
                        | Phase::Locked
                ) =>
            {
                Some(0)
            }
            (0, 1)
                if matches!(
                    self.phase,
                    Phase::ImageStopped | Phase::Uploading | Phase::Sealed | Phase::Locked
                ) =>
            {
                Some(0)
            }
            // The native owner is stopped, with no active service or
            // pending boot result. This is never Apple reset-state evidence.
            (0x13, 1)
                if self.profile == FirmwareStartup::Maverick
                    && matches!(self.phase, Phase::Uploading | Phase::Sealed | Phase::Locked) =>
            {
                Some(0)
            }
            (0x14, 1)
                if self.profile == FirmwareStartup::Monaco
                    && matches!(self.phase, Phase::Uploading | Phase::Sealed | Phase::Locked) =>
            {
                Some(0)
            }
            (1, 2) if self.metadata.is_some() => {
                return Ok(self.metadata.expect("metadata").to_le_bytes().to_vec());
            }
            _ => None,
        };
        value.map(|value| vec![value]).ok_or("PMIC loader read requires a qualified written control; identity/mode/key/startup service is unqualified")
    }

    pub fn prepare(
        &self,
        address: u16,
        data: &[u8],
        memory: &FirmwareMemory,
        now: u64,
    ) -> Result<Write, &'static str> {
        let control = self.control();
        let (key, value, lock) = self.key();
        if address == control + 4 && data == [0] {
            return Ok(Write::Stop);
        }
        if address == key && data == value && self.phase == Phase::Stopped {
            return Ok(Write::Phase);
        }
        let configuration = match self.profile {
            FirmwareStartup::Maverick => 0x49,
            FirmwareStartup::Monaco => 0xc1,
        };
        if address == control + 4 && data == [configuration] && self.phase == Phase::Unlocked
            || address == control + 5 && data == [0] && self.phase == Phase::Configured
            || address == control && data == [0] && self.phase == Phase::FlagsCleared
        {
            return Ok(Write::Phase);
        }
        if address == control + 1 && data.len() == 2 && self.phase == Phase::ImageStopped {
            return Ok(Write::Metadata(u16::from_le_bytes([data[0], data[1]])));
        }
        if self.profile == FirmwareStartup::Maverick
            && address == 0xc828
            && data == [4]
            && self.phase == Phase::Uploading
        {
            return Image::parse(
                memory.bytes(),
                &self.written,
                self.metadata.expect("upload metadata"),
            )
            .map(Write::Seal);
        }
        if address == lock && data == [0] && self.phase == Phase::Sealed {
            return Ok(Write::Phase);
        }
        if address == control + 6 && data == [1] && self.phase == Phase::Locked {
            let clock = self.clock.as_ref().ok_or("PMIC start requires its actual explicitly configured native execution/timer clock owner")?;
            // Original Maverick image1 main 80e..818 configures timer3 with
            // request100000. This validates a real representable native
            // countdown deadline before any startup effect. It does not arm
            // the timer or supply missing clock-selection/event semantics.
            if self.profile == FirmwareStartup::Maverick {
                clock.deadline(now, clock::Reload::from_request(100000).countdown_cycles())?;
                let image = self.image.as_ref().expect("locked image");
                integrity::verify(
                    &memory.bytes()[..image.bytes],
                    image.configuration,
                    image.version,
                    image.metadata,
                )?;
            }
            return Err(match self.profile {
                FirmwareStartup::Maverick => {
                    "PMIC start requires initialized native event/timer, channel and shared-service resource owners"
                }
                FirmwareStartup::Monaco => {
                    "PMIC start requires initialized native firmware hardware-input/calibration, event/timer and shared-service resource owners"
                }
            });
        }
        Err("PMIC protected loader command, width, value or transaction order is unqualified")
    }

    pub fn commit(&mut self, write: Write) {
        match write {
            Write::Stop => {
                self.phase = Phase::Stopped;
                self.metadata = None;
                self.written.fill(false);
                self.image = None;
            }
            Write::Phase => {
                self.phase = match self.phase {
                    Phase::Stopped => Phase::Unlocked,
                    Phase::Unlocked => Phase::Configured,
                    Phase::Configured => Phase::FlagsCleared,
                    Phase::FlagsCleared => Phase::ImageStopped,
                    Phase::Sealed => Phase::Locked,
                    _ => unreachable!("prepared protected loader phase"),
                }
            }
            Write::Metadata(metadata) => {
                self.metadata = Some(metadata);
                self.phase = Phase::Uploading;
            }
            Write::Seal(image) => {
                self.image = Some(image);
                self.phase = Phase::Sealed;
            }
        }
    }
    pub fn check_memory(&self, writing: bool) -> Result<(), &'static str> {
        if self.phase == Phase::Uploading
            || !writing && matches!(self.phase, Phase::Sealed | Phase::Locked)
        {
            Ok(())
        } else {
            Err("PMIC loader SRAM access requires its actual protected upload/readback transaction")
        }
    }
    pub fn written(&mut self, range: Range<usize>) {
        self.written[range].fill(true);
    }
}

#[cfg(test)]
mod tests;
