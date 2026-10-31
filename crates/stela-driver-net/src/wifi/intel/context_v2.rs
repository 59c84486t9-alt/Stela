// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2018, 2020-2026 Intel Corporation
//! Standalone AX210 context-v2/scratch preparation from pcie/ctxt-info-v2.c
//! and pcie/iwl-context-info-v2.h at the pinned Linux revision.
//!
//! This is CPU-only serialization, not a DMA, IML/ROM or PNVM completion.
//! Addresses require real kept mappings. The whole 4KiB peripheral-info
//! allocation is device writable, including dummy tail locations at 2/3KiB.
//! Context/scratch/info survive ALIVE for the later PNVM protocol; IML and
//! transient firmware can be released only on kept-epoch ALIVE.
use super::{
    context::{self, Images, Region, validate},
    firmware::{self, Family, Firmware},
    identity::Profile,
    platform::StepConfiguration,
};

pub const CONTEXT_BYTES: usize = 104;
pub const SCRATCH_BYTES: usize = 1724;
/// Without external FSEQ the donor advertises only through dram.common, in
/// bytes, despite the context header comment describing the field as dwords.
pub const ADVERTISED_SCRATCH_BYTES: usize = 1660;
pub const INFO_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug)]
pub struct Queues {
    /// AX210 transfer descriptors are 16 bytes per receive entry.
    pub free: Region,
    /// AX210 completion descriptors are 32 bytes per receive entry.
    pub used: Region,
    /// AX210 hardware producer status is a single 16-bit value.
    pub status: Region,
    /// max(IWL_CMD_QUEUE_SIZE, AX210 min_txq_size) = 128 long 256-byte TFDs.
    pub command: Region,
    /// Count after the AX210 family doubling, not the cfg base count.
    pub receive_entries: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Memory {
    pub info: Region,
    pub scratch: Region,
    pub context: Region,
    pub iml: Region,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    WrongFamily,
    Firmware(firmware::Error),
    Layout(context::Error),
}
impl From<context::Error> for Error {
    fn from(value: context::Error) -> Self {
        Self::Layout(value)
    }
}
impl From<firmware::Error> for Error {
    fn from(value: firmware::Error) -> Self {
        Self::Firmware(value)
    }
}

#[derive(Debug)]
pub struct Ax210Context {
    context: [u8; CONTEXT_BYTES],
    scratch: [u8; SCRATCH_BYTES],
}
impl Ax210Context {
    /// The normal 4KiB-RB profile, without an external FSEQ or debug
    /// destination.
    /// The normal MVM transport configuration leaves external-clock flags
    /// zero; ECKV radio init remains a separate firmware operation.
    ///
    /// This bounded allocator profile admits 16..1024 receive entries. The
    /// upper bound keeps the 32-byte used ring within the transport's
    /// 32KiB allocation limit; it is not a claim about the hardware maximum.
    /// All inputs are serialization data, never ownership/visibility proof.
    pub fn encode(
        profile: &Profile,
        firmware: &Firmware<'_>,
        queues: Queues,
        images: Images<'_>,
        memory: Memory,
        step: &StepConfiguration<'_>,
    ) -> Result<Self, Error> {
        if profile.family() != Family::Ax210 {
            return Err(Error::WrongFamily);
        }
        firmware.require_family(Family::Ax210)?;
        let plan = firmware.self_load_plan()?;
        let iml = firmware.iml().ok_or(firmware::Error::Missing("IML"))?;
        let entries = usize::from(queues.receive_entries);
        if !(16..=1024).contains(&entries) || !entries.is_power_of_two() {
            return Err(context::Error::QueueSize.into());
        }
        validate(queues.free, entries * 16, 256)?;
        validate(queues.used, entries * 32, 256)?;
        validate(queues.status, 2, 16)?;
        validate(queues.command, 128 * 256, 256)?;
        validate(memory.info, INFO_BYTES, 4096)?;
        // Match the native transport's fresh page-backed coherent allocation
        // profile rather than infer a smaller undocumented hardware alignment.
        validate(memory.scratch, SCRATCH_BYTES, 4096)?;
        validate(memory.context, CONTEXT_BYTES, 4096)?;
        if iml.len() > 32768 {
            return Err(context::Error::PayloadLength.into());
        }
        validate(memory.iml, iml.len(), 4096)?;
        let groups = [
            (plan.umac(), images.umac, 124),
            (plan.lmac(), images.lmac, 636),
            (plan.paging(), images.paging, 1148),
        ];
        for (sections, regions, _) in groups {
            if sections.len() != regions.len() || regions.is_empty() || regions.len() > 64 {
                return Err(context::Error::ImageCount.into());
            }
            for (section, region) in sections.iter().zip(regions) {
                validate(*region, section.data.len(), 4)?;
            }
        }
        let fixed = [
            queues.free,
            queues.used,
            queues.status,
            queues.command,
            memory.info,
            memory.scratch,
            memory.context,
            memory.iml,
        ];
        let regions = fixed
            .iter()
            .chain(images.umac)
            .chain(images.lmac)
            .chain(images.paging);
        for (index, a) in regions.clone().enumerate() {
            for b in regions.clone().skip(index + 1) {
                if a.address < b.address + b.bytes as u64 && b.address < a.address + a.bytes as u64
                {
                    return Err(context::Error::AliasedRegion.into());
                }
            }
        }
        let mut context = [0; CONTEXT_BYTES];
        for (at, address) in [
            (8, memory.info.address),
            (16, queues.status.address),
            (24, memory.info.address + 2048),
            (32, memory.info.address + 3072),
            (52, queues.command.address),
            (60, queues.used.address),
            (88, memory.scratch.address),
        ] {
            context[at..at + 8].copy_from_slice(&address.to_le_bytes());
        }
        context[68..70].copy_from_slice(&4u16.to_le_bytes()); // ilog2(128)-3
        context[70..72].copy_from_slice(&(entries.ilog2() as u16).to_le_bytes());
        context[96..100].copy_from_slice(&(ADVERTISED_SCRATCH_BYTES as u32).to_le_bytes());
        let mut scratch = [0; SCRATCH_BYTES];
        scratch[..2].copy_from_slice(&(profile.observed().hardware_revision as u16).to_le_bytes());
        scratch[4..6].copy_from_slice(&((SCRATCH_BYTES / 4) as u16).to_le_bytes());
        // RB_SIZE_4K | MTR_MODE | MTR_FORMAT_256B, with IMR_DEBUG_EN where the
        // MAC configuration asks for it.
        let control = 0x000f_0000 | u32::from(profile.platform().imr) << 1;
        scratch[8..12].copy_from_slice(&control.to_le_bytes());
        scratch[48..56].copy_from_slice(&queues.free.address.to_le_bytes());
        let mailboxes = step.mailboxes();
        scratch[76..80].copy_from_slice(&mailboxes[0].to_le_bytes());
        scratch[80..84].copy_from_slice(&mailboxes[1].to_le_bytes());
        for (_, regions, base) in groups {
            for (index, region) in regions.iter().enumerate() {
                let at = base + index * 8;
                scratch[at..at + 8].copy_from_slice(&region.address.to_le_bytes());
            }
        }
        Ok(Self { context, scratch })
    }
    pub fn context(&self) -> &[u8; CONTEXT_BYTES] {
        &self.context
    }
    pub fn scratch(&self) -> &[u8; SCRATCH_BYTES] {
        &self.scratch
    }
}

#[cfg(test)]
mod tests;
