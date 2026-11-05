// SPDX-License-Identifier: GPL-2.0-only
//! Register-only containment of inherited conventional HDA DMA. This is an
//! engine observation, not a root, IRQ, firmware or worker retirement receipt.
use super::{Config, Registers, registers::*};
use crate::{Error, Phase, Timer};

/// A completed conventional HDA engine-stop observation. It deliberately
/// grants no original-root migration or DMA allocation permission.
pub struct Stopped {
    streams: u8,
}
impl Stopped {
    pub fn streams(&self) -> u8 {
        self.streams
    }
}

enum Width {
    Byte,
    Word,
    Dword,
}
struct Field {
    offset: usize,
    width: Width,
    mask: u32,
}

fn wait<R: Registers>(
    registers: &mut R,
    timer: &impl Timer,
    timeout: u32,
    field: Field,
    phase: Phase,
) -> Result<(), Error> {
    let Field {
        offset,
        width,
        mask,
    } = field;
    let start = timer.now_us();
    loop {
        let (value, failed) = match width {
            Width::Byte => {
                let v = registers.read8(offset);
                (u32::from(v), v == u8::MAX)
            }
            Width::Word => {
                let v = registers.read16(offset);
                (u32::from(v), v == u16::MAX)
            }
            Width::Dword => {
                let v = registers.read32(offset);
                (v, v == u32::MAX)
            }
        };
        if failed {
            return Err(Error::RegisterUnavailable { offset });
        }
        if value & mask == 0 {
            return Ok(());
        }
        if timer.now_us().wrapping_sub(start) >= u64::from(timeout) {
            return Err(Error::Timeout(phase));
        }
        timer.relax();
    }
}

/// Stop every inherited physical stream, CORB/RIRB and position DMA without
/// allocating, zeroing, rebasing or resetting inherited buffers or the link.
/// Controller/stream interrupt enables are disabled and read back separately.
///
/// The caller's register-provider ownership/exclusion and power prerequisites
/// remain necessary. The platform must independently retire old IRQ delivery,
/// firmware and CPU/work users and drain the original root before any binding.
/// A mask readback, stopped RUN bit or returned observation cannot replace
/// those proofs. Failure is uncertain; an owning lifecycle must latch failure
/// and retain the original config/MMIO/root/backing without replay or reset.
pub fn stop_inherited(
    registers: &mut impl Registers,
    timer: &impl Timer,
    config: &Config,
) -> Result<Stopped, Error> {
    timer.check().map_err(Error::MinimumDelay)?;
    if config.transition_timeout_us == 0 {
        return Err(Error::InvalidConfiguration);
    }
    let (major, minor) = (registers.read8(VMAJ), registers.read8(VMIN));
    if major != 1 || minor != 0 {
        return Err(Error::UnsupportedVersion { major, minor });
    }
    let gcap = registers.read16(GCAP);
    let streams = ((gcap >> 8) & 15) + ((gcap >> 12) & 15) + ((gcap >> 3) & 31);
    if streams == 0 || streams > 30 || registers.region_bytes() < 0x80 + usize::from(streams) * 0x20
    {
        return Err(Error::UnsupportedTopology);
    }
    let gctl = registers.read32(GCTL);
    if gctl == u32::MAX {
        return Err(Error::RegisterUnavailable { offset: GCTL });
    }
    registers.write32(INTCTL, 0);
    wait(
        registers,
        timer,
        config.transition_timeout_us,
        Field {
            offset: INTCTL,
            width: Width::Dword,
            mask: u32::MAX,
        },
        Phase::CommandStop,
    )?;
    registers.write16(WAKEEN, 0);
    wait(
        registers,
        timer,
        config.transition_timeout_us,
        Field {
            offset: WAKEEN,
            width: Width::Word,
            mask: u32::from(CODEC_MASK),
        },
        Phase::CommandStop,
    )?;
    registers.write32(GCTL, gctl & !GCTL_UNSOL);
    wait(
        registers,
        timer,
        config.transition_timeout_us,
        Field {
            offset: GCTL,
            width: Width::Dword,
            mask: GCTL_UNSOL,
        },
        Phase::CommandStop,
    )?;
    for index in 0..streams as u8 {
        let base = stream_base(index);
        let previous = registers.read8(base + SD_CTL);
        if previous == u8::MAX {
            return Err(Error::RegisterUnavailable {
                offset: base + SD_CTL,
            });
        }
        registers.write8(base + SD_CTL, previous & !(SD_RUN | SD_STATUS));
        wait(
            registers,
            timer,
            config.transition_timeout_us,
            Field {
                offset: base + SD_CTL,
                width: Width::Byte,
                mask: u32::from(SD_RUN | SD_STATUS),
            },
            Phase::StreamStop,
        )?;
        registers.write8(base + SD_STS, SD_STATUS);
        wait(
            registers,
            timer,
            config.transition_timeout_us,
            Field {
                offset: base + SD_STS,
                width: Width::Byte,
                mask: u32::from(SD_STATUS),
            },
            Phase::StreamStop,
        )?;
    }
    for (offset, mask) in [(CORBCTL, COMMAND_RUN | 1), (RIRBCTL, RIRB_RUN_STATUS)] {
        registers.write8(offset, 0);
        wait(
            registers,
            timer,
            config.transition_timeout_us,
            Field {
                offset,
                width: Width::Byte,
                mask: u32::from(mask),
            },
            Phase::CommandStop,
        )?;
    }
    for (offset, mask) in [
        (CORBSTS, CORB_MEMORY),
        (RIRBSTS, RIRB_RESPONSE | RIRB_OVERRUN),
    ] {
        registers.write8(offset, mask);
        wait(
            registers,
            timer,
            config.transition_timeout_us,
            Field {
                offset,
                width: Width::Byte,
                mask: u32::from(mask),
            },
            Phase::CommandStop,
        )?;
    }
    // DPLBASE bit0 enables position DMA. Clear it before changing the high
    // address; retain inherited backing through the independent original drain.
    for offset in [DPLBASE, DPUBASE] {
        registers.write32(offset, 0);
        wait(
            registers,
            timer,
            config.transition_timeout_us,
            Field {
                offset,
                width: Width::Dword,
                mask: u32::MAX,
            },
            Phase::CommandStop,
        )?;
    }
    Ok(Stopped {
        streams: streams as u8,
    })
}

#[cfg(test)]
mod tests;
