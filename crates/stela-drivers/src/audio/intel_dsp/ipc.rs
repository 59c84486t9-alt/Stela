// SPDX-License-Identifier: GPL-2.0-only
//! SOF IPC3 cold-ready and single-outstanding CNL doorbell protocol.
//! Adapted from pinned Linux intel/cnl.c, ipc3.c and info.h.
//! Copyright(c) 2018, 2020 Intel Corporation
use super::{Controller, Error, FirmwareReport, Mailboxes, Phase, Registers, registers::*};
use crate::bus::i2c::Timer;

pub(super) fn word(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::FirmwareImage)?
            .try_into()
            .map_err(|_| Error::FirmwareImage)?,
    ))
}
pub(super) fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
pub(super) fn firmware_payload(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.len() < 4096 {
        return Err(Error::FirmwareImage);
    }
    let payload = if word(bytes, 0)? == 0x6e614d58 {
        let full = word(bytes, 4)? as usize;
        let header = word(bytes, 8)? as usize;
        if header < 16 || full < header || full >= bytes.len() || word(bytes, 12)? >> 24 != 1 {
            return Err(Error::FirmwareImage);
        }
        let mut offset = header;
        while offset < full {
            // Extended manifests may end in zero-filled padding.
            if bytes[offset..full].iter().all(|byte| *byte == 0) {
                break;
            }
            let size = word(bytes, offset + 4)? as usize;
            if size < 8
                || !size.is_multiple_of(4)
                || offset.checked_add(size).is_none_or(|end| end > full)
            {
                return Err(Error::FirmwareImage);
            }
            // A cAVS LPRO selection requires actual clock preparation that this
            // held-D0 HPRO profile does not own. Do not silently ignore it.
            if word(bytes, offset)? == 6 {
                if !(size - 8).is_multiple_of(8) {
                    return Err(Error::FirmwareImage);
                }
                for element in bytes[offset + 8..offset + size].chunks_exact(8) {
                    if word(element, 0)? == 1 && word(element, 4)? != 0 {
                        return Err(Error::FirmwareImage);
                    }
                }
            }
            offset += size;
        }
        &bytes[full..]
    } else {
        bytes
    };
    if payload.len() < 4096 {
        return Err(Error::FirmwareImage);
    }
    // Signed Intel image validation belongs to the ROM/CSE. No synthetic
    // firmware or host-side "authenticated" flag replaces FW_ENTERED/READY.
    Ok(payload)
}

impl<R: Registers, T: Timer> Controller<R, T> {
    fn sram_read(&mut self, offset: usize, bytes: &mut [u8]) -> Result<(), Error> {
        if offset < 0x80000
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > self.registers.bytes(Bar::Dsp))
        {
            return Err(Error::Mailbox);
        }
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = self.registers.read8(Bar::Dsp, offset + index)?;
        }
        Ok(())
    }
    fn sram_write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if offset < 0x80000
            || offset
                .checked_add(bytes.len())
                .is_none_or(|end| end > self.registers.bytes(Bar::Dsp))
        {
            return Err(Error::Mailbox);
        }
        for (index, &byte) in bytes.iter().enumerate() {
            self.registers.write8(Bar::Dsp, offset + index, byte)?;
        }
        Ok(())
    }
    pub(super) fn firmware_ready(&mut self, sha256: [u8; 32]) -> Result<FirmwareReport, Error> {
        let start = self.timer.now_us();
        let notification = self.poll(
            Bar::Dsp,
            IPC_NOTIFY,
            BUSY,
            BUSY,
            start,
            3_000_000,
            Phase::Firmware,
        )?;
        // IPC3 commands live in SRAM, not in the CNL doorbell. Only the
        // documented panic magic gives the lower doorbell bits meaning here.
        if notification & 0x0ffff000 == 0x0dead000 {
            return Err(Error::FirmwarePanic(notification));
        }
        let mut ready = [0u8; 108];
        self.sram_read(READY_MAILBOX, &mut ready)?;
        if word(&ready, 0)? != ready.len() as u32
            || word(&ready, 4)? != 0x70000000
            || word(&ready, 24)? != 60
        {
            return Err(Error::Mailbox);
        }
        let abi = word(&ready, 64)?;
        if abi >> 24 != 3 || ((abi >> 12) & 0xfff) > 23 || abi < 0x0300a000 {
            return Err(Error::FirmwareAbi(abi));
        }
        let mut next = READY_MAILBOX + ready.len();
        let mut windows = None;
        for _ in 0..16 {
            let mut header = [0u8; 12];
            self.sram_read(next, &mut header)?;
            if word(&header, 4)? != 0x70000000 {
                break;
            }
            let size = word(&header, 0)? as usize;
            if !(12..=4096).contains(&size)
                || size & 3 != 0
                || next
                    .checked_add(size)
                    .is_none_or(|end| end > READY_MAILBOX + 4096)
            {
                return Err(Error::Mailbox);
            }
            match word(&header, 8)? {
                1 => {
                    if windows.is_some() || size < 16 {
                        return Err(Error::Mailbox);
                    }
                    let count = self.read(Bar::Dsp, next + 12)? as usize;
                    if count == 0 || count > 16 || size < 16 + count * 24 || size > 16 + 16 * 24 {
                        return Err(Error::Mailbox);
                    }
                    let mut host = None;
                    let mut dsp = None;
                    let mut spans = [(0usize, 0usize); 16];
                    for index in 0..count {
                        let at = next + 16 + index * 24;
                        if self.read(Bar::Dsp, at)? != 24 {
                            return Err(Error::Mailbox);
                        }
                        let kind = self.read(Bar::Dsp, at + 4)?;
                        let id = self.read(Bar::Dsp, at + 8)? as usize;
                        let bytes = self.read(Bar::Dsp, at + 16)? as usize;
                        let offset = self.read(Bar::Dsp, at + 20)? as usize;
                        if id > 3
                            || kind > 6
                            || bytes == 0
                            || offset & 3 != 0
                            || offset.checked_add(bytes).is_none_or(|end| end > 0x20000)
                        {
                            return Err(Error::Mailbox);
                        }
                        let start = 0x80000 + id * 0x20000 + offset;
                        let end = start
                            .checked_add(bytes)
                            .filter(|end| *end <= self.registers.bytes(Bar::Dsp))
                            .ok_or(Error::Mailbox)?;
                        if spans[..index]
                            .iter()
                            .any(|&(lo, hi)| start < hi && lo < end)
                        {
                            return Err(Error::Mailbox);
                        }
                        spans[index] = (start, end);
                        match kind {
                            0 => {
                                if host.replace((start, bytes)).is_some() || bytes < 384 {
                                    return Err(Error::Mailbox);
                                }
                            }
                            1 => {
                                if dsp.replace((start, bytes)).is_some() || bytes < 384 {
                                    return Err(Error::Mailbox);
                                }
                            }
                            _ => (),
                        }
                    }
                    let (host, host_bytes) = host.ok_or(Error::Mailbox)?;
                    let (dsp, dsp_bytes) = dsp.ok_or(Error::Mailbox)?;
                    windows = Some(Mailboxes {
                        host,
                        host_bytes,
                        dsp,
                        dsp_bytes,
                    });
                }
                0 | 2 | 3 | 4 => (),
                _ => return Err(Error::Mailbox),
            }
            next += size;
        }
        let boxes: Mailboxes = windows.take().ok_or(Error::Mailbox)?;
        self.mailboxes = Some(boxes);
        self.update(Bar::Dsp, IPC_NOTIFY, BUSY, BUSY)?;
        self.update(Bar::Dsp, IPC_NOTIFY_ACK, BUSY, BUSY)?;
        Ok(FirmwareReport {
            sha256,
            abi,
            major: u16::from_le_bytes([ready[28], ready[29]]),
            minor: u16::from_le_bytes([ready[30], ready[31]]),
            micro: u16::from_le_bytes([ready[32], ready[33]]),
            build: u16::from_le_bytes([ready[34], ready[35]]),
        })
    }
    pub(super) fn exchange(&mut self, message: &[u8], reply: &mut [u8]) -> Result<usize, Error> {
        self.authority()?;
        let boxes = self.mailboxes.ok_or(Error::State)?;
        if message.len() < 8
            || message.len() > 384
            || word(message, 0)? as usize != message.len()
            || message.len() > boxes.host_bytes
            || reply.len() < 12
        {
            return Err(Error::Mailbox);
        }
        if boxes.dsp_bytes < 8
            || boxes
                .dsp
                .checked_add(boxes.dsp_bytes)
                .is_none_or(|end| end > self.registers.bytes(Bar::Dsp))
        {
            return Err(Error::Mailbox);
        }
        if self.read(Bar::Dsp, ADSPCS)? & 0x01010101 != 0x01010000 {
            return Err(Error::Authority);
        }
        if self.read(Bar::Dsp, IPC_REQ)? & BUSY != 0
            || self.read(Bar::Dsp, IPC_ACK)? & BUSY != 0
            || self.read(Bar::Dsp, IPC_NOTIFY)? & BUSY != 0
        {
            return Err(Error::IpcReply);
        }
        let start = self.timer.now_us();
        self.sram_write(boxes.host, message)?;
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.write(Bar::Dsp, IPC_REQ, BUSY)?;
        loop {
            if self.timer.now_us().wrapping_sub(start) >= 500_000 {
                return Err(Error::Timeout(Phase::Ipc));
            }
            let notification = self.read(Bar::Dsp, IPC_NOTIFY)?;
            if notification & BUSY != 0 {
                return Err(Error::FirmwarePanic(notification));
            }
            let ack = self.read(Bar::Dsp, IPC_ACK)?;
            if self.timer.now_us().wrapping_sub(start) >= 500_000 {
                return Err(Error::Timeout(Phase::Ipc));
            }
            if ack & BUSY != 0 {
                break;
            }
            self.timer.relax();
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let mut header = [0u8; 12];
        self.sram_read(boxes.host, &mut header)?;
        let size = word(&header, 0)? as usize;
        if size < 12 || size > reply.len() || size > boxes.host_bytes || size > 384 {
            return Err(Error::IpcReply);
        }
        self.sram_read(boxes.host, &mut reply[..size])?;
        self.update(Bar::Dsp, IPC_ACK, BUSY, BUSY)?;
        let error = word(&header, 8)? as i32;
        if error < 0 {
            return Err(Error::IpcError(error));
        }
        if error != 0 {
            return Err(Error::IpcReply);
        }
        Ok(size)
    }
}
