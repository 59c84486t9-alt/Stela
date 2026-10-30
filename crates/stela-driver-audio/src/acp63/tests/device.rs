// SPDX-License-Identifier: GPL-2.0-only
//! Register side effects and sample generation for the PDM model.
use super::*;

impl Device {
    pub(super) fn read(&mut self, offset: usize) -> u32 {
        self.accesses.push((offset, false));
        assert!(
            !matches!(
                offset,
                0x102c | 0x141c | 0x1420 | 0x1424 | 0x1800 | 0x1804 | 0x1808
            ),
            "Renoir/CLKMUX-only read {offset:x}"
        );
        if offset == 0xc40 {
            self.atu_reads += 1;
            return self.atu_readback;
        }
        let value = if self.lost_read == Some(offset) {
            self.lost_read = None;
            u32::MAX
        } else if offset == 0x2c18 {
            if self.unstable {
                self.count = self.count.wrapping_add(1u64 << 32);
            }
            (self.count >> 32) as u32
        } else if offset == 0x2c1c {
            if self.rollover {
                self.rollover = false;
                self.count += 8;
            }
            self.count as u32
        } else {
            self.words[offset / 4]
        };
        if let Some((at, ready, elapsed)) = self.jump_read
            && at == offset
            && ready == value
        {
            self.jump_read = None;
            self.clock.fetch_add(elapsed, Ordering::Relaxed);
        }
        if offset == 0x1000 && value == 0 {
            self.retirement.push(Retirement::ResetAcknowledged);
        }
        if offset == 0xc04 && value == 0 {
            self.retirement.push(Retirement::GroupDisabled);
        }
        value
    }

    pub(super) fn write(&mut self, offset: usize, value: u32) {
        self.accesses.push((offset, true));
        assert!(
            !matches!(
                offset,
                0x102c | 0x141c | 0x1420 | 0x1424 | 0x1800 | 0x1804 | 0x1808
            ),
            "Renoir/CLKMUX-only write {offset:x}"
        );
        self.writes.push((offset, value));
        if self.ignore_write == Some(offset) {
            return;
        }
        match offset {
            0x1024 => {
                let on = if matches!(self.identity.revision, 0x70..=0x72) {
                    0x1f
                } else {
                    1
                };
                assert_eq!(value, on, "dedicated ACP63 has no source PGFSM-off request");
                // Request acceptance and eventual completion are separate:
                // the pinned power-on path must tolerate a valid command
                // whose PGFSM status never reaches powered-on.
                if !self.power_never {
                    self.words[0x1028 / 4] = 0;
                }
            }
            0x1000 => {
                self.words[offset / 4] = if self.reset_never || value == 1 {
                    0x10001
                } else {
                    0
                };
                if value == 0 && !self.reset_never {
                    self.resets += 1;
                    // Do not clear group1: retirement must explicitly
                    // disable/read back the PAGE_BASE enable bit.
                    for register in [0x2c04, 0x2c08] {
                        self.words[register / 4] = 0;
                    }
                    self.cursor = 0;
                    self.count = 0;
                }
            }
            0xc40 => {
                assert_eq!(value, 1, "cache invalidation is a write-one command");
                // Adversarial permitted read behavior, not a physical
                // self-clear guarantee, ACK or payload-completion model.
                self.words[offset / 4] = 0;
            }
            0x10004 if value & 0x8000_0000 != 0 => {
                self.published_reset = Some(self.resets);
                self.words[offset / 4] = value;
            }
            0x1a0c => self.words[offset / 4] &= !value, // Real W1C semantics.
            0x2c08 => {
                if value == 1 {
                    assert!(self.master);
                    assert_eq!(self.words[0x1004 / 4], 1);
                    assert_eq!(self.words[0x1014 / 4], 0);
                    assert_eq!(self.words[0x2c60 / 4], 7);
                    assert_eq!(self.words[0x2c04 / 4], 1);
                    assert_eq!(self.words[0x2c28 / 4], 0);
                    assert_eq!(self.words[0x2c2c / 4], 2);
                    assert_ne!(self.words[0x1a04 / 4] & (1 << 29), 0);
                    assert_ne!(self.words[0x1a04 / 4] & (1 << 16), 0);
                    assert_eq!(self.words[0x1a00 / 4], 1);
                    assert!(self.device_owns);
                    self.cursor = 0;
                    // Request may retire while independent active status
                    // stays asserted. Source checks bit1, not exact3.
                    self.words[offset / 4] = if self.start_never { 1 } else { 2 };
                } else if value == 2 && !self.stop_never {
                    self.words[offset / 4] = 0;
                }
            }
            0x2c24 => {
                assert_eq!(self.words[0x2c08 / 4], 0);
                assert_eq!(self.words[0x2c04 / 4], 0);
            }
            _ => self.words[offset / 4] = value,
        }
        if let Some((at, request, elapsed)) = self.jump_write
            && at == offset
            && request == value
        {
            self.jump_write = None;
            self.clock.fetch_add(elapsed, Ordering::Relaxed);
        }
        if self.fail_after_write == Some(offset) {
            self.fail_after_write = None;
            self.lost_read = Some(offset);
        }
    }

    pub(super) fn advance(&mut self, frames: usize) {
        if !self.master || self.words[0x2c08 / 4] & 2 == 0 {
            return;
        }
        assert!(self.device_owns);
        assert_eq!(self.words[0xc00 / 4], 2);
        assert_eq!(self.words[0xc04 / 4], 0x8380_0000);
        assert_eq!(self.words[0x2c0c / 4], 0x0400_0000);
        let ring = self.words[0x2c10 / 4] as usize;
        let period = self.words[0x2c20 / 4] as usize;
        for _ in 0..frames {
            for channel in 0..2 {
                let offset = (self.cursor + channel * 4) % ring;
                let entry = 0x10000 / 4 + offset / 4096 * 2;
                let high = self.words[entry + 1];
                assert_ne!(high & 0x8000_0000, 0);
                let iova = u64::from(self.words[entry]) | u64::from(high & 0x7fff_ffff) << 32;
                let translation = self.translation.as_ref().unwrap();
                assert!(iova >= translation.token.address);
                let mapped = (iova - translation.token.address) as usize + offset % 4096;
                assert!(mapped + 4 <= translation.token.bytes);
                // These physical pages are not contiguous;
                // only the attached domain constructs the contiguous IOVA.
                assert_eq!(
                    translation.pages.physical_pages()[mapped / 4096],
                    0x5000_0000 + (mapped / 4096) as u64 * 0x3000
                );
                let pointer = translation.cpu.address(mapped, 4).unwrap();
                let sample = sample(self.frames, channel);
                if self.defer_payload {
                    // A real fabric may still hold issued payload after
                    // the ACP counter and engine-stop acknowledgment.
                    self.posted.push((mapped, sample));
                } else {
                    // SAFETY: this synchronous model owns DMA while active;
                    // CPU RAM is reached through its domain.
                    unsafe { pointer.as_ptr().cast::<i32>().write_volatile(sample) };
                }
            }
            self.frames += 1;
            self.count = self.count.wrapping_add(8);
            self.cursor = (self.cursor + 8) % ring;
            if self.cursor.is_multiple_of(period) && !self.defer_payload {
                // The ordinary model supplies the pinned source completed-
                // period event only after its coherent payload.
                // A deferred retirement fabric has not delivered that
                // event; raw progress/stop acknowledgment alone cannot.
                self.words[0x1a0c / 4] |= 1 << 16;
            }
        }
    }
}
