// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! Linux r8169_firmware.c instruction format, with native bounds and budgets.
//! The checksum is a format check, not a firmware signature. Catalog integrity
//! and exact device binding are checked before this parser is called.
use super::{Error, Timer, block_error};
use crate::block::BlockError;

const HEADER: usize = 45;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_STEPS: usize = 262_144;
const MAX_DELAY_US: u64 = 2_000_000;
const MAX_EXECUTION_US: u64 = 10_000_000;

pub(super) struct Script<'a> {
    code: &'a [u8],
}

pub(super) trait ScriptIo {
    fn read(&mut self, mac: bool, reg: u16) -> Result<u16, BlockError>;
    fn write(&mut self, mac: bool, reg: u16, value: u16) -> Result<(), BlockError>;
    /// Restore the shared OCP base even if the script fails or ends in MCU mode.
    fn restore(&mut self);
}

impl<'a> Script<'a> {
    pub(super) fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let bad = Error::Script;
        if bytes.len() < 4 || bytes.len() > MAX_BYTES {
            return Err(bad("firmware size outside 4..=4194304"));
        }
        let code = if bytes[..4] == [0; 4] {
            if bytes.len() < HEADER {
                return Err(bad("truncated firmware header"));
            }
            if bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0 {
                return Err(bad("firmware checksum mismatch"));
            }
            let start = word(bytes, 36) as usize;
            let length = word(bytes, 40) as usize;
            // Start need not be aligned. Decode individual LE words, not a cast.
            if start < HEADER || start > bytes.len() || length > (bytes.len() - start) / 4 {
                return Err(bad("firmware command range outside image"));
            }
            &bytes[start..start + length * 4]
        } else {
            if !bytes.len().is_multiple_of(4) {
                return Err(bad("unaligned raw firmware length"));
            }
            bytes
        };
        if code.is_empty() {
            return Err(bad("empty firmware program"));
        }
        let script = Self { code };
        for pc in 0..script.len() {
            let action = script.action(pc);
            let op = action >> 28;
            let reg = ((action >> 16) & 0xfff) as usize;
            let data = action as u16;
            match op {
                0 | 1 | 2 | 7 | 8 | 12 | 14 => (),
                4 if data <= 1 => (),
                3 if reg <= pc => (),
                9 if pc + 2 < script.len() => (),
                10 | 11 | 13 if pc + 1 + reg < script.len() => (),
                _ => return Err(bad("unknown opcode, MDIO mode or out-of-range jump")),
            }
        }
        Ok(script)
    }

    fn len(&self) -> usize {
        self.code.len() / 4
    }
    fn action(&self, pc: usize) -> u32 {
        word(self.code, pc * 4)
    }

    pub(super) fn execute(&self, io: &mut impl ScriptIo, timer: &impl Timer) -> Result<(), Error> {
        let result = self.run(io, timer);
        io.restore();
        result
    }

    fn run(&self, io: &mut impl ScriptIo, timer: &impl Timer) -> Result<(), Error> {
        let (mut pc, mut reads, mut previous, mut mac, mut delays) =
            (0usize, 0u32, 0u16, false, 0u64);
        let started = timer.now();
        for _ in 0..MAX_STEPS {
            if pc == self.len() {
                return Ok(());
            }
            if timer.now().wrapping_sub(started) >= MAX_EXECUTION_US {
                return Err(Error::Script("firmware execution deadline exceeded"));
            }
            let action = self.action(pc);
            let op = action >> 28;
            let reg = ((action >> 16) & 0xfff) as u16;
            let data = action as u16;
            let mut next = pc + 1;
            match op {
                0 => {
                    previous = io.read(mac, reg).map_err(block_error)?;
                    reads = reads.wrapping_add(1);
                }
                1 => previous |= data,
                2 => previous &= data,
                3 => next = pc - usize::from(reg),
                4 => mac = data != 0,
                7 => reads = 0,
                8 => io.write(mac, reg, data).map_err(block_error)?,
                9 if reads == u32::from(data) => next += 1,
                10 if previous == data => next += usize::from(reg),
                11 if previous != data => next += usize::from(reg),
                12 => io.write(mac, reg, previous).map_err(block_error)?,
                13 => next += usize::from(reg),
                14 => {
                    let delay = u64::from(data) * 1000;
                    delays += delay;
                    if delays > MAX_DELAY_US {
                        return Err(Error::Script("firmware delay budget exceeded"));
                    }
                    timer.delay(delay);
                }
                _ => (), // Already exhaustively validated; conditional skip not taken.
            }
            pc = next;
        }
        Err(Error::Script("firmware instruction budget exceeded"))
    }
}
fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated firmware word"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::Cell;
    #[derive(Default)]
    struct Time(Cell<u64>);
    impl Timer for Time {
        fn now(&self) -> u64 {
            self.0.get()
        }
        fn delay(&self, us: u64) {
            self.0.set(self.0.get() + us);
        }
    }
    #[derive(Default)]
    struct Io {
        writes: Vec<(bool, u16, u16)>,
        reads: Vec<(bool, u16)>,
        restored: bool,
        fail: bool,
    }
    impl ScriptIo for Io {
        fn read(&mut self, mac: bool, reg: u16) -> Result<u16, BlockError> {
            if self.fail {
                return Err(BlockError::Timeout);
            }
            self.reads.push((mac, reg));
            Ok(0x55aa)
        }
        fn write(&mut self, mac: bool, reg: u16, value: u16) -> Result<(), BlockError> {
            if self.fail {
                return Err(BlockError::Timeout);
            }
            self.writes.push((mac, reg, value));
            Ok(())
        }
        fn restore(&mut self) {
            self.restored = true;
        }
    }
    fn raw(code: &[u32]) -> Vec<u8> {
        code.iter().flat_map(|v| v.to_le_bytes()).collect()
    }
    fn image(code: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0u8; 45];
        bytes[4..8].copy_from_slice(b"test");
        bytes[36..40].copy_from_slice(&45u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&(code.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&raw(code));
        bytes[44] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        bytes
    }
    #[test]
    fn independent_header_fixture_uses_unaligned_le_commands_and_checksum() {
        let bytes = image(&[0x80010023]);
        let s = Script::parse(&bytes).unwrap();
        let mut io = Io::default();
        s.execute(&mut io, &Time::default()).unwrap();
        assert_eq!(io.writes, [(false, 1, 0x23)]);
        assert!(io.restored);
        for offset in [4, 36, 40, 44, 46] {
            let mut corrupt = bytes.clone();
            corrupt[offset] ^= 1;
            assert!(Script::parse(&corrupt).is_err());
        }
        let mut overlapping = image(&[0x80010023]);
        overlapping[36] = 0;
        overlapping[44] = 0;
        overlapping[44] = 0u8.wrapping_sub(overlapping.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
        assert!(Script::parse(&overlapping).is_err());
    }
    #[test]
    fn skips_modes_reads_and_previous_data_match_linux_instruction_semantics() {
        let bytes = raw(&[
            0x00020001, // read PHY2 ->55aa, count1 (nonzero raw-format marker)
            0x10000005, // OR5 ->55af
            0x2000ffff, // ANDffff
            0xc0040000, // writeprevious PHY4
            0x90000001, // readcount==1 skip next
            0x8005dead, 0xa00155af, // eq skip1
            0x8006dead, 0xb0010000, // neq skip1
            0x8007dead, 0x70000000, 0x40000001, // MCUmode
            0x80081234, 0x40000000, 0xd0010000, // unconditionalskip1
            0x8009dead, 0xe0000001,
        ]);
        let mut io = Io::default();
        let time = Time::default();
        Script::parse(&bytes)
            .unwrap()
            .execute(&mut io, &time)
            .unwrap();
        assert_eq!(io.reads, [(false, 2)]);
        assert_eq!(io.writes, [(false, 4, 0x55af), (true, 8, 0x1234)]);
        assert_eq!(time.now(), 1000);
        assert!(io.restored);
    }
    #[test]
    fn rejects_bad_opcodes_modes_and_each_jump_boundary_before_io() {
        for code in [
            vec![0x50000000],
            vec![0x40000002],
            vec![0x30010000],
            vec![0x90000000, 0x80000000],
            vec![0xa0010000, 0x80000000],
            vec![0xb0010000, 0x80000000],
            vec![0xd0010000, 0x80000000],
        ] {
            assert!(Script::parse(&raw(&code)).is_err(), "{code:x?}");
        }
        assert!(Script::parse(&[0; 44]).is_err());
        assert!(Script::parse(&[1, 2, 3, 4, 5]).is_err());
        assert!(Script::parse(&image(&[])).is_err());
    }
    #[test]
    fn backward_loops_delays_and_bus_failures_have_budgets_and_restore_state() {
        let time = Time::default();
        let mut io = Io::default();
        let bytes = raw(&[0x30000000]);
        assert_eq!(
            Script::parse(&bytes).unwrap().execute(&mut io, &time),
            Err(Error::Script("firmware instruction budget exceeded"))
        );
        assert!(io.restored);
        let bytes = raw(&[0xe000ffff]);
        assert_eq!(
            Script::parse(&bytes).unwrap().execute(&mut io, &time),
            Err(Error::Script("firmware delay budget exceeded"))
        );
        let mut io = Io {
            fail: true,
            ..Io::default()
        };
        let bytes = raw(&[0x80010001]);
        assert_eq!(
            Script::parse(&bytes).unwrap().execute(&mut io, &time),
            Err(Error::Device(BlockError::Timeout))
        );
        assert!(io.restored);
    }
}
