// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2002 ShuChen <shuchen@realtek.com.tw>
// Copyright (c) 2003-2007 Francois Romieu <romieu@fr.zoreil.com>
// Copyright (c) a lot of people too. Please respect their work.
// Copyright (c) 2026 Stela contributors
//! MAC40/42/44 start and source-licensed RTL8411B RX fix from pinned Linux.
use super::super::registers::*;
use super::{BlockError, Hardware, Registers, Timer};
const RX_FIX: &[u16] = &[
    0xe008, 0xe00a, 0xe00c, 0xe00e, 0xe027, 0xe04f, 0xe05e, 0xe065, 0xc602, 0xbe00, 0x0000, 0xc502,
    0xbd00, 0x074c, 0xc302, 0xbb00, 0x080a, 0x6420, 0x48c2, 0x8c20, 0xc516, 0x64a4, 0x49c0, 0xf009,
    0x74a2, 0x8ca5, 0x74a0, 0xc50e, 0x9ca2, 0x1c11, 0x9ca0, 0xe006, 0x74f8, 0x48c4, 0x8cf8, 0xc404,
    0xbc00, 0xc403, 0xbc00, 0x0bf2, 0x0c0a, 0xe434, 0xd3c0, 0x49d9, 0xf01f, 0xc526, 0x64a5, 0x1400,
    0xf007, 0x0c01, 0x8ca5, 0x1c15, 0xc51b, 0x9ca0, 0xe013, 0xc519, 0x74a0, 0x48c4, 0x8ca0, 0xc516,
    0x74a4, 0x48c8, 0x48ca, 0x9ca4, 0xc512, 0x1b00, 0x9ba0, 0x1b1c, 0x483f, 0x9ba2, 0x1b04, 0xc508,
    0x9ba0, 0xc505, 0xbd00, 0xc502, 0xbd00, 0x0300, 0x051e, 0xe434, 0xe018, 0xe092, 0xde20, 0xd3c0,
    0xc50f, 0x76a4, 0x49e3, 0xf007, 0x49c0, 0xf103, 0xc607, 0xbe00, 0xc606, 0xbe00, 0xc602, 0xbe00,
    0x0c4c, 0x0c28, 0x0c2c, 0xdc00, 0xc707, 0x1d00, 0x8de2, 0x48c1, 0xc502, 0xbd00, 0x00aa, 0xe0c0,
    0xc502, 0xbd00, 0x0132,
];
impl<R: Registers, T: Timer> Hardware<'_, R, T> {
    pub(super) fn g_start(&self) -> Result<(), BlockError> {
        let r = self.registers;
        self.eri_write(0xc8, 15, (0x08 << 16) | 2)?;
        self.eri_write(0xe8, 15, (0x10 << 16) | 6)?;
        self.eri_write(0xcc, 1, 0x38)?;
        self.eri_write(0xd0, 1, 0x48)?;
        self.latency()?;
        self.eri_modify(0xdc, 1, 0)?;
        self.eri_modify(0xdc, 0, 1)?;
        self.eri_write(0x2f8, 3, 0x1d8f)?;
        r.write32(MISC, self.mmio32(MISC)? & !RXDV_GATED);
        self.eri_write(0xc0, 3, 0)?;
        self.eri_write(0xb8, 3, 0)?;
        self.eri_modify(0x2fc, 6, 1)?;
        self.eri_modify(0x1b0, (1 << 12) | 3, 0)?; // RX config and TX-LPI off.
        r.write8(CONFIG3, self.mmio8(CONFIG3)? & !(1 << 1));
        match self.revision.version {
            40 => self.ephys(&[
                (0, 8, 0),
                (0xc, 0x3ff0, 0x0820),
                (0x1e, 0, 1),
                (0x19, 0x8000, 0),
            ])?,
            42 => self.ephys(&[
                (0, 8, 0),
                (0xc, 0x3ff0, 0x0820),
                (0x19, 0xffff, 0x7c00),
                (0x1e, 0xffff, 0x20eb),
                (0xd, 0xffff, 0x1666),
                (0, 0xffff, 0x10a3),
                (6, 0xffff, 0xf050),
                (4, 0, 0x10),
                (0x1d, 0x4000, 0),
            ])?,
            44 => {
                self.ephys(&[
                    (0, 8, 0),
                    (0xc, 0x37d0, 0x0820),
                    (0x1e, 0, 1),
                    (0x19, 0x8021, 0),
                    (0x1e, 0, 0x2000),
                    (0xd, 0x100, 0x200),
                    (0, 0, 0x80),
                    (6, 0, 0x10),
                    (4, 0, 0x10),
                    (0x1d, 0, 0x4000),
                ])?;
                for address in (0xfc28..=0xfc36).step_by(2) {
                    self.mac_ocp_write(address, 0)?;
                }
                self.timer.delay(3_000)?;
                self.mac_ocp_write(0xfc26, 0)?;
                for (n, value) in RX_FIX.iter().copied().enumerate() {
                    self.mac_ocp_write(0xf800 + 2 * n as u16, value)?;
                }
                self.mac_ocp_write(0xfc26, 0x8000)?;
                for (address, value) in [
                    (0xfc2a, 0x0743),
                    (0xfc2c, 0x0801),
                    (0xfc2e, 0x0be9),
                    (0xfc30, 0x02fd),
                    (0xfc32, 0x0c25),
                    (0xfc34, 0x00a9),
                    (0xfc36, 0x012d),
                ] {
                    self.mac_ocp_write(address, value)?;
                }
            }
            _ => return Err(BlockError::Unsupported("unimplemented Realtek G start")),
        }
        r.write8(0x1b, self.mmio8(0x1b)? & !7);
        self.mac_ocp_modify(0xc0ac, 0, 0x1f80)
    }
}
