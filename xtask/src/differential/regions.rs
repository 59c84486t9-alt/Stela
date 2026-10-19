//! Region lane: random straight-line sequences of the integer and memory
//! forms the compiler's register-allocated and clean-load regions select,
//! translated as one ordinary block. Single-word cases never form a region,
//! so this lane is what compares region recipes, their residency and the
//! settling before each access and exit with the original.
//!
//! A few registers hold window pointers ([`Subject::pointers`]); the
//! sequence never writes them but by small immediates and writeback, and
//! retires one after a load into it, so most cases complete. SP is a
//! 16-byte aligned window pointer and its writeback keeps that alignment.
use super::Random;

/// The lane's form id; `--form` selects it by any part of this name.
pub(super) const FORM: &str = "region_sequence";
const MAX_LENGTH: u64 = 24;
const SP: u32 = 31;
const ZR: u32 = 31;
/// Window pointers each sequence starts with.
const POINTERS: usize = 3;

/// One sequence and the mask of X registers that start as window pointers.
pub(super) fn sequence(random: &mut Random) -> (Vec<u32>, u32) {
    let mut generator = Generator {
        random,
        pointers: 0,
    };
    while generator.pointers.count_ones() < POINTERS as u32 {
        generator.pointers |= 1 << generator.any();
    }
    let initial = generator.pointers;
    let length = 2 + generator.random.next() % (MAX_LENGTH - 1);
    let code = (0..length).map(|_| generator.word()).collect();
    (code, initial)
}

struct Generator<'a> {
    random: &'a mut Random,
    /// Registers that still hold window pointers.
    pointers: u32,
}

impl Generator<'_> {
    fn below(&mut self, bound: u64) -> u32 {
        (self.random.next() % bound) as u32
    }

    fn any(&mut self) -> u32 {
        self.below(31)
    }

    /// A register that is not a live pointer: any destination but a base.
    fn data(&mut self) -> u32 {
        loop {
            let register = self.below(32);
            if register == ZR || self.pointers & (1 << register) == 0 {
                return register;
            }
        }
    }

    /// A general register that is not a live pointer.
    fn destination(&mut self) -> u32 {
        loop {
            let register = self.data();
            if register != ZR {
                return register;
            }
        }
    }

    /// A live pointer base, or SP.
    fn base(&mut self, sp: bool) -> u32 {
        let live: Vec<u32> = (0..31).filter(|r| self.pointers & (1 << r) != 0).collect();
        if sp || live.is_empty() {
            return SP;
        }
        live[self.below(live.len() as u64) as usize]
    }

    fn word(&mut self) -> u32 {
        match self.below(16) {
            0..=7 => self.arithmetic(),
            8..=11 => self.load(),
            12 | 13 => self.pair(),
            _ => self.store(),
        }
    }

    fn arithmetic(&mut self) -> u32 {
        let sf = self.below(4).min(1) << 31;
        let (d, n, m) = (self.data(), self.any(), self.any());
        // Rd 31 of ADD and SUB immediate is SP, which stays a pointer.
        let sp_safe = if d == ZR { self.destination() } else { d };
        match self.below(11) {
            // ADD/SUB(S) immediate; ADD/SUB of a pointer keeps it in the window.
            0 => {
                let opcode = [0x1100_0000, 0x3100_0000, 0x5100_0000, 0x7100_0000];
                let opcode = opcode[self.below(4) as usize];
                sf | opcode | self.below(4096) << 10 | n << 5 | sp_safe
            }
            1 => {
                let base = self.base(false);
                let opcode = if self.below(2) == 0 {
                    0x9100_0000
                } else {
                    0xd100_0000
                };
                let unit = if base == SP { 16 } else { 1 };
                opcode | (self.below(64 / u64::from(unit)) * unit) << 10 | base << 5 | base
            }
            // ADD/SUB(S) shifted register, LSL/LSR/ASR.
            2 => {
                let opcode = [0x0b00_0000, 0x2b00_0000, 0x4b00_0000, 0x6b00_0000];
                let opcode = opcode[self.below(4) as usize];
                let amount = self.below(if sf != 0 { 64 } else { 32 });
                sf | opcode | self.below(3) << 22 | m << 16 | amount << 10 | n << 5 | d
            }
            // AND/ORR/EOR/ANDS shifted register.
            3 => {
                let opcode = [0x0a00_0000, 0x2a00_0000, 0x4a00_0000, 0x6a00_0000];
                let opcode = opcode[self.below(4) as usize];
                let amount = self.below(if sf != 0 { 64 } else { 32 });
                sf | opcode | self.below(4) << 22 | m << 16 | amount << 10 | n << 5 | d
            }
            // MOV (ORR from ZR).
            4 => sf | 0x2a00_03e0 | m << 16 | d,
            // MOVZ/MOVK.
            5 => {
                let opcode = if self.below(2) == 0 {
                    0x5280_0000
                } else {
                    0x7280_0000
                };
                let hw = self.below(if sf != 0 { 4 } else { 2 });
                sf | opcode | hw << 21 | self.below(1 << 16) << 5 | d
            }
            // MADD/MSUB, MUL when Ra is ZR.
            6 => {
                let a = if self.below(2) == 0 { ZR } else { self.any() };
                sf | 0x1b00_0000 | self.below(2) << 15 | m << 16 | a << 10 | n << 5 | d
            }
            // LSL/LSR immediate (UBFM).
            7 => {
                let bits = if sf != 0 { 64 } else { 32 };
                let shift = self.below(bits);
                let (immr, imms) = if self.below(2) == 0 {
                    (shift, bits as u32 - 1)
                } else {
                    ((bits as u32 - shift) % bits as u32, bits as u32 - 1 - shift)
                };
                sf | 0x5300_0000 | (sf >> 9) | immr << 16 | imms << 10 | n << 5 | d
            }
            // CSEL/CSINC.
            8 => {
                sf | 0x1a80_0000 | m << 16 | self.below(16) << 12 | self.below(2) << 10 | n << 5 | d
            }
            // CMP/CMN register and immediate.
            9 => sf | 0x6b00_001f | m << 16 | n << 5,
            // ROR immediate (EXTR with equal sources).
            _ => {
                let amount = self.below(if sf != 0 { 64 } else { 32 });
                sf | 0x1380_0000 | (sf >> 9) | n << 16 | amount << 10 | n << 5 | d
            }
        }
    }

    /// LDR(B/H/SB/SH/SW), LDR W/X: unsigned offset, unscaled or writeback.
    fn load(&mut self) -> u32 {
        // (size, opc) for zero- and sign-extending loads.
        const FORMS: [(u32, u32); 8] = [
            (0, 1),
            (1, 1),
            (2, 1),
            (3, 1),
            (0, 2),
            (1, 2),
            (2, 2),
            (0, 3),
        ];
        let (size, opc) = FORMS[self.below(FORMS.len() as u64) as usize];
        let sp = self.below(4) == 0;
        let n = self.base(sp);
        // A rare load into a pointer base retires it for the rest.
        let t = if n != SP && self.below(8) == 0 {
            self.pointers &= !(1 << n);
            n
        } else {
            self.data()
        };
        let head = size << 30 | 0x3800_0000 | opc << 22;
        match self.below(4) {
            0 | 1 => head | 1 << 24 | self.below(256) << 10 | n << 5 | t,
            2 => head | (self.below(512) & 0x1ff) << 12 | n << 5 | t,
            _ if t == n => head | 1 << 24 | n << 5 | t,
            _ => {
                let index = if self.below(2) == 0 { 1 } else { 3 };
                let step = self.step(n, 1 << size) as u32;
                head | (step & 0x1ff) << 12 | index << 10 | n << 5 | t
            }
        }
    }

    /// STR(B/H), STR W/X: unsigned offset, unscaled or writeback.
    fn store(&mut self) -> u32 {
        let size = self.below(4);
        let sp = self.below(3) == 0;
        let n = self.base(sp);
        let t = self.any();
        let head = size << 30 | 0x3800_0000;
        match self.below(4) {
            0 | 1 => head | 1 << 24 | self.below(256) << 10 | n << 5 | t,
            2 => head | (self.below(512) & 0x1ff) << 12 | n << 5 | t,
            _ if self.pointers & (1 << t) != 0 || t == n => head | 1 << 24 | n << 5 | t,
            _ => {
                let index = if self.below(2) == 0 { 1 } else { 3 };
                let step = self.step(n, 1 << size) as u32;
                head | (step & 0x1ff) << 12 | index << 10 | n << 5 | t
            }
        }
    }

    /// LDP/STP W/X: offset or writeback, distinct load destinations.
    fn pair(&mut self) -> u32 {
        let x = self.below(2);
        let load = self.below(2) == 1;
        let sp = self.below(2) == 0;
        let n = self.base(sp);
        let (t, t2) = loop {
            let (t, t2) = if load {
                (self.data(), self.data())
            } else {
                (self.any(), self.any())
            };
            if !load || t != t2 {
                break (t, t2);
            }
        };
        let scale = 4 << x;
        let mode = self.below(3);
        // Writeback through a base that is also a transfer register is
        // CONSTRAINED UNPREDICTABLE; loads never name a live pointer.
        let writeback =
            mode != 0 && self.pointers & (1 << t) == 0 && self.pointers & (1 << t2) == 0;
        let (index, offset) = if writeback {
            (
                if mode == 1 { 1 } else { 3 },
                self.step(n, scale) / scale as i32,
            )
        } else {
            let offset = self.below(32) as i32;
            (2, if self.below(2) == 0 { offset } else { -offset })
        };
        x << 31
            | 0x2800_0000
            | index << 23
            | u32::from(load) << 22
            | (offset as u32 & 0x7f) << 15
            | t2 << 10
            | n << 5
            | t
    }

    /// A small signed writeback step in bytes; SP steps stay multiples of
    /// 16.
    fn step(&mut self, base: u32, unit: u32) -> i32 {
        let unit = if base == SP { 16 } else { unit };
        let magnitude = ((1 + self.below(4)) * unit) as i32;
        if self.below(2) == 0 {
            magnitude
        } else {
            -magnitude
        }
    }
}
