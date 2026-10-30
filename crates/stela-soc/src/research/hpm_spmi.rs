//! HPM's SPMI mailbox transport, independent of the native register body.
//!
//! Original 26A434 mac15g AppleHPMARMSPMI (SHA256
//! 8210f3645ea16c2481bcaf285ead56eaf2e591bb0d124fe2c01f596c6361ded3):
//! writeIECSReg at VA978f8d0 bounds bodies to 1..64 bytes; writeRegs at
//! 978fb34 selects/polls register0, writes body bytes at 0xa0 (excluding
//! the IECS length prefix), then selects again to commit. readRegs at
//! 9790250 selects/polls, reads length at 0x1f, then reads at 0x20 using
//! the requested capacity, not necessarily the reported length. A cleared
//! status bit7 and selector bits6:0 identify completion. Native operations
//! here complete before their SPMI ACK; polling never manufactures readiness.
//!
//! enterRTPC/exitRTPC at 9791cf0/9791e50 use SPMI Sleep/Wakeup, not mailbox
//! registers. Their power effects and indexed output levels belong to
//! the backend. No SN201202x body or firmware identity is supplied here and
//! no board compatible is admitted. CD3217/18 and ccg3pa2 are not substitutes.
use alloc::vec::Vec;
use stela_contracts::refuse;

use crate::spmi::{Command, SlaveError, SpmiSlave};

const CAPACITY: usize = 64;
const SELECTOR: u16 = 0;
const LENGTH: u16 = 0x1f;
const READ_DATA: u16 = 0x20;
const WRITE_DATA: u16 = 0xa0;

/// One captured native response. The backend supplies every readable wire byte,
/// including any checked tail beyond its reported length; transport adds none.
#[derive(Clone)]
pub struct Register {
    bytes: Vec<u8>,
    reported: u8,
}
impl Register {
    pub fn new(bytes: &[u8], reported: usize) -> Result<Self, SlaveError> {
        if bytes.is_empty() || bytes.len() > CAPACITY || reported == 0 || reported > bytes.len() {
            return Err(SlaveError::Unsupported(refuse!(
                "HPM mailbox response extent is unqualified"
            )));
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            reported: reported as u8,
        })
    }
}

/// HPM register owner. Selection must validate a real readable or writable
/// register before reporting ready; writes execute the whole staged body once.
/// Clone preparation must not publish external effects before acceptance. There
/// is no default register body, ready reply or invented IRQ.
pub trait Registers: Clone {
    fn select(&mut self, register: u8, now: u64) -> Result<(), SlaveError>;
    fn read(&mut self, register: u8, now: u64) -> Result<Register, SlaveError>;
    fn write(&mut self, register: u8, bytes: &[u8], now: u64) -> Result<(), SlaveError>;
    /// An accepted RTPC transition owns its power state and keeps the
    /// mailbox state. Unknown power/retention/output behavior must refuse.
    fn command(&mut self, _command: Command, _now: u64) -> Result<(), SlaveError> {
        Err(SlaveError::Unsupported(refuse!(
            "HPM RTPC command/output state is unqualified"
        )))
    }
    fn interrupt_level(&self, _output: u8) -> Option<bool> {
        None
    }
    fn interrupt_armed(&self) -> bool {
        true
    }
    fn check_time(&self, _now: u64) -> Result<(), SlaveError> {
        Ok(())
    }
    fn advance(&mut self, _now: u64) -> Option<u64> {
        None
    }
}

#[derive(Clone)]
pub struct Mailbox<R: Registers> {
    registers: R,
    selected: Option<u8>,
    staged: Vec<u8>,
    response: Option<Register>,
}
impl<R: Registers> Mailbox<R> {
    pub fn new(registers: R) -> Self {
        Self {
            registers,
            selected: None,
            staged: Vec::new(),
            response: None,
        }
    }
    fn selected(&self) -> Result<u8, SlaveError> {
        self.selected.ok_or(SlaveError::Unsupported(refuse!(
            "HPM mailbox has no accepted selector"
        )))
    }
    fn capture(&mut self, now: u64) -> Result<&Register, SlaveError> {
        let register = self.selected()?;
        if self.response.is_none() {
            self.response = Some(self.registers.read(register, now)?);
        }
        Ok(self.response.as_ref().expect("captured response"))
    }
    fn read_inner(&mut self, address: u16, bytes: &mut [u8], now: u64) -> Result<(), SlaveError> {
        if address == SELECTOR && bytes.len() == 1 {
            bytes[0] = self.selected()?;
        } else if !self.staged.is_empty() {
            return Err(SlaveError::Unsupported(refuse!(
                "HPM mailbox read while a write body is owned is unqualified"
            )));
        } else if address == LENGTH && bytes.len() == 1 {
            bytes[0] = self.capture(now)?.reported;
        } else {
            let start =
                address
                    .checked_sub(READ_DATA)
                    .map(usize::from)
                    .ok_or(SlaveError::Unsupported(refuse!(
                        "HPM mailbox read address is unqualified"
                    )))?;
            let end = start
                .checked_add(bytes.len())
                .filter(|_| !bytes.is_empty())
                .ok_or(SlaveError::Unsupported(refuse!(
                    "HPM mailbox read extent is unqualified"
                )))?;
            let data = self
                .capture(now)?
                .bytes
                .get(start..end)
                .ok_or(SlaveError::Unsupported(refuse!(
                    "HPM mailbox read exceeds the native response"
                )))?;
            bytes.copy_from_slice(data);
        }
        Ok(())
    }
    fn write_inner(&mut self, address: u16, bytes: &[u8], now: u64) -> Result<(), SlaveError> {
        if address == SELECTOR {
            let &[register] = bytes else {
                return Err(SlaveError::Unsupported(refuse!(
                    "HPM mailbox selector is exactly one byte"
                )));
            };
            if register & 0x80 != 0 {
                return Err(SlaveError::Unsupported(refuse!(
                    "HPM mailbox selector uses seven bits"
                )));
            }
            if self.staged.is_empty() {
                self.registers.select(register, now)?;
                self.selected = Some(register);
            } else {
                if self.selected()? != register {
                    return Err(SlaveError::Unsupported(refuse!(
                        "HPM mailbox selector would discard an owned write"
                    )));
                }
                self.registers.write(register, &self.staged, now)?;
                self.staged.clear();
            }
            self.response = None;
        } else {
            self.selected()?;
            if usize::from(address) != usize::from(WRITE_DATA) + self.staged.len()
                || bytes.is_empty()
                || bytes.len() > CAPACITY - self.staged.len()
            {
                return Err(SlaveError::Unsupported(refuse!(
                    "HPM mailbox write is not a contiguous 1..64 byte body"
                )));
            }
            self.staged.extend_from_slice(bytes);
        }
        Ok(())
    }
}
impl<R: Registers> SpmiSlave for Mailbox<R> {
    fn read(&mut self, address: u16, bytes: &mut [u8], now: u64) -> Result<(), SlaveError> {
        let mut next = self.clone();
        let mut output = [0; CAPACITY];
        let output = output
            .get_mut(..bytes.len())
            .ok_or(SlaveError::Unsupported(refuse!(
                "HPM mailbox read exceeds 64 bytes"
            )))?;
        next.read_inner(address, output, now)?;
        bytes.copy_from_slice(output);
        *self = next;
        Ok(())
    }
    fn write(&mut self, address: u16, bytes: &[u8], now: u64) -> Result<(), SlaveError> {
        let mut next = self.clone();
        next.write_inner(address, bytes, now)?;
        *self = next;
        Ok(())
    }
    fn command(&mut self, command: Command, now: u64) -> Result<(), SlaveError> {
        if !self.staged.is_empty() {
            return Err(SlaveError::Unsupported(refuse!(
                "HPM RTPC while a mailbox body is owned is unqualified"
            )));
        }
        if matches!(command, Command::Reset | Command::Shutdown) {
            return Err(SlaveError::Unsupported(refuse!(
                "HPM mailbox reset/supply state is unqualified"
            )));
        }
        let mut next = self.clone();
        next.registers.command(command, now)?;
        *self = next;
        Ok(())
    }
    fn interrupt_level(&self) -> Option<bool> {
        self.registers.interrupt_level(0)
    }
    fn interrupt_level_at(&self, output: u8) -> Option<bool> {
        self.registers.interrupt_level(output)
    }
    fn interrupt_armed(&self) -> bool {
        self.registers.interrupt_armed()
    }
    fn check_time(&self, now: u64) -> Result<(), SlaveError> {
        self.registers.check_time(now)
    }
    fn advance(&mut self, now: u64) -> Option<u64> {
        self.registers.advance(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Authored backend fixture: its bytes and power effects are not an Apple
    /// identity or an implementation of SN201202x firmware.
    #[derive(Clone)]
    struct Body {
        bytes: Vec<u8>,
        reported: usize,
        selects: usize,
        reads: usize,
        writes: usize,
    }
    impl Registers for Body {
        fn select(&mut self, register: u8, _: u64) -> Result<(), SlaveError> {
            self.selects += 1;
            if [9, 0x18].contains(&register) {
                Ok(())
            } else {
                Err(SlaveError::Unsupported(refuse!(
                    "fixture has no such register"
                )))
            }
        }
        fn read(&mut self, register: u8, _: u64) -> Result<Register, SlaveError> {
            self.reads += 1;
            if register != 9 {
                return Err(SlaveError::Unsupported(refuse!(
                    "fixture write-only register"
                )));
            }
            Register::new(&self.bytes, self.reported)
        }
        fn write(&mut self, _: u8, bytes: &[u8], _: u64) -> Result<(), SlaveError> {
            self.writes += 1;
            // Mutate the preparation before refusing: neither
            // that mutation nor its count may escape a failed mailbox call.
            self.bytes[0] = bytes[0];
            if bytes.len() != self.bytes.len() || bytes[0] == 0xff {
                return Err(SlaveError::Unsupported(refuse!(
                    "fixture body is unqualified"
                )));
            }
            self.bytes.copy_from_slice(bytes);
            Ok(())
        }
    }
    fn mailbox(bytes: usize) -> Mailbox<Body> {
        Mailbox::new(Body {
            bytes: (0..bytes as u8).collect(),
            reported: bytes,
            selects: 0,
            reads: 0,
            writes: 0,
        })
    }
    fn read(m: &mut Mailbox<Body>, address: u16, len: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0; len];
        SpmiSlave::read(m, address, &mut bytes, 0).unwrap();
        bytes
    }

    #[test]
    #[ignore = "oracle: STELA_TEST_HPM_SPMI_KC_ROOT"]
    fn original_ap_mailbox_and_rtpc_producers_are_source_pinned() {
        use sha2::Digest;
        let root = std::path::PathBuf::from(std::env::var("STELA_TEST_HPM_SPMI_KC_ROOT").unwrap());
        // Absolute coordinates belong only to these immutable evidence fixtures.
        // They never select a production device body or firmware response.
        for (name, digest, words) in [
            (
                "kernelcache.release.mac15g",
                "8210f3645ea16c2481bcaf285ead56eaf2e591bb0d124fe2c01f596c6361ded3",
                [
                    (0xfffffe000978f93c_u64, 0xf100fd1f_u32),
                    (0xfffffe000978fb90_u64, 0xd2811c11_u32),
                    (0xfffffe000978fd2c_u64, 0xd10006c3_u32),
                    (0xfffffe000978fd50_u64, 0x910006a2_u32),
                    (0xfffffe000978fd54_u64, 0x52801401_u32),
                    (0xfffffe000978fd8c_u64, 0xd2811c11_u32),
                    (0xfffffe0009790480_u64, 0x528003e1_u32),
                    (0xfffffe0009790520_u64, 0xf9400283_u32),
                    (0xfffffe0009790544_u64, 0x52800401_u32),
                    (0xfffffe0009791ddc_u64, 0x9123c208_u32),
                    (0xfffffe0009791ef8_u64, 0xd2812011_u32),
                    (0xfffffe000978f5fc_u64, 0x71000d1f_u32),
                    (0xfffffe000978f604_u64, 0x7100091f_u32),
                    (0xfffffe000978f810_u64, 0xd65f03c0_u32),
                    (0xfffffe000978f834_u64, 0x39055e7f_u32),
                ],
            ),
            (
                "kernelcache.release.mac15j",
                "d2c63d611b83f9b12a3b66f0b9e3882260de44f665423d341bf1ea60808ec3e6",
                [
                    (0xfffffe000980552c_u64, 0xf100fd1f_u32),
                    (0xfffffe0009805780_u64, 0xd2811c11_u32),
                    (0xfffffe000980591c_u64, 0xd10006c3_u32),
                    (0xfffffe0009805940_u64, 0x910006a2_u32),
                    (0xfffffe0009805944_u64, 0x52801401_u32),
                    (0xfffffe000980597c_u64, 0xd2811c11_u32),
                    (0xfffffe0009806070_u64, 0x528003e1_u32),
                    (0xfffffe0009806110_u64, 0xf9400283_u32),
                    (0xfffffe0009806134_u64, 0x52800401_u32),
                    (0xfffffe00098079cc_u64, 0x9123c208_u32),
                    (0xfffffe0009807ae8_u64, 0xd2812011_u32),
                    (0xfffffe00098051ec_u64, 0x71000d1f_u32),
                    (0xfffffe00098051f4_u64, 0x7100091f_u32),
                    (0xfffffe0009805400_u64, 0xd65f03c0_u32),
                    (0xfffffe0009805424_u64, 0x39055e7f_u32),
                ],
            ),
            (
                "kernelcache.release.mac16g",
                "196efb3db57543e7c2cc8f12e6468a7a95b6d80a3924117178dfbe3ade52ca0e",
                [
                    (0xfffffe0009800b4c_u64, 0xf100fd1f_u32),
                    (0xfffffe0009800da0_u64, 0xd2811c11_u32),
                    (0xfffffe0009800f3c_u64, 0xd10006c3_u32),
                    (0xfffffe0009800f60_u64, 0x910006a2_u32),
                    (0xfffffe0009800f64_u64, 0x52801401_u32),
                    (0xfffffe0009800f9c_u64, 0xd2811c11_u32),
                    (0xfffffe0009801690_u64, 0x528003e1_u32),
                    (0xfffffe0009801730_u64, 0xf9400283_u32),
                    (0xfffffe0009801754_u64, 0x52800401_u32),
                    (0xfffffe0009802fec_u64, 0x9123c208_u32),
                    (0xfffffe0009803108_u64, 0xd2812011_u32),
                    (0xfffffe000980080c_u64, 0x71000d1f_u32),
                    (0xfffffe0009800814_u64, 0x7100091f_u32),
                    (0xfffffe0009800a20_u64, 0xd65f03c0_u32),
                    (0xfffffe0009800a44_u64, 0x39055e7f_u32),
                ],
            ),
            (
                "kernelcache.release.mac17g",
                "4c7c9ba936b617c1c0a8cb27381acd6b56d99f1a954216b80ca7ae96439affcf",
                [
                    (0xfffffe000983dcac_u64, 0xf100fd1f_u32),
                    (0xfffffe000983df00_u64, 0xd2811c11_u32),
                    (0xfffffe000983e09c_u64, 0xd10006c3_u32),
                    (0xfffffe000983e0c0_u64, 0x910006a2_u32),
                    (0xfffffe000983e0c4_u64, 0x52801401_u32),
                    (0xfffffe000983e0fc_u64, 0xd2811c11_u32),
                    (0xfffffe000983e7f0_u64, 0x528003e1_u32),
                    (0xfffffe000983e890_u64, 0xf9400283_u32),
                    (0xfffffe000983e8b4_u64, 0x52800401_u32),
                    (0xfffffe000984014c_u64, 0x9123c208_u32),
                    (0xfffffe0009840268_u64, 0xd2812011_u32),
                    (0xfffffe000983d96c_u64, 0x71000d1f_u32),
                    (0xfffffe000983d974_u64, 0x7100091f_u32),
                    (0xfffffe000983db80_u64, 0xd65f03c0_u32),
                    (0xfffffe000983dba4_u64, 0x39055e7f_u32),
                ],
            ),
        ] {
            let bytes = std::fs::read(root.join(name)).unwrap();
            assert_eq!(format!("{:x}", sha2::Sha256::digest(&bytes)), digest);
            for (va, encoding) in words {
                let at = (va - 0xffff_fe00_0700_4000) as usize;
                assert_eq!(
                    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
                    encoding,
                    "{name} at {va:#x}"
                );
            }
        }
    }

    #[test]
    fn response_length_and_split_data_share_one_native_snapshot_without_padding() {
        let mut m = mailbox(8);
        m.registers.reported = 4;
        let mut unchanged = [0xaa];
        assert!(SpmiSlave::read(&mut m, SELECTOR, &mut unchanged, 0).is_err());
        assert_eq!(unchanged, [0xaa]);
        SpmiSlave::write(&mut m, SELECTOR, &[9], 0).unwrap();
        assert_eq!(read(&mut m, SELECTOR, 1), [9]);
        assert_eq!(m.registers.reads, 0); // polling did not complete a read
        assert_eq!(read(&mut m, LENGTH, 1), [4]);
        m.registers.bytes.fill(0xee);
        assert_eq!(read(&mut m, READ_DATA, 3), [0, 1, 2]);
        // The backend explicitly supplied all eight wire bytes even though
        // only four are reported. No zero tail is invented by the mailbox.
        assert_eq!(read(&mut m, READ_DATA + 3, 5), [3, 4, 5, 6, 7]);
        assert_eq!(m.registers.reads, 1);
        assert!(SpmiSlave::read(&mut m, READ_DATA + 8, &mut unchanged, 0).is_err());
        assert_eq!(unchanged, [0xaa]);
        SpmiSlave::write(&mut m, SELECTOR, &[9], 0).unwrap();
        assert_eq!(read(&mut m, READ_DATA, 8), [0xee; 8]);
        assert_eq!(m.registers.reads, 2);
        for (bytes, reported) in [
            (&[][..], 0),
            (&[1][..], 0),
            (&[1][..], 2),
            (&[0; 65][..], 64),
        ] {
            assert!(Register::new(bytes, reported).is_err());
        }
    }

    #[test]
    fn every_body_length_is_staged_without_the_iecs_prefix_and_committed_once() {
        for len in 1..=CAPACITY {
            let mut m = mailbox(len);
            let body: Vec<u8> = (1..=len as u8).collect();
            SpmiSlave::write(&mut m, SELECTOR, &[9], 0).unwrap();
            assert_eq!(read(&mut m, SELECTOR, 1), [9]);
            for (index, chunk) in body.chunks(16).enumerate() {
                SpmiSlave::write(&mut m, WRITE_DATA + (index * 16) as u16, chunk, 0).unwrap();
                assert_eq!(m.registers.writes, 0);
            }
            SpmiSlave::write(&mut m, SELECTOR, &[9], 0).unwrap();
            assert_eq!(m.registers.bytes, body);
            assert_eq!(m.registers.writes, 1);
            assert_eq!(m.registers.selects, 1);
            assert!(m.staged.is_empty());
            assert_eq!(read(&mut m, SELECTOR, 1), [9]);
        }
    }

    #[test]
    fn refused_selectors_bodies_extents_and_rtpc_preserve_all_accepted_ownership() {
        let mut m = mailbox(4);
        assert!(SpmiSlave::write(&mut m, SELECTOR, &[0x7f], 0).is_err());
        assert_eq!(m.registers.selects, 0);
        assert_eq!(m.selected, None);
        SpmiSlave::write(&mut m, SELECTOR, &[9], 0).unwrap();
        assert!(SpmiSlave::write(&mut m, WRITE_DATA + 1, &[1], 0).is_err());
        SpmiSlave::write(&mut m, WRITE_DATA, &[0xff], 0).unwrap();
        let mut unchanged = [0xaa];
        for selector in [&[0x18][..], &[0x89][..], &[9, 9][..]] {
            assert!(SpmiSlave::write(&mut m, SELECTOR, selector, 0).is_err());
        }
        assert!(SpmiSlave::write(&mut m, SELECTOR, &[9], 0).is_err());
        assert!(SpmiSlave::read(&mut m, LENGTH, &mut unchanged, 0).is_err());
        assert!(SpmiSlave::command(&mut m, Command::Sleep, 0).is_err());
        assert_eq!(m.registers.writes, 0);
        assert_eq!(m.registers.bytes, [0, 1, 2, 3]);
        assert_eq!(m.staged, [0xff]);
        assert_eq!(unchanged, [0xaa]);
        assert_eq!(read(&mut m, SELECTOR, 1), [9]);
        let mut m = mailbox(4);
        for command in [
            Command::Sleep,
            Command::Wakeup,
            Command::Reset,
            Command::Shutdown,
        ] {
            assert!(SpmiSlave::command(&mut m, command, 0).is_err());
        }
        assert_eq!(SpmiSlave::interrupt_level_at(&m, 0), None);
        assert_eq!(SpmiSlave::interrupt_level_at(&m, 2), None);
        assert!(SpmiSlave::interrupt_armed(&m));
        SpmiSlave::write(&mut m, SELECTOR, &[0x18], 0).unwrap();
        assert!(SpmiSlave::read(&mut m, LENGTH, &mut unchanged, 0).is_err());
        assert_eq!(m.registers.reads, 0); // failed backend preparation rolled back
    }
}
