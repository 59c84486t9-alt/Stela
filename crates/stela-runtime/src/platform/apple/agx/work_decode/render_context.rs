//! Original fixed TA/3D common-context phase, after the preceding busy/trace
//! predicates and before native parameters. Source reads and every private
//! or physical native store retain their individual committed boundaries.

use super::{
    Frame, Submission,
    resources::{Lease, Policy},
    scene,
    ta::Word,
};
use crate::platform::apple::agx::{channel::Kind, ring::Shared};

mod program;
pub use program::Program;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum G13XVariant {
    A000,
    B000,
    C000,
}

pub use super::ownership::Identity;

pub trait Access {
    fn program(&self) -> Program;
    fn memory(&mut self) -> &mut dyn Shared;
    fn begin(
        &mut self,
        submission: &Submission,
        frame: &Frame,
        lease: Lease,
        identity: &Identity,
        committed: u8,
    ) -> Result<(), &'static str>;
    fn read_epoch(&mut self, pipe: u8) -> Result<u8, &'static str>;
    fn write_epoch(&mut self, pipe: u8, value: u8) -> Result<(), &'static str>;
    fn read_mask(&mut self) -> Result<u64, &'static str>;
    fn read_mirror(&mut self) -> Result<u64, &'static str>;
    fn write_native(&mut self, word: Word, value: u64) -> Result<(), &'static str>;
    fn write_slot_status(&mut self, lease: Lease, value: u32) -> Result<(), &'static str>;
}

/// Exact UBFIZ/LSRV/LSLV/STRB behavior, including low32 shift masking. This
/// is a private image byte, not a default for a physical hardware register.
pub(crate) fn increment_epoch(old: u8, index: u32) -> u8 {
    let shift = (index & 0xff) << 1;
    let old = u32::from(old);
    let next = (old.wrapping_shr(shift).wrapping_add(1)) & 3;
    ((old & !3u32.wrapping_shl(shift)) | next.wrapping_shl(shift)) as u8
}

pub(crate) fn native_words(policy: Policy, pipe: u8) -> alloc::vec::Vec<Word> {
    let mut words = alloc::vec![Word::new(if pipe == 0 { 0x10208 } else { 0x10210 }, 4)];
    if policy == Policy::G13X {
        words.push(Word::new(0x17000, 8));
    }
    words.push(Word::new(0x17610, 8));
    if policy == Policy::G13X {
        words.push(Word::new(0x7610, 8));
    }
    words
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Index,
    EpochRead,
    EpochStore,
    Context,
    MaskRead,
    Native(usize),
    Slot,
    Done,
}

#[derive(Debug)]
pub struct Context {
    submission: Submission,
    frame: Frame,
    lease: Lease,
    program: Program,
    identity: Identity,
    epoch_object: u64,
    index: u32,
    epoch: u8,
    context: u32,
    mask: u64,
    mirror: Option<u64>,
    status: u32,
    stage: Stage,
    committed: u8,
}
impl Context {
    pub fn new(
        submission: &Submission,
        frame: &Frame,
        lease: Lease,
        program: Program,
    ) -> Result<Self, &'static str> {
        let policy = program.policy();
        scene::Key::read(submission, frame)?;
        let (pipe, object, flag, selector, status) = match submission.command.kind {
            Kind::Ta => (0, 0x2c, 0x40, 0x44, 0x48),
            Kind::ThreeD => (1, 0x44, 0x58, 0x5c, 0x60),
            _ => return Err("GFX render context requires accepted TA or 3D work"),
        };
        if lease.pipe != pipe || lease.slot >= 6 {
            return Err("GFX render context differs from its source pipeline lease");
        }
        let epoch_object = frame.u64(object)?;
        if epoch_object == 0 {
            return Err("GFX render context has no epoch object");
        }
        epoch_object
            .checked_add(0x33)
            .ok_or("GFX render epoch object wraps")?;
        let low = if policy == Policy::G13X {
            u32::from(lease.slot) | (u32::from(pipe) << 4)
        } else {
            frame.u32(selector)? & 0x3f
        };
        let context = low | submission.context << 8;
        let status = frame.u32(status)?;
        let _ = frame.u32(flag)?; // part of the immutable source frame
        Ok(Self {
            submission: submission.clone(),
            frame: frame.clone(),
            lease,
            program,
            identity: Identity::new(),
            epoch_object,
            index: 0,
            epoch: 0,
            context,
            mask: 0,
            mirror: None,
            status,
            stage: Stage::Index,
            committed: 0,
        })
    }
    pub fn completed(&self) -> bool {
        self.stage == Stage::Done
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if access.program() != self.program {
            return Err("GFX render context program differs from its native owner");
        }
        if self.completed() {
            return Ok(());
        }
        if !self.identity.live() {
            return Err("GFX render context was canceled by its native owner");
        }
        access.begin(
            &self.submission,
            &self.frame,
            self.lease,
            &self.identity,
            self.committed,
        )?;
        let words = native_words(self.program.policy(), self.lease.pipe);
        loop {
            match self.stage {
                Stage::Index => {
                    self.index = access.memory().read_u32(self.epoch_object + 0x30)?;
                    self.stage = Stage::EpochRead;
                }
                Stage::EpochRead => {
                    self.epoch = increment_epoch(access.read_epoch(self.lease.pipe)?, self.index);
                    self.stage = Stage::EpochStore;
                }
                Stage::EpochStore => {
                    access.write_epoch(self.lease.pipe, self.epoch)?;
                    self.committed += 1;
                    self.stage = Stage::Context;
                }
                Stage::Context => {
                    access.write_native(words[0], u64::from(self.context))?;
                    self.committed += 1;
                    self.stage = Stage::MaskRead;
                }
                Stage::MaskRead => {
                    let old = access.read_mask()?;
                    let flag = self
                        .frame
                        .u32(if self.lease.pipe == 0 { 0x40 } else { 0x58 })?;
                    let bit = 1u64 << self.submission.context;
                    self.mask = if flag == 0 { old & !bit } else { old | bit };
                    self.stage = Stage::Native(1);
                }
                Stage::Native(index) => {
                    let word = words[index];
                    let value = if word == Word::new(0x7610, 8) && self.program.merge_mirror() {
                        let old = match self.mirror {
                            Some(old) => old,
                            None => {
                                let old = access.read_mirror()?;
                                self.mirror = Some(old);
                                old
                            }
                        };
                        self.mask | old | (1u64 << self.submission.context)
                    } else if word == Word::new(0x17000, 8) {
                        0x100
                    } else {
                        self.mask
                    };
                    access.write_native(word, value)?;
                    self.committed += 1;
                    self.stage = if index + 1 == words.len() {
                        Stage::Slot
                    } else {
                        Stage::Native(index + 1)
                    };
                }
                Stage::Slot => {
                    access.write_slot_status(self.lease, self.status)?;
                    self.committed += 1;
                    self.stage = Stage::Done;
                }
                Stage::Done => return Ok(()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_epoch_uses_original_word_shift_and_byte_store_semantics() {
        for (index, expected) in [
            (0, 0x3a),
            (1, 0x3d),
            (2, 0x09),
            (3, 0x79),
            (4, 0x39),
            (15, 0x39),
            (16, 0x3a),
            (255, 0x39),
            (256, 0x3a),
            (u32::MAX, 0x39),
        ] {
            assert_eq!(increment_epoch(0x39, index), expected);
        }
        for (index, expected) in [
            (0, 0xfc),
            (1, 0xf3),
            (2, 0xcf),
            (3, 0x3f),
            (4, 0xff),
            (16, 0xfc),
        ] {
            assert_eq!(increment_epoch(0xff, index), expected);
        }
    }
}
