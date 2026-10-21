//! Original fixed 3D native parameter programming, after the common
//! context prefix. G13G 0x11d48..0x1220c, G13X 0x12724..0x12bd0 and
//! G14G 0x14f80..0x154bc first publish the scene's masked pointer, then
//! interleave each source block read/native store. This configuration phase
//! grants no TVB/resource acquisition, engine trigger or work completion.

use super::{
    Frame, Submission,
    resources::{Lease, Policy},
    scene,
    ta::{Access, Word},
};
use crate::platform::apple::agx::channel::Kind;
use alloc::vec::Vec;

// (native offset, original source-block offset, source block: 0=u32,
// 1=u64, 2=literal setup-control). Tables remain independent by family.
const G13G: [(u32, u16, u8); 60] = [
    (0x15378, 0x0, 0),
    (0x15380, 0x4, 0),
    (0x15130, 0x10, 0),
    (0x15138, 0x14, 0),
    (0x100b0, 0x20, 0),
    (0x10050, 0x2c, 0),
    (0x15300, 0x30, 0),
    (0x15308, 0x34, 0),
    (0x15358, 0x38, 0),
    (0x168f0, 0x3c, 0),
    (0x16450, 0x24, 0),
    (0x100d8, 0x28, 0),
    (0x11f78, 0x40, 0),
    (0x16838, 0x44, 0),
    (0x10008, 0x0, 1),
    (0x15368, 0x8, 1),
    (0x15370, 0x10, 1),
    (0x10018, 0x18, 1),
    (0x15108, 0x20, 1),
    (0x15100, 0x28, 1),
    (0x15020, 0x30, 1),
    (0x15210, 0x38, 1),
    (0x15048, 0x40, 1),
    (0x15320, 0x48, 1),
    (0x15310, 0x50, 1),
    (0x15318, 0x58, 1),
    (0x15328, 0x60, 1),
    (0x15330, 0x68, 1),
    (0x15338, 0x70, 1),
    (0x15340, 0x78, 1),
    (0x15400, 0x80, 1),
    (0x15420, 0x88, 1),
    (0x15408, 0x90, 1),
    (0x15428, 0x98, 1),
    (0x153c0, 0xa0, 1),
    (0x15410, 0xa8, 1),
    (0x153c8, 0xb0, 1),
    (0x15430, 0xb8, 1),
    (0x153d0, 0xc0, 1),
    (0x15418, 0xc8, 1),
    (0x153d8, 0xd0, 1),
    (0x15438, 0xd8, 1),
    (0x16428, 0xe0, 1),
    (0x16060, 0xe8, 1),
    (0x16430, 0xf0, 1),
    (0x16098, 0xf8, 1),
    (0x10038, 0x100, 1),
    (0x100c0, 0x108, 1),
    (0x16900, 0x110, 1),
    (0x168d0, 0x118, 1),
    (0x100a0, 0x120, 1),
    (0x15068, 0x128, 1),
    (0x15070, 0x130, 1),
    (0x16058, 0x138, 1),
    (0x10068, 0x140, 1),
    (0x100b8, 0x148, 1),
    (0x11000, 0x100, 2),
    (0x11820, 0x150, 1),
    (0x11828, 0x158, 1),
    (0x120a0, 0x160, 1),
];
const G13X: [(u32, u16, u8); 59] = [
    (0x15378, 0x0, 0),
    (0x15380, 0x4, 0),
    (0x15130, 0x10, 0),
    (0x15138, 0x14, 0),
    (0x100b0, 0x20, 0),
    (0x10050, 0x2c, 0),
    (0x15300, 0x30, 0),
    (0x15308, 0x34, 0),
    (0x15358, 0x38, 0),
    (0x168f0, 0x3c, 0),
    (0x16450, 0x24, 0),
    (0x100d8, 0x28, 0),
    (0x11f78, 0x40, 0),
    (0x16838, 0x44, 0),
    (0x10008, 0x0, 1),
    (0x15368, 0x8, 1),
    (0x15370, 0x10, 1),
    (0x10018, 0x18, 1),
    (0x15108, 0x20, 1),
    (0x15100, 0x28, 1),
    (0x15020, 0x30, 1),
    (0x15210, 0x38, 1),
    (0x15048, 0x40, 1),
    (0x15320, 0x48, 1),
    (0x15310, 0x50, 1),
    (0x15318, 0x58, 1),
    (0x15328, 0x60, 1),
    (0x15330, 0x68, 1),
    (0x15338, 0x70, 1),
    (0x15340, 0x78, 1),
    (0x15400, 0x80, 1),
    (0x15420, 0x88, 1),
    (0x15408, 0x90, 1),
    (0x15428, 0x98, 1),
    (0x153c0, 0xa0, 1),
    (0x15410, 0xa8, 1),
    (0x153c8, 0xb0, 1),
    (0x15430, 0xb8, 1),
    (0x153d0, 0xc0, 1),
    (0x15418, 0xc8, 1),
    (0x153d8, 0xd0, 1),
    (0x15438, 0xd8, 1),
    (0x16428, 0xe0, 1),
    (0x16060, 0xe8, 1),
    (0x16430, 0xf0, 1),
    (0x16098, 0xf8, 1),
    (0x10038, 0x100, 1),
    (0x100c0, 0x108, 1),
    (0x16900, 0x110, 1),
    (0x168d0, 0x118, 1),
    (0x100a0, 0x120, 1),
    (0x15068, 0x128, 1),
    (0x15070, 0x130, 1),
    (0x16058, 0x138, 1),
    (0x10068, 0x140, 1),
    (0x11000, 0x100, 2),
    (0x11820, 0x150, 1),
    (0x11828, 0x158, 1),
    (0x120a0, 0x160, 1),
];
const G14G: [(u32, u16, u8); 66] = [
    (0x15378, 0x0, 0),
    (0x15380, 0x4, 0),
    (0x15130, 0x10, 0),
    (0x15138, 0x14, 0),
    (0x100b0, 0x20, 0),
    (0x10050, 0x2c, 0),
    (0x15300, 0x30, 0),
    (0x15308, 0x34, 0),
    (0x15358, 0x38, 0),
    (0x168f0, 0x3c, 0),
    (0x16450, 0x24, 0),
    (0x100d8, 0x28, 0),
    (0x11f78, 0x40, 0),
    (0x16838, 0x44, 0),
    (0x10008, 0x0, 1),
    (0x15368, 0x8, 1),
    (0x15370, 0x10, 1),
    (0x10018, 0x18, 1),
    (0x15108, 0x20, 1),
    (0x15100, 0x28, 1),
    (0x15020, 0x30, 1),
    (0x15210, 0x38, 1),
    (0x15048, 0x40, 1),
    (0x15320, 0x48, 1),
    (0x15310, 0x50, 1),
    (0x15318, 0x58, 1),
    (0x15348, 0x60, 1),
    (0x15350, 0x68, 1),
    (0x15328, 0x70, 1),
    (0x15330, 0x78, 1),
    (0x15338, 0x80, 1),
    (0x15340, 0x88, 1),
    (0x15230, 0x90, 1),
    (0x15220, 0x98, 1),
    (0x15238, 0xa0, 1),
    (0x15228, 0xa8, 1),
    (0x15400, 0xb0, 1),
    (0x15420, 0xb8, 1),
    (0x15408, 0xc0, 1),
    (0x15428, 0xc8, 1),
    (0x153c0, 0xd0, 1),
    (0x15410, 0xd8, 1),
    (0x153c8, 0xe0, 1),
    (0x15430, 0xe8, 1),
    (0x153d0, 0xf0, 1),
    (0x15418, 0xf8, 1),
    (0x153d8, 0x100, 1),
    (0x15438, 0x108, 1),
    (0x16428, 0x110, 1),
    (0x16060, 0x118, 1),
    (0x16430, 0x120, 1),
    (0x16098, 0x128, 1),
    (0x10038, 0x130, 1),
    (0x100c0, 0x138, 1),
    (0x16900, 0x140, 1),
    (0x168d0, 0x148, 1),
    (0x100a0, 0x150, 1),
    (0x15068, 0x158, 1),
    (0x15070, 0x160, 1),
    (0x16058, 0x168, 1),
    (0x10068, 0x170, 1),
    (0x100b8, 0x178, 1),
    (0x11000, 0x100, 2),
    (0x11820, 0x180, 1),
    (0x11828, 0x188, 1),
    (0x120a0, 0x190, 1),
];

fn table(policy: Policy) -> &'static [(u32, u16, u8)] {
    match policy {
        Policy::G13G => &G13G,
        Policy::G13X => &G13X,
        Policy::G14G => &G14G,
    }
}
pub(crate) fn words(policy: Policy) -> Vec<Word> {
    let mut result = alloc::vec![Word::new(0x168c0, 8)];
    result.extend(
        table(policy)
            .iter()
            .map(|&(offset, _, source)| Word::new(offset, if source == 0 { 4 } else { 8 })),
    );
    result
}
#[derive(Debug)]
pub struct Parameters {
    submission: Submission,
    lease: Lease,
    policy: Policy,
    frame: Frame,
    scene: u64,
    first: u64,
    second: u64,
    next: usize,
    held: Option<u64>,
}
impl Parameters {
    pub fn new(
        submission: &Submission,
        frame: &Frame,
        lease: Lease,
        policy: Policy,
    ) -> Result<Self, &'static str> {
        if submission.command.kind != Kind::ThreeD {
            return Err("GFX 3D parameters require an accepted 3D command");
        }
        scene::Key::read(submission, frame)?;
        if lease.pipe != 1 || lease.slot >= 6 {
            return Err("GFX 3D native parameter phase requires its fragment lease");
        }
        let scene = frame.u64(0x14)?;
        let first = frame.u64(4)?;
        let second = frame.u64(0xc)?;
        if first == 0 || second == 0 {
            return Err("GFX 3D setup has no native parameter blocks");
        }
        first
            .checked_add(0x47)
            .ok_or("GFX 3D first parameter block wraps")?;
        second
            .checked_add(if policy == Policy::G14G { 0x197 } else { 0x167 })
            .ok_or("GFX 3D second parameter block wraps")?;
        Ok(Self {
            submission: submission.clone(),
            lease,
            policy,
            frame: frame.clone(),
            scene,
            first,
            second,
            next: 0,
            held: None,
        })
    }
    pub(super) fn identity(&self) -> (&Submission, &Frame, Lease, Policy) {
        (&self.submission, &self.frame, self.lease, self.policy)
    }
    pub fn completed(&self) -> bool {
        self.next == table(self.policy).len() + 1
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if access.policy() != self.policy {
            return Err("GFX 3D native parameter family differs from its actual SGX owner");
        }
        if self.completed() {
            return Ok(());
        }
        access.begin(&self.submission, self.lease, &self.frame)?;
        let words = words(self.policy);
        while let Some(&word) = words.get(self.next) {
            if self.held.is_none() {
                self.held = Some(if self.next == 0 {
                    access.memory().read_u64(self.scene + 0x18)? & !0xf
                } else {
                    let (_, offset, source) = table(self.policy)[self.next - 1];
                    match source {
                        0 => u64::from(access.memory().read_u32(self.first + u64::from(offset))?),
                        1 => access.memory().read_u64(self.second + u64::from(offset))?,
                        2 => 0x100,
                        _ => unreachable!(),
                    }
                });
            }
            access.write_native(word, self.held.unwrap())?;
            self.held = None;
            self.next += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::{
        channel::Record,
        work_decode::ta::tests::{Memory, fixture as ta_fixture},
    };
    fn fixture(policy: Policy) -> (Memory, Submission, Frame) {
        let (mut memory, mut input, mut frame) = ta_fixture(policy);
        input.command.kind = Kind::ThreeD;
        frame.record = Record::Setup3d;
        frame.data.resize(frame.record.bytes() as usize, 0);
        frame.data[0x14..0x1c].copy_from_slice(&0x7000u64.to_le_bytes());
        frame.data[0x54..0x58].copy_from_slice(&input.context.to_le_bytes());
        for index in 0..18 {
            memory
                .flat
                .put_u32(0x4000 + index * 4, 0x100 + index as u32);
        }
        for index in 0..51 {
            memory.flat.put_u64(0x5000 + index * 8, 0xdead0000 + index);
        }
        memory.flat.put_u64(0x7018, 0x20ff);
        (memory, input, frame)
    }
    const LEASE: Lease = Lease { pipe: 1, slot: 2 };
    #[test]
    fn complete_original_3d_store_sequences_retain_each_read_and_native_fault() {
        for policy in [Policy::G13G, Policy::G13X, Policy::G14G] {
            let (mut baseline, input, frame) = fixture(policy);
            let mut phase = Parameters::new(&input, &frame, LEASE, policy).unwrap();
            phase.advance(&mut baseline).unwrap();
            assert_eq!(
                baseline.writes.len(),
                match policy {
                    Policy::G13G => 61,
                    Policy::G13X => 60,
                    Policy::G14G => 67,
                }
            );
            let get = |offset| {
                baseline
                    .writes
                    .iter()
                    .find(|(word, _)| word.range().0 == offset)
                    .unwrap()
                    .1
            };
            assert_eq!(get(0x168c0), 0x20f0);
            assert_eq!(
                get(0x15328),
                if policy == Policy::G14G {
                    0xdead000e
                } else {
                    0xdead000c
                }
            );
            assert_eq!(
                get(0x120a0),
                if policy == Policy::G14G {
                    0xdead0032
                } else {
                    0xdead002c
                }
            );
            assert_eq!(get(0x11000), 0x100);
            assert_eq!(
                baseline
                    .writes
                    .iter()
                    .any(|(word, _)| word.range().0 == 0x100b8),
                policy != Policy::G13X
            );
            let literal = baseline.writes.len() - 4;
            for read in 0..baseline.reads.len() {
                let (mut memory, input, frame) = fixture(policy);
                let mut phase = Parameters::new(&input, &frame, LEASE, policy).unwrap();
                memory.read_fault = Some(read);
                assert!(phase.advance(&mut memory).is_err());
                assert_eq!(memory.writes.len(), read + usize::from(read >= literal));
                phase.advance(&mut memory).unwrap();
                assert_eq!(memory.writes, baseline.writes);
                assert_eq!(memory.reads, baseline.reads);
            }
            for write in 0..baseline.writes.len() {
                let (mut memory, input, frame) = fixture(policy);
                let mut phase = Parameters::new(&input, &frame, LEASE, policy).unwrap();
                memory.write_fault = Some(write);
                assert!(phase.advance(&mut memory).is_err());
                assert_eq!(memory.writes.len(), write);
                if write != literal {
                    let read = memory.reads.last().unwrap();
                    memory
                        .flat
                        .put(read.address, &alloc::vec![0xff; read.width]);
                }
                phase.advance(&mut memory).unwrap();
                assert!(phase.completed());
                assert_eq!(memory.writes, baseline.writes);
                assert_eq!(memory.reads, baseline.reads);
            }
        }
    }
    #[test]
    fn wrong_context_pipe_or_wrapping_blocks_refuse_before_effects() {
        let (memory, input, frame) = fixture(Policy::G13X);
        assert!(
            Parameters::new(&input, &frame, Lease { pipe: 0, ..LEASE }, memory.policy).is_err()
        );
        let mut foreign = input.clone();
        foreign.context += 1;
        assert!(Parameters::new(&foreign, &frame, LEASE, memory.policy).is_err());
        for offset in [4, 0xc] {
            let mut frame = frame.clone();
            frame.data[offset..offset + 8].copy_from_slice(&(u64::MAX - 2).to_le_bytes());
            assert!(Parameters::new(&input, &frame, LEASE, memory.policy).is_err());
        }
    }
}
