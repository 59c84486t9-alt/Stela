//! Original fixed TA parameter stores, after the common context prefix and
//! before resource acquisition. Firmware G13G 0x1148c..0x117b8, G13X
//! 0x11dc0..0x12188 and G14G 0x14364..0x14690 interleave each parameter
//! read with its native store. Completion here is only this configuration
//! phase; it grants no TVB allocation, native start or command completion.

use super::{
    Frame, Submission,
    resources::{Lease, Policy},
    scene,
};
use crate::platform::apple::agx::ring::Shared;
use alloc::vec::Vec;

const TILING: [u32; 13] = [
    0x101b0, 0x10130, 0x10120, 0x10128, 0x101b8, 0x1c068, 0x1c070, 0x1c080, 0x1c0a8, 0x10170,
    0x10168, 0x11f70, 0x16830,
];
const PARAMETERS: [u32; 24] = [
    0x10140, 0x14820, 0x10178, 0x1c0a0, 0x10100, 0x1c050, 0x1c060, 0x10148, 0x10138, 0x10108,
    0x10110, 0x10118, 0x16958, 0x16950, 0x16880, 0x10150, 0x1c198, 0x1c1a0, 0x1c1a8, 0x1c1b0,
    0x1c1b8, 0x10060, 0x16930, 0x12098,
];
const OFFSETS_G13: [u16; 24] = [
    0, 8, 0x10, 0x20, 0x28, 0x30, 0x38, 0x48, 0x50, 0x58, 0x70, 0x78, 0x80, 0x88, 0x90, 0xb0, 0xb8,
    0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0x110, 0x118,
];
const OFFSETS_G14: [u16; 24] = [
    0, 8, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80,
    0x88, 0x90, 0x98, 0xa0, 0xa8, 0xc8, 0xd0,
];
const G13X_EXTRA: [(u16, u32); 9] = [
    (0x18, 0x10228),
    (0x40, 0x1c0c8),
    (0x60, 0x10160),
    (0x98, 0x16948),
    (0xa0, 0x16888),
    (0xa8, 0x16890),
    (0xe8, 0x10250),
    (0xf0, 0x169a8),
    (0x68, 0x168e0),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Word {
    offset: u32,
    width: u32,
}
impl Word {
    pub(crate) const fn new(offset: u32, width: u32) -> Self {
        Self { offset, width }
    }
    pub(crate) fn range(self) -> (u32, u32) {
        (self.offset, self.width)
    }
}
#[derive(Debug, Clone, Copy)]
enum Source {
    Tiling(u16),
    Parameter(u16),
    Setup,
}
#[derive(Debug, Clone, Copy)]
struct Store {
    word: Word,
    source: Source,
}
fn stores(policy: Policy) -> Vec<Store> {
    let mut result = Vec::new();
    for (index, &offset) in TILING.iter().enumerate() {
        result.push(Store {
            word: Word { offset, width: 4 },
            source: Source::Tiling(index as u16 * 4),
        });
    }
    let offsets = if policy == Policy::G14G {
        OFFSETS_G14
    } else {
        OFFSETS_G13
    };
    for (&offset, source) in PARAMETERS.iter().zip(offsets) {
        result.push(Store {
            word: Word { offset, width: 8 },
            source: Source::Parameter(source),
        });
    }
    let extra: &[(u16, u32)] = match policy {
        Policy::G13X => &G13X_EXTRA,
        Policy::G13G => &[(0xf8, 0x10240)],
        Policy::G14G => &[(0xb0, 0x10240)],
    };
    for &(source, offset) in extra {
        result.push(Store {
            word: Word { offset, width: 8 },
            source: Source::Parameter(source),
        });
    }
    result.push(Store {
        word: Word {
            offset: 0x11000,
            width: 8,
        },
        source: Source::Setup,
    });
    let tail = if policy == Policy::G14G { 0xb8 } else { 0x100 };
    for (index, offset) in [0x11800, 0x11808].into_iter().enumerate() {
        result.push(Store {
            word: Word { offset, width: 8 },
            source: Source::Parameter(tail + index as u16 * 8),
        });
    }
    result
}

pub(crate) fn words(policy: Policy) -> Vec<Word> {
    stores(policy).into_iter().map(|store| store.word).collect()
}

/// The actual SGX adapter binds one accepted render submission/lease and commits each native
/// store atomically on success. An error commits no part of that operation.
pub trait Access {
    fn policy(&self) -> Policy;
    fn memory(&mut self) -> &mut dyn Shared;
    fn begin(
        &mut self,
        submission: &Submission,
        lease: Lease,
        frame: &Frame,
    ) -> Result<(), &'static str>;
    fn write_native(&mut self, word: Word, value: u64) -> Result<(), &'static str>;
}

#[derive(Debug)]
pub struct Parameters {
    submission: Submission,
    lease: Lease,
    policy: Policy,
    frame: Frame,
    tiling: u64,
    parameters: u64,
    stores: Vec<Store>,
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
        if submission.command.kind != crate::platform::apple::agx::channel::Kind::Ta {
            return Err("GFX TA parameters require an accepted TA command");
        }
        scene::Key::read(submission, frame)?;
        if lease.pipe != 0 || lease.slot >= 6 {
            return Err("GFX TA parameter phase requires its geometry lease");
        }
        let tiling = frame.u64(4)?;
        let parameters = frame.u64(0xc)?;
        if tiling == 0 || parameters == 0 {
            return Err("GFX TA setup has no native parameter blocks");
        }
        tiling
            .checked_add(0x33)
            .ok_or("GFX TA tiling parameter block wraps")?;
        parameters
            .checked_add(if policy == Policy::G14G { 0xd7 } else { 0x11f })
            .ok_or("GFX TA native parameter block wraps")?;
        Ok(Self {
            submission: submission.clone(),
            lease,
            policy,
            frame: frame.clone(),
            tiling,
            parameters,
            stores: stores(policy),
            next: 0,
            held: None,
        })
    }
    pub(super) fn identity(&self) -> (&Submission, &Frame, Lease, Policy) {
        (&self.submission, &self.frame, self.lease, self.policy)
    }
    pub fn completed(&self) -> bool {
        self.next == self.stores.len()
    }
    pub fn advance(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        if access.policy() != self.policy {
            return Err("GFX TA native parameter family differs from its actual SGX owner");
        }
        if self.completed() {
            return Ok(());
        }
        access.begin(&self.submission, self.lease, &self.frame)?;
        while let Some(store) = self.stores.get(self.next) {
            if self.held.is_none() {
                self.held = Some(match store.source {
                    Source::Tiling(offset) => {
                        u64::from(access.memory().read_u32(self.tiling + u64::from(offset))?)
                    }
                    Source::Parameter(offset) => access
                        .memory()
                        .read_u64(self.parameters + u64::from(offset))?,
                    Source::Setup => 0x100,
                });
            }
            access.write_native(store.word, self.held.unwrap())?;
            self.next += 1;
            self.held = None;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::platform::apple::agx::{
        channel::{Command, Kind, Record, Stamp},
        ring::tests::Flat,
        work_decode::Encoding,
    };
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Read {
        pub(crate) address: u64,
        pub(crate) width: usize,
    }
    pub(crate) struct Memory {
        pub(crate) flat: Flat,
        pub(crate) policy: Policy,
        pub(crate) reads: Vec<Read>,
        pub(crate) writes: Vec<(Word, u64)>,
        pub(crate) read_fault: Option<usize>,
        pub(crate) write_fault: Option<usize>,
    }
    impl Shared for Memory {
        fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), &'static str> {
            if self.read_fault == Some(self.reads.len()) {
                self.read_fault = None;
                return Err("parameter read fault");
            }
            self.flat.read(address, bytes)?;
            self.reads.push(Read {
                address,
                width: bytes.len(),
            });
            Ok(())
        }
        fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), &'static str> {
            self.flat.write(address, bytes)
        }
        fn gpu_read(
            &mut self,
            _: usize,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("parameter phase ran GPU")
        }
        fn gpu_write(
            &mut self,
            _: usize,
            _: u64,
            _: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("parameter phase ran GPU")
        }
    }
    impl Access for Memory {
        fn policy(&self) -> Policy {
            self.policy
        }
        fn memory(&mut self) -> &mut dyn Shared {
            self
        }
        fn begin(&mut self, _: &Submission, _: Lease, _: &Frame) -> Result<(), &'static str> {
            Ok(())
        }
        fn write_native(&mut self, word: Word, value: u64) -> Result<(), &'static str> {
            if self.write_fault == Some(self.writes.len()) {
                self.write_fault = None;
                return Err("native write fault");
            }
            self.writes.push((word, value));
            Ok(())
        }
    }
    pub(crate) fn fixture(policy: Policy) -> (Memory, Submission, Frame) {
        let submission = Submission {
            command: Command {
                va: 0x2000,
                kind: Kind::Ta,
            },
            encoding: Encoding::Fixed,
            counter: 2,
            context: 5,
            stamp: Stamp {
                driver: 0x200,
                firmware: 0x204,
                value: 0x100,
                index: 0,
            },
            stream: 0x3000,
            stream_bytes: 0x400,
        };
        let mut flat = Flat::new(0x1000, 0x8000);
        flat.put_u32(submission.stream, 5);
        flat.put_u64(submission.stream + 4, 0x4000);
        flat.put_u64(submission.stream + 0xc, 0x5000);
        flat.put_u64(submission.stream + 0x1c, 0x7000);
        flat.put_u32(submission.stream + 0x3c, submission.context);
        for i in 0..13 {
            flat.put_u32(0x4000 + i * 4, 0x100 + i as u32);
        }
        for i in 0..36 {
            flat.put_u64(0x5000 + i * 8, 0xdead0000 + i);
        }
        let frame = submission.cursor().next(&mut flat).unwrap().unwrap();
        assert_eq!(frame.record, Record::SetupTa);
        (
            Memory {
                flat,
                policy,
                reads: Vec::new(),
                writes: Vec::new(),
                read_fault: None,
                write_fault: None,
            },
            submission,
            frame,
        )
    }
    const LEASE: Lease = Lease { pipe: 0, slot: 1 };
    #[test]
    fn all_source_read_and_native_store_fault_boundaries_settle_without_replaying_a_prefix() {
        for policy in [Policy::G13G, Policy::G13X, Policy::G14G] {
            let (mut baseline, input, frame) = fixture(policy);
            let mut phase = Parameters::new(&input, &frame, LEASE, policy).unwrap();
            phase.advance(&mut baseline).unwrap();
            assert_eq!(
                baseline.writes.len(),
                if policy == Policy::G13X { 49 } else { 41 }
            );
            let get = |offset| {
                baseline
                    .writes
                    .iter()
                    .find(|(word, _)| word.offset == offset)
                    .unwrap()
                    .1
            };
            assert_eq!(
                get(0x1c0a0),
                if policy == Policy::G14G {
                    0xdead0003
                } else {
                    0xdead0004
                }
            );
            assert_eq!(get(0x11000), 0x100);
            if policy == Policy::G13X {
                assert_eq!(get(0x168e0), 0xdead000d);
            }
            for read in 0..baseline.reads.len() {
                let (mut memory, input, frame) = fixture(policy);
                let mut phase = Parameters::new(&input, &frame, LEASE, policy).unwrap();
                memory.read_fault = Some(read);
                assert!(phase.advance(&mut memory).is_err());
                assert_eq!(
                    memory.writes.len(),
                    read + usize::from(read >= baseline.writes.len() - 3)
                );
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
                // A pending store retains its already-read value, including
                // when the source RAM changes before native PIO recovers.
                if write != baseline.writes.len() - 3 {
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
    fn malformed_or_foreign_parameter_ownership_refuses_before_effects() {
        let (mut memory, input, frame) = fixture(Policy::G13X);
        assert!(
            Parameters::new(&input, &frame, Lease { pipe: 1, ..LEASE }, memory.policy).is_err()
        );
        let mut phase = Parameters::new(&input, &frame, LEASE, memory.policy).unwrap();
        memory.policy = Policy::G14G;
        assert!(phase.advance(&mut memory).is_err());
        assert!(memory.reads.is_empty() && memory.writes.is_empty());
        for offset in [4, 0xc] {
            let mut frame = frame.clone();
            frame.data[offset..offset + 8].copy_from_slice(&(u64::MAX - 2).to_le_bytes());
            assert!(Parameters::new(&input, &frame, LEASE, Policy::G13X).is_err());
        }
    }
}
