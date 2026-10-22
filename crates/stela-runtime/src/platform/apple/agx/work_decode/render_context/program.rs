//! Source-program selection, separate from the GPU family. The selected
//! container contains materially different a000 and b000/c000 consumers.

use super::{G13XVariant, Policy};
use crate::platform::apple::agx::{
    firmware_image::{Selected, Source},
    initdata::Root,
    ring::Shared,
};

/// Captured at the original initdata-copy boundary, before render work.
/// This is neither a chip-to-variant guess nor native register reset state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    policy: Policy,
    variant: Option<G13XVariant>,
    mode: Option<(u64, u64, u32)>,
    source: Option<Source>,
    startup_tail: Option<(u64, u64, u32)>,
}
impl Program {
    pub fn fixed(policy: Policy, tag: [u8; 4]) -> Result<Self, &'static str> {
        if policy == Policy::G13X {
            return Err("GFX render context requires the selected G13X firmware variant");
        }
        if !matches!(
            (policy, &tag),
            (Policy::G13G, b"b100") | (Policy::G14G, b"b000")
        ) {
            return Err(
                "GFX render context program is not qualified for this selected firmware tag",
            );
        }
        Ok(Self {
            policy,
            variant: None,
            mode: None,
            source: None,
            startup_tail: None,
        })
    }
    /// A native-prefix primitive: capture only a000's consumed mirror mode.
    /// All G13X members copy two startup words; use `selected_g13x` for that
    /// complete selected-input phase. This primitive has no source receipt.
    pub fn g13x(
        variant: G13XVariant,
        root: &Root,
        memory: &mut dyn Shared,
    ) -> Result<Self, &'static str> {
        let mode = if variant == G13XVariant::A000 {
            if root.rings == 0 {
                return Err("GFX render context has no hardware-configuration directory");
            }
            root.rings
                .checked_add(7)
                .ok_or("GFX render directory pointer wraps")?;
            let hardware = memory.read_u64(root.rings)?;
            if hardware == 0 {
                return Err("GFX render context has no hardware-configuration object");
            }
            let at = hardware
                .checked_add(0x10d4)
                .ok_or("GFX render mode address wraps")?;
            at.checked_add(3).ok_or("GFX render mode extent wraps")?;
            Some((root.rings, hardware, memory.read_u32(at)?))
        } else {
            None
        };
        Ok(Self {
            policy: Policy::G13X,
            variant: Some(variant),
            mode,
            source: None,
            startup_tail: None,
        })
    }
    /// Retain the actual selected bytes/tag/revision before the startup-copy
    /// reads. All three members copy +10d4, reload the directory, then copy
    /// +10d8. Each accepted pointer/load is retained across later DMA faults.
    pub fn selected_g13x(
        selected: &Selected<'_>,
        root: &Root,
    ) -> Result<super::Capture, &'static str> {
        let source = selected.source();
        let variant = match &source.tag {
            b"a000" => G13XVariant::A000,
            b"b000" => G13XVariant::B000,
            b"c000" => G13XVariant::C000,
            _ => {
                return Err(
                    "GFX selected G13X firmware program is not qualified for this FTAB tag",
                );
            }
        };
        if root.rings == 0 {
            return Err("GFX render context has no hardware-configuration directory");
        }
        root.rings
            .checked_add(7)
            .ok_or("GFX render directory pointer wraps")?;
        Ok(Capture {
            program: Self {
                policy: Policy::G13X,
                variant: Some(variant),
                mode: None,
                source: Some(source),
                startup_tail: None,
            },
            directory: root.rings,
            hardware: None,
            tail_hardware: None,
            complete: false,
        })
    }
    /// Provenance of a selected-input capture. A family-only primitive has
    /// no such authority and cannot replace this initialized program.
    pub fn source(self) -> Option<Source> {
        self.source
    }
    pub fn startup_words(self) -> Option<[u32; 2]> {
        Some([self.mode?.2, self.startup_tail?.2])
    }
    pub fn policy(self) -> Policy {
        self.policy
    }
    pub(crate) fn require_cl_parameters(self, selected: Option<Self>) -> Result<(), &'static str> {
        if (self.source.is_some() || self.variant == Some(G13XVariant::A000))
            && selected != Some(self)
        {
            return Err("GFX CL parameters require their exact initialized firmware program");
        }
        Ok(())
    }
    pub(crate) fn merge_mirror(self) -> bool {
        self.variant == Some(G13XVariant::A000) && self.mode.is_some_and(|(_, _, mode)| mode == 3)
    }
}

/// A retained input-copy phase; it neither writes native registers nor marks
/// firmware startup ready. Qualification of the preserved source and all
/// preceding/following startup effects remains required by the caller.
#[derive(Debug)]
pub struct Capture {
    program: Program,
    directory: u64,
    hardware: Option<u64>,
    tail_hardware: Option<u64>,
    complete: bool,
}
impl Capture {
    pub fn advance(&mut self, memory: &mut dyn Shared) -> Result<Program, &'static str> {
        if self.complete {
            return Ok(self.program);
        }
        if self.program.mode.is_none() {
            if self.hardware.is_none() {
                let hardware = memory.read_u64(self.directory)?;
                // A successful load remains accepted even when its pointer
                // validation or the following mode load refuses.
                self.hardware = Some(hardware);
            }
            let hardware = self.hardware.unwrap();
            if hardware == 0 {
                return Err("GFX render context has no hardware-configuration object");
            }
            let at = hardware
                .checked_add(0x10d4)
                .ok_or("GFX render mode address wraps")?;
            at.checked_add(3).ok_or("GFX render mode extent wraps")?;
            self.program.mode = Some((self.directory, hardware, memory.read_u32(at)?));
        }
        // All three G13X programs copy a second independent startup word.
        // The original reloads the directory after storing the first word;
        // it must observe that second pointer, then retain it through faults.
        if self.tail_hardware.is_none() {
            self.tail_hardware = Some(memory.read_u64(self.directory)?);
        }
        let hardware = self.tail_hardware.unwrap();
        if hardware == 0 {
            return Err("GFX startup tail has no hardware-configuration object");
        }
        let at = hardware
            .checked_add(0x10d8)
            .ok_or("GFX startup tail address wraps")?;
        at.checked_add(3).ok_or("GFX startup tail extent wraps")?;
        self.program.startup_tail = Some((self.directory, hardware, memory.read_u32(at)?));
        self.complete = true;
        Ok(self.program)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    struct Memory {
        reads: Vec<(u64, usize)>,
        hardware: u64,
        mode: u32,
        fail: bool,
    }
    impl Shared for Memory {
        fn read(&mut self, at: u64, out: &mut [u8]) -> Result<(), &'static str> {
            self.reads.push((at, out.len()));
            match (at, out.len()) {
                (0x100, 8) => out.copy_from_slice(&self.hardware.to_le_bytes()),
                (_, 4)
                    if !self.fail
                        && (at == self.hardware.checked_add(0x10d4).unwrap_or(0)
                            || at == self.hardware.checked_add(0x10d8).unwrap_or(0)) =>
                {
                    out.copy_from_slice(&self.mode.to_le_bytes())
                }
                _ => return Err("mode capture fault"),
            }
            Ok(())
        }
        fn write(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
            panic!("capture cannot write")
        }
        fn gpu_read(
            &mut self,
            _: usize,
            _: u64,
            _: &mut [u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("capture cannot access GPU context")
        }
        fn gpu_write(
            &mut self,
            _: usize,
            _: u64,
            _: &[u8],
        ) -> Result<(), crate::platform::dma::DmaError> {
            panic!("capture cannot access GPU context")
        }
    }
    fn root(rings: u64) -> Root {
        Root {
            rings,
            page_1660: 1,
            object_358: 2,
            object_848: 3,
            object_928: 4,
            object_930: 5,
            object_368: 6,
            config: [0xff; 0x68],
        }
    }
    #[test]
    fn selected_variant_captures_only_its_original_initdata_input() {
        let mut mem = Memory {
            reads: Vec::new(),
            hardware: 0x1000,
            mode: 3,
            fail: false,
        };
        assert!(Program::fixed(Policy::G13X, *b"c000").is_err());
        assert!(Program::fixed(Policy::G13G, *b"a000").is_err());
        assert!(Program::fixed(Policy::G14G, *b"a000").is_err());
        assert!(Program::fixed(Policy::G13G, *b"b100").is_ok());
        assert!(Program::fixed(Policy::G14G, *b"b000").is_ok());
        let selected = Program::g13x(G13XVariant::A000, &root(0x100), &mut mem).unwrap();
        assert!(selected.merge_mirror());
        assert!(selected.require_cl_parameters(None).is_err());
        assert!(selected.require_cl_parameters(Some(selected)).is_ok());
        assert_eq!(mem.reads, [(0x100, 8), (0x20d4, 4)]);
        mem.mode = 0;
        assert!(selected.merge_mirror()); // immutable startup copy
        assert!(
            !Program::g13x(G13XVariant::A000, &root(0x100), &mut mem)
                .unwrap()
                .merge_mirror()
        );
        for variant in [G13XVariant::B000, G13XVariant::C000] {
            assert!(
                Program::g13x(variant, &root(0x100), &mut mem)
                    .unwrap()
                    .require_cl_parameters(None)
                    .is_ok()
            );
            let reads = mem.reads.len();
            assert!(
                !Program::g13x(variant, &root(u64::MAX), &mut mem)
                    .unwrap()
                    .merge_mirror()
            );
            assert_eq!(mem.reads.len(), reads);
        }
        mem.fail = true;
        assert!(Program::g13x(G13XVariant::A000, &root(0x100), &mut mem).is_err());
        mem.fail = false;
        mem.hardware = u64::MAX - 0x10d4;
        let reads = mem.reads.len();
        assert!(Program::g13x(G13XVariant::A000, &root(0x100), &mut mem).is_err());
        assert_eq!(mem.reads.len(), reads + 1);
        let reads = mem.reads.len();
        assert!(Program::g13x(G13XVariant::A000, &root(u64::MAX - 6), &mut mem).is_err());
        assert_eq!(mem.reads.len(), reads);
    }
    #[test]
    fn selected_payload_identity_and_accepted_pointer_survive_mode_fault_and_source_edits() {
        use crate::platform::apple::agx::firmware_image::{
            Ftab,
            tests::{identity, image},
        };
        use sha2::{Digest, Sha256};
        let bytes = image(&[*b"a000", *b"b000", *b"c000"]);
        let ftab = Ftab::read(&bytes, Sha256::digest(&bytes).into()).unwrap();
        let selected = ftab.select_t6000(&identity(0, 0)).unwrap();
        let mut capture = Program::selected_g13x(&selected, &root(0x100)).unwrap();
        let mut mem = Memory {
            reads: Vec::new(),
            hardware: 0x1000,
            mode: 3,
            fail: true,
        };
        assert!(capture.advance(&mut mem).is_err());
        assert_eq!(mem.reads, [(0x100, 8), (0x20d4, 4)]);
        mem.hardware = 0x2000;
        // The source directory changed, but the accepted pointer does not.
        // Supply only the original target for retry.
        struct Retry<'a>(&'a mut Memory);
        impl Shared for Retry<'_> {
            fn read(&mut self, at: u64, out: &mut [u8]) -> Result<(), &'static str> {
                self.0.reads.push((at, out.len()));
                match (at, out.len()) {
                    (0x20d4, 4) => out.copy_from_slice(&self.0.mode.to_le_bytes()),
                    (0x100, 8) => out.copy_from_slice(&self.0.hardware.to_le_bytes()),
                    (0x30d8, 4) => out.copy_from_slice(&0x89abcdefu32.to_le_bytes()),
                    _ => panic!("accepted first directory replayed or wrong second pointer"),
                }
                Ok(())
            }
            fn write(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
                panic!("capture wrote");
            }
            fn gpu_read(
                &mut self,
                _: usize,
                _: u64,
                _: &mut [u8],
            ) -> Result<(), crate::platform::dma::DmaError> {
                panic!("GPU read");
            }
            fn gpu_write(
                &mut self,
                _: usize,
                _: u64,
                _: &[u8],
            ) -> Result<(), crate::platform::dma::DmaError> {
                panic!("GPU write");
            }
        }
        let program = capture.advance(&mut Retry(&mut mem)).unwrap();
        assert!(program.merge_mirror());
        assert_eq!(program.source(), Some(selected.source()));
        mem.mode = 0;
        let n = mem.reads.len();
        assert_eq!(capture.advance(&mut mem).unwrap(), program);
        assert_eq!(mem.reads.len(), n);
        // Even an otherwise identical synthetic container is a distinct
        // source, and family-only primitives cannot replace the bound copy.
        let mut changed = bytes.clone();
        changed[0] = 1;
        let changed_ftab = Ftab::read(&changed, Sha256::digest(&changed).into()).unwrap();
        let selected = changed_ftab.select_t6000(&identity(0, 0)).unwrap();
        mem.hardware = 0x1000;
        mem.mode = 3;
        mem.fail = false;
        let other = Program::selected_g13x(&selected, &root(0x100))
            .unwrap()
            .advance(&mut mem)
            .unwrap();
        assert_ne!(other, program);
        let primitive = Program::g13x(G13XVariant::A000, &root(0x100), &mut mem).unwrap();
        assert_ne!(primitive, program);
        assert!(program.require_cl_parameters(Some(primitive)).is_err());
    }
    #[test]
    fn every_selected_variant_copies_both_words_and_unknown_tags_never_choose_a_similar_program() {
        use crate::platform::apple::agx::firmware_image::{
            Ftab,
            tests::{identity, image},
        };
        use sha2::{Digest, Sha256};
        let bytes = image(&[*b"a000", *b"b000", *b"c000"]);
        let ftab = Ftab::read(&bytes, Sha256::digest(&bytes).into()).unwrap();
        for raw in [0, 0x10, 0x20] {
            let selected = ftab.select_t6000(&identity(raw, 0)).unwrap();
            assert!(Program::selected_g13x(&selected, &root(u64::MAX)).is_err());
            let mut mem = Memory {
                reads: Vec::new(),
                hardware: 0x1000,
                mode: 3,
                fail: false,
            };
            let program = Program::selected_g13x(&selected, &root(0x100))
                .unwrap()
                .advance(&mut mem)
                .unwrap();
            assert_eq!(program.merge_mirror(), raw == 0);
            assert_eq!(
                mem.reads,
                [(0x100, 8), (0x20d4, 4), (0x100, 8), (0x20d8, 4)]
            );
            assert_eq!(program.source(), Some(selected.source()));
            assert_eq!(program.startup_words(), Some([3, 3]));
            assert!(program.require_cl_parameters(None).is_err());
            assert!(program.require_cl_parameters(Some(program)).is_ok());
            assert_eq!(program.startup_tail, Some((0x100, 0x1000, 3)));
        }
        let bytes = image(&[*b"z999"]);
        let ftab = Ftab::read(&bytes, Sha256::digest(&bytes).into()).unwrap();
        let selected = ftab.select_t6000(&identity(0, 0)).unwrap();
        assert!(Program::selected_g13x(&selected, &root(0x100)).is_err());
    }
    #[test]
    fn each_original_startup_load_retains_its_accepted_prefix_across_faults() {
        use crate::platform::apple::agx::firmware_image::{
            Ftab,
            tests::{identity, image},
        };
        use sha2::{Digest, Sha256};
        struct Fault {
            loads: Vec<(u64, usize)>,
            committed: usize,
            fail: Option<usize>,
        }
        impl Shared for Fault {
            fn read(&mut self, at: u64, out: &mut [u8]) -> Result<(), &'static str> {
                self.loads.push((at, out.len()));
                if self.fail == Some(self.committed) {
                    self.fail = None;
                    return Err("startup load fault");
                }
                match self.committed {
                    0 => {
                        assert_eq!(at, 0x100);
                        out.copy_from_slice(&0x1000u64.to_le_bytes());
                    }
                    1 => {
                        assert_eq!(at, 0x20d4);
                        out.copy_from_slice(&3u32.to_le_bytes());
                    }
                    2 => {
                        assert_eq!(at, 0x100);
                        out.copy_from_slice(&0x2000u64.to_le_bytes());
                    }
                    3 => {
                        assert_eq!(at, 0x30d8);
                        out.copy_from_slice(&0x12345678u32.to_le_bytes());
                    }
                    _ => panic!("committed startup input replay"),
                }
                self.committed += 1;
                Ok(())
            }
            fn write(&mut self, _: u64, _: &[u8]) -> Result<(), &'static str> {
                panic!("capture wrote");
            }
            fn gpu_read(
                &mut self,
                _: usize,
                _: u64,
                _: &mut [u8],
            ) -> Result<(), crate::platform::dma::DmaError> {
                panic!("GPU read");
            }
            fn gpu_write(
                &mut self,
                _: usize,
                _: u64,
                _: &[u8],
            ) -> Result<(), crate::platform::dma::DmaError> {
                panic!("GPU write");
            }
        }
        let bytes = image(&[*b"a000", *b"b000", *b"c000"]);
        let ftab = Ftab::read(&bytes, Sha256::digest(&bytes).into()).unwrap();
        for raw in [0, 0x10, 0x20] {
            for fail in 0..4 {
                let selected = ftab.select_t6000(&identity(raw, 0)).unwrap();
                let mut capture = Program::selected_g13x(&selected, &root(0x100)).unwrap();
                let mut mem = Fault {
                    loads: Vec::new(),
                    committed: 0,
                    fail: Some(fail),
                };
                assert!(capture.advance(&mut mem).is_err());
                assert_eq!(mem.committed, fail);
                let program = capture.advance(&mut mem).unwrap();
                assert_eq!(mem.committed, 4);
                assert_eq!(mem.loads.len(), 5);
                assert_eq!(program.mode, Some((0x100, 0x1000, 3)));
                assert_eq!(program.startup_tail, Some((0x100, 0x2000, 0x12345678)));
                assert_eq!(capture.advance(&mut mem).unwrap(), program);
                assert_eq!(mem.loads.len(), 5);
            }
        }
    }
}
