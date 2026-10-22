//! Source-program selection, separate from the GPU family. The selected
//! container contains materially different a000 and b000/c000 consumers.

use super::{G13XVariant, Policy};
use crate::platform::apple::agx::{initdata::Root, ring::Shared};

/// Captured at the original initdata-copy boundary, before render work.
/// This is neither a chip-to-variant guess nor native register reset state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    policy: Policy,
    variant: Option<G13XVariant>,
    mode: Option<(u64, u64, u32)>,
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
        })
    }
    /// The caller must supply the actual selected FTAB variant. Original
    /// a000 0x8714 copies *(rings[0]+0x10d4) to its private mode word; its
    /// context tail alone consumes mode==3. b000/c000 have no such read.
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
        })
    }
    pub fn policy(self) -> Policy {
        self.policy
    }
    pub(crate) fn require_cl_parameters(self) -> Result<(), &'static str> {
        if self.variant == Some(G13XVariant::A000) {
            return Err("GFX selected a000 CL common-parameter program is not qualified");
        }
        Ok(())
    }
    pub(crate) fn merge_mirror(self) -> bool {
        self.variant == Some(G13XVariant::A000) && self.mode.is_some_and(|(_, _, mode)| mode == 3)
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
                (_, 4) if !self.fail && at == self.hardware.checked_add(0x10d4).unwrap_or(0) => {
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
        assert!(selected.require_cl_parameters().is_err());
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
                    .require_cl_parameters()
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
}
