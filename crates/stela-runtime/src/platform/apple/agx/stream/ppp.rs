//! PPP state records (cmdbuf.xml `PPP Header` and the words it marks
//! present; Mesa `agxdecode_record`, `agx_ppp.h`).
//!
//! A record is a header word and then, in header-bit order, every word it
//! marks present; the record's size must match exactly. Words left absent
//! keep the state of earlier records, so [`apply`] merges a record into the
//! running [`PppState`]. Words whose content no source describes (`Output
//! unknown`, `Varying word 2`, `Occlusion query 2`) are accepted only when
//! zero, as Mesa writes them.

use super::{StreamError, check_known, field, mask, read_u32, refuse};
use crate::platform::apple::agx::isa::machine::Memory;
use alloc::vec::Vec;

/// `Fragment control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FragmentControl {
    pub visibility_mode: u32,
    pub scissor: bool,
    pub depth_bias: bool,
    pub stencil_test: bool,
    pub two_sided_stencil: bool,
    pub tag_write_disable: bool,
    pub sample_mask_after_depth_stencil: bool,
    pub disable_tri_merging: bool,
    pub pass_type: u32,
}

/// `Fragment face` merged with `Fragment face 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Face {
    pub stencil_reference: u8,
    /// `Line width`: 4.4 fixed point minus one.
    pub line_width: u8,
    pub polygon_mode: u32,
    pub disable_depth_write: bool,
    pub depth_function: u32,
    /// From word 2: both depth functions must pass, either disable bit
    /// clear writes depth.
    pub disable_depth_write_2: bool,
    pub conservative_depth: u32,
    pub depth_function_2: u32,
    pub object_type: u32,
}

/// `Fragment stencil`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stencil {
    pub write_mask: u8,
    pub read_mask: u8,
    pub depth_pass: u32,
    pub depth_fail: u32,
    pub stencil_fail: u32,
    pub compare: u32,
}

/// `Viewport`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Viewport {
    pub translate: [f32; 3],
    pub scale: [f32; 3],
}

/// `Region clip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RegionClip {
    pub enable: bool,
    /// Tiles, inclusive minimum and exclusive maximum.
    pub min: [u32; 2],
    pub max: [u32; 2],
}

/// `Cull` with `Cull 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cull {
    pub front: bool,
    pub back: bool,
    /// `PPP Vertex`: 1, 2, 3 for vertex 0, 1, 2.
    pub flat_shading_vertex: u32,
    pub depth_clip: bool,
    pub depth_clamp: bool,
    pub primitive_msaa: bool,
    pub front_face_ccw: bool,
    pub rasterizer_discard: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cull2 {
    pub clamp_w: bool,
    pub draw_clipped_edges: bool,
    pub needs_primitive_id: bool,
    pub rasterizer_discard: bool,
}

/// The fragment shader words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FragmentShader {
    pub uniform_halves: u32,
    pub texture_states: u32,
    pub sampler_states: u32,
    pub preshader_registers: u32,
    pub cf_binding_count: u32,
    pub pipeline: u32,
    /// The CF binding table, from the USC base.
    pub cf_bindings: u32,
}

/// The running PPP state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PppState {
    pub fragment_control: Option<FragmentControl>,
    pub front: Face,
    pub back: Face,
    pub front_stencil: Stencil,
    pub back_stencil: Stencil,
    /// Indices into the scissor and depth-bias arrays.
    pub scissor_index: u32,
    pub depth_bias_index: u32,
    pub region_clip: Vec<RegionClip>,
    pub viewports: Vec<Viewport>,
    pub w_clamp: Option<f32>,
    /// `Output select` bits.
    pub output_select: u32,
    pub varying_counts_32: [u32; 3],
    pub varying_counts_16: [u32; 3],
    pub cull: Cull,
    pub cull_2: Cull2,
    pub fragment_shader: Option<FragmentShader>,
    pub occlusion_index: Option<u32>,
    pub output_size: Option<u32>,
}

/// `PPP Header` bits.
mod header {
    pub const FRAGMENT_CONTROL: u32 = 0;
    pub const FRAGMENT_CONTROL_2: u32 = 1;
    pub const FRONT_FACE: u32 = 2;
    pub const FRONT_FACE_2: u32 = 3;
    pub const FRONT_STENCIL: u32 = 4;
    pub const BACK_FACE: u32 = 5;
    pub const BACK_FACE_2: u32 = 6;
    pub const BACK_STENCIL: u32 = 7;
    pub const DEPTH_BIAS_SCISSOR: u32 = 8;
    pub const REGION_CLIP: u32 = 10;
    pub const VIEWPORT: u32 = 11;
    pub const W_CLAMP: u32 = 16;
    pub const OUTPUT_SELECT: u32 = 17;
    pub const VARYING_COUNTS_32: u32 = 18;
    pub const VARYING_COUNTS_16: u32 = 19;
    pub const CULL: u32 = 21;
    pub const CULL_2: u32 = 22;
    pub const FRAGMENT_SHADER: u32 = 23;
    pub const OCCLUSION_QUERY: u32 = 24;
    pub const OCCLUSION_QUERY_2: u32 = 25;
    pub const OUTPUT_UNKNOWN: u32 = 26;
    pub const OUTPUT_SIZE: u32 = 27;
    pub const VARYING_WORD_2: u32 = 28;
}

/// Words of a viewport.
const VIEWPORT_WORDS: usize = 6;

struct Cursor<'a> {
    memory: &'a mut dyn Memory,
    address: u64,
    end: u64,
}

impl Cursor<'_> {
    fn word(&mut self) -> Result<u64, StreamError> {
        if self.address + 4 > self.end {
            return refuse(self.address, "a PPP record shorter than its header says");
        }
        let word = u64::from(read_u32(self.memory, self.address)?);
        self.address += 4;
        Ok(word)
    }

    fn checked(&mut self, known: u64, reason: &'static str) -> Result<u64, StreamError> {
        let at = self.address;
        let word = self.word()?;
        check_known(at, word, known, reason)?;
        Ok(word)
    }

    fn zero(&mut self, reason: &'static str) -> Result<(), StreamError> {
        self.checked(0, reason).map(|_| ())
    }

    fn float(&mut self) -> Result<f32, StreamError> {
        Ok(f32::from_bits(self.word()? as u32))
    }
}

fn face(word: u64) -> Face {
    Face {
        stencil_reference: field(word, 0, 8) as u8,
        line_width: field(word, 8, 8) as u8,
        polygon_mode: field(word, 18, 2) as u32,
        disable_depth_write: field(word, 21, 1) != 0,
        depth_function: field(word, 24, 3) as u32,
        ..Face::default()
    }
}

fn face_2(face: &mut Face, word: u64) {
    face.disable_depth_write_2 = field(word, 21, 1) != 0;
    face.conservative_depth = field(word, 22, 2) as u32;
    face.depth_function_2 = field(word, 24, 3) as u32;
    face.object_type = field(word, 28, 4) as u32;
}

fn stencil(word: u64) -> Stencil {
    Stencil {
        write_mask: field(word, 0, 8) as u8,
        read_mask: field(word, 8, 8) as u8,
        depth_pass: field(word, 16, 3) as u32,
        depth_fail: field(word, 19, 3) as u32,
        stencil_fail: field(word, 22, 3) as u32,
        compare: field(word, 25, 3) as u32,
    }
}

const FACE_BITS: u64 = mask(&[(0, 16), (18, 2), (21, 3), (24, 3)]);
const FACE_2_BITS: u64 = mask(&[(21, 3), (24, 3), (28, 4)]);
const STENCIL_BITS: u64 = mask(&[(0, 28)]);

/// Merge the record of `words` words at `address` into `state`.
pub fn apply(
    memory: &mut dyn Memory,
    address: u64,
    words: u32,
    state: &mut PppState,
) -> Result<(), StreamError> {
    let end = address + 4 * u64::from(words);
    let mut cursor = Cursor {
        memory,
        address,
        end,
    };
    let header_word = cursor.word()?;
    let known = mask(&[(0, 9), (10, 7), (17, 3), (21, 8)]);
    check_known(
        address,
        header_word,
        known,
        "a PPP header with unnamed bits",
    )?;
    let has = |bit: u32| field(header_word, bit, 1) != 0;
    let viewport_count = field(header_word, 12, 4) as usize + 1;

    if has(header::FRAGMENT_CONTROL) || has(header::FRAGMENT_CONTROL_2) {
        // Both words share the layout; the second follows the first.
        let mut control = None;
        for present in [
            has(header::FRAGMENT_CONTROL),
            has(header::FRAGMENT_CONTROL_2),
        ] {
            if !present {
                continue;
            }
            let word = cursor.checked(
                mask(&[(9, 1), (14, 4), (17, 3), (21, 1), (25, 2), (29, 3)]),
                "a fragment control word with unnamed bits",
            )?;
            control = Some(FragmentControl {
                visibility_mode: field(word, 14, 2) as u32,
                scissor: field(word, 16, 1) != 0,
                depth_bias: field(word, 17, 1) != 0,
                stencil_test: field(word, 18, 1) != 0,
                two_sided_stencil: field(word, 19, 1) != 0,
                tag_write_disable: field(word, 21, 1) != 0,
                sample_mask_after_depth_stencil: field(word, 25, 1) != 0,
                disable_tri_merging: field(word, 26, 1) != 0,
                pass_type: field(word, 29, 3) as u32,
            });
        }
        state.fragment_control = control;
    }
    if has(header::FRONT_FACE) {
        state.front = face(cursor.checked(FACE_BITS, "a fragment face word with unnamed bits")?);
    }
    if has(header::FRONT_FACE_2) {
        face_2(
            &mut state.front,
            cursor.checked(FACE_2_BITS, "a fragment face 2 word with unnamed bits")?,
        );
    }
    if has(header::FRONT_STENCIL) {
        state.front_stencil =
            stencil(cursor.checked(STENCIL_BITS, "a fragment stencil word with unnamed bits")?);
    }
    if has(header::BACK_FACE) {
        state.back = face(cursor.checked(FACE_BITS, "a fragment face word with unnamed bits")?);
    }
    if has(header::BACK_FACE_2) {
        face_2(
            &mut state.back,
            cursor.checked(FACE_2_BITS, "a fragment face 2 word with unnamed bits")?,
        );
    }
    if has(header::BACK_STENCIL) {
        state.back_stencil =
            stencil(cursor.checked(STENCIL_BITS, "a fragment stencil word with unnamed bits")?);
    }
    if has(header::DEPTH_BIAS_SCISSOR) {
        let word = cursor.word()?;
        state.scissor_index = field(word, 0, 16) as u32;
        state.depth_bias_index = field(word, 16, 16) as u32;
    }
    if has(header::REGION_CLIP) {
        state.region_clip.clear();
        for _ in 0..viewport_count {
            let a = cursor.checked(
                mask(&[(0, 9), (16, 9), (31, 1)]),
                "a region clip word with unnamed bits",
            )?;
            let b = cursor.checked(
                mask(&[(0, 9), (16, 9)]),
                "a region clip word with unnamed bits",
            )?;
            state.region_clip.push(RegionClip {
                enable: field(a, 31, 1) != 0,
                min: [field(a, 16, 9) as u32, field(b, 16, 9) as u32],
                max: [field(a, 0, 9) as u32 + 1, field(b, 0, 9) as u32 + 1],
            });
        }
    }
    if has(header::VIEWPORT) {
        cursor.zero("a viewport control word with bits set (no field is known)")?;
        state.viewports.clear();
        for _ in 0..viewport_count {
            let mut values = [0f32; VIEWPORT_WORDS];
            for value in values.iter_mut() {
                *value = cursor.float()?;
            }
            state.viewports.push(Viewport {
                translate: [values[0], values[2], values[4]],
                scale: [values[1], values[3], values[5]],
            });
        }
    }
    if has(header::W_CLAMP) {
        state.w_clamp = Some(cursor.float()?);
    }
    if has(header::OUTPUT_SELECT) {
        state.output_select = cursor.checked(
            mask(&[(0, 17), (18, 5)]),
            "an output select word with unnamed bits",
        )? as u32;
    }
    for (bit, counts) in [
        (header::VARYING_COUNTS_32, &mut state.varying_counts_32),
        (header::VARYING_COUNTS_16, &mut state.varying_counts_16),
    ] {
        if has(bit) {
            let word =
                cursor.checked(mask(&[(0, 24)]), "a varying counts word with unnamed bits")?;
            *counts = [
                field(word, 0, 8) as u32,
                field(word, 8, 8) as u32,
                field(word, 16, 8) as u32,
            ];
        }
    }
    if has(header::CULL) {
        let word = cursor.checked(
            mask(&[(0, 2), (7, 5), (15, 3)]),
            "a cull word with unnamed bits",
        )?;
        state.cull = Cull {
            front: field(word, 0, 1) != 0,
            back: field(word, 1, 1) != 0,
            flat_shading_vertex: field(word, 7, 2) as u32,
            depth_clip: field(word, 10, 1) != 0,
            depth_clamp: field(word, 11, 1) != 0,
            primitive_msaa: field(word, 15, 1) != 0,
            front_face_ccw: field(word, 16, 1) != 0,
            rasterizer_discard: field(word, 17, 1) != 0,
        };
    }
    if has(header::CULL_2) {
        let word = cursor.checked(
            mask(&[(5, 1), (9, 1), (12, 1), (17, 1)]),
            "a cull 2 word with unnamed bits",
        )?;
        state.cull_2 = Cull2 {
            clamp_w: field(word, 5, 1) != 0,
            draw_clipped_edges: field(word, 9, 1) != 0,
            needs_primitive_id: field(word, 12, 1) != 0,
            rasterizer_discard: field(word, 17, 1) != 0,
        };
    }
    if has(header::FRAGMENT_SHADER) {
        let at = cursor.address;
        let word0 = cursor.checked(
            mask(&[(0, 23)]),
            "a fragment shader word 0 with unnamed bits",
        )?;
        if word0 & 1 != 0 {
            return refuse(at, "a fragment shader word 0 with its unknown bit set");
        }
        let word1 = cursor.checked(
            mask(&[(6, 26)]),
            "a fragment shader word 1 with unnamed bits",
        )?;
        let word2 = cursor.checked(
            mask(&[(2, 30)]),
            "a fragment shader word 2 with unnamed bits",
        )?;
        // Word 3's four bits vary with textures and uniforms (Mesa:
        // "needs investigation") and change no state the model keeps.
        cursor.checked(
            mask(&[(0, 4)]),
            "a fragment shader word 3 with unnamed bits",
        )?;
        state.fragment_shader = Some(FragmentShader {
            uniform_halves: super::groups(field(word0, 1, 3), 64, 3) as u32,
            texture_states: super::groups(field(word0, 4, 5), 8, 5) as u32,
            sampler_states: field(word0, 9, 3) as u32,
            preshader_registers: super::groups(field(word0, 12, 4), 16, 4) as u32,
            cf_binding_count: field(word0, 16, 7) as u32,
            pipeline: (field(word1, 6, 26) << 6) as u32,
            cf_bindings: (field(word2, 2, 30) << 2) as u32,
        });
    }
    if has(header::OCCLUSION_QUERY) {
        let word = cursor.checked(
            mask(&[(17, 15)]),
            "an occlusion query word with unnamed bits",
        )?;
        state.occlusion_index = Some(field(word, 17, 15) as u32);
    }
    if has(header::OCCLUSION_QUERY_2) {
        cursor.zero("an occlusion query 2 word with bits set (no field is known)")?;
    }
    if has(header::OUTPUT_UNKNOWN) {
        cursor.zero("an output unknown word with bits set (no field is known)")?;
    }
    if has(header::OUTPUT_SIZE) {
        state.output_size = Some(cursor.word()? as u32);
    }
    if has(header::VARYING_WORD_2) {
        cursor.zero("a varying word 2 with bits set (no field is known)")?;
        cursor.zero("a varying word 2 with bits set (no field is known)")?;
    }
    if cursor.address != end {
        return refuse(cursor.address, "a PPP record longer than its header says");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Flat, words};
    use super::*;

    const BASE: u64 = 0x1_0000_0000;

    #[test]
    fn records_merge_present_words() {
        let mut memory = Flat::new(BASE, 0x100);
        // Viewport (one) and cull.
        let header = 1 << 11 | 1 << 21;
        let mut record = alloc::vec![header, 0];
        record.extend([16.0f32, 16.0, 8.0, -8.0, 0.0, 1.0].map(f32::to_bits));
        record.push(1 << 1 | 1 << 16);
        words(&mut memory, BASE, &record);
        let mut state = PppState::default();
        apply(&mut memory, BASE, record.len() as u32, &mut state).unwrap();
        assert_eq!(
            state.viewports,
            [Viewport {
                translate: [16.0, 8.0, 0.0],
                scale: [16.0, -8.0, 1.0]
            }]
        );
        assert!(state.cull.back && state.cull.front_face_ccw);
        // A size that disagrees with the header refuses.
        assert!(apply(&mut memory, BASE, record.len() as u32 + 1, &mut state).is_err());
        assert!(apply(&mut memory, BASE, record.len() as u32 - 1, &mut state).is_err());
    }
}
