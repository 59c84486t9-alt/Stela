//! Original render-target shape carried from TA to its matching 3D scene.
//! These are source-programmed inputs, not a native start/TVB capability.

use super::{FirmwareWork, GeometryInputs, Run, SamplerHeap, Word, ZlsBindings, scene};
use crate::platform::apple::agx::{
    channel::Kind,
    exec::render::{FragmentInputs, Program, SampleStorage},
    sgx::Native,
    work_decode::{Frame, Submission, resources::Lease},
};
use alloc::rc::{Rc, Weak};
use core::cell::{Cell, RefCell};

/// The original TA shape is immutable alongside the accepted setup. It may
/// accompany a linear geometry product; it grants no stock completion.
pub struct TaGeometryBinding {
    issuer: Weak<RefCell<Native>>,
    valid: Rc<Cell<bool>>,
    pub(crate) submission: Submission,
    pub(crate) frame: Frame,
    pub(crate) inputs: GeometryInputs,
    shape: Shape,
}

impl TaGeometryBinding {
    pub(crate) fn check_live(&self) -> Result<(), &'static str> {
        if !self.valid.get() || self.issuer.upgrade().is_none() {
            return Err("GFX native TA metadata was cancelled or invalidated");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    tile: (u32, u32),
    samples: u32,
    layers: u32,
    // Both original layered encodings are retained, not normalized away.
    layer_control: u32,
}
fn tile_samples(word: u64) -> Result<((u32, u32), u32), &'static str> {
    if word & !0xf003 != 0 || word & 3 == 3 {
        return Err("GFX original tile/sample word contains unqualified bits");
    }
    let tile = (
        ((word >> 12) & 3) as u32 * 16,
        ((word >> 14) & 3) as u32 * 16,
    );
    if ![(32, 32), (32, 16), (16, 16)].contains(&tile) {
        return Err("GFX original tile dimensions have no qualified USC layout");
    }
    Ok((tile, 1 << (word & 3)))
}
impl Shape {
    fn read(tile: u64, layer: u32) -> Result<Self, &'static str> {
        let (tile, samples) = tile_samples(tile)?;
        // The original producer emits 8000 for one layer, d000/e000 with
        // layers-1 otherwise. The retained public consumer bounds layers
        // to 2048; larger encodings are explicitly outside this binding.
        let layers = match layer {
            0x8000 => 1,
            _ if [0xd000, 0xe000].contains(&(layer & !0x7ff)) && layer & 0x7ff != 0 => {
                (layer & 0x7ff) + 1
            }
            _ => return Err("GFX original TA layer encoding is not qualified"),
        };
        Ok(Self {
            tile,
            samples,
            layers,
            layer_control: layer,
        })
    }
    fn check_3d(&self, tile: u64, control: u64) -> Result<(), &'static str> {
        if tile_samples(tile)? != (self.tile, self.samples) {
            return Err("GFX 3D tile/sample shape differs from its accepted TA geometry");
        }
        if control & !1 != 0 {
            return Err("GFX native 3D render control effects are not qualified");
        }
        if (control & 1 != 0) != (self.layer_control != 0x8000) {
            return Err("GFX 3D layered flag differs from its accepted TA geometry");
        }
        Ok(())
    }
}
fn complete(run: &Run, input: &Submission, lease: Lease, kind: Kind) -> Result<(), &'static str> {
    if run.submission != *input
        || run.lease != lease
        || input.command.kind != kind
        || run.next != run.words.len()
    {
        return Err("GFX render binding requires its complete accepted native parameter phase");
    }
    Ok(())
}
impl FirmwareWork {
    /// Capture the actual TA inputs without a future 3D read. The source
    /// consumer still owns common setup, TVB, trigger and retirement.
    pub fn ta_geometry_binding(
        &self,
        submission: &Submission,
        lease: Lease,
        sampler_heap: Option<SamplerHeap>,
    ) -> Result<TaGeometryBinding, &'static str> {
        let inputs = self.ta_geometry_inputs(submission, lease, sampler_heap)?;
        let native = self.power.native.borrow();
        let registers = &native.work.render;
        let run = registers
            .run
            .as_ref()
            .ok_or("GFX TA binding has no native owner")?;
        complete(run, submission, lease, Kind::Ta)?;
        scene::Key::read(submission, &run.frame)?;
        let tile = registers
            .committed(Word::new(0x10148, 8))
            .ok_or("GFX TA tile/sample word has not been programmed")?;
        let layers = registers
            .committed(Word::new(0x10168, 4))
            .ok_or("GFX TA layer word has not been programmed")?;
        let shape = Shape::read(
            tile,
            u32::try_from(layers).map_err(|_| "GFX TA layer word exceeds its source width")?,
        )?;
        if run.binding_issued.replace(true) {
            return Err("GFX accepted TA geometry binding was already transferred");
        }
        Ok(TaGeometryBinding {
            issuer: Rc::downgrade(&self.power.native),
            valid: run.valid.clone(),
            submission: submission.clone(),
            frame: run.frame.clone(),
            inputs,
            shape,
        })
    }
    pub(crate) fn fragment_inputs_from_ta(
        &self,
        submission: &Submission,
        lease: Lease,
        ta: &TaGeometryBinding,
        sampler_heap: Option<SamplerHeap>,
    ) -> Result<(Frame, FragmentInputs), &'static str> {
        self.available()?;
        ta.check_live()?;
        if !Weak::ptr_eq(&Rc::downgrade(&self.power.native), &ta.issuer) {
            return Err("GFX native 3D binding belongs to a different SGX owner");
        }
        let zls = self.three_d_zls_bindings(submission, lease)?;
        let storage = self.three_d_sample_storage(submission, lease)?;
        let native = self.power.native.borrow();
        let registers = &native.work.render;
        let run = registers
            .run
            .as_ref()
            .ok_or("GFX 3D binding has no native owner")?;
        complete(run, submission, lease, Kind::ThreeD)?;
        if scene::Key::read(submission, &run.frame)? != scene::Key::read(&ta.submission, &ta.frame)?
        {
            return Err("GFX native 3D binding does not own the original TA scene/context");
        }
        let word = |offset, width| {
            registers
                .committed(Word::new(offset, width))
                .ok_or("GFX native 3D input has not been programmed")
        };
        let inputs = fragment_inputs(ta.inputs, ta.shape, zls, storage, sampler_heap, word)?;
        Ok((run.frame.clone(), inputs))
    }
}

fn fragment_inputs(
    geometry: GeometryInputs,
    shape: Shape,
    zls: ZlsBindings,
    storage: SampleStorage,
    sampler_heap: Option<SamplerHeap>,
    word: impl Fn(u32, u32) -> Result<u64, &'static str>,
) -> Result<FragmentInputs, &'static str> {
    let scalar = |offset, width| {
        u32::try_from(word(offset, width)?)
            .map_err(|_| "GFX native 3D scalar has unqualified upper bits")
    };
    shape.check_3d(word(0x10008, 8)?, word(0x10038, 8)?)?;
    let inputs = FragmentInputs {
        usc_base: word(0x10068, 8)?,
        vm_slot: geometry.vm_slot,
        width: geometry.width,
        height: geometry.height,
        layers: shape.layers,
        tile: shape.tile,
        samples: shape.samples,
        sample_bytes: storage,
        multisample_control: scalar(0x10018, 8)?,
        background: Program {
            counts: scalar(0x15368, 8)?,
            usc: word(0x15370, 8)?,
        },
        end_of_tile: Program {
            counts: scalar(0x15378, 4)?,
            usc: word(0x15380, 4)?,
        },
        depth_clear: scalar(0x15300, 4)?,
        background_values: scalar(0x15308, 4)?,
        scissors: word(0x15108, 8)?,
        depth_biases: word(0x15100, 8)?,
        visibility: word(0x15310, 8)?,
        zls_control: zls.control,
        zls_pixels: zls.pixels,
        depth: zls.depth,
        stencil: zls.stencil,
        sampler_heap,
    };
    inputs
        .check()
        .map_err(|_| "GFX original 3D bindings contain unsupported fragment state")?;
    Ok(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_tile_sample_layer_words_preserve_shape_and_reject_unqualified_effects() {
        for (tile_word, tile) in [(0xa000, (32, 32)), (0x6000, (32, 16)), (0x5000, (16, 16))] {
            for sample_bits in 0..3 {
                for layers in [1, 2, 3, 2048] {
                    for mode in [0xd000, 0xe000] {
                        let layer_word = if layers == 1 {
                            0x8000
                        } else {
                            mode | (layers - 1)
                        };
                        let shape = Shape::read(tile_word | sample_bits, layer_word).unwrap();
                        assert_eq!(
                            (shape.tile, shape.samples, shape.layers),
                            (tile, 1 << sample_bits, layers)
                        );
                        assert_eq!(shape.layer_control, layer_word);
                        let layered = u64::from(layers > 1);
                        shape.check_3d(tile_word | sample_bits, layered).unwrap();
                        assert!(
                            shape
                                .check_3d(tile_word | sample_bits, layered ^ 1)
                                .is_err()
                        );
                        assert!(
                            shape
                                .check_3d(tile_word | sample_bits, layered | 0x280)
                                .is_err()
                        );
                        assert!(shape.check_3d(tile_word | 3, layered).is_err());
                    }
                }
            }
        }
        for word in [0, 0x10000, 0xd000, 0xe000, 0x8001, 0xd800, 0xe800, u32::MAX] {
            assert!(Shape::read(0xa000, word).is_err());
        }
        for tile in [0, 0x9000, 0xf000, 0xa003, 0x1_a000, u64::MAX] {
            assert!(Shape::read(tile, 0x8000).is_err());
        }
    }
    #[test]
    fn three_d_input_decoder_uses_its_own_programs_and_retained_ta_shape() {
        use crate::platform::apple::agx::exec::render::{Zls, ZlsPair};
        let geometry = GeometryInputs {
            vdm_stream: 0x4000,
            usc_base: 0x100000000,
            vm_slot: 7,
            ppp_control: 0x200,
            width: 640,
            height: 480,
            sampler_heap: None,
        };
        let shape = Shape::read(0x6001, 0xe002).unwrap();
        let surface = Zls {
            base: 0x200000000,
            stride: 1,
            meta: 0x300000000,
            meta_stride: 0,
        };
        let zls = ZlsBindings {
            control: 0,
            pixels: 639 | 479 << 15,
            depth: ZlsPair {
                load: surface,
                store: Zls {
                    base: 0x400000000,
                    ..surface
                },
            },
            stencil: ZlsPair {
                load: surface,
                store: surface,
            },
        };
        let words = [
            (0x10008, 8, 0x6001),
            (0x10038, 8, 1),
            (0x10068, 8, 0x500000000),
            (0x10018, 8, 0x88),
            (0x15368, 8, 0x22),
            (0x15370, 8, 0x304),
            (0x15378, 4, 0x44),
            (0x15380, 4, 0x384),
            (0x15300, 4, u64::from(1f32.to_bits())),
            (0x15308, 4, 0x300),
            (0x15108, 8, 0x800000000),
            (0x15100, 8, 0x900000000),
            (0x15310, 8, 0xa00000000),
        ];
        let read = |offset, width| {
            words
                .iter()
                .find(|(o, w, _)| (*o, *w) == (offset, width))
                .map(|(_, _, value)| *value)
                .ok_or("missing native word")
        };
        let inputs =
            fragment_inputs(geometry, shape, zls, SampleStorage::native(8), None, read).unwrap();
        assert_eq!(
            (
                inputs.width,
                inputs.height,
                inputs.layers,
                inputs.tile,
                inputs.samples
            ),
            (640, 480, 3, (32, 16), 2)
        );
        assert_eq!((inputs.usc_base, inputs.vm_slot), (0x500000000, 7));
        assert_eq!(
            inputs.background,
            Program {
                usc: 0x304,
                counts: 0x22
            }
        );
        assert_eq!(
            inputs.end_of_tile,
            Program {
                usc: 0x384,
                counts: 0x44
            }
        );
        assert_eq!(
            (inputs.scissors, inputs.depth_biases, inputs.visibility),
            (0x800000000, 0x900000000, 0xa00000000)
        );
        assert_eq!(inputs.depth, zls.depth);
        assert_eq!(inputs.sample_bytes, SampleStorage::native(8));
        // Each independent native input remains mandatory; no fallback to
        // a TA word or a helper default follows a missing/wide value.
        for &(at, width, _) in &words {
            let missing = |offset, w| {
                if (offset, w) == (at, width) {
                    Err("missing native word")
                } else {
                    read(offset, w)
                }
            };
            assert!(
                fragment_inputs(
                    geometry,
                    shape,
                    zls,
                    SampleStorage::native(8),
                    None,
                    missing
                )
                .is_err()
            );
        }
        for at in [0x10018, 0x15368, 0x15378, 0x15300, 0x15308] {
            let wide = |offset, width| {
                if offset == at {
                    Ok(0x1_00000000)
                } else {
                    read(offset, width)
                }
            };
            assert!(
                fragment_inputs(geometry, shape, zls, SampleStorage::native(8), None, wide)
                    .is_err()
            );
        }
    }
}
