//! Fragment tests that fragment functions run themselves.
//!
//! On a device without stencil export, a fragment function that writes the
//! stencil reference tests and updates the pass's depth and stencil in its
//! interlock section, on storage copies of the attachments
//! ([`TestedCopy`]), and its pipeline tests neither
//! ([`RenderPipelinePlan::tests_fragments`]). Before such a draw the
//! encoder ends the pass instance and copies the attachments into their
//! copies, which then hold the pass's depth and stencil; before a draw
//! that tests depth or stencil in its pipeline, and where the pass ends, it
//! copies them back. Each copy is an image copy between the attachment's
//! aspect and a color image of its texel size.
//!
//!
//! A color attachment no storage view of which reads its raw texels, an
//! A8Unorm texture's or a 3D texture's depth planes, or which a backend may
//! render through a shadow of its own, a linear image, likewise lives in a
//! storage copy ([`AttachmentInputs::color_copies`]) while draws access it
//! as storage, and returns to the attachment before a draw renders it
//! through the blend unit and where the pass ends.
//!
//! [`RenderPipelinePlan::tests_fragments`]: crate::metal::pipeline::RenderPipelinePlan::tests_fragments
//! [`AttachmentInputs::color_copies`]: crate::metal::pass::AttachmentInputs::color_copies
use super::{CommandBuffer, Recorder, Resolver, render::render};
use crate::metal::{
    binding::{FragmentTests, ResourceId},
    error::{Error, Result},
    pass::TestedCopy,
    pipeline::DepthStencilState,
    vulkan::{
        Access, CompareOp, ImageAspects, PipelineStages,
        command::{Barrier, Command, DepthStencil, ImageCopy, Subresource},
    },
};
use alloc::vec::Vec;

/// Where the pass's depth and stencil are, and whether the pipeline's
/// tests are off.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(in crate::metal::command_buffer) struct TestState {
    /// The copies hold the pass's depth and stencil.
    copied: bool,
    /// The encoder's dynamic depth-stencil state tests nothing, for a
    /// pipeline that tests fragments itself.
    untested: bool,
    /// The color attachments whose copies hold the pass's texels, one bit
    /// each.
    colors: u32,
}

impl TestState {
    pub(in crate::metal::command_buffer) fn untested(&self) -> bool {
        self.untested
    }
}

/// The attachments' accesses the copies follow and precede.
pub(super) const ATTACHMENT: (PipelineStages, Access) = (
    PipelineStages::EARLY_FRAGMENT_TESTS.union(PipelineStages::LATE_FRAGMENT_TESTS),
    Access::DEPTH_STENCIL_ATTACHMENT_READ.union(Access::DEPTH_STENCIL_ATTACHMENT_WRITE),
);
/// The fragment functions' storage accesses of the copies.
const STORAGE: (PipelineStages, Access) = (
    PipelineStages::FRAGMENT_SHADER,
    Access::SHADER_READ.union(Access::SHADER_WRITE),
);
pub(super) const TRANSFER: (PipelineStages, Access) = (
    PipelineStages::ALL_TRANSFER,
    Access::TRANSFER_READ.union(Access::TRANSFER_WRITE),
);

pub(super) fn barrier(
    recorder: &mut Recorder,
    src: (PipelineStages, Access),
    dst: (PipelineStages, Access),
) {
    recorder.push(Command::Barrier(Barrier {
        src_stages: src.0,
        src_access: src.1,
        dst_stages: dst.0,
        dst_access: dst.1,
    }));
}

/// Copies each attachment into its copy, or with `back`, each copy into
/// its attachment.
fn copy(recorder: &mut Recorder, copies: &[TestedCopy], back: bool) {
    let (before, after) = if back {
        (STORAGE, ATTACHMENT)
    } else {
        (ATTACHMENT, STORAGE)
    };
    barrier(recorder, before, TRANSFER);
    copy_images(recorder, copies, back);
    barrier(recorder, TRANSFER, after);
}

/// A color attachment's accesses its copies follow and precede.
const COLOR_ATTACHMENT: (PipelineStages, Access) = (
    PipelineStages::COLOR_ATTACHMENT_OUTPUT,
    Access::COLOR_ATTACHMENT_READ.union(Access::COLOR_ATTACHMENT_WRITE),
);

/// The image copies of [`copy`], without its barriers. A 3D attachment's
/// layers are its depth planes, which a copy addresses by depth.
pub(super) fn copy_images(recorder: &mut Recorder, copies: &[TestedCopy], back: bool) {
    for copy in copies {
        let (base_array_layer, layer_count, depth) = if copy.planes {
            (0, 1, copy.base_layer as i32)
        } else {
            (copy.base_layer, copy.layers, 0)
        };
        let attachment = Subresource {
            aspects: copy.aspect,
            mip_level: copy.level,
            base_array_layer,
            layer_count,
        };
        let image = Subresource {
            aspects: ImageAspects::COLOR,
            mip_level: 0,
            base_array_layer: 0,
            layer_count: copy.layers,
        };
        let (src, dst, src_sub, dst_sub, src_offset, dst_offset) = if back {
            (
                copy.image,
                copy.attachment,
                image,
                attachment,
                [0; 3],
                [0, 0, depth],
            )
        } else {
            (
                copy.attachment,
                copy.image,
                attachment,
                image,
                [0, 0, depth],
                [0; 3],
            )
        };
        // A copy between a 3D image and a 2D array spans the array's layers
        // in depth.
        let extent_depth = if copy.planes { copy.layers } else { 1 };
        recorder.push(Command::CopyImage {
            src,
            dst,
            regions: alloc::vec![ImageCopy {
                src: src_sub,
                src_offset,
                dst: dst_sub,
                dst_offset,
                extent: [copy.extent[0], copy.extent[1], extent_depth],
            }],
        });
    }
}

/// A face's stencil word (`air_to_nir.h`).
fn stencil_word(face: &crate::metal::pipeline::StencilFace) -> u32 {
    face.compare_op.raw()
        | face.fail_op.raw() << 3
        | face.depth_fail_op.raw() << 6
        | face.pass_op.raw() << 9
        | (face.compare_mask & 0xff) << 16
        | (face.write_mask & 0xff) << 24
}

/// The words of `state` for a pass with `depth` and `stencil` copies.
fn words(
    state: &DepthStencilState,
    depth: Option<&TestedCopy>,
    stencil: bool,
    clamps: bool,
) -> [u32; 3] {
    let compare = if state.depth_test_enable {
        state.depth_compare_op
    } else {
        CompareOp::Always
    };
    let mut depth_word =
        compare.raw() | depth.map_or(0, |copy| copy.encoding) << FragmentTests::DEPTH_FORMAT_SHIFT;
    if state.depth_write_enable {
        depth_word |= FragmentTests::DEPTH_WRITE;
    }
    if stencil {
        depth_word |= FragmentTests::STENCIL_ATTACHED;
    }
    if clamps {
        depth_word |= FragmentTests::DEPTH_CLAMP;
    }
    // A stencil test that is off passes and keeps.
    let face = |face| {
        if state.stencil_test_enable {
            stencil_word(face)
        } else {
            CompareOp::Always.raw()
        }
    };
    [depth_word, face(&state.front), face(&state.back)]
}

/// The dynamic depth-stencil state of a pipeline that tests nothing.
fn untested() -> DepthStencil {
    let inert = (
        crate::metal::vulkan::StencilOp::Keep,
        crate::metal::vulkan::StencilOp::Keep,
        crate::metal::vulkan::StencilOp::Keep,
        CompareOp::Always,
        0,
        0,
    );
    DepthStencil {
        depth_test: false,
        depth_write: false,
        depth_compare: CompareOp::Always,
        stencil_test: false,
        faces: [inert, inert],
    }
}

impl CommandBuffer {
    /// Brings the pass's depth and stencil to where the bound pipeline
    /// tests them, and a pipeline testing fragments itself its table's
    /// state, before a draw.
    pub(super) fn prepare_fragment_tests(&mut self, resolver: &mut dyn Resolver) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let Some(tests_fragments) = render
            .pipeline
            .as_ref()
            .map(|pipeline| pipeline.plan.tests_fragments)
        else {
            return Ok(());
        };
        self.prepare_tests(resolver, tests_fragments)
    }

    /// Brings the pass's depth and stencil to where a pipeline that does or
    /// does not test fragments itself tests them, as
    /// [`prepare_fragment_tests`](Self::prepare_fragment_tests) does for
    /// the bound pipeline: before an execution of GPU-resident commands
    /// whose pipelines do.
    pub(super) fn prepare_tests(
        &mut self,
        resolver: &mut dyn Resolver,
        tests_fragments: bool,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let pass = render.pass();
        let inputs = pass.inputs;
        let attached = (pass.depth.is_some(), pass.stencil.is_some());
        let copies: Vec<TestedCopy> = [inputs.depth_copy, inputs.stencil_copy]
            .into_iter()
            .flatten()
            .collect();
        let state = render.raster.depth_stencil;
        if !tests_fragments {
            let tested = state.depth_test_enable || state.stencil_test_enable;
            if render.tests.copied && tested {
                render.tests.copied = false;
                self.outside_pass(resolver, |recorder| copy(recorder, &copies, true))?;
            }
            let render = super::render::render(&mut self.encoder)?;
            if render.tests.untested {
                render.tests.untested = false;
                self.recorder
                    .push(Command::SetDepthStencil(super::render::depth_stencil(
                        &state,
                    )));
            }
            return Ok(());
        }
        if attached != (inputs.depth_copy.is_some(), inputs.stencil_copy.is_some()) {
            return Err(Error::Unsupported(
                "fragment tests a function runs itself in a pass that began before its pipeline was made",
            ));
        }
        let tests = FragmentTests {
            state: words(
                &state,
                inputs.depth_copy.as_ref(),
                inputs.stencil_copy.is_some(),
                render.raster.clip_mode == crate::metal::abi::DepthClipMode::Clamp,
            ),
            references: render.stencil_references[0] & 0xff
                | (render.stencil_references[1] & 0xff) << 8,
            range: render.depth_range.map(f32::to_bits),
            depth: inputs.depth_copy.map_or(ResourceId::NULL, |copy| copy.id),
            stencil: inputs.stencil_copy.map_or(ResourceId::NULL, |copy| copy.id),
        };
        let copied = render.tests.copied;
        let was_untested = render.tests.untested;
        render.tests.copied = true;
        render.tests.untested = true;
        if !copied && !copies.is_empty() {
            self.outside_pass(resolver, |recorder| copy(recorder, &copies, false))?;
        }
        if !was_untested {
            self.recorder.push(Command::SetDepthStencil(untested()));
        }
        self.bindings.set_fragment_tests(tests);
        Ok(())
    }

    /// Returns the copies to the attachments where the pass ends.
    pub(super) fn finish_fragment_tests(&mut self, resolver: &mut dyn Resolver) -> Result<()> {
        self.place_color_copies(resolver, 0)?;
        let render = render(&mut self.encoder)?;
        if !render.tests.copied {
            return Ok(());
        }
        render.tests.copied = false;
        let inputs = render.pass().inputs;
        let copies: Vec<TestedCopy> = [inputs.depth_copy, inputs.stencil_copy]
            .into_iter()
            .flatten()
            .collect();
        self.outside_pass(resolver, |recorder| copy(recorder, &copies, true))
    }

    /// Brings each copied color attachment's texels to its copy where the
    /// next draw or tile dispatch accesses it as `storage`, and the others'
    /// back to their attachments.
    pub(super) fn place_color_copies(
        &mut self,
        resolver: &mut dyn Resolver,
        storage: u32,
    ) -> Result<()> {
        let render = render(&mut self.encoder)?;
        let colors = render.pass().inputs.color_copies;
        let present = (0..colors.len())
            .filter(|&index| colors[index].is_some())
            .fold(0u32, |mask, index| mask | 1 << index);
        let copied = render.tests.colors;
        let back = copied & !storage;
        let into = storage & present & !copied;
        if back == 0 && into == 0 {
            return Ok(());
        }
        render.tests.colors = copied & !back | into;
        let pick = |mask: u32| -> Vec<TestedCopy> {
            (0..colors.len())
                .filter(|&index| mask & 1 << index != 0)
                .filter_map(|index| colors[index])
                .collect()
        };
        let (back, into) = (pick(back), pick(into));
        let accesses = (
            COLOR_ATTACHMENT.0.union(STORAGE.0),
            COLOR_ATTACHMENT.1.union(STORAGE.1),
        );
        self.outside_pass(resolver, |recorder| {
            barrier(recorder, accesses, TRANSFER);
            copy_images(recorder, &back, true);
            copy_images(recorder, &into, false);
            barrier(recorder, TRANSFER, accesses);
        })
    }
}
