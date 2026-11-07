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
//! [`RenderPipelinePlan::tests_fragments`]: crate::metal::pipeline::RenderPipelinePlan::tests_fragments
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
}

impl TestState {
    pub(in crate::metal::command_buffer) fn untested(&self) -> bool {
        self.untested
    }
}

/// The attachments' accesses the copies follow and precede.
const ATTACHMENT: (PipelineStages, Access) = (
    PipelineStages::EARLY_FRAGMENT_TESTS.union(PipelineStages::LATE_FRAGMENT_TESTS),
    Access::DEPTH_STENCIL_ATTACHMENT_READ.union(Access::DEPTH_STENCIL_ATTACHMENT_WRITE),
);
/// The fragment functions' storage accesses of the copies.
const STORAGE: (PipelineStages, Access) = (
    PipelineStages::FRAGMENT_SHADER,
    Access::SHADER_READ.union(Access::SHADER_WRITE),
);
const TRANSFER: (PipelineStages, Access) = (
    PipelineStages::ALL_TRANSFER,
    Access::TRANSFER_READ.union(Access::TRANSFER_WRITE),
);

fn barrier(recorder: &mut Recorder, src: (PipelineStages, Access), dst: (PipelineStages, Access)) {
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
    for copy in copies {
        let attachment = Subresource {
            aspects: copy.aspect,
            mip_level: copy.level,
            base_array_layer: copy.base_layer,
            layer_count: copy.layers,
        };
        let image = Subresource {
            aspects: ImageAspects::COLOR,
            mip_level: 0,
            base_array_layer: 0,
            layer_count: copy.layers,
        };
        let (src, dst, src_sub, dst_sub) = if back {
            (copy.image, copy.attachment, image, attachment)
        } else {
            (copy.attachment, copy.image, attachment, image)
        };
        recorder.push(Command::CopyImage {
            src,
            dst,
            regions: alloc::vec![ImageCopy {
                src: src_sub,
                src_offset: [0; 3],
                dst: dst_sub,
                dst_offset: [0; 3],
                extent: [copy.extent[0], copy.extent[1], 1],
            }],
        });
    }
    barrier(recorder, TRANSFER, after);
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
                "stencil feedback in a pass that began before its pipeline was made",
            ));
        }
        let tests = FragmentTests {
            state: words(
                &state,
                inputs.depth_copy.as_ref(),
                inputs.stencil_copy.is_some(),
                render.raster.clip_mode == crate::metal::abi::DepthClipMode::Clamp,
            ),
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
}
