//! The vertex half of a render pass: VDM draws to binned primitives.
//!
//! Semantics (Public: cmdbuf.xml, Mesa `agx_uvs.h`, `agx_nir_lower_uvs.c`,
//! `hk_cmd_draw.c` and the compiler README's vertex ABI; Inferred where
//! marked):
//! - A draw's vertex IDs are `start + i`, or for an indexed draw the index
//!   plus the base vertex (`start`); an index equal to the restart index
//!   cuts the primitive when restart is on. An index past the buffer's size
//!   reads as 0 (Inferred: the size exists for robustness). Indirect draws
//!   read Metal's argument layout (`count, instances, start` and, indexed,
//!   `first index, base vertex`); the first index offsets the buffer.
//! - Each vertex runs the vertex shader on one thread with `r5` its vertex
//!   ID and `r6` its instance ID (0-based); `st_var` writes its UVS words.
//! - The UVS is position (4 words), the user varyings (smooth, flat, linear
//!   counts from `Varying counts 32`), point size, the layer (low half) and
//!   viewport (high half) word, then the clip distances (`Output select`).
//! - Assembly follows Vulkan's vertex orders (strips alternate the first
//!   two vertices of odd triangles, fans pivot on vertex 0 last); quads
//!   split into `(0, 1, 2)` and `(0, 2, 3)` with one primitive ID (Inferred
//!   for the hardware's own orders). Primitive IDs count from 0 per
//!   instance.
//! - Clipping is [`crate::platform::apple::agx::raster::clip`]; W is
//!   clamped below by `W clamp` before the divide when both the PPP
//!   control and `Cull 2` enable it (Inferred placement after clipping).
//! - The window position is `translate + scale * ndc`; the layer and
//!   viewport come from the provoking vertex (`PPP Vertex`, Vulkan's rule).
//!   A primitive on a layer past the pass is dropped (Inferred).
//! - A triangle is front-facing when counter-clockwise in window space
//!   under `front face CCW` (Vulkan's signed-area rule), culled per `Cull`,
//!   and filled, outlined or drawn as points per its face's polygon mode.
//!   Outlines skip edges clipping created unless `draw clipped edges`.
//! - Depth bias (triangles only, as Mesa enables it) adds `constant * r +
//!   slope * max(|dz/dx|, |dz/dy|)`, clamped; `r` is 1 for Z16 (Mesa scales
//!   the constant for unorm) and `2^(e - 23)` for the triangle's largest
//!   depth exponent `e` for Z32F (Vulkan's float rule; Inferred).
//! - Rasterizer discard drops every primitive (`Cull` or `Cull 2`).
//!
//! Refused by name: tessellation (in the stream walker), 16-bit varyings,
//! barycentric coordinates, Bresenham lines (`primitive MSAA`), points
//! without a size, and a viewport index past the PPP's viewports.

use super::super::{GROUP_BUDGET, ShaderState, WorkError};
use super::{RenderPass, Stats, heap_sampler, ppp_control};
use crate::platform::apple::agx::isa::machine::{
    Env, Exit, Fault, Memory, Program, SIMD_WIDTH, Specials,
};
use crate::platform::apple::agx::raster::clip::{self, Interp, Volume};
use crate::platform::apple::agx::raster::coverage::{self, Rect};
use crate::platform::apple::agx::stream::cdm::extended_samplers;
use crate::platform::apple::agx::stream::ppp::{FragmentControl, PppState};
use crate::platform::apple::agx::stream::usc::{self, FragmentProperties};
use crate::platform::apple::agx::stream::vdm::{Command, Draw, StateUpdate, Walker};
use crate::platform::apple::agx::stream::{field, read_u32};
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// UVS words of the position.
pub const POSITION_WORDS: usize = 4;
/// Register halves of `r5` (vertex ID) and `r6` (instance ID).
const VERTEX_ID_HALF: usize = 10;
const INSTANCE_ID_HALF: usize = 12;

/// `Primitive` values.
mod primitive {
    pub const POINTS: u32 = 0;
    pub const LINES: u32 = 1;
    pub const LINE_STRIP: u32 = 3;
    pub const LINE_LOOP: u32 = 5;
    pub const TRIANGLES: u32 = 6;
    pub const TRIANGLE_STRIP: u32 = 9;
    pub const TRIANGLE_FAN: u32 = 11;
    pub const QUADS: u32 = 14;
    pub const QUAD_STRIP: u32 = 15;
}

/// `Output select` fields.
pub mod output {
    pub const CLIP_DISTANCES: u32 = 0xffff;
    pub const POINT_SIZE: u32 = 1 << 18;
    pub const VIEWPORT_TARGET: u32 = 1 << 19;
    pub const RENDER_TARGET: u32 = 1 << 20;
    pub const FRAG_COORD_Z: u32 = 1 << 21;
    pub const BARYCENTRIC: u32 = 1 << 22;
}

/// `Polygon Mode` and `Object Type` values.
mod polygon {
    pub const FILL: u32 = 0;
    pub const LINE: u32 = 1;
    pub const POINT: u32 = 2;
}
pub mod object {
    pub const POINT_SPRITE_UV10: u32 = 2;
}

/// The UVS layout of a draw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uvs {
    pub classes: Vec<Interp>,
    pub point_size: Option<usize>,
    pub layer_viewport: Option<usize>,
    pub clip: core::ops::Range<usize>,
}

impl Uvs {
    fn new(ppp: &PppState, outputs: u32) -> Result<Self, WorkError> {
        if ppp.varying_counts_16 != [0; 3] {
            return Err(WorkError::Refused(
                "16-bit varyings (their UVS placement is unrecorded)",
            ));
        }
        let select = ppp.output_select;
        if select & output::BARYCENTRIC != 0 {
            return Err(WorkError::Refused(
                "hardware barycentric coordinates (their slots are unrecorded)",
            ));
        }
        let [smooth, flat, linear] = ppp.varying_counts_32.map(|n| n as usize);
        let mut classes = vec![Interp::Smooth; POSITION_WORDS];
        classes.extend(core::iter::repeat_n(Interp::Smooth, smooth));
        classes.extend(core::iter::repeat_n(Interp::Flat, flat));
        classes.extend(core::iter::repeat_n(Interp::Linear, linear));
        let point_size = (select & output::POINT_SIZE != 0).then(|| {
            classes.push(Interp::Flat);
            classes.len() - 1
        });
        let layer_viewport = (select & (output::VIEWPORT_TARGET | output::RENDER_TARGET) != 0)
            .then(|| {
                classes.push(Interp::Flat);
                classes.len() - 1
            });
        let planes = select & output::CLIP_DISTANCES;
        if planes & (planes + 1) != 0 {
            return Err(WorkError::Refused(
                "clip distance planes that are not contiguous from plane 0",
            ));
        }
        let start = classes.len();
        classes.extend(core::iter::repeat_n(
            Interp::Smooth,
            planes.count_ones() as usize,
        ));
        if classes.len() > outputs as usize {
            return Err(WorkError::Refused(
                "a UVS layout larger than the vertex shader's outputs",
            ));
        }
        Ok(Uvs {
            clip: start..classes.len(),
            classes,
            point_size,
            layer_viewport,
        })
    }
}

/// A vertex in window space.
#[derive(Debug, Clone, PartialEq)]
pub struct Vertex {
    /// Window x, y (pixels) and depth.
    pub window: [f64; 3],
    /// 1 / clip w.
    pub rhw: f64,
    pub words: Vec<u32>,
}

/// What the rasterizer covers.
#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Triangle([Vertex; 3]),
    /// A segment and its width in pixels.
    Line([Vertex; 2], f64),
    /// A point and its size in pixels.
    Point(Vertex, f64),
}

/// One binned primitive.
#[derive(Debug, Clone, PartialEq)]
pub struct Primitive {
    /// Index into [`Binned::states`].
    pub state: usize,
    pub shape: Shape,
    /// The assembled vertices' UVS words, in primitive order (flat shading
    /// reads these, not clipped vertices).
    pub flat: Vec<Vec<u32>>,
    pub front: bool,
    pub layer: u32,
    /// Pixels the primitive may cover (framebuffer, scissor, region clip).
    pub bounds: Rect,
    /// The depth range fragments clamp to, when depth clamping.
    pub depth_clamp: Option<(f32, f32)>,
    pub id: u32,
}

/// A CF binding (cmdbuf.xml `CF binding`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub components: u32,
    pub shade_model: u32,
    pub source: u32,
    pub base_slot: u32,
    pub base_register: u32,
}

/// `Shade model` and `Coefficient source` values.
pub mod shade {
    pub const FLAT_VERTEX_0: u32 = 0;
    pub const FLAT_VERTEX_2: u32 = 2;
    pub const LINEAR: u32 = 3;
    pub const FLAT_VERTEX_1: u32 = 6;
    pub const PERSPECTIVE: u32 = 7;
}
pub mod source {
    pub const VARYING: u32 = 0;
    pub const FRAG_COORD_Z: u32 = 1;
    pub const POINT_COORD: u32 = 2;
    pub const PRIMITIVE_ID: u32 = 3;
    pub const BARYCENTRIC: u32 = 5;
}

/// A fragment shader with its CF bindings.
pub struct FragmentPipeline {
    pub shader: ShaderState,
    pub properties: FragmentProperties,
    /// `Number of 32-bit slots` and of coefficient registers.
    pub slots: u32,
    pub registers: u32,
    pub bindings: Vec<Binding>,
}

/// The PPP state a primitive was drawn with.
pub struct DrawState {
    pub ppp: PppState,
    pub control: FragmentControl,
    /// Index into [`Binned::pipelines`]; `None` without a fragment shader.
    pub fragment: Option<usize>,
    pub uvs: Uvs,
}

/// The output of the vertex half.
#[derive(Default)]
pub struct Binned {
    pub primitives: Vec<Primitive>,
    pub states: Vec<DrawState>,
    pub pipelines: Vec<FragmentPipeline>,
    /// The `FragmentShader` words each pipeline was loaded from.
    keys: Vec<crate::platform::apple::agx::stream::ppp::FragmentShader>,
    pub program: Program,
}

/// A vertex shader thread's environment.
struct VertexEnv<'a> {
    memory: &'a mut dyn Memory,
    pass: &'a RenderPass,
    outputs: &'a mut [Vec<u32>],
}

impl Memory for VertexEnv<'_> {
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), Fault> {
        self.memory.read(address, buffer)
    }
    fn write(&mut self, address: u64, data: &[u8]) -> Result<(), Fault> {
        self.memory.write(address, data)
    }
}

impl Env for VertexEnv<'_> {
    fn store_varying(&mut self, lane: usize, slot: u32, value: u32) -> Result<(), &'static str> {
        let words = self
            .outputs
            .get_mut(lane)
            .ok_or("st_var from a thread with no vertex")?;
        *words
            .get_mut(slot as usize)
            .ok_or("st_var past the vertex outputs")? = value;
        Ok(())
    }

    fn no_varyings(&mut self) -> Result<(), &'static str> {
        Ok(())
    }

    fn sampler_heap(&mut self, index: u32) -> Result<[u8; 8], &'static str> {
        heap_sampler(self.memory, self.pass, index)
    }
}

/// The VDM state the walk accumulates.
#[derive(Default)]
struct VertexState {
    restart_index: u32,
    pipeline: Option<u32>,
    sampler_states: u32,
    outputs: u32,
}

impl VertexState {
    fn update(&mut self, update: &StateUpdate) {
        if let Some(index) = update.restart_index {
            self.restart_index = index;
        }
        if let Some(shader) = update.shader {
            self.sampler_states = shader.sampler_states;
        }
        if let Some(pipeline) = update.pipeline {
            self.pipeline = Some(pipeline);
        }
        if let Some([count, _]) = update.outputs {
            self.outputs = count;
        }
    }
}

/// Run the vertex half of `pass`.
pub fn run(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    stats: &mut Stats,
) -> Result<Binned, WorkError> {
    let mut binned = Binned::default();
    let mut ppp = PppState::default();
    let mut vertex = VertexState::default();
    let mut walker = Walker::new(pass.vdm_stream);
    while let Some(command) = walker.next(memory)? {
        match command {
            Command::Ppp { address, words } => {
                crate::platform::apple::agx::stream::ppp::apply(memory, address, words, &mut ppp)?
            }
            Command::State(update) => vertex.update(&update),
            Command::Draw(draw) => {
                draw_primitives(memory, pass, &ppp, &vertex, &draw, &mut binned, stats)?;
                stats.draws += 1;
            }
            Command::Barrier(_) => {}
        }
    }
    Ok(binned)
}

/// The vertex IDs of a draw (`None` cuts) and its instance count.
fn vertex_ids(
    memory: &mut dyn Memory,
    draw: &Draw,
    restart_index: u32,
) -> Result<(Vec<Option<u32>>, u32), WorkError> {
    let (count, instances, start, first_index) = match draw.indirect {
        Some(address) => {
            let word = |memory: &mut dyn Memory, i: u64| read_u32(memory, address + 4 * i);
            let count = word(memory, 0)?;
            let instances = word(memory, 1)?;
            if draw.indices.is_some() {
                (count, instances, word(memory, 3)?, word(memory, 2)?)
            } else {
                (count, instances, word(memory, 2)?, 0)
            }
        }
        None => (
            draw.count
                .ok_or(WorkError::Refused("a direct draw without a count"))?,
            draw.instances.ok_or(WorkError::Refused(
                "a direct draw without an instance count",
            ))?,
            draw.start.unwrap_or(0),
            0,
        ),
    };
    let mut ids = Vec::with_capacity(count as usize);
    match draw.indices {
        None => ids.extend((0..count).map(|i| Some(start.wrapping_add(i)))),
        Some((buffer, size, limit)) => {
            let bytes = size.bytes();
            for i in 0..u64::from(count) {
                let offset = (u64::from(first_index) + i) * bytes;
                let raw = if limit.is_some_and(|limit| offset + bytes > limit) {
                    0
                } else {
                    let mut value = [0u8; 4];
                    memory.read(buffer + offset, &mut value[..bytes as usize])?;
                    u32::from_le_bytes(value)
                };
                ids.push(if draw.restart && raw == restart_index {
                    None
                } else {
                    Some(raw.wrapping_add(start))
                });
            }
        }
    }
    Ok((ids, instances))
}

/// Primitives of a topology over runs of vertex IDs, each a list of
/// vertices and its primitive ID.
fn assemble(topology: u32, ids: &[Option<u32>]) -> Result<Vec<(Vec<u32>, u32)>, WorkError> {
    let mut out = Vec::new();
    let mut id = 0u32;
    for run in ids.split(Option::is_none) {
        let v: Vec<u32> = run.iter().map(|v| v.expect("runs hold no cuts")).collect();
        let n = v.len();
        let mut push = |vertices: Vec<u32>, out: &mut Vec<(Vec<u32>, u32)>| {
            out.push((vertices, id));
            id += 1;
        };
        match topology {
            primitive::POINTS => v.iter().for_each(|&a| push(vec![a], &mut out)),
            primitive::LINES => v
                .as_chunks::<2>()
                .0
                .iter()
                .for_each(|c| push(c.to_vec(), &mut out)),
            primitive::LINE_STRIP | primitive::LINE_LOOP => {
                for i in 1..n {
                    push(vec![v[i - 1], v[i]], &mut out);
                }
                if topology == primitive::LINE_LOOP && n > 2 {
                    push(vec![v[n - 1], v[0]], &mut out);
                }
            }
            primitive::TRIANGLES => v
                .as_chunks::<3>()
                .0
                .iter()
                .for_each(|c| push(c.to_vec(), &mut out)),
            primitive::TRIANGLE_STRIP => {
                for i in 0..n.saturating_sub(2) {
                    let odd = i & 1;
                    push(vec![v[i], v[i + 1 + odd], v[i + 2 - odd]], &mut out);
                }
            }
            primitive::TRIANGLE_FAN => {
                for i in 0..n.saturating_sub(2) {
                    push(vec![v[i + 1], v[i + 2], v[0]], &mut out);
                }
            }
            primitive::QUADS => v
                .as_chunks::<4>()
                .0
                .iter()
                .for_each(|c| push(c.to_vec(), &mut out)),
            primitive::QUAD_STRIP => {
                for i in (0..n.saturating_sub(3)).step_by(2) {
                    push(vec![v[i], v[i + 1], v[i + 3], v[i + 2]], &mut out);
                }
            }
            _ => return Err(WorkError::Refused("a VDM primitive the description lacks")),
        }
    }
    Ok(out)
}

/// Shade every vertex ID of one instance; returns their UVS words.
fn shade_vertices(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    state: &ShaderState,
    program: &mut Program,
    ids: &[u32],
    instance: u32,
    words: usize,
) -> Result<BTreeMap<u32, Vec<u32>>, WorkError> {
    let mut shaded = BTreeMap::new();
    for chunk in ids.chunks(SIMD_WIDTH) {
        let mut group = state.group(chunk.len(), state.code);
        for (lane, &id) in chunk.iter().enumerate() {
            group.set_reg32(lane, VERTEX_ID_HALF, id);
            group.set_reg32(lane, INSTANCE_ID_HALF, instance);
        }
        group.specials = Specials {
            core_index: Some(0),
            vm_slot: Some(pass.vm_slot),
            ..Specials::default()
        };
        let mut outputs = vec![vec![0u32; words]; chunk.len()];
        let mut env = VertexEnv {
            memory,
            pass,
            outputs: &mut outputs,
        };
        let mut budget = GROUP_BUDGET;
        if group.run(program, &mut env, &mut budget)? == Exit::Barrier {
            return Err(WorkError::Refused(
                "a threadgroup barrier in a vertex shader",
            ));
        }
        for (&id, words) in chunk.iter().zip(outputs) {
            shaded.insert(id, words);
        }
    }
    Ok(shaded)
}

fn word(words: &[u32], index: usize) -> f64 {
    f64::from(f32::from_bits(words[index]))
}

/// The binned state for a draw, reusing the last one when unchanged.
fn draw_state(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    ppp: &PppState,
    uvs: Uvs,
    binned: &mut Binned,
) -> Result<usize, WorkError> {
    if let Some(last) = binned.states.last()
        && last.ppp == *ppp
        && last.uvs == uvs
    {
        return Ok(binned.states.len() - 1);
    }
    let fragment = match ppp.fragment_shader {
        None => None,
        Some(words) => match binned.keys.iter().position(|key| *key == words) {
            Some(index) => Some(index),
            None => {
                let pipeline = load_fragment(memory, pass, &words, &mut binned.program)?;
                binned.pipelines.push(pipeline);
                binned.keys.push(words);
                Some(binned.pipelines.len() - 1)
            }
        },
    };
    binned.states.push(DrawState {
        ppp: ppp.clone(),
        control: ppp.fragment_control.unwrap_or_default(),
        fragment,
        uvs,
    });
    Ok(binned.states.len() - 1)
}

/// Load a fragment shader's USC state and CF bindings and run its
/// preshader.
fn load_fragment(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    words: &crate::platform::apple::agx::stream::ppp::FragmentShader,
    program: &mut Program,
) -> Result<FragmentPipeline, WorkError> {
    let usc = usc::parse(memory, pass.usc_base, u64::from(words.pipeline))?;
    let properties = usc.fragment.ok_or(WorkError::Refused(
        "a fragment shader without Fragment properties",
    ))?;
    let mut shader = ShaderState::load(
        memory,
        pass.usc_base,
        &usc,
        extended_samplers(words.sampler_states),
    )?;
    let mut outputs: [Vec<u32>; 0] = [];
    shader.run_preshader(
        &mut VertexEnv {
            memory,
            pass,
            outputs: &mut outputs,
        },
        program,
    )?;
    let table = pass.usc_base + u64::from(words.cf_bindings);
    let header = read_u32(memory, table)?;
    let mut bindings = Vec::with_capacity(words.cf_binding_count as usize);
    for i in 0..u64::from(words.cf_binding_count) {
        let at = table + 4 + 4 * i;
        let word = u64::from(read_u32(memory, at)?);
        if word >> 24 != 0 {
            return Err(WorkError::Refused("a CF binding with unnamed bits"));
        }
        let binding = Binding {
            components: field(word, 0, 2) as u32 + 1,
            shade_model: field(word, 2, 3) as u32,
            source: field(word, 5, 3) as u32,
            base_slot: field(word, 8, 8) as u32,
            base_register: field(word, 16, 8) as u32,
        };
        if ![
            shade::FLAT_VERTEX_0,
            shade::FLAT_VERTEX_1,
            shade::FLAT_VERTEX_2,
            shade::LINEAR,
            shade::PERSPECTIVE,
        ]
        .contains(&binding.shade_model)
        {
            return Err(WorkError::Refused(
                "a CF binding shade model the description lacks",
            ));
        }
        match binding.source {
            source::VARYING | source::FRAG_COORD_Z | source::POINT_COORD | source::PRIMITIVE_ID => {
            }
            source::BARYCENTRIC => {
                return Err(WorkError::Refused(
                    "barycentric coefficient sources (their planes are unrecorded)",
                ));
            }
            _ => {
                return Err(WorkError::Refused(
                    "a CF binding source the description lacks",
                ));
            }
        }
        bindings.push(binding);
    }
    Ok(FragmentPipeline {
        shader,
        properties,
        slots: header & 0xff,
        registers: (header >> 8) & 0xff,
        bindings,
    })
}

/// Shade, assemble, clip and bin one draw.
fn draw_primitives(
    memory: &mut dyn Memory,
    pass: &RenderPass,
    ppp: &PppState,
    vertex: &VertexState,
    draw: &Draw,
    binned: &mut Binned,
    stats: &mut Stats,
) -> Result<(), WorkError> {
    let pipeline = vertex
        .pipeline
        .ok_or(WorkError::Refused("a draw before any vertex shader"))?;
    let uvs = Uvs::new(ppp, vertex.outputs)?;
    let usc = usc::parse(memory, pass.usc_base, u64::from(pipeline))?;
    let mut shader = ShaderState::load(
        memory,
        pass.usc_base,
        &usc,
        extended_samplers(vertex.sampler_states),
    )?;
    let mut outputs: [Vec<u32>; 0] = [];
    shader.run_preshader(
        &mut VertexEnv {
            memory,
            pass,
            outputs: &mut outputs,
        },
        &mut binned.program,
    )?;
    let (ids, instances) = vertex_ids(memory, draw, vertex.restart_index)?;
    let primitives = assemble(draw.primitive, &ids)?;
    let unique: Vec<u32> = ids
        .iter()
        .flatten()
        .copied()
        .collect::<alloc::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if ppp.cull.rasterizer_discard || ppp.cull_2.rasterizer_discard {
        // Vertex shaders still run for their side effects.
        for instance in 0..instances {
            shade_vertices(
                memory,
                pass,
                &shader,
                &mut binned.program,
                &unique,
                instance,
                vertex.outputs as usize,
            )?;
        }
        return Ok(());
    }
    if ppp.cull.primitive_msaa {
        return Err(WorkError::Refused(
            "Bresenham lines (primitive MSAA; their rasterization rules are unrecorded)",
        ));
    }
    let state = draw_state(memory, pass, ppp, uvs.clone(), binned)?;
    let mut context = Context::new(memory, pass, ppp, &uvs)?;
    for instance in 0..instances {
        let shaded = shade_vertices(
            context.memory,
            pass,
            &shader,
            &mut binned.program,
            &unique,
            instance,
            vertex.outputs as usize,
        )?;
        for (vertices, id) in &primitives {
            let words: Vec<Vec<u32>> = vertices.iter().map(|v| shaded[v].clone()).collect();
            let before = binned.primitives.len();
            context.primitive(words, *id, state, &mut binned.primitives)?;
            stats.primitives += (binned.primitives.len() - before) as u64;
        }
    }
    Ok(())
}

/// What turning assembled vertices into window primitives needs.
struct Context<'a> {
    memory: &'a mut dyn Memory,
    pass: &'a RenderPass,
    ppp: &'a PppState,
    uvs: &'a Uvs,
    volume: Volume,
    w_clamp: Option<f64>,
}

/// `Scissor` entry bytes and `Depth bias` entry bytes.
const SCISSOR_BYTES: u64 = 16;
const DEPTH_BIAS_BYTES: u64 = 12;
/// `Region clip` units.
const REGION_TILE: u32 = 32;
/// The mantissa bits of an f32 (Vulkan's float depth-bias unit).
const F32_MANTISSA: i32 = 23;
const F32_BIAS: i32 = 127;
const F64_BIAS: i32 = 1023;
const F64_MANTISSA: i32 = 52;

impl<'a> Context<'a> {
    fn new(
        memory: &'a mut dyn Memory,
        pass: &'a RenderPass,
        ppp: &'a PppState,
        uvs: &'a Uvs,
    ) -> Result<Self, WorkError> {
        let w_clamp = if pass.ppp_control & ppp_control::W_CLAMP != 0 && ppp.cull_2.clamp_w {
            Some(f64::from(ppp.w_clamp.ok_or(WorkError::Refused(
                "W clamping without a W clamp word",
            ))?))
        } else {
            None
        };
        Ok(Context {
            memory,
            pass,
            ppp,
            uvs,
            volume: Volume {
                depth_clip: ppp.cull.depth_clip,
                opengl_depth: pass.ppp_control & ppp_control::OPENGL != 0,
            },
            w_clamp,
        })
    }

    fn clip_vertex(&self, words: &[u32]) -> clip::Vertex {
        clip::Vertex {
            position: [0, 1, 2, 3].map(|c| word(words, c)),
            words: words.to_vec(),
            clip: self.uvs.clip.clone().map(|i| word(words, i)).collect(),
            edge: true,
        }
    }

    /// The window vertex of a clipped vertex through viewport `viewport`.
    fn window(&self, v: &clip::Vertex, viewport: usize) -> Result<Vertex, WorkError> {
        let mut w = v.position[3];
        if let Some(clamp) = self.w_clamp {
            w = w.max(clamp);
        }
        let vp = self.ppp.viewports.get(viewport).ok_or(WorkError::Refused(
            "a viewport index past the PPP's viewports",
        ))?;
        let window = [0, 1, 2]
            .map(|c| f64::from(vp.translate[c]) + f64::from(vp.scale[c]) * v.position[c] / w);
        Ok(Vertex {
            window,
            rhw: 1.0 / w,
            words: v.words.clone(),
        })
    }

    /// The provoking vertex (`PPP Vertex` 1, 2, 3 for vertex 0, 1, 2).
    fn provoking(&self, count: usize) -> usize {
        (self.ppp.cull.flat_shading_vertex.saturating_sub(1) as usize).min(count - 1)
    }

    fn point_size(&self, words: &[u32]) -> Result<f64, WorkError> {
        match self.uvs.point_size {
            Some(index) => Ok(word(words, index)),
            None if self.pass.ppp_control & ppp_control::DEFAULT_POINT_SIZE != 0 => Ok(1.0),
            None => Err(WorkError::Refused("a point without a size")),
        }
    }

    fn line_width(&self, front: bool) -> f64 {
        let face = if front { self.ppp.front } else { self.ppp.back };
        f64::from(u32::from(face.line_width) + 1) / 16.0
    }

    /// Bin one assembled primitive of a draw.
    fn primitive(
        &mut self,
        flat: Vec<Vec<u32>>,
        id: u32,
        state: usize,
        out: &mut Vec<Primitive>,
    ) -> Result<(), WorkError> {
        let provoking = &flat[self.provoking(flat.len())];
        let (layer, viewport) = match self.uvs.layer_viewport {
            Some(index) => {
                let value = provoking[index];
                let select = self.ppp.output_select;
                (
                    if select & output::RENDER_TARGET != 0 {
                        value & 0xffff
                    } else {
                        0
                    },
                    if select & output::VIEWPORT_TARGET != 0 {
                        value >> 16
                    } else {
                        0
                    },
                )
            }
            None => (0, 0),
        };
        if layer >= self.pass.layers {
            return Ok(());
        }
        let viewport = viewport as usize;
        let (bounds, depth_range) = self.bounds(viewport)?;
        if bounds.is_empty() {
            return Ok(());
        }
        let base = Primitive {
            state,
            shape: Shape::Point(
                Vertex {
                    window: [0.0; 3],
                    rhw: 0.0,
                    words: Vec::new(),
                },
                0.0,
            ),
            flat: flat.clone(),
            front: true,
            layer,
            bounds,
            depth_clamp: self.ppp.cull.depth_clamp.then_some(depth_range),
            id,
        };
        let vertices: Vec<clip::Vertex> = flat.iter().map(|w| self.clip_vertex(w)).collect();
        match vertices.len() {
            1 => {
                if clip::point(&vertices[0], self.volume) {
                    let size = self.point_size(&flat[0])?;
                    let v = self.window(&vertices[0], viewport)?;
                    out.push(Primitive {
                        shape: Shape::Point(v, size),
                        ..base
                    });
                }
            }
            2 => {
                if let Some((a, b)) = clip::line(
                    vertices[0].clone(),
                    vertices[1].clone(),
                    self.volume,
                    &self.uvs.classes,
                ) {
                    let shape = Shape::Line(
                        [self.window(&a, viewport)?, self.window(&b, viewport)?],
                        self.line_width(true),
                    );
                    out.push(Primitive { shape, ..base });
                }
            }
            _ => {
                // Triangles and quads clip as one polygon each.
                let clipped = clip::polygon(vertices, self.volume, &self.uvs.classes);
                if clipped.is_empty() {
                    return Ok(());
                }
                let mut window: Vec<Vertex> = clipped
                    .iter()
                    .map(|v| self.window(v, viewport))
                    .collect::<Result<_, _>>()?;
                let area: f64 = (0..window.len())
                    .map(|i| {
                        let (p, q) = (&window[i].window, &window[(i + 1) % window.len()].window);
                        p[0] * q[1] - q[0] * p[1]
                    })
                    .sum();
                if area == 0.0 {
                    return Ok(());
                }
                let counter_clockwise = area < 0.0;
                let front = counter_clockwise == self.ppp.cull.front_face_ccw;
                if (front && self.ppp.cull.front) || (!front && self.ppp.cull.back) {
                    return Ok(());
                }
                let control = self.ppp.fragment_control.unwrap_or_default();
                if control.depth_bias {
                    let bias = self.depth_bias(&window)?;
                    for v in window.iter_mut() {
                        v.window[2] += bias;
                    }
                }
                let face = if front { self.ppp.front } else { self.ppp.back };
                let base = Primitive { front, ..base };
                match face.polygon_mode {
                    polygon::FILL => {
                        for i in 1..window.len() - 1 {
                            let xy = |v: &Vertex| [v.window[0], v.window[1]];
                            let corners = [xy(&window[0]), xy(&window[i]), xy(&window[i + 1])];
                            if coverage::doubled_area(corners) == 0.0 {
                                // Clipping can leave coincident vertices.
                                continue;
                            }
                            let shape = Shape::Triangle([
                                window[0].clone(),
                                window[i].clone(),
                                window[i + 1].clone(),
                            ]);
                            out.push(Primitive {
                                shape,
                                ..base.clone()
                            });
                        }
                    }
                    polygon::LINE => {
                        let width = self.line_width(front);
                        for i in 0..window.len() {
                            if !clipped[i].edge && !self.ppp.cull_2.draw_clipped_edges {
                                continue;
                            }
                            let j = (i + 1) % window.len();
                            let shape = Shape::Line([window[i].clone(), window[j].clone()], width);
                            out.push(Primitive {
                                shape,
                                ..base.clone()
                            });
                        }
                    }
                    polygon::POINT => {
                        for (v, c) in window.iter().zip(&clipped) {
                            if !c.edge && !self.ppp.cull_2.draw_clipped_edges {
                                continue;
                            }
                            let size = self.point_size(&v.words)?;
                            out.push(Primitive {
                                shape: Shape::Point(v.clone(), size),
                                ..base.clone()
                            });
                        }
                    }
                    _ => return Err(WorkError::Refused("a polygon mode the description lacks")),
                }
            }
        }
        Ok(())
    }

    /// The pixels a primitive of `viewport` may cover and its depth range.
    fn bounds(&mut self, viewport: usize) -> Result<(Rect, (f32, f32)), WorkError> {
        let mut rect = Rect {
            min: [0, 0],
            max: [self.pass.width, self.pass.height],
        };
        let mut range = (0.0f32, 1.0f32);
        let control = self.ppp.fragment_control.unwrap_or_default();
        if control.scissor {
            let index = u64::from(self.ppp.scissor_index) + viewport as u64;
            let at = self.pass.scissors + SCISSOR_BYTES * index;
            let w0 = read_u32(self.memory, at)?;
            let w1 = read_u32(self.memory, at + 4)?;
            let min_z = f32::from_bits(read_u32(self.memory, at + 8)?);
            let max_z = f32::from_bits(read_u32(self.memory, at + 12)?);
            rect = rect.intersect(Rect {
                min: [w0 >> 16, w1 >> 16],
                max: [w0 & 0xffff, w1 & 0xffff],
            });
            range = (min_z, max_z);
        }
        if let Some(region) = self.ppp.region_clip.get(viewport)
            && region.enable
        {
            rect = rect.intersect(Rect {
                min: region.min.map(|t| t * REGION_TILE),
                max: region.max.map(|t| t * REGION_TILE),
            });
        }
        Ok((rect, range))
    }

    /// The depth bias of a polygon (`Depth bias` entry).
    fn depth_bias(&mut self, window: &[Vertex]) -> Result<f64, WorkError> {
        let at = self.pass.depth_biases + DEPTH_BIAS_BYTES * u64::from(self.ppp.depth_bias_index);
        let constant = f64::from(f32::from_bits(read_u32(self.memory, at)?));
        let slope = f64::from(f32::from_bits(read_u32(self.memory, at + 4)?));
        let clamp = f64::from(f32::from_bits(read_u32(self.memory, at + 8)?));
        let p = [0, 1, 2].map(|i| [window[i].window[0], window[i].window[1]]);
        let plane = crate::platform::apple::agx::raster::plane::Plane::triangle(
            p,
            [0, 1, 2].map(|i| window[i].window[2]),
        );
        let m = plane.a.abs().max(plane.b.abs());
        let r = if self.pass.depth_16() {
            1.0
        } else {
            let largest = window.iter().map(|v| v.window[2].abs()).fold(0.0, f64::max);
            let biased = ((largest as f32).to_bits() >> F32_MANTISSA) & 0xff;
            let exponent = (biased as i32).max(1) - F32_BIAS;
            // 2^(e - 23) as an f64 (always a normal number).
            f64::from_bits(((exponent - F32_MANTISSA + F64_BIAS) as u64) << F64_MANTISSA)
        };
        let bias = constant * r + slope * m;
        Ok(if clamp > 0.0 {
            bias.min(clamp)
        } else if clamp < 0.0 {
            bias.max(clamp)
        } else {
            bias
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topologies_assemble_in_vulkan_order() {
        let ids: Vec<Option<u32>> = (0..5).map(Some).collect();
        let strip = assemble(primitive::TRIANGLE_STRIP, &ids).unwrap();
        assert_eq!(
            strip.iter().map(|(v, _)| v.clone()).collect::<Vec<_>>(),
            [vec![0, 1, 2], vec![1, 3, 2], vec![2, 3, 4]]
        );
        let fan = assemble(primitive::TRIANGLE_FAN, &ids).unwrap();
        assert_eq!(fan[0].0, [1, 2, 0]);
        let looped = assemble(primitive::LINE_LOOP, &ids[..3]).unwrap();
        assert_eq!(looped.last().unwrap().0, [2, 0]);
        // A cut restarts the strip; primitive IDs keep counting.
        let cut = [Some(0), Some(1), Some(2), None, Some(3), Some(4), Some(5)];
        let tris = assemble(primitive::TRIANGLE_STRIP, &cut).unwrap();
        assert_eq!(tris, [(vec![0, 1, 2], 0), (vec![3, 4, 5], 1)]);
        let quads = assemble(primitive::QUAD_STRIP, &(0..6).map(Some).collect::<Vec<_>>()).unwrap();
        assert_eq!(quads[1].0, [2, 3, 5, 4]);
        assert!(assemble(7, &ids).is_err());
    }

    #[test]
    fn the_uvs_layout_follows_output_select() {
        let mut ppp = PppState {
            varying_counts_32: [2, 1, 1],
            output_select: output::POINT_SIZE | output::RENDER_TARGET | 0b11,
            ..PppState::default()
        };
        let uvs = Uvs::new(&ppp, 12).unwrap();
        assert_eq!(uvs.classes.len(), 12);
        assert_eq!(uvs.classes[6], Interp::Flat);
        assert_eq!(uvs.classes[7], Interp::Linear);
        assert_eq!(
            (uvs.point_size, uvs.layer_viewport, uvs.clip),
            (Some(8), Some(9), 10..12)
        );
        assert!(Uvs::new(&ppp, 11).is_err());
        ppp.varying_counts_16 = [1, 0, 0];
        assert!(Uvs::new(&ppp, 12).is_err());
    }
}
