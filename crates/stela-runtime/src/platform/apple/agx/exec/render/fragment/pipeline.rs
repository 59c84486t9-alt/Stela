//! Fragment USC, preshader and coefficient inputs, owned by 3D. TA keeps
//! the original PPP metadata without reading or running its pointees.

use super::super::super::{ShaderState, WorkError};
use super::super::{FragmentInputs, heap_sampler};
use crate::platform::apple::agx::{
    isa::machine::{Env, Fault, Memory, Program},
    stream::{
        cdm::extended_samplers,
        field, read_u32,
        usc::{self, FragmentProperties},
    },
};
use alloc::vec::Vec;

struct PipelineEnv<'a> {
    memory: &'a mut dyn Memory,
    pass: &'a FragmentInputs,
}
impl Memory for PipelineEnv<'_> {
    fn read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), Fault> {
        self.memory.read(address, bytes)
    }
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Fault> {
        self.memory.write(address, bytes)
    }
}
impl Env for PipelineEnv<'_> {
    fn no_varyings(&mut self) -> Result<(), &'static str> {
        Ok(())
    }
    fn sampler_heap(&mut self, index: u32) -> Result<[u8; 8], &'static str> {
        heap_sampler(self.memory, self.pass, index)
    }
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

/// Load a fragment shader's USC state and CF bindings and run its
/// preshader.
pub(super) fn load(
    memory: &mut dyn Memory,
    pass: &FragmentInputs,
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
    shader.run_preshader(&mut PipelineEnv { memory, pass }, program)?;
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
