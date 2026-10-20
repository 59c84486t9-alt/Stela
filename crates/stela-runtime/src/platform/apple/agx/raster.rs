//! Fixed-function rasterization: the steps between vertex outputs and
//! fragment shading that the hardware performs without a shader.
//!
//! - [`clip`]: clipping against the view volume and user clip distances.
//! - [`coverage`]: sample coverage of triangles, lines and points.
//! - [`plane`]: the coefficient planes fragment shaders interpolate from.
//! - [`zs`]: depth and stencil tests.
//!
//! The render pass that drives them is [`super::exec::render`].

pub mod clip;
pub mod coverage;
pub mod plane;
pub mod zs;
