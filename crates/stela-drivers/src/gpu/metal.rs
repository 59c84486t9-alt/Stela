//! Stela's Metal device over a Vulkan backend.
//!
//! The guest's unchanged Metal framework reaches this device through the
//! frontend; every Metal object and command lowers here to the internal
//! [`vulkan`] boundary, which the vendor's Mesa driver executes (NVK for the
//! [`nvidia`] route). Capabilities derive from the Vulkan device, the AIR
//! compiler and this implementation together ([`capabilities`]).
//!
//! [`library`] parses Metal libraries and exposes their original AIR and
//! metadata, which [`compiler`] lowers through the AIR compiler service. AGX machine code archives are a different input and are not
//! accepted as AIR libraries.
#[macro_use]
mod macros;

pub mod abi;
pub mod binding;
pub mod capabilities;
pub mod command_buffer;
pub mod compiler;
pub mod device;
pub mod error;
pub mod hazard;
pub mod heap;
pub mod indirect;
pub mod library;
#[cfg(feature = "metal-vulkan")]
pub mod native;
pub mod nvidia;
pub mod pass;
pub mod pipeline;
pub mod pixel_format;
pub mod resource;
pub mod sampler;
pub mod shader;
pub mod sparse;
pub mod upload;
pub mod vertex;
pub mod vulkan;
