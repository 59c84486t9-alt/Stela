//! Shared input handling for the Metal driver frontend.
//!
//! Parsing a library exposes its original AIR and metadata; it does not compile
//! shaders, initialize hardware, or establish any Metal capability. AGX machine
//! code archives are a different input and are not accepted as AIR libraries.
pub mod library;
