//! The Apple AGX G14G GPU (`sgx`, `gfx-asc`) of the T8112, modeled as a native
//! coprocessor at its AP-facing firmware protocol plus a GPU execution engine.
//! Apple's `armfw_g14g` is not executed. The chosen route, the full 26A434
//! interface inventory and the Known/Inferred/Unknown status are in
//! docs/research/agx.md.
//!
//! Layers, each its own submodule:
//! - [`firmware`]: the GFX RTKit application endpoints (0x20 message, 0x21
//!   doorbell) and the firmware-protocol state (initdata pointer, work and
//!   firmware-control doorbells).
//! - [`uat`]: the GPU address translator (16 KiB pages, three levels, paired
//!   TTBRs per context) and its page-table encodings and faults.
//!
//! Still to come (docs/research/agx.md §2, §4, §5): the initdata and ring
//! field layouts, the GFX MMIO register inventory, the shader-ISA interpreter
//! and command-stream executor, and the pixel-checked render harness.

pub mod firmware;
pub mod uat;
