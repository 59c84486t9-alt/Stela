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
//! - [`sgx`]: the `sgx` register block the AP touches directly (identity,
//!   core mask, GPC controls, the MMU configuration that roots the UAT).
//! - [`uat`]: the GPU address translator (16 KiB pages, three levels, paired
//!   TTBRs per context), its page-table encodings and faults, and the stream
//!   IOMMU the firmware and GPU reach memory through.
//! - [`initdata`]: the initdata root, the objects it names and the ring
//!   directory.
//! - [`ring`]: the shared-memory ring layout (state block, 256 entries,
//!   descriptors) and the firmware's consume.
//! - [`isa`]: a bit-exact decoder and x86-host interpreter for a bounded
//!   subset of the AGX2 shader ISA.
//! - [`exec`]: a compute-style dispatch that runs a shader over a surface grid
//!   and stores checked pixels, with an in-order fence.
//!
//! Still to come (docs/research/agx.md §2, §5): the channel command layouts
//! behind the data-master entries, the rest of the shader ISA (integer,
//! memory/PBE, texture, control flow), the VDM/CDM/PPP control streams, the
//! tiler/rasterizer, texture formats and compression, and driving the
//! executor from a real firmware work queue.

pub mod exec;
pub mod firmware;
pub mod initdata;
pub mod isa;
pub mod ring;
pub mod sgx;
pub mod uat;
