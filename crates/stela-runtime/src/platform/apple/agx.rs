//! The Apple AGX GPUs (`sgx`, `gfx-asc`), modeled as a native coprocessor at
//! their AP-facing firmware protocol plus a GPU execution engine. Apple's GFX
//! firmware is not executed. The chosen route, the full 26A434 interface
//! inventory and the Known/Inferred/Unknown status are in
//! docs/research/agx.md; [`generation`] names every SoC's GPU and which
//! families the model implements (G14G today).
//!
//! Layers, each its own submodule:
//! - [`generation`]: the census of every 26A434 GPU (compatible, kext,
//!   firmware, identity, MMU layout, initdata magic) and admission.
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
//! - [`channel`]: a channel's command queue, the commands it names (type,
//!   stream, completion stamp) and the command-stream records.
//! - [`signal`]: the commands that need no GPU work (shared-event and
//!   dashboard signals), run to completion.
//! - [`event`]: the firmware event ring's producer and the entries the kext
//!   reads (Flag, shared-event signal, CLPC notice).
//! - [`isa`]: the AGX2 shader ISA, decoded from tables generated out of
//!   Mesa's `AGX2.xml` and interpreted a SIMD group at a time.
//! - [`format`]: pixel and texture formats, layouts, compression and
//!   sampling.
//! - [`stream`]: the CDM, VDM, PPP and USC control streams.
//! - [`raster`]: clipping, coverage, coefficient planes and depth/stencil
//!   tests.
//! - [`exec`]: the execution engine that runs those streams' work.
//! - [`work`]: the bridge that runs a GPU-work channel command on the engine
//!   in the submitting UAT context and completes it with its stamps and
//!   events.
//!
//! The requirement matrix and its statuses are docs/research/agx.md §5.

pub mod channel;
pub mod event;
pub mod exec;
pub mod firmware;
pub mod firmware_image;
pub mod format;
pub mod generation;
pub mod initdata;
pub mod isa;
pub mod pio;
pub mod raster;
pub mod ring;
pub mod sgx;
pub mod signal;
pub mod stream;
pub mod uat;
pub mod work;
pub mod work_decode;
