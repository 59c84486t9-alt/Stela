//! Every operation the driver's service accepts, and the call by which
//! the suite reaches it. The service's requests (`service/wire.rs`) and
//! encoded commands (`service/wire/commands.rs`) are the whole boundary
//! between Metal and the driver, so a code no case reaches is behaviour
//! the differential test cannot see. The test fails on a code without an
//! entry, an entry naming no code, and a call no runner or corpus source
//! makes.

/// How the suite reaches an operation.
enum Reach {
    /// A call in the runner or the corpus that only this operation serves.
    Call(&'static str),
    /// Reached without a call of its own, or left out, and why.
    Without(&'static str),
}

const OPERATIONS: &[(&str, Reach)] = &[
    ("Negotiate", Reach::Without("every case opens a connection")),
    (
        "Capabilities",
        Reach::Without("every case reads the capability block"),
    ),
    ("Release", Reach::Without("every case releases its objects")),
    (
        "Report",
        Reach::Without("the frontend's own log of what it could not do"),
    ),
    (
        "Poll",
        Reach::Without("every command buffer completes through it"),
    ),
    ("Commit", Reach::Without("every command buffer")),
    ("NewLibrary", Reach::Call("newLibraryWithData:")),
    ("LibraryFunctionNames", Reach::Call("functionNames")),
    (
        "LibraryExternFunctionNames",
        Reach::Call("externFunctionNames"),
    ),
    (
        "LibraryLinkedNames",
        Reach::Without(
            "pipelines of a library loaded from a file load the dynamic libraries it links",
        ),
    ),
    ("LibraryIdentity", Reach::Call("installName")),
    ("LibraryData", Reach::Call("[dynamic serializeToURL:")),
    ("NewSourceLibrary", Reach::Call("newLibraryWithSource:")),
    (
        "NewStitchedLibrary",
        Reach::Call("newLibraryWithStitchedDescriptor:"),
    ),
    ("NewArchive", Reach::Call("newBinaryArchiveWithDescriptor:")),
    ("ArchiveData", Reach::Call("[archive serializeToURL:")),
    ("NewFunction", Reach::Call("newFunctionWithName:")),
    ("FunctionReflection", Reach::Call(".functionType")),
    (
        "FunctionBindings",
        Reach::Call("MTLPipelineOptionBindingInfo"),
    ),
    (
        "ArgumentLayout",
        Reach::Call("newArgumentEncoderWithArguments:"),
    ),
    ("NewBuffer", Reach::Call("newBufferWithLength:")),
    ("BufferDidModifyRange", Reach::Call("didModifyRange:")),
    ("NewTexture", Reach::Call("newTextureWithDescriptor:")),
    (
        "NewTextureView",
        Reach::Call("newTextureViewWithPixelFormat:"),
    ),
    (
        "NewBufferTexture",
        Reach::Call("newTextureWithDescriptor:td offset:"),
    ),
    ("ReplaceRegion", Reach::Call("replaceRegion:")),
    ("GetBytes", Reach::Call("getBytes:")),
    ("NewSampler", Reach::Call("newSamplerStateWithDescriptor:")),
    ("NewHeap", Reach::Call("newHeapWithDescriptor:")),
    (
        "HeapBufferSizeAndAlign",
        Reach::Call("heapBufferSizeAndAlignWithLength:"),
    ),
    (
        "HeapTextureSizeAndAlign",
        Reach::Call("heapTextureSizeAndAlignWithDescriptor:"),
    ),
    ("NewHeapBuffer", Reach::Call("[placed newBufferWithLength:")),
    (
        "NewHeapTexture",
        Reach::Call("[placed newTextureWithDescriptor:"),
    ),
    ("HeapUsage", Reach::Call("usedSize")),
    ("MakeAliasable", Reach::Call("makeAliasable")),
    (
        "NewImportedBuffer",
        Reach::Call("newBufferWithBytesNoCopy:"),
    ),
    (
        "FormatAlignments",
        Reach::Call("minimumLinearTextureAlignmentForPixelFormat:"),
    ),
    (
        "SparseTileSize",
        Reach::Call("sparseTileSizeWithTextureType:"),
    ),
    (
        "NewRenderPipeline",
        Reach::Call("newRenderPipelineStateWithDescriptor:"),
    ),
    (
        "NewMeshPipeline",
        Reach::Call("newRenderPipelineStateWithMeshDescriptor:"),
    ),
    (
        "NewTilePipeline",
        Reach::Call("newRenderPipelineStateWithTileDescriptor:"),
    ),
    (
        "NewComputePipeline",
        Reach::Call("newComputePipelineStateWithDescriptor:"),
    ),
    ("FunctionHandle", Reach::Call("functionHandleWithFunction:")),
    (
        "NewFunctionTable",
        Reach::Call("newVisibleFunctionTableWithDescriptor:"),
    ),
    ("SetFunctions", Reach::Call("setFunction")),
    ("NewEvent", Reach::Call("newSharedEvent]")),
    ("EventSignaledValue", Reach::Call(".signaledValue)")),
    ("SetEventSignaledValue", Reach::Call("signaledValue =")),
    ("WaitEvent", Reach::Call("waitUntilSignaledValue:")),
    (
        "NewCounterBuffer",
        Reach::Call("newCounterSampleBufferWithDescriptor:"),
    ),
    ("ResolveCounters", Reach::Call("resolveCounterRange:")),
    ("SampleTimestamps", Reach::Call("sampleTimestamps:")),
    ("AllocatedSize", Reach::Call("currentAllocatedSize")),
    ("CommandBufferTimes", Reach::Call("GPUStartTime")),
    ("CompletedAfter", Reach::Call("encodeWaitForEvent:")),
    ("ShareObject", Reach::Call("newSharedTextureHandle]")),
    ("OpenSharedEvent", Reach::Call("newSharedEventWithHandle:")),
    (
        "OpenSharedTexture",
        Reach::Call("newSharedTextureWithHandle:"),
    ),
    (
        "NewIndirectCommandBuffer",
        Reach::Call("newIndirectCommandBufferWithDescriptor:"),
    ),
    ("IndirectResourceId", Reach::Call("gpuResourceID")),
    (
        "EncodeIndirect",
        Reach::Call("indirectRenderCommandAtIndex:"),
    ),
    ("ResetIndirect", Reach::Call("resetWithRange:")),
    ("CommandBufferCode::EndEncoding", Reach::Call("endEncoding")),
    (
        "CommandBufferCode::SignalEvent",
        Reach::Call("encodeSignalEvent:"),
    ),
    (
        "CommandBufferCode::WaitForEvent",
        Reach::Call("encodeWaitForEvent:"),
    ),
    (
        "CommandBufferCode::SampleCounters",
        Reach::Call("sampleCountersInBuffer:"),
    ),
    ("CommandBufferCode::LogBuffer", Reach::Call("logState")),
    ("ComputeCode::Begin", Reach::Call("computeCommandEncoder")),
    (
        "ComputeCode::SetPipeline",
        Reach::Call("setComputePipelineState:"),
    ),
    ("ComputeCode::SetBuffer", Reach::Call("setBuffer:")),
    (
        "ComputeCode::SetBufferOffset",
        Reach::Call("setBufferOffset:"),
    ),
    ("ComputeCode::SetBytes", Reach::Call("setBytes:")),
    (
        "ComputeCode::SetBufferStride",
        Reach::Call("[ce setBuffer:b offset:offset attributeStride:"),
    ),
    (
        "ComputeCode::SetBufferOffsetStride",
        Reach::Call("[ce setBufferOffset:offset attributeStride:"),
    ),
    (
        "ComputeCode::SetBytesStride",
        Reach::Call("[ce setBytes:bytes length:length attributeStride:"),
    ),
    ("ComputeCode::SetTexture", Reach::Call("setTexture:")),
    ("ComputeCode::SetSampler", Reach::Call("setSamplerState:")),
    (
        "ComputeCode::SetThreadgroupMemory",
        Reach::Call("[ce setThreadgroupMemoryLength:"),
    ),
    (
        "ComputeCode::SetImageblockSize",
        Reach::Call("setImageblockWidth:"),
    ),
    (
        "ComputeCode::DispatchThreadgroups",
        Reach::Call("dispatchThreadgroups:"),
    ),
    (
        "ComputeCode::DispatchThreads",
        Reach::Call("dispatchThreads:"),
    ),
    (
        "ComputeCode::DispatchIndirect",
        Reach::Call("dispatchThreadgroupsWithIndirectBuffer:"),
    ),
    (
        "ComputeCode::MemoryBarrier",
        Reach::Call("memoryBarrierWithScope:scope]"),
    ),
    (
        "ComputeCode::SetStageInRegion",
        Reach::Call("[e setStageInRegion:"),
    ),
    (
        "ComputeCode::SetStageInRegionIndirect",
        Reach::Call("setStageInRegionWithIndirectBuffer:"),
    ),
    ("BlitCode::Begin", Reach::Call("blitCommandEncoder")),
    (
        "BlitCode::CopyBuffer",
        Reach::Call("sourceOffset:0 toBuffer:shared"),
    ),
    (
        "BlitCode::CopyBufferToTexture",
        Reach::Call("sourceBytesPerRow:"),
    ),
    (
        "BlitCode::CopyTextureToBuffer",
        Reach::Call("destinationBytesPerRow:"),
    ),
    ("BlitCode::CopyTexture", Reach::Call("toTexture:")),
    ("BlitCode::CopyTextureSlices", Reach::Call("sliceCount:")),
    ("BlitCode::FillBuffer", Reach::Call("fillBuffer:")),
    (
        "BlitCode::GenerateMipmaps",
        Reach::Call("generateMipmapsForTexture:"),
    ),
    ("BlitCode::Synchronize", Reach::Call("synchronizeResource:")),
    (
        "BlitCode::SynchronizeTexture",
        Reach::Call("synchronizeTexture:"),
    ),
    ("BlitCode::ResolveCounters", Reach::Call("resolveCounters:")),
    (
        "IndirectCode::Execute",
        Reach::Call("withRange:NSMakeRange(number(x, @\"start\", 0)"),
    ),
    (
        "IndirectCode::ExecuteIndirect",
        Reach::Call("executeCommandsInBuffer:icb indirectBuffer:"),
    ),
    ("IndirectCode::Reset", Reach::Call("resetCommandsInBuffer:")),
    (
        "IndirectCode::Copy",
        Reach::Call("copyIndirectCommandBuffer:"),
    ),
    (
        "IndirectCode::Optimize",
        Reach::Call("optimizeIndirectCommandBuffer:"),
    ),
    (
        "IndirectRenderCode::SetPipeline",
        Reach::Call("set_render_pipeline_state"),
    ),
    (
        "IndirectRenderCode::SetBuffer",
        Reach::Call("[r setVertexBuffer:buffer"),
    ),
    (
        "IndirectRenderCode::SetVertexBufferStride",
        Reach::Call("[r setVertexBuffer:buffer offset:offset attributeStride:"),
    ),
    (
        "IndirectRenderCode::SetCullMode",
        Reach::Call("[r setCullMode:"),
    ),
    (
        "IndirectRenderCode::SetFrontFacingWinding",
        Reach::Call("[r setFrontFacingWinding:"),
    ),
    (
        "IndirectRenderCode::SetDepthBias",
        Reach::Call("[r setDepthBias:"),
    ),
    (
        "IndirectRenderCode::SetDepthStencilState",
        Reach::Call("[r setDepthStencilState:"),
    ),
    (
        "IndirectRenderCode::SetTriangleFillMode",
        Reach::Call("[r setTriangleFillMode:"),
    ),
    (
        "IndirectRenderCode::SetDepthClipMode",
        Reach::Call("[r setDepthClipMode:"),
    ),
    (
        "IndirectRenderCode::SetBarrier",
        Reach::Call("[r setBarrier]"),
    ),
    (
        "IndirectRenderCode::ClearBarrier",
        Reach::Call("[r clearBarrier]"),
    ),
    (
        "IndirectRenderCode::DrawPrimitives",
        Reach::Call("[r drawPrimitives:"),
    ),
    (
        "IndirectRenderCode::DrawIndexed",
        Reach::Call("[r drawIndexedPrimitives:"),
    ),
    (
        "IndirectRenderCode::DrawPatches",
        Reach::Call("[r drawPatches:"),
    ),
    (
        "IndirectRenderCode::DrawMeshThreadgroups",
        Reach::Call("[r drawMeshThreadgroups:"),
    ),
    (
        "IndirectRenderCode::DrawMeshThreads",
        Reach::Call("[r drawMeshThreads:"),
    ),
    ("IndirectRenderCode::Reset", Reach::Call("[r reset]")),
    (
        "IndirectRenderCode::SetObjectThreadgroupMemory",
        Reach::Call("[r setObjectThreadgroupMemoryLength:"),
    ),
    (
        "IndirectComputeCode::SetPipeline",
        Reach::Call("[k_ setComputePipelineState:"),
    ),
    (
        "IndirectComputeCode::SetBuffer",
        Reach::Call("setKernelBuffer:"),
    ),
    (
        "IndirectComputeCode::SetBufferStride",
        Reach::Call("[k_ setKernelBuffer:buffer offset:number(u, @\"offset\", 0) attributeStride:"),
    ),
    (
        "IndirectComputeCode::SetThreadgroupMemory",
        Reach::Call("[k_ setThreadgroupMemoryLength:"),
    ),
    (
        "IndirectComputeCode::SetImageblockSize",
        Reach::Call("[k_ setImageblockWidth:"),
    ),
    (
        "IndirectComputeCode::SetStageInRegion",
        Reach::Call("[k_ setStageInRegion:"),
    ),
    (
        "IndirectComputeCode::SetBarrier",
        Reach::Call("[k_ setBarrier]"),
    ),
    (
        "IndirectComputeCode::ClearBarrier",
        Reach::Call("[k_ clearBarrier]"),
    ),
    (
        "IndirectComputeCode::DispatchThreadgroups",
        Reach::Call("concurrentDispatchThreadgroups:"),
    ),
    (
        "IndirectComputeCode::DispatchThreads",
        Reach::Call("concurrent_dispatch_threads"),
    ),
    ("IndirectComputeCode::Reset", Reach::Call("[k_ reset]")),
    (
        "ResourceStateCode::Begin",
        Reach::Call("resourceStateCommandEncoder]"),
    ),
    (
        "ResourceStateCode::UpdateMappings",
        Reach::Call("updateTextureMappings:t mode:"),
    ),
    (
        "ResourceStateCode::UpdateMappingIndirect",
        Reach::Call("indirectBuffer:indirect indirectBufferOffset:"),
    ),
    (
        "ResourceStateCode::MoveMappings",
        Reach::Call("moveTextureMappingsFromTexture:"),
    ),
    (
        "RenderCode::Begin",
        Reach::Call("renderCommandEncoderWithDescriptor:"),
    ),
    (
        "RenderCode::SetPipeline",
        Reach::Call("setRenderPipelineState:"),
    ),
    ("RenderCode::SetBuffer", Reach::Call("setVertexBuffer:")),
    (
        "RenderCode::SetBufferOffset",
        Reach::Call("setVertexBufferOffset:"),
    ),
    ("RenderCode::SetBytes", Reach::Call("setVertexBytes:")),
    ("RenderCode::SetTexture", Reach::Call("setFragmentTexture:")),
    (
        "RenderCode::SetSampler",
        Reach::Call("setFragmentSamplerState:"),
    ),
    (
        "RenderCode::SetVertexBufferStride",
        Reach::Call("attributeStride:8"),
    ),
    (
        "RenderCode::SetVertexBufferOffsetStride",
        Reach::Call("[re setVertexBufferOffset:offset attributeStride:"),
    ),
    ("RenderCode::SetViewports", Reach::Call("setViewports:")),
    (
        "RenderCode::SetScissorRects",
        Reach::Call("setScissorRects:"),
    ),
    ("RenderCode::SetCullMode", Reach::Call("[e setCullMode:")),
    (
        "RenderCode::SetFrontFacingWinding",
        Reach::Call("[e setFrontFacingWinding:"),
    ),
    ("RenderCode::SetDepthBias", Reach::Call("[e setDepthBias:")),
    (
        "RenderCode::SetDepthStencilState",
        Reach::Call("[e setDepthStencilState:"),
    ),
    (
        "RenderCode::SetStencilReference",
        Reach::Call("setStencilFrontReferenceValue:"),
    ),
    (
        "RenderCode::SetBlendColor",
        Reach::Call("setBlendColorRed:"),
    ),
    (
        "RenderCode::SetTriangleFillMode",
        Reach::Call("[e setTriangleFillMode:"),
    ),
    (
        "RenderCode::SetDepthClipMode",
        Reach::Call("[e setDepthClipMode:"),
    ),
    (
        "RenderCode::SetVertexAmplification",
        Reach::Call("setVertexAmplificationCount:"),
    ),
    (
        "RenderCode::SetVisibilityResultMode",
        Reach::Call("setVisibilityResultMode:"),
    ),
    (
        "RenderCode::SetColorStoreAction",
        Reach::Call("setColorStoreAction:"),
    ),
    (
        "RenderCode::SetDepthStoreAction",
        Reach::Call("setDepthStoreAction:"),
    ),
    (
        "RenderCode::SetStencilStoreAction",
        Reach::Call("setStencilStoreAction:"),
    ),
    ("RenderCode::MemoryBarrier", Reach::Call("afterStages:")),
    ("RenderCode::DrawPrimitives", Reach::Call("drawPrimitives:")),
    (
        "RenderCode::DrawIndexed",
        Reach::Call("drawIndexedPrimitives:"),
    ),
    (
        "RenderCode::DrawIndirect",
        Reach::Call("drawPrimitives:primitive indirectBuffer:"),
    ),
    (
        "RenderCode::DrawIndexedIndirect",
        Reach::Call("indexBufferOffset:number(r, @\"index_offset\", 0) indirectBuffer:"),
    ),
    (
        "RenderCode::SetTessellationFactorBuffer",
        Reach::Call("setTessellationFactorBuffer:"),
    ),
    (
        "RenderCode::SetTessellationFactorScale",
        Reach::Call("setTessellationFactorScale:"),
    ),
    ("RenderCode::DrawPatches", Reach::Call("patchStart:")),
    (
        "RenderCode::DrawPatchesIndirect",
        Reach::Call("patchIndexBufferOffset:0 indirectBuffer:"),
    ),
    (
        "RenderCode::DrawMeshThreadgroups",
        Reach::Call("[e drawMeshThreadgroups:"),
    ),
    (
        "RenderCode::DrawMeshThreads",
        Reach::Call("[e drawMeshThreads:"),
    ),
    (
        "RenderCode::DrawMeshIndirect",
        Reach::Call("drawMeshThreadgroupsWithIndirectBuffer:"),
    ),
    (
        "RenderCode::SetColorStoreActionOptions",
        Reach::Call("setColorStoreActionOptions:"),
    ),
    (
        "RenderCode::SetDepthStoreActionOptions",
        Reach::Call("setDepthStoreActionOptions:"),
    ),
    (
        "RenderCode::SetStencilStoreActionOptions",
        Reach::Call("setStencilStoreActionOptions:"),
    ),
    (
        "RenderCode::SetObjectThreadgroupMemory",
        Reach::Call("[e setObjectThreadgroupMemoryLength:"),
    ),
    (
        "RenderCode::SetTilePipeline",
        Reach::Call("[e setRenderPipelineState:tile_pipelines[k]]"),
    ),
    (
        "RenderCode::SetTileThreadgroupMemory",
        Reach::Call("[e setThreadgroupMemoryLength:"),
    ),
    (
        "RenderCode::DispatchThreadsPerTile",
        Reach::Call("dispatchThreadsPerTile:"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeSet, fs};

    fn read(path: &str) -> String {
        fs::read_to_string(crate::tools::root().join(path)).unwrap()
    }

    /// The request names and `Enum::Variant` command codes, in source order.
    fn codes() -> Vec<String> {
        let variant = |line: &str| {
            let (name, rest) = line.trim().split_once(" = 0x")?;
            (name.chars().all(char::is_alphanumeric)
                && name.starts_with(char::is_uppercase)
                && !rest.is_empty())
            .then(|| name.to_string())
        };
        let wire = read("crates/stela-driver-gpu/src/metal/service/wire.rs");
        let table = wire.split_once("operations! {").unwrap().1;
        let mut codes: Vec<String> = table
            .lines()
            .take_while(|l| !l.starts_with('}'))
            .filter(|l| l.contains("=>"))
            .filter_map(variant)
            .collect();
        let commands = read("crates/stela-driver-gpu/src/metal/service/wire/commands.rs");
        let mut current: Option<&str> = None;
        for line in commands.lines() {
            if let Some(rest) = line
                .trim()
                .strip_prefix("pub enum ")
                .or_else(|| line.trim().strip_prefix("enum "))
            {
                current = rest
                    .split(|c: char| !c.is_alphanumeric())
                    .next()
                    .filter(|n| n.ends_with("Code"));
            } else if line.trim() == "}" {
                current = None;
            } else if let Some(e) = current
                && let Some(v) = variant(line)
            {
                codes.push(format!("{e}::{v}"));
            }
        }
        codes
    }

    #[test]
    fn every_driver_operation_has_a_case() {
        let root = "crates/stela-driver-gpu/tests/metal_suite";
        let mut text = read(&format!("{root}/runner.m"));
        for entry in fs::read_dir(crate::tools::root().join(root).join("corpus")).unwrap() {
            text.push_str(&fs::read_to_string(entry.unwrap().path()).unwrap());
        }
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let codes = codes();
        assert!(codes.len() > 150, "found only {} codes", codes.len());
        let known: BTreeSet<&str> = OPERATIONS.iter().map(|(n, _)| *n).collect();
        let unmapped: Vec<&String> = codes
            .iter()
            .filter(|c| !known.contains(c.as_str()))
            .collect();
        assert!(
            unmapped.is_empty(),
            "driver operations without a case: {unmapped:?}"
        );
        let names: BTreeSet<&str> = codes.iter().map(String::as_str).collect();
        let stale: Vec<&str> = known
            .iter()
            .copied()
            .filter(|n| !names.contains(n))
            .collect();
        assert!(
            stale.is_empty(),
            "entries for operations the driver no longer has: {stale:?}"
        );
        let unreached: Vec<(&str, &str)> = OPERATIONS
            .iter()
            .filter_map(|(n, r)| match r {
                Reach::Call(call) if !text.contains(call) => Some((*n, *call)),
                _ => None,
            })
            .collect();
        assert!(
            unreached.is_empty(),
            "calls the suite no longer makes: {unreached:?}"
        );
        for (name, reach) in OPERATIONS {
            if let Reach::Without(why) = reach {
                assert!(!why.is_empty(), "{name} needs a reason");
            }
        }
    }
}
