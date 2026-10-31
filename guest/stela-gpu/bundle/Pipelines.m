/* Render, mesh and compute pipelines, function tables and their reflection. */
#include "Bundle.h"

/* Handles of a descriptor's objects, for the length of one request. */
typedef struct {
	uint64_t *handles;
	size_t count;
} HandleList;

static StelaSpan handle_list(NSArray *objects, StelaSpan *spans, size_t *used, uint64_t **storage)
{
	NSUInteger count = objects.count;
	if (count == 0) {
		return stela_span(NULL, 0);
	}
	uint64_t *handles = malloc(count * sizeof(*handles));
	for (NSUInteger i = 0; i < count; i++) {
		handles[i] = ((StelaGPUObject *)[objects objectAtIndex:i])->_handle;
	}
	storage[*used] = handles;
	StelaSpan span = stela_span(handles, count * sizeof(*handles));
	spans[(*used)++] = span;
	return span;
}

/* What one request's linked functions need kept: three spans a stage. */
typedef struct {
	StelaSpan spans[9];
	uint64_t *storage[9];
	size_t used;
} Linked;

static void linked_functions(Linked *linked, id functions, NSArray *libraries, NSUInteger depth,
			     StelaLinkedFunctionsRecord *record)
{
	*record = (StelaLinkedFunctionsRecord){
		.functions = handle_list([functions functions], linked->spans, &linked->used, linked->storage),
		.private_functions = handle_list([functions privateFunctions], linked->spans, &linked->used, linked->storage),
		.libraries = handle_list(libraries, linked->spans, &linked->used, linked->storage),
		.max_call_stack_depth = depth,
	};
}

static void linked_free(Linked *linked)
{
	for (size_t i = 0; i < linked->used; i++) {
		free(linked->storage[i]);
	}
}

static void targets_record(id descriptor, StelaRenderTargetsRecord *record)
{
	id attachments = [descriptor colorAttachments];
	for (NSUInteger i = 0; i < 8; i++) {
		id attachment = [attachments objectAtIndexedSubscript:i];
		record->color_attachments[i] = (StelaColorAttachmentRecord){
			.pixel_format = [attachment pixelFormat],
			.source_rgb_blend_factor = [attachment sourceRGBBlendFactor],
			.destination_rgb_blend_factor = [attachment destinationRGBBlendFactor],
			.rgb_blend_operation = [attachment rgbBlendOperation],
			.source_alpha_blend_factor = [attachment sourceAlphaBlendFactor],
			.destination_alpha_blend_factor = [attachment destinationAlphaBlendFactor],
			.alpha_blend_operation = [attachment alphaBlendOperation],
			.write_mask = [attachment writeMask],
			.blending_enabled = [attachment isBlendingEnabled],
		};
	}
	record->depth_attachment_pixel_format = [descriptor depthAttachmentPixelFormat];
	record->stencil_attachment_pixel_format = [descriptor stencilAttachmentPixelFormat];
	record->raster_sample_count = [descriptor rasterSampleCount];
	record->alpha_to_coverage_enabled = [descriptor isAlphaToCoverageEnabled];
	record->alpha_to_one_enabled = [descriptor isAlphaToOneEnabled];
	record->rasterization_enabled = [descriptor isRasterizationEnabled];
}

static void attributes_record(id source, StelaAttributeRecord *attributes, StelaLayoutRecord *layouts)
{
	id declared = [source attributes];
	id laid = [source layouts];
	for (NSUInteger i = 0; i < 31; i++) {
		id attribute = [declared objectAtIndexedSubscript:i];
		attributes[i] = (StelaAttributeRecord){
			.format = [attribute format],
			.offset = [attribute offset],
			.buffer_index = [attribute bufferIndex],
		};
		id layout = [laid objectAtIndexedSubscript:i];
		layouts[i] = (StelaLayoutRecord){
			.stride = [layout stride],
			.step_function = [layout stepFunction],
			.step_rate = [layout stepRate],
		};
	}
}

static NSError *pipeline_error(const StelaFailure *failure)
{
	return stela_error(MTLLibraryErrorDomain, failure->status == StelaStatusUnsupported ? MTLLibraryErrorUnsupported
											    : MTLLibraryErrorCompileFailure,
			   failure);
}

@implementation StelaGPURenderReflection
@end

@implementation StelaGPUComputeReflection
@end

@implementation StelaGPUFunctionHandle

- (NSUInteger)functionType
{
	return _function->_functionType;
}

- (NSString *)name
{
	return _function->_name;
}

- (id)device
{
	return _function->_device;
}

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_value};
}

@end

@implementation StelaGPUFunctionTable

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_gpuAddress};
}

- (void)setFunctions:(const id __unsafe_unretained[])functions withRange:(NSRange)range
{
	uint64_t *handles = calloc(range.length, sizeof(*handles));
	for (NSUInteger i = 0; i < range.length; i++) {
		handles[i] = functions[i] ? ((StelaGPUFunctionHandle *)functions[i])->_value : 0;
	}
	StelaSetFunctionsRequest request = {
		.table = _handle,
		.index = range.location,
		.handles = stela_span(handles, range.length * sizeof(*handles)),
	};
	StelaEmpty nothing;
	StelaFailure failure;
	StelaSpans spans = {.reads = &request.handles, .read_count = 1};
	if (STELA_CALL_SPANS(&_device->_gate, SetFunctions, &request, &nothing, spans, &failure) != StelaStatusOk) {
		stela_report("setFunctions:withRange:", &failure);
	}
	free(handles);
}

- (void)setFunction:(id)function atIndex:(NSUInteger)index
{
	__unsafe_unretained id functions[1] = {function};
	[self setFunctions:functions withRange:(NSRange){index, 1}];
}

@end

/* The pipelines' shared ways to functions and tables. */
static id function_handle(StelaGPUDevice *device, uint64_t pipeline, StelaGPUFunction *function, uint64_t stage)
{
	StelaFunctionHandleRequest request = {.pipeline = pipeline, .function = function->_handle, .stage = stage};
	StelaFunctionHandleResponse response = {};
	StelaFailure failure;
	if (STELA_CALL(&device->_gate, FunctionHandle, &request, &response, &failure) != StelaStatusOk) {
		stela_report("a function handle", &failure);
		return nil;
	}
	if (response.value == 0) {
		return nil;
	}
	StelaGPUFunctionHandle *handle = [StelaGPUFunctionHandle new];
	handle->_value = response.value;
	handle->_function = function;
	return handle;
}

static id function_table(StelaGPUDevice *device, id descriptor)
{
	StelaNewFunctionTableRequest request = {.function_count = [descriptor functionCount]};
	StelaBufferResponse response;
	StelaFailure failure;
	if (STELA_CALL(&device->_gate, NewFunctionTable, &request, &response, &failure) != StelaStatusOk) {
		stela_report("a visible function table", &failure);
		return nil;
	}
	StelaGPUFunctionTable *table = [[StelaGPUFunctionTable alloc] initWithDevice:device
									    response:&response
									     options:MTLStorageModePrivate
										     << MTLResourceStorageModeShift
									      length:request.function_count
										      * sizeof(uint64_t)];
	table->_functionCount = request.function_count;
	return table;
}

@implementation StelaGPURenderPipeline

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_resourceID};
}

- (BOOL)supportIndirectCommandBuffers
{
	return _supportIndirectCommandBuffers;
}

- (NSUInteger)maxTotalThreadsPerObjectThreadgroup
{
	return _maxTotalThreadsPerObjectThreadgroup;
}

- (NSUInteger)maxTotalThreadsPerMeshThreadgroup
{
	return _maxTotalThreadsPerMeshThreadgroup;
}

- (NSUInteger)objectThreadExecutionWidth
{
	return _objectThreadExecutionWidth;
}

- (NSUInteger)meshThreadExecutionWidth
{
	return _meshThreadExecutionWidth;
}

- (NSUInteger)imageblockSampleLength
{
	return 0;
}

- (NSUInteger)imageblockMemoryLengthForDimensions:(MTLSize)size
{
	(void)size;
	return 0;
}

- (id)functionHandleWithFunction:(id)function stage:(NSUInteger)stage
{
	return function_handle(_device, _handle, function, stage);
}

- (id)newVisibleFunctionTableWithDescriptor:(id)descriptor stage:(NSUInteger)stage
{
	(void)stage;
	return function_table(_device, descriptor);
}

- (id)newIntersectionFunctionTableWithDescriptor:(id)descriptor stage:(NSUInteger)stage
{
	(void)descriptor;
	(void)stage;
	return nil;
}

@end

@implementation StelaGPUComputePipeline

- (MTLResourceID)gpuResourceID
{
	return (MTLResourceID){_resourceID};
}

- (BOOL)supportIndirectCommandBuffers
{
	return _supportIndirectCommandBuffers;
}

- (NSUInteger)maxTotalThreadsPerThreadgroup
{
	return _maxTotalThreadsPerThreadgroup;
}

- (NSUInteger)threadExecutionWidth
{
	return _threadExecutionWidth;
}

- (NSUInteger)staticThreadgroupMemoryLength
{
	return _staticThreadgroupMemoryLength;
}

- (NSUInteger)imageblockMemoryLengthForDimensions:(MTLSize)size
{
	(void)size;
	return 0;
}

- (id)functionHandleWithFunction:(id)function
{
	return function_handle(_device, _handle, function, 0);
}

- (id)newVisibleFunctionTableWithDescriptor:(id)descriptor
{
	return function_table(_device, descriptor);
}

- (id)newIntersectionFunctionTableWithDescriptor:(id)descriptor
{
	(void)descriptor;
	return nil;
}

- (id)newComputePipelineStateWithAdditionalBinaryFunctions:(NSArray *)functions error:(NSError **)error
{
	(void)functions;
	if (error) {
		StelaFailure failure = {.status = StelaStatusUnsupported, .reason = "binary functions"};
		*error = pipeline_error(&failure);
	}
	return nil;
}

@end

@implementation StelaGPUDevice (Pipelines)

static id render_pipeline(StelaGPUDevice *device, const StelaRenderPipelineResponse *response, id descriptor,
			  BOOL indirect)
{
	StelaGPURenderPipeline *pipeline = [[StelaGPURenderPipeline alloc] initWithDevice:device
										   handle:response->handle];
	pipeline->_resourceID = response->resource_id;
	pipeline->_maxTotalThreadsPerObjectThreadgroup = response->max_total_threads_per_object_threadgroup;
	pipeline->_maxTotalThreadsPerMeshThreadgroup = response->max_total_threads_per_mesh_threadgroup;
	pipeline->_objectThreadExecutionWidth = response->object_thread_execution_width;
	pipeline->_meshThreadExecutionWidth = response->mesh_thread_execution_width;
	pipeline->_supportIndirectCommandBuffers = indirect;
	pipeline.label = [descriptor label];
	return pipeline;
}

- (id)newRenderPipelineStateWithDescriptor:(id)descriptor
				   options:(NSUInteger)options
				reflection:(id *)reflection
				     error:(NSError **)error
{
	StelaGPUFunction *vertex = [descriptor vertexFunction];
	StelaGPUFunction *fragment = [descriptor fragmentFunction];
	id layout = [descriptor vertexDescriptor];
	BOOL indirect = [descriptor supportIndirectCommandBuffers];
	StelaNewRenderPipelineRequest request = {
		.vertex_function = vertex->_handle,
		.fragment_function = fragment ? fragment->_handle : 0,
		.input_primitive_topology = [descriptor inputPrimitiveTopology],
		.max_vertex_amplification_count = [descriptor maxVertexAmplificationCount],
		.tessellation = {
			.partition_mode = [descriptor tessellationPartitionMode],
			.max_tessellation_factor = [descriptor maxTessellationFactor],
			.factor_format = [descriptor tessellationFactorFormat],
			.control_point_index_type = [descriptor tessellationControlPointIndexType],
			.factor_step_function = [descriptor tessellationFactorStepFunction],
			.output_winding_order = [descriptor tessellationOutputWindingOrder],
			.factor_scale_enabled = [descriptor isTessellationFactorScaleEnabled],
		},
		.flags = (layout ? StelaPipelineFlags_DESCRIBED_INPUT : 0)
			 | (indirect ? StelaPipelineFlags_INDIRECT_COMMAND_BUFFERS : 0),
	};
	targets_record(descriptor, &request.targets);
	if (layout) {
		attributes_record(layout, request.vertex_descriptor.attributes, request.vertex_descriptor.layouts);
	}
	Linked linked = {};
	linked_functions(&linked, [descriptor vertexLinkedFunctions], [descriptor vertexPreloadedLibraries],
			 [descriptor maxVertexCallStackDepth], &request.vertex_linked_functions);
	linked_functions(&linked, [descriptor fragmentLinkedFunctions], [descriptor fragmentPreloadedLibraries],
			 [descriptor maxFragmentCallStackDepth], &request.fragment_linked_functions);
	StelaRenderPipelineResponse response;
	StelaFailure failure;
	StelaSpans spans = {.reads = linked.spans, .read_count = linked.used};
	uint32_t status = STELA_CALL_SPANS(&_gate, NewRenderPipeline, &request, &response, spans, &failure);
	linked_free(&linked);
	if (status != StelaStatusOk) {
		if (error) {
			*error = pipeline_error(&failure);
		}
		return nil;
	}
	if (reflection) {
		StelaGPURenderReflection *gathered = [StelaGPURenderReflection new];
		if (options & MTLPipelineOptionBindingInfo) {
			gathered.vertexBindings = [StelaGPUReflection bindingsOfFunction:vertex];
			gathered.fragmentBindings = fragment ? [StelaGPUReflection bindingsOfFunction:fragment]
							     : [NSArray array];
		}
		*reflection = gathered;
	}
	return render_pipeline(self, &response, descriptor, indirect);
}

- (id)newRenderPipelineStateWithDescriptor:(id)descriptor error:(NSError **)error
{
	return [self newRenderPipelineStateWithDescriptor:descriptor options:0 reflection:NULL error:error];
}

- (void)newRenderPipelineStateWithDescriptor:(id)descriptor
				     options:(NSUInteger)options
			   completionHandler:(void (^)(id, id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		id reflection = nil;
		NSError *error = nil;
		id pipeline = [self newRenderPipelineStateWithDescriptor:descriptor
								 options:options
							      reflection:&reflection
								   error:&error];
		handler(pipeline, reflection, error);
	});
}

- (void)newRenderPipelineStateWithDescriptor:(id)descriptor completionHandler:(void (^)(id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		NSError *error = nil;
		id pipeline = [self newRenderPipelineStateWithDescriptor:descriptor error:&error];
		handler(pipeline, error);
	});
}

- (id)newRenderPipelineStateWithMeshDescriptor:(id)descriptor
				       options:(NSUInteger)options
				    reflection:(id *)reflection
					 error:(NSError **)error
{
	StelaGPUFunction *object = [descriptor objectFunction];
	StelaGPUFunction *mesh = [descriptor meshFunction];
	StelaGPUFunction *fragment = [descriptor fragmentFunction];
	BOOL indirect = [descriptor supportIndirectCommandBuffers];
	StelaNewMeshPipelineRequest request = {
		.object_function = object ? object->_handle : 0,
		.mesh_function = mesh->_handle,
		.fragment_function = fragment ? fragment->_handle : 0,
		.max_vertex_amplification_count = [descriptor maxVertexAmplificationCount],
		.max_total_threads_per_object_threadgroup = [descriptor maxTotalThreadsPerObjectThreadgroup],
		.max_total_threads_per_mesh_threadgroup = [descriptor maxTotalThreadsPerMeshThreadgroup],
		.payload_memory_length = [descriptor payloadMemoryLength],
		.flags = (indirect ? StelaPipelineFlags_INDIRECT_COMMAND_BUFFERS : 0)
			 | ([descriptor objectThreadgroupSizeIsMultipleOfThreadExecutionWidth]
				    ? StelaPipelineFlags_OBJECT_THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH
				    : 0)
			 | ([descriptor meshThreadgroupSizeIsMultipleOfThreadExecutionWidth]
				    ? StelaPipelineFlags_MESH_THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH
				    : 0),
	};
	targets_record(descriptor, &request.targets);
	Linked linked = {};
	linked_functions(&linked, [descriptor objectLinkedFunctions], nil, 1, &request.object_linked_functions);
	linked_functions(&linked, [descriptor meshLinkedFunctions], nil, 1, &request.mesh_linked_functions);
	linked_functions(&linked, [descriptor fragmentLinkedFunctions], nil, 1, &request.fragment_linked_functions);
	StelaRenderPipelineResponse response;
	StelaFailure failure;
	StelaSpans spans = {.reads = linked.spans, .read_count = linked.used};
	uint32_t status = STELA_CALL_SPANS(&_gate, NewMeshPipeline, &request, &response, spans, &failure);
	linked_free(&linked);
	if (status != StelaStatusOk) {
		if (error) {
			*error = pipeline_error(&failure);
		}
		return nil;
	}
	if (reflection) {
		StelaGPURenderReflection *gathered = [StelaGPURenderReflection new];
		if (options & MTLPipelineOptionBindingInfo) {
			gathered.objectBindings = object ? [StelaGPUReflection bindingsOfFunction:object]
							 : [NSArray array];
			gathered.meshBindings = [StelaGPUReflection bindingsOfFunction:mesh];
			gathered.fragmentBindings = fragment ? [StelaGPUReflection bindingsOfFunction:fragment]
							     : [NSArray array];
		}
		*reflection = gathered;
	}
	return render_pipeline(self, &response, descriptor, indirect);
}

- (void)newRenderPipelineStateWithMeshDescriptor:(id)descriptor
					 options:(NSUInteger)options
			       completionHandler:(void (^)(id, id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		id reflection = nil;
		NSError *error = nil;
		id pipeline = [self newRenderPipelineStateWithMeshDescriptor:descriptor
								     options:options
								  reflection:&reflection
								       error:&error];
		handler(pipeline, reflection, error);
	});
}

/* Tile shading needs tile memory, which only Apple's GPUs have. */
- (id)newRenderPipelineStateWithTileDescriptor:(id)descriptor
				       options:(NSUInteger)options
				    reflection:(id *)reflection
					 error:(NSError **)error
{
	(void)descriptor;
	(void)options;
	(void)reflection;
	if (error) {
		StelaFailure failure = {.status = StelaStatusUnsupported, .reason = "tile shading"};
		*error = pipeline_error(&failure);
	}
	return nil;
}

- (id)newComputePipelineStateWithDescriptor:(id)descriptor
				    options:(NSUInteger)options
				 reflection:(id *)reflection
				      error:(NSError **)error
{
	StelaGPUFunction *function = [descriptor computeFunction];
	id input = [descriptor stageInputDescriptor];
	BOOL indirect = [descriptor supportIndirectCommandBuffers];
	StelaNewComputePipelineRequest request = {
		.compute_function = function->_handle,
		.max_total_threads_per_threadgroup = [descriptor maxTotalThreadsPerThreadgroup],
		.flags = (input ? StelaPipelineFlags_DESCRIBED_INPUT : 0)
			 | (indirect ? StelaPipelineFlags_INDIRECT_COMMAND_BUFFERS : 0)
			 | ([descriptor threadGroupSizeIsMultipleOfThreadExecutionWidth]
				    ? StelaPipelineFlags_THREADGROUP_SIZE_IS_MULTIPLE_OF_WIDTH
				    : 0),
	};
	if (input) {
		attributes_record(input, request.stage_input.attributes, request.stage_input.layouts);
		request.stage_input.index_type = [input indexType];
		request.stage_input.index_buffer_index = [input indexBufferIndex];
	}
	Linked linked = {};
	linked_functions(&linked, [descriptor linkedFunctions], [descriptor preloadedLibraries],
			 [descriptor maxCallStackDepth], &request.linked_functions);
	StelaComputePipelineResponse response;
	StelaFailure failure;
	StelaSpans spans = {.reads = linked.spans, .read_count = linked.used};
	uint32_t status = STELA_CALL_SPANS(&_gate, NewComputePipeline, &request, &response, spans, &failure);
	linked_free(&linked);
	if (status != StelaStatusOk) {
		if (error) {
			*error = pipeline_error(&failure);
		}
		return nil;
	}
	if (reflection) {
		StelaGPUComputeReflection *gathered = [StelaGPUComputeReflection new];
		if (options & MTLPipelineOptionBindingInfo) {
			gathered.bindings = [StelaGPUReflection bindingsOfFunction:function];
		}
		*reflection = gathered;
	}
	StelaGPUComputePipeline *pipeline = [[StelaGPUComputePipeline alloc] initWithDevice:self
										     handle:response.handle];
	pipeline->_resourceID = response.resource_id;
	pipeline->_maxTotalThreadsPerThreadgroup = response.max_total_threads_per_threadgroup;
	pipeline->_threadExecutionWidth = response.thread_execution_width;
	pipeline->_staticThreadgroupMemoryLength = response.static_threadgroup_memory_length;
	pipeline->_supportIndirectCommandBuffers = indirect;
	pipeline.label = [descriptor label];
	return pipeline;
}

- (void)newComputePipelineStateWithDescriptor:(id)descriptor
				      options:(NSUInteger)options
			    completionHandler:(void (^)(id, id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		id reflection = nil;
		NSError *error = nil;
		id pipeline = [self newComputePipelineStateWithDescriptor:descriptor
								  options:options
							       reflection:&reflection
								    error:&error];
		handler(pipeline, reflection, error);
	});
}

- (id)newComputePipelineStateWithFunction:(id)function
				  options:(NSUInteger)options
			       reflection:(id *)reflection
				    error:(NSError **)error
{
	id descriptor = [NSClassFromString(@"MTLComputePipelineDescriptor") new];
	[descriptor setComputeFunction:function];
	return [self newComputePipelineStateWithDescriptor:descriptor
						   options:options
						reflection:reflection
						     error:error];
}

- (id)newComputePipelineStateWithFunction:(id)function error:(NSError **)error
{
	return [self newComputePipelineStateWithFunction:function options:0 reflection:NULL error:error];
}

- (void)newComputePipelineStateWithFunction:(id)function
				    options:(NSUInteger)options
			  completionHandler:(void (^)(id, id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		id reflection = nil;
		NSError *error = nil;
		id pipeline = [self newComputePipelineStateWithFunction:function
								options:options
							     reflection:&reflection
								  error:&error];
		handler(pipeline, reflection, error);
	});
}

- (void)newComputePipelineStateWithFunction:(id)function completionHandler:(void (^)(id, NSError *))handler
{
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		NSError *error = nil;
		id pipeline = [self newComputePipelineStateWithFunction:function error:&error];
		handler(pipeline, error);
	});
}

@end
