/* SPDX-License-Identifier: MIT */
#ifndef STELA_AIR_METADATA_H
#define STELA_AIR_METADATA_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define AIR_MAX_ARGUMENTS 128
#define AIR_MAX_CLIP_DISTANCES 8
#define AIR_MAX_VERTEX_ATTRIBUTES 31u
#define AIR_MAX_RENDER_TARGETS 8u
#define AIR_MAX_PATCH_CONTROL_POINTS 32u
#define AIR_MAX_METADATA_OPERANDS 256
#define AIR_MAX_BITCODE_BYTES (64u * 1024u * 1024u)

enum stela_air_error_kind {
   STELA_AIR_OK,
   STELA_AIR_INPUT,
   STELA_AIR_LLVM_VERSION,
   STELA_AIR_BITCODE,
   STELA_AIR_VERIFY,
   STELA_AIR_TARGET,
   STELA_AIR_METADATA,
   STELA_AIR_ARGUMENT,
   STELA_AIR_CONTROL_FLOW,
   STELA_AIR_INSTRUCTION,
   STELA_AIR_TYPE,
   STELA_AIR_MEMORY,
   STELA_AIR_LIMIT,
   STELA_AIR_ALLOCATION,
};

struct stela_air_error {
   enum stela_air_error_kind kind;
   unsigned instruction; /* Zero-based instruction ordinal, not source line. */
   char detail[256];
};

enum stela_air_buffer_access {
   STELA_AIR_READ = 1,
   STELA_AIR_WRITE = 2,
   STELA_AIR_READ_WRITE = 3,
};

/* A MTLFunctionConstantValues value, laid out as Metal's: its lanes packed,
 * each bool one byte, a three-lane vector optionally padded to four. */
struct stela_air_constant_value {
   unsigned index;
   const void *bytes;
   size_t size;
};
/* The function constant values inspection specializes a module with, as
 * compilation does: an argument a false [[function_constant]] qualifies is
 * then absent. Inspection without them reflects every such argument. */
struct stela_air_constants {
   const struct stela_air_constant_value *values;
   unsigned count;
};
/* An AIR module linked with the input's, and the values of its function
 * constants: NULL for a module that declares none. */
struct stela_air_module {
   const void *bitcode;
   size_t size;
   const struct stela_air_constant_value *constants;
   unsigned constant_count;
};
/* A function a visible function table's handle calls, by name. */
struct stela_air_linked_function {
   const char *name;
   size_t name_bytes;
};
/* The sampler a constexpr sampler's state is: its 64-bit MTLResourceID. */
struct stela_air_constexpr_sampler {
   uint64_t state, id;
};

struct stela_air_buffer {
   unsigned argument;
   unsigned index; /* air.location_index; not an LLVM parameter byte offset. */
   unsigned address_space;
   enum stela_air_buffer_access access;
   unsigned type_size; /* Zero when the input omits this optional reflection. */
   unsigned type_alignment;
   /* An air.visible_function_table: device memory of 64-bit function
    * handles, read only. */
   bool function_table;
};


/* A function constant: an operand of !air.function_constants,
 * {ptr addrspace(2) @storage, !"type", !"name", i32 index[, i1 required]}, as
 * Metal.jl's library builder reads Apple's AIR. Functions load the constant
 * from its storage and test it with air.is_function_constant_defined. type
 * is its MSL spelling. Linked modules record whether functions require a
 * value; the constant is optional where they do not. */
struct stela_air_function_constant {
   const char *name, *type;
   size_t name_bytes, type_bytes;
   unsigned index;
   bool required;
};
#define AIR_MAX_FUNCTION_CONSTANTS 256u

struct stela_air_metadata;
/* A structure an argument points to or a member is, as its
 * air.struct_type_info reflects it; stela_air_layout_members visits its
 * members during the inspection's callback. */
struct stela_air_layout;

/* Borrowed callback views expire on callback return. Inspection validates LLVM,
 * module/entry ABI and metadata, not executable-body support, bindings, GPU
 * capability, or compiler provenance. Only actual air.kernel entries are
 * exposed; unsupported metadata/stages remain explicit. */
struct stela_air_inspection {
   const char *target;
   size_t target_bytes;
   /* The module's llvm.ident, its compiler's build identity; NULL when it
    * records none. */
   const char *ident;
   size_t ident_bytes;
   unsigned air_minor, language_major, language_minor;
   bool denorms_disable, fast_math;
   const struct stela_air_function_constant *function_constants;
   unsigned function_constant_count;
   unsigned commands; /* enum stela_air_command_use flags. */
   struct stela_air_metadata *metadata; /* Decodes layouts. */
};
/* What a module's functions do with indirect command buffers. */
enum stela_air_command_use {
   STELA_AIR_COMMANDS_ENCODE = 1, /* Encode commands or read a buffer's size. */
   STELA_AIR_COMMANDS_BARRIERS = 2, /* Set or copy a command's barrier. */
};
enum stela_air_primitive {
   STELA_AIR_PRIMITIVE_UNKNOWN,
   STELA_AIR_CHAR, STELA_AIR_UCHAR, STELA_AIR_SHORT, STELA_AIR_USHORT,
   STELA_AIR_INT, STELA_AIR_UINT, STELA_AIR_LONG, STELA_AIR_ULONG, STELA_AIR_FLOAT,
   STELA_AIR_HALF,
};

/* MTLTextureType, as the texture's reflected type name spells it. */
enum stela_air_texture_type {
   STELA_AIR_TEXTURE_1D = 1, STELA_AIR_TEXTURE_1D_ARRAY,
   STELA_AIR_TEXTURE_2D, STELA_AIR_TEXTURE_2D_ARRAY,
   STELA_AIR_TEXTURE_2D_MS, STELA_AIR_TEXTURE_2D_MS_ARRAY,
   STELA_AIR_TEXTURE_3D, STELA_AIR_TEXTURE_CUBE, STELA_AIR_TEXTURE_CUBE_ARRAY,
   STELA_AIR_TEXTURE_BUFFER,
};
/* access::sample/read/write/read_write; the values are AIR's access operand. */
enum stela_air_texture_access {
   STELA_AIR_TEXTURE_SAMPLE, STELA_AIR_TEXTURE_READ, STELA_AIR_TEXTURE_WRITE,
   STELA_AIR_TEXTURE_READ_WRITE,
};
/* A [[texture(index)]] argument. depth marks the depth* types, whose texels
 * are one float. primitive is the component type: FLOAT, HALF, INT, UINT,
 * SHORT or USHORT. An array<texture, length> argument is length textures
 * from index; length is zero for one texture. */
struct stela_air_texture {
   unsigned argument, index, length;
   enum stela_air_texture_type type;
   enum stela_air_texture_access access;
   enum stela_air_primitive primitive;
   bool depth;
};
/* A [[sampler(index)]] argument, or length samplers from index for an
 * array<sampler, length> argument. */
struct stela_air_sampler {
   unsigned argument, index, length;
};
#define AIR_MAX_TEXTURES 128u
#define AIR_MAX_SAMPLERS 16u

/* Metal's builtin inputs. AIR names each after its MSL attribute,
 * "air.<attribute>"; each is an integer scalar or vector of up to three
 * 16- or 32-bit lanes, or front_facing's bool. */
enum stela_air_builtin {
   STELA_AIR_BUILTIN_NONE,
   /* Kernels. */
   STELA_AIR_THREAD_POSITION_IN_GRID,
   STELA_AIR_THREAD_POSITION_IN_THREADGROUP,
   STELA_AIR_THREADGROUP_POSITION_IN_GRID,
   STELA_AIR_THREADS_PER_THREADGROUP,
   STELA_AIR_DISPATCH_THREADS_PER_THREADGROUP,
   STELA_AIR_THREADGROUPS_PER_GRID,
   STELA_AIR_THREADS_PER_GRID,
   STELA_AIR_THREAD_INDEX_IN_THREADGROUP,
   STELA_AIR_SIMDGROUP_INDEX_IN_THREADGROUP,
   STELA_AIR_SIMDGROUPS_PER_THREADGROUP,
   STELA_AIR_DISPATCH_SIMDGROUPS_PER_THREADGROUP,
   STELA_AIR_QUADGROUP_INDEX_IN_THREADGROUP,
   STELA_AIR_QUADGROUPS_PER_THREADGROUP,
   STELA_AIR_DISPATCH_QUADGROUPS_PER_THREADGROUP,
   /* Every stage. */
   STELA_AIR_THREAD_INDEX_IN_SIMDGROUP,
   STELA_AIR_THREADS_PER_SIMDGROUP,
   STELA_AIR_THREAD_EXECUTION_WIDTH,
   STELA_AIR_THREAD_INDEX_IN_QUADGROUP,
   /* Vertex functions; post-tessellation ones have patch IDs, not vertex
    * IDs. */
   STELA_AIR_VERTEX_ID,
   STELA_AIR_INSTANCE_ID,
   STELA_AIR_BASE_VERTEX,
   STELA_AIR_BASE_INSTANCE,
   STELA_AIR_PATCH_ID,
   /* Vertex and fragment functions. */
   STELA_AIR_AMPLIFICATION_ID,
   /* Fragment functions. */
   STELA_AIR_FRONT_FACING,
   STELA_AIR_SAMPLE_ID,
   STELA_AIR_SAMPLE_MASK_IN,
   STELA_AIR_PRIMITIVE_ID,
   STELA_AIR_RENDER_TARGET_ARRAY_INDEX_IN,
   STELA_AIR_VIEWPORT_ARRAY_INDEX_IN,
   STELA_AIR_POINT_COORD, /* float2 */
   STELA_AIR_BUILTIN_COUNT,
};

struct stela_air_argument_info {
   struct stela_air_buffer buffer;
   unsigned kind; /* 1=buffer, 2=builtin, 3=texture, 4=sampler, 5=stage-in. */
   enum stela_air_builtin builtin; /* kind 2 */
   unsigned location; /* kind 5: the attribute. */
   struct stela_air_texture texture; /* kind 3 */
   struct stela_air_sampler sampler; /* kind 4 */
   unsigned components;
   bool plain_buffer_type;
   bool argument_buffer; /* kind 1: an air.indirect_buffer. */
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   enum stela_air_primitive primitive;
   unsigned type_components; /* 1..4 only for known reflected builtin types. */
   bool used; /* Actual uses in this AIR module, not a final machine-code liveness claim. */
   bool absent; /* Its [[function_constant]] is false. */
   const struct stela_air_layout *layout; /* kind 1: the structure it points to, or NULL. */
};
struct stela_air_entry {
   const char *name;
   size_t name_bytes;
   unsigned argument_count;
   const struct stela_air_argument_info *arguments;
   bool reflection_complete; /* Bounded plain-resource reflection; see README. */
   unsigned max_threads; /* air.max_work_group_size, or zero when undeclared. */
   /* The threadgroup globals the entry uses, in module order, each placed at
    * its alignment. */
   uint64_t threadgroup_bytes;
};
typedef bool (*stela_air_visit_entry)(const struct stela_air_inspection *,
                                     const struct stela_air_entry *, void *);
bool stela_air_inspect(const void *bitcode, size_t size, const struct stela_air_constants *constants,
                       unsigned max_entries,
                       stela_air_visit_entry visit, void *data,
                       struct stela_air_error *error);
/* Additive render-only descriptor API. These enums are neither MTLFunctionType
 * nor MTLB TYPE values. Every string/array is borrowed through callback return.
 * This validates selected entry ABI/reflection, not body execution or hardware.
 * Legacy stela_air_inspect continues its original compute-only acceptance. */
/* Object and mesh functions are compute-like: they take kernel builtins,
 * threadgroup memory and barriers. A visible function is no stage: its
 * inspection visits an empty entry with the module's facts. */
enum stela_air_stage {
   STELA_AIR_VERTEX = 1, STELA_AIR_FRAGMENT, STELA_AIR_OBJECT, STELA_AIR_MESH, STELA_AIR_VISIBLE,
};
enum stela_air_stage_semantic {
   STELA_AIR_STAGE_BUFFER = 1, STELA_AIR_STAGE_BUILTIN, STELA_AIR_POSITION,
   STELA_AIR_VARYING, STELA_AIR_RENDER_TARGET, STELA_AIR_STAGE_TEXTURE,
   STELA_AIR_STAGE_SAMPLER,
   /* A stage-in attribute at location; a post-tessellation vertex
    * function's per-patch one. */
   STELA_AIR_VERTEX_INPUT,
   /* A post-tessellation vertex function's patch_control_point<T>: its
    * members are the attributes of each control point. */
   STELA_AIR_CONTROL_POINTS,
   STELA_AIR_POSITION_IN_PATCH, /* The tessellated vertex's float2 or float3. */
   /* A fragment's barycentric_coord: float to float3, interpolated and
    * sampled as qualified. */
   STELA_AIR_BARYCENTRIC,
   /* Object and mesh inputs: the object payload, a mesh function's mesh and
    * an object function's mesh grid properties. */
   STELA_AIR_PAYLOAD, STELA_AIR_MESH_OUTPUT, STELA_AIR_MESH_GRID,
   /* Vertex and mesh outputs. */
   STELA_AIR_POINT_SIZE, STELA_AIR_LAYER, STELA_AIR_VIEWPORT,
   STELA_AIR_CLIP_DISTANCE, /* A [clip_distances x float] leaf. */
   STELA_AIR_MESH_PRIMITIVE_ID, /* A mesh primitive's primitive ID. */
   STELA_AIR_PRIMITIVE_CULLED, /* A mesh primitive's bool [[primitive_culled]]. */
   /* Fragment outputs. */
   STELA_AIR_DEPTH, STELA_AIR_SAMPLE_MASK, STELA_AIR_STENCIL,
};
enum stela_air_interpolation {
   STELA_AIR_INTERPOLATION_NONE, STELA_AIR_PERSPECTIVE,
   STELA_AIR_NO_PERSPECTIVE, STELA_AIR_FLAT,
};
/* Where an interpolated fragment input is sampled. */
enum stela_air_sampling {
   STELA_AIR_SAMPLING_NONE, STELA_AIR_CENTER, STELA_AIR_CENTROID, STELA_AIR_SAMPLE,
};
/* A depth output's air.depth_qualifier. */
enum stela_air_depth_qualifier {
   STELA_AIR_DEPTH_ANY, STELA_AIR_DEPTH_GREATER, STELA_AIR_DEPTH_LESS,
};
struct stela_air_struct_member {
   unsigned offset, size;
   enum stela_air_primitive primitive;
   unsigned components;
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   /* A control point member's stage-in attribute, and whether the function
    * never reads it. */
   unsigned location;
   bool unused;
};
struct stela_air_stage_io {
   enum stela_air_stage_semantic semantic;
   unsigned argument; /* LLVM argument or ordered return leaf, as applicable. */
   struct stela_air_buffer buffer; /* Only STAGE_BUFFER; AS2 remains readonly. */
   struct stela_air_texture texture; /* Only STAGE_TEXTURE. */
   struct stela_air_sampler sampler; /* Only STAGE_SAMPLER. */
   enum stela_air_builtin builtin; /* Only STAGE_BUILTIN. */
   enum stela_air_primitive primitive;
   unsigned components;
   enum stela_air_interpolation interpolation;
   enum stela_air_sampling sampling;
   enum stela_air_depth_qualifier depth; /* Only DEPTH. */
   bool used, invariant;
   bool absent; /* An argument whose [[function_constant]] is false. */
   bool argument_buffer; /* Only STAGE_BUFFER: an air.indirect_buffer. */
   /* A VARYING the function interpolates itself, an interpolant<T, P>: its
    * argument is an opaque pointer the air.interpolate_* calls read, and it
    * has no sampling qualifier. */
   bool interpolant;
   /* A mesh output each primitive has, rather than each vertex; a fragment
    * input of one. */
   bool per_primitive;
   /* RENDER_TARGET attachment and dual-source index; VERTEX_INPUT attribute;
    * the data index of a mesh VARYING. */
   unsigned location, index;
   unsigned clip_distances; /* Only CLIP_DISTANCE: 1 to AIR_MAX_CLIP_DISTANCES. */
   const char *name, *type_name, *identifier;
   size_t name_bytes, type_name_bytes, identifier_bytes;
   unsigned member_count;
   const struct stela_air_struct_member *members;
   /* STAGE_BUFFER and PAYLOAD: the structure it points to, or NULL. */
   const struct stela_air_layout *layout;
};
/* The primitives a mesh function outputs. */
enum stela_air_topology { STELA_AIR_POINTS = 1, STELA_AIR_LINES, STELA_AIR_TRIANGLES };
/* The patch a post-tessellation vertex function's [[patch]] names. */
enum stela_air_patch { STELA_AIR_PATCH_NONE, STELA_AIR_PATCH_TRIANGLE, STELA_AIR_PATCH_QUAD };
struct stela_air_stage_entry {
   enum stela_air_stage stage;
   bool framebuffer_fetch_present, framebuffer_fetch_enabled; /* Compile option, never a fetch operation. */
   const char *name;
   size_t name_bytes;
   unsigned input_count, output_count;
   const struct stela_air_stage_io *inputs, *outputs;
   /* An object or mesh function's air.max_work_group_size, an object
    * function's air.max_mesh_work_groups; zero when undeclared. Kernels
    * reflect theirs as stela_air_entry's. */
   unsigned max_threads, max_mesh_threadgroups;
   /* A mesh function's vertex and primitive capacities and topology. Its
    * outputs are its mesh's vertex and primitive data. */
   unsigned max_vertices, max_primitives;
   enum stela_air_topology topology;
   /* A post-tessellation vertex function's patch and its control points,
    * zero when it does not declare them. */
   enum stela_air_patch patch;
   unsigned patch_control_points;
   /* As a kernel's stela_air_entry; a fragment function that calls
    * air.discard_fragment. */
   uint64_t threadgroup_bytes;
   bool discards;
   /* A fragment function's [[early_fragment_tests]]. */
   bool early_fragment_tests;
};
typedef bool (*stela_air_visit_stage)(const struct stela_air_inspection *,
                                     const struct stela_air_stage_entry *, void *);
bool stela_air_inspect_stage(const void *, size_t, const struct stela_air_constants *,
                             const char *entry,
                             enum stela_air_stage, stela_air_visit_stage, void *,
                             struct stela_air_error *);
/* The stage whose entry list names entry: *stage is zero for air.kernel.
 * Only the lists are read; inspection validates the rest. */
bool stela_air_entry_stage(const void *, size_t, const char *entry, unsigned *stage,
                           struct stela_air_error *);
/* Calls visit with each function the entry lists name and its list, zero for
 * air.kernel, as stela_air_entry_stage numbers them, until it refuses one. */
typedef bool (*stela_air_visit_function)(void *, const char *name, size_t name_bytes,
                                         unsigned stage);
bool stela_air_functions(const void *, size_t, stela_air_visit_function, void *,
                         struct stela_air_error *);
/* A visible function a stitched function calls, and the module defining it. */
struct stela_air_stitch_source {
   const void *bitcode;
   size_t size;
   const char *name;
};
#define STELA_AIR_STITCH_INPUT UINT32_MAX
#define STELA_AIR_STITCH_NO_OUTPUT UINT32_MAX
/* A node of a stitched function: an input, argument `input` of the function,
 * or a call of source `function` on the values of earlier nodes. */
struct stela_air_stitch_node {
   uint32_t function, input;
   const uint32_t *arguments;
   uint32_t argument_count;
};
struct stela_air_stitch_graph {
   const char *name;
   const struct stela_air_stitch_node *nodes;
   uint32_t node_count;
   uint32_t output; /* The node whose result it returns. */
};
/* Calls visit with the bitcode of a module of the graphs: air_stitch.c. */
typedef void (*stela_air_visit_bytes)(void *, const void *, size_t);
bool stela_air_stitch(const struct stela_air_stitch_source *, unsigned,
                      const struct stela_air_stitch_graph *, unsigned, stela_air_visit_bytes,
                      void *, struct stela_air_error *);
/* A module's constexpr sampler states, AIR_MAX_SAMPLER_STATES at most, as
 * stela_air_metadata_sampler_states lists them. */
#define AIR_MAX_SAMPLER_STATES AIR_MAX_METADATA_OPERANDS
bool stela_air_sampler_states(const void *, size_t, uint64_t *states, unsigned *count,
                              struct stela_air_error *);

enum stela_air_field_kind {
   STELA_AIR_FIELD_DATA, /* Inline constant data. */
   STELA_AIR_FIELD_BUFFER, /* A device or constant buffer's address. */
   STELA_AIR_FIELD_ARGUMENTS, /* A nested argument buffer's address. */
   STELA_AIR_FIELD_TEXTURE, /* A texture's 64-bit MTLResourceID. */
   STELA_AIR_FIELD_SAMPLER, /* A sampler's 64-bit MTLResourceID. */
   /* An indirect command buffer's or a pipeline state's 64-bit
    * gpuResourceID, which only AIR's command functions use. */
   STELA_AIR_FIELD_COMMANDS,
   STELA_AIR_FIELD_RENDER_PIPELINE,
   STELA_AIR_FIELD_COMPUTE_PIPELINE,
};
/* A member of a layout: its offset, the bytes of one element, its element
 * count (zero for one), and its MSL type spelling and name. layout is the
 * structure the member is, or a nested argument buffer's, which it points
 * to. An argument buffer's members are arguments: each holds count
 * resources of kind from [[id]] id, and a buffer's or texture's descriptor
 * as a top-level argument of its kind spells it; an inlined structure's id
 * is its first member's. */
struct stela_air_layout_member {
   unsigned offset, size, elements, count;
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   const struct stela_air_layout *layout;
   bool argument;
   enum stela_air_field_kind kind;
   unsigned id;
   struct stela_air_buffer buffer;
   struct stela_air_texture texture;
};
typedef bool (*stela_air_visit_member)(const struct stela_air_layout_member *, void *);
/* Visits layout's members in increasing offsets, during the callback of the
 * inspection that gave the layout; false when a member is malformed or the
 * visitor refuses one. */
bool stela_air_layout_members(const struct stela_air_inspection *, const struct stela_air_layout *,
                              stela_air_visit_member, void *);

/* One validated VS/FS varying map. Identifiers borrow from the supplied entry
 * descriptors; caller must own/copy those strings beyond inspector callbacks.
 * Location is relative to NIR VARYING_SLOT_VAR0, not a hardware register.
 * Exact opaque identifier/type matching, bounded by explicit target IO slots;
 * no source-name/hash exceptions or invented interpolation. Failure preserves
 * rows/count. Successful rows must remain live through stage translation. These
 * same-process values require readable UTF-8 identifiers with exact byte extents;
 * duplicate IDs/locations/types and target slot limits are checked before effects. */
struct stela_air_varying_slot {
   const char *identifier;
   size_t identifier_bytes;
   enum stela_air_primitive primitive;
   unsigned components, location;
   bool per_primitive; /* Mesh primitive data rather than vertex data. */
};
bool stela_air_link_stage_io(const struct stela_air_stage_entry *vertex,
                             const struct stela_air_stage_entry *fragment,
                             unsigned max_slots, struct stela_air_varying_slot *rows,
                             unsigned capacity, unsigned *count,
                             struct stela_air_error *);

/* Compiler implementation only. Ordinary metadata consumers need no LLVM or
 * NIR headers and receive no LLVM objects. Define before the first include. */
#ifdef STELA_AIR_METADATA_INTERNAL
#include "llvm-c/Core.h"
#include "llvm-c/Target.h"
/* Shared decoder state, borrowed from the caller's real LLVM module. No NIR,
 * resource mapping or GPU/Metal object is created by metadata inspection. */
struct stela_air_metadata {
   LLVMModuleRef module;
   LLVMTargetDataRef layout;
   struct stela_air_error *error;
   unsigned air_minor, language_major, language_minor;
   unsigned max_device_buffers, max_threadgroup_buffers, max_constant_buffers;
   bool render; /* Additive decoder mode; legacy compute remains false. */
   bool framebuffer_fetch_present, framebuffer_fetch_enabled;
   bool denorms_disable, fast_math;
   /* The module's one llvm.ident string, which qualified profiles name, or
    * NULL; captured by validation, before linking adds others. */
   const char *ident;
   unsigned ident_bytes;
   /* Whether air.static_init constructors compute program-scope constants:
    * AS2 globals they store, which are constant data once translation has
    * evaluated them. */
   bool constructed;
};

bool stela_air_md_string(LLVMValueRef value, const char *expected);
bool stela_air_md_uint(LLVMValueRef value, unsigned *number);
/* Whether only os_log's calls read a value: its object or a string, which
 * calls take as constants and no function reaches at run time. */
bool stela_air_log_only(LLVMValueRef value);
bool stela_air_md_node(struct stela_air_metadata *m, LLVMValueRef node,
                       LLVMValueRef *operands, unsigned *count);
bool stela_air_named_md(struct stela_air_metadata *m, const char *name,
                        LLVMValueRef *operands, unsigned *count);
bool stela_air_metadata_layout(struct stela_air_metadata *m);
bool stela_air_metadata_validate(struct stela_air_metadata *m);
/* The module's function constants and, when storage is not NULL, the global
 * each is stored in: an AS2 scalar or 2-4 lane vector of integers, half or
 * float, which specialization defines. Indices, names and storage are unique. */
bool stela_air_metadata_function_constants(struct stela_air_metadata *m,
                                           struct stela_air_function_constant *constants,
                                           LLVMValueRef *storage, unsigned *count);
/* Whether global stores a function constant. */
bool stela_air_metadata_is_function_constant(struct stela_air_metadata *m, LLVMValueRef global);
/* The module's constexpr samplers: each operand of !air.sampler_states names
 * an internal AS2 constant [2 x i64] global, which texture calls take as
 * their sampler, holding Apple's encoding of the sampler's state. The second
 * word is zero; states[i] is the first, metal/sampler.rs decodes it. Each
 * global is listed once. */
bool stela_air_metadata_sampler_states(struct stela_air_metadata *m, LLVMValueRef *globals,
                                       uint64_t *states, unsigned *count);
/* The state of global when it is a validated module's constexpr sampler. */
bool stela_air_metadata_sampler_state(struct stela_air_metadata *m, LLVMValueRef global,
                                      uint64_t *state);
/* One LLVM-only storage validator shared by conservative reflection and NIR.
 * These describe the qualified ABI, not compiler provenance or GPU limits.
 * No shared storage is allocated here; only actually used globals are lowered
 * by the selected entry's original NIR path. Errors use m->error; observational
 * consumers must supply their own local error state. */
bool stela_air_metadata_shared_profile(struct stela_air_metadata *m);
/* A module global: threadgroup memory, or constant data with an initializer. */
struct stela_air_global {
   bool constant;
   uint64_t size;
   unsigned alignment;
};
bool stela_air_metadata_global(struct stela_air_metadata *m, LLVMValueRef global,
                               struct stela_air_global *info);
/* Validates every global but function constants' storage, the constructor
 * list and llvm.used or llvm.compiler.used, which only keep globals from the
 * optimizer; `threadgroup` reports any threadgroup memory. */
bool stela_air_metadata_globals(struct stela_air_metadata *m, bool *threadgroup);
/* llvm.global_ctors when it lists only air.static_init functions, which
 * compute the program-scope constants derived from function constants; NULL
 * otherwise. */
LLVMValueRef stela_air_metadata_constructors(LLVMModuleRef module);
/* A global air.static_init constructors may compute: an internal AS2 global
 * with an initializer they replace. */
bool stela_air_metadata_constructed(LLVMValueRef global);

/* An argument buffer's fields: kernel->fields[first, first + count), in
 * increasing offsets, of a structure of size bytes, through arrays of
 * which pointers to it step. */
struct stela_air_fields {
   unsigned first, count, size;
};
/* One argument of an argument buffer: count elements filling size bytes at
 * offset. Addresses and resource IDs are aligned 8-byte elements. The
 * descriptors' argument is the argument buffer's top-level argument and
 * their index the field's [[id]]. */
struct stela_air_field {
   enum stela_air_field_kind kind;
   unsigned offset, size, count;
   struct stela_air_buffer buffer; /* Buffers and argument buffers. */
   struct stela_air_fields arguments; /* An argument buffer's fields. */
   struct stela_air_texture texture;
   struct stela_air_sampler sampler;
};
#define AIR_MAX_FIELDS 128u
#define AIR_MAX_ARGUMENT_BUFFER_DEPTH 8u

struct stela_air_argument {
   LLVMValueRef value; /* Borrowed, decoder/compiler internal only. */
   LLVMValueRef layout; /* Its air.struct_type_info, or NULL. */
   struct stela_air_buffer buffer;
   struct stela_air_texture texture;
   struct stela_air_sampler sampler;
   bool is_buffer, is_texture, is_sampler;
   /* A buffer argument that is an argument buffer: these are its fields. */
   bool is_argument_buffer;
   struct stela_air_fields fields;
   /* Object and mesh inputs; the payload's buffer holds its size, alignment
    * and access. */
   bool is_payload, is_mesh, is_mesh_grid;
   /* A stage-in attribute at location: a kernel's air.stage_in. */
   bool is_stage_in;
   unsigned location;
   enum stela_air_builtin builtin; /* Otherwise a builtin input. */
   unsigned components; /* The builtin's lanes. */
   bool plain_buffer_type; /* Reflected MSL builtin scalar/vector, not a struct. */
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   enum stela_air_primitive primitive;
   unsigned type_components;
   bool used;
   /* Its [[function_constant]] is false: it has no binding, and its index
    * is another argument's to take. */
   bool absent;
};
struct stela_air_kernel {
   unsigned count, field_count;
   unsigned max_threads; /* A kernel's air.max_work_group_size, or zero. */
   struct stela_air_argument arguments[AIR_MAX_ARGUMENTS];
   struct stela_air_field fields[AIR_MAX_FIELDS];
};
bool stela_air_metadata_kernel(struct stela_air_metadata *m, LLVMValueRef fn,
                               struct stela_air_kernel *kernel);
struct stela_air_render {
   struct stela_air_stage_entry entry;
   struct stela_air_stage_io inputs[AIR_MAX_ARGUMENTS], outputs[AIR_MAX_ARGUMENTS];
   struct stela_air_struct_member members[AIR_MAX_ARGUMENTS];
   unsigned member_count;
   struct stela_air_kernel arguments;
   /* A post-tessellation vertex function's control point fetch. */
   LLVMValueRef control_point_function;
};
bool stela_air_metadata_stage(struct stela_air_metadata *, LLVMValueRef,
                              enum stela_air_stage, struct stela_air_render *);
bool stela_air_metadata_stage_map(struct stela_air_metadata *, const struct stela_air_render *,
                                 const struct stela_air_varying_slot *, unsigned count, unsigned max_slots);
/* Whether type is an output's reflected scalar or vector type. */
bool stela_air_metadata_output_type(const struct stela_air_stage_io *io, LLVMTypeRef type);


#endif
#ifdef __cplusplus
}
#endif
#endif
