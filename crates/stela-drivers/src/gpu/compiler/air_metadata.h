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

struct stela_air_buffer {
   unsigned argument;
   unsigned index; /* air.location_index; not an LLVM parameter byte offset. */
   unsigned address_space;
   enum stela_air_buffer_access access;
   unsigned type_size; /* Zero when the input omits this optional reflection. */
   unsigned type_alignment;
};


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
 * SHORT or USHORT. */
struct stela_air_texture {
   unsigned argument, index;
   enum stela_air_texture_type type;
   enum stela_air_texture_access access;
   enum stela_air_primitive primitive;
   bool depth;
};
/* A [[sampler(index)]] argument. */
struct stela_air_sampler {
   unsigned argument, index;
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
   /* Vertex functions. */
   STELA_AIR_VERTEX_ID,
   STELA_AIR_INSTANCE_ID,
   STELA_AIR_BASE_VERTEX,
   STELA_AIR_BASE_INSTANCE,
   /* Vertex and fragment functions. */
   STELA_AIR_AMPLIFICATION_ID,
   /* Fragment functions. */
   STELA_AIR_FRONT_FACING,
   STELA_AIR_SAMPLE_ID,
   STELA_AIR_SAMPLE_MASK_IN,
   STELA_AIR_PRIMITIVE_ID,
   STELA_AIR_RENDER_TARGET_ARRAY_INDEX_IN,
   STELA_AIR_VIEWPORT_ARRAY_INDEX_IN,
   STELA_AIR_BUILTIN_COUNT,
};

struct stela_air_argument_info {
   struct stela_air_buffer buffer;
   unsigned kind; /* 1=buffer, 2=builtin, 3=texture, 4=sampler. */
   enum stela_air_builtin builtin; /* kind 2 */
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
bool stela_air_inspect(const void *bitcode, size_t size, unsigned max_entries,
                       stela_air_visit_entry visit, void *data,
                       struct stela_air_error *error);
/* Additive render-only descriptor API. These enums are neither MTLFunctionType
 * nor MTLB TYPE values. Every string/array is borrowed through callback return.
 * This validates selected entry ABI/reflection, not body execution or hardware.
 * Legacy stela_air_inspect continues its original compute-only acceptance. */
/* Object and mesh functions are compute-like: they take kernel builtins,
 * threadgroup memory and barriers. */
enum stela_air_stage {
   STELA_AIR_VERTEX = 1, STELA_AIR_FRAGMENT, STELA_AIR_OBJECT, STELA_AIR_MESH,
};
enum stela_air_stage_semantic {
   STELA_AIR_STAGE_BUFFER = 1, STELA_AIR_STAGE_BUILTIN, STELA_AIR_POSITION,
   STELA_AIR_VARYING, STELA_AIR_RENDER_TARGET, STELA_AIR_STAGE_TEXTURE,
   STELA_AIR_STAGE_SAMPLER,
   STELA_AIR_VERTEX_INPUT, /* A stage-in attribute at location. */
   /* Object and mesh inputs: the object payload, a mesh function's mesh and
    * an object function's mesh grid properties. */
   STELA_AIR_PAYLOAD, STELA_AIR_MESH_OUTPUT, STELA_AIR_MESH_GRID,
   /* Vertex and mesh outputs. */
   STELA_AIR_POINT_SIZE, STELA_AIR_LAYER, STELA_AIR_VIEWPORT,
   STELA_AIR_CLIP_DISTANCE, /* A [clip_distances x float] leaf. */
   STELA_AIR_MESH_PRIMITIVE_ID, /* A mesh primitive's primitive ID. */
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
   bool argument_buffer; /* Only STAGE_BUFFER: an air.indirect_buffer. */
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
};
/* The primitives a mesh function outputs. */
enum stela_air_topology { STELA_AIR_POINTS = 1, STELA_AIR_LINES, STELA_AIR_TRIANGLES };
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
   /* As a kernel's stela_air_entry; a fragment function that calls
    * air.discard_fragment. */
   uint64_t threadgroup_bytes;
   bool discards;
};
typedef bool (*stela_air_visit_stage)(const struct stela_air_inspection *,
                                     const struct stela_air_stage_entry *, void *);
bool stela_air_inspect_stage(const void *, size_t, const char *entry,
                             enum stela_air_stage, stela_air_visit_stage, void *,
                             struct stela_air_error *);
/* The stage whose entry list names entry: *stage is zero for air.kernel.
 * Only the lists are read; inspection validates the rest. */
bool stela_air_entry_stage(const void *, size_t, const char *entry, unsigned *stage,
                           struct stela_air_error *);

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
};

bool stela_air_md_string(LLVMValueRef value, const char *expected);
bool stela_air_md_uint(LLVMValueRef value, unsigned *number);
bool stela_air_md_node(struct stela_air_metadata *m, LLVMValueRef node,
                       LLVMValueRef *operands, unsigned *count);
bool stela_air_named_md(struct stela_air_metadata *m, const char *name,
                        LLVMValueRef *operands, unsigned *count);
bool stela_air_metadata_layout(struct stela_air_metadata *m);
bool stela_air_metadata_validate(struct stela_air_metadata *m);
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
/* Validates every global; `threadgroup` reports any threadgroup memory. */
bool stela_air_metadata_globals(struct stela_air_metadata *m, bool *threadgroup);

/* An argument buffer's fields: kernel->fields[first, first + count), in
 * increasing offsets. */
struct stela_air_fields {
   unsigned first, count;
};
enum stela_air_field_kind {
   STELA_AIR_FIELD_DATA, /* Inline constant data. */
   STELA_AIR_FIELD_BUFFER, /* A device or constant buffer's address. */
   STELA_AIR_FIELD_ARGUMENTS, /* A nested argument buffer's address. */
   STELA_AIR_FIELD_TEXTURE, /* A texture's 64-bit MTLResourceID. */
   STELA_AIR_FIELD_SAMPLER, /* A sampler's 64-bit MTLResourceID. */
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
   enum stela_air_builtin builtin; /* Otherwise a builtin input. */
   unsigned components; /* The builtin's lanes. */
   bool plain_buffer_type; /* Reflected MSL builtin scalar/vector, not a struct. */
   const char *name, *type_name;
   size_t name_bytes, type_name_bytes;
   enum stela_air_primitive primitive;
   unsigned type_components;
   bool used;
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
};
bool stela_air_metadata_stage(struct stela_air_metadata *, LLVMValueRef,
                              enum stela_air_stage, struct stela_air_render *);
bool stela_air_metadata_stage_map(struct stela_air_metadata *, const struct stela_air_render *,
                                 const struct stela_air_varying_slot *, unsigned count, unsigned max_slots);
bool stela_air_metadata_stage_buffer_type(struct stela_air_metadata *,
                                          const struct stela_air_stage_io *, LLVMTypeRef);
/* Whether type is an output's reflected scalar or vector type. */
bool stela_air_metadata_output_type(const struct stela_air_stage_io *io, LLVMTypeRef type);


#endif
#ifdef __cplusplus
}
#endif
#endif
