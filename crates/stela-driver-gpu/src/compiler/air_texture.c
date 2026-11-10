/* SPDX-License-Identifier: MIT */
/* AIR's texture functions, as Apple's compiler emits them and DXMT's AIR
 * builder (src/airconv/nt/air_builder.cpp) records them. Each function's name
 * spells the operation, the texture's AIR type and its texel type; this file
 * rebuilds the exact name from the texture argument's reflection, so a call
 * whose type disagrees with its argument is refused rather than guessed. The
 * operands follow in a fixed order that depends on the texture type:
 *
 *   sample[_compare]  texture, sampler, [i32 1 for depth], coord, [array],
 *                     [compare reference], [i1 offset present, offset],
 *                     i1 lod is level, f32 lod or bias, f32 min lod, i32 access
 *   sample_..._grad   texture, sampler, [i32 1], coord, [array],
 *                     [compare reference], dPdx, dPdy, f32 min lod, [i1, offset],
 *                     i32 access
 *   read              texture, [read sampler], [i32 1], position, [cube face],
 *                     [array], [sample], [zero offset of a 2D or 3D], [lod],
 *                     i32 access, the sampler and offset from Metal 4
 *
 * Metal 1 has no access operand. Before Metal 2.2 samples have no minimum
 * level of detail, and sample, read and gather return the bare texel.
 *   write             texture, position, [cube face], [array], texel, [lod],
 *                     i32 access
 *   gather[_compare]  texture, sampler, [i32 1], coord, [array],
 *                     [compare reference], [i1, offset], [component],
 *                     i32 access
 *   get_*             texture, [lod for width, height and depth]
 *   calculate_*_lod   texture, sampler, coord, i32 access
 *   fence             texture
 *
 * Sample, read and gather return {texel, i8 residency}: sparse_color's
 * resident() is bit 0 clear. Atomics are described where they are lowered. */
#include "air_texture.h"
#include "compiler/nir/nir_format_convert.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Indexed by enum stela_air_texture_type. */
static const struct shape {
   const char *name, *depth; /* AIR type names; no depth variant when NULL. */
   enum glsl_sampler_dim dim;
   bool array, mipmapped;
   unsigned coords;    /* Sample coordinate components. */
   unsigned positions; /* Read and write position components. */
} shapes[] = {
   [STELA_AIR_TEXTURE_1D] = {"texture_1d", NULL, GLSL_SAMPLER_DIM_1D, false, true, 1, 1},
   [STELA_AIR_TEXTURE_1D_ARRAY] = {"texture_1d_array", NULL, GLSL_SAMPLER_DIM_1D, true, true, 1, 1},
   [STELA_AIR_TEXTURE_2D] = {"texture_2d", "depth_2d", GLSL_SAMPLER_DIM_2D, false, true, 2, 2},
   [STELA_AIR_TEXTURE_2D_ARRAY] = {"texture_2d_array", "depth_2d_array", GLSL_SAMPLER_DIM_2D, true,
                                   true, 2, 2},
   [STELA_AIR_TEXTURE_2D_MS] = {"texture_2d_ms", "depth_2d_ms", GLSL_SAMPLER_DIM_MS, false, false,
                                2, 2},
   [STELA_AIR_TEXTURE_2D_MS_ARRAY] = {"texture_2d_ms_array", "depth_2d_ms_array",
                                      GLSL_SAMPLER_DIM_MS, true, false, 2, 2},
   [STELA_AIR_TEXTURE_3D] = {"texture_3d", NULL, GLSL_SAMPLER_DIM_3D, false, true, 3, 3},
   [STELA_AIR_TEXTURE_CUBE] = {"texture_cube", "depth_cube", GLSL_SAMPLER_DIM_CUBE, false, true,
                               3, 2},
   [STELA_AIR_TEXTURE_CUBE_ARRAY] = {"texture_cube_array", "depth_cube_array",
                                     GLSL_SAMPLER_DIM_CUBE, true, true, 3, 2},
   [STELA_AIR_TEXTURE_BUFFER] = {"texture_buffer_1d", NULL, GLSL_SAMPLER_DIM_BUF, false, false,
                                 1, 1},
};

enum operation {
   SAMPLE, SAMPLE_COMPARE, SAMPLE_GRAD, SAMPLE_COMPARE_GRAD, READ, WRITE, GATHER, GATHER_COMPARE,
   WIDTH, HEIGHT, DEPTH, ARRAY_SIZE, MIP_LEVELS, SAMPLES, CLAMPED_LOD, UNCLAMPED_LOD, FENCE,
   IS_NULL, BLOCK_READ, SLICE_WRITE,
};

/* Each operation's name stem, and whether its name ends in the texel type. */
static const struct {
   const char *stem;
   bool typed;
} operations[] = {
   [SAMPLE] = {"sample", true}, [SAMPLE_COMPARE] = {"sample_compare", true},
   [SAMPLE_GRAD] = {"sample", true}, [SAMPLE_COMPARE_GRAD] = {"sample_compare", true},
   [READ] = {"read", true}, [WRITE] = {"write", true},
   [GATHER] = {"gather", true}, [GATHER_COMPARE] = {"gather_compare", true},
   [WIDTH] = {"get_width"}, [HEIGHT] = {"get_height"}, [DEPTH] = {"get_depth"},
   [ARRAY_SIZE] = {"get_array_size"}, [MIP_LEVELS] = {"get_num_mip_levels"},
   [SAMPLES] = {"get_num_samples"}, [CLAMPED_LOD] = {"calculate_clamped_lod"},
   [UNCLAMPED_LOD] = {"calculate_unclamped_lod"}, [FENCE] = {"fence"}, [IS_NULL] = {"is_null"},
   [BLOCK_READ] = {"block_read", true},
   /* Its suffix is the slice's member type, which need not be the texel's. */
   [SLICE_WRITE] = {"write_imageblock_slice_to"},
};

struct call {
   const struct stela_air_texture_context *c;
   nir_builder *b;
   LLVMValueRef inst;
   const struct stela_air_texture *texture;
   nir_def *texture_id; /* An argument buffer's texture's ID, or NULL. */
   const struct shape *shape;
   unsigned next, count;
   bool coherent;
   /* Whether the call's positions, offsets and levels are 16 bits (.i16). */
   bool short_indices;
   /* Whether the call's residency is read, and then its value. */
   bool sparse;
   nir_def *residency;
   /* Whether the call's sampler compares with Never, or NULL. */
   nir_def *never;
   /* The call's sampler's stela_air_sampler_filter bits, or NULL. */
   nir_def *filter;
};

static bool
fail(const struct call *call, const char *fmt, ...)
{
   struct stela_air_error *error = call->c->error;
   if (error->kind == STELA_AIR_OK) {
      error->kind = STELA_AIR_INSTRUCTION;
      va_list args;
      va_start(args, fmt);
      vsnprintf(error->detail, sizeof(error->detail), fmt, args);
      va_end(args);
   }
   return false;
}

static bool
integer_texels(const struct stela_air_texture *texture)
{
   return texture->primitive != STELA_AIR_FLOAT && texture->primitive != STELA_AIR_HALF;
}

static enum glsl_base_type
base_type(const struct stela_air_texture *texture)
{
   switch (texture->primitive) {
   case STELA_AIR_INT:
   case STELA_AIR_SHORT:
      return GLSL_TYPE_INT;
   case STELA_AIR_UINT:
   case STELA_AIR_USHORT:
      return GLSL_TYPE_UINT;
   default:
      return GLSL_TYPE_FLOAT;
   }
}

static bool
storage(const struct stela_air_texture *texture)
{
   return texture->access == STELA_AIR_TEXTURE_WRITE ||
          texture->access == STELA_AIR_TEXTURE_READ_WRITE;
}

/* The descriptor type the texture's accesses need. */
static const struct glsl_type *
descriptor_type(const struct stela_air_texture *texture)
{
   const struct shape *shape = &shapes[texture->type];
   return storage(texture) ? glsl_image_type(shape->dim, shape->array, base_type(texture))
                           : glsl_texture_type(shape->dim, shape->array, base_type(texture));
}

/* The texel type's overload suffix: ".v4f32", ".s.v4i32", ".f32" for depth. */
static const char *
overload(const struct stela_air_texture *texture, bool gather)
{
   if (texture->depth)
      return gather ? ".v4f32" : ".f32";
   switch (texture->primitive) {
   case STELA_AIR_HALF: return ".v4f16";
   case STELA_AIR_INT: return ".s.v4i32";
   case STELA_AIR_UINT: return ".u.v4i32";
   case STELA_AIR_SHORT: return ".s.v4i16";
   case STELA_AIR_USHORT: return ".u.v4i16";
   default: return ".v4f32";
   }
}

static bool
named(const struct call *call, enum operation op, bool coherent, bool short_indices,
      const char *name, size_t bytes)
{
   const struct stela_air_texture *texture = call->texture;
   const char *type = texture->depth ? call->shape->depth : call->shape->name;
   const char *texel = "";
   if (operations[op].typed)
      texel = op == GATHER_COMPARE ? ".f32" : overload(texture, op == GATHER);
   char expected[96];
   int length = snprintf(expected, sizeof(expected), "air.%s_%s%s%s%s%s", operations[op].stem, type,
                         op == SAMPLE_GRAD || op == SAMPLE_COMPARE_GRAD ? "_grad" : "",
                         short_indices ? ".i16" : "",
                         coherent ? ".device_coherent" : "",
                         texel);
   return length > 0 && (size_t)length == bytes && !memcmp(expected, name, bytes);
}

static bool
type_is(LLVMTypeRef type, unsigned components, LLVMTypeKind kind, unsigned bits)
{
   if (components > 1) {
      if (LLVMGetTypeKind(type) != LLVMVectorTypeKind || LLVMGetVectorSize(type) != components)
         return false;
      type = LLVMGetElementType(type);
   }
   if (LLVMGetTypeKind(type) != kind)
      return false;
   return kind != LLVMIntegerTypeKind || LLVMGetIntTypeWidth(type) == bits;
}

/* The LLVM shape of the shader's texel type. */
static void
texel_shape(const struct stela_air_texture *texture, bool gather, unsigned *components,
            LLVMTypeKind *kind, unsigned *bits)
{
   *components = texture->depth && !gather ? 1 : 4;
   *kind = texture->primitive == STELA_AIR_HALF ? LLVMHalfTypeKind :
           integer_texels(texture) ? LLVMIntegerTypeKind : LLVMFloatTypeKind;
   *bits = texture->primitive == STELA_AIR_SHORT || texture->primitive == STELA_AIR_USHORT ? 16 : 32;
}

static bool
texel_type(const struct call *call, LLVMTypeRef type, bool gather)
{
   unsigned components, bits;
   LLVMTypeKind kind;
   texel_shape(call->texture, gather, &components, &kind, &bits);
   return type_is(type, components, kind, bits);
}

/* The call returns {texel, i8}, or the bare texel. */
static bool
result_type(const struct call *call, bool gather)
{
   LLVMTypeRef type = LLVMTypeOf(call->inst);
   if (LLVMGetTypeKind(type) != LLVMStructTypeKind)
      return texel_type(call, type, gather);
   return LLVMCountStructElementTypes(type) == 2 &&
          texel_type(call, LLVMStructGetTypeAtIndex(type, 0), gather) &&
          type_is(LLVMStructGetTypeAtIndex(type, 1), 1, LLVMIntegerTypeKind, 8);
}

static LLVMValueRef
take(struct call *call)
{
   if (call->next >= call->count) {
      fail(call, "texture call has too few operands");
      return NULL;
   }
   return LLVMGetOperand(call->inst, call->next++);
}

/* The next operand as NIR, of the given LLVM shape. */
static nir_def *
operand(struct call *call, unsigned components, LLVMTypeKind kind, unsigned bits)
{
   LLVMValueRef value = take(call);
   if (!value)
      return NULL;
   if (!type_is(LLVMTypeOf(value), components, kind, bits)) {
      fail(call, "texture call operand %u has an unexpected type", call->next - 1);
      return NULL;
   }
   return call->c->operand(call->c->translator, value);
}

/* The next position, level or layer, of `components` lanes, as 32 bits. */
static nir_def *
index_operand(struct call *call, unsigned components)
{
   if (!call->short_indices)
      return operand(call, components, LLVMIntegerTypeKind, 32);
   nir_def *value = operand(call, components, LLVMIntegerTypeKind, 16);
   return value ? nir_u2u32(call->b, value) : NULL;
}

static nir_def *
uint_operand(struct call *call)
{
   return index_operand(call, 1);
}

static nir_def *
float_operand(struct call *call, unsigned components)
{
   return operand(call, components, LLVMFloatTypeKind, 32);
}

static bool
constant(struct call *call, unsigned bits, uint64_t *value)
{
   LLVMValueRef operand = take(call);
   if (!operand)
      return false;
   if (!LLVMIsAConstantInt(operand) || !type_is(LLVMTypeOf(operand), 1, LLVMIntegerTypeKind, bits))
      return fail(call, "texture call operand %u must be a constant i%u", call->next - 1, bits);
   *value = LLVMConstIntGetZExtValue(operand);
   return true;
}

static bool
expect(struct call *call, unsigned bits, uint64_t expected, const char *what)
{
   uint64_t value;
   if (!constant(call, bits, &value))
      return false;
   return value == expected || fail(call, "unsupported texture %s %llu", what,
                                    (unsigned long long)value);
}

/* Whether the operand just taken is all-zero bits: 0, or +0.0. */
static bool
zero_operand(const struct call *call)
{
   return LLVMIsNull(LLVMGetOperand(call->inst, call->next - 1));
}

static bool
access_operand(struct call *call, uint64_t access)
{
   return call->next == call->count || expect(call, 32, access, "access operand");
}

/* The minimum level of detail, NULL when absent or zero. */
static bool
min_lod_operand(struct call *call, nir_def **min_lod)
{
   *min_lod = NULL;
   if (call->next == call->count ||
       LLVMGetTypeKind(LLVMTypeOf(LLVMGetOperand(call->inst, call->next))) != LLVMFloatTypeKind)
      return true;
   nir_def *value = float_operand(call, 1);
   if (value && !zero_operand(call))
      *min_lod = value;
   return value != NULL;
}

/* The signed texel offset Metal 4 places after a 2D or 3D position, added
 * to *position. */
static bool
position_offset(struct call *call, nir_def **position)
{
   const struct shape *shape = call->shape;
   if ((shape->dim != GLSL_SAMPLER_DIM_2D && shape->dim != GLSL_SAMPLER_DIM_3D) ||
       call->next == call->count)
      return true;
   LLVMValueRef value = LLVMGetOperand(call->inst, call->next);
   if (!type_is(LLVMTypeOf(value), shape->positions, LLVMIntegerTypeKind,
                call->short_indices ? 16 : 32))
      return true;
   call->next++;
   if (LLVMIsNull(value))
      return true;
   nir_def *offset = call->c->operand(call->c->translator, value);
   if (!offset)
      return false;
   *position = nir_iadd(call->b, *position, nir_i2i32(call->b, offset));
   return true;
}

/* The optional texel offset: an i1 presence flag and the offset. */
static bool
offset(struct call *call, nir_def **offset)
{
   unsigned components = call->shape->coords;
   if (call->shape->dim == GLSL_SAMPLER_DIM_CUBE)
      return true;
   uint64_t present;
   if (!constant(call, 1, &present))
      return false;
   nir_def *value = operand(call, components, LLVMIntegerTypeKind, 32);
   if (!value)
      return false;
   *offset = present && !zero_operand(call) ? value : NULL;
   return true;
}

static bool
finished(const struct call *call)
{
   return call->next == call->count || fail(call, "texture call has too many operands");
}

static nir_deref_instr *
bind_texture(const struct call *call, const struct glsl_type *type, bool faces, nir_def *level)
{
   const struct stela_air_options *options = call->c->options;
   nir_deref_instr *deref = NULL;
   if (call->texture_id && options->bind_texture_id)
      deref = options->bind_texture_id(call->b, call->texture_id, type, faces, level,
                                       options->binding_data);
   else if (!call->texture_id && options->bind_texture)
      deref = options->bind_texture(call->b, call->texture, type, faces, level,
                                    options->binding_data);
   if (!deref || deref->type != type) {
      fail(call, "texture %u is unbound or bound to another type", call->texture->index);
      return NULL;
   }
   return deref;
}

static nir_deref_instr *
texture_deref(const struct call *call, nir_def *level)
{
   return bind_texture(call, descriptor_type(call->texture), false, level);
}

/* A cube texture's faces: a 2D array whose layer is face + 6 * cube. */
static nir_deref_instr *
faces_deref(const struct call *call)
{
   return bind_texture(call, glsl_texture_type(GLSL_SAMPLER_DIM_2D, true, base_type(call->texture)),
                       true, NULL);
}

static nir_deref_instr *
sampler_deref(struct call *call)
{
   LLVMValueRef value = take(call);
   if (!value)
      return NULL;
   nir_def *id;
   const struct stela_air_sampler *sampler = call->c->sampler(call->c->translator, value, &id);
   if (!sampler && !id) {
      fail(call, "texture call samples with a value that is not a sampler");
      return NULL;
   }
   const struct stela_air_options *options = call->c->options;
   bool integer = integer_texels(call->texture);
   nir_deref_instr *deref = NULL;
   if (id && options->bind_sampler_id)
      deref = options->bind_sampler_id(call->b, id, integer, options->binding_data);
   else if (!id && options->bind_sampler)
      deref = options->bind_sampler(call->b, sampler, integer, options->binding_data);
   if (!deref || deref->type != glsl_bare_sampler_type()) {
      fail(call, "a sampler is unbound");
      return NULL;
   }
   if (options->sampler_never)
      call->never = options->sampler_never(call->b, id ? NULL : sampler, id, options->binding_data);
   /* A constexpr sampler's bits fold to a constant, which decides whether
    * its samples take the bicubic path. A bound sampler's matter only where
    * the options say the one bound there filters bicubically, and an
    * argument value's where samplers of argument values may. */
   bool cubic = id ? options->dynamic_bicubic || nir_src_is_const(nir_src_for_ssa(id)) :
                     sampler->index < 32 && (options->bicubic_samplers >> sampler->index & 1);
   if (options->sampler_filter && cubic) {
      bool fold = call->b->constant_fold_alu;
      call->b->constant_fold_alu = true;
      call->filter = options->sampler_filter(call->b, id ? NULL : sampler, id, options->binding_data);
      call->b->constant_fold_alu = fold;
   }
   return deref;
}

struct tex {
   nir_texop op;
   nir_deref_instr *texture, *sampler;
   nir_def *coord, *comparator, *offset, *lod, *bias, *min_lod, *ddx, *ddy, *ms_index;
   unsigned component;
   /* faces reads a cube texture through faces_deref. */
   bool shadow, faces;
};

static nir_def *
emit(const struct call *call, const struct tex *t)
{
   const struct {
      nir_tex_src_type type;
      nir_def *def;
   } sources[] = {
      {nir_tex_src_texture_deref, &t->texture->def},
      {nir_tex_src_sampler_deref, t->sampler ? &t->sampler->def : NULL},
      {nir_tex_src_coord, t->coord}, {nir_tex_src_comparator, t->comparator},
      {nir_tex_src_offset, t->offset}, {nir_tex_src_lod, t->lod}, {nir_tex_src_bias, t->bias},
      {nir_tex_src_min_lod, t->min_lod}, {nir_tex_src_ddx, t->ddx}, {nir_tex_src_ddy, t->ddy},
      {nir_tex_src_ms_index, t->ms_index},
   };
   unsigned count = 0;
   for (unsigned i = 0; i < ARRAY_SIZE(sources); i++)
      count += sources[i].def != NULL;
   nir_tex_instr *tex = nir_tex_instr_create(call->b->shader, count);
   for (unsigned i = 0, n = 0; i < ARRAY_SIZE(sources); i++) {
      if (sources[i].def)
         tex->src[n++] = nir_tex_src_for_ssa(sources[i].type, sources[i].def);
   }
   tex->op = t->op;
   tex->sampler_dim = t->faces ? GLSL_SAMPLER_DIM_2D : call->shape->dim;
   tex->is_array = t->faces || call->shape->array;
   tex->is_shadow = t->shadow;
   /* A comparison returns one value, but a gather four: NIR reads a
    * new-style shadow op's result as a single component. */
   tex->is_new_style_shadow = t->shadow && t->op != nir_texop_tg4;
   tex->is_sparse = call->sparse;
   tex->component = t->component;
   if (t->coord)
      tex->coord_components = t->coord->num_components;
   switch (t->op) {
   case nir_texop_txs:
   case nir_texop_query_levels:
   case nir_texop_texture_samples:
      tex->dest_type = nir_type_int32;
      break;
   case nir_texop_lod:
      tex->dest_type = nir_type_float32;
      break;
   default:
      tex->dest_type = nir_get_nir_type_for_glsl_base_type(base_type(call->texture));
      break;
   }
   nir_def_init(&tex->instr, &tex->def, nir_tex_instr_dest_size(tex), 32);
   nir_builder_instr_insert(call->b, &tex->instr);
   /* A Never comparison fails every texel; the sparse residency stays. */
   if (t->shadow && call->never) {
      nir_def *channels[NIR_MAX_VEC_COMPONENTS];
      unsigned compared = tex->def.num_components - call->sparse;
      for (unsigned i = 0; i < tex->def.num_components; i++) {
         channels[i] = nir_channel(call->b, &tex->def, i);
         if (i < compared)
            channels[i] = nir_bcsel(call->b, call->never, nir_imm_float(call->b, 0.0f), channels[i]);
      }
      return nir_vec(call->b, channels, tex->def.num_components);
   }
   return &tex->def;
}

/* The texel of a sparse result, whose last component is its residency code,
 * keeping the residency; any other result as it is. */
static nir_def *
resident(struct call *call, nir_def *value)
{
   if (!call->sparse)
      return value;
   nir_builder *b = call->b;
   unsigned components = value->num_components - 1;
   nir_def *code = nir_channel(b, value, components);
   call->residency = nir_b2iN(b, nir_inot(b, nir_is_sparse_texels_resident(b, 1, code)), 8);
   return nir_trim_vector(b, value, components);
}

/* A 32-bit texel as the shader's texel type: one float for depth, 16-bit
 * components for half, short and ushort textures. */
static nir_def *
texel(const struct call *call, nir_def *value, bool gather)
{
   nir_builder *b = call->b;
   if (call->texture->depth)
      return gather || value->num_components == 1 ? value : nir_channel(b, value, 0);
   switch (call->texture->primitive) {
   case STELA_AIR_HALF: return nir_f2f16(b, value);
   case STELA_AIR_SHORT: return nir_i2i16(b, value);
   case STELA_AIR_USHORT: return nir_u2u16(b, value);
   default: return value;
   }
}

/* The coordinate with an array layer appended: a float for sampling. */
static nir_def *
layered(const struct call *call, nir_def *coord, nir_def *layer, bool sample)
{
   if (!layer)
      return coord;
   nir_def *components[4];
   for (unsigned i = 0; i < coord->num_components; i++)
      components[i] = nir_channel(call->b, coord, i);
   components[coord->num_components] = sample ? nir_u2f32(call->b, layer) : layer;
   return nir_vec(call->b, components, coord->num_components + 1);
}

/* What a sample's coordinates divide by for its sampler: the base level's
 * size where the sampler takes pixel coordinates, whose Vulkan sampler is
 * normalized and held to the base level, else one. NULL where the sampler
 * cannot take them: Metal's pixel coordinates do not reach cube textures. */
static nir_def *
pixel_scale(const struct call *call, nir_deref_instr *texture)
{
   if (!call->filter || call->shape->dim == GLSL_SAMPLER_DIM_CUBE)
      return NULL;
   nir_src filter = nir_src_for_ssa(call->filter);
   if (nir_src_is_const(filter) && !(nir_src_as_uint(filter) & STELA_AIR_SAMPLER_PIXELS))
      return NULL;
   nir_builder *b = call->b;
   unsigned n = call->shape->coords;
   struct tex size = {.op = nir_texop_txs, .texture = texture, .lod = nir_imm_int(b, 0)};
   nir_def *texels = nir_i2f32(b, nir_trim_vector(b, emit(call, &size), n));
   nir_def *one = nir_trim_vector(b, nir_imm_vec4(b, 1.0, 1.0, 1.0, 1.0), n);
   return nir_bcsel(b, nir_test_mask(b, call->filter, STELA_AIR_SAMPLER_PIXELS), texels, one);
}

/* Catmull-Rom's weights (B = 0, C = 1/2) of the four texels about a
 * sample a fraction f past the second's center. */
static void
catmull_rom(nir_builder *b, nir_def *f, nir_def *weights[4])
{
   nir_def *f2 = nir_fmul(b, f, f), *f3 = nir_fmul(b, f2, f);
   nir_def *half_f3 = nir_fmul_imm(b, f3, 0.5);
   /* (-f^3 + 2f^2 - f) / 2, (3f^3 - 5f^2 + 2) / 2, (-3f^3 + 4f^2 + f) / 2,
    * (f^3 - f^2) / 2. */
   weights[0] = nir_fsub(b, nir_fsub(b, f2, half_f3), nir_fmul_imm(b, f, 0.5));
   weights[1] = nir_fadd_imm(b, nir_fsub(b, nir_fmul_imm(b, f3, 1.5), nir_fmul_imm(b, f2, 2.5)), 1.0);
   weights[2] = nir_fadd(b, nir_fsub(b, nir_fmul_imm(b, f2, 2.0), nir_fmul_imm(b, f3, 1.5)),
                         nir_fmul_imm(b, f, 0.5));
   weights[3] = nir_fsub(b, half_f3, nir_fmul_imm(b, f2, 0.5));
}

/* The sampler's lod_min_clamp (or its lod_max_clamp): the level of detail
 * the sampler clamps a pixel's coordinates to when they change by 2^-24
 * (2^24) of the texture per pixel, far below (above) any level. Fragment
 * functions alone take implicit derivatives. */
static nir_def *
sampler_lod_bound(const struct call *call, const struct tex *t, float scale)
{
   nir_builder *b = call->b;
   nir_def *pixel = nir_trim_vector(b, nir_load_frag_coord(b), 2);
   struct tex query = {.op = nir_texop_lod, .texture = t->texture, .sampler = t->sampler,
                       .coord = nir_fmul_imm(b, pixel, scale)};
   return nir_channel(b, emit(call, &query), 0);
}

/* The level of detail Metal selects a bicubic sample's mip level from:
 * the explicit or computed one plus the bias, clamped to the sampler's
 * range, then to the shader's minimum. */
static nir_def *
cubic_lod(const struct call *call, const struct tex *t)
{
   nir_builder *b = call->b;
   nir_def *lod;
   if (t->op == nir_texop_txl) {
      lod = t->lod;
   } else if (t->op == nir_texop_txd) {
      /* log2 of the longer gradient in base-level texels. */
      struct tex size = {.op = nir_texop_txs, .texture = t->texture, .lod = nir_imm_int(b, 0)};
      nir_def *texels = nir_i2f32(b, nir_trim_vector(b, emit(call, &size), 2));
      nir_def *x = nir_fmul(b, t->ddx, texels), *y = nir_fmul(b, t->ddy, texels);
      lod = nir_flog2(b, nir_fsqrt(b, nir_fmax(b, nir_fdot(b, x, x), nir_fdot(b, y, y))));
   } else {
      struct tex query = {.op = nir_texop_lod, .texture = t->texture, .sampler = t->sampler,
                          .coord = nir_trim_vector(b, t->coord, 2)};
      /* The unclamped level: the sampler's clamp follows the bias. */
      lod = nir_channel(b, emit(call, &query), 1);
      if (t->bias)
         lod = nir_fadd(b, lod, t->bias);
   }
   if (b->shader->info.stage == MESA_SHADER_FRAGMENT) {
      lod = nir_fmax(b, lod, sampler_lod_bound(call, t, 0x1p-24f));
      lod = nir_fmin(b, lod, sampler_lod_bound(call, t, 0x1p24f));
   }
   /* Elsewhere the taps' explicit level clamps to the sampler's range. */
   return t->min_lod ? nir_fmax(b, lod, t->min_lod) : lod;
}

/* One bicubic sample's taps: a loop over them, which keeps each sample's
 * code to one tap however many sites a shader has. */
struct cubic_taps {
   struct call *call;
   const struct tex *t;
   nir_def *first, *scale, *layer, *lod, *wx, *wy, *nearest;
};

/* Tap index of the 4 x 4 about the sample, or the nearest texel alone: a
 * texel-center tap through the sampler, which keeps its address modes,
 * weighted into the sum, values[0], and with sparse residency its code
 * ANDed into values[1]. */
static bool
cubic_tap(void *data, nir_def *index, nir_def **values)
{
   struct cubic_taps *taps = data;
   struct call *call = taps->call;
   nir_builder *b = call->b;
   nir_def *i = nir_iand_imm(b, index, 3), *j = nir_ushr_imm(b, index, 2);
   nir_def *step = nir_vec2(b, nir_u2f32(b, i), nir_u2f32(b, j));
   nir_def *center = nir_fadd(b, taps->first, nir_fadd_imm(b, step, -0.5));
   nir_def *c = nir_fdiv(b, center, taps->scale);
   nir_def *channels[3] = {nir_channel(b, c, 0), nir_channel(b, c, 1), taps->layer};
   struct tex tap = {.op = nir_texop_txl, .texture = taps->t->texture, .sampler = taps->t->sampler,
                     .coord = nir_vec(b, channels, taps->layer ? 3 : 2), .lod = taps->lod};
   nir_def *texel = emit(call, &tap);
   if (call->sparse) {
      nir_def *tap_code = nir_channel(b, texel, 4);
      nir_def *code = nir_sparse_residency_code_and(b, values[1], tap_code);
      values[1] = nir_bcsel(b, nir_ieq_imm(b, index, 0), tap_code, code);
      texel = nir_trim_vector(b, texel, 4);
   }
   nir_def *weight = nir_bcsel(b, taps->nearest, nir_imm_float(b, 1.0),
                               nir_fmul(b, nir_vector_extract(b, taps->wx, i),
                                        nir_vector_extract(b, taps->wy, j)));
   values[0] = nir_ffma(b, texel, weight, values[0]);
   return true;
}

/* A 2D texture's sample through a sampler with Metal's bicubic filter,
 * which Vulkan lacks: sixteen texel-center taps through the sampler, which
 * keeps its address modes, weighted as Apple GPUs weigh them, on the mip
 * level nearest mip selection takes. Normalized formats' results clamp to
 * their range, and 32-bit float textures take the nearest texel. With a
 * linear mip filter between levels Apple GPUs hang. */
static nir_def *
bicubic(struct call *call, const struct tex *t)
{
   nir_builder *b = call->b;
   const struct stela_air_options *options = call->c->options;
   nir_def *class = options->texture_filter_class(
      b, call->texture_id ? NULL : call->texture, call->texture_id, options->binding_data);
   nir_def *level = nir_imm_int(b, 0);
   if (!(t->op == nir_texop_txl && nir_src_is_const(nir_src_for_ssa(t->lod)) &&
         nir_src_as_float(nir_src_for_ssa(t->lod)) == 0.0)) {
      /* Vulkan's nearest selection: ceil(lod + 1/2) - 1 within the levels. */
      struct tex count = {.op = nir_texop_query_levels, .texture = t->texture};
      nir_def *last = nir_iadd_imm(b, emit(call, &count), -1);
      nir_def *rounded = nir_fceil(b, nir_fadd_imm(b, cubic_lod(call, t), 0.5));
      nir_def *nearest = nir_iadd_imm(b, nir_f2i32(b, rounded), -1);
      nearest = nir_imin(b, nir_imax(b, nearest, nir_imm_int(b, 0)), last);
      level = nir_bcsel(b, nir_test_mask(b, call->filter, STELA_AIR_SAMPLER_MIPPED), nearest, level);
   }
   /* Pixel coordinates arrive normalized (pixel_scale). */
   struct tex size = {.op = nir_texop_txs, .texture = t->texture, .lod = level};
   nir_def *scale = nir_i2f32(b, nir_trim_vector(b, emit(call, &size), 2));
   nir_def *position = nir_fmul(b, nir_trim_vector(b, t->coord, 2), scale);
   if (t->offset)
      position = nir_fadd(b, position, nir_i2f32(b, t->offset));
   /* The nearest texel is the one tap at floor(p) + 1/2; the 4 x 4 starts
    * at floor(p - 1/2) - 1/2, a fraction f before p - 1/2. */
   nir_def *nearest = nir_ieq_imm(b, class, STELA_AIR_FILTER_NEAREST);
   nir_def *centered = nir_fadd_imm(b, position, -0.5);
   nir_def *start = nir_ffloor(b, centered);
   nir_def *fraction = nir_fsub(b, centered, start);
   nir_def *wx[4], *wy[4];
   catmull_rom(b, nir_channel(b, fraction, 0), wx);
   catmull_rom(b, nir_channel(b, fraction, 1), wy);
   struct cubic_taps taps = {
      .call = call,
      .t = t,
      .first = nir_bcsel(b, nearest, nir_fadd_imm(b, nir_ffloor(b, position), 1.0), start),
      .scale = scale,
      .layer = t->coord->num_components > 2 ? nir_channel(b, t->coord, 2) : NULL,
      .lod = nir_i2f32(b, level),
      .wx = nir_vec(b, wx, 4),
      .wy = nir_vec(b, wy, 4),
      .nearest = nearest,
   };
   nir_def *values[2] = {nir_imm_zero(b, 4, 32), nir_imm_int(b, 0)};
   const struct stela_air_texture_context *c = call->c;
   if (!c->repeat(c->translator, nir_bcsel(b, nearest, nir_imm_int(b, 1), nir_imm_int(b, 16)),
                  call->sparse ? 2 : 1, values, cubic_tap, &taps))
      return NULL;
   nir_def *sum = values[0];
   nir_def *low = nir_bcsel(b, nir_ieq_imm(b, class, STELA_AIR_FILTER_SNORM),
                            nir_imm_float(b, -1.0), nir_imm_float(b, 0.0));
   nir_def *clamped = nir_fmin(b, nir_fmax(b, sum, low), nir_imm_float(b, 1.0));
   nir_def *normalized = nir_iand(b, nir_ine_imm(b, class, STELA_AIR_FILTER_FLOAT),
                                  nir_inot(b, nearest));
   nir_def *filtered = nir_bcsel(b, normalized, clamped, sum);
   if (call->sparse)
      filtered = nir_vector_insert_imm(b, nir_pad_vector(b, filtered, 5), values[1], 4);
   return filtered;
}

/* Whether a sample may go through bicubic: Metal's bicubic filter reaches a
 * float 2D texture's samples that do not compare, through a constexpr
 * sampler that has it or another the options say may have it. */
static bool
cubic_reaches(const struct call *call, bool compare)
{
   const struct stela_air_options *options = call->c->options;
   if (!call->filter || !options->texture_filter_class || !call->c->branch || !call->c->repeat ||
       compare || call->shape->dim != GLSL_SAMPLER_DIM_2D ||
       base_type(call->texture) != GLSL_TYPE_FLOAT)
      return false;
   /* The bits are read only where the sampler may filter bicubically. */
   nir_src filter = nir_src_for_ssa(call->filter);
   return !nir_src_is_const(filter) || (nir_src_as_uint(filter) & STELA_AIR_SAMPLER_CUBIC) != 0;
}

/* Whether a sample or read may be of a two-plane texture: a float 2D
 * texture's, where the options say textures may have two planes. */
static bool
planes_reach(const struct call *call)
{
   const struct stela_air_options *options = call->c->options;
   return options->dynamic_planes && options->texture_planes && call->c->branch &&
          !call->sparse && call->shape->dim == GLSL_SAMPLER_DIM_2D && !call->shape->array &&
          !call->texture->depth && base_type(call->texture) == GLSL_TYPE_FLOAT;
}

/* The texture's second plane (enum stela_air_planes), zero for one. */
static nir_def *
texture_planes(const struct call *call)
{
   const struct stela_air_options *options = call->c->options;
   return options->texture_planes(call->b, call->texture_id ? NULL : call->texture,
                                  call->texture_id, options->binding_data);
}

/* How a two-plane texture's components convert, from texture_planes: a
 * texture's own values, which every sample and read of it shares. Each
 * component is first taken in whole steps: a byte, or the high 10 bits of
 * a 16-bit word, whose low 6 bits Apple GPUs ignore. The first plane's then
 * converts as (step + luma_bias) * luma_scale, the second's as (step +
 * chroma_bias) * chroma_scale: luma and chroma where `ycbcr`, else green
 * and blue and red over the largest step. Computed once ahead of the
 * branch to the planes, a function's samples of one texture share them. */
struct planes_conversion {
   nir_def *ten, *ycbcr;
   nir_def *steps;
   nir_def *luma_bias, *luma_scale;
   nir_def *chroma_bias, *chroma_scale;
};

/* BT.601 luma and chroma (Apple GPUs' conversion) in full range (luma over
 * the largest step, chroma (C - half) over twice that half, (C - 128) / 256
 * for bytes) or video range (luma (Y - 16 s) / (219 s), chroma (C - half) /
 * (224 s), s a byte's step in the component's). */
static struct planes_conversion
planes_conversion(nir_builder *b, nir_def *planes)
{
   struct planes_conversion c;
   c.ten = nir_test_mask(b, planes, STELA_AIR_PLANES_TEN_BIT);
   c.ycbcr = nir_test_mask(b, planes, STELA_AIR_PLANES_YCBCR);
   nir_def *video = nir_iand(b, c.ycbcr, nir_test_mask(b, planes, STELA_AIR_PLANES_VIDEO));
   nir_def *full = nir_iand(b, c.ycbcr, nir_inot(b, video));
#define TEN(wide, narrow) nir_bcsel(b, c.ten, nir_imm_float(b, wide), nir_imm_float(b, narrow))
   c.steps = TEN(65535.0f / 64.0f, 255.0f);
   nir_def *largest = TEN(1.0f / 1023.0f, 1.0f / 255.0f);
   nir_def *zero = nir_imm_float(b, 0.0f);
   c.luma_bias = nir_bcsel(b, video, TEN(-64.0f, -16.0f), zero);
   c.luma_scale = nir_bcsel(b, video, TEN(1.0f / 876.0f, 1.0f / 219.0f), largest);
   c.chroma_bias = nir_bcsel(b, c.ycbcr, TEN(-512.0f, -128.0f), zero);
   c.chroma_scale = nir_bcsel(b, video, TEN(1.0f / 896.0f, 1.0f / 224.0f),
                              nir_bcsel(b, full, TEN(1.0f / 1024.0f, 1.0f / 256.0f), largest));
#undef TEN
   return c;
}

/* A plane's components in whole steps from its view's UNORM values. A read
 * takes the step exactly; a filtered sample keeps the fraction, within a
 * step of the low bits' share. */
static nir_def *
plane_steps(nir_builder *b, nir_def *value, const struct planes_conversion *c, bool read)
{
   if (!read)
      return nir_fmul(b, value, c->steps);
   nir_def *wide = nir_fmul_imm(b, nir_fround_even(b, nir_fmul_imm(b, value, 65535.0)), 1.0 / 64.0);
   return nir_bcsel(b, c->ten, nir_ffloor(b, wide), nir_fround_even(b, nir_fmul_imm(b, value, 255.0)));
}

/* A two-plane texture's texel, opaque, from its components in whole steps:
 * green from its first plane's, blue and red from its second's; or luma
 * and Cb and Cr converted to RGB as Apple GPUs convert them, saturated and
 * rounded to 1/2048. */
static nir_def *
planes_color(nir_builder *b, nir_def *first, nir_def *second, const struct planes_conversion *c)
{
   nir_def *luma = nir_fmul(b, nir_fadd(b, nir_channel(b, first, 0), c->luma_bias), c->luma_scale);
   nir_def *chroma = nir_fmul(b, nir_fadd(b, nir_trim_vector(b, second, 2), c->chroma_bias),
                              c->chroma_scale);
   nir_def *cb = nir_channel(b, chroma, 0), *cr = nir_channel(b, chroma, 1);
   nir_def *rgb = nir_vec3(b, cr, luma, cb);
   nir_def *green = nir_ffma(b, cb, nir_imm_float(b, -0.344136f), luma);
   nir_def *converted =
      nir_fsat(b, nir_vec3(b, nir_ffma(b, cr, nir_imm_float(b, 1.402f), luma),
                           nir_ffma(b, cr, nir_imm_float(b, -0.714136f), green),
                           nir_ffma(b, cb, nir_imm_float(b, 1.772f), luma)));
   converted = nir_fmul_imm(b, nir_fround_even(b, nir_fmul_imm(b, converted, 2048.0)), 1.0 / 2048.0);
   nir_def *color = nir_bcsel(b, c->ycbcr, converted, rgb);
   return nir_vec4(b, nir_channel(b, color, 0), nir_channel(b, color, 1), nir_channel(b, color, 2),
                   nir_imm_float(b, 1.0));
}

/* A two-plane texture's texel from its planes' UNORM values, as samples
 * filter them: in whole steps, then planes_color. */
static nir_def *
planes_rgba(nir_builder *b, nir_def *first, nir_def *second, const struct planes_conversion *c)
{
   return planes_color(b, plane_steps(b, first, c, false), plane_steps(b, second, c, false), c);
}

nir_def *
stela_air_planes_rgba(nir_builder *b, nir_def *first, nir_def *second, nir_def *planes)
{
   struct planes_conversion c = planes_conversion(b, planes);
   return planes_rgba(b, first, second, &c);
}

/* The inverse: an RGB color's first-plane value and its second plane's
 * two, in [0, 1]. Luma and chroma are full-range BT.601 with chroma scaled
 * by 256 / 255 around 128 / 255, as Apple GPUs store them. */
void
stela_air_rgb_planes(nir_builder *b, nir_def *rgba, bool ycbcr, nir_def **first, nir_def **second)
{
   nir_def *rgb = nir_fsat(b, nir_trim_vector(b, rgba, 3));
   nir_def *r = nir_channel(b, rgb, 0), *g = nir_channel(b, rgb, 1), *bl = nir_channel(b, rgb, 2);
   if (!ycbcr) {
      *first = g;
      *second = nir_vec2(b, bl, r);
      return;
   }
   nir_def *luma = nir_fdot(b, rgb, nir_imm_vec3(b, 0.299f, 0.587f, 0.114f));
   nir_def *offset = nir_imm_float(b, 128.0f / 255.0f);
   nir_def *cb = nir_ffma(b, nir_fsub(b, bl, luma), nir_imm_float(b, 256.0f / (255.0f * 1.772f)), offset);
   nir_def *cr = nir_ffma(b, nir_fsub(b, r, luma), nir_imm_float(b, 256.0f / (255.0f * 1.402f)), offset);
   *first = luma;
   *second = nir_fsat(b, nir_vec2(b, cb, cr));
}

/* A two-plane texture's second plane at its first plane's texel coord, in
 * whole steps, as Apple GPUs read it: each axis the plane halves takes its
 * two texels nearest the center, three quarters of the nearer, clamped at
 * the edges; an axis it keeps takes the texel. Apple GPUs upsample to
 * whole steps, rounding halves up, so the sum is taken in sixteenths of
 * whole steps, where it is exact. */
static nir_def *
planes_upsampled(const struct call *call, const struct tex *second, nir_def *coord,
                 nir_def *planes, const struct planes_conversion *conversion)
{
   nir_builder *b = call->b;
   nir_def *subsampling = nir_iand_imm(b, planes, STELA_AIR_PLANES_SUBSAMPLING);
   nir_def *halves = nir_vec2(b, nir_uge_imm(b, subsampling, STELA_AIR_PLANES_HORIZONTAL),
                              nir_ieq_imm(b, subsampling, STELA_AIR_PLANES_BOTH));
   struct tex size = {.op = nir_texop_txs, .texture = second->texture,
                      .lod = second->lod ? second->lod : nir_imm_int(b, 0)};
   nir_def *last = nir_iadd_imm(b, nir_trim_vector(b, emit(call, &size), 2), -1);
   nir_def *odd = nir_ine_imm(b, nir_iand_imm(b, coord, 1), 0);
   nir_def *first = nir_bcsel(b, halves, nir_ishr_imm(b, nir_iadd_imm(b, coord, -1), 1), coord);
   /* The second texel's weight in quarters. */
   nir_def *weight = nir_bcsel(b, halves, nir_bcsel(b, odd, nir_imm_float(b, 1.0f),
                                                    nir_imm_float(b, 3.0f)),
                               nir_imm_float(b, 0.0f));
   nir_def *zero = nir_imm_ivec2(b, 0, 0);
   nir_def *low = nir_imin(b, nir_imax(b, first, zero), last);
   nir_def *high = nir_imin(b, nir_imax(b, nir_iadd_imm(b, first, 1), zero), last);
   nir_def *texels[4];
   for (unsigned i = 0; i < 4; i++) {
      struct tex at = *second;
      at.coord = nir_vec2(b, nir_channel(b, i & 1 ? high : low, 0),
                          nir_channel(b, i & 2 ? high : low, 1));
      texels[i] = plane_steps(b, emit(call, &at), conversion, true);
   }
   nir_def *rows[2];
   nir_def *across = nir_channel(b, weight, 0), *down = nir_channel(b, weight, 1);
   for (unsigned i = 0; i < 2; i++)
      rows[i] = nir_ffma(b, across, texels[2 * i + 1],
                         nir_fmul(b, nir_fsub_imm(b, 4.0, across), texels[2 * i]));
   nir_def *sum = nir_ffma(b, down, rows[1], nir_fmul(b, nir_fsub_imm(b, 4.0, down), rows[0]));
   return nir_ffloor(b, nir_fmul_imm(b, nir_fadd_imm(b, sum, 8.0), 1.0 / 16.0));
}

/* A sample through t: bicubic where the sampler may filter so, else as
 * Vulkan samples. */
static nir_def *
one_sample(struct call *call, const struct tex *t, bool compare)
{
   if (!cubic_reaches(call, compare))
      return emit(call, t);
   const struct stela_air_texture_context *c = call->c;
   nir_block *blocks[4];
   if (!c->branch(c->translator, nir_test_mask(call->b, call->filter, STELA_AIR_SAMPLER_CUBIC),
                  blocks))
      return NULL;
   nir_def *cubic = bicubic(call, t);
   if (!cubic)
      return NULL;
   c->branch_else(c->translator, blocks);
   return c->branch_join(c->translator, blocks, cubic, emit(call, t));
}

static bool
sample(struct call *call, enum operation op, nir_def **result)
{
   const struct shape *shape = call->shape;
   bool compare = op == SAMPLE_COMPARE || op == SAMPLE_COMPARE_GRAD;
   if (call->texture->access != STELA_AIR_TEXTURE_SAMPLE)
      return fail(call, "sampling a texture without sample access");
   if (shape->dim == GLSL_SAMPLER_DIM_MS || shape->dim == GLSL_SAMPLER_DIM_BUF)
      return fail(call, "sampling a multisample or buffer texture");
   if (compare && !call->texture->depth)
      return fail(call, "comparing a texture that is not a depth texture");
   if (!result_type(call, false))
      return fail(call, "texture sample has an unexpected result type");
   struct tex t = {.op = nir_texop_tex, .shadow = compare};
   if (!(t.texture = texture_deref(call, NULL)) || !(t.sampler = sampler_deref(call)))
      return false;
   if (call->texture->depth && !expect(call, 32, 1, "depth operand"))
      return false;
   nir_def *coord = float_operand(call, shape->coords);
   nir_def *layer = shape->array ? uint_operand(call) : NULL;
   if (!coord || (shape->array && !layer))
      return false;
   nir_def *scale = pixel_scale(call, t.texture);
   if (scale)
      coord = nir_fdiv(call->b, coord, scale);
   t.coord = layered(call, coord, layer, true);
   if (compare && !(t.comparator = float_operand(call, 1)))
      return false;
   bool fragment = call->b->shader->info.stage == MESA_SHADER_FRAGMENT;
   if (op == SAMPLE_GRAD || op == SAMPLE_COMPARE_GRAD) {
      t.op = nir_texop_txd;
      if (!(t.ddx = float_operand(call, shape->coords)) ||
          !(t.ddy = float_operand(call, shape->coords)) || !min_lod_operand(call, &t.min_lod))
         return false;
      if (scale) {
         t.ddx = nir_fdiv(call->b, t.ddx, scale);
         t.ddy = nir_fdiv(call->b, t.ddy, scale);
      }
      if (!offset(call, &t.offset))
         return false;
   } else {
      if (!offset(call, &t.offset))
         return false;
      uint64_t level;
      if (!constant(call, 1, &level))
         return false;
      nir_def *lod = float_operand(call, 1);
      bool zero_lod = lod && zero_operand(call);
      nir_def *min_lod;
      if (!lod || !min_lod_operand(call, &min_lod))
         return false;
      if (level) {
         t.op = nir_texop_txl;
         t.lod = lod;
      } else if (fragment) {
         t.op = zero_lod ? nir_texop_tex : nir_texop_txb;
         t.bias = zero_lod ? NULL : lod;
      } else {
         /* No implicit derivatives outside fragment functions: Metal samples
          * from the base level, biased. */
         t.op = nir_texop_txl;
         t.lod = lod;
      }
      if (min_lod) {
         if (t.op == nir_texop_txl)
            t.lod = nir_fmax(call->b, t.lod, min_lod);
         else
            t.min_lod = min_lod;
      }
   }
   if (!access_operand(call, STELA_AIR_TEXTURE_SAMPLE) || !finished(call))
      return false;
   nir_def *value;
   if (!compare && planes_reach(call)) {
      /* A two-plane texture's planes sample at the same coordinates, each
       * filtering its own texels. */
      const struct stela_air_texture_context *c = call->c;
      nir_block *blocks[4];
      nir_def *planes = texture_planes(call);
      if (!planes)
         return false;
      struct planes_conversion conversion = planes_conversion(call->b, planes);
      if (!c->branch(c->translator, nir_ine_imm(call->b, planes, 0), blocks))
         return false;
      struct tex second = t;
      if (!(second.texture = bind_texture(call, descriptor_type(call->texture), true, NULL)))
         return false;
      nir_def *combined = planes_rgba(call->b, emit(call, &t), emit(call, &second), &conversion);
      c->branch_else(c->translator, blocks);
      nir_def *single = one_sample(call, &t, compare);
      if (!single || !(value = c->branch_join(c->translator, blocks, combined, single)))
         return false;
   } else if (!(value = one_sample(call, &t, compare))) {
      return false;
   }
   *result = texel(call, resident(call, value), false);
   return true;
}

static bool
gather(struct call *call, enum operation op, nir_def **result)
{
   const struct shape *shape = call->shape;
   bool compare = op == GATHER_COMPARE;
   if (call->texture->access != STELA_AIR_TEXTURE_SAMPLE)
      return fail(call, "gathering from a texture without sample access");
   if (shape->dim != GLSL_SAMPLER_DIM_2D && shape->dim != GLSL_SAMPLER_DIM_CUBE)
      return fail(call, "gathering from a texture that is not 2D or cube");
   if (compare && !call->texture->depth)
      return fail(call, "comparing a texture that is not a depth texture");
   if (!result_type(call, true))
      return fail(call, "texture gather has an unexpected result type");
   struct tex t = {.op = nir_texop_tg4, .shadow = compare};
   if (!(t.texture = texture_deref(call, NULL)) || !(t.sampler = sampler_deref(call)))
      return false;
   if (call->texture->depth && !expect(call, 32, 1, "depth operand"))
      return false;
   nir_def *coord = float_operand(call, shape->coords);
   nir_def *layer = shape->array ? uint_operand(call) : NULL;
   if (!coord || (shape->array && !layer))
      return false;
   nir_def *scale = pixel_scale(call, t.texture);
   if (scale)
      coord = nir_fdiv(call->b, coord, scale);
   t.coord = layered(call, coord, layer, true);
   if (compare && !(t.comparator = float_operand(call, 1)))
      return false;
   if (!offset(call, &t.offset))
      return false;
   if (!call->texture->depth) {
      uint64_t component;
      if (!constant(call, 32, &component))
         return false;
      if (component > 3)
         return fail(call, "gathering component %llu", (unsigned long long)component);
      t.component = (unsigned)component;
   }
   if (!access_operand(call, STELA_AIR_TEXTURE_SAMPLE) || !finished(call))
      return false;
   *result = texel(call, resident(call, emit(call, &t)), true);
   return true;
}

/* An image coordinate: the position, then the cube face (plus six per
 * layer of a cube array) or the layer, padded to four components. */
static nir_def *
image_coord(const struct call *call, nir_def *position, nir_def *face, nir_def *layer)
{
   nir_builder *b = call->b;
   nir_def *components[4];
   unsigned n = 0;
   for (unsigned i = 0; i < position->num_components; i++)
      components[n++] = nir_channel(b, position, i);
   if (face)
      components[n++] = layer ? nir_iadd(b, face, nir_imul_imm(b, layer, 6)) : face;
   else if (layer)
      components[n++] = layer;
   while (n < 4)
      components[n++] = nir_imm_int(b, 0);
   return nir_vec(b, components, 4);
}

/* The level operand of a mipmapped texture's image access, which selects its
 * descriptor; NULL for other textures. */
static bool
image_level(struct call *call, nir_def **level)
{
   *level = NULL;
   return !call->shape->mipmapped || (*level = uint_operand(call));
}

/* The access of an image intrinsic through a deref of level: the binding
 * indexes descriptors by level, which may differ between invocations. */
static enum gl_access_qualifier
image_access(const struct call *call, nir_def *level)
{
   return (call->coherent ? ACCESS_COHERENT : 0) |
          (level && !nir_src_is_const(nir_src_for_ssa(level)) ? ACCESS_NON_UNIFORM : 0);
}

/* The name of the function value calls directly, or NULL. */
static const char *
called_name(LLVMValueRef value, size_t *bytes)
{
   *bytes = 0;
   if (!LLVMIsACallInst(value))
      return NULL;
   LLVMValueRef callee = LLVMGetCalledValue(value);
   return LLVMIsAFunction(callee) ? LLVMGetValueName2(callee, bytes) : NULL;
}

bool
stela_air_read_sampler(LLVMValueRef value)
{
   size_t bytes;
   const char *name = called_name(value, &bytes);
   return name && bytes == strlen("air.get_read_sampler") && !memcmp(name, "air.get_read_sampler", bytes);
}

/* Whether `name` is `stem` and a texture type: texture_2d, depth_2d and the
 * like. */
static bool
null_named(const char *name, size_t bytes, const char *stem)
{
   size_t length = strlen(stem);
   if (bytes <= length || memcmp(name, stem, length))
      return false;
   name += length;
   bytes -= length;
   return (bytes > 8 && !memcmp(name, "texture_", 8)) || (bytes > 6 && !memcmp(name, "depth_", 6));
}

bool
stela_air_null_texture(LLVMValueRef value)
{
   size_t bytes;
   const char *name = called_name(value, &bytes);
   return name && null_named(name, bytes, "air.get_null_");
}

bool
stela_air_texture_use(LLVMValueRef inst, struct stela_air_texture *texture)
{
   static const struct {
      const char *suffix;
      enum stela_air_primitive primitive;
   } texels[] = {
      {".v4f32", STELA_AIR_FLOAT}, {".v4f16", STELA_AIR_HALF}, {".s.v4i32", STELA_AIR_INT},
      {".u.v4i32", STELA_AIR_UINT}, {".s.v4i16", STELA_AIR_SHORT}, {".u.v4i16", STELA_AIR_USHORT},
      {".f32", STELA_AIR_FLOAT},
   };
   size_t bytes;
   const char *name = called_name(inst, &bytes);
   if (!name || LLVMGetNumArgOperands(inst) == 0)
      return false;
   /* The longest operation stem and shape name that start the name. */
   int op = -1;
   unsigned type = 0;
   bool depth = false;
   size_t matched = 0;
   for (unsigned o = 0; o < ARRAY_SIZE(operations); o++) {
      for (unsigned s = 1; s < ARRAY_SIZE(shapes); s++) {
         for (unsigned d = 0; d < 2; d++) {
            const char *shape = d ? shapes[s].depth : shapes[s].name;
            char prefix[64];
            int length = shape ? snprintf(prefix, sizeof(prefix), "air.%s_%s", operations[o].stem, shape) : 0;
            if (length <= 0 || (size_t)length <= matched || (size_t)length > bytes ||
                memcmp(prefix, name, (size_t)length) ||
                ((size_t)length < bytes && name[length] != '.' && name[length] != '_'))
               continue;
            op = (int)o, type = s, depth = d, matched = (size_t)length;
         }
      }
   }
   if (op < 0)
      return false;
   enum stela_air_primitive primitive = STELA_AIR_PRIMITIVE_UNKNOWN;
   for (unsigned i = 0; operations[op].typed && i < ARRAY_SIZE(texels); i++) {
      size_t length = strlen(texels[i].suffix);
      if (bytes > length && !memcmp(name + bytes - length, texels[i].suffix, length))
         primitive = texels[i].primitive;
   }
   if (operations[op].typed && primitive == STELA_AIR_PRIMITIVE_UNKNOWN)
      return false;
   if (texture->type && (texture->type != type || texture->depth != depth))
      return false;
   texture->type = type;
   texture->depth = depth;
   if (primitive != STELA_AIR_PRIMITIVE_UNKNOWN && !depth) {
      if (texture->primitive != STELA_AIR_PRIMITIVE_UNKNOWN && texture->primitive != primitive)
         return false;
      texture->primitive = primitive;
   }
   if (depth)
      texture->primitive = STELA_AIR_FLOAT;
   bool writes = op == WRITE || op == SLICE_WRITE, reads = op == READ;
   bool samples = op == SAMPLE || op == SAMPLE_COMPARE || op == SAMPLE_GRAD ||
                  op == SAMPLE_COMPARE_GRAD || op == GATHER || op == GATHER_COMPARE ||
                  op == BLOCK_READ;
   bool wrote = texture->access == STELA_AIR_TEXTURE_WRITE ||
                texture->access == STELA_AIR_TEXTURE_READ_WRITE;
   bool read = texture->access == STELA_AIR_TEXTURE_READ ||
               texture->access == STELA_AIR_TEXTURE_READ_WRITE;
   if (samples && wrote)
      return false;
   if (writes)
      texture->access = read ? STELA_AIR_TEXTURE_READ_WRITE : STELA_AIR_TEXTURE_WRITE;
   else if (reads && wrote)
      texture->access = STELA_AIR_TEXTURE_READ_WRITE;
   else if (reads && texture->access != STELA_AIR_TEXTURE_SAMPLE)
      texture->access = STELA_AIR_TEXTURE_READ;
   return true;
}

/* A float texel the shader writes to or read from storage images: its color
 * channels encoded to sRGB, or decoded from it, where the texture's storage
 * images hold an sRGB format's texels (stela_air_options'
 * texture_srgb_storage). Alpha stays linear. */
static nir_def *
srgb_storage(const struct call *call, nir_def *texel, bool encode)
{
   const struct stela_air_options *options = call->c->options;
   if (base_type(call->texture) != GLSL_TYPE_FLOAT || !options->texture_srgb_storage)
      return texel;
   nir_def *srgb = options->texture_srgb_storage(
      call->b, call->texture_id ? NULL : call->texture, call->texture_id, options->binding_data);
   if (!srgb)
      return texel;
   nir_builder *b = call->b;
   nir_def *channels[NIR_MAX_VEC_COMPONENTS];
   for (unsigned i = 0; i < texel->num_components; i++) {
      nir_def *c = nir_channel(b, texel, i);
      if (i < 3) {
         nir_def *converted =
            encode ? nir_format_linear_to_srgb(b, nir_fsat(b, c)) : nir_format_srgb_to_linear(b, c);
         c = nir_bcsel(b, srgb, converted, c);
      }
      channels[i] = c;
   }
   return nir_vec(b, channels, texel->num_components);
}

/* A signed position clamped to the texels of a level whose size, and then
 * layers, size holds. */
static nir_def *
edge_clamped(const struct call *call, nir_def *position, nir_def *size)
{
   nir_builder *b = call->b;
   nir_def *last = nir_iadd_imm(b, nir_trim_vector(b, size, position->num_components), -1);
   return nir_imin(b, nir_imax(b, position, nir_imm_zero(b, position->num_components, 32)), last);
}

static bool
read_texel(struct call *call, nir_def **result)
{
   const struct shape *shape = call->shape;
   const struct stela_air_texture *texture = call->texture;
   if (texture->access == STELA_AIR_TEXTURE_WRITE)
      return fail(call, "reading a write-only texture");
   if (!result_type(call, false))
      return fail(call, "texture read has an unexpected result type");
   bool image = texture->access == STELA_AIR_TEXTURE_READ_WRITE;
   /* Texel fetches take no cube, so a cube's are of its faces. */
   bool faces = shape->dim == GLSL_SAMPLER_DIM_CUBE && !image;
   nir_deref_instr *deref = image ? NULL : faces ? faces_deref(call) : texture_deref(call, NULL);
   if (!image && !deref)
      return false;
   /* Metal 4 reads take the placeholder, or a sampler, through which they
    * clamp to the texture's edge as Apple7 GPUs read. */
   LLVMValueRef sampler = call->next < call->count ? LLVMGetOperand(call->inst, call->next) : NULL;
   bool clamps = sampler && !stela_air_read_sampler(sampler) &&
                 LLVMGetTypeKind(LLVMTypeOf(sampler)) == LLVMPointerTypeKind &&
                 LLVMGetPointerAddressSpace(LLVMTypeOf(sampler)) == 2;
   call->next += clamps || (sampler && stela_air_read_sampler(sampler));
   if (texture->depth && !expect(call, 32, 1, "depth operand"))
      return false;
   nir_def *position = index_operand(call, shape->positions);
   nir_def *face = position && shape->dim == GLSL_SAMPLER_DIM_CUBE ? uint_operand(call) : NULL;
   nir_def *layer = position && shape->array ? uint_operand(call) : NULL;
   nir_def *sample = position && shape->dim == GLSL_SAMPLER_DIM_MS ? uint_operand(call) : NULL;
   if (!position || (shape->dim == GLSL_SAMPLER_DIM_CUBE && !face) || (shape->array && !layer) ||
       (shape->dim == GLSL_SAMPLER_DIM_MS && !sample))
      return false;
   if (!position_offset(call, &position))
      return false;
   nir_builder *b = call->b;
   nir_def *value;
   if (image) {
      nir_def *level;
      if (!image_level(call, &level) || !access_operand(call, texture->access) ||
          !finished(call) || !(deref = texture_deref(call, level)))
         return false;
      if (clamps) {
         nir_def *size = nir_image_deref_size(b, shape->positions + (face || layer), 32,
                                              &deref->def, nir_imm_int(b, 0),
                                              .image_dim = shape->dim, .image_array = shape->array,
                                              .access = image_access(call, level));
         position = edge_clamped(call, position, size);
      }
      nir_def *coord = image_coord(call, position, face, layer);
      nir_def *index = sample ? sample : nir_undef(b, 1, 32);
      nir_alu_type type = nir_get_nir_type_for_glsl_base_type(base_type(texture));
      value = call->sparse ?
         nir_image_deref_sparse_load(b, 5, 32, &deref->def, coord, index, nir_imm_int(b, 0),
                                     .image_dim = shape->dim, .image_array = shape->array,
                                     .access = image_access(call, level), .dest_type = type) :
         nir_image_deref_load(b, 4, 32, &deref->def, coord, index, nir_imm_int(b, 0),
                              .image_dim = shape->dim, .image_array = shape->array,
                              .access = image_access(call, level), .dest_type = type);
   } else {
      nir_def *lod = NULL;
      if (shape->mipmapped && !(lod = uint_operand(call)))
         return false;
      if (clamps) {
         struct tex size = {.op = nir_texop_txs, .texture = deref, .faces = faces,
                            .lod = shape->dim == GLSL_SAMPLER_DIM_MS ? NULL :
                                   lod ? lod : nir_imm_int(b, 0)};
         position = edge_clamped(call, position, emit(call, &size));
      }
      nir_def *coord = faces ? nir_trim_vector(b, image_coord(call, position, face, layer), 3) :
                               layered(call, position, layer, false);
      struct tex t = {.op = sample ? nir_texop_txf_ms : nir_texop_txf, .texture = deref,
                      .coord = coord, .ms_index = sample, .faces = faces, .lod = lod};
      if (!access_operand(call, texture->access) || !finished(call))
         return false;
      if (planes_reach(call)) {
         /* A two-plane texture's second plane is upsampled to the first's
          * texels: halved across from 4:2:2, both ways from 4:2:0. */
         const struct stela_air_texture_context *c = call->c;
         nir_block *blocks[4];
         nir_def *planes = texture_planes(call);
         if (!planes)
            return false;
         struct planes_conversion conversion = planes_conversion(b, planes);
         if (!c->branch(c->translator, nir_ine_imm(b, planes, 0), blocks))
            return false;
         struct tex second = t;
         if (!(second.texture = bind_texture(call, descriptor_type(texture), true, NULL)))
            return false;
         nir_def *combined =
            planes_color(b, plane_steps(b, emit(call, &t), &conversion, true),
                         planes_upsampled(call, &second, coord, planes, &conversion), &conversion);
         c->branch_else(c->translator, blocks);
         if (!(value = c->branch_join(c->translator, blocks, combined, emit(call, &t))))
            return false;
      } else {
         value = emit(call, &t);
      }
   }
   value = resident(call, value);
   if (image)
      value = srgb_storage(call, value, false);
   *result = texel(call, value, false);
   return true;
}

/* A block of texels into thread memory: the sampler, the block's position
 * and offset, the level, a zero, the texels' destination, a residency
 * destination or null, and the block's constant width and height. Texel
 * (x, y) of the block is at position + offset + (x, y), its destination's
 * element y * width + x, and its residency that byte of the residency
 * destination, coded as a sparse read's is. */
static bool
block_read(struct call *call)
{
   const struct shape *shape = call->shape;
   const struct stela_air_texture *texture = call->texture;
   if (texture->access != STELA_AIR_TEXTURE_SAMPLE || shape->dim != GLSL_SAMPLER_DIM_2D ||
       shape->array || texture->depth || !shape->mipmapped)
      return fail(call, "block reads read 2D sampled color textures");
   if (!call->c->store_at)
      return fail(call, "block reads need thread memory");
   if (LLVMGetTypeKind(LLVMTypeOf(call->inst)) != LLVMVoidTypeKind)
      return fail(call, "a block read returns nothing");
   LLVMValueRef sampler = take(call);
   if (!sampler || LLVMGetTypeKind(LLVMTypeOf(sampler)) != LLVMPointerTypeKind)
      return fail(call, "a block read takes a sampler");
   nir_def *position = index_operand(call, 2);
   nir_def *offset = position ? index_operand(call, 2) : NULL;
   nir_def *level = offset ? uint_operand(call) : NULL;
   if (!level || !expect(call, 32, 0, "block read operand"))
      return false;
   LLVMValueRef destination = take(call), residency = destination ? take(call) : NULL;
   LLVMValueRef size = residency ? take(call) : NULL;
   if (!size)
      return false;
   call->sparse = !LLVMIsAConstantPointerNull(residency);
   if (!type_is(LLVMTypeOf(size), 2, LLVMIntegerTypeKind, 32) || !LLVMIsAConstant(size) ||
       !LLVMIsAConstantInt(LLVMGetAggregateElement(size, 0)) ||
       !LLVMIsAConstantInt(LLVMGetAggregateElement(size, 1)))
      return fail(call, "a block read's size must be a constant uint2");
   uint64_t width = LLVMConstIntGetZExtValue(LLVMGetAggregateElement(size, 0));
   uint64_t height = LLVMConstIntGetZExtValue(LLVMGetAggregateElement(size, 1));
   if (!width || !height || width * height > 64)
      return fail(call, "a block read of %llu by %llu texels", (unsigned long long)width,
                  (unsigned long long)height);
   if (!finished(call))
      return false;
   nir_deref_instr *deref = texture_deref(call, NULL);
   if (!deref)
      return false;
   nir_builder *b = call->b;
   nir_def *origin = nir_iadd(b, position, offset);
   for (uint64_t i = 0; i < width * height; i++) {
      nir_def *at = nir_iadd(b, origin, nir_imm_ivec2(b, (int)(i % width), (int)(i / width)));
      struct tex t = {.op = nir_texop_txf, .texture = deref, .coord = at, .lod = level};
      nir_def *value = texel(call, resident(call, emit(call, &t)), false);
      unsigned bytes = value->num_components * value->bit_size / 8;
      if (!call->c->store_at(call->c->translator, destination, nir_imm_int64(b, (int64_t)(i * bytes)),
                             value))
         return false;
      if (call->sparse &&
          !call->c->store_at(call->c->translator, residency, nir_imm_int64(b, (int64_t)i),
                             call->residency))
         return false;
   }
   return true;
}

static bool
write_texel(struct call *call)
{
   const struct shape *shape = call->shape;
   const struct stela_air_texture *texture = call->texture;
   if (!storage(texture))
      return fail(call, "writing a texture without write access");
   if (texture->depth || shape->dim == GLSL_SAMPLER_DIM_MS)
      return fail(call, "writing a depth or multisample texture");
   if (LLVMGetTypeKind(LLVMTypeOf(call->inst)) != LLVMVoidTypeKind)
      return fail(call, "texture write has a result");
   nir_def *position = index_operand(call, shape->positions);
   nir_def *face = position && shape->dim == GLSL_SAMPLER_DIM_CUBE ? uint_operand(call) : NULL;
   nir_def *layer = position && shape->array ? uint_operand(call) : NULL;
   if (!position || (shape->dim == GLSL_SAMPLER_DIM_CUBE && !face) || (shape->array && !layer))
      return false;
   unsigned components, bits;
   LLVMTypeKind kind;
   texel_shape(texture, false, &components, &kind, &bits);
   nir_def *value = operand(call, components, kind, bits);
   nir_def *level;
   nir_deref_instr *deref;
   if (!value || !image_level(call, &level) || !access_operand(call, texture->access) ||
       !finished(call) || !(deref = texture_deref(call, level)))
      return false;
   nir_builder *b = call->b;
   switch (texture->primitive) {
   case STELA_AIR_HALF: value = nir_f2f32(b, value); break;
   case STELA_AIR_SHORT: value = nir_i2i32(b, value); break;
   case STELA_AIR_USHORT: value = nir_u2u32(b, value); break;
   default: break;
   }
   value = srgb_storage(call, value, true);
   nir_image_deref_store(b, &deref->def, image_coord(call, position, face, layer),
                         nir_undef(b, 1, 32), value, nir_imm_int(b, 0), .image_dim = shape->dim,
                         .image_array = shape->array, .access = image_access(call, level),
                         .src_type = nir_get_nir_type_for_glsl_base_type(base_type(texture)));
   return true;
}

/* The member type a slice write's name ends in: f16, f32, i8, i16 or i32,
 * or a vector of 2 to 4 of them, as v4f16. */
static bool
slice_type(const char *text, size_t bytes, unsigned *components, bool *floating, unsigned *bits)
{
   *components = 1;
   if (bytes > 2 && text[0] == 'v' && text[1] >= '2' && text[1] <= '4') {
      *components = (unsigned)(text[1] - '0');
      text += 2;
      bytes -= 2;
   }
   static const struct {
      const char *name;
      bool floating;
      unsigned bits;
   } types[] = {{"f16", true, 16}, {"f32", true, 32}, {"i8", false, 8}, {"i16", false, 16},
                {"i32", false, 32}};
   for (unsigned i = 0; i < ARRAY_SIZE(types); i++) {
      if (bytes == strlen(types[i].name) && !memcmp(text, types[i].name, bytes)) {
         *floating = types[i].floating;
         *bits = types[i].bits;
         return true;
      }
   }
   return false;
}

struct slice {
   struct call *call;
   LLVMValueRef member;
   nir_def *level, *position, *width;
   unsigned components, bits;
   bool floating;
};

/* Pixel index of a slice's region, row by row, to its texel. */
static bool
slice_pixel(void *data, nir_def *index, nir_def **values)
{
   (void)values;
   struct slice *slice = data;
   struct call *call = slice->call;
   nir_builder *b = call->b;
   nir_def *x = nir_umod(b, index, slice->width), *y = nir_udiv(b, index, slice->width);
   nir_def *pixel = nir_iadd(b, nir_imul(b, y, nir_channel(b, call->c->imageblock_extent, 0)), x);
   nir_def *value = call->c->imageblock_load(call->c->translator, slice->member, pixel,
                                             slice->components, slice->bits);
   /* Derefs stay in the block that uses them. */
   nir_deref_instr *deref = value ? texture_deref(call, slice->level) : NULL;
   if (!deref)
      return false;
   bool is_signed = base_type(call->texture) == GLSL_TYPE_INT;
   value = slice->floating ? nir_f2f32(b, value) : is_signed ? nir_i2i32(b, value) :
                                                             nir_u2u32(b, value);
   nir_def *lanes[4];
   for (unsigned i = 0; i < 4; i++)
      lanes[i] = i < slice->components ? nir_channel(b, value, i) :
                 slice->floating ? nir_imm_float(b, i == 3) : nir_imm_int(b, i == 3);
   nir_def *at = nir_iadd(b, slice->position, nir_vec2(b, x, y));
   nir_def *texel = slice->floating ? srgb_storage(call, nir_vec(b, lanes, 4), true) :
                                      nir_vec(b, lanes, 4);
   nir_image_deref_store(b, &deref->def, image_coord(call, at, NULL, NULL), nir_undef(b, 1, 32),
                         texel, nir_imm_int(b, 0),
                         .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = false,
                         .access = image_access(call, slice->level),
                         .src_type = nir_get_nir_type_for_glsl_base_type(base_type(call->texture)));
   return true;
}

/* An imageblock slice into a texture, as texture2d::write(slice, position,
 * lod) emits it:
 *
 *   air.write_imageblock_slice_to_texture_2d[.i16].<member type>: texture,
 *     slice, i1 sized, <2 x i16> zero, <2 x i16> size, position, lod,
 *     i1 implicit layout, i32 access
 *
 * The slice is one member of every element of a kernel's explicit
 * imageblock. Pixel (x, y) of the block, within size when sized and the
 * whole block otherwise, goes to texel position + (x, y); those past the
 * texture's edge go nowhere. */
static bool
slice_write(struct call *call, const char *member_type, size_t member_type_bytes)
{
   const struct stela_air_texture *texture = call->texture;
   const struct stela_air_texture_context *c = call->c;
   struct slice slice = {.call = call};
   if (!storage(texture) || texture->depth || call->shape->dim != GLSL_SAMPLER_DIM_2D ||
       call->shape->array)
      return fail(call, "imageblock slices write 2D color textures with write access");
   if (!c->imageblock_extent || !c->imageblock_load || !c->repeat)
      return fail(call, "an imageblock slice write in a function without an explicit imageblock");
   if (!slice_type(member_type, member_type_bytes, &slice.components, &slice.floating, &slice.bits))
      return fail(call, "an imageblock slice of member type %.*s", (int)member_type_bytes,
                  member_type);
   if (slice.floating == integer_texels(texture))
      return fail(call, "an imageblock slice of another kind than its texture's texels");
   if (LLVMGetTypeKind(LLVMTypeOf(call->inst)) != LLVMVoidTypeKind)
      return fail(call, "an imageblock slice write has a result");
   slice.member = take(call);
   if (!slice.member)
      return false;
   if (LLVMGetTypeKind(LLVMTypeOf(slice.member)) != LLVMPointerTypeKind ||
       LLVMGetPointerAddressSpace(LLVMTypeOf(slice.member)) != 4)
      return fail(call, "an imageblock slice write takes an imageblock member");
   uint64_t sized;
   if (!constant(call, 1, &sized))
      return false;
   LLVMValueRef origin = take(call);
   if (!origin)
      return false;
   if (!type_is(LLVMTypeOf(origin), 2, LLVMIntegerTypeKind, 16) ||
       !(LLVMIsNull(origin) || LLVMIsUndef(origin)))
      return fail(call, "an imageblock slice from other than the block's origin");
   nir_def *size;
   if (sized) {
      size = operand(call, 2, LLVMIntegerTypeKind, 16);
   } else {
      LLVMValueRef unsized = take(call);
      size = unsized ? nir_imm_ivec2(call->b, 0, 0) : NULL;
   }
   slice.position = size ? index_operand(call, 2) : NULL;
   if (!slice.position || !image_level(call, &slice.level) ||
       !expect(call, 1, 0, "imageblock slice layout") || !access_operand(call, texture->access) ||
       !finished(call))
      return false;
   nir_deref_instr *deref = texture_deref(call, slice.level);
   if (!deref)
      return false;
   nir_builder *b = call->b;
   nir_def *extent = c->imageblock_extent;
   if (sized)
      extent = nir_umin(b, nir_u2u32(b, size), extent);
   nir_def *texels = nir_image_deref_size(b, 2, 32, &deref->def, nir_imm_int(b, 0),
                                          .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = false,
                                          .access = image_access(call, slice.level));
   extent = nir_umin(b, extent, nir_usub_sat(b, texels, slice.position));
   slice.width = nir_channel(b, extent, 0);
   return c->repeat(c->translator, nir_imul(b, slice.width, nir_channel(b, extent, 1)), 0, NULL,
                    slice_pixel, &slice);
}

/* Texture atomics, as DXMT records them:
 *
 *   air.atomic_fetch_<op>_explicit_<type>.<s|u>.v4i32, and atomic_exchange_:
 *     texture, position, [array], [zero offset], <4 x i32> operand, i32 order,
 *     i32 access -> <4 x i32> old texel
 *   air.atomic_compare_exchange_weak_explicit_<type>.<s|u>.v4i32: texture,
 *     position, [array], [zero offset], ptr expected, <4 x i32> desired,
 *     i32 success order, i32 failure order, i32 access -> i1 exchanged
 *
 * The sign selects min and max's comparison and does not change the other
 * operations. Operands use their x component, and an old texel reads as an
 * R32 texel does, (x, 0, 0, 1). Orders are relaxed. */
static const struct {
   const char *stem;
   nir_atomic_op op, signed_op;
   /* A load adds nothing, and a store takes its texel ahead of its position
    * and answers nothing. */
   bool negate, load, store;
} atomics[] = {
   {"fetch_add", nir_atomic_op_iadd, nir_atomic_op_iadd},
   {"fetch_sub", nir_atomic_op_iadd, nir_atomic_op_iadd, true},
   {"fetch_and", nir_atomic_op_iand, nir_atomic_op_iand},
   {"fetch_or", nir_atomic_op_ior, nir_atomic_op_ior},
   {"fetch_xor", nir_atomic_op_ixor, nir_atomic_op_ixor},
   {"fetch_min", nir_atomic_op_umin, nir_atomic_op_imin},
   {"fetch_max", nir_atomic_op_umax, nir_atomic_op_imax},
   {"exchange", nir_atomic_op_xchg, nir_atomic_op_xchg},
   {"compare_exchange_weak", nir_atomic_op_cmpxchg, nir_atomic_op_cmpxchg},
   {"load", nir_atomic_op_iadd, nir_atomic_op_iadd, .load = true},
   {"store", nir_atomic_op_xchg, nir_atomic_op_xchg, .store = true},
};

/* The index in atomics of a texture atomic's name, and its sign; or -1. */
static int
atomic_named(const struct call *call, const char *name, size_t bytes, bool *is_signed)
{
   const char *type = call->texture->depth ? call->shape->depth : call->shape->name;
   for (unsigned i = 0; i < ARRAY_SIZE(atomics); i++) {
      for (unsigned sign = 0; sign < 2; sign++) {
         char expected[96];
         int length = snprintf(expected, sizeof(expected), "air.atomic_%s_explicit_%s.%c.v4i32",
                               atomics[i].stem, type, sign ? 's' : 'u');
         if (length > 0 && (size_t)length == bytes && !memcmp(expected, name, bytes)) {
            *is_signed = sign;
            return (int)i;
         }
      }
   }
   return -1;
}

static bool
atomic(struct call *call, unsigned index, bool is_signed, nir_def **result)
{
   const struct shape *shape = call->shape;
   const struct stela_air_texture *texture = call->texture;
   bool exchange = atomics[index].op == nir_atomic_op_cmpxchg;
   bool load = atomics[index].load, store = atomics[index].store;
   if (texture->access != STELA_AIR_TEXTURE_READ_WRITE || texture->depth ||
       (texture->primitive != STELA_AIR_INT && texture->primitive != STELA_AIR_UINT) ||
       shape->dim == GLSL_SAMPLER_DIM_CUBE || shape->dim == GLSL_SAMPLER_DIM_MS)
      return fail(call, "texture atomics act on read-write 32-bit integer textures, not cube or multisample");
   LLVMTypeRef type = LLVMTypeOf(call->inst);
   if (store ? LLVMGetTypeKind(type) != LLVMVoidTypeKind :
               !type_is(type, exchange ? 1 : 4, LLVMIntegerTypeKind, exchange ? 1 : 32))
      return fail(call, "texture atomic has an unexpected result type");
   nir_deref_instr *deref = texture_deref(call, NULL);
   if (!deref)
      return false;
   nir_def *data = store ? operand(call, 4, LLVMIntegerTypeKind, 32) : NULL;
   nir_def *position = operand(call, shape->positions, LLVMIntegerTypeKind, 32);
   nir_def *layer = position && shape->array ? uint_operand(call) : NULL;
   if (!position || (shape->array && !layer) || !position_offset(call, &position))
      return false;
   LLVMValueRef expected = exchange ? take(call) : NULL;
   if (exchange && (!expected || LLVMGetTypeKind(LLVMTypeOf(expected)) != LLVMPointerTypeKind))
      return fail(call, "texture compare-exchange takes its expected texel through a pointer");
   if (!load && !store)
      data = operand(call, 4, LLVMIntegerTypeKind, 32);
   if ((!load && !data) || !expect(call, 32, 0, "atomic order") ||
       (exchange && !expect(call, 32, 0, "atomic order")) ||
       !expect(call, 32, texture->access, "access operand") || !finished(call))
      return false;
   nir_builder *b = call->b;
   nir_def *coord = image_coord(call, position, NULL, layer);
   enum pipe_format format = texture->primitive == STELA_AIR_INT ? PIPE_FORMAT_R32_SINT :
                                                                   PIPE_FORMAT_R32_UINT;
   data = load ? nir_imm_int(b, 0) : nir_channel(b, data, 0);
   if (exchange) {
      nir_def *compare = call->c->load_word(call->c->translator, expected);
      if (!compare)
         return false;
      nir_def *old = nir_image_deref_atomic_swap(b, 32, &deref->def, coord, nir_undef(b, 1, 32),
                                                 compare, data, .image_dim = shape->dim,
                                                 .image_array = shape->array, .format = format,
                                                 .atomic_op = nir_atomic_op_cmpxchg);
      /* expected receives the texel seen, which success leaves unchanged. */
      if (!call->c->store_word(call->c->translator, expected, old))
         return false;
      *result = nir_ieq(b, old, compare);
      return true;
   }
   if (atomics[index].negate)
      data = nir_ineg(b, data);
   nir_def *old = nir_image_deref_atomic(b, 32, &deref->def, coord, nir_undef(b, 1, 32), data,
                                         .image_dim = shape->dim, .image_array = shape->array,
                                         .format = format,
                                         .atomic_op = is_signed ? atomics[index].signed_op :
                                                                  atomics[index].op);
   nir_def *zero = nir_imm_int(b, 0);
   if (!store)
      *result = nir_vec4(b, old, zero, zero, nir_imm_int(b, 1));
   return true;
}

static bool
query(struct call *call, enum operation op, nir_def **result)
{
   const struct shape *shape = call->shape;
   bool image = storage(call->texture);
   if (!type_is(LLVMTypeOf(call->inst), 1, LLVMIntegerTypeKind, 32))
      return fail(call, "texture query has an unexpected result type");
   /* The size components: width, height, depth or layers. */
   unsigned dimensions = shape->dim == GLSL_SAMPLER_DIM_1D || shape->dim == GLSL_SAMPLER_DIM_BUF ? 1 :
                         shape->dim == GLSL_SAMPLER_DIM_3D ? 3 : 2;
   unsigned channel = op == WIDTH ? 0 : op == HEIGHT ? 1 : op == DEPTH ? 2 : dimensions;
   if ((op == HEIGHT && dimensions < 2) || (op == DEPTH && dimensions < 3) ||
       (op == ARRAY_SIZE && !shape->array) || (op == SAMPLES && shape->dim != GLSL_SAMPLER_DIM_MS) ||
       (op == MIP_LEVELS && !shape->mipmapped))
      return fail(call, "texture query does not apply to its texture type");
   nir_builder *b = call->b;
   if (image && op == MIP_LEVELS) {
      const struct stela_air_options *options = call->c->options;
      if (!options->texture_levels)
         return fail(call, "querying the levels of a storage texture");
      if (!finished(call))
         return false;
      *result = options->texture_levels(b, call->texture_id ? NULL : call->texture,
                                        call->texture_id, options->binding_data);
      return *result || fail(call, "texture %u is unbound", call->texture->index);
   }
   bool sized = op == WIDTH || op == HEIGHT || op == DEPTH || op == ARRAY_SIZE;
   nir_def *lod = NULL;
   if ((op == WIDTH || op == HEIGHT || op == DEPTH) && shape->mipmapped &&
       !(lod = uint_operand(call)))
      return false;
   /* A storage texture's level selects its descriptor. */
   nir_deref_instr *deref;
   if (!finished(call) || !(deref = texture_deref(call, image ? lod : NULL)))
      return false;
   unsigned size = dimensions + shape->array;
   if (image) {
      nir_def *value = op == SAMPLES ?
         nir_image_deref_samples(b, 32, &deref->def, .image_dim = shape->dim,
                                 .image_array = shape->array) :
         nir_image_deref_size(b, size, 32, &deref->def, nir_imm_int(b, 0),
                              .image_dim = shape->dim, .image_array = shape->array,
                              .access = image_access(call, lod));
      *result = sized ? nir_channel(b, value, channel) : value;
      return true;
   }
   struct tex t = {.texture = deref};
   if (sized) {
      t.op = nir_texop_txs;
      if (shape->dim != GLSL_SAMPLER_DIM_BUF && shape->dim != GLSL_SAMPLER_DIM_MS)
         t.lod = lod ? lod : nir_imm_int(b, 0);
      *result = nir_channel(b, emit(call, &t), channel);
   } else {
      t.op = op == SAMPLES ? nir_texop_texture_samples : nir_texop_query_levels;
      *result = emit(call, &t);
   }
   return true;
}

static bool
is_null(struct call *call, nir_def **result)
{
   const struct stela_air_options *options = call->c->options;
   if (!options->texture_null)
      return fail(call, "testing for a null texture");
   if (!finished(call))
      return false;
   *result = options->texture_null(call->b, call->texture_id ? NULL : call->texture,
                                   call->texture_id, options->binding_data);
   return *result || fail(call, "texture %u is unbound", call->texture->index);
}

static bool
lod(struct call *call, enum operation op, nir_def **result)
{
   const struct shape *shape = call->shape;
   /* A kernel's neighbors are its quadgroup, four consecutive threads, which
    * a threadgroup's last may leave short of neighbors to difference. */
   shader_info *info = &call->b->shader->info;
   if (mesa_shader_stage_uses_workgroup(info->stage))
      info->derivative_group = DERIVATIVE_GROUP_LINEAR;
   else if (info->stage != MESA_SHADER_FRAGMENT)
      return fail(call, "calculating a level of detail without neighboring threads");
   if (call->texture->access != STELA_AIR_TEXTURE_SAMPLE ||
       shape->dim == GLSL_SAMPLER_DIM_MS || shape->dim == GLSL_SAMPLER_DIM_BUF)
      return fail(call, "calculating a level of detail of a texture that is not sampled");
   if (!type_is(LLVMTypeOf(call->inst), 1, LLVMFloatTypeKind, 32))
      return fail(call, "level of detail has an unexpected result type");
   struct tex t = {.op = nir_texop_lod};
   if (!(t.texture = texture_deref(call, NULL)) || !(t.sampler = sampler_deref(call)) ||
       !(t.coord = float_operand(call, shape->coords)) ||
       !access_operand(call, STELA_AIR_TEXTURE_SAMPLE) || !finished(call))
      return false;
   nir_def *scale = pixel_scale(call, t.texture);
   if (scale)
      t.coord = nir_fdiv(call->b, t.coord, scale);
   /* x is the clamped level of detail, y the unclamped one. */
   *result = nir_channel(call->b, emit(call, &t), op == CLAMPED_LOD ? 0 : 1);
   return true;
}

static bool
fence(struct call *call)
{
   if (!storage(call->texture))
      return fail(call, "fencing a texture without write access");
   if (LLVMGetTypeKind(LLVMTypeOf(call->inst)) != LLVMVoidTypeKind || !finished(call))
      return fail(call, "texture fence has an unexpected signature");
   /* Makes the thread's earlier writes visible to its later reads. */
   nir_barrier(call->b, .memory_scope = SCOPE_WORKGROUP, .memory_semantics = NIR_MEMORY_ACQ_REL,
               .memory_modes = nir_var_image);
   return true;
}

/* Whether anything may read the call's residency: a use other than an
 * extractvalue of its texel, through PHIs up to `depth` deep. */
static bool
reads_residency(LLVMValueRef inst, unsigned depth)
{
   for (LLVMUseRef use = LLVMGetFirstUse(inst); use; use = LLVMGetNextUse(use)) {
      LLVMValueRef user = LLVMGetUser(use);
      if (LLVMIsAPHINode(user)) {
         if (!depth || reads_residency(user, depth - 1))
            return true;
      } else if (!LLVMIsAExtractValueInst(user) || LLVMGetNumIndices(user) != 1 ||
                 LLVMGetIndices(user)[0]) {
         return true;
      }
   }
   return false;
}

/* A call on a null texture, which has no descriptor: everything reads zero
 * but its own is_null, and writes go nowhere. */
static enum stela_air_texture_status
null_call(const struct stela_air_texture_context *context, LLVMValueRef inst, const char *name,
          size_t name_bytes, nir_def **result, bool *pair)
{
   if (null_named(name, name_bytes, "air.is_null_")) {
      *result = nir_imm_true(context->b);
      return STELA_AIR_TEXTURE_LOWERED;
   }
   LLVMTypeRef type = LLVMTypeOf(inst);
   if (LLVMGetTypeKind(type) == LLVMVoidTypeKind)
      return STELA_AIR_TEXTURE_LOWERED;
   *pair = LLVMGetTypeKind(type) == LLVMStructTypeKind;
   if (*pair)
      type = LLVMStructGetTypeAtIndex(type, 0);
   bool vector = LLVMGetTypeKind(type) == LLVMVectorTypeKind;
   LLVMTypeRef element = vector ? LLVMGetElementType(type) : type;
   LLVMTypeKind kind = LLVMGetTypeKind(element);
   unsigned bits = kind == LLVMHalfTypeKind ? 16 : kind == LLVMFloatTypeKind ? 32 :
                   kind == LLVMIntegerTypeKind ? LLVMGetIntTypeWidth(element) : 0;
   if (!bits) {
      fail(&(struct call){.c = context}, "null texture call returns an unknown type");
      return STELA_AIR_TEXTURE_FAILED;
   }
   *result = nir_imm_zero(context->b, vector ? LLVMGetVectorSize(type) : 1, bits);
   return STELA_AIR_TEXTURE_LOWERED;
}

enum stela_air_texture_status
stela_air_texture_call(const struct stela_air_texture_context *context, LLVMValueRef inst,
                       const char *name, size_t name_bytes, nir_def **result, bool *pair,
                       nir_def **residency)
{
   *result = NULL;
   *pair = false;
   *residency = NULL;
   if (!LLVMGetNumArgOperands(inst))
      return STELA_AIR_TEXTURE_OTHER;
   if (stela_air_null_texture(LLVMGetOperand(inst, 0)))
      return null_call(context, inst, name, name_bytes, result, pair);
   nir_def *texture_id;
   const struct stela_air_texture *texture =
      context->texture(context->translator, LLVMGetOperand(inst, 0), &texture_id);
   if (!texture)
      return STELA_AIR_TEXTURE_OTHER;
   struct call call = {
      .c = context, .b = context->b, .inst = inst, .texture = texture, .texture_id = texture_id,
      .shape = &shapes[texture->type], .next = 1, .count = LLVMGetNumArgOperands(inst),
   };
   LLVMValueRef callee = LLVMGetCalledValue(inst);
   if (!LLVMIsAFunction(callee) || !LLVMIsDeclaration(callee) ||
       LLVMGetCalledFunctionType(inst) != LLVMGlobalGetValueType(callee) ||
       LLVMGetNumOperandBundles(inst)) {
      fail(&call, "texture call is not a direct call of an AIR declaration");
      return STELA_AIR_TEXTURE_FAILED;
   }
   bool is_signed;
   int atomic_index = atomic_named(&call, name, name_bytes, &is_signed);
   if (atomic_index >= 0)
      return atomic(&call, (unsigned)atomic_index, is_signed, result) ? STELA_AIR_TEXTURE_LOWERED :
                                                                       STELA_AIR_TEXTURE_FAILED;
   /* A slice write's name ends in its member type. */
   char stem[96];
   int stem_bytes = snprintf(stem, sizeof(stem), "air.%s_%s", operations[SLICE_WRITE].stem,
                             call.shape->name);
   if (stem_bytes > 0 && name_bytes > (size_t)stem_bytes + 1 && !memcmp(name, stem, (size_t)stem_bytes) &&
       name[stem_bytes] == '.') {
      const char *rest = name + stem_bytes + 1;
      size_t rest_bytes = name_bytes - (size_t)stem_bytes - 1;
      if (rest_bytes > 4 && !memcmp(rest, "i16.", 4)) {
         call.short_indices = true;
         rest += 4;
         rest_bytes -= 4;
      }
      return slice_write(&call, rest, rest_bytes) ? STELA_AIR_TEXTURE_LOWERED :
                                                    STELA_AIR_TEXTURE_FAILED;
   }
   int op = -1;
   for (unsigned o = 0; o < ARRAY_SIZE(operations) && op < 0; o++) {
      bool forms = o == READ || o == WRITE;
      for (unsigned form = 0; form < (forms ? 4u : 1u) && op < 0; form++) {
         bool coherent = form & 1, short_indices = form & 2;
         if (named(&call, (enum operation)o, coherent, short_indices, name, name_bytes)) {
            op = (int)o;
            call.coherent = coherent;
            call.short_indices = short_indices;
         }
      }
   }
   if (op < 0) {
      fail(&call, "unsupported texture function %.*s", (int)name_bytes, name);
      return STELA_AIR_TEXTURE_FAILED;
   }
   bool lowered;
   *pair = LLVMGetTypeKind(LLVMTypeOf(inst)) == LLVMStructTypeKind &&
           (op == SAMPLE || op == SAMPLE_COMPARE || op == SAMPLE_GRAD ||
            op == SAMPLE_COMPARE_GRAD || op == READ || op == GATHER || op == GATHER_COMPARE);
   call.sparse = *pair && reads_residency(inst, 4);
   switch ((enum operation)op) {
   case SAMPLE:
   case SAMPLE_COMPARE:
   case SAMPLE_GRAD:
   case SAMPLE_COMPARE_GRAD:
      lowered = sample(&call, (enum operation)op, result);
      break;
   case READ:
      lowered = read_texel(&call, result);
      break;
   case GATHER:
   case GATHER_COMPARE:
      lowered = gather(&call, (enum operation)op, result);
      break;
   case WRITE:
      lowered = write_texel(&call);
      break;
   case CLAMPED_LOD:
   case UNCLAMPED_LOD:
      lowered = lod(&call, (enum operation)op, result);
      break;
   case FENCE:
      lowered = fence(&call);
      break;
   case IS_NULL:
      lowered = is_null(&call, result);
      break;
   case BLOCK_READ:
      lowered = block_read(&call);
      break;
   default:
      lowered = query(&call, (enum operation)op, result);
      break;
   }
   *residency = call.residency;
   return lowered ? STELA_AIR_TEXTURE_LOWERED : STELA_AIR_TEXTURE_FAILED;
}
