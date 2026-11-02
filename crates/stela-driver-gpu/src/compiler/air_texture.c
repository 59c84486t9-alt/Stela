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
   IS_NULL,
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

/* The offset Metal 4 places after a 2D or 3D position, always zero. */
static bool
position_offset(struct call *call)
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
   return LLVMIsNull(value) || fail(call, "accessing a texel at an offset");
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
   tex->is_new_style_shadow = t->shadow;
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
   t.coord = layered(call, coord, layer, true);
   if (compare && !(t.comparator = float_operand(call, 1)))
      return false;
   bool fragment = call->b->shader->info.stage == MESA_SHADER_FRAGMENT;
   if (op == SAMPLE_GRAD || op == SAMPLE_COMPARE_GRAD) {
      t.op = nir_texop_txd;
      if (!(t.ddx = float_operand(call, shape->coords)) ||
          !(t.ddy = float_operand(call, shape->coords)) || !min_lod_operand(call, &t.min_lod))
         return false;
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
   *result = texel(call, resident(call, emit(call, &t)), false);
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

bool
stela_air_null_texture(LLVMValueRef value)
{
   size_t bytes;
   const char *name = called_name(value, &bytes);
   size_t stem = strlen("air.get_null_texture_");
   return name && bytes > stem && !memcmp(name, "air.get_null_texture_", stem);
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
   call->next += call->next < call->count &&
                 stela_air_read_sampler(LLVMGetOperand(call->inst, call->next));
   if (texture->depth && !expect(call, 32, 1, "depth operand"))
      return false;
   nir_def *position = index_operand(call, shape->positions);
   nir_def *face = position && shape->dim == GLSL_SAMPLER_DIM_CUBE ? uint_operand(call) : NULL;
   nir_def *layer = position && shape->array ? uint_operand(call) : NULL;
   nir_def *sample = position && shape->dim == GLSL_SAMPLER_DIM_MS ? uint_operand(call) : NULL;
   if (!position || (shape->dim == GLSL_SAMPLER_DIM_CUBE && !face) || (shape->array && !layer) ||
       (shape->dim == GLSL_SAMPLER_DIM_MS && !sample))
      return false;
   if (!position_offset(call))
      return false;
   nir_builder *b = call->b;
   nir_def *value;
   if (image) {
      nir_def *level;
      if (!image_level(call, &level) || !access_operand(call, texture->access) ||
          !finished(call) || !(deref = texture_deref(call, level)))
         return false;
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
      nir_def *coord = faces ? nir_trim_vector(b, image_coord(call, position, face, layer), 3) :
                               layered(call, position, layer, false);
      struct tex t = {.op = sample ? nir_texop_txf_ms : nir_texop_txf, .texture = deref,
                      .coord = coord, .ms_index = sample, .faces = faces};
      if (shape->mipmapped && !(t.lod = uint_operand(call)))
         return false;
      if (!access_operand(call, texture->access) || !finished(call))
         return false;
      value = emit(call, &t);
   }
   *result = texel(call, resident(call, value), false);
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
   nir_image_deref_store(b, &deref->def, image_coord(call, position, face, layer),
                         nir_undef(b, 1, 32), value, nir_imm_int(b, 0), .image_dim = shape->dim,
                         .image_array = shape->array, .access = image_access(call, level),
                         .src_type = nir_get_nir_type_for_glsl_base_type(base_type(texture)));
   return true;
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
   if (!position || (shape->array && !layer) || !position_offset(call))
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
   size_t stem = strlen("air.is_null_texture_");
   if (name_bytes > stem && !memcmp(name, "air.is_null_texture_", stem)) {
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
   default:
      lowered = query(&call, (enum operation)op, result);
      break;
   }
   *residency = call.residency;
   return lowered ? STELA_AIR_TEXTURE_LOWERED : STELA_AIR_TEXTURE_FAILED;
}
