/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "metal_abi.h"
#include "compiler/nir/nir_format_convert.h"
#include "util/ralloc.h"

/* As SPIR-V reaches a driver: the offset in the source, the range the block's. */
static nir_def *load_push(nir_builder *b, unsigned components, unsigned bit_size, unsigned offset)
{
   return nir_load_push_constant(b, components, bit_size, nir_imm_int(b, (int)offset),
                                 .range = STELA_METAL_PUSH_BYTES, .align_mul = bit_size / 8);
}

/* A load of memory nothing writes while the shader runs: the tables and the
 * internal kernels' arguments and results. */
static nir_def *load(nir_builder *b, nir_def *address, unsigned offset, unsigned bit_size)
{
   return nir_load_global(b, 1, bit_size, nir_iadd_imm(b, address, offset),
                          .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER,
                          .align_mul = bit_size / 8);
}

/* Access of a load at a fixed offset within a stage's argument table, which
 * every draw and dispatch binds before it runs: it reads mapped memory in
 * every invocation, so it may also run where control flow would skip it. */
#define TABLE_ACCESS (ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER | ACCESS_CAN_SPECULATE)

/* A field at offset of the argument table at address. */
static nir_def *table_load(nir_builder *b, nir_def *address, unsigned offset, unsigned bit_size)
{
   return nir_load_global(b, 1, bit_size, nir_iadd_imm(b, address, offset),
                          .access = TABLE_ACCESS, .align_mul = bit_size / 8);
}

nir_def *stela_metal_load_table(nir_builder *b, enum stela_metal_table table)
{
   return load_push(b, 1, 64, STELA_METAL_PUSH_TABLES + 8u * (unsigned)table);
}

nir_def *stela_metal_load_device_value(nir_builder *b, enum stela_air_device_value value,
                                       void *stage)
{
   const struct stela_metal_stage *metal = stage;
   switch (value) {
   case STELA_AIR_DISPATCH_GRID:
      return load_push(b, 3, 32, STELA_METAL_PUSH_GRID);
   case STELA_AIR_AMPLIFICATION:
      return load_push(b, 1, 32, STELA_METAL_PUSH_AMPLIFICATION);
   case STELA_AIR_VIEW_MAPPING:
      return load_push(b, 1, 32, STELA_METAL_PUSH_VIEW_MAPPING);
   case STELA_AIR_AMPLIFICATIONS:
      return load_push(b, 1, 32, STELA_METAL_PUSH_AMPLIFICATIONS);
   case STELA_AIR_LOG_BUFFER:
      return load_push(b, 1, 64, STELA_METAL_PUSH_LOG);
   case STELA_AIR_THREADGROUP_SHAPE:
      return nir_load_global(b, 3, 32,
                             nir_iadd_imm(b, load_push(b, 1, 64, STELA_METAL_PUSH_ARGUMENTS),
                                          STELA_METAL_DISPATCH_SHAPE),
                             .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER, .align_mul = 4);
   case STELA_AIR_TILE:
      return nir_load_global(b, 4, 32,
                             nir_iadd_imm(b, load_push(b, 1, 64, STELA_METAL_PUSH_ARGUMENTS),
                                          STELA_METAL_DISPATCH_TILE),
                             .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER, .align_mul = 16);
   case STELA_AIR_STAGE_IN_ORIGIN:
   case STELA_AIR_STAGE_IN_SIZE:
      /* A stage-in dispatch's arguments are its region. */
      return nir_load_global(b, 3, 32,
                             nir_iadd_imm(b, load_push(b, 1, 64, STELA_METAL_PUSH_ARGUMENTS),
                                          value == STELA_AIR_STAGE_IN_ORIGIN ? STELA_METAL_STAGE_IN_ORIGIN :
                                                                               STELA_METAL_STAGE_IN_SIZE),
                             .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER, .align_mul = 4);
   case STELA_AIR_SAMPLE_COUNT:
      return table_load(b, stela_metal_load_table(b, metal->table), STELA_METAL_TABLE_SAMPLE_COUNT, 32);
   case STELA_AIR_BLEND_COLOR:
      return nir_load_global(b, 4, 32,
                             nir_iadd_imm(b, stela_metal_load_table(b, metal->table),
                                          STELA_METAL_TABLE_BLEND_COLOR),
                             .access = TABLE_ACCESS, .align_mul = 16);
   case STELA_AIR_SAMPLE_POSITIONS:
      return nir_load_global(b, 4, 32,
                             nir_iadd_imm(b, stela_metal_load_table(b, metal->table),
                                          STELA_METAL_TABLE_SAMPLE_POSITIONS),
                             .access = TABLE_ACCESS, .align_mul = 16);
   case STELA_AIR_IMAGEBLOCK:
      return nir_load_global(b, 4, 32,
                             nir_iadd_imm(b, stela_metal_load_table(b, metal->table),
                                          STELA_METAL_TABLE_IMAGEBLOCK),
                             .access = TABLE_ACCESS, .align_mul = 16);
   case STELA_AIR_DIRTY_TILES:
      return nir_load_global(b, 4, 32,
                             nir_iadd_imm(b, stela_metal_load_table(b, metal->table),
                                          STELA_METAL_TABLE_DIRTY),
                             .access = TABLE_ACCESS, .align_mul = 16);
   case STELA_AIR_DEPTH_STENCIL:
   case STELA_AIR_DEPTH_RANGE:
      return nir_load_global(b, 4, 32,
                             nir_iadd_imm(b, stela_metal_load_table(b, metal->table),
                                          value == STELA_AIR_DEPTH_STENCIL ? STELA_METAL_TABLE_DEPTH_STENCIL :
                                                                             STELA_METAL_TABLE_DEPTH_RANGE),
                             .access = TABLE_ACCESS, .align_mul = 16);
   case STELA_AIR_PATCH_IDS: {
      /* The tessellation control stage's PATCH0. */
      nir_variable *ids = nir_variable_create(b->shader, nir_var_shader_in, glsl_uvec_type(3),
                                              "patch_ids");
      ids->data.location = VARYING_SLOT_PATCH0;
      ids->data.patch = true;
      return nir_load_var(b, ids);
   }
   }
   return NULL;
}

nir_def *stela_metal_threadgroup_offset(nir_builder *b, const struct stela_air_buffer *buffer,
                                        void *stage)
{
   (void)stage;
   if (buffer->index >= STELA_METAL_BUFFERS)
      return NULL;
   return load(b, load_push(b, 1, 64, STELA_METAL_PUSH_ARGUMENTS),
               STELA_METAL_DISPATCH_OFFSETS + 4u * buffer->index, 32);
}

nir_def *stela_metal_bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer,
                                 void *stage)
{
   const struct stela_metal_stage *metal = stage;
   if (buffer->index >= STELA_METAL_BUFFERS)
      return NULL;
   return table_load(b, stela_metal_load_table(b, metal->table),
                     STELA_METAL_TABLE_BUFFER_ADDRESSES + 8u * buffer->index, 64);
}

/* The heap array of elements of type, as a variable of mode. Each element
 * type has its own variable; variables of one array alias. */
static nir_variable *heap(nir_shader *shader, enum stela_metal_heap_array array,
                          const struct glsl_type *element, nir_variable_mode mode)
{
   const struct glsl_type *type = glsl_array_type(element, 0, 0);
   nir_foreach_variable_with_modes(var, shader, mode) {
      if (var->data.descriptor_set == STELA_METAL_HEAP_SET && var->data.binding == array &&
          var->type == type)
         return var;
   }
   nir_variable *var = nir_variable_create(shader, mode, type, "stela_metal_heap");
   var->data.descriptor_set = STELA_METAL_HEAP_SET;
   var->data.binding = array;
   if (mode == nir_var_image)
      var->data.image.format = PIPE_FORMAT_NONE;
   return var;
}

/* The heap element a half of the resource ID id names. */
static nir_deref_instr *heap_element(nir_builder *b, nir_def *index,
                                     enum stela_metal_heap_array array,
                                     const struct glsl_type *type, nir_variable_mode mode)
{
   return nir_build_deref_array(b, nir_build_deref_var(b, heap(b->shader, array, type, mode)),
                                index);
}

/* The descriptor index of an MTLResourceID's half. */
static nir_def *id_half(nir_builder *b, nir_def *id, bool high)
{
   return high ? nir_unpack_64_2x32_split_y(b, id) : nir_unpack_64_2x32_split_x(b, id);
}

/* The storage descriptor of level in a texture ID's high half: the index plus
 * the level, or the null descriptor for a level past its count. */
static nir_def *storage_level(nir_builder *b, nir_def *id, nir_def *level)
{
   nir_def *high = id_half(b, id, true);
   nir_def *first = nir_iand_imm(b, high, (1u << STELA_METAL_PLANES_SHIFT) - 1);
   if (!level)
      return first;
   nir_def *levels = nir_iadd_imm(b, nir_ushr_imm(b, high, STELA_METAL_LEVEL_SHIFT), 1);
   return nir_bcsel(b, nir_ult(b, level, levels), nir_iadd(b, first, level), nir_imm_int(b, 0));
}

/* The resource ID at offset in the stage's table. */
static nir_def *table_id(nir_builder *b, const struct stela_metal_stage *stage, unsigned offset)
{
   return table_load(b, stela_metal_load_table(b, stage->table), offset, 64);
}

nir_def *stela_metal_texture_view_word(nir_builder *b, nir_def *id, nir_def **address,
                                       void *stage)
{
   (void)stage;
   /* The shift drops the flag. */
   *address = nir_ishl_imm(b, id, 3);
   return nir_ine_imm(b, nir_iand_imm(b, id_half(b, id, true), STELA_METAL_POOL_VIEW), 0);
}

nir_deref_instr *stela_metal_bind_texture_id(nir_builder *b, nir_def *id,
                                             const struct glsl_type *type, bool faces,
                                             nir_def *level, void *stage)
{
   (void)stage;
   bool image = glsl_type_is_image(type);
   bool buffer = glsl_get_sampler_dim(type) == GLSL_SAMPLER_DIM_BUF;
   if (faces && (image || buffer))
      return NULL;
   enum stela_metal_heap_array array =
      image ? (buffer ? STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS : STELA_METAL_HEAP_STORAGE_IMAGES)
            : (buffer ? STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS : STELA_METAL_HEAP_SAMPLED_IMAGES);
   nir_def *index = image ? storage_level(b, id, level) : id_half(b, id, false);
   /* The null descriptor's successor is null too. */
   if (faces)
      index = nir_bcsel(b, nir_ieq_imm(b, index, 0), index, nir_iadd_imm(b, index, 1));
   return heap_element(b, index, array, type, image ? nir_var_image : nir_var_uniform);
}

nir_deref_instr *stela_metal_bind_sampler_id(nir_builder *b, nir_def *id, bool integer,
                                             void *stage)
{
   (void)stage;
   nir_def *index = id_half(b, id, integer);
   if (integer)
      index = nir_iand_imm(b, index, STELA_METAL_SAMPLER_PIXELS - 1);
   return heap_element(b, index, STELA_METAL_HEAP_SAMPLERS, glsl_bare_sampler_type(),
                       nir_var_uniform);
}

nir_deref_instr *stela_metal_bind_texture(nir_builder *b, const struct stela_air_texture *texture,
                                          const struct glsl_type *type, bool faces,
                                          nir_def *level, void *stage)
{
   if (texture->index >= STELA_METAL_TEXTURES)
      return NULL;
   return stela_metal_bind_texture_id(
      b, table_id(b, stage, STELA_METAL_TABLE_TEXTURES + 8u * texture->index), type, faces,
      level, stage);
}

nir_deref_instr *stela_metal_bind_attachment(nir_builder *b, unsigned location,
                                             const struct glsl_type *type, void *stage)
{
   return stela_metal_bind_texture_id(
      b, table_id(b, stage, STELA_METAL_TABLE_ATTACHMENTS + 8u * location), type, false, NULL,
      stage);
}

nir_deref_instr *stela_metal_bind_depth_stencil(nir_builder *b, bool stencil,
                                                const struct glsl_type *type, void *stage)
{
   return stela_metal_bind_texture_id(
      b, table_id(b, stage, STELA_METAL_TABLE_DEPTH_COPIES + (stencil ? 8u : 0u)), type, false, NULL,
      stage);
}

/* The MTLResourceID a texture query names, or NULL for a bad binding. */
static nir_def *
queried_id(nir_builder *b, const struct stela_air_texture *texture, nir_def *id, void *stage)
{
   if (id)
      return id;
   if (texture->index >= STELA_METAL_TEXTURES)
      return NULL;
   return table_id(b, stage, STELA_METAL_TABLE_TEXTURES + 8u * texture->index);
}

nir_def *stela_metal_texture_levels(nir_builder *b, const struct stela_air_texture *texture,
                                    nir_def *id, void *stage)
{
   id = queried_id(b, texture, id, stage);
   return id ? nir_iadd_imm(b, nir_ushr_imm(b, id_half(b, id, true), STELA_METAL_LEVEL_SHIFT), 1) :
               NULL;
}

nir_def *stela_metal_texture_null(nir_builder *b, const struct stela_air_texture *texture,
                                  nir_def *id, void *stage)
{
   id = queried_id(b, texture, id, stage);
   return id ? nir_ieq_imm(b, id, 0) : NULL;
}

/* Whether a texture ID's high half carries STELA_METAL_EXTENDED_STORAGE: its
 * chroma flag without a second plane. */
static nir_def *extended_storage(nir_builder *b, nir_def *high)
{
   nir_def *planes = nir_ubitfield_extract_imm(b, high, STELA_METAL_PLANES_SHIFT, 3);
   return nir_ieq_imm(b, planes, STELA_METAL_EXTENDED_STORAGE >> STELA_METAL_PLANES_SHIFT);
}

nir_def *stela_metal_texture_srgb_storage(nir_builder *b, const struct stela_air_texture *texture,
                                          nir_def *id, void *stage)
{
   id = queried_id(b, texture, id, stage);
   if (!id)
      return NULL;
   nir_def *high = id_half(b, id, true);
   nir_def *srgb = nir_ine_imm(b, nir_iand_imm(b, high, STELA_METAL_SRGB_STORAGE), 0);
   return nir_iand(b, srgb, nir_inot(b, extended_storage(b, high)));
}

nir_def *stela_metal_texture_extended_storage(nir_builder *b,
                                              const struct stela_air_texture *texture,
                                              nir_def *id, void *stage)
{
   id = queried_id(b, texture, id, stage);
   if (!id)
      return NULL;
   nir_def *high = id_half(b, id, true);
   nir_def *srgb = nir_ine_imm(b, nir_iand_imm(b, high, STELA_METAL_SRGB_STORAGE), 0);
   nir_def *kind = nir_bcsel(b, srgb, nir_imm_int(b, STELA_AIR_EXTENDED_STORAGE_SRGB),
                             nir_imm_int(b, STELA_AIR_EXTENDED_STORAGE_CODES));
   return nir_bcsel(b, extended_storage(b, high), kind, nir_imm_int(b, STELA_AIR_EXTENDED_STORAGE_NONE));
}

nir_def *stela_metal_texture_planes(nir_builder *b, const struct stela_air_texture *texture,
                                    nir_def *id, void *stage)
{
   id = queried_id(b, texture, id, stage);
   if (!id)
      return NULL;
   nir_def *high = id_half(b, id, true);
   nir_def *planes = nir_ubitfield_extract_imm(b, high, STELA_METAL_PLANES_SHIFT, 3);
   nir_def *ten = nir_ubitfield_extract_imm(b, high, STELA_METAL_PLANES_SHIFT - 1, 1);
   nir_def *video = nir_ubitfield_extract_imm(b, high, STELA_METAL_PLANES_SHIFT - 2, 1);
   /* Those two are storage index bits of a one-plane texture. */
   nir_def *flags = nir_ior(b, nir_ishl_imm(b, ten, 3), nir_ishl_imm(b, video, 4));
   /* Video range without YCbCr marks extended-range codes, whose ten-bit
    * flag is the sRGB curve. */
   nir_def *xr = nir_iand(b, nir_ieq_imm(b, video, 1),
                          nir_ieq_imm(b, nir_iand_imm(b, planes, STELA_AIR_PLANES_YCBCR), 0));
   nir_def *xr_flags = nir_ior_imm(b, nir_ishl_imm(b, ten, 6), STELA_AIR_PLANES_XR10);
   flags = nir_bcsel(b, xr, xr_flags, flags);
   /* STELA_METAL_EXTENDED_STORAGE alone is one plane. */
   return nir_bcsel(b, nir_ine_imm(b, nir_iand_imm(b, planes, 3), 0), nir_ior(b, planes, flags),
                    nir_imm_int(b, 0));
}

nir_def *stela_metal_texture_filter_class(nir_builder *b, const struct stela_air_texture *texture,
                                          nir_def *id, void *stage)
{
   id = queried_id(b, texture, id, stage);
   return id ? nir_ubitfield_extract_imm(b, id_half(b, id, true), STELA_METAL_FILTER_CLASS_SHIFT, 2)
             : NULL;
}

nir_deref_instr *stela_metal_bind_sampler(nir_builder *b, const struct stela_air_sampler *sampler,
                                          bool integer, void *stage)
{
   if (sampler->index >= STELA_METAL_SAMPLERS)
      return NULL;
   return stela_metal_bind_sampler_id(
      b, table_id(b, stage, STELA_METAL_TABLE_SAMPLERS + 8u * sampler->index), integer, stage);
}

/* The high half of the MTLResourceID a sampler query names, or NULL for a
 * bad binding. */
static nir_def *
sampler_flags(nir_builder *b, const struct stela_air_sampler *sampler, nir_def *id, void *stage)
{
   if (!id) {
      if (sampler->index >= STELA_METAL_SAMPLERS)
         return NULL;
      id = table_id(b, stage, STELA_METAL_TABLE_SAMPLERS + 8u * sampler->index);
   }
   return id_half(b, id, true);
}

nir_def *stela_metal_sampler_never(nir_builder *b, const struct stela_air_sampler *sampler,
                                   nir_def *id, void *stage)
{
   nir_def *flags = sampler_flags(b, sampler, id, stage);
   return flags ? nir_test_mask(b, flags, STELA_METAL_SAMPLER_NEVER) : NULL;
}

nir_def *stela_metal_sampler_filter(nir_builder *b, const struct stela_air_sampler *sampler,
                                    nir_def *id, void *stage)
{
   nir_def *flags = sampler_flags(b, sampler, id, stage);
   if (!flags)
      return NULL;
   nir_def *zero = nir_imm_int(b, 0);
   nir_def *bits = zero;
   static const struct {
      uint32_t metal, air;
   } map[] = {
      {STELA_METAL_SAMPLER_CUBIC, STELA_AIR_SAMPLER_CUBIC},
      {STELA_METAL_SAMPLER_MIPPED, STELA_AIR_SAMPLER_MIPPED},
      {STELA_METAL_SAMPLER_PIXELS, STELA_AIR_SAMPLER_PIXELS},
   };
   for (unsigned i = 0; i < ARRAY_SIZE(map); i++)
      bits = nir_ior(b, bits, nir_bcsel(b, nir_test_mask(b, flags, map[i].metal),
                                        nir_imm_int(b, map[i].air), zero));
   return bits;
}

nir_def *stela_metal_resource_id(nir_builder *b, const struct stela_air_texture *texture,
                                 const struct stela_air_sampler *sampler, nir_def *element,
                                 void *stage)
{
   const struct stela_metal_stage *metal = stage;
   unsigned index = texture ? texture->index : sampler->index;
   unsigned length = texture ? texture->length : sampler->length;
   unsigned slots = texture ? STELA_METAL_TEXTURES : STELA_METAL_SAMPLERS;
   if (!length || index >= slots || length > slots - index)
      return NULL;
   /* The load stays within the array's slots, whatever the element. */
   nir_def *slot = nir_umin(b, element, nir_imm_int64(b, length - 1));
   nir_def *address = nir_iadd(b, stela_metal_load_table(b, metal->table), nir_imul_imm(b, slot, 8));
   unsigned first = (texture ? STELA_METAL_TABLE_TEXTURES : STELA_METAL_TABLE_SAMPLERS) + 8u * index;
   return nir_bcsel(b, nir_ult_imm(b, element, length), table_load(b, address, first, 64),
                    nir_imm_int64(b, 0));
}

nir_def *stela_metal_command_count(nir_builder *b, nir_def *buffer, void *stage)
{
   (void)stage;
   return load(b, buffer, STELA_METAL_INDIRECT_COUNT, 32);
}

/* Command index's record in the buffer at buffer: its address, the record
 * stride, and whether the buffer holds it. The header never changes. */
struct record {
   nir_def *buffer, *address, *stride, *valid;
};

static struct record record_at(nir_builder *b, nir_def *buffer, nir_def *index)
{
   nir_def *stride = load(b, buffer, STELA_METAL_INDIRECT_STRIDE, 32);
   nir_def *first = nir_iadd_imm(b, buffer, STELA_METAL_INDIRECT_HEADER_BYTES);
   return (struct record){
      .buffer = buffer,
      .address = nir_iadd(b, first, nir_imul(b, nir_u2u64(b, index), nir_u2u64(b, stride))),
      .stride = stride,
      .valid = nir_ult(b, index, load(b, buffer, STELA_METAL_INDIRECT_COUNT, 32)),
   };
}

/* The address of a record's part at a uint offset, if any, plus a constant
 * one. */
static nir_def *record_part(nir_builder *b, const struct record *record, nir_def *offset,
                            unsigned constant)
{
   nir_def *address = nir_iadd_imm(b, record->address, constant);
   return offset ? nir_iadd(b, address, nir_u2u64(b, offset)) : address;
}

static void put(struct stela_air_command_encoding *encoding, nir_def *address, nir_def *value,
                nir_def *valid)
{
   assert(encoding->store_count < STELA_AIR_COMMAND_STORES);
   encoding->stores[encoding->store_count++] =
      (struct stela_air_command_store){address, value, valid};
}

/* A buffer slot of the record's table of the stage, and a vertex or kernel
 * buffer's stride word, zero for the pipeline's. */
static void bind_buffer(nir_builder *b, const struct record *record,
                        const struct stela_air_command *command,
                        struct stela_air_command_encoding *encoding)
{
   unsigned table = command->binding.stage == STELA_AIR_FRAGMENT;
   nir_def *start = load(b, record->buffer, STELA_METAL_INDIRECT_TABLES + 4u * table, 32);
   nir_def *slots = load(b, record->buffer, STELA_METAL_INDIRECT_TABLE_SLOTS + 4u * table, 32);
   nir_def *slot = command->binding.slot;
   nir_def *valid = nir_iand(b, record->valid, nir_ult(b, slot, slots));
   nir_def *address = nir_iadd(b, start, nir_imul_imm(b, slot, 8));
   nir_def *length = nir_iadd(b, address, nir_imul_imm(b, slots, 8));
   put(encoding, record_part(b, record, address, 0), command->binding.address, valid);
   put(encoding, record_part(b, record, length, 0),
       nir_imm_int64(b, STELA_METAL_RECORD_UNBOUNDED), valid);
   bool kernel = !command->binding.stage;
   if (command->binding.stage != STELA_AIR_VERTEX && !kernel)
      return;
   nir_def *words = load(b, record->buffer,
                         kernel ? STELA_METAL_INDIRECT_STRIDES : STELA_METAL_INDIRECT_WORDS, 32);
   nir_def *word_count = load(b, record->buffer,
                              kernel ? STELA_METAL_INDIRECT_STRIDE_COUNT :
                                       STELA_METAL_INDIRECT_WORD_COUNT, 32);
   nir_def *stride = command->binding.stride;
   put(encoding, record_part(b, record, nir_iadd(b, words, nir_imul_imm(b, slot, 4)), 0),
       nir_bcsel(b, nir_ieq_imm(b, stride, -1), nir_imm_int(b, 0), nir_u2u32(b, stride)),
       nir_iand(b, record->valid, nir_ult(b, slot, word_count)));
}

/* A draw's action and arguments, and an indexed draw's indices: their
 * address, the bytes the draw reads and their MTLIndexType. */
static void draw(nir_builder *b, const struct record *record,
                 const struct stela_air_command *command,
                 struct stela_air_command_encoding *encoding)
{
   bool indexed = command->op == STELA_AIR_COMMAND_DRAW_INDEXED;
   nir_def *valid = record->valid, *zero = nir_imm_int(b, 0);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_ACTION),
       nir_imm_int(b, indexed ? STELA_METAL_RECORD_DRAW_INDEXED : STELA_METAL_RECORD_DRAW), valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_VERTICES),
       nir_vec4(b, command->draw.count, command->draw.instances,
                indexed ? zero : command->draw.first_vertex,
                indexed ? command->draw.base_vertex : zero),
       valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_BASE_INSTANCE),
       nir_vec2(b, command->draw.base_instance, command->draw.primitive), valid);
   if (!indexed)
      return;
   nir_def *bytes = nir_imul_imm(b, nir_u2u64(b, command->draw.count), command->draw.index_bytes);
   nir_def *length = nir_u2u32(b, nir_umin(b, bytes, nir_imm_int64(b, UINT32_MAX)));
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_INDEX_ADDRESS),
       command->draw.indices, valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_INDEX_LENGTH),
       nir_vec2(b, length, nir_imm_int(b, command->draw.index_bytes == 4)), valid);
}

/* A patch draw's action and arguments in six stores; buffers a shader
 * names come without lengths, so the record bounds them as unbounded. */
static void draw_patches(nir_builder *b, const struct record *record,
                         const struct stela_air_command *command,
                         struct stela_air_command_encoding *encoding)
{
   bool indexed = command->op == STELA_AIR_COMMAND_DRAW_INDEXED_PATCHES;
   nir_def *valid = record->valid, *zero = nir_imm_int(b, 0);
   nir_def *unbounded = nir_imm_int(b, STELA_METAL_RECORD_UNBOUNDED);
   nir_def *control_point_indices = nir_unpack_64_2x32(b, command->patches.control_point_indices);
   nir_def *patch_indices = nir_unpack_64_2x32(b, command->patches.patch_indices);
   nir_def *factors = nir_unpack_64_2x32(b, command->patches.factors);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_ACTION),
       nir_imm_int(b, indexed ? STELA_METAL_RECORD_DRAW_INDEXED_PATCHES :
                                STELA_METAL_RECORD_DRAW_PATCHES),
       valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_VERTICES),
       nir_vec4(b, command->patches.count, command->patches.instances, command->patches.start,
                command->patches.control_points),
       valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_BASE_INSTANCE),
       nir_vec2(b, command->patches.base_instance, zero), valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_CONTROL_POINT_INDICES),
       nir_vec4(b, nir_channel(b, control_point_indices, 0),
                nir_channel(b, control_point_indices, 1), indexed ? unbounded : zero,
                command->patches.instance_stride),
       valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_PATCH_INDICES),
       nir_vec4(b, nir_channel(b, patch_indices, 0), nir_channel(b, patch_indices, 1),
                nir_channel(b, factors, 0), nir_channel(b, factors, 1)),
       valid);
   put(encoding, record_part(b, record, NULL, STELA_METAL_RECORD_PATCH_INDEX_LENGTH),
       nir_vec4(b, unbounded, unbounded, command->patches.scale, nir_imm_int(b, 1)), valid);
}

bool stela_metal_encode_command(nir_builder *b, const struct stela_air_command *command,
                                struct stela_air_command_encoding *encoding, void *stage)
{
   (void)stage;
   struct record record = record_at(b, command->buffer, command->index);
   nir_def *valid = record.valid;
   switch (command->op) {
   case STELA_AIR_COMMAND_RESET:
      /* A zeroed record is a reset command. */
      encoding->destination = record.address;
      encoding->bytes = record.stride;
      encoding->copy_valid = valid;
      return true;
   case STELA_AIR_COMMAND_COPY: {
      struct record source = record_at(b, command->source.buffer, command->source.index);
      encoding->destination = record.address;
      encoding->source = source.address;
      encoding->bytes = record.stride;
      encoding->copy_valid = nir_iand(b, nir_iand(b, valid, source.valid),
                                      nir_ieq(b, record.stride, source.stride));
      return true;
   }
   case STELA_AIR_COMMAND_SET_BARRIER:
   case STELA_AIR_COMMAND_CLEAR_BARRIER:
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_BARRIER),
          nir_imm_int(b, command->op == STELA_AIR_COMMAND_SET_BARRIER), valid);
      return true;
   case STELA_AIR_COMMAND_PIPELINE:
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_PIPELINE), command->pipeline,
          valid);
      return true;
   case STELA_AIR_COMMAND_BUFFER:
      bind_buffer(b, &record, command, encoding);
      return true;
   case STELA_AIR_COMMAND_THREADGROUP_LENGTH: {
      nir_def *words = load(b, record.buffer, STELA_METAL_INDIRECT_WORDS, 32);
      nir_def *word_count = load(b, record.buffer, STELA_METAL_INDIRECT_WORD_COUNT, 32);
      nir_def *slot = command->threadgroup.slot;
      put(encoding, record_part(b, &record, nir_iadd(b, words, nir_imul_imm(b, slot, 4)), 0),
          command->threadgroup.length, nir_iand(b, valid, nir_ult(b, slot, word_count)));
      return true;
   }
   case STELA_AIR_COMMAND_STAGE_IN_REGION:
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_STAGE_IN_ORIGIN),
          command->region.origin, valid);
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_STAGE_IN_SIZE),
          command->region.size, valid);
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_STAGE_IN), nir_imm_int(b, 1),
          valid);
      return true;
   case STELA_AIR_COMMAND_DRAW:
   case STELA_AIR_COMMAND_DRAW_INDEXED:
      draw(b, &record, command, encoding);
      return true;
   case STELA_AIR_COMMAND_DRAW_PATCHES:
   case STELA_AIR_COMMAND_DRAW_INDEXED_PATCHES:
      draw_patches(b, &record, command, encoding);
      return true;
   case STELA_AIR_COMMAND_DISPATCH_THREADGROUPS:
   case STELA_AIR_COMMAND_DISPATCH_THREADS: {
      bool threads = command->op == STELA_AIR_COMMAND_DISPATCH_THREADS;
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_ACTION),
          nir_imm_int(b, threads ? STELA_METAL_RECORD_DISPATCH_THREADS : STELA_METAL_RECORD_DISPATCH),
          valid);
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_GRID), command->dispatch.grid,
          valid);
      put(encoding, record_part(b, &record, NULL, STELA_METAL_RECORD_THREADS),
          command->dispatch.threads, valid);
      return true;
   }
   }
   return false;
}

/* A compute kernel's builder with its arguments address and thread index,
 * inside `if (thread < count)` for the u32 count at count_offset. */
static nir_builder kernel(const nir_shader_compiler_options *options, const char *name,
                          unsigned count_offset, nir_def **arguments, nir_def **thread)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_COMPUTE, options, "%s", name);
   b.shader->info.workgroup_size[0] = STELA_METAL_KERNEL_WORKGROUP;
   b.shader->info.workgroup_size[1] = 1;
   b.shader->info.workgroup_size[2] = 1;
   *arguments = load_push(&b, 1, 64, STELA_METAL_PUSH_ARGUMENTS);
   *thread = nir_channel(&b, nir_load_global_invocation_id(&b, 32), 0);
   nir_push_if(&b, nir_ult(&b, *thread, load(&b, *arguments, count_offset, 32)));
   return b;
}

static nir_shader *validated(nir_builder *b)
{
   nir_lower_vars_to_ssa(b->shader);
   nir_remove_dead_variables(b->shader, nir_var_function_temp, NULL);
   nir_validate_shader(b->shader, "Metal internal shader");
   return b->shader;
}

static nir_shader *finish(nir_builder *b)
{
   nir_pop_if(b, NULL);
   return validated(b);
}

nir_shader *stela_metal_accumulate_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_accumulate", STELA_METAL_ACCUMULATE_COUNT,
                          &arguments, &thread);
   nir_def *results = load(&b, arguments, STELA_METAL_ACCUMULATE_RESULTS, 64);
   nir_def *stride = load(&b, arguments, STELA_METAL_ACCUMULATE_STRIDE, 32);
   nir_def *run = nir_iadd(&b, nir_iadd_imm(&b, arguments, STELA_METAL_ACCUMULATE_RUNS),
                           nir_u2u64(&b, nir_imul_imm(&b, thread,
                                                      STELA_METAL_ACCUMULATE_RUN_BYTES)));
   nir_def *first = load(&b, run, 0, 32);
   nir_def *count = load(&b, run, 4, 32);
   nir_def *destination = load(&b, run, 8, 64);

   nir_variable *sum = nir_local_variable_create(b.impl, glsl_uint64_t_type(), "sum");
   nir_variable *index = nir_local_variable_create(b.impl, glsl_uint_type(), "index");
   nir_store_var(&b, sum, nir_imm_int64(&b, 0), 1);
   nir_store_var(&b, index, nir_imm_int(&b, 0), 1);
   nir_push_loop(&b);
   {
      nir_def *j = nir_load_var(&b, index);
      nir_break_if(&b, nir_uge(&b, j, count));
      nir_def *element = nir_iadd(&b, first, nir_imul(&b, j, stride));
      nir_def *address = nir_iadd(&b, results, nir_u2u64(&b, nir_imul_imm(&b, element, 8)));
      nir_store_var(&b, sum, nir_iadd(&b, nir_load_var(&b, sum), load(&b, address, 0, 64)), 1);
      nir_store_var(&b, index, nir_iadd_imm(&b, j, 1), 1);
   }
   nir_pop_loop(&b, NULL);
   nir_store_global(&b, nir_load_var(&b, sum), destination, .align_mul = 8);
   return finish(&b);
}

nir_shader *stela_metal_select_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_select", STELA_METAL_SELECT_COUNT, &arguments,
                          &thread);
   nir_def *range = load(&b, arguments, STELA_METAL_SELECT_RANGE, 64);
   nir_def *location = load(&b, range, 0, 32);
   nir_def *length = load(&b, range, 4, 32);
   /* location <= n < location + length, without the sum's overflow. */
   nir_def *selected = nir_iand(&b, nir_uge(&b, thread, location),
                                nir_ult(&b, nir_isub(&b, thread, location), length));
   nir_def *flags = load(&b, arguments, STELA_METAL_SELECT_FLAGS, 64);
   nir_def *flag = nir_iadd(&b, flags, nir_u2u64(&b, nir_imul_imm(&b, thread, 4)));
   nir_store_global(&b, nir_b2i32(&b, selected), flag, .align_mul = 4);
   return finish(&b);
}

static void store(nir_builder *b, nir_def *value, nir_def *address, unsigned offset)
{
   nir_store_global(b, value, nir_iadd_imm(b, address, offset), .align_mul = value->bit_size / 8);
}

/* address + index * size. */
static nir_def *element(nir_builder *b, nir_def *address, nir_def *index, unsigned size)
{
   return nir_iadd(b, address, nir_u2u64(b, nir_imul_imm(b, index, size)));
}

/* Opens for (index = 0; index < count; index++) over counter. */
static nir_def *push_count(nir_builder *b, nir_variable *counter, nir_def *count)
{
   nir_store_var(b, counter, nir_imm_int(b, 0), 1);
   nir_push_loop(b);
   nir_def *index = nir_load_var(b, counter);
   nir_break_if(b, nir_uge(b, index, count));
   return index;
}

static void pop_count(nir_builder *b, nir_variable *counter, nir_def *index)
{
   nir_store_var(b, counter, nir_iadd_imm(b, index, 1), 1);
   nir_pop_loop(b, NULL);
}

/* Writes a thread's argument table of stage (vertex or fragment): the
 * encoder's, with the record's buffer slots. */
static nir_def *resolve_table(nir_builder *b, nir_def *arguments, nir_def *header,
                              nir_def *record, nir_def *thread, unsigned stage,
                              nir_variable *counter)
{
   nir_def *tables = load(b, arguments, STELA_METAL_RESOLVE_TABLES, 64);
   nir_def *table = element(b, tables, nir_iadd_imm(b, nir_imul_imm(b, thread, 2), stage),
                            STELA_METAL_TABLE_BYTES);
   nir_def *source = load(b, arguments, STELA_METAL_RESOLVE_PUSH + 8u * stage, 64);
   nir_def *word = push_count(b, counter, nir_imm_int(b, STELA_METAL_TABLE_BYTES / 16));
   {
      nir_def *value = nir_load_global(b, 4, 32, element(b, source, word, 16),
                                       .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER,
                                       .align_mul = 16);
      nir_store_global(b, value, element(b, table, word, 16), .align_mul = 16);
   }
   pop_count(b, counter, word);
   nir_def *offset = load(b, header, STELA_METAL_INDIRECT_TABLES + 4u * stage, 32);
   nir_def *slots = load(b, header, STELA_METAL_INDIRECT_TABLE_SLOTS + 4u * stage, 32);
   nir_def *addresses = nir_iadd(b, record, nir_u2u64(b, offset));
   nir_def *lengths = element(b, addresses, slots, 8);
   nir_def *slot = push_count(b, counter, slots);
   {
      nir_def *at = element(b, table, slot, 8);
      store(b, load(b, element(b, addresses, slot, 8), 0, 64), at,
            STELA_METAL_TABLE_BUFFER_ADDRESSES);
      store(b, load(b, element(b, lengths, slot, 8), 0, 64), at, STELA_METAL_TABLE_BUFFER_LENGTHS);
   }
   pop_count(b, counter, slot);
   return table;
}

/* Writes a thread's vertex buffer bindings: the encoder's when the buffer
 * inherits buffers, else the vertex table's, each of its own stride or else
 * the class's. Each buffer's own stride also goes to the sequence's
 * TessellationArguments, whose evaluation stage fetches layouts of dynamic
 * stride by it. */
static void resolve_vertex_buffers(nir_builder *b, nir_def *arguments, nir_def *header,
                                   nir_def *record, nir_def *sequence, nir_def *class,
                                   nir_def *inherit_buffers, nir_variable *counter)
{
   nir_def *tessellation_strides = nir_iadd_imm(
      b, sequence, STELA_METAL_SEQUENCE_TESSELLATION + STELA_METAL_TESSELLATION_STRIDES);
   nir_def *table =
      nir_iadd(b, record, nir_u2u64(b, load(b, header, STELA_METAL_INDIRECT_TABLES, 32)));
   nir_def *slots = load(b, header, STELA_METAL_INDIRECT_TABLE_SLOTS, 32);
   nir_def *lengths = element(b, table, slots, 8);
   nir_def *words =
      nir_iadd(b, record, nir_u2u64(b, load(b, header, STELA_METAL_INDIRECT_WORDS, 32)));
   nir_def *word_count = load(b, header, STELA_METAL_INDIRECT_WORD_COUNT, 32);
   nir_def *known = nir_ult(b, class, load(b, arguments, STELA_METAL_RESOLVE_CLASS_COUNT, 32));
   nir_def *strides = element(b, load(b, arguments, STELA_METAL_RESOLVE_STRIDES, 64),
                              nir_bcsel(b, known, class, nir_imm_int(b, 0)),
                              4 * STELA_METAL_BUFFERS);
   nir_def *index = push_count(b, counter, nir_imm_int(b, STELA_METAL_BUFFERS));
   {
      nir_def *encoder =
         nir_load_global(b, 4, 32,
                         element(b, nir_iadd_imm(b, arguments, STELA_METAL_RESOLVE_VERTEX_BUFFERS),
                                 index, STELA_METAL_SEQUENCE_VERTEX_BUFFER_BYTES),
                         .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER, .align_mul = 16);
      /* An inheriting buffer's records hold no slots or strides. */
      nir_def *bound = nir_ult(b, index, slots);
      nir_def *zero = nir_imm_int64(b, 0);
      nir_def *address = nir_bcsel(b, bound, load(b, element(b, table, index, 8), 0, 64),
                                   nir_bcsel(b, inherit_buffers,
                                             nir_pack_64_2x32(b, nir_channels(b, encoder, 0x3)),
                                             zero));
      nir_def *length =
         nir_bcsel(b, bound, load(b, element(b, lengths, index, 8), 0, 64),
                   nir_bcsel(b, inherit_buffers, nir_u2u64(b, nir_channel(b, encoder, 2)), zero));
      nir_def *own = nir_bcsel(b, nir_ult(b, index, word_count),
                               load(b, element(b, words, index, 4), 0, 32),
                               nir_bcsel(b, inherit_buffers, nir_channel(b, encoder, 3),
                                         nir_imm_int(b, 0)));
      nir_def *pipeline = nir_bcsel(b, known, load(b, element(b, strides, index, 4), 0, 32),
                                    nir_imm_int(b, 0));
      nir_def *target =
         element(b, nir_iadd_imm(b, sequence, STELA_METAL_SEQUENCE_VERTEX_BUFFERS), index,
                 STELA_METAL_SEQUENCE_VERTEX_BUFFER_BYTES);
      store(b, address, target, 0);
      store(b, nir_u2u32(b, nir_umin(b, length, nir_imm_int64(b, UINT32_MAX))), target, 8);
      store(b, nir_bcsel(b, nir_ine_imm(b, own, 0), own, pipeline), target, 12);
      store(b, own, element(b, tessellation_strides, index, 4), 0);
   }
   pop_count(b, counter, index);
}

/* A (64-bit address, uint byte length) binding of a record as a
 * TessellationArguments binding at offset. */
static void tessellation_binding(nir_builder *b, nir_def *record, unsigned address,
                                 unsigned length, nir_def *arguments, unsigned offset)
{
   store(b, load(b, record, address, 64), arguments, offset);
   store(b, nir_u2u64(b, load(b, record, length, 32)), arguments, offset + 8);
}

/* A patch draw's TessellationArguments, in the sequence its push constants'
 * arguments then address: the record's bindings, control points and
 * instance stride, and its factor scale where it gave one and the pipeline
 * scales factors, else the CPU-encoded draws' scale. */
static void resolve_tessellation(nir_builder *b, nir_def *arguments, nir_def *record,
                                 nir_def *sequence, nir_def *flags)
{
   nir_def *tessellation = nir_iadd_imm(b, sequence, STELA_METAL_SEQUENCE_TESSELLATION);
   store(b, tessellation, sequence, STELA_METAL_SEQUENCE_PUSH + STELA_METAL_PUSH_ARGUMENTS);
   tessellation_binding(b, record, STELA_METAL_RECORD_FACTORS, STELA_METAL_RECORD_FACTOR_LENGTH,
                        tessellation, STELA_METAL_TESSELLATION_FACTORS);
   tessellation_binding(b, record, STELA_METAL_RECORD_PATCH_INDICES,
                        STELA_METAL_RECORD_PATCH_INDEX_LENGTH, tessellation,
                        STELA_METAL_TESSELLATION_PATCH_INDICES);
   tessellation_binding(b, record, STELA_METAL_RECORD_CONTROL_POINT_INDICES,
                        STELA_METAL_RECORD_CONTROL_POINT_INDEX_LENGTH, tessellation,
                        STELA_METAL_TESSELLATION_CONTROL_POINT_INDICES);
   store(b, load(b, record, STELA_METAL_RECORD_INSTANCE_STRIDE, 32), tessellation,
         STELA_METAL_TESSELLATION_INSTANCE_STRIDE);
   nir_def *own = nir_iand(b, nir_ine_imm(b, load(b, record, STELA_METAL_RECORD_SCALED, 32), 0),
                           nir_test_mask(b, flags, STELA_METAL_RESOLVE_SCALES));
   nir_def *scale = nir_bcsel(b, own, load(b, record, STELA_METAL_RECORD_FACTOR_SCALE, 32),
                              load(b, arguments, STELA_METAL_RESOLVE_FACTOR_SCALE, 32));
   store(b, scale, tessellation, STELA_METAL_TESSELLATION_FACTOR_SCALE);
   store(b, load(b, record, STELA_METAL_RECORD_CONTROL_POINTS, 32), tessellation,
         STELA_METAL_TESSELLATION_CONTROL_POINTS);
}

/* The record of the thread's command, and whether the execution range
 * and the buffer hold the command. */
static nir_def *resolved_record(nir_builder *b, nir_def *arguments, nir_def *header,
                                nir_def *thread, nir_def **record)
{
   nir_def *command = nir_iadd(b, thread, load(b, arguments, STELA_METAL_RESOLVE_FIRST, 32));
   nir_def *stride = load(b, header, STELA_METAL_INDIRECT_STRIDE, 32);
   *record = nir_iadd(b, nir_iadd_imm(b, header, STELA_METAL_INDIRECT_HEADER_BYTES),
                      nir_imul(b, nir_u2u64(b, command), nir_u2u64(b, stride)));
   nir_def *range = load(b, arguments, STELA_METAL_RESOLVE_RANGE, 64);
   nir_def *location = load(b, range, 0, 32);
   /* location <= command < location + length, without the sum's overflow,
    * and within the buffer. */
   nir_def *in_range = nir_iand(b, nir_uge(b, command, location),
                                nir_ult(b, nir_isub(b, command, location), load(b, range, 4, 32)));
   return nir_iand(b, in_range,
                   nir_ult(b, command, load(b, header, STELA_METAL_INDIRECT_COUNT, 32)));
}

nir_shader *stela_metal_resolve_draws_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_resolve_draws", STELA_METAL_RESOLVE_COUNT,
                          &arguments, &thread);
   nir_variable *counter = nir_local_variable_create(b.impl, glsl_uint_type(), "counter");
   nir_def *header = load(&b, arguments, STELA_METAL_RESOLVE_HEADER, 64);
   nir_def *record;
   nir_def *selected = resolved_record(&b, arguments, header, thread, &record);
   nir_def *flags = load(&b, arguments, STELA_METAL_RESOLVE_FLAGS, 32);
   nir_def *inherit_pipeline = nir_test_mask(&b, flags, STELA_METAL_RESOLVE_INHERIT_PIPELINE);
   nir_def *inherit_buffers = nir_test_mask(&b, flags, STELA_METAL_RESOLVE_INHERIT_BUFFERS);
   nir_def *sequence = element(&b, load(&b, arguments, STELA_METAL_RESOLVE_SEQUENCES, 64), thread,
                               STELA_METAL_SEQUENCE_BYTES);

   /* The command's class, action and primitive type; commands outside the
    * range take no action and write only zero counts. */
   nir_variable *matched[3];
   for (unsigned field = 0; field < ARRAY_SIZE(matched); field++) {
      matched[field] = nir_local_variable_create(b.impl, glsl_uint_type(), "matched");
      nir_store_var(&b, matched[field], nir_imm_int(&b, 0), 1);
   }
   nir_push_if(&b, selected);
   nir_def *handle = load(&b, record, STELA_METAL_RECORD_PIPELINE, 64);
   /* Without a pipeline handle, a command is no class. */
   nir_def *class = nir_bcsel(&b, inherit_pipeline, nir_imm_int(&b, 0),
                              nir_iadd_imm(&b, nir_unpack_64_2x32_split_y(&b, handle), -1));
   nir_store_var(&b, matched[0], class, 1);
   nir_store_var(&b, matched[1], load(&b, record, STELA_METAL_RECORD_ACTION, 32), 1);
   nir_store_var(&b, matched[2], load(&b, record, STELA_METAL_RECORD_PRIMITIVE, 32), 1);
   store(&b, nir_unpack_64_2x32_split_x(&b, handle), sequence, STELA_METAL_SEQUENCE_PIPELINE);

   /* The encoder's push constants, with the command's argument tables. */
   for (unsigned word = 0; word < STELA_METAL_PUSH_BYTES / 4; word++)
      store(&b, load(&b, arguments, STELA_METAL_RESOLVE_PUSH + 4 * word, 32), sequence,
            STELA_METAL_SEQUENCE_PUSH + 4 * word);
   nir_push_if(&b, nir_inot(&b, inherit_buffers));
   for (unsigned stage = 0; stage < 2; stage++) {
      nir_def *table = resolve_table(&b, arguments, header, record, thread, stage, counter);
      store(&b, table, sequence, STELA_METAL_SEQUENCE_PUSH + STELA_METAL_PUSH_TABLES + 8 * stage);
   }
   nir_pop_if(&b, NULL);

   /* The index buffer's address, byte length and VkIndexType, which numbers
    * the index types as MTLIndexType does. */
   store(&b, load(&b, record, STELA_METAL_RECORD_INDEX_ADDRESS, 64), sequence,
         STELA_METAL_SEQUENCE_INDEX_BUFFER);
   store(&b, load(&b, record, STELA_METAL_RECORD_INDEX_LENGTH, 32), sequence,
         STELA_METAL_SEQUENCE_INDEX_BUFFER + 8);
   store(&b, load(&b, record, STELA_METAL_RECORD_INDEX_TYPE, 32), sequence,
         STELA_METAL_SEQUENCE_INDEX_BUFFER + 12);
   resolve_vertex_buffers(&b, arguments, header, record, sequence, class, inherit_buffers,
                          counter);
   nir_push_if(&b, nir_uge_imm(&b, nir_load_var(&b, matched[1]), STELA_METAL_RECORD_DRAW_PATCHES));
   resolve_tessellation(&b, arguments, record, sequence, flags);
   nir_pop_if(&b, NULL);

   /* (vertex count, instance count, first vertex, base instance), and
    * (index count, instance count, first index, base vertex, base instance)
    * with the offset in the index buffer's address. */
   nir_def *vertices = load(&b, record, STELA_METAL_RECORD_VERTICES, 32);
   nir_def *instances = load(&b, record, STELA_METAL_RECORD_INSTANCES, 32);
   nir_def *base_instance = load(&b, record, STELA_METAL_RECORD_BASE_INSTANCE, 32);
   nir_def *first_vertex = load(&b, record, STELA_METAL_RECORD_FIRST_VERTEX, 32);
   store(&b, nir_vec4(&b, vertices, instances, first_vertex, base_instance), sequence,
         STELA_METAL_SEQUENCE_DRAW);
   nir_def *indexed[] = {vertices, instances, nir_imm_int(&b, 0),
                         load(&b, record, STELA_METAL_RECORD_BASE_VERTEX, 32), base_instance};
   for (unsigned field = 0; field < ARRAY_SIZE(indexed); field++)
      store(&b, indexed[field], sequence, STELA_METAL_SEQUENCE_DRAW_INDEXED + 4 * field);
   nir_pop_if(&b, NULL);
   class = nir_load_var(&b, matched[0]);
   nir_def *action = nir_load_var(&b, matched[1]);
   nir_def *primitive = nir_load_var(&b, matched[2]);

   nir_def *counts = load(&b, arguments, STELA_METAL_RESOLVE_COUNTS, 64);
   nir_def *slot_count = load(&b, arguments, STELA_METAL_RESOLVE_SLOT_COUNT, 32);
   nir_def *slot = push_count(&b, counter, slot_count);
   {
      nir_def *entry = element(&b, nir_iadd_imm(&b, arguments, STELA_METAL_RESOLVE_SLOTS), slot,
                               STELA_METAL_RESOLVE_SLOT_BYTES);
      nir_def *matches =
         nir_iand(&b, nir_iand(&b, nir_ine_imm(&b, action, 0), nir_ieq(&b, class, load(&b, entry, 0, 32))),
                  nir_iand(&b, nir_ieq(&b, action, load(&b, entry, 4, 32)),
                           nir_ieq(&b, primitive, load(&b, entry, 8, 32))));
      nir_def *at = nir_iadd(&b, nir_imul(&b, thread, slot_count), slot);
      store(&b, nir_b2i32(&b, matches), element(&b, counts, at, 4), 0);
   }
   pop_count(&b, counter, slot);
   return finish(&b);
}

/* The uvec3 at address + offset. */
static nir_def *load_uvec3(nir_builder *b, nir_def *address, unsigned offset)
{
   return nir_vec3(b, load(b, address, offset, 32), load(b, address, offset + 4, 32),
                   load(b, address, offset + 8, 32));
}

nir_shader *stela_metal_resolve_dispatches_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_resolve_dispatches", STELA_METAL_RESOLVE_COUNT,
                          &arguments, &thread);
   nir_variable *counter = nir_local_variable_create(b.impl, glsl_uint_type(), "counter");
   nir_variable *offset = nir_local_variable_create(b.impl, glsl_uint_type(), "offset");
   nir_def *header = load(&b, arguments, STELA_METAL_RESOLVE_HEADER, 64);
   nir_def *record;
   nir_def *selected = resolved_record(&b, arguments, header, thread, &record);
   nir_def *flags = load(&b, arguments, STELA_METAL_RESOLVE_FLAGS, 32);
   nir_def *inherit_pipeline = nir_test_mask(&b, flags, STELA_METAL_RESOLVE_INHERIT_PIPELINE);
   nir_def *inherit_buffers = nir_test_mask(&b, flags, STELA_METAL_RESOLVE_INHERIT_BUFFERS);
   nir_def *sequence = element(&b, load(&b, arguments, STELA_METAL_RESOLVE_SEQUENCES, 64), thread,
                               STELA_METAL_SEQUENCE_BYTES);
   nir_def *dispatch = nir_iadd_imm(&b, sequence, STELA_METAL_SEQUENCE_DISPATCH_ARGUMENTS);

   /* The encoder's push constants, with the dispatch's arguments; a command
    * the range does not hold dispatches nothing. */
   for (unsigned word = 0; word < STELA_METAL_PUSH_BYTES / 4; word++)
      store(&b, load(&b, arguments, STELA_METAL_RESOLVE_PUSH + 4 * word, 32), sequence,
            STELA_METAL_SEQUENCE_PUSH + 4 * word);
   store(&b, dispatch, sequence, STELA_METAL_SEQUENCE_PUSH + STELA_METAL_PUSH_ARGUMENTS);
   nir_def *none = nir_imm_ivec3(&b, 0, 0, 0);
   store(&b, none, sequence, STELA_METAL_SEQUENCE_PUSH + STELA_METAL_PUSH_GRID);
   store(&b, nir_imm_int(&b, 0), sequence, STELA_METAL_SEQUENCE_PIPELINE);
   store(&b, none, sequence, STELA_METAL_SEQUENCE_DISPATCH);
   nir_push_if(&b, selected);
   nir_def *handle = load(&b, record, STELA_METAL_RECORD_PIPELINE, 64);
   nir_def *action = load(&b, record, STELA_METAL_RECORD_ACTION, 32);
   nir_def *compute = nir_ieq_imm(&b, nir_unpack_64_2x32_split_y(&b, handle),
                                  STELA_METAL_RECORD_COMPUTE_PIPELINES);
   nir_def *runs = nir_iand(&b, nir_ine_imm(&b, action, 0), nir_ior(&b, inherit_pipeline, compute));
   store(&b, nir_bcsel(&b, compute, nir_unpack_64_2x32_split_x(&b, handle), nir_imm_int(&b, 0)),
         sequence, STELA_METAL_SEQUENCE_PIPELINE);
   nir_push_if(&b, nir_inot(&b, inherit_buffers));
   nir_def *table = resolve_table(&b, arguments, header, record, thread, 0, counter);
   store(&b, table, sequence, STELA_METAL_SEQUENCE_PUSH + STELA_METAL_PUSH_TABLES);
   nir_pop_if(&b, NULL);

   /* Threadgroups, or the threadgroups that cover a grid of threads, which
    * the kernel then bounds. */
   nir_def *grid = load_uvec3(&b, record, STELA_METAL_RECORD_GRID);
   nir_def *threads = load_uvec3(&b, record, STELA_METAL_RECORD_THREADS);
   nir_def *by_threads = nir_ieq_imm(&b, action, STELA_METAL_RECORD_DISPATCH_THREADS);
   nir_def *width = nir_umax_imm(&b, threads, 1);
   nir_def *covering = nir_iadd(&b, nir_udiv(&b, grid, width),
                                nir_b2i32(&b, nir_ine_imm(&b, nir_umod(&b, grid, width), 0)));
   store(&b, nir_bcsel(&b, by_threads, grid, none), sequence,
         STELA_METAL_SEQUENCE_PUSH + STELA_METAL_PUSH_GRID);
   store(&b, nir_bcsel(&b, runs, nir_bcsel(&b, by_threads, covering, grid), none), sequence,
         STELA_METAL_SEQUENCE_DISPATCH);

   /* The stage-in region, the shape, and each threadgroup buffer's offset:
    * the lengths before it, each rounded up to 16 bytes. */
   store(&b, load_uvec3(&b, record, STELA_METAL_RECORD_STAGE_IN_ORIGIN), dispatch,
         STELA_METAL_DISPATCH_REGION);
   store(&b, load_uvec3(&b, record, STELA_METAL_RECORD_STAGE_IN_SIZE), dispatch,
         STELA_METAL_DISPATCH_REGION + 12);
   store(&b, threads, dispatch, STELA_METAL_DISPATCH_SHAPE);
   nir_def *words =
      nir_iadd(&b, record, nir_u2u64(&b, load(&b, header, STELA_METAL_INDIRECT_WORDS, 32)));
   nir_def *word_count = load(&b, header, STELA_METAL_INDIRECT_WORD_COUNT, 32);
   nir_store_var(&b, offset, nir_imm_int(&b, 0), 1);
   nir_def *index = push_count(&b, counter, nir_imm_int(&b, STELA_METAL_BUFFERS));
   {
      nir_def *at = nir_load_var(&b, offset);
      store(&b, at, element(&b, dispatch, index, 4), STELA_METAL_DISPATCH_OFFSETS);
      nir_def *length = nir_bcsel(&b, nir_ult(&b, index, word_count),
                                  load(&b, element(&b, words, index, 4), 0, 32), nir_imm_int(&b, 0));
      nir_def *rounded = nir_iand_imm(&b, nir_iadd_imm(&b, length, 15), ~15u);
      nir_store_var(&b, offset, nir_iadd(&b, at, rounded), 1);
   }
   pop_count(&b, counter, index);

   /* The kernel buffers' attribute strides, which dynamic stage-in layouts
    * read, zero past the record's. */
   nir_def *strides =
      nir_iadd(&b, record, nir_u2u64(&b, load(&b, header, STELA_METAL_INDIRECT_STRIDES, 32)));
   nir_def *stride_count = load(&b, header, STELA_METAL_INDIRECT_STRIDE_COUNT, 32);
   nir_def *slot = push_count(&b, counter, nir_imm_int(&b, STELA_METAL_BUFFERS));
   nir_def *stride = nir_bcsel(&b, nir_ult(&b, slot, stride_count),
                               load(&b, element(&b, strides, slot, 4), 0, 32), nir_imm_int(&b, 0));
   store(&b, stride, element(&b, dispatch, slot, 4), STELA_METAL_DISPATCH_STRIDES);
   pop_count(&b, counter, slot);
   nir_pop_if(&b, NULL);
   return finish(&b);
}

nir_shader *stela_metal_tessellation_vertex(const nir_shader_compiler_options *options)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_VERTEX, options,
                                                  "stela_metal_tessellation_vertex");
   nir_variable *patch = nir_variable_create(b.shader, nir_var_shader_out, glsl_uvec_type(3),
                                             "patch");
   patch->data.location = VARYING_SLOT_VAR0;
   patch->data.interpolation = INTERP_MODE_FLAT;
   nir_def *base = nir_load_base_instance(&b);
   nir_def *instance = nir_iadd(&b, nir_load_instance_id(&b), base);
   nir_store_var(&b, patch, nir_vec3(&b, nir_load_vertex_id(&b), instance, base), 0x7);
   return validated(&b);
}

/* How an MTLVertexFormat's lanes read. */
enum vertex_kind {
   VERTEX_UINT = 1,
   VERTEX_SINT,
   VERTEX_UNORM,
   VERTEX_SNORM,
   VERTEX_HALF,
   VERTEX_FLOAT,
   /* Packed formats, one word each. */
   VERTEX_UNORM_1010102,
   VERTEX_SNORM_1010102,
   VERTEX_RG11B10,
   VERTEX_RGB9E5,
};

struct vertex_format {
   uint8_t lanes, bits; /* Lanes of bits each; packed formats' lanes vary. */
   enum vertex_kind kind;
   bool bgra; /* The bytes hold blue, green, red, alpha. */
};

/* By MTLVertexFormat; the gaps name no format. */
static const struct vertex_format vertex_formats[] = {
   [1] = {2, 8, VERTEX_UINT},    [2] = {3, 8, VERTEX_UINT},    [3] = {4, 8, VERTEX_UINT},
   [4] = {2, 8, VERTEX_SINT},    [5] = {3, 8, VERTEX_SINT},    [6] = {4, 8, VERTEX_SINT},
   [7] = {2, 8, VERTEX_UNORM},   [8] = {3, 8, VERTEX_UNORM},   [9] = {4, 8, VERTEX_UNORM},
   [10] = {2, 8, VERTEX_SNORM},  [11] = {3, 8, VERTEX_SNORM},  [12] = {4, 8, VERTEX_SNORM},
   [13] = {2, 16, VERTEX_UINT},  [14] = {3, 16, VERTEX_UINT},  [15] = {4, 16, VERTEX_UINT},
   [16] = {2, 16, VERTEX_SINT},  [17] = {3, 16, VERTEX_SINT},  [18] = {4, 16, VERTEX_SINT},
   [19] = {2, 16, VERTEX_UNORM}, [20] = {3, 16, VERTEX_UNORM}, [21] = {4, 16, VERTEX_UNORM},
   [22] = {2, 16, VERTEX_SNORM}, [23] = {3, 16, VERTEX_SNORM}, [24] = {4, 16, VERTEX_SNORM},
   [25] = {2, 16, VERTEX_HALF},  [26] = {3, 16, VERTEX_HALF},  [27] = {4, 16, VERTEX_HALF},
   [28] = {1, 32, VERTEX_FLOAT}, [29] = {2, 32, VERTEX_FLOAT}, [30] = {3, 32, VERTEX_FLOAT},
   [31] = {4, 32, VERTEX_FLOAT},
   [32] = {1, 32, VERTEX_SINT},  [33] = {2, 32, VERTEX_SINT},  [34] = {3, 32, VERTEX_SINT},
   [35] = {4, 32, VERTEX_SINT},
   [36] = {1, 32, VERTEX_UINT},  [37] = {2, 32, VERTEX_UINT},  [38] = {3, 32, VERTEX_UINT},
   [39] = {4, 32, VERTEX_UINT},
   [40] = {4, 0, VERTEX_SNORM_1010102},
   [41] = {4, 0, VERTEX_UNORM_1010102},
   [42] = {4, 8, VERTEX_UNORM, true},
   [45] = {1, 8, VERTEX_UINT},   [46] = {1, 8, VERTEX_SINT},
   [47] = {1, 8, VERTEX_UNORM},  [48] = {1, 8, VERTEX_SNORM},
   [49] = {1, 16, VERTEX_UINT},  [50] = {1, 16, VERTEX_SINT},
   [51] = {1, 16, VERTEX_UNORM}, [52] = {1, 16, VERTEX_SNORM},
   [53] = {1, 16, VERTEX_HALF},
   [54] = {3, 0, VERTEX_RG11B10},
   [55] = {3, 0, VERTEX_RGB9E5},
};

static const struct vertex_format *vertex_format(unsigned format)
{
   if (format >= ARRAY_SIZE(vertex_formats) || !vertex_formats[format].kind)
      return NULL;
   return &vertex_formats[format];
}

unsigned stela_metal_vertex_format_bytes(unsigned format)
{
   const struct vertex_format *f = vertex_format(format);
   if (!f)
      return 0;
   return f->bits ? f->lanes * f->bits / 8 : 4;
}

bool stela_metal_vertex_format_integer(unsigned format)
{
   const struct vertex_format *f = vertex_format(format);
   return f && (f->kind == VERTEX_UINT || f->kind == VERTEX_SINT);
}

nir_def *stela_metal_decode_attribute(nir_builder *b, nir_def *words, unsigned format)
{
   const struct vertex_format *f = vertex_format(format);
   assert(f && words->bit_size == 32 &&
          words->num_components == DIV_ROUND_UP(stela_metal_vertex_format_bytes(format), 4));
   const unsigned packed[] = {10, 10, 10, 2};
   const unsigned lane_bits[] = {f->bits, f->bits, f->bits, f->bits};
   const unsigned *bits = f->bits ? lane_bits : packed;
   nir_def *value;
   switch (f->kind) {
   case VERTEX_UINT:
   case VERTEX_HALF:
   case VERTEX_UNORM:
   case VERTEX_UNORM_1010102:
      value = f->bits == 32 ? words : nir_format_unpack_uint(b, words, bits, f->lanes);
      if (f->kind == VERTEX_HALF)
         value = nir_f2f32(b, nir_u2u16(b, value));
      else if (f->kind != VERTEX_UINT)
         value = nir_format_unorm_to_float(b, value, bits);
      break;
   case VERTEX_SINT:
   case VERTEX_SNORM:
   case VERTEX_SNORM_1010102:
      value = f->bits == 32 ? words : nir_format_unpack_sint(b, words, bits, f->lanes);
      if (f->kind != VERTEX_SINT)
         value = nir_format_snorm_to_float(b, value, bits);
      break;
   case VERTEX_FLOAT:
      value = words;
      break;
   case VERTEX_RG11B10:
      value = nir_format_unpack_11f11f10f(b, words);
      break;
   case VERTEX_RGB9E5:
      value = nir_format_unpack_r9g9b9e5(b, words);
      break;
   default:
      UNREACHABLE("a vertex format");
   }
   if (f->bgra)
      value = nir_swizzle(b, value, (unsigned[]){2, 1, 0, 3}, 4);
   bool integer = stela_metal_vertex_format_integer(format);
   nir_def *lanes[4] = {
      integer ? nir_imm_int(b, 0) : nir_imm_float(b, 0.0f),
      integer ? nir_imm_int(b, 0) : nir_imm_float(b, 0.0f),
      integer ? nir_imm_int(b, 0) : nir_imm_float(b, 0.0f),
      integer ? nir_imm_int(b, 1) : nir_imm_float(b, 1.0f),
   };
   for (unsigned i = 0; i < value->num_components; i++)
      lanes[i] = nir_channel(b, value, i);
   return nir_vec(b, lanes, 4);
}

nir_def *stela_metal_fetch_attribute(nir_builder *b, nir_def *base, nir_def *offset, nir_def *bound,
                                     unsigned format)
{
   unsigned bytes = stela_metal_vertex_format_bytes(format);
   if (!bytes)
      return NULL;
   nir_def *words = nir_load_global_constant_bounded(b, DIV_ROUND_UP(bytes, 4), 32, base, offset,
                                                     bound, .align_mul = 4);
   return stela_metal_decode_attribute(b, words, format);
}

/* A 64-bit byte count as a 32-bit one, saturated: offsets past every
 * 32-bit bound stay past it. */
static nir_def *saturate32(nir_builder *b, nir_def *bytes)
{
   return nir_u2u32(b, nir_umin(b, bytes, nir_imm_int64(b, UINT32_MAX)));
}

/* The index at element of the indices at address, which hold length
 * bytes of bytes-wide indices: zero past them. */
static nir_def *index_at(nir_builder *b, nir_def *indices, nir_def *length, nir_def *element,
                         unsigned bytes)
{
   nir_def *offset = saturate32(b, nir_imul_imm(b, nir_u2u64(b, element), bytes));
   nir_def *index = nir_load_global_constant_bounded(b, 1, 8 * bytes, indices, offset,
                                                     saturate32(b, length), .align_mul = bytes);
   return nir_u2u32(b, index);
}

/* A buffer slot of the primary argument table: its address and length. */
static void table_buffer(nir_builder *b, unsigned buffer, nir_def **address, nir_def **length)
{
   nir_def *table = stela_metal_load_table(b, STELA_METAL_TABLE_PRIMARY);
   *address = table_load(b, table, STELA_METAL_TABLE_BUFFER_ADDRESSES + 8u * buffer, 64);
   *length = table_load(b, table, STELA_METAL_TABLE_BUFFER_LENGTHS + 8u * buffer, 64);
}

/* The attribute at location, when the layout provides it as integer says. */
static const struct stela_metal_stage_in_attribute *
provided(const struct stela_metal_stage_in *stage_in, unsigned location, bool integer)
{
   if (location >= AIR_MAX_VERTEX_ATTRIBUTES)
      return NULL;
   const struct stela_metal_stage_in_attribute *attribute = &stage_in->attributes[location];
   if (!stela_metal_vertex_format_bytes(attribute->format) || attribute->buffer >= STELA_METAL_BUFFERS ||
       stela_metal_vertex_format_integer(attribute->format) != integer)
      return NULL;
   return attribute;
}

/* The attribute in the element of its buffer at stride; zero past the
 * buffer, and everywhere unless valid, when valid is not NULL. */
static nir_def *fetch_element(nir_builder *b, const struct stela_metal_stage_in_attribute *attribute,
                              nir_def *element, nir_def *stride, nir_def *valid)
{
   nir_def *base, *length;
   table_buffer(b, attribute->buffer, &base, &length);
   nir_def *offset = nir_iadd_imm(b, nir_imul(b, nir_u2u64(b, element), nir_u2u64(b, stride)),
                                  attribute->offset);
   /* Buffers end on word boundaries, so a format's last word is readable
    * even past its last byte. */
   nir_def *bound = saturate32(b, nir_iand_imm(b, nir_iadd_imm(b, length, 3), ~(int64_t)3));
   if (valid)
      bound = nir_bcsel(b, valid, bound, nir_imm_int(b, 0));
   return stela_metal_fetch_attribute(b, base, saturate32(b, offset), bound, attribute->format);
}

nir_def *stela_metal_fetch_patch_attribute(nir_builder *b, const struct stela_metal_stage_in *stage_in,
                                           const struct stela_metal_tessellation *tessellation,
                                           unsigned location, nir_def *ids, nir_def *point,
                                           bool integer)
{
   const struct stela_metal_stage_in_attribute *attribute = provided(stage_in, location, integer);
   if (!attribute)
      return NULL;
   const struct stela_metal_stage_in_layout *layout = &stage_in->layouts[attribute->buffer];
   nir_def *arguments = load_push(b, 1, 64, STELA_METAL_PUSH_ARGUMENTS);
   nir_def *patch = nir_channel(b, ids, 0), *element;
   switch (layout->step) {
   case STELA_METAL_STEP_CONSTANT:
      element = nir_imm_int(b, 0);
      break;
   case STELA_METAL_STEP_PER_INSTANCE: {
      /* As Vulkan's divisors: the base instance's element, then one per
       * rate instances. */
      if (!layout->rate)
         return NULL;
      nir_def *base = nir_channel(b, ids, 2);
      element = nir_iadd(b, base, nir_udiv_imm(b, nir_isub(b, nir_channel(b, ids, 1), base),
                                               layout->rate));
      break;
   }
   case STELA_METAL_STEP_PER_PATCH:
      if (!layout->rate)
         return NULL;
      element = nir_udiv_imm(b, patch, layout->rate);
      break;
   case STELA_METAL_STEP_PER_PATCH_CONTROL_POINT: {
      if (!point)
         return NULL;
      nir_def *count = load(b, arguments, STELA_METAL_TESSELLATION_CONTROL_POINTS, 32);
      element = nir_iadd(b, nir_imul(b, patch, count), point);
      unsigned bytes = tessellation->control_point_index_bytes;
      if (bytes) {
         nir_def *indices = load(b, arguments, STELA_METAL_TESSELLATION_CONTROL_POINT_INDICES, 64);
         nir_def *length = load(b, arguments, STELA_METAL_TESSELLATION_CONTROL_POINT_INDICES + 8, 64);
         element = index_at(b, indices, length, element, bytes);
      }
      break;
   }
   default:
      return NULL;
   }
   nir_def *stride = layout->stride == STELA_METAL_STRIDE_DYNAMIC ?
      load(b, arguments, STELA_METAL_TESSELLATION_STRIDES + 4u * attribute->buffer, 32) :
      nir_imm_int(b, (int)layout->stride);
   return fetch_element(b, attribute, element, stride, NULL);
}

nir_def *stela_metal_fetch_stage_in(nir_builder *b, const struct stela_metal_stage_in *stage_in,
                                    unsigned location, nir_def *position, bool integer)
{
   const struct stela_metal_stage_in_attribute *attribute = provided(stage_in, location, integer);
   if (!attribute)
      return NULL;
   const struct stela_metal_stage_in_layout *layout = &stage_in->layouts[attribute->buffer];
   nir_def *region = load_push(b, 1, 64, STELA_METAL_PUSH_ARGUMENTS);
   nir_def *inside = nir_imm_true(b), *origin[3];
   for (unsigned axis = 0; axis < 3; axis++) {
      origin[axis] = load(b, region, STELA_METAL_STAGE_IN_ORIGIN + 4 * axis, 32);
      nir_def *size = load(b, region, STELA_METAL_STAGE_IN_SIZE + 4 * axis, 32);
      inside = nir_iand(b, inside, nir_ult(b, nir_channel(b, position, axis), size));
   }
   nir_def *element;
   switch (layout->step) {
   case STELA_METAL_STEP_CONSTANT:
      element = nir_imm_int(b, 0);
      break;
   case STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X:
   case STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y:
   case STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X_INDEXED:
   case STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y_INDEXED: {
      bool indexed = layout->step >= STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X_INDEXED;
      unsigned axis = layout->step == STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y ||
                      layout->step == STELA_METAL_STEP_THREAD_POSITION_IN_GRID_Y_INDEXED;
      if (!layout->rate ||
          (indexed && ((stage_in->index_bytes != 2 && stage_in->index_bytes != 4) ||
                       stage_in->index_buffer >= STELA_METAL_BUFFERS)))
         return NULL;
      element = nir_iadd(b, origin[axis],
                         nir_udiv_imm(b, nir_channel(b, position, axis), layout->rate));
      if (indexed) {
         nir_def *indices, *length;
         table_buffer(b, stage_in->index_buffer, &indices, &length);
         element = index_at(b, indices, length, element, stage_in->index_bytes);
      }
      break;
   }
   default:
      return NULL;
   }
   nir_def *stride = layout->stride == STELA_METAL_STRIDE_DYNAMIC ?
      load(b, region, STELA_METAL_DISPATCH_STRIDES + 4u * attribute->buffer, 32) :
      nir_imm_int(b, (int)layout->stride);
   return fetch_element(b, attribute, element, stride, inside);
}

nir_def *stela_metal_tessellation_factor(nir_builder *b, nir_def *factor, nir_def *scale,
                                         const struct stela_metal_tessellation *tessellation)
{
   unsigned max = tessellation->partition == STELA_METAL_PARTITION_FRACTIONAL_ODD
                     ? tessellation->max_factor - 1
                     : tessellation->max_factor;
   nir_def *scaled = nir_fmul(b, factor, scale);
   nir_def *clamped = nir_fmin(b, scaled, nir_imm_float(b, (float)max));
   if (tessellation->partition == STELA_METAL_PARTITION_POW2) {
      /* The next power of two in integers, which transcendental
       * approximations could round past. */
      nir_def *integer = nir_f2u32(b, nir_fceil(b, clamped));
      nir_def *bits = nir_iadd_imm(b, nir_ufind_msb(b, nir_iadd_imm(b, integer, -1)), 1);
      clamped = nir_fmin(b, nir_u2f32(b, nir_ishl(b, nir_imm_int(b, 1), bits)),
                         nir_imm_float(b, (float)max));
   }
   return nir_bcsel(b, nir_fgt_imm(b, scaled, 0.0), clamped, scaled);
}

static nir_variable *patch_output(nir_shader *shader, const struct glsl_type *type,
                                  unsigned location, const char *name)
{
   nir_variable *var = nir_variable_create(shader, nir_var_shader_out, type, name);
   var->data.location = location;
   var->data.patch = true;
   var->data.compact = glsl_type_is_array(type);
   return var;
}

nir_shader *stela_metal_tessellation_control(const nir_shader_compiler_options *options,
                                             const struct stela_metal_tessellation *tessellation)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_TESS_CTRL, options,
                                                  "stela_metal_tessellation_control");
   b.shader->info.tess.tcs_vertices_out = 1;
   b.shader->info.tess._primitive_mode =
      tessellation->quad ? TESS_PRIMITIVE_QUADS : TESS_PRIMITIVE_TRIANGLES;
   switch (tessellation->partition) {
   case STELA_METAL_PARTITION_POW2:
   case STELA_METAL_PARTITION_INTEGER:
      b.shader->info.tess.spacing = TESS_SPACING_EQUAL;
      break;
   case STELA_METAL_PARTITION_FRACTIONAL_ODD:
      b.shader->info.tess.spacing = TESS_SPACING_FRACTIONAL_ODD;
      break;
   case STELA_METAL_PARTITION_FRACTIONAL_EVEN:
      b.shader->info.tess.spacing = TESS_SPACING_FRACTIONAL_EVEN;
      break;
   }
   /* The APIs orient the domain oppositely: Metal's clockwise is Vulkan's
    * VertexOrderCcw, as MoltenVK and DXVK map it. */
   b.shader->info.tess.ccw = tessellation->winding == STELA_METAL_WINDING_CLOCKWISE;

   nir_variable *input = nir_variable_create(
      b.shader, nir_var_shader_in, glsl_array_type(glsl_uvec_type(3), 32, 0), "patch");
   input->data.location = VARYING_SLOT_VAR0;
   input->data.interpolation = INTERP_MODE_FLAT;
   nir_variable *outputs[2] = {
      patch_output(b.shader, glsl_array_type(glsl_float_type(), 4, 0),
                   VARYING_SLOT_TESS_LEVEL_OUTER, "outer"),
      patch_output(b.shader, glsl_array_type(glsl_float_type(), 2, 0),
                   VARYING_SLOT_TESS_LEVEL_INNER, "inner"),
   };
   nir_variable *patch_ids = patch_output(b.shader, glsl_uvec_type(3), VARYING_SLOT_PATCH0,
                                          "patch_ids");

   nir_def *vertex =
      nir_load_deref(&b, nir_build_deref_array_imm(&b, nir_build_deref_var(&b, input), 0));
   nir_def *number = nir_channel(&b, vertex, 0);
   nir_def *instance = nir_channel(&b, vertex, 1);
   nir_def *arguments = load_push(&b, 1, 64, STELA_METAL_PUSH_ARGUMENTS);

   /* The patch ID: the patch number, or its entry in the patch index buffer. */
   nir_def *indices = load(&b, arguments, STELA_METAL_TESSELLATION_PATCH_INDICES, 64);
   nir_def *indices_bytes = load(&b, arguments, STELA_METAL_TESSELLATION_PATCH_INDICES + 8, 64);
   nir_def *index_offset = nir_imul_imm(&b, nir_u2u64(&b, number), 4);
   nir_def *indexed = nir_ine_imm(&b, indices, 0);
   nir_def *index_in_bounds = nir_uge(&b, indices_bytes, nir_iadd_imm(&b, index_offset, 4));
   nir_variable *patch = nir_local_variable_create(b.impl, glsl_uint_type(), "patch");
   nir_store_var(&b, patch, number, 1);
   nir_push_if(&b, nir_iand(&b, indexed, index_in_bounds));
   nir_store_var(&b, patch, load(&b, nir_iadd(&b, indices, index_offset), 0, 32), 1);
   nir_pop_if(&b, NULL);
   nir_def *id = nir_load_var(&b, patch);

   /* The patch's factor record. */
   unsigned edges = tessellation->quad ? 4 : 3, insides = tessellation->quad ? 2 : 1;
   unsigned record = 2 * (edges + insides);
   nir_def *offset = nir_imm_int64(&b, 0);
   if (tessellation->step == STELA_METAL_FACTOR_STEP_PER_PATCH ||
       tessellation->step == STELA_METAL_FACTOR_STEP_PER_PATCH_AND_PER_INSTANCE)
      offset = nir_iadd(&b, offset, nir_imul_imm(&b, nir_u2u64(&b, id), record));
   if (tessellation->step == STELA_METAL_FACTOR_STEP_PER_INSTANCE ||
       tessellation->step == STELA_METAL_FACTOR_STEP_PER_PATCH_AND_PER_INSTANCE) {
      nir_def *stride = load(&b, arguments, STELA_METAL_TESSELLATION_INSTANCE_STRIDE, 32);
      offset = nir_iadd(&b, offset, nir_imul(&b, nir_u2u64(&b, instance), nir_u2u64(&b, stride)));
   }
   nir_def *factors = load(&b, arguments, STELA_METAL_TESSELLATION_FACTORS, 64);
   nir_def *factors_bytes = load(&b, arguments, STELA_METAL_TESSELLATION_FACTORS + 8, 64);
   nir_def *in_bounds = nir_iand(&b, nir_ior(&b, nir_inot(&b, indexed), index_in_bounds),
                                 nir_uge(&b, factors_bytes, nir_iadd_imm(&b, offset, record)));

   /* Zero levels, which cull the patch, unless the record is in bounds. */
   nir_variable *levels[2] = {
      nir_local_variable_create(b.impl, glsl_vec4_type(), "outer"),
      nir_local_variable_create(b.impl, glsl_vec_type(2), "inner"),
   };
   nir_store_var(&b, levels[0], nir_imm_zero(&b, 4, 32), 0xf);
   nir_store_var(&b, levels[1], nir_imm_zero(&b, 2, 32), 0x3);
   nir_push_if(&b, in_bounds);
   {
      nir_def *scale = tessellation->scales ? load(&b, arguments, STELA_METAL_TESSELLATION_FACTOR_SCALE, 32)
                                            : nir_imm_float(&b, 1.0f);
      nir_def *address = nir_iadd(&b, factors, offset);
      nir_def *values[6];
      for (unsigned i = 0; i < edges + insides; i++)
         values[i] = stela_metal_tessellation_factor(
            &b, nir_f2f32(&b, load(&b, address, 2 * i, 16)), scale, tessellation);
      nir_def *zero = nir_imm_float(&b, 0.0f);
      nir_def *outer[4] = {values[0], values[1], values[2], edges == 4 ? values[3] : zero};
      nir_def *inner[2] = {values[edges], insides == 2 ? values[edges + 1] : zero};
      nir_store_var(&b, levels[0], nir_vec(&b, outer, 4), 0xf);
      nir_store_var(&b, levels[1], nir_vec(&b, inner, 2), 0x3);
   }
   nir_pop_if(&b, NULL);

   for (unsigned level = 0; level < 2; level++) {
      nir_def *value = nir_load_var(&b, levels[level]);
      nir_deref_instr *output = nir_build_deref_var(&b, outputs[level]);
      for (unsigned i = 0; i < glsl_get_length(outputs[level]->type); i++)
         nir_store_deref(&b, nir_build_deref_array_imm(&b, output, i), nir_channel(&b, value, i),
                         1);
   }
   nir_store_var(&b, patch_ids, nir_vec3(&b, id, instance, nir_channel(&b, vertex, 2)), 0x7);
   return validated(&b);
}

/* An extended-range code's value: (code - 384) / 510, through the sRGB curve
 * mirrored below zero for the sRGB encodings. */
static nir_def *xr_value(nir_builder *b, nir_def *code, bool srgb)
{
   nir_def *v = nir_fmul_imm(b, nir_fadd_imm(b, nir_u2f32(b, code), -384.0), 1.0 / 510.0);
   if (!srgb)
      return v;
   nir_def *m = nir_fabs(b, v);
   nir_def *curve = nir_fpow(b, nir_fmul_imm(b, nir_fadd_imm(b, m, 0.055), 1.0 / 1.055),
                             nir_imm_float(b, 2.4f));
   nir_def *linear = nir_bcsel(b, nir_fge(b, nir_imm_float(b, 0.04045f), m),
                               nir_fmul_imm(b, m, 1.0 / 12.92), curve);
   return nir_bcsel(b, nir_flt(b, v, nir_imm_float(b, 0.0f)), nir_fneg(b, linear), linear);
}

/* The nearest code of a value, ties to even, in [low, high]. */
static nir_def *xr_code(nir_builder *b, nir_def *v, bool srgb, float low, float high)
{
   if (srgb) {
      nir_def *m = nir_fabs(b, v);
      nir_def *curve = nir_fadd_imm(
         b, nir_fmul_imm(b, nir_fpow(b, m, nir_imm_float(b, 1.0f / 2.4f)), 1.055), -0.055);
      nir_def *encoded = nir_bcsel(b, nir_fge(b, nir_imm_float(b, 0.0031308f), m),
                                   nir_fmul_imm(b, m, 12.92), curve);
      v = nir_bcsel(b, nir_flt(b, v, nir_imm_float(b, 0.0f)), nir_fneg(b, encoded), encoded);
   }
   nir_def *code = nir_fround_even(b, nir_fadd_imm(b, nir_fmul_imm(b, v, 510.0), 384.0));
   code = nir_fmin(b, nir_fmax(b, code, nir_imm_float(b, low)), nir_imm_float(b, high));
   return nir_f2u32(b, code);
}

/* The texel kernels' common part: thread's image coordinate, its byte offset
 * in the buffer for texels of texel_bytes, and its texture's raw view. */
struct texels {
   nir_def *arguments, *buffer, *encoding, *coord, *offset;
   /* The alpha plane's texel of a two-plane encoding, or zero. */
   nir_def *alpha;
   /* STELA_METAL_TEXELS_MIRROR_*, and the mirror's coordinate. */
   nir_def *mirror, *mirror_coord;
   /* The thread's index. */
   nir_def *thread;
   nir_deref_instr *image;
};

static nir_builder texels(const nir_shader_compiler_options *options, const char *name,
                          struct texels *t)
{
   nir_def *thread;
   nir_builder b = kernel(options, name, STELA_METAL_TEXELS_COUNT, &t->arguments, &thread);
   t->thread = thread;
   nir_def *arguments = t->arguments;
   nir_def *width = load(&b, arguments, STELA_METAL_TEXELS_WIDTH, 32);
   nir_def *height = load(&b, arguments, STELA_METAL_TEXELS_HEIGHT, 32);
   nir_def *per_image = nir_imul(&b, width, height);
   nir_def *z = nir_udiv(&b, thread, per_image);
   nir_def *rest = nir_isub(&b, thread, nir_imul(&b, z, per_image));
   nir_def *y = nir_udiv(&b, rest, width);
   nir_def *x = nir_isub(&b, rest, nir_imul(&b, y, width));
   nir_def *origin[3];
   for (unsigned i = 0; i < 3; i++)
      origin[i] = load(&b, arguments, STELA_METAL_TEXELS_ORIGIN + 4 * i, 32);
   t->coord = nir_vec4(&b, nir_iadd(&b, x, origin[0]), nir_iadd(&b, y, origin[1]),
                       nir_iadd(&b, z, origin[2]), nir_imm_int(&b, 0));
   t->encoding = load(&b, arguments, STELA_METAL_TEXELS_ENCODING, 32);
   nir_def *wide = nir_ior(&b, nir_ieq_imm(&b, t->encoding, STELA_METAL_TEXELS_XR10X4),
                           nir_ieq_imm(&b, t->encoding, STELA_METAL_TEXELS_XR10X4_SRGB));
   nir_def *narrow = nir_ior(&b, nir_ieq_imm(&b, t->encoding, STELA_METAL_TEXELS_ROTATED16),
                             nir_ieq_imm(&b, t->encoding, STELA_METAL_TEXELS_PADDED8X2));
   nir_def *texel_bytes = nir_bcsel(&b, wide, nir_imm_int(&b, 8),
                                    nir_bcsel(&b, narrow, nir_imm_int(&b, 2), nir_imm_int(&b, 4)));
   nir_def *offset = nir_iadd(
      &b, nir_imul(&b, z, load(&b, arguments, STELA_METAL_TEXELS_IMAGE_BYTES, 32)),
      nir_iadd(&b, nir_imul(&b, y, load(&b, arguments, STELA_METAL_TEXELS_ROW, 32)),
               nir_imul(&b, x, texel_bytes)));
   t->buffer = load(&b, arguments, STELA_METAL_TEXELS_BUFFER, 64);
   t->offset = nir_u2u64(&b, offset);
   nir_def *alpha = load(&b, arguments, STELA_METAL_TEXELS_ALPHA, 64);
   nir_def *alpha_offset = nir_iadd(
      &b, nir_imul(&b, y, load(&b, arguments, STELA_METAL_TEXELS_ALPHA_ROW, 32)), x);
   t->alpha = nir_bcsel(&b, nir_ieq_imm(&b, alpha, 0), alpha,
                        nir_iadd(&b, alpha, nir_u2u64(&b, alpha_offset)));
   t->mirror = load(&b, arguments, STELA_METAL_TEXELS_MIRROR, 32);
   t->mirror_coord = nir_vector_insert_imm(&b, t->coord,
                                           nir_iadd_imm(&b, nir_channel(&b, t->coord, 2), 1), 2);
   const struct glsl_type *type = glsl_image_type(GLSL_SAMPLER_DIM_2D, true, GLSL_TYPE_UINT);
   t->image = stela_metal_bind_texture_id(&b, load(&b, arguments, STELA_METAL_TEXELS_IMAGE, 64),
                                          type, false, NULL, NULL);
   return b;
}

/* The nearest halves of x and y, ties to even, x in the low bits. NIR's
 * pack_half_2x16_split leaves its rounding open, and backends with a
 * truncating pack take that (nir_opt_algebraic), so each converts on its
 * own. */
static nir_def *nearest_halves(nir_builder *b, nir_def *x, nir_def *y)
{
   return nir_pack_32_2x16_split(b, nir_f2f16_rtne(b, x), nir_f2f16_rtne(b, y));
}

/* Half floats of red, green, blue and alpha, two to a word. */
static nir_def *halves(nir_builder *b, nir_def *r, nir_def *g, nir_def *bl, nir_def *a)
{
   return nir_vec4(b, nearest_halves(b, r, g), nearest_halves(b, bl, a), nir_imm_int(b, 0),
                   nir_imm_int(b, 0));
}

/* The stored texel of a BGR10_XR word or a BGRA10_XR pair of words. */
static nir_def *store_xr(nir_builder *b, nir_def *lo, nir_def *hi, bool alpha, bool srgb)
{
   if (!alpha) {
      nir_def *blue = nir_iand_imm(b, lo, 0x3ff);
      nir_def *green = nir_iand_imm(b, nir_ushr_imm(b, lo, 10), 0x3ff);
      nir_def *red = nir_iand_imm(b, nir_ushr_imm(b, lo, 20), 0x3ff);
      return halves(b, xr_value(b, red, srgb), xr_value(b, green, srgb), xr_value(b, blue, srgb),
                    nir_imm_float(b, 1.0f));
   }
   /* NAK takes no ubfe; each code is the top ten bits of a half word. */
   nir_def *blue = nir_iand_imm(b, nir_ushr_imm(b, lo, 6), 0x3ff);
   nir_def *green = nir_ushr_imm(b, lo, 22);
   nir_def *red = nir_iand_imm(b, nir_ushr_imm(b, hi, 6), 0x3ff);
   nir_def *code = nir_ushr_imm(b, hi, 22);
   nir_def *a = nir_fsat(b, xr_value(b, code, false));
   return halves(b, xr_value(b, red, srgb), xr_value(b, green, srgb), xr_value(b, blue, srgb), a);
}

/* Writes a two-plane texel's codes word and alpha byte to its mirror. */
static void store_mirror(nir_builder *b, const struct texels *t, nir_def *word, nir_def *alpha)
{
   nir_image_deref_store(b, &t->image->def, t->mirror_coord, nir_undef(b, 1, 32),
                         nir_vec4(b, word, alpha, nir_imm_int(b, 0), nir_imm_int(b, 0)),
                         nir_imm_int(b, 0), .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true,
                         .format = PIPE_FORMAT_NONE, .src_type = nir_type_uint32);
}

nir_shader *stela_metal_store_texels_kernel(const nir_shader_compiler_options *options)
{
   struct texels t;
   nir_builder b = texels(options, "stela_metal_store_texels", &t);
   nir_def *address = nir_iadd(&b, t.buffer, t.offset);
   nir_def *narrow = nir_ior(&b, nir_ieq_imm(&b, t.encoding, STELA_METAL_TEXELS_ROTATED16),
                             nir_ieq_imm(&b, t.encoding, STELA_METAL_TEXELS_PADDED8X2));
   nir_push_if(&b, narrow);
   {
      nir_def *word = nir_u2u32(&b, nir_load_global(&b, 1, 16, address, .align_mul = 2));
      /* Rotated right by a bit, or padded with blue zero and alpha one. */
      nir_def *rotated = nir_bcsel(
         &b, nir_ieq_imm(&b, t.encoding, STELA_METAL_TEXELS_ROTATED16),
         nir_ior(&b, nir_ushr_imm(&b, word, 1), nir_ishl_imm(&b, nir_iand_imm(&b, word, 1), 15)),
         nir_ior_imm(&b, word, 0xffu << 24));
      nir_image_deref_store(&b, &t.image->def, t.coord, nir_undef(&b, 1, 32),
                            nir_vec4(&b, rotated, nir_imm_int(&b, 0), nir_imm_int(&b, 0),
                                     nir_imm_int(&b, 1)),
                            nir_imm_int(&b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                            .image_array = true, .format = PIPE_FORMAT_NONE,
                            .src_type = nir_type_uint32);
   }
   nir_push_else(&b, NULL);
   nir_def *lo = nir_load_global(&b, 1, 32, address, .align_mul = 4);
   for (unsigned e = STELA_METAL_TEXELS_XR10_PLANES; e <= STELA_METAL_TEXELS_XR10_PLANES_SRGB; e++) {
      bool srgb = e == STELA_METAL_TEXELS_XR10_PLANES_SRGB;
      nir_push_if(&b, nir_ieq_imm(&b, t.encoding, e));
      {
         /* Alpha from its plane's byte, or kept from the image's texel. */
         nir_def *has_alpha = nir_ine_imm(&b, t.alpha, 0);
         nir_def *none = nir_imm_int(&b, 0);
         nir_push_if(&b, has_alpha);
         nir_def *byte = nir_u2u32(&b, nir_load_global(&b, 1, 8, t.alpha, .align_mul = 1));
         nir_pop_if(&b, NULL);
         byte = nir_if_phi(&b, byte, none);
         nir_def *kept = nir_image_deref_load(
            &b, 4, 32, &t.image->def, t.coord, nir_undef(&b, 1, 32), nir_imm_int(&b, 0),
            .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true, .format = PIPE_FORMAT_NONE,
            .dest_type = nir_type_uint32);
         nir_def *kept_alpha = nir_f2f32(&b, nir_unpack_32_2x16_split_y(&b, nir_channel(&b, kept, 1)));
         nir_def *a = nir_bcsel(&b, has_alpha, nir_fmul_imm(&b, nir_u2f32(&b, byte), 1.0 / 255.0),
                                kept_alpha);
         nir_def *blue = nir_iand_imm(&b, lo, 0x3ff);
         nir_def *green = nir_iand_imm(&b, nir_ushr_imm(&b, lo, 10), 0x3ff);
         nir_def *red = nir_iand_imm(&b, nir_ushr_imm(&b, lo, 20), 0x3ff);
         nir_image_deref_store(&b, &t.image->def, t.coord, nir_undef(&b, 1, 32),
                               halves(&b, xr_value(&b, red, srgb), xr_value(&b, green, srgb),
                                      xr_value(&b, blue, srgb), a),
                               nir_imm_int(&b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                               .image_array = true, .format = PIPE_FORMAT_NONE,
                               .src_type = nir_type_uint32);
         /* The mirror holds what the planes do. */
         nir_push_if(&b, nir_ine_imm(&b, t.mirror, STELA_METAL_TEXELS_MIRROR_NONE));
         store_mirror(&b, &t, lo, byte);
         nir_pop_if(&b, NULL);
      }
      nir_pop_if(&b, NULL);
   }
   for (unsigned e = STELA_METAL_TEXELS_XR10; e <= STELA_METAL_TEXELS_XR10X4_SRGB; e++) {
      bool alpha = e >= STELA_METAL_TEXELS_XR10X4;
      bool srgb = e == STELA_METAL_TEXELS_XR10_SRGB || e == STELA_METAL_TEXELS_XR10X4_SRGB;
      nir_push_if(&b, nir_ieq_imm(&b, t.encoding, e));
      nir_def *hi = alpha ? nir_load_global(&b, 1, 32, nir_iadd_imm(&b, address, 4), .align_mul = 4)
                          : NULL;
      nir_image_deref_store(&b, &t.image->def, t.coord, nir_undef(&b, 1, 32),
                            store_xr(&b, lo, hi, alpha, srgb), nir_imm_int(&b, 0),
                            .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true,
                            .format = PIPE_FORMAT_NONE, .src_type = nir_type_uint32);
      nir_pop_if(&b, NULL);
   }
   nir_pop_if(&b, NULL);
   return finish(&b);
}

_Static_assert(STELA_METAL_DIRTY_TILE_SHIFT == STELA_AIR_DIRTY_TILE_SHIFT &&
               STELA_METAL_DIRTY_LAYER == STELA_AIR_DIRTY_LAYER &&
               STELA_METAL_DIRTY_TILE == 1u << STELA_METAL_DIRTY_TILE_SHIFT,
               "the dirty tiles the compiler marks are the ones the load kernel reads");

/* Encodes the working image's texel at coord into an IOSurface's planes, at
 * address and alpha (zero for none), where its codes or alpha differ from
 * the mirror's when the mirror is compared, and writes the mirror with it. */
static void encode_planes_texel(nir_builder *b, const struct texels *t, nir_def *coord,
                                nir_def *address, nir_def *alpha, bool srgb)
{
   nir_def *stored = nir_image_deref_load(b, 4, 32, &t->image->def, coord, nir_undef(b, 1, 32),
                                          nir_imm_int(b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                                          .image_array = true, .format = PIPE_FORMAT_NONE,
                                          .dest_type = nir_type_uint32);
   nir_def *rg = nir_channel(b, stored, 0), *ba = nir_channel(b, stored, 1);
   nir_def *r = nir_f2f32(b, nir_unpack_32_2x16_split_x(b, rg));
   nir_def *g = nir_f2f32(b, nir_unpack_32_2x16_split_y(b, rg));
   nir_def *bl = nir_f2f32(b, nir_unpack_32_2x16_split_x(b, ba));
   nir_def *a = nir_f2f32(b, nir_unpack_32_2x16_split_y(b, ba));
   nir_def *word = nir_ior(b, nir_ior(b, xr_code(b, bl, srgb, 0, 1023),
                                      nir_ishl_imm(b, xr_code(b, g, srgb, 0, 1023), 10)),
                           nir_ishl_imm(b, xr_code(b, r, srgb, 0, 1023), 20));
   nir_def *steps = nir_f2u32(b, nir_fround_even(b, nir_fmul_imm(b, nir_fsat(b, a), 255.0)));
   nir_def *alpha_byte = nir_bcsel(b, nir_ine_imm(b, alpha, 0), steps, nir_imm_int(b, 0));
   nir_def *mirror_coord = nir_vector_insert_imm(b, coord,
                                                 nir_iadd_imm(b, nir_channel(b, coord, 2), 1), 2);
   nir_def *changed = nir_imm_true(b);
   nir_push_if(b, nir_ieq_imm(b, t->mirror, STELA_METAL_TEXELS_MIRROR_COMPARE));
   nir_def *mirrored = nir_image_deref_load(
      b, 4, 32, &t->image->def, mirror_coord, nir_undef(b, 1, 32), nir_imm_int(b, 0),
      .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true, .format = PIPE_FORMAT_NONE,
      .dest_type = nir_type_uint32);
   nir_def *differs = nir_ior(b, nir_ine(b, nir_channel(b, mirrored, 0), word),
                              nir_ine(b, nir_channel(b, mirrored, 1), alpha_byte));
   nir_pop_if(b, NULL);
   differs = nir_if_phi(b, differs, changed);
   nir_push_if(b, differs);
   {
      nir_store_global(b, word, address, .align_mul = 4);
      nir_push_if(b, nir_ine_imm(b, alpha, 0));
      nir_store_global(b, nir_u2u8(b, steps), alpha, .align_mul = 1);
      nir_pop_if(b, NULL);
      nir_push_if(b, nir_ine_imm(b, t->mirror, STELA_METAL_TEXELS_MIRROR_NONE));
      nir_image_deref_store(b, &t->image->def, mirror_coord, nir_undef(b, 1, 32),
                            nir_vec4(b, word, alpha_byte, nir_imm_int(b, 0), nir_imm_int(b, 0)),
                            nir_imm_int(b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                            .image_array = true, .format = PIPE_FORMAT_NONE,
                            .src_type = nir_type_uint32);
      nir_pop_if(b, NULL);
   }
   nir_pop_if(b, NULL);
}

/* A load given the pass's stamp: thread n converts column n % 64 of tile
 * n / 64 of the region, row by row, when the dirty layer holds the stamp
 * at the tile: a workgroup is a tile, so a clean tile's workgroup only
 * reads that texel. */
static void encode_dirty_tiles(nir_builder *b, const struct texels *t, nir_def *stamp)
{
   nir_def *arguments = t->arguments;
   nir_def *width = load(b, arguments, STELA_METAL_TEXELS_WIDTH, 32);
   nir_def *height = load(b, arguments, STELA_METAL_TEXELS_HEIGHT, 32);
   nir_def *row_bytes = load(b, arguments, STELA_METAL_TEXELS_ROW, 32);
   nir_def *alpha_row = load(b, arguments, STELA_METAL_TEXELS_ALPHA_ROW, 32);
   nir_def *alpha = load(b, arguments, STELA_METAL_TEXELS_ALPHA, 64);
   nir_def *origin[3];
   for (unsigned i = 0; i < 3; i++)
      origin[i] = load(b, arguments, STELA_METAL_TEXELS_ORIGIN + 4 * i, 32);
   nir_def *tiles_x = nir_ushr_imm(b, nir_iadd_imm(b, width, STELA_METAL_DIRTY_TILE - 1),
                                   STELA_METAL_DIRTY_TILE_SHIFT);
   nir_def *tile = nir_ushr_imm(b, t->thread, 6);
   nir_def *lane = nir_iand_imm(b, t->thread, 63);
   nir_def *ty = nir_udiv(b, tile, tiles_x);
   nir_def *tx = nir_isub(b, tile, nir_imul(b, ty, tiles_x));
   /* The tiles are the image's, from the region's origin. */
   nir_def *at = nir_vec4(b, nir_iadd(b, nir_ishr_imm(b, origin[0], STELA_METAL_DIRTY_TILE_SHIFT), tx),
                          nir_iadd(b, nir_ishr_imm(b, origin[1], STELA_METAL_DIRTY_TILE_SHIFT), ty),
                          nir_iadd_imm(b, origin[2], STELA_METAL_DIRTY_LAYER), nir_imm_int(b, 0));
   nir_def *mark = nir_channel(b, nir_image_deref_load(b, 4, 32, &t->image->def, at,
                                                        nir_undef(b, 1, 32), nir_imm_int(b, 0),
                                                        .image_dim = GLSL_SAMPLER_DIM_2D,
                                                        .image_array = true,
                                                        .format = PIPE_FORMAT_NONE,
                                                        .dest_type = nir_type_uint32), 0);
   nir_def *x = nir_iadd(b, nir_ishl_imm(b, tx, STELA_METAL_DIRTY_TILE_SHIFT), lane);
   nir_push_if(b, nir_iand(b, nir_ieq(b, mark, stamp), nir_ult(b, x, width)));
   for (unsigned e = STELA_METAL_TEXELS_XR10_PLANES; e <= STELA_METAL_TEXELS_XR10_PLANES_SRGB; e++) {
      nir_push_if(b, nir_ieq_imm(b, t->encoding, e));
      nir_variable *row = nir_local_variable_create(b->impl, glsl_uint_type(), "row");
      nir_store_var(b, row, nir_imm_int(b, 0), 1);
      nir_push_loop(b);
      {
         nir_def *r = nir_load_var(b, row);
         nir_def *y = nir_iadd(b, nir_ishl_imm(b, ty, STELA_METAL_DIRTY_TILE_SHIFT), r);
         nir_break_if(b, nir_ior(b, nir_uge_imm(b, r, STELA_METAL_DIRTY_TILE), nir_uge(b, y, height)));
         nir_def *coord = nir_vec4(b, nir_iadd(b, origin[0], x), nir_iadd(b, origin[1], y),
                                   origin[2], nir_imm_int(b, 0));
         nir_def *address = nir_iadd(b, t->buffer,
                                     nir_u2u64(b, nir_iadd(b, nir_imul(b, y, row_bytes),
                                                           nir_ishl_imm(b, x, 2))));
         nir_def *alpha_at = nir_bcsel(
            b, nir_ieq_imm(b, alpha, 0), alpha,
            nir_iadd(b, alpha, nir_u2u64(b, nir_iadd(b, nir_imul(b, y, alpha_row), x))));
         encode_planes_texel(b, t, coord, address, alpha_at,
                             e == STELA_METAL_TEXELS_XR10_PLANES_SRGB);
         nir_store_var(b, row, nir_iadd_imm(b, r, 1), 1);
      }
      nir_pop_loop(b, NULL);
      nir_pop_if(b, NULL);
   }
   nir_pop_if(b, NULL);
}

nir_shader *stela_metal_load_texels_kernel(const nir_shader_compiler_options *options)
{
   struct texels t;
   nir_builder b = texels(options, "stela_metal_load_texels", &t);
   nir_def *stamp = load(&b, t.arguments, STELA_METAL_TEXELS_STAMP, 32);
   nir_push_if(&b, nir_ine_imm(&b, stamp, 0));
   encode_dirty_tiles(&b, &t, stamp);
   nir_push_else(&b, NULL);
   nir_def *address = nir_iadd(&b, t.buffer, t.offset);
   nir_def *stored = nir_image_deref_load(&b, 4, 32, &t.image->def, t.coord, nir_undef(&b, 1, 32),
                                          nir_imm_int(&b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                                          .image_array = true, .format = PIPE_FORMAT_NONE,
                                          .dest_type = nir_type_uint32);
   nir_def *rg = nir_channel(&b, stored, 0), *ba = nir_channel(&b, stored, 1);
   nir_push_if(&b, nir_ieq_imm(&b, t.encoding, STELA_METAL_TEXELS_ROTATED16));
   {
      /* Bit 15 returns to bit 0. */
      nir_def *word = nir_iand_imm(&b, rg, 0xffff);
      nir_def *metal = nir_ior(&b, nir_iand_imm(&b, nir_ishl_imm(&b, word, 1), 0xffff),
                               nir_ushr_imm(&b, word, 15));
      nir_store_global(&b, nir_u2u16(&b, metal), address, .align_mul = 2);
   }
   nir_pop_if(&b, NULL);
   nir_push_if(&b, nir_ieq_imm(&b, t.encoding, STELA_METAL_TEXELS_PADDED8X2));
   /* Red and green, without the padding. */
   nir_store_global(&b, nir_u2u16(&b, rg), address, .align_mul = 2);
   nir_pop_if(&b, NULL);
   /* Each half, widened: NAK has no vector unpack_32_2x16, which
    * unpack_half_2x16 scalarizes to. */
   nir_def *r = nir_f2f32(&b, nir_unpack_32_2x16_split_x(&b, rg));
   nir_def *g = nir_f2f32(&b, nir_unpack_32_2x16_split_y(&b, rg));
   nir_def *bl = nir_f2f32(&b, nir_unpack_32_2x16_split_x(&b, ba));
   nir_def *a = nir_f2f32(&b, nir_unpack_32_2x16_split_y(&b, ba));
   for (unsigned e = STELA_METAL_TEXELS_XR10; e <= STELA_METAL_TEXELS_XR10X4_SRGB; e++) {
      bool alpha = e >= STELA_METAL_TEXELS_XR10X4;
      bool srgb = e == STELA_METAL_TEXELS_XR10_SRGB || e == STELA_METAL_TEXELS_XR10X4_SRGB;
      nir_push_if(&b, nir_ieq_imm(&b, t.encoding, e));
      nir_def *codes[3] = {xr_code(&b, bl, srgb, 0, 1023), xr_code(&b, g, srgb, 0, 1023),
                           xr_code(&b, r, srgb, 0, 1023)};
      if (!alpha) {
         /* Blue, green and red from bit 0; the top two bits are ones. */
         nir_def *word = nir_ior(&b, nir_ior(&b, codes[0], nir_ishl_imm(&b, codes[1], 10)),
                                 nir_ior_imm(&b, nir_ishl_imm(&b, codes[2], 20), 3u << 30));
         nir_store_global(&b, word, address, .align_mul = 4);
      } else {
         nir_def *alpha_code = xr_code(&b, a, false, 384, 894);
         nir_def *lo = nir_ior(&b, nir_ishl_imm(&b, codes[0], 6), nir_ishl_imm(&b, codes[1], 22));
         nir_def *hi = nir_ior(&b, nir_ishl_imm(&b, codes[2], 6), nir_ishl_imm(&b, alpha_code, 22));
         nir_store_global(&b, nir_vec2(&b, lo, hi), address, .align_mul = 4);
      }
      nir_pop_if(&b, NULL);
   }
   for (unsigned e = STELA_METAL_TEXELS_XR10_PLANES; e <= STELA_METAL_TEXELS_XR10_PLANES_SRGB; e++) {
      bool srgb = e == STELA_METAL_TEXELS_XR10_PLANES_SRGB;
      nir_push_if(&b, nir_ieq_imm(&b, t.encoding, e));
      nir_def *codes[3] = {xr_code(&b, bl, srgb, 0, 1023), xr_code(&b, g, srgb, 0, 1023),
                           xr_code(&b, r, srgb, 0, 1023)};
      nir_def *steps = nir_fround_even(&b, nir_fmul_imm(&b, nir_fsat(&b, a), 255.0));
      /* Blue, green and red from bit 0; the top two bits are zero. */
      nir_def *word = nir_ior(&b, nir_ior(&b, codes[0], nir_ishl_imm(&b, codes[1], 10)),
                              nir_ishl_imm(&b, codes[2], 20));
      nir_def *alpha_byte = nir_f2u32(&b, steps);
      /* A texel whose codes and alpha the planes hold already, as the
       * mirror says, is not written again. */
      nir_def *compares = nir_ieq_imm(&b, t.mirror, STELA_METAL_TEXELS_MIRROR_COMPARE);
      nir_def *changed = nir_imm_false(&b);
      nir_push_if(&b, compares);
      nir_def *mirrored = nir_image_deref_load(
         &b, 4, 32, &t.image->def, t.mirror_coord, nir_undef(&b, 1, 32), nir_imm_int(&b, 0),
         .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true, .format = PIPE_FORMAT_NONE,
         .dest_type = nir_type_uint32);
      nir_def *held = nir_iand(&b, nir_ieq(&b, nir_channel(&b, mirrored, 0), word),
                               nir_ieq(&b, nir_channel(&b, mirrored, 1), alpha_byte));
      nir_pop_if(&b, NULL);
      held = nir_if_phi(&b, held, changed);
      nir_push_if(&b, nir_inot(&b, held));
      nir_push_if(&b, nir_ine_imm(&b, t.buffer, 0));
      {
         nir_store_global(&b, word, address, .align_mul = 4);
         nir_push_if(&b, nir_ine_imm(&b, t.mirror, STELA_METAL_TEXELS_MIRROR_NONE));
         store_mirror(&b, &t, word, nir_bcsel(&b, nir_ine_imm(&b, t.alpha, 0), alpha_byte,
                                              nir_imm_int(&b, 0)));
         nir_pop_if(&b, NULL);
      }
      nir_push_else(&b, NULL);
      {
         /* The image's texels become the values they read. */
         nir_def *value = halves(&b, xr_value(&b, codes[2], srgb), xr_value(&b, codes[1], srgb),
                                 xr_value(&b, codes[0], srgb), nir_fmul_imm(&b, steps, 1.0 / 255.0));
         nir_image_deref_store(&b, &t.image->def, t.coord, nir_undef(&b, 1, 32), value,
                               nir_imm_int(&b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                               .image_array = true, .format = PIPE_FORMAT_NONE,
                               .src_type = nir_type_uint32);
      }
      nir_pop_if(&b, NULL);
      nir_push_if(&b, nir_ine_imm(&b, t.alpha, 0));
      nir_store_global(&b, nir_u2u8(&b, alpha_byte), t.alpha, .align_mul = 1);
      nir_pop_if(&b, NULL);
      nir_pop_if(&b, NULL);
      nir_pop_if(&b, NULL);
   }
   nir_pop_if(&b, NULL);
   return finish(&b);
}

/* enum stela_metal_average_format's layouts. */
static const enum pipe_format average_formats[] = {
   [STELA_METAL_AVERAGE_R8_SRGB] = PIPE_FORMAT_R8_SRGB,
   [STELA_METAL_AVERAGE_R4G4B4A4_UNORM] = PIPE_FORMAT_A4B4G4R4_UNORM,
};

/* A depth sample's bits, from a copy of an enum stela_air_depth_format, as a
 * float of the same order: unorm depth widened, and float depth as it is. */
static nir_def *depth_value(nir_builder *b, nir_def *bits, nir_def *encoding)
{
   nir_def *mask = nir_bcsel(b, nir_ieq_imm(b, encoding, STELA_AIR_DEPTH_UNORM16),
                             nir_imm_int(b, 0xffff), nir_imm_int(b, 0xffffff));
   return nir_bcsel(b, nir_ieq_imm(b, encoding, STELA_AIR_DEPTH_FLOAT32), bits,
                    nir_u2f32(b, nir_iand(b, bits, mask)));
}

/* STELA_METAL_AVERAGE_FOLLOW_DEPTH: the stencil of the first sample whose
 * depth is the least, or the greatest, which a min or max depth resolve
 * keeps. */
static void follow_depth(nir_builder *b, nir_def *arguments, nir_def *format, nir_def *samples,
                         nir_def *coord, nir_def *stencils, nir_def *destination)
{
   const struct glsl_type *ms = glsl_image_type(GLSL_SAMPLER_DIM_MS, true, GLSL_TYPE_UINT);
   nir_deref_instr *depths = stela_metal_bind_texture_id(
      b, load(b, arguments, STELA_METAL_AVERAGE_DEPTH, 64), ms, false, NULL, NULL);
   nir_def *encoding = nir_iand_imm(b, format, STELA_METAL_AVERAGE_DEPTH_FORMAT_MASK);
   nir_def *greatest = nir_ine_imm(b, nir_iand_imm(b, format, STELA_METAL_AVERAGE_FOLLOW_MAX), 0);
   nir_variable *best = nir_local_variable_create(b->impl, glsl_float_type(), "best depth");
   nir_variable *chosen = nir_local_variable_create(b->impl, glsl_uint_type(), "chosen sample");
   for (unsigned s = 0; s < 8; s++) {
      nir_push_if(b, nir_ult(b, nir_imm_int(b, s), samples));
      nir_def *bits = nir_channel(
         b, nir_image_deref_load(b, 4, 32, &depths->def, coord, nir_imm_int(b, s), nir_imm_int(b, 0),
                                 .image_dim = GLSL_SAMPLER_DIM_MS, .image_array = true,
                                 .format = PIPE_FORMAT_NONE, .dest_type = nir_type_uint32),
         0);
      nir_def *depth = depth_value(b, bits, encoding);
      if (s == 0) {
         nir_store_var(b, best, depth, 1);
         nir_store_var(b, chosen, nir_imm_int(b, 0), 1);
      } else {
         /* Strict, so that ties keep the first sample. */
         nir_def *kept = nir_load_var(b, best);
         nir_push_if(b, nir_bcsel(b, greatest, nir_flt(b, kept, depth), nir_flt(b, depth, kept)));
         nir_store_var(b, best, depth, 1);
         nir_store_var(b, chosen, nir_imm_int(b, s), 1);
         nir_pop_if(b, NULL);
      }
      nir_pop_if(b, NULL);
   }
   nir_def *stencil = nir_image_deref_load(
      b, 4, 32, stencils, coord, nir_load_var(b, chosen), nir_imm_int(b, 0),
      .image_dim = GLSL_SAMPLER_DIM_MS, .image_array = true, .format = PIPE_FORMAT_NONE,
      .dest_type = nir_type_uint32);
   nir_image_deref_store(b, destination, coord, nir_undef(b, 1, 32),
                         nir_vec4(b, nir_channel(b, stencil, 0), nir_imm_int(b, 0),
                                  nir_imm_int(b, 0), nir_imm_int(b, 0)),
                         nir_imm_int(b, 0), .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true,
                         .format = PIPE_FORMAT_NONE, .src_type = nir_type_uint32);
}

nir_shader *stela_metal_average_samples_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_average_samples", STELA_METAL_AVERAGE_COUNT,
                          &arguments, &thread);
   nir_def *width = load(&b, arguments, STELA_METAL_AVERAGE_WIDTH, 32);
   nir_def *height = load(&b, arguments, STELA_METAL_AVERAGE_HEIGHT, 32);
   nir_def *per_layer = nir_imul(&b, width, height);
   nir_def *layer = nir_udiv(&b, thread, per_layer);
   nir_def *rest = nir_isub(&b, thread, nir_imul(&b, layer, per_layer));
   nir_def *y = nir_udiv(&b, rest, width);
   nir_def *x = nir_isub(&b, rest, nir_imul(&b, y, width));
   nir_def *coord = nir_vec4(&b, x, y, layer, nir_imm_int(&b, 0));
   nir_def *samples = load(&b, arguments, STELA_METAL_AVERAGE_SAMPLES, 32);
   nir_def *format = load(&b, arguments, STELA_METAL_AVERAGE_FORMAT, 32);
   const struct glsl_type *ms = glsl_image_type(GLSL_SAMPLER_DIM_MS, true, GLSL_TYPE_UINT);
   const struct glsl_type *single = glsl_image_type(GLSL_SAMPLER_DIM_2D, true, GLSL_TYPE_UINT);
   nir_deref_instr *source = stela_metal_bind_texture_id(
      &b, load(&b, arguments, STELA_METAL_AVERAGE_SOURCE, 64), ms, false, NULL, NULL);
   nir_deref_instr *destination = stela_metal_bind_texture_id(
      &b, load(&b, arguments, STELA_METAL_AVERAGE_DESTINATION, 64), single, false, NULL, NULL);
   nir_variable *sum = nir_local_variable_create(b.impl, glsl_vec4_type(), "sum");
   for (unsigned f = 1; f < ARRAY_SIZE(average_formats); f++) {
      enum pipe_format pipe = average_formats[f];
      unsigned words = DIV_ROUND_UP(util_format_get_blocksizebits(pipe), 32);
      nir_push_if(&b, nir_ieq_imm(&b, format, f));
      nir_store_var(&b, sum, nir_imm_vec4(&b, 0.0f, 0.0f, 0.0f, 0.0f), 0xf);
      /* Metal's multisampled textures hold at most eight samples. */
      for (unsigned s = 0; s < 8; s++) {
         nir_push_if(&b, nir_ult(&b, nir_imm_int(&b, s), samples));
         nir_def *bits = nir_image_deref_load(
            &b, 4, 32, &source->def, coord, nir_imm_int(&b, s), nir_imm_int(&b, 0),
            .image_dim = GLSL_SAMPLER_DIM_MS, .image_array = true, .format = PIPE_FORMAT_NONE,
            .dest_type = nir_type_uint32);
         nir_def *value = nir_format_unpack_rgba(&b, nir_trim_vector(&b, bits, words), pipe);
         nir_store_var(&b, sum, nir_fadd(&b, nir_load_var(&b, sum), value), 0xf);
         nir_pop_if(&b, NULL);
      }
      nir_def *mean = nir_fmul(&b, nir_load_var(&b, sum), nir_frcp(&b, nir_u2f32(&b, samples)));
      nir_def *packed = nir_format_pack_rgba(&b, pipe, mean);
      nir_image_deref_store(&b, &destination->def, coord, nir_undef(&b, 1, 32),
                            nir_pad_vector_imm_int(&b, packed, 0, 4), nir_imm_int(&b, 0),
                            .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true,
                            .format = PIPE_FORMAT_NONE, .src_type = nir_type_uint32);
      nir_pop_if(&b, NULL);
   }
   nir_push_if(&b, nir_ine_imm(&b, nir_iand_imm(&b, format, STELA_METAL_AVERAGE_FOLLOW_DEPTH), 0));
   follow_depth(&b, arguments, format, samples, coord, &source->def, &destination->def);
   nir_pop_if(&b, NULL);
   return finish(&b);
}

/* Bits offset to offset + count of x, unsigned or sign-extended: NAK takes
 * no ubfe or ibfe. */
static nir_def *field(nir_builder *b, nir_def *x, unsigned offset, unsigned count)
{
   return nir_iand_imm(b, nir_ushr_imm(b, x, offset), BITFIELD_MASK(count));
}

static nir_def *signed_field(nir_builder *b, nir_def *x, unsigned offset, unsigned count)
{
   return nir_ishr_imm(b, nir_ishl_imm(b, x, 32 - offset - count), 32 - count);
}

/* A word's bytes in the other order: ETC and EAC blocks are big-endian. */
static nir_def *byte_swap(nir_builder *b, nir_def *x)
{
   nir_def *low = nir_ior(b, nir_ishl_imm(b, nir_iand_imm(b, x, 0xff), 24),
                          nir_ishl_imm(b, nir_iand_imm(b, x, 0xff00), 8));
   nir_def *high =
      nir_ior(b, nir_iand_imm(b, nir_ushr_imm(b, x, 8), 0xff00), nir_ushr_imm(b, x, 24));
   return nir_ior(b, low, high);
}

/* table[index] for an index below count. */
static nir_def *lookup(nir_builder *b, const unsigned *table, unsigned count, nir_def *index)
{
   nir_def *result = nir_imm_int(b, table[0]);
   for (unsigned i = 1; i < count; i++)
      result = nir_bcsel(b, nir_ieq_imm(b, index, i), nir_imm_int(b, table[i]), result);
   return result;
}

static nir_def *clamp_int(nir_builder *b, nir_def *v, int low, int high)
{
   return nir_imin(b, nir_imax(b, v, nir_imm_int(b, low)), nir_imm_int(b, high));
}

/* A channel of bits widened to 8 by repeating its top bits. */
static nir_def *widen(nir_builder *b, nir_def *v, unsigned bits)
{
   return nir_ior(b, nir_ishl_imm(b, v, 8 - bits), nir_ushr_imm(b, v, 2 * bits - 8));
}

static nir_def *widen3(nir_builder *b, nir_def *r, nir_def *g, nir_def *bl, unsigned bits)
{
   return nir_vec3(b, widen(b, r, bits), widen(b, g, bits), widen(b, bl, bits));
}

/* An ETC2 alpha or EAC block's base, multiplier and modifier at pixel
 * index p, x * 4 + y; hi and lo are its big-endian words. */
struct etc_alpha {
   nir_def *base, *multiplier, *modifier, *hi;
};

static struct etc_alpha etc_alpha(nir_builder *b, nir_def *first, nir_def *second, nir_def *p)
{
   nir_def *hi = byte_swap(b, first), *lo = byte_swap(b, second);
   static const unsigned magnitudes[16] = {0xe852, 0xc962, 0xc741, 0xc531, 0xb752, 0xa862,
                                           0xa763, 0xa742, 0x9751, 0x9741, 0x9731, 0x9641,
                                           0x9632, 0x9210, 0x8753, 0x8642};
   /* Pixel p's 3-bit index starts at bit 45 - 3p of the block; its top bit
    * may lie in the other word. */
   nir_def *offset = nir_isub_imm(b, 45, nir_imul_imm(b, p, 3));
   nir_def *top = nir_iadd_imm(b, offset, 2);
   nir_def *low = nir_bcsel(b, nir_uge_imm(b, offset, 32), hi, lo);
   nir_def *high = nir_bcsel(b, nir_uge_imm(b, top, 32), hi, lo);
   nir_def *index = nir_iand_imm(b, nir_ushr(b, low, nir_iand_imm(b, offset, 31)), 3);
   nir_def *sign = nir_iand_imm(b, nir_ushr(b, high, nir_iand_imm(b, top, 31)), 1);
   nir_def *table = lookup(b, magnitudes, 16, field(b, hi, 16, 4));
   nir_def *magnitude = nir_iand_imm(b, nir_ushr(b, table, nir_imul_imm(b, index, 4)), 0xf);
   /* A clear sign bit negates the magnitude less one: -3 for 2. */
   return (struct etc_alpha){
      .base = field(b, hi, 24, 8),
      .multiplier = field(b, hi, 20, 4),
      .modifier = nir_ixor(b, magnitude, nir_iadd_imm(b, sign, -1)),
      .hi = hi,
   };
}

/* An EAC channel's 11-bit value as its 16-bit unorm or snorm code. */
static nir_def *eac_channel(nir_builder *b, nir_def *first, nir_def *second, nir_def *p,
                            nir_def *is_signed)
{
   struct etc_alpha a = etc_alpha(b, first, second, p);
   nir_def *multiplier = nir_imax(b, nir_imul_imm(b, a.multiplier, 8), nir_imm_int(b, 1));
   /* A signed base of -128 counts as -127. */
   nir_def *signed_base =
      nir_imul_imm(b, nir_imax(b, signed_field(b, a.hi, 24, 8), nir_imm_int(b, -127)), 8);
   nir_def *base = nir_bcsel(b, is_signed, signed_base, nir_iadd_imm(b, nir_imul_imm(b, a.base, 8), 4));
   nir_def *value = nir_iadd(b, base, nir_imul(b, a.modifier, multiplier));
   nir_def *unorm = nir_udiv_imm(
      b, nir_iadd_imm(b, nir_imul_imm(b, clamp_int(b, value, 0, 2047), 65535), 1023), 2047);
   nir_def *snorm = clamp_int(b, value, -1023, 1023);
   nir_def *magnitude =
      nir_udiv_imm(b, nir_iadd_imm(b, nir_imul_imm(b, nir_iabs(b, snorm), 32767), 511), 1023);
   snorm = nir_bcsel(b, nir_ilt_imm(b, snorm, 0), nir_ineg(b, magnitude), magnitude);
   return nir_iand_imm(b, nir_bcsel(b, is_signed, snorm, unorm), 0xffff);
}

/* An ETC2 RGB block's color at x and y, 8 bits a channel, and whether a
 * punch-through alpha block leaves the texel transparent. */
static nir_def *etc_color(nir_builder *b, nir_def *first, nir_def *second, nir_def *x,
                          nir_def *y, nir_def *punch_through, nir_def **transparent)
{
   static const unsigned distances[8] = {3, 6, 11, 16, 23, 32, 41, 64};
   static const unsigned small[8] = {2, 5, 9, 13, 18, 24, 33, 47};
   static const unsigned large[8] = {8, 17, 29, 42, 60, 80, 106, 183};
   nir_def *hi = byte_swap(b, first), *lo = byte_swap(b, second);
   /* Pixel p, x * 4 + y, has its index's low bit at bit p and high bit at
    * bit p + 16; msb holds the high bit in place, 0 or 2. */
   nir_def *p = nir_iadd(b, nir_imul_imm(b, x, 4), y);
   nir_def *lsb = nir_iand_imm(b, nir_ushr(b, lo, p), 1);
   nir_def *msb = nir_iand_imm(b, nir_ushr(b, lo, nir_iadd_imm(b, p, 15)), 2);
   nir_def *index = nir_ior(b, msb, lsb);
   nir_def *flip = nir_test_mask(b, hi, 1);
   /* The differential bit, which punch-through blocks spend on opacity. */
   nir_def *diff = nir_test_mask(b, hi, 2);
   nir_def *subblock = nir_ushr_imm(b, nir_bcsel(b, flip, y, x), 1);
   nir_def *non_opaque = nir_iand(b, punch_through, nir_inot(b, diff));
   nir_def *individual = nir_iand(b, nir_inot(b, punch_through), nir_inot(b, diff));

   nir_def *nibbles[3];
   for (unsigned i = 0; i < 3; i++) {
      nir_def *shift = nir_isub_imm(b, 28 - 8 * i, nir_imul_imm(b, subblock, 4));
      nibbles[i] = widen(b, nir_iand_imm(b, nir_ushr(b, hi, shift), 0xf), 4);
   }
   nir_def *individual_base = nir_vec(b, nibbles, 3);
   nir_def *rb = field(b, hi, 27, 5), *gb = field(b, hi, 19, 5), *bb = field(b, hi, 11, 5);
   nir_def *r1 = nir_iadd(b, rb, signed_field(b, hi, 24, 3));
   nir_def *g1 = nir_iadd(b, gb, signed_field(b, hi, 16, 3));
   nir_def *b1 = nir_iadd(b, bb, signed_field(b, hi, 8, 3));
   nir_def *second_sub = nir_ine_imm(b, subblock, 0);
   nir_def *differential_base =
      widen3(b, nir_bcsel(b, second_sub, r1, rb), nir_bcsel(b, second_sub, g1, gb),
             nir_bcsel(b, second_sub, b1, bb), 5);
   /* A differential channel past 5 bits selects T, H or planar mode. */
   nir_def *t_mode = nir_iand(b, nir_inot(b, individual), nir_ugt_imm(b, r1, 31));
   nir_def *h_mode =
      nir_iand(b, nir_iand(b, nir_inot(b, individual), nir_inot(b, t_mode)), nir_ugt_imm(b, g1, 31));
   nir_def *planar = nir_iand(b, nir_iand(b, nir_inot(b, individual), nir_inot(b, t_mode)),
                              nir_iand(b, nir_inot(b, h_mode), nir_ugt_imm(b, b1, 31)));

   /* Individual and differential modes modify their subblock's base. */
   nir_def *table = nir_iand_imm(b, nir_ushr(b, hi, nir_isub_imm(b, 5, nir_imul_imm(b, subblock, 3))), 7);
   nir_def *magnitude = nir_bcsel(b, nir_ine_imm(b, lsb, 0), lookup(b, large, 8, table),
                                  lookup(b, small, 8, table));
   nir_def *sign = nir_isub_imm(b, 1, msb);
   /* Punch-through's index 0 is unmodified and 2 transparent. */
   sign = nir_bcsel(b, non_opaque, nir_imul(b, sign, lsb), sign);
   nir_def *etc1 = nir_iadd(b, nir_bcsel(b, individual, individual_base, differential_base),
                            nir_imul(b, magnitude, sign));

   /* T mode: index 0 paints the first color, the rest the second moved by
    * a distance. */
   nir_def *t_first = widen3(b, nir_ior(b, field(b, hi, 24, 2), nir_ishl_imm(b, field(b, hi, 27, 2), 2)),
                             field(b, hi, 20, 4), field(b, hi, 16, 4), 4);
   nir_def *t_second = widen3(b, field(b, hi, 12, 4), field(b, hi, 8, 4), field(b, hi, 4, 4), 4);
   nir_def *t_distance =
      lookup(b, distances, 8, nir_ior(b, nir_ishl_imm(b, field(b, hi, 2, 2), 1), field(b, hi, 0, 1)));
   nir_def *t = nir_bcsel(b, nir_ieq_imm(b, index, 0), t_first,
                          nir_iadd(b, t_second, nir_imul(b, t_distance, nir_isub_imm(b, 2, index))));

   /* H mode: the high bit picks a color, the low bit the distance's sign;
    * the colors' order is the distance's lowest bit. */
   nir_def *h_r0 = field(b, hi, 27, 4);
   nir_def *h_g0 = nir_ior(b, nir_ishl_imm(b, field(b, hi, 24, 3), 1), field(b, hi, 20, 1));
   nir_def *h_b0 = nir_ior(b, field(b, hi, 15, 3), nir_ishl_imm(b, field(b, hi, 19, 1), 3));
   nir_def *h_r2 = field(b, hi, 11, 4), *h_g2 = field(b, hi, 7, 4), *h_b2 = field(b, hi, 3, 4);
   nir_def *order0 = nir_ior(b, nir_ishl_imm(b, h_r0, 16), nir_ior(b, nir_ishl_imm(b, h_g0, 8), h_b0));
   nir_def *order2 = nir_ior(b, nir_ishl_imm(b, h_r2, 16), nir_ior(b, nir_ishl_imm(b, h_g2, 8), h_b2));
   nir_def *h_index = nir_ior(b, nir_ior(b, nir_iand_imm(b, hi, 4), nir_ishl_imm(b, field(b, hi, 0, 1), 1)),
                              nir_b2i32(b, nir_uge(b, order0, order2)));
   nir_def *h_base = nir_bcsel(b, nir_ine_imm(b, msb, 0), widen3(b, h_r2, h_g2, h_b2, 4),
                               widen3(b, h_r0, h_g0, h_b0, 4));
   nir_def *h = nir_iadd(b, h_base, nir_imul(b, lookup(b, distances, 8, h_index),
                                             nir_isub_imm(b, 1, nir_imul_imm(b, lsb, 2))));

   /* Planar mode: a plane through the origin, horizontal and vertical
    * colors. */
   nir_def *origin = nir_vec3(
      b, widen(b, field(b, hi, 25, 6), 6),
      widen(b, nir_ior(b, field(b, hi, 17, 6), nir_ishl_imm(b, field(b, hi, 24, 1), 6)), 7),
      widen(b, nir_ior(b, nir_ior(b, nir_ishl_imm(b, field(b, hi, 11, 2), 3),
                                  nir_ishl_imm(b, field(b, hi, 16, 1), 5)),
                       field(b, hi, 7, 3)),
            6));
   nir_def *horizontal = nir_vec3(
      b, widen(b, nir_ior(b, field(b, hi, 0, 1), nir_ishl_imm(b, field(b, hi, 2, 5), 1)), 6),
      widen(b, field(b, lo, 25, 7), 7), widen(b, field(b, lo, 19, 6), 6));
   nir_def *vertical = nir_vec3(b, widen(b, field(b, lo, 13, 6), 6), widen(b, field(b, lo, 6, 7), 7),
                                widen(b, field(b, lo, 0, 6), 6));
   nir_def *dx = nir_imul(b, nir_isub(b, horizontal, origin), x);
   nir_def *dy = nir_imul(b, nir_isub(b, vertical, origin), y);
   nir_def *plane = nir_iadd(b, origin, nir_ishr_imm(b, nir_iadd_imm(b, nir_iadd(b, dx, dy), 2), 2));

   nir_def *rgb = nir_bcsel(b, t_mode, t, nir_bcsel(b, h_mode, h, nir_bcsel(b, planar, plane, etc1)));
   *transparent = nir_iand(b, nir_iand(b, non_opaque, nir_inot(b, planar)), nir_ieq_imm(b, index, 2));
   return nir_vec3(b, clamp_int(b, nir_channel(b, rgb, 0), 0, 255),
                   clamp_int(b, nir_channel(b, rgb, 1), 0, 255),
                   clamp_int(b, nir_channel(b, rgb, 2), 0, 255));
}

nir_def *stela_metal_decode_etc(nir_builder *b, nir_def *words, nir_def *x, nir_def *y,
                                nir_def *codec)
{
   nir_def *w[4];
   for (unsigned i = 0; i < 4; i++)
      w[i] = nir_channel(b, words, i);
   nir_def *p = nir_iadd(b, nir_imul_imm(b, x, 4), y);
   nir_def *rgba8 = nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RGBA8);
   nir_def *punch_through = nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_ETC2_RGB8A1);
   /* An RGBA8 block's alpha block precedes its color block. */
   nir_def *transparent;
   nir_def *rgb = etc_color(b, nir_bcsel(b, rgba8, w[2], w[0]), nir_bcsel(b, rgba8, w[3], w[1]),
                            x, y, punch_through, &transparent);
   struct etc_alpha a = etc_alpha(b, w[0], w[1], p);
   nir_def *alpha = nir_bcsel(
      b, rgba8, clamp_int(b, nir_iadd(b, a.base, nir_imul(b, a.modifier, a.multiplier)), 0, 255),
      nir_imm_int(b, 255));
   nir_def *color = nir_ior(b, nir_ior(b, nir_channel(b, rgb, 0), nir_ishl_imm(b, nir_channel(b, rgb, 1), 8)),
                            nir_ior(b, nir_ishl_imm(b, nir_channel(b, rgb, 2), 16), nir_ishl_imm(b, alpha, 24)));
   color = nir_bcsel(b, transparent, nir_imm_int(b, 0), color);

   nir_def *is_signed = nir_ior(b, nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_R11_SNORM),
                                nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RG11_SNORM));
   nir_def *red = eac_channel(b, w[0], w[1], p, is_signed);
   nir_def *green = eac_channel(b, w[2], w[3], p, is_signed);
   nir_def *two = nir_ior(b, nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RG11),
                          nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RG11_SNORM));
   nir_def *eac = nir_bcsel(b, two, nir_ior(b, red, nir_ishl_imm(b, green, 16)), red);
   return nir_bcsel(b, nir_uge_imm(b, codec, STELA_METAL_BLOCKS_EAC_R11), eac, color);
}

/* The decode kernels' common part: the thread's image coordinate, its
 * coordinate in its block, the block's words, and the codec. The region
 * starts on a block boundary. */
struct blocks {
   nir_def *codec, *coord, *x, *y, *words, *block_width, *block_height;
   nir_deref_instr *image;
};

static nir_builder blocks(const nir_shader_compiler_options *options, const char *name,
                          nir_def *(*block_bytes)(nir_builder *, nir_def *), struct blocks *k)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, name, STELA_METAL_TEXELS_COUNT, &arguments, &thread);
   nir_def *width = load(&b, arguments, STELA_METAL_TEXELS_WIDTH, 32);
   nir_def *height = load(&b, arguments, STELA_METAL_TEXELS_HEIGHT, 32);
   nir_def *per_image = nir_imul(&b, width, height);
   nir_def *z = nir_udiv(&b, thread, per_image);
   nir_def *rest = nir_isub(&b, thread, nir_imul(&b, z, per_image));
   nir_def *y = nir_udiv(&b, rest, width);
   nir_def *x = nir_isub(&b, rest, nir_imul(&b, y, width));
   nir_def *origin[3];
   for (unsigned i = 0; i < 3; i++)
      origin[i] = load(&b, arguments, STELA_METAL_TEXELS_ORIGIN + 4 * i, 32);
   k->coord = nir_vec4(&b, nir_iadd(&b, x, origin[0]), nir_iadd(&b, y, origin[1]),
                       nir_iadd(&b, z, origin[2]), nir_imm_int(&b, 0));
   nir_def *encoding = load(&b, arguments, STELA_METAL_TEXELS_ENCODING, 32);
   k->codec = nir_iand_imm(&b, encoding, 0xff);
   nir_def *block_width = field(&b, encoding, 8, 8);
   nir_def *block_height = field(&b, encoding, 16, 8);
   k->block_width = block_width;
   k->block_height = block_height;
   nir_def *column = nir_udiv(&b, x, block_width);
   nir_def *row = nir_udiv(&b, y, block_height);
   k->x = nir_isub(&b, x, nir_imul(&b, column, block_width));
   k->y = nir_isub(&b, y, nir_imul(&b, row, block_height));
   nir_def *bytes = block_bytes(&b, k->codec);
   nir_def *offset = nir_iadd(
      &b, nir_imul(&b, z, load(&b, arguments, STELA_METAL_TEXELS_IMAGE_BYTES, 32)),
      nir_iadd(&b, nir_imul(&b, row, load(&b, arguments, STELA_METAL_TEXELS_ROW, 32)),
               nir_imul(&b, column, bytes)));
   nir_def *address = nir_iadd(&b, load(&b, arguments, STELA_METAL_TEXELS_BUFFER, 64),
                               nir_u2u64(&b, offset));
   /* An 8-byte block's words end it: the buffer may too. */
   nir_def *low = nir_load_global(&b, 2, 32, address, .align_mul = 8);
   nir_def *zero = nir_imm_ivec2(&b, 0, 0);
   nir_push_if(&b, nir_ieq_imm(&b, bytes, 16));
   nir_def *loaded = nir_load_global(&b, 2, 32, nir_iadd_imm(&b, address, 8), .align_mul = 8);
   nir_pop_if(&b, NULL);
   nir_def *high = nir_if_phi(&b, loaded, zero);
   k->words = nir_vec4(&b, nir_channel(&b, low, 0), nir_channel(&b, low, 1),
                       nir_channel(&b, high, 0), nir_channel(&b, high, 1));
   const struct glsl_type *type = glsl_image_type(GLSL_SAMPLER_DIM_2D, true, GLSL_TYPE_UINT);
   k->image = stela_metal_bind_texture_id(&b, load(&b, arguments, STELA_METAL_TEXELS_IMAGE, 64),
                                          type, false, NULL, NULL);
   return b;
}

/* Stores a decoded texel's raw bits, whose image format keeps as many as
 * it holds. */
static nir_shader *store_decoded(nir_builder *b, const struct blocks *k, nir_def *raw)
{
   nir_def *texel = nir_pad_vector_imm_int(b, raw, 0, 4);
   nir_image_deref_store(b, &k->image->def, k->coord, nir_undef(b, 1, 32), texel,
                         nir_imm_int(b, 0), .image_dim = GLSL_SAMPLER_DIM_2D,
                         .image_array = true, .format = PIPE_FORMAT_NONE,
                         .src_type = nir_type_uint32);
   return finish(b);
}

static nir_def *etc_block_bytes(nir_builder *b, nir_def *codec)
{
   nir_def *wide = nir_ior(b, nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RGBA8),
                           nir_ior(b, nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RG11),
                                   nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_EAC_RG11_SNORM)));
   return nir_bcsel(b, wide, nir_imm_int(b, 16), nir_imm_int(b, 8));
}

nir_shader *stela_metal_decode_etc_kernel(const nir_shader_compiler_options *options)
{
   struct blocks k;
   nir_builder b = blocks(options, "stela_metal_decode_etc", etc_block_bytes, &k);
   return store_decoded(&b, &k, stela_metal_decode_etc(&b, k.words, k.x, k.y, k.codec));
}

/* The low 16 bits of x spread to the even bits. */
static nir_def *spread(nir_builder *b, nir_def *x)
{
   x = nir_iand_imm(b, x, 0xffff);
   x = nir_iand_imm(b, nir_ior(b, x, nir_ishl_imm(b, x, 8)), 0x00ff00ff);
   x = nir_iand_imm(b, nir_ior(b, x, nir_ishl_imm(b, x, 4)), 0x0f0f0f0f);
   x = nir_iand_imm(b, nir_ior(b, x, nir_ishl_imm(b, x, 2)), 0x33333333);
   return nir_iand_imm(b, nir_ior(b, x, nir_ishl_imm(b, x, 1)), 0x55555555);
}

/* Block x, y's place in a PVRTC level of columns by rows blocks: the bits
 * of both below the smaller dimension interleave, y's in the even bits,
 * and the longer dimension's rest follows. */
static nir_def *twiddled(nir_builder *b, nir_def *x, nir_def *y, nir_def *columns, nir_def *rows)
{
   nir_def *smaller = nir_umin(b, columns, rows);
   nir_def *shift = nir_ufind_msb(b, smaller);
   nir_def *low = nir_iadd_imm(b, smaller, -1);
   nir_def *interleaved = nir_ior(b, spread(b, nir_iand(b, y, low)),
                                  nir_ishl_imm(b, spread(b, nir_iand(b, x, low)), 1));
   nir_def *rest = nir_ior(b, nir_ushr(b, x, shift), nir_ushr(b, y, shift));
   return nir_ior(b, interleaved, nir_ishl(b, rest, nir_ishl_imm(b, shift, 1)));
}

/* A 4-bit channel widened to 5 by its top bit. */
static nir_def *widen4(nir_builder *b, nir_def *v)
{
   return nir_ior(b, nir_ishl_imm(b, v, 1), nir_ushr_imm(b, v, 3));
}

/* A PVRTC block's first or second color, 5 bits a color channel and 4 of
 * alpha: opaque colors hold 5, 5 and 4 or 5 bits and no alpha, translucent
 * ones 3 bits of alpha and 4, 4 and 3 or 4 bits, each widened by its top
 * bits. */
static nir_def *pvrtc_color(nir_builder *b, nir_def *color, bool second)
{
   nir_def *v = second ? nir_ushr_imm(b, color, 16) : nir_iand_imm(b, color, 0xffff);
   nir_def *b3 = field(b, v, 1, 3);
   nir_def *opaque = nir_vec4(
      b, field(b, v, 10, 5), field(b, v, 5, 5),
      second ? field(b, v, 0, 5) : widen4(b, field(b, v, 1, 4)), nir_imm_int(b, 15));
   nir_def *translucent = nir_vec4(
      b, widen4(b, field(b, v, 8, 4)), widen4(b, field(b, v, 4, 4)),
      second ? widen4(b, field(b, v, 0, 4))
             : nir_ior(b, nir_ishl_imm(b, b3, 2), nir_ushr_imm(b, b3, 1)),
      nir_ishl_imm(b, field(b, v, 12, 3), 1));
   return nir_bcsel(b, nir_test_mask(b, v, 0x8000), opaque, translucent);
}

/* A 2-bit modulation value's weight in eighths of the second color. */
static nir_def *pvrtc_weight(nir_builder *b, nir_def *value)
{
   static const unsigned weights[4] = {0, 3, 5, 8};
   return lookup(b, weights, 4, value);
}

/* The weight a 2-bpp block stores for its texel x, y, which a 1-bit block
 * holds for every texel and a 2-bit block for those whose x and y share a
 * parity, and the block's way of weighing the others: 0 for none, 1 from
 * four neighbors, 2 from horizontal and 3 from vertical ones. A 2-bit
 * block's first value flags the one-axis modes, which then lend the bit
 * at 20 to the center texel's value; both values copy their high bit. */
static nir_def *pvrtc2_stored(nir_builder *b, nir_def *block, nir_def *x, nir_def *y,
                              nir_def **mode)
{
   nir_def *bits = nir_channel(b, block, 0);
   nir_def *two_bit = nir_test_mask(b, nir_channel(b, block, 1), 1);
   nir_def *one_axis = nir_test_mask(b, bits, 1);
   nir_def *vertical = nir_test_mask(b, bits, 1u << 20);
   *mode = nir_bcsel(b, two_bit,
                     nir_bcsel(b, one_axis, nir_bcsel(b, vertical, nir_imm_int(b, 3), nir_imm_int(b, 2)),
                               nir_imm_int(b, 1)),
                     nir_imm_int(b, 0));
   nir_def *centered = nir_bcsel(
      b, nir_test_mask(b, bits, 1u << 21), nir_ior_imm(b, bits, 1u << 20), nir_iand_imm(b, bits, ~(1u << 20)));
   bits = nir_bcsel(b, one_axis, centered, bits);
   bits = nir_bcsel(b, nir_test_mask(b, bits, 2), nir_ior_imm(b, bits, 1), nir_iand_imm(b, bits, ~1u));
   nir_def *k = nir_iadd(b, nir_imul_imm(b, y, 4), nir_ushr_imm(b, x, 1));
   nir_def *two = nir_iand_imm(b, nir_ushr(b, bits, nir_imul_imm(b, k, 2)), 3);
   nir_def *one = nir_iand_imm(b, nir_ushr(b, nir_channel(b, block, 0), nir_iadd(b, nir_imul_imm(b, y, 8), x)), 1);
   return pvrtc_weight(b, nir_bcsel(b, two_bit, two, nir_imul_imm(b, one, 3)));
}

/* The stored weight at x, y of the 16x8 texels four 2-bpp blocks cover,
 * the first two above the others. */
static nir_def *pvrtc2_at(nir_builder *b, nir_def *const quad[4], nir_def *x, nir_def *y,
                          nir_def **mode)
{
   nir_def *right = nir_uge_imm(b, x, 8), *lower = nir_uge_imm(b, y, 4);
   nir_def *block = nir_bcsel(b, lower, nir_bcsel(b, right, quad[3], quad[2]),
                              nir_bcsel(b, right, quad[1], quad[0]));
   nir_def *ignored;
   return pvrtc2_stored(b, block, nir_iand_imm(b, x, 7), nir_iand_imm(b, y, 3),
                        mode ? mode : &ignored);
}

nir_def *stela_metal_decode_pvrtc(nir_builder *b, nir_def *blocks, nir_def *columns,
                                  nir_def *rows, nir_def *x, nir_def *y, nir_def *codec)
{
   nir_def *two_bpp = nir_ieq_imm(b, codec, STELA_METAL_BLOCKS_PVRTC_2BPP);
   nir_def *width = nir_bcsel(b, two_bpp, nir_imm_int(b, 8), nir_imm_int(b, 4));
   nir_def *width_shift = nir_bcsel(b, two_bpp, nir_imm_int(b, 3), nir_imm_int(b, 2));
   /* The texel lies between the centers of four blocks, wrapping: the
    * first at its upper left, at lx, ly from its center. */
   nir_def *sx = nir_isub(b, nir_iadd(b, x, nir_imul(b, columns, width)), nir_ushr_imm(b, width, 1));
   nir_def *sy = nir_iadd(b, y, nir_iadd_imm(b, nir_imul_imm(b, rows, 4), -2));
   nir_def *px = nir_iand(b, nir_ushr(b, sx, width_shift), nir_iadd_imm(b, columns, -1));
   nir_def *py = nir_iand(b, nir_ushr_imm(b, sy, 2), nir_iadd_imm(b, rows, -1));
   nir_def *qx = nir_iand(b, nir_iadd_imm(b, px, 1), nir_iadd_imm(b, columns, -1));
   nir_def *qy = nir_iand(b, nir_iadd_imm(b, py, 1), nir_iadd_imm(b, rows, -1));
   nir_def *lx = nir_iand(b, sx, nir_iadd_imm(b, width, -1));
   nir_def *ly = nir_iand_imm(b, sy, 3);
   nir_def *quad[4];
   nir_def *at[4][2] = {{px, py}, {qx, py}, {px, qy}, {qx, qy}};
   for (unsigned i = 0; i < 4; i++) {
      nir_def *index = twiddled(b, at[i][0], at[i][1], columns, rows);
      nir_def *address = nir_iadd(b, blocks, nir_u2u64(b, nir_imul_imm(b, index, 8)));
      quad[i] = nir_load_global(b, 2, 32, address, .align_mul = 8);
   }
   /* The colors at the texel, weighed by its distance to each center:
    * sixteenths at 4 bpp, thirty-seconds at 2, widened to 8 bits. */
   nir_def *rx = nir_isub(b, width, lx), *ry = nir_isub_imm(b, 4, ly);
   nir_def *weights[4] = {nir_imul(b, rx, ry), nir_imul(b, lx, ry), nir_imul(b, rx, ly),
                          nir_imul(b, lx, ly)};
   nir_def *colors[2];
   for (unsigned c = 0; c < 2; c++) {
      nir_def *sum = nir_imm_ivec4(b, 0, 0, 0, 0);
      for (unsigned i = 0; i < 4; i++)
         sum = nir_iadd(b, sum, nir_imul(b, pvrtc_color(b, nir_channel(b, quad[i], 1), c), weights[i]));
      nir_def *rgb = nir_trim_vector(b, sum, 3), *a = nir_channel(b, sum, 3);
      nir_def *four_rgb = nir_iadd(b, nir_ushr_imm(b, rgb, 1), nir_ushr_imm(b, rgb, 6));
      nir_def *two_rgb = nir_iadd(b, nir_ushr_imm(b, rgb, 2), nir_ushr_imm(b, rgb, 7));
      nir_def *four_a = nir_iadd(b, a, nir_ushr_imm(b, a, 4));
      nir_def *two_a = nir_iadd(b, nir_ushr_imm(b, a, 1), nir_ushr_imm(b, a, 5));
      nir_def *widened = nir_bcsel(b, two_bpp, two_rgb, four_rgb);
      colors[c] = nir_vec4(b, nir_channel(b, widened, 0), nir_channel(b, widened, 1),
                           nir_channel(b, widened, 2), nir_bcsel(b, two_bpp, two_a, four_a));
   }

   /* The texel's own block weighs the second color: at 4 bpp by its
    * 2-bit value, which a punch-through block reads as 0, 4, 4 with no
    * alpha, or 8. */
   nir_def *qlx = nir_iadd(b, lx, nir_ushr_imm(b, width, 1)), *qly = nir_iadd_imm(b, ly, 2);
   nir_def *own4 = nir_bcsel(b, nir_uge_imm(b, qly, 4),
                             nir_bcsel(b, nir_uge_imm(b, qlx, 4), quad[3], quad[2]),
                             nir_bcsel(b, nir_uge_imm(b, qlx, 4), quad[1], quad[0]));
   nir_def *index4 = nir_iadd(b, nir_imul_imm(b, nir_iand_imm(b, qly, 3), 4), nir_iand_imm(b, qlx, 3));
   nir_def *value4 = nir_iand_imm(b, nir_ushr(b, nir_channel(b, own4, 0), nir_imul_imm(b, index4, 2)), 3);
   nir_def *punch_mode = nir_test_mask(b, nir_channel(b, own4, 1), 1);
   static const unsigned punched[4] = {0, 4, 4, 8};
   nir_def *weight4 = nir_bcsel(b, punch_mode, lookup(b, punched, 4, value4), pvrtc_weight(b, value4));
   nir_def *punch = nir_iand(b, punch_mode, nir_ieq_imm(b, value4, 2));

   /* At 2 bpp a texel a 2-bit block stores no value for averages its
    * neighbors', rounding to nearest. */
   nir_def *mode;
   nir_def *stored = pvrtc2_at(b, quad, qlx, qly, &mode);
   nir_def *left = pvrtc2_at(b, quad, nir_iadd_imm(b, qlx, -1), qly, NULL);
   nir_def *right = pvrtc2_at(b, quad, nir_iadd_imm(b, qlx, 1), qly, NULL);
   nir_def *up = pvrtc2_at(b, quad, qlx, nir_iadd_imm(b, qly, -1), NULL);
   nir_def *down = pvrtc2_at(b, quad, qlx, nir_iadd_imm(b, qly, 1), NULL);
   nir_def *both = nir_ushr_imm(b, nir_iadd_imm(b, nir_iadd(b, nir_iadd(b, left, right), nir_iadd(b, up, down)), 2), 2);
   nir_def *across = nir_ushr_imm(b, nir_iadd_imm(b, nir_iadd(b, left, right), 1), 1);
   nir_def *along = nir_ushr_imm(b, nir_iadd_imm(b, nir_iadd(b, up, down), 1), 1);
   nir_def *odd = nir_test_mask(b, nir_ixor(b, qlx, qly), 1);
   nir_def *weight2 = nir_bcsel(
      b, nir_ior(b, nir_ieq_imm(b, mode, 0), nir_inot(b, odd)), stored,
      nir_bcsel(b, nir_ieq_imm(b, mode, 1), both, nir_bcsel(b, nir_ieq_imm(b, mode, 2), across, along)));

   nir_def *weight = nir_bcsel(b, two_bpp, weight2, weight4);
   nir_def *texel = nir_ushr_imm(
      b, nir_iadd(b, nir_imul(b, colors[0], nir_isub_imm(b, 8, weight)), nir_imul(b, colors[1], weight)), 3);
   nir_def *alpha = nir_bcsel(b, nir_iand(b, punch, nir_inot(b, two_bpp)), nir_imm_int(b, 0),
                              nir_channel(b, texel, 3));
   return nir_ior(b, nir_ior(b, nir_channel(b, texel, 0), nir_ishl_imm(b, nir_channel(b, texel, 1), 8)),
                  nir_ior(b, nir_ishl_imm(b, nir_channel(b, texel, 2), 16), nir_ishl_imm(b, alpha, 24)));
}

nir_shader *stela_metal_decode_pvrtc_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_decode_pvrtc", STELA_METAL_TEXELS_COUNT, &arguments,
                          &thread);
   nir_def *width = load(&b, arguments, STELA_METAL_TEXELS_WIDTH, 32);
   nir_def *height = load(&b, arguments, STELA_METAL_TEXELS_HEIGHT, 32);
   nir_def *y = nir_udiv(&b, thread, width);
   nir_def *x = nir_isub(&b, thread, nir_imul(&b, y, width));
   nir_def *codec = nir_iand_imm(&b, load(&b, arguments, STELA_METAL_TEXELS_ENCODING, 32), 0xff);
   nir_def *block_width = nir_bcsel(&b, nir_ieq_imm(&b, codec, STELA_METAL_BLOCKS_PVRTC_2BPP),
                                    nir_imm_int(&b, 8), nir_imm_int(&b, 4));
   nir_def *columns = nir_udiv(&b, nir_iadd(&b, width, nir_iadd_imm(&b, block_width, -1)), block_width);
   nir_def *rows = nir_ushr_imm(&b, nir_iadd_imm(&b, height, 3), 2);
   nir_def *raw = stela_metal_decode_pvrtc(&b, load(&b, arguments, STELA_METAL_TEXELS_BUFFER, 64),
                                           columns, rows, x, y, codec);
   const struct glsl_type *type = glsl_image_type(GLSL_SAMPLER_DIM_2D, true, GLSL_TYPE_UINT);
   nir_deref_instr *image = stela_metal_bind_texture_id(
      &b, load(&b, arguments, STELA_METAL_TEXELS_IMAGE, 64), type, false, NULL, NULL);
   nir_def *coord = nir_vec4(&b, x, y, load(&b, arguments, STELA_METAL_TEXELS_ORIGIN + 8, 32),
                             nir_imm_int(&b, 0));
   nir_image_deref_store(&b, &image->def, coord, nir_undef(&b, 1, 32),
                         nir_vec4(&b, raw, nir_imm_int(&b, 0), nir_imm_int(&b, 0), nir_imm_int(&b, 1)),
                         nir_imm_int(&b, 0), .image_dim = GLSL_SAMPLER_DIM_2D, .image_array = true,
                         .format = PIPE_FORMAT_NONE, .src_type = nir_type_uint32);
   return finish(&b);
}

nir_shader *stela_metal_reorder_blocks_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_reorder_blocks", STELA_METAL_REORDER_COUNT,
                          &arguments, &thread);
   nir_def *width = load(&b, arguments, STELA_METAL_REORDER_WIDTH, 32);
   nir_def *row = nir_udiv(&b, thread, width);
   nir_def *column = nir_isub(&b, thread, nir_imul(&b, row, width));
   nir_def *rows_address = nir_iadd(
      &b, load(&b, arguments, STELA_METAL_REORDER_ROWS, 64),
      nir_u2u64(&b, nir_iadd(&b, nir_imul(&b, row, load(&b, arguments, STELA_METAL_REORDER_ROW_BYTES, 32)),
                             nir_imul_imm(&b, column, 8))));
   nir_def *x = nir_iadd(&b, column, load(&b, arguments, STELA_METAL_REORDER_ORIGIN, 32));
   nir_def *y = nir_iadd(&b, row, load(&b, arguments, STELA_METAL_REORDER_ORIGIN + 4, 32));
   nir_def *index = twiddled(&b, x, y, load(&b, arguments, STELA_METAL_REORDER_COLUMNS, 32),
                             load(&b, arguments, STELA_METAL_REORDER_LEVEL_ROWS, 32));
   nir_def *level_address = nir_iadd(&b, load(&b, arguments, STELA_METAL_REORDER_LEVEL, 64),
                                     nir_u2u64(&b, nir_imul_imm(&b, index, 8)));
   nir_def *to_rows = nir_ine_imm(&b, load(&b, arguments, STELA_METAL_REORDER_TO_ROWS, 32), 0);
   nir_def *from = nir_bcsel(&b, to_rows, level_address, rows_address);
   nir_def *to = nir_bcsel(&b, to_rows, rows_address, level_address);
   nir_store_global(&b, nir_load_global(&b, 2, 32, from, .align_mul = 8), to, .align_mul = 8);
   return finish(&b);
}

/* ASTC: a block's word, zero past its last. */
static nir_def *astc_word(nir_builder *b, nir_def *const w[4], nir_def *index)
{
   nir_def *word = nir_imm_int(b, 0);
   for (unsigned i = 0; i < 4; i++)
      word = nir_bcsel(b, nir_ieq_imm(b, index, i), w[i], word);
   return word;
}

/* count bits, at most 24, of a block's stream from offset; those from end
 * on read zero, as an integer sequence's missing bits do. */
static nir_def *astc_bits(nir_builder *b, nir_def *const w[4], nir_def *offset, nir_def *count,
                          nir_def *end)
{
   nir_def *index = nir_ushr_imm(b, offset, 5), *shift = nir_iand_imm(b, offset, 31);
   nir_def *low = astc_word(b, w, index), *high = astc_word(b, w, nir_iadd_imm(b, index, 1));
   /* The next word shifts in twice, so that a zero shift moves none. */
   nir_def *bits = nir_ior(b, nir_ushr(b, low, shift),
                           nir_ishl(b, nir_ishl_imm(b, high, 1), nir_isub_imm(b, 31, shift)));
   nir_def *kept = nir_imax(b, nir_imin(b, count, nir_isub(b, end, offset)), nir_imm_int(b, 0));
   return nir_iand(b, bits, nir_iadd_imm(b, nir_ishl(b, nir_imm_int(b, 1), kept), -1));
}

static nir_def *astc_at(nir_builder *b, nir_def *const w[4], nir_def *offset, unsigned count)
{
   return astc_bits(b, w, offset, nir_imm_int(b, count), nir_imm_int(b, 128));
}

/* Bits offset to offset + count of the block. */
static nir_def *astc_field(nir_builder *b, nir_def *const w[4], unsigned offset, unsigned count)
{
   unsigned i = offset / 32, shift = offset % 32;
   nir_def *bits = nir_ushr_imm(b, w[i], shift);
   if (shift + count > 32)
      bits = nir_ior(b, bits, nir_ishl_imm(b, w[i + 1], 32 - shift));
   return nir_iand_imm(b, bits, BITFIELD_MASK(count));
}

static nir_def *pick(nir_builder *b, nir_def *const *values, unsigned count, nir_def *index)
{
   nir_def *value = values[0];
   for (unsigned i = 1; i < count; i++)
      value = nir_bcsel(b, nir_ieq_imm(b, index, i), values[i], value);
   return value;
}

static nir_def *flip(nir_builder *b, nir_def *bit)
{
   return nir_ixor(b, bit, nir_imm_int(b, 1));
}

/* The k'th of the five trits an integer sequence block's 8 bits t hold. */
static nir_def *astc_trit(nir_builder *b, nir_def *t, nir_def *k)
{
   nir_def *two = nir_imm_int(b, 2);
   nir_def *high = nir_ieq_imm(b, field(b, t, 2, 3), 7);
   nir_def *c = nir_bcsel(b, high, nir_ior(b, nir_ishl_imm(b, field(b, t, 5, 3), 2), field(b, t, 0, 2)),
                          field(b, t, 0, 5));
   nir_def *t65 = field(b, t, 5, 2), *t7 = field(b, t, 7, 1);
   nir_def *both = nir_ieq_imm(b, t65, 3);
   nir_def *t4 = nir_bcsel(b, nir_ior(b, high, both), two, t7);
   nir_def *t3 = nir_bcsel(b, high, two, nir_bcsel(b, both, t7, t65));
   nir_def *c4 = field(b, c, 4, 1), *c3 = field(b, c, 3, 1), *c2 = field(b, c, 2, 1);
   nir_def *c1 = field(b, c, 1, 1), *c0 = field(b, c, 0, 1);
   nir_def *low3 = nir_ieq_imm(b, field(b, c, 0, 2), 3);
   nir_def *mid3 = nir_ieq_imm(b, field(b, c, 2, 2), 3);
   nir_def *t2 = nir_bcsel(b, nir_ior(b, low3, mid3), two, c4);
   nir_def *t1 = nir_bcsel(b, low3, c4, nir_bcsel(b, mid3, two, field(b, c, 2, 2)));
   nir_def *t0 = nir_bcsel(
      b, low3, nir_ior(b, nir_ishl_imm(b, c3, 1), nir_iand(b, c2, flip(b, c3))),
      nir_bcsel(b, mid3, field(b, c, 0, 2), nir_ior(b, nir_ishl_imm(b, c1, 1), nir_iand(b, c0, flip(b, c1)))));
   nir_def *trits[5] = {t0, t1, t2, t3, t4};
   return pick(b, trits, 5, k);
}

/* The k'th of the three quints an integer sequence block's 7 bits q hold. */
static nir_def *astc_quint(nir_builder *b, nir_def *q, nir_def *k)
{
   nir_def *four = nir_imm_int(b, 4);
   nir_def *q0 = field(b, q, 0, 1), *q3 = field(b, q, 3, 1), *q4 = field(b, q, 4, 1);
   nir_def *q21 = field(b, q, 1, 2), *q65 = field(b, q, 5, 2);
   nir_def *special = nir_iand(b, nir_ieq_imm(b, q21, 3), nir_ieq_imm(b, q65, 0));
   nir_def *n0 = flip(b, q0);
   nir_def *s2 = nir_ior(b, nir_ishl_imm(b, q0, 2),
                         nir_ior(b, nir_ishl_imm(b, nir_iand(b, q4, n0), 1), nir_iand(b, q3, n0)));
   nir_def *wide = nir_ieq_imm(b, q21, 3);
   nir_def *inverted = nir_ixor(b, q65, nir_imm_int(b, 3));
   nir_def *c = nir_bcsel(
      b, wide,
      nir_ior(b, nir_ior(b, nir_ishl_imm(b, q4, 4), nir_ishl_imm(b, q3, 3)),
              nir_ior(b, nir_ishl_imm(b, field(b, inverted, 1, 1), 2),
                      nir_ior(b, nir_ishl_imm(b, field(b, inverted, 0, 1), 1), q0))),
      field(b, q, 0, 5));
   nir_def *e2 = nir_bcsel(b, wide, four, q65);
   nir_def *five = nir_ieq_imm(b, field(b, c, 0, 3), 5);
   nir_def *e1 = nir_bcsel(b, five, four, field(b, c, 3, 2));
   nir_def *e0 = nir_bcsel(b, five, field(b, c, 3, 2), field(b, c, 0, 3));
   nir_def *quints[3] = {nir_bcsel(b, special, four, e0), nir_bcsel(b, special, four, e1),
                         nir_bcsel(b, special, s2, e2)};
   return pick(b, quints, 3, k);
}

/* An integer sequence of values of `bits` bits with a trit or quint each,
 * or neither, from start to end of a stream. */
struct astc_sequence {
   nir_def *start, *end, *bits, *trits, *quints;
};

/* The index'th value of a sequence, its trit or quint above its bits. */
static nir_def *astc_value(nir_builder *b, nir_def *const w[4], const struct astc_sequence *s,
                           nir_def *index)
{
   nir_def *m = s->bits;
#define AT(base, ms, extra) nir_iadd(b, base, nir_iadd_imm(b, nir_imul_imm(b, m, ms), extra))
   nir_def *plain = astc_bits(b, w, nir_iadd(b, s->start, nir_imul(b, index, m)), m, s->end);

   /* Five values to 8 bits of trits, interleaved after each value. */
   nir_def *g5 = nir_udiv_imm(b, index, 5), *k5 = nir_isub(b, index, nir_imul_imm(b, g5, 5));
   nir_def *base5 = nir_iadd(b, s->start, nir_imul(b, g5, nir_iadd_imm(b, nir_imul_imm(b, m, 5), 8)));
   nir_def *two = nir_imm_int(b, 2), *one = nir_imm_int(b, 1);
   nir_def *t = nir_ior(
      b, nir_ior(b, astc_bits(b, w, AT(base5, 1, 0), two, s->end),
                 nir_ishl_imm(b, astc_bits(b, w, AT(base5, 2, 2), two, s->end), 2)),
      nir_ior(b, nir_ishl_imm(b, astc_bits(b, w, AT(base5, 3, 4), one, s->end), 4),
              nir_ior(b, nir_ishl_imm(b, astc_bits(b, w, AT(base5, 4, 5), two, s->end), 5),
                      nir_ishl_imm(b, astc_bits(b, w, AT(base5, 5, 7), one, s->end), 7))));
   static const unsigned trit_gaps[5] = {0, 2, 4, 5, 7};
   nir_def *low5 = astc_bits(
      b, w, nir_iadd(b, base5, nir_iadd(b, nir_imul(b, k5, m), lookup(b, trit_gaps, 5, k5))), m, s->end);
   nir_def *trit = nir_ior(b, nir_ishl(b, astc_trit(b, t, k5), m), low5);

   /* Three values to 7 bits of quints. */
   nir_def *g3 = nir_udiv_imm(b, index, 3), *k3 = nir_isub(b, index, nir_imul_imm(b, g3, 3));
   nir_def *base3 = nir_iadd(b, s->start, nir_imul(b, g3, nir_iadd_imm(b, nir_imul_imm(b, m, 3), 7)));
   nir_def *q = nir_ior(
      b, astc_bits(b, w, AT(base3, 1, 0), nir_imm_int(b, 3), s->end),
      nir_ior(b, nir_ishl_imm(b, astc_bits(b, w, AT(base3, 2, 3), two, s->end), 3),
              nir_ishl_imm(b, astc_bits(b, w, AT(base3, 3, 5), two, s->end), 5)));
   static const unsigned quint_gaps[3] = {0, 3, 5};
   nir_def *low3 = astc_bits(
      b, w, nir_iadd(b, base3, nir_iadd(b, nir_imul(b, k3, m), lookup(b, quint_gaps, 3, k3))), m, s->end);
   nir_def *quint = nir_ior(b, nir_ishl(b, astc_quint(b, q, k3), m), low3);
#undef AT
   return nir_bcsel(b, s->trits, trit, nir_bcsel(b, s->quints, quint, plain));
}

/* A trit or quint value's bits m, its unquantization's B and C, from
 * Khronos's tables: T = D * C + B, xored with A, keeps A's top bit. */
static nir_def *astc_unquantize(nir_builder *b, nir_def *v, nir_def *m, nir_def *bv, nir_def *cv,
                                unsigned a_mask, unsigned top)
{
   nir_def *a = nir_bcsel(b, nir_test_mask(b, v, 1), nir_imm_int(b, a_mask), nir_imm_int(b, 0));
   nir_def *d = nir_ushr(b, v, m);
   nir_def *t = nir_ixor(b, nir_iadd(b, nir_imul(b, d, cv), bv), a);
   return nir_ior(b, nir_iand_imm(b, a, top), nir_ushr_imm(b, t, 2));
}

/* A color endpoint value widened to 8 bits. */
static nir_def *astc_color_value(nir_builder *b, nir_def *v, const struct astc_sequence *s)
{
   nir_def *m = s->bits;
   /* Bits alone repeat to 8. */
   nir_def *repeated[9] = {
      nir_imm_int(b, 0),
      nir_imul_imm(b, v, 0xff),
      nir_imul_imm(b, v, 0x55),
      nir_ior(b, nir_ior(b, nir_ishl_imm(b, v, 5), nir_ishl_imm(b, v, 2)), nir_ushr_imm(b, v, 1)),
      nir_imul_imm(b, v, 0x11),
      nir_ior(b, nir_ishl_imm(b, v, 3), nir_ushr_imm(b, v, 2)),
      nir_ior(b, nir_ishl_imm(b, v, 2), nir_ushr_imm(b, v, 4)),
      nir_ior(b, nir_ishl_imm(b, v, 1), nir_ushr_imm(b, v, 6)),
      v,
   };
   nir_def *plain = pick(b, repeated, 9, m);
   nir_def *t2 = field(b, v, 1, 2), *t3 = field(b, v, 1, 3), *t4 = field(b, v, 1, 4), *t5 = field(b, v, 1, 5);
   nir_def *b2 = nir_bcsel(b, nir_test_mask(b, v, 2), nir_imm_int(b, 0x116), nir_imm_int(b, 0));
   nir_def *trit_b[7] = {
      nir_imm_int(b, 0),
      nir_imm_int(b, 0),
      b2,
      nir_ior(b, nir_ior(b, t2, nir_ishl_imm(b, t2, 2)), nir_ishl_imm(b, t2, 7)),
      nir_ior(b, t3, nir_ishl_imm(b, t3, 6)),
      nir_ior(b, nir_ushr_imm(b, t4, 2), nir_ishl_imm(b, t4, 5)),
      nir_ior(b, nir_ishl_imm(b, t5, 4), nir_ushr_imm(b, t5, 4)),
   };
   static const unsigned trit_c[7] = {0, 204, 93, 44, 22, 11, 5};
   nir_def *q2 = nir_bcsel(b, nir_test_mask(b, v, 2), nir_imm_int(b, 0x10c), nir_imm_int(b, 0));
   nir_def *quint_b[6] = {
      nir_imm_int(b, 0),
      nir_imm_int(b, 0),
      q2,
      nir_ior(b, nir_ior(b, nir_ushr_imm(b, t2, 1), nir_ishl_imm(b, t2, 1)), nir_ishl_imm(b, t2, 7)),
      nir_ior(b, nir_ushr_imm(b, t3, 1), nir_ishl_imm(b, t3, 6)),
      nir_ishl_imm(b, t4, 5),
   };
   static const unsigned quint_c[6] = {0, 113, 54, 26, 13, 6};
   nir_def *trit = astc_unquantize(b, v, m, pick(b, trit_b, 7, m), lookup(b, trit_c, 7, m), 0x1ff, 0x80);
   nir_def *quint = astc_unquantize(b, v, m, pick(b, quint_b, 6, m), lookup(b, quint_c, 6, m), 0x1ff, 0x80);
   return nir_bcsel(b, s->trits, trit, nir_bcsel(b, s->quints, quint, plain));
}

/* A weight unquantized to 0 to 64. */
static nir_def *astc_weight_value(nir_builder *b, nir_def *v, const struct astc_sequence *s)
{
   nir_def *m = s->bits;
   nir_def *repeated[6] = {
      nir_imm_int(b, 0),
      nir_imul_imm(b, v, 63),
      nir_imul_imm(b, v, 21),
      nir_imul_imm(b, v, 9),
      nir_ior(b, nir_ushr_imm(b, v, 2), nir_ishl_imm(b, v, 2)),
      nir_ior(b, nir_ushr_imm(b, v, 4), nir_ishl_imm(b, v, 1)),
   };
   nir_def *plain = pick(b, repeated, 6, m);
   nir_def *t2 = field(b, v, 1, 2);
   nir_def *trit_b[4] = {
      nir_imm_int(b, 0),
      nir_imm_int(b, 0),
      nir_bcsel(b, nir_test_mask(b, v, 2), nir_imm_int(b, 0x45), nir_imm_int(b, 0)),
      nir_ior(b, t2, nir_ishl_imm(b, t2, 5)),
   };
   static const unsigned trit_c[4] = {0, 50, 23, 11};
   nir_def *quint_b[3] = {
      nir_imm_int(b, 0),
      nir_imm_int(b, 0),
      nir_bcsel(b, nir_test_mask(b, v, 2), nir_imm_int(b, 0x42), nir_imm_int(b, 0)),
   };
   static const unsigned quint_c[3] = {0, 28, 13};
   nir_def *trit = astc_unquantize(b, v, m, pick(b, trit_b, 4, m), lookup(b, trit_c, 4, m), 0x7f, 0x20);
   nir_def *quint = astc_unquantize(b, v, m, pick(b, quint_b, 3, m), lookup(b, quint_c, 3, m), 0x7f, 0x20);
   nir_def *quantized = nir_bcsel(b, s->trits, trit, nir_bcsel(b, s->quints, quint, plain));
   nir_def *widened = nir_iadd(b, quantized, nir_b2i32(b, nir_uge_imm(b, quantized, 33)));
   /* Without bits, three trits or five quints spread over 0 to 64 alone. */
   nir_def *bare = nir_bcsel(b, s->trits, nir_imul_imm(b, v, 32), nir_imul_imm(b, v, 16));
   nir_def *unpadded = nir_iand(b, nir_ieq_imm(b, m, 0), nir_ior(b, s->trits, s->quints));
   return nir_bcsel(b, unpadded, bare, widened);
}

/* Which of count partitions holds texel x, y: Khronos's hash of the
 * block's seed. */
static nir_def *astc_partition(nir_builder *b, nir_def *seed, nir_def *count, nir_def *x, nir_def *y,
                               nir_def *small)
{
   x = nir_bcsel(b, small, nir_ishl_imm(b, x, 1), x);
   y = nir_bcsel(b, small, nir_ishl_imm(b, y, 1), y);
   nir_def *r = nir_iadd(b, seed, nir_imul_imm(b, nir_iadd_imm(b, count, -1), 1024));
   r = nir_ixor(b, r, nir_ushr_imm(b, r, 15));
   r = nir_isub(b, r, nir_ishl_imm(b, r, 17));
   r = nir_iadd(b, r, nir_ishl_imm(b, r, 7));
   r = nir_iadd(b, r, nir_ishl_imm(b, r, 4));
   r = nir_ixor(b, r, nir_ushr_imm(b, r, 5));
   r = nir_iadd(b, r, nir_ishl_imm(b, r, 16));
   r = nir_ixor(b, r, nir_ushr_imm(b, r, 7));
   r = nir_ixor(b, r, nir_ushr_imm(b, r, 3));
   r = nir_ixor(b, r, nir_ishl_imm(b, r, 6));
   r = nir_ixor(b, r, nir_ushr_imm(b, r, 17));
   nir_def *three = nir_ieq_imm(b, count, 3);
   nir_def *four_or_five = nir_bcsel(b, nir_test_mask(b, seed, 2), nir_imm_int(b, 4), nir_imm_int(b, 5));
   nir_def *six_or_five = nir_bcsel(b, three, nir_imm_int(b, 6), nir_imm_int(b, 5));
   nir_def *odd = nir_test_mask(b, seed, 1);
   nir_def *sh1 = nir_bcsel(b, odd, four_or_five, six_or_five);
   nir_def *sh2 = nir_bcsel(b, odd, six_or_five, four_or_five);
   nir_def *s[8];
   for (unsigned i = 0; i < 8; i++) {
      nir_def *v = field(b, r, 4 * i, 4);
      s[i] = nir_ushr(b, nir_imul(b, v, v), i % 2 ? sh2 : sh1);
   }
   nir_def *at[4];
   for (unsigned i = 0; i < 4; i++)
      at[i] = nir_iand_imm(b, nir_iadd(b, nir_iadd(b, nir_imul(b, s[2 * i], x), nir_imul(b, s[2 * i + 1], y)),
                                       nir_ushr_imm(b, r, 14 - 4 * i)), 0x3f);
   at[2] = nir_bcsel(b, nir_ult_imm(b, count, 3), nir_imm_int(b, 0), at[2]);
   at[3] = nir_bcsel(b, nir_ult_imm(b, count, 4), nir_imm_int(b, 0), at[3]);
   nir_def *first = nir_iand(b, nir_uge(b, at[0], at[1]), nir_iand(b, nir_uge(b, at[0], at[2]), nir_uge(b, at[0], at[3])));
   nir_def *second = nir_iand(b, nir_uge(b, at[1], at[2]), nir_uge(b, at[1], at[3]));
   nir_def *third = nir_uge(b, at[2], at[3]);
   return nir_bcsel(b, first, nir_imm_int(b, 0),
                    nir_bcsel(b, second, nir_imm_int(b, 1), nir_bcsel(b, third, nir_imm_int(b, 2), nir_imm_int(b, 3))));
}

/* bit_transfer_signed: an offset's top bit moves to its base, and it
 * keeps a signed 6 bits. */
static void astc_transfer(nir_builder *b, nir_def **offset, nir_def **base)
{
   *base = nir_ior(b, nir_ushr_imm(b, *base, 1), nir_iand_imm(b, *offset, 0x80));
   *offset = signed_field(b, *offset, 1, 6);
}

static nir_def *astc_contract(nir_builder *b, nir_def *r, nir_def *g, nir_def *bl, nir_def *a)
{
   return nir_vec4(b, nir_ishr_imm(b, nir_iadd(b, r, bl), 1), nir_ishr_imm(b, nir_iadd(b, g, bl), 1), bl, a);
}

static nir_def *astc_clamp(nir_builder *b, nir_def *v)
{
   return nir_imin(b, nir_imax(b, v, nir_imm_int(b, 0)), nir_imm_int(b, 255));
}

/* A partition's endpoints from its values in an LDR endpoint mode. */
static void astc_endpoints(nir_builder *b, nir_def *cem, nir_def *const v[8], nir_def **e0, nir_def **e1)
{
   nir_def *opaque = nir_imm_int(b, 255);
   nir_def *lum[2], *lum_a[2], *lum_offset[2], *scaled[2], *direct[2], *offset[2];
   lum[0] = nir_vec4(b, v[0], v[0], v[0], opaque);
   lum[1] = nir_vec4(b, v[1], v[1], v[1], opaque);
   nir_def *l0 = nir_ior(b, nir_ushr_imm(b, v[0], 2), nir_iand_imm(b, v[1], 0xc0));
   nir_def *l1 = nir_imin(b, nir_iadd(b, l0, nir_iand_imm(b, v[1], 0x3f)), opaque);
   nir_def *luminance_offset[2] = {nir_vec4(b, l0, l0, l0, opaque), nir_vec4(b, l1, l1, l1, opaque)};
   lum_a[0] = nir_vec4(b, v[0], v[0], v[0], v[2]);
   lum_a[1] = nir_vec4(b, v[1], v[1], v[1], v[3]);
   nir_def *o[8], *base[8];
   for (unsigned i = 0; i < 8; i += 2) {
      o[i + 1] = v[i + 1];
      base[i] = v[i];
      astc_transfer(b, &o[i + 1], &base[i]);
   }
   nir_def *la = nir_iadd(b, base[0], o[1]);
   lum_offset[0] = nir_vec4(b, base[0], base[0], base[0], base[2]);
   lum_offset[1] = astc_clamp(b, nir_vec4(b, la, la, la, nir_iadd(b, base[2], o[3])));
   /* Base and scale; with two alphas when cem is 10. */
   nir_def *alpha = nir_ieq_imm(b, cem, 10);
   scaled[0] = nir_vec4(b, nir_ushr_imm(b, nir_imul(b, v[0], v[3]), 8), nir_ushr_imm(b, nir_imul(b, v[1], v[3]), 8),
                        nir_ushr_imm(b, nir_imul(b, v[2], v[3]), 8), nir_bcsel(b, alpha, v[4], opaque));
   scaled[1] = nir_vec4(b, v[0], v[1], v[2], nir_bcsel(b, alpha, v[5], opaque));
   /* Direct and base-offset RGB, with alpha when cem is 12 or 13. */
   nir_def *with_alpha = nir_uge_imm(b, cem, 12);
   nir_def *a0 = nir_bcsel(b, with_alpha, v[6], opaque), *a1 = nir_bcsel(b, with_alpha, v[7], opaque);
   nir_def *s0 = nir_iadd(b, nir_iadd(b, v[0], v[2]), v[4]);
   nir_def *s1 = nir_iadd(b, nir_iadd(b, v[1], v[3]), v[5]);
   nir_def *ordered = nir_uge(b, s1, s0);
   direct[0] = nir_bcsel(b, ordered, nir_vec4(b, v[0], v[2], v[4], a0), astc_contract(b, v[1], v[3], v[5], a1));
   direct[1] = nir_bcsel(b, ordered, nir_vec4(b, v[1], v[3], v[5], a1), astc_contract(b, v[0], v[2], v[4], a0));
   nir_def *b6 = nir_bcsel(b, with_alpha, base[6], opaque);
   nir_def *sum6 = nir_bcsel(b, with_alpha, nir_iadd(b, base[6], o[7]), opaque);
   nir_def *r = nir_iadd(b, base[0], o[1]), *g = nir_iadd(b, base[2], o[3]), *bl = nir_iadd(b, base[4], o[5]);
   nir_def *forward = nir_ige_imm(b, nir_iadd(b, nir_iadd(b, o[1], o[3]), o[5]), 0);
   offset[0] = nir_bcsel(b, forward, nir_vec4(b, base[0], base[2], base[4], b6),
                         astc_clamp(b, astc_contract(b, r, g, bl, sum6)));
   offset[1] = nir_bcsel(b, forward, astc_clamp(b, nir_vec4(b, r, g, bl, sum6)),
                         astc_contract(b, base[0], base[2], base[4], b6));
   for (unsigned e = 0; e < 2; e++) {
      nir_def *result = direct[e];
      result = nir_bcsel(b, nir_ieq_imm(b, cem, 0), lum[e], result);
      result = nir_bcsel(b, nir_ieq_imm(b, cem, 1), luminance_offset[e], result);
      result = nir_bcsel(b, nir_ieq_imm(b, cem, 4), lum_a[e], result);
      result = nir_bcsel(b, nir_ieq_imm(b, cem, 5), lum_offset[e], result);
      result = nir_bcsel(b, nir_ior(b, nir_ieq_imm(b, cem, 6), nir_ieq_imm(b, cem, 10)), scaled[e], result);
      result = nir_bcsel(b, nir_ior(b, nir_ieq_imm(b, cem, 9), nir_ieq_imm(b, cem, 13)), offset[e], result);
      if (e)
         *e1 = result;
      else
         *e0 = result;
   }
}

/* x with bit << shift set when mode's bit in mask is: the HDR endpoint
 * modes scatter their values' high bits by a mode. */
static nir_def *astc_or_if(nir_builder *b, nir_def *x, nir_def *mode, unsigned mask, nir_def *bit,
                           unsigned shift)
{
   nir_def *set = nir_ine_imm(b, nir_iand_imm(b, nir_ishl(b, nir_imm_int(b, 1), mode), mask), 0);
   return nir_ior(b, x, nir_bcsel(b, set, nir_ishl_imm(b, bit, shift), nir_imm_int(b, 0)));
}

static nir_def *astc_clamp12(nir_builder *b, nir_def *v)
{
   return nir_imin(b, nir_imax(b, v, nir_imm_int(b, 0)), nir_imm_int(b, 0xfff));
}

static nir_def *astc_bit(nir_builder *b, nir_def *v, unsigned bit)
{
   return field(b, v, bit, 1);
}

/* HDR endpoint mode 11's 12-bit RGB endpoints from v[0] to v[5]. */
static void astc_hdr_rgb(nir_builder *b, nir_def *const v[8], nir_def *e0[3], nir_def *e1[3])
{
   nir_def *major = nir_ior(b, astc_bit(b, v[4], 7), nir_ishl_imm(b, astc_bit(b, v[5], 7), 1));
   nir_def *mode = nir_ior(b, nir_ior(b, astc_bit(b, v[1], 7), nir_ishl_imm(b, astc_bit(b, v[2], 7), 1)),
                           nir_ishl_imm(b, astc_bit(b, v[3], 7), 2));
   nir_def *va = nir_ior(b, v[0], nir_ishl_imm(b, nir_iand_imm(b, v[1], 0x40), 2));
   nir_def *vb0 = nir_iand_imm(b, v[2], 0x3f), *vb1 = nir_iand_imm(b, v[3], 0x3f);
   nir_def *vc = nir_iand_imm(b, v[1], 0x3f);
   static const unsigned dbits[8] = {7, 6, 7, 6, 5, 6, 5, 6};
   nir_def *unused = nir_isub_imm(b, 32, lookup(b, dbits, 8, mode));
   nir_def *vd0 = nir_ishr(b, nir_ishl(b, nir_iand_imm(b, v[4], 0x7f), unused), unused);
   nir_def *vd1 = nir_ishr(b, nir_ishl(b, nir_iand_imm(b, v[5], 0x7f), unused), unused);
   nir_def *x0 = astc_bit(b, v[2], 6), *x1 = astc_bit(b, v[3], 6), *x2 = astc_bit(b, v[4], 6);
   nir_def *x3 = astc_bit(b, v[5], 6), *x4 = astc_bit(b, v[4], 5), *x5 = astc_bit(b, v[5], 5);
   va = astc_or_if(b, va, mode, 0xa4, x0, 9);
   va = astc_or_if(b, va, mode, 0x08, x2, 9);
   va = astc_or_if(b, va, mode, 0x50, x4, 9);
   va = astc_or_if(b, va, mode, 0x50, x5, 10);
   va = astc_or_if(b, va, mode, 0xa0, x1, 10);
   va = astc_or_if(b, va, mode, 0xc0, x2, 11);
   vc = astc_or_if(b, vc, mode, 0x04, x1, 6);
   vc = astc_or_if(b, vc, mode, 0xe8, x3, 6);
   vc = astc_or_if(b, vc, mode, 0x20, x2, 7);
   vb0 = astc_or_if(b, vb0, mode, 0x5b, x0, 6);
   vb1 = astc_or_if(b, vb1, mode, 0x5b, x1, 6);
   vb0 = astc_or_if(b, vb0, mode, 0x12, x2, 7);
   vb1 = astc_or_if(b, vb1, mode, 0x12, x3, 7);
   nir_def *shift = nir_ixor(b, nir_ushr_imm(b, mode, 1), nir_imm_int(b, 3));
   va = nir_ishl(b, va, shift);
   vb0 = nir_ishl(b, vb0, shift);
   vb1 = nir_ishl(b, vb1, shift);
   vc = nir_ishl(b, vc, shift);
   vd0 = nir_ishl(b, vd0, shift);
   vd1 = nir_ishl(b, vd1, shift);
   nir_def *high[3] = {va, nir_isub(b, va, vb0), nir_isub(b, va, vb1)};
   nir_def *low[3] = {nir_isub(b, va, vc), nir_isub(b, nir_isub(b, nir_isub(b, va, vb0), vc), vd0),
                      nir_isub(b, nir_isub(b, nir_isub(b, va, vb1), vc), vd1)};
   /* The major component first, its values unscattered in mode 3. */
   nir_def *direct = nir_ieq_imm(b, major, 3);
   nir_def *direct0[3] = {nir_ishl_imm(b, v[0], 4), nir_ishl_imm(b, v[2], 4),
                          nir_ishl_imm(b, nir_iand_imm(b, v[4], 0x7f), 5)};
   nir_def *direct1[3] = {nir_ishl_imm(b, v[1], 4), nir_ishl_imm(b, v[3], 4),
                          nir_ishl_imm(b, nir_iand_imm(b, v[5], 0x7f), 5)};
   /* Major 1 swaps red and green, 2 red and blue. */
   nir_def *one = nir_ieq_imm(b, major, 1), *two = nir_ieq_imm(b, major, 2);
   nir_def *const *ends[2] = {low, high};
   nir_def **out[2] = {e0, e1};
   nir_def *const *directs[2] = {direct0, direct1};
   for (unsigned e = 0; e < 2; e++) {
      nir_def *const *x = ends[e];
      nir_def *swapped[3] = {
         nir_bcsel(b, one, x[1], nir_bcsel(b, two, x[2], x[0])),
         nir_bcsel(b, one, x[0], x[1]),
         nir_bcsel(b, two, x[0], x[2]),
      };
      for (unsigned c = 0; c < 3; c++)
         out[e][c] = nir_bcsel(b, direct, directs[e][c], astc_clamp12(b, swapped[c]));
   }
}

/* HDR endpoint mode 7's 12-bit RGB endpoints: a base and a scale below it. */
static void astc_hdr_rgb_scale(nir_builder *b, nir_def *const v[8], nir_def *e0[3], nir_def *e1[3])
{
   nir_def *modeval = nir_ior(b, nir_ior(b, field(b, v[0], 6, 2), nir_ishl_imm(b, astc_bit(b, v[1], 7), 2)),
                              nir_ishl_imm(b, astc_bit(b, v[2], 7), 3));
   nir_def *split = nir_ine_imm(b, nir_iand_imm(b, modeval, 0xc), 0xc);
   nir_def *all = nir_ieq_imm(b, modeval, 0xf);
   nir_def *major = nir_bcsel(b, split, nir_ushr_imm(b, modeval, 2),
                              nir_bcsel(b, all, nir_imm_int(b, 0), nir_iand_imm(b, modeval, 3)));
   nir_def *mode = nir_bcsel(b, split, nir_iand_imm(b, modeval, 3),
                             nir_bcsel(b, all, nir_imm_int(b, 5), nir_imm_int(b, 4)));
   nir_def *red = nir_iand_imm(b, v[0], 0x3f), *green = nir_iand_imm(b, v[1], 0x1f);
   nir_def *blue = nir_iand_imm(b, v[2], 0x1f), *scale = nir_iand_imm(b, v[3], 0x1f);
   nir_def *x0 = astc_bit(b, v[1], 6), *x1 = astc_bit(b, v[1], 5), *x2 = astc_bit(b, v[2], 6);
   nir_def *x3 = astc_bit(b, v[2], 5), *x4 = astc_bit(b, v[3], 7), *x5 = astc_bit(b, v[3], 6);
   nir_def *x6 = astc_bit(b, v[3], 5);
   green = astc_or_if(b, green, mode, 0x30, x0, 6);
   green = astc_or_if(b, green, mode, 0x3a, x1, 5);
   blue = astc_or_if(b, blue, mode, 0x30, x2, 6);
   blue = astc_or_if(b, blue, mode, 0x3a, x3, 5);
   scale = astc_or_if(b, scale, mode, 0x3d, x6, 5);
   scale = astc_or_if(b, scale, mode, 0x2d, x5, 6);
   scale = astc_or_if(b, scale, mode, 0x04, x4, 7);
   red = astc_or_if(b, red, mode, 0x3b, x4, 6);
   red = astc_or_if(b, red, mode, 0x04, x3, 6);
   red = astc_or_if(b, red, mode, 0x10, x5, 7);
   red = astc_or_if(b, red, mode, 0x0f, x2, 7);
   red = astc_or_if(b, red, mode, 0x05, x1, 8);
   red = astc_or_if(b, red, mode, 0x0a, x0, 8);
   red = astc_or_if(b, red, mode, 0x05, x0, 9);
   red = astc_or_if(b, red, mode, 0x02, x6, 9);
   red = astc_or_if(b, red, mode, 0x01, x3, 10);
   red = astc_or_if(b, red, mode, 0x02, x5, 10);
   static const unsigned shifts[6] = {1, 1, 2, 3, 4, 5};
   nir_def *shift = lookup(b, shifts, 6, mode);
   red = nir_ishl(b, red, shift);
   green = nir_ishl(b, green, shift);
   blue = nir_ishl(b, blue, shift);
   scale = nir_ishl(b, scale, shift);
   nir_def *offsets = nir_ine_imm(b, mode, 5);
   green = nir_bcsel(b, offsets, nir_isub(b, red, green), green);
   blue = nir_bcsel(b, offsets, nir_isub(b, red, blue), blue);
   nir_def *swapped[3] = {
      nir_bcsel(b, nir_ieq_imm(b, major, 1), green, nir_bcsel(b, nir_ieq_imm(b, major, 2), blue, red)),
      nir_bcsel(b, nir_ieq_imm(b, major, 1), red, green),
      nir_bcsel(b, nir_ieq_imm(b, major, 2), red, blue),
   };
   for (unsigned c = 0; c < 3; c++) {
      e1[c] = astc_clamp12(b, swapped[c]);
      e0[c] = astc_clamp12(b, nir_isub(b, swapped[c], scale));
   }
}

/* A partition's endpoints in an HDR texture, 16 bits a channel: HDR
 * endpoint modes' 12-bit logarithmic values shifted up, and LDR modes'
 * 8-bit values widened. *rgb_hdr and *alpha_hdr say which channels are
 * logarithmic. */
static void astc_hdr_endpoints(nir_builder *b, nir_def *cem, nir_def *const v[8], nir_def *ldr0,
                               nir_def *ldr1, nir_def **e0, nir_def **e1, nir_def **rgb_hdr,
                               nir_def **alpha_hdr)
{
   /* Mode 2: luminance, large range. */
   nir_def *ordered = nir_uge(b, v[1], v[0]);
   nir_def *large0 = nir_bcsel(b, ordered, nir_ishl_imm(b, v[0], 4), nir_iadd_imm(b, nir_ishl_imm(b, v[1], 4), 8));
   nir_def *large1 = nir_bcsel(b, ordered, nir_ishl_imm(b, v[1], 4), nir_iadd_imm(b, nir_ishl_imm(b, v[0], 4), -8));
   /* Mode 3: luminance, small range. */
   nir_def *coarse = nir_test_mask(b, v[0], 0x80);
   nir_def *small0 = nir_bcsel(
      b, coarse, nir_ior(b, nir_ishl_imm(b, nir_iand_imm(b, v[1], 0xe0), 4), nir_ishl_imm(b, nir_iand_imm(b, v[0], 0x7f), 2)),
      nir_ior(b, nir_ishl_imm(b, nir_iand_imm(b, v[1], 0xf0), 4), nir_ishl_imm(b, nir_iand_imm(b, v[0], 0x7f), 1)));
   nir_def *d = nir_bcsel(b, coarse, nir_ishl_imm(b, nir_iand_imm(b, v[1], 0x1f), 2),
                          nir_ishl_imm(b, nir_iand_imm(b, v[1], 0x0f), 1));
   nir_def *small1 = nir_imin(b, nir_iadd(b, small0, d), nir_imm_int(b, 0xfff));
   nir_def *scaled0[3], *scaled1[3], *direct0[3], *direct1[3];
   astc_hdr_rgb_scale(b, v, scaled0, scaled1);
   astc_hdr_rgb(b, v, direct0, direct1);
   /* Mode 15's alpha: two 7-bit values, or a base and a signed offset. */
   nir_def *selector = nir_ior(b, astc_bit(b, v[6], 7), nir_ishl_imm(b, astc_bit(b, v[7], 7), 1));
   nir_def *a6 = nir_iand_imm(b, v[6], 0x7f), *a7 = nir_iand_imm(b, v[7], 0x7f);
   nir_def *base = nir_ior(b, a6, nir_iand_imm(b, nir_ishl(b, a7, nir_iadd_imm(b, selector, 1)), 0x780));
   nir_def *half = nir_ushr(b, nir_imm_int(b, 32), selector);
   nir_def *offset = nir_isub(b, nir_ixor(b, nir_iand(b, a7, nir_ushr(b, nir_imm_int(b, 0x3f), selector)), half), half);
   nir_def *up = nir_isub_imm(b, 4, selector);
   base = nir_ishl(b, base, up);
   nir_def *packed = nir_ieq_imm(b, selector, 3);
   nir_def *alpha0 = nir_bcsel(b, packed, nir_ishl_imm(b, a6, 5), base);
   nir_def *alpha1 = nir_bcsel(b, packed, nir_ishl_imm(b, a7, 5),
                               astc_clamp12(b, nir_iadd(b, base, nir_ishl(b, offset, up))));
   nir_def *one = nir_imm_int(b, 0x780);
   nir_def *rgb0[3], *rgb1[3];
   for (unsigned c = 0; c < 3; c++) {
      rgb0[c] = nir_bcsel(b, nir_ieq_imm(b, cem, 2), large0,
                          nir_bcsel(b, nir_ieq_imm(b, cem, 3), small0,
                                    nir_bcsel(b, nir_ieq_imm(b, cem, 7), scaled0[c], direct0[c])));
      rgb1[c] = nir_bcsel(b, nir_ieq_imm(b, cem, 2), large1,
                          nir_bcsel(b, nir_ieq_imm(b, cem, 3), small1,
                                    nir_bcsel(b, nir_ieq_imm(b, cem, 7), scaled1[c], direct1[c])));
   }
   nir_def *ldr_alpha = nir_ieq_imm(b, cem, 14);
   nir_def *a0 = nir_bcsel(b, nir_ieq_imm(b, cem, 15), alpha0, one);
   nir_def *a1 = nir_bcsel(b, nir_ieq_imm(b, cem, 15), alpha1, one);
   nir_def *hdr0 = nir_ishl_imm(b, nir_vec4(b, rgb0[0], rgb0[1], rgb0[2], a0), 4);
   nir_def *hdr1 = nir_ishl_imm(b, nir_vec4(b, rgb1[0], rgb1[1], rgb1[2], a1), 4);
   /* Mode 14's alpha is LDR, widened as LDR modes' channels are. */
   hdr0 = nir_vector_insert_imm(b, hdr0, nir_bcsel(b, ldr_alpha, nir_imul_imm(b, v[6], 257), nir_channel(b, hdr0, 3)), 3);
   hdr1 = nir_vector_insert_imm(b, hdr1, nir_bcsel(b, ldr_alpha, nir_imul_imm(b, v[7], 257), nir_channel(b, hdr1, 3)), 3);
   *rgb_hdr = nir_ior(b, nir_ior(b, nir_ieq_imm(b, cem, 2), nir_ieq_imm(b, cem, 3)),
                      nir_ior(b, nir_ieq_imm(b, cem, 7), nir_ior(b, nir_ieq_imm(b, cem, 11), nir_uge_imm(b, cem, 14))));
   *alpha_hdr = nir_iand(b, *rgb_hdr, nir_inot(b, ldr_alpha));
   *e0 = nir_bcsel(b, *rgb_hdr, hdr0, ldr0);
   *e1 = nir_bcsel(b, *rgb_hdr, hdr1, ldr1);
}

/* A logarithmic 16-bit value's half float: its top 5 bits the exponent,
 * the mantissa's 11 bits mapped piecewise linearly to 10, clamped below
 * infinity. */
static nir_def *astc_lns_to_half(nir_builder *b, nir_def *c)
{
   nir_def *e = nir_ushr_imm(b, c, 11), *m = nir_iand_imm(b, c, 0x7ff);
   nir_def *mt = nir_bcsel(b, nir_ult_imm(b, m, 512), nir_imul_imm(b, m, 3),
                           nir_bcsel(b, nir_uge_imm(b, m, 1536), nir_iadd_imm(b, nir_imul_imm(b, m, 5), -2048),
                                     nir_iadd_imm(b, nir_imul_imm(b, m, 4), -512)));
   nir_def *h = nir_iadd(b, nir_ishl_imm(b, e, 10), nir_ushr_imm(b, mt, 3));
   return nir_umin(b, h, nir_imm_int(b, 0x7bff));
}

/* A UNORM16 value's half float, c / 65535 rounded to nearest: c / 65535
 * never falls halfway between halves, and only 65535 reaches 1. */
static nir_def *astc_unorm16_to_half(nir_builder *b, nir_def *c)
{
   nir_def *top = nir_ufind_msb(b, nir_imax(b, c, nir_imm_int(b, 1)));
   /* 2^(top - 16) <= c / 65535 < 2^(top - 15): 11 bits of mantissa. */
   nir_def *scaled = nir_ishl(b, c, nir_isub_imm(b, 26, top));
   nir_def *m = nir_udiv_imm(b, scaled, 65535);
   nir_def *normal = nir_iadd(b, nir_ishl_imm(b, nir_iadd_imm(b, top, -1), 10), nir_iadd_imm(b, m, -1024));
   /* Below 2^-14, c < 4: a subnormal's 2^-24 steps. */
   nir_def *subnormal = nir_udiv_imm(b, nir_iadd_imm(b, nir_ishl_imm(b, c, 24), 32767), 65535);
   nir_def *h = nir_bcsel(b, nir_ult_imm(b, c, 4), subnormal, normal);
   return nir_bcsel(b, nir_ieq_imm(b, c, 0xffff), nir_imm_int(b, 0x3c00), h);
}

nir_def *stela_metal_decode_astc(nir_builder *b, nir_def *words, nir_def *x, nir_def *y,
                                 nir_def *block_width, nir_def *block_height, nir_def *srgb,
                                 nir_def *hdr_texture)
{
   nir_def *w[4];
   for (unsigned i = 0; i < 4; i++)
      w[i] = nir_channel(b, words, i);
   nir_def *mode = astc_field(b, w, 0, 11);

   /* The weight grid: Khronos's block mode layouts. */
   nir_def *a = field(b, mode, 5, 2), *bb = field(b, mode, 7, 2);
   nir_def *layout = field(b, mode, 2, 2);
   nir_def *tall = nir_test_mask(b, bb, 2);
   nir_def *a2 = nir_iadd_imm(b, a, 2);
   nir_def *wide_w = nir_bcsel(
      b, nir_ieq_imm(b, layout, 0), nir_iadd_imm(b, bb, 4),
      nir_bcsel(b, nir_ieq_imm(b, layout, 1), nir_iadd_imm(b, bb, 8),
                nir_bcsel(b, nir_ior(b, nir_ieq_imm(b, layout, 2), nir_inot(b, tall)), a2,
                          nir_iadd_imm(b, nir_iand_imm(b, bb, 1), 2))));
   nir_def *wide_h = nir_bcsel(
      b, nir_ult_imm(b, layout, 2), a2,
      nir_bcsel(b, nir_ieq_imm(b, layout, 2), nir_iadd_imm(b, bb, 8),
                nir_bcsel(b, tall, a2, nir_iadd_imm(b, bb, 6))));
   nir_def *wide_range = nir_ior(b, nir_ishl_imm(b, field(b, mode, 0, 2), 1), field(b, mode, 4, 1));
   nir_def *other = field(b, mode, 7, 2), *bit5 = nir_test_mask(b, mode, 1 << 5);
   nir_def *square = nir_ieq_imm(b, other, 2);
   nir_def *narrow_w = nir_bcsel(
      b, nir_ieq_imm(b, other, 0), nir_imm_int(b, 12),
      nir_bcsel(b, nir_ieq_imm(b, other, 1), a2,
                nir_bcsel(b, square, nir_iadd_imm(b, a, 6),
                          nir_bcsel(b, bit5, nir_imm_int(b, 10), nir_imm_int(b, 6)))));
   nir_def *narrow_h = nir_bcsel(
      b, nir_ieq_imm(b, other, 0), a2,
      nir_bcsel(b, nir_ieq_imm(b, other, 1), nir_imm_int(b, 12),
                nir_bcsel(b, square, nir_iadd_imm(b, field(b, mode, 9, 2), 6),
                          nir_bcsel(b, bit5, nir_imm_int(b, 6), nir_imm_int(b, 10)))));
   nir_def *narrow_range = nir_ior(b, field(b, mode, 4, 1), nir_ishl_imm(b, field(b, mode, 2, 2), 1));
   nir_def *narrow = nir_ieq_imm(b, field(b, mode, 0, 2), 0);
   nir_def *grid_w = nir_bcsel(b, narrow, narrow_w, wide_w);
   nir_def *grid_h = nir_bcsel(b, narrow, narrow_h, wide_h);
   nir_def *range = nir_bcsel(b, narrow, narrow_range, wide_range);
   nir_def *plain = nir_iand(b, narrow, square);
   nir_def *dual = nir_iand(b, nir_test_mask(b, mode, 1 << 10), nir_inot(b, plain));
   nir_def *precise = nir_iand(b, nir_test_mask(b, mode, 1 << 9), nir_inot(b, plain));
   nir_def *void_extent = nir_ieq_imm(b, nir_iand_imm(b, mode, 0x1ff), 0x1fc);
   nir_def *reserved = nir_iand(
      b, narrow, nir_ior(b, nir_iand(b, nir_ieq_imm(b, field(b, mode, 6, 3), 7), nir_inot(b, void_extent)),
                         nir_ieq_imm(b, field(b, mode, 0, 4), 0)));

   /* The weights' sequence, from the block's top bit down. */
   nir_def *quant = nir_iadd(b, range, nir_bcsel(b, precise, nir_imm_int(b, 8), nir_imm_int(b, 0)));
   static const unsigned weight_trits[16] = {0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0};
   static const unsigned weight_quints[16] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0};
   static const unsigned weight_bits[16] = {0, 0, 1, 0, 2, 0, 1, 3, 0, 0, 1, 2, 4, 2, 3, 5};
   nir_def *planes = nir_bcsel(b, dual, nir_imm_int(b, 2), nir_imm_int(b, 1));
   nir_def *count = nir_imul(b, nir_imul(b, grid_w, grid_h), planes);
   struct astc_sequence weights = {
      .start = nir_imm_int(b, 0),
      .bits = lookup(b, weight_bits, 16, quant),
      .trits = nir_ine_imm(b, lookup(b, weight_trits, 16, quant), 0),
      .quints = nir_ine_imm(b, lookup(b, weight_quints, 16, quant), 0),
   };
   nir_def *weight_size = nir_iadd(
      b, nir_imul(b, count, weights.bits),
      nir_bcsel(b, weights.trits, nir_udiv_imm(b, nir_iadd_imm(b, nir_imul_imm(b, count, 8), 4), 5),
                nir_bcsel(b, weights.quints, nir_udiv_imm(b, nir_iadd_imm(b, nir_imul_imm(b, count, 7), 2), 3),
                          nir_imm_int(b, 0))));
   weights.end = weight_size;
   nir_def *top = nir_isub_imm(b, 128, weight_size);

   /* Partitions and their endpoint modes. */
   nir_def *partitions = nir_iadd_imm(b, astc_field(b, w, 11, 2), 1);
   nir_def *single = nir_ieq_imm(b, partitions, 1);
   nir_def *selector = astc_field(b, w, 23, 6);
   nir_def *shared = nir_ior(b, single, nir_ieq_imm(b, nir_iand_imm(b, selector, 3), 0));
   nir_def *class = nir_iadd_imm(b, nir_iand_imm(b, selector, 3), -1);
   nir_def *two = nir_ieq_imm(b, partitions, 2), *three = nir_ieq_imm(b, partitions, 3);
   nir_def *at[4] = {
      nir_iadd_imm(b, top, -8), nir_iadd_imm(b, top, -6), nir_iadd_imm(b, top, -4), nir_iadd_imm(b, top, -2),
   };
   nir_def *low[4] = {
      nir_bcsel(b, two, astc_field(b, w, 27, 2),
                nir_bcsel(b, three,
                          nir_ior(b, astc_field(b, w, 28, 1),
                                  nir_ishl_imm(b, astc_at(b, w, nir_iadd_imm(b, top, -5), 1), 1)),
                          astc_at(b, w, at[0], 2))),
      nir_bcsel(b, two, astc_at(b, w, at[3], 2),
                nir_bcsel(b, three, astc_at(b, w, at[2], 2), astc_at(b, w, at[1], 2))),
      nir_bcsel(b, three, astc_at(b, w, at[3], 2), astc_at(b, w, at[2], 2)),
      astc_at(b, w, at[3], 2),
   };
   nir_def *one_mode = nir_bcsel(b, single, astc_field(b, w, 13, 4), nir_ushr_imm(b, selector, 2));
   nir_def *cems[4], *value_counts[4];
   nir_def *values = nir_imm_int(b, 0);
   for (unsigned p = 0; p < 4; p++) {
      nir_def *own = nir_ior(b, nir_ishl_imm(b, nir_iadd(b, class, astc_field(b, w, 25 + p, 1)), 2), low[p]);
      cems[p] = nir_bcsel(b, shared, one_mode, own);
      value_counts[p] = nir_bcsel(b, nir_ult_imm(b, partitions, p + 1), nir_imm_int(b, 0),
                                  nir_iadd_imm(b, nir_ushr_imm(b, nir_iand_imm(b, cems[p], ~3u), 1), 2));
      values = nir_iadd(b, values, value_counts[p]);
   }
   nir_def *extra = nir_bcsel(b, shared, nir_imm_int(b, 0),
                              nir_bcsel(b, two, nir_imm_int(b, 2), nir_bcsel(b, three, nir_imm_int(b, 5), nir_imm_int(b, 8))));
   nir_def *config = nir_bcsel(b, single, nir_imm_int(b, 17), nir_iadd_imm(b, extra, 29));
   nir_def *selector_bits = nir_bcsel(b, dual, nir_imm_int(b, 2), nir_imm_int(b, 0));
   nir_def *remaining = nir_isub(b, nir_isub(b, top, config), selector_bits);

   /* The endpoints' sequence: the finest range that fits what is left. */
   static const unsigned color_trits[17] = {1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0};
   static const unsigned color_quints[17] = {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0};
   static const unsigned color_bits[17] = {1, 3, 1, 2, 4, 2, 3, 5, 3, 4, 6, 4, 5, 7, 5, 6, 8};
   struct astc_sequence colors = {
      .start = nir_bcsel(b, single, nir_imm_int(b, 17), nir_imm_int(b, 29)),
      .bits = nir_imm_int(b, 0),
      .trits = nir_imm_false(b),
      .quints = nir_imm_false(b),
   };
   nir_def *color_size = nir_imm_int(b, 0);
   for (unsigned i = 0; i < 17; i++) {
      nir_def *size = nir_imul_imm(b, values, color_bits[i]);
      if (color_trits[i])
         size = nir_iadd(b, size, nir_udiv_imm(b, nir_iadd_imm(b, nir_imul_imm(b, values, 8), 4), 5));
      if (color_quints[i])
         size = nir_iadd(b, size, nir_udiv_imm(b, nir_iadd_imm(b, nir_imul_imm(b, values, 7), 2), 3));
      nir_def *fits = nir_ige(b, remaining, size);
      colors.bits = nir_bcsel(b, fits, nir_imm_int(b, color_bits[i]), colors.bits);
      colors.trits = nir_bcsel(b, fits, nir_imm_bool(b, color_trits[i]), colors.trits);
      colors.quints = nir_bcsel(b, fits, nir_imm_bool(b, color_quints[i]), colors.quints);
      color_size = nir_bcsel(b, fits, size, color_size);
   }
   colors.end = nir_iadd(b, colors.start, color_size);

   nir_def *error = nir_ior(
      b, nir_ior(b, reserved, nir_ior(b, nir_ult(b, block_width, grid_w), nir_ult(b, block_height, grid_h))),
      nir_ior(b, nir_iand(b, dual, nir_ieq_imm(b, partitions, 4)),
              nir_ior(b, nir_ior(b, nir_ugt_imm(b, count, 64), nir_ult_imm(b, weight_size, 24)),
                      nir_ior(b, nir_ugt_imm(b, weight_size, 96),
                              nir_ior(b, nir_ugt_imm(b, values, 18),
                                      nir_ilt(b, remaining,
                                              nir_udiv_imm(b, nir_iadd_imm(b, nir_imul_imm(b, values, 13), 4), 5)))))));

   /* The texel's partition, its endpoint mode and values. */
   nir_def *small = nir_ult_imm(b, nir_imul(b, block_width, block_height), 31);
   nir_def *partition = nir_bcsel(b, single, nir_imm_int(b, 0),
                                  astc_partition(b, astc_field(b, w, 13, 10), partitions, x, y, small));
   nir_def *firsts[4] = {nir_imm_int(b, 0), value_counts[0], nir_iadd(b, value_counts[0], value_counts[1]),
                         nir_iadd(b, nir_iadd(b, value_counts[0], value_counts[1]), value_counts[2])};
   nir_def *first = pick(b, firsts, 4, partition);
   nir_def *cem = pick(b, cems, 4, partition);
   nir_def *v[8];
   for (unsigned i = 0; i < 8; i++)
      v[i] = astc_color_value(b, astc_value(b, w, &colors, nir_iadd_imm(b, first, i)), &colors);
   nir_def *e0, *e1;
   astc_endpoints(b, cem, v, &e0, &e1);
   nir_def *hdr = nir_ior(b, nir_ior(b, nir_ieq_imm(b, cem, 2), nir_ieq_imm(b, cem, 3)),
                          nir_ior(b, nir_ieq_imm(b, cem, 7),
                                  nir_ior(b, nir_ieq_imm(b, cem, 11), nir_uge_imm(b, cem, 14))));

   /* The texel's weights, bilinear between the grid's. */
   nir_def *reversed[4];
   for (unsigned i = 0; i < 4; i++)
      reversed[i] = nir_bitfield_reverse(b, w[3 - i]);
   nir_def *ds = nir_udiv(b, nir_iadd_imm(b, nir_ushr_imm(b, block_width, 1), 1024), nir_iadd_imm(b, block_width, -1));
   nir_def *dt = nir_udiv(b, nir_iadd_imm(b, nir_ushr_imm(b, block_height, 1), 1024), nir_iadd_imm(b, block_height, -1));
   nir_def *gs = nir_ushr_imm(b, nir_iadd_imm(b, nir_imul(b, nir_imul(b, ds, x), nir_iadd_imm(b, grid_w, -1)), 32), 6);
   nir_def *gt = nir_ushr_imm(b, nir_iadd_imm(b, nir_imul(b, nir_imul(b, dt, y), nir_iadd_imm(b, grid_h, -1)), 32), 6);
   nir_def *fs = nir_iand_imm(b, gs, 15), *ft = nir_iand_imm(b, gt, 15);
   nir_def *v0 = nir_iadd(b, nir_ushr_imm(b, gs, 4), nir_imul(b, nir_ushr_imm(b, gt, 4), grid_w));
   nir_def *w11 = nir_ushr_imm(b, nir_iadd_imm(b, nir_imul(b, fs, ft), 8), 4);
   nir_def *factors[4] = {nir_iadd(b, nir_isub(b, nir_isub_imm(b, 16, fs), ft), w11), nir_isub(b, fs, w11),
                          nir_isub(b, ft, w11), w11};
   nir_def *corners[4] = {v0, nir_iadd_imm(b, v0, 1), nir_iadd(b, v0, grid_w), nir_iadd_imm(b, nir_iadd(b, v0, grid_w), 1)};
   nir_def *infill[2];
   for (unsigned plane = 0; plane < 2; plane++) {
      nir_def *sum = nir_imm_int(b, 8);
      for (unsigned i = 0; i < 4; i++) {
         nir_def *index = nir_iadd_imm(b, nir_imul(b, corners[i], planes), plane);
         nir_def *value = astc_weight_value(b, astc_value(b, reversed, &weights, index), &weights);
         sum = nir_iadd(b, sum, nir_imul(b, value, factors[i]));
      }
      infill[plane] = nir_ushr_imm(b, sum, 4);
   }
   nir_def *component = astc_at(b, w, nir_isub(b, nir_iadd_imm(b, top, -2), extra), 2);
   nir_def *weight[4];
   for (unsigned c = 0; c < 4; c++)
      weight[c] = nir_bcsel(b, nir_iand(b, dual, nir_ieq_imm(b, component, c)), infill[1], infill[0]);
   nir_def *wv = nir_vec4(b, weight[0], weight[1], weight[2], weight[3]);

   /* Endpoints widened to 16 bits, sRGB's with its half-step, blended. An
    * HDR texture's HDR endpoint modes give logarithmic channels. */
   nir_def *half = nir_imm_int(b, 0x80);
   nir_def *c0 = nir_ior(b, nir_ishl_imm(b, e0, 8), nir_bcsel(b, srgb, half, e0));
   nir_def *c1 = nir_ior(b, nir_ishl_imm(b, e1, 8), nir_bcsel(b, srgb, half, e1));
   nir_def *h0, *h1, *rgb_hdr, *alpha_hdr;
   astc_hdr_endpoints(b, cem, v, c0, c1, &h0, &h1, &rgb_hdr, &alpha_hdr);
   c0 = nir_bcsel(b, hdr_texture, h0, c0);
   c1 = nir_bcsel(b, hdr_texture, h1, c1);
   nir_def *color = nir_ushr_imm(
      b, nir_iadd_imm(b, nir_iadd(b, nir_imul(b, c0, nir_isub_imm(b, 64, wv)), nir_imul(b, c1, wv)), 32), 6);

   /* A void extent's constant color; it is LDR, with its reserved bits
    * set, and its extent all ones or not empty. */
   nir_def *constant = nir_vec4(b, astc_field(b, w, 64, 16), astc_field(b, w, 80, 16),
                                astc_field(b, w, 96, 16), astc_field(b, w, 112, 16));
   nir_def *min_s = astc_field(b, w, 12, 13), *max_s = astc_field(b, w, 25, 13);
   nir_def *min_t = astc_field(b, w, 38, 13), *max_t = astc_field(b, w, 51, 13);
   nir_def *unbounded = nir_iand(b, nir_iand(b, nir_ieq_imm(b, min_s, 0x1fff), nir_ieq_imm(b, max_s, 0x1fff)),
                                 nir_iand(b, nir_ieq_imm(b, min_t, 0x1fff), nir_ieq_imm(b, max_t, 0x1fff)));
   nir_def *empty = nir_ior(b, nir_uge(b, min_s, max_s), nir_uge(b, min_t, max_t));
   /* An HDR texture's void extent may hold half floats, flagged by bit 9. */
   nir_def *half_void = nir_iand(b, hdr_texture, nir_test_mask(b, mode, 1 << 9));
   nir_def *reserved_void = nir_bcsel(b, hdr_texture, nir_ine_imm(b, astc_field(b, w, 10, 2), 3),
                                      nir_ine_imm(b, astc_field(b, w, 9, 3), 6));
   nir_def *bad_void = nir_ior(b, reserved_void, nir_iand(b, nir_inot(b, unbounded), empty));

   nir_def *magenta = nir_imm_ivec4(b, 0xffff, 0, 0xffff, 0xffff);
   nir_def *failed = nir_ior(b, error, nir_iand(b, hdr, nir_inot(b, hdr_texture)));
   color = nir_bcsel(b, failed, magenta, color);
   color = nir_bcsel(b, void_extent, nir_bcsel(b, bad_void, magenta, constant), color);
   nir_def *blended = nir_inot(b, nir_ior(b, failed, void_extent));

   /* sRGB keeps 8 bits; linear 12, read as unorm and widened to 16. */
   nir_def *byte = nir_ushr_imm(b, color, 8);
   nir_def *twelve = nir_ushr_imm(b, color, 4);
   nir_def *wide = nir_ior(b, nir_ishl_imm(b, twelve, 4), nir_ushr_imm(b, twelve, 8));
   nir_def *packed8 = nir_ior(b, nir_ior(b, nir_channel(b, byte, 0), nir_ishl_imm(b, nir_channel(b, byte, 1), 8)),
                              nir_ior(b, nir_ishl_imm(b, nir_channel(b, byte, 2), 16),
                                      nir_ishl_imm(b, nir_channel(b, byte, 3), 24)));
   nir_def *low16 = nir_ior(b, nir_channel(b, wide, 0), nir_ishl_imm(b, nir_channel(b, wide, 1), 16));
   nir_def *high16 = nir_ior(b, nir_channel(b, wide, 2), nir_ishl_imm(b, nir_channel(b, wide, 3), 16));

   /* An HDR texture's halves: logarithmic channels through their curve,
    * UNORM16 ones divided, a half-float void extent's as they are. */
   nir_def *halves[4];
   for (unsigned c = 0; c < 4; c++) {
      nir_def *value = nir_channel(b, color, c);
      nir_def *logarithmic = nir_iand(b, blended, c == 3 ? alpha_hdr : rgb_hdr);
      nir_def *h = nir_bcsel(b, logarithmic, astc_lns_to_half(b, value), astc_unorm16_to_half(b, value));
      halves[c] = nir_bcsel(b, nir_iand(b, void_extent, nir_iand(b, half_void, nir_inot(b, bad_void))), value, h);
   }
   nir_def *low_half = nir_ior(b, halves[0], nir_ishl_imm(b, halves[1], 16));
   nir_def *high_half = nir_ior(b, halves[2], nir_ishl_imm(b, halves[3], 16));
   /* An HDR texture's error color is four NaNs. */
   nir_def *invalid = nir_bcsel(b, void_extent, bad_void, failed);
   nir_def *nan = nir_imm_int(b, 0x7e007e00);
   low16 = nir_bcsel(b, hdr_texture, nir_bcsel(b, invalid, nan, low_half), low16);
   high16 = nir_bcsel(b, hdr_texture, nir_bcsel(b, invalid, nan, high_half), high16);
   return nir_vec2(b, nir_bcsel(b, srgb, packed8, low16), nir_bcsel(b, srgb, nir_imm_int(b, 0), high16));
}

static nir_def *astc_block_bytes(nir_builder *b, nir_def *codec)
{
   (void)codec;
   return nir_imm_int(b, 16);
}

nir_shader *stela_metal_decode_astc_kernel(const nir_shader_compiler_options *options)
{
   struct blocks k;
   nir_builder b = blocks(options, "stela_metal_decode_astc", astc_block_bytes, &k);
   nir_def *srgb = nir_ieq_imm(&b, k.codec, STELA_METAL_BLOCKS_ASTC_SRGB);
   nir_def *hdr = nir_ieq_imm(&b, k.codec, STELA_METAL_BLOCKS_ASTC_HDR);
   return store_decoded(&b, &k, stela_metal_decode_astc(&b, k.words, k.x, k.y, k.block_width,
                                                        k.block_height, srgb, hdr));
}
