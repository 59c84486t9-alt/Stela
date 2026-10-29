/* SPDX-License-Identifier: MIT */
#include "metal_abi.h"
#include "compiler/nir/nir_format_convert.h"
#include "util/ralloc.h"

static nir_def *load_push(nir_builder *b, unsigned bit_size, unsigned offset)
{
   return nir_load_push_constant(b, 1, bit_size, nir_imm_int(b, 0), .base = (int)offset,
                                 .range = bit_size / 8, .align_mul = bit_size / 8);
}

/* A load of memory nothing writes while the shader runs: the tables and the
 * internal kernels' arguments and results. */
static nir_def *load(nir_builder *b, nir_def *address, unsigned offset, unsigned bit_size)
{
   return nir_load_global(b, 1, bit_size, nir_iadd_imm(b, address, offset),
                          .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER,
                          .align_mul = bit_size / 8);
}

nir_def *stela_metal_load_table(nir_builder *b, enum stela_metal_table table)
{
   return load_push(b, 64, STELA_METAL_PUSH_TABLES + 8u * (unsigned)table);
}

nir_def *stela_metal_load_device_value(nir_builder *b, enum stela_air_device_value value,
                                       void *stage)
{
   (void)stage;
   switch (value) {
   case STELA_AIR_DISPATCH_GRID:
      return nir_load_push_constant(b, 3, 32, nir_imm_int(b, 0), .base = STELA_METAL_PUSH_GRID,
                                    .range = 12, .align_mul = 4);
   case STELA_AIR_AMPLIFICATION:
      return load_push(b, 32, STELA_METAL_PUSH_AMPLIFICATION);
   case STELA_AIR_VIEW_MAPPING:
      return load_push(b, 32, STELA_METAL_PUSH_VIEW_MAPPING);
   case STELA_AIR_THREADGROUP_SHAPE:
      return nir_load_global(b, 3, 32,
                             nir_iadd_imm(b, load_push(b, 64, STELA_METAL_PUSH_ARGUMENTS),
                                          STELA_METAL_DISPATCH_SHAPE),
                             .access = ACCESS_NON_WRITEABLE | ACCESS_CAN_REORDER, .align_mul = 4);
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
   return load(b, load_push(b, 64, STELA_METAL_PUSH_ARGUMENTS),
               STELA_METAL_DISPATCH_OFFSETS + 4u * buffer->index, 32);
}

nir_def *stela_metal_bind_buffer(nir_builder *b, const struct stela_air_buffer *buffer,
                                 void *stage)
{
   const struct stela_metal_stage *metal = stage;
   if (buffer->index >= STELA_METAL_BUFFERS)
      return NULL;
   return load(b, stela_metal_load_table(b, metal->table),
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
   nir_def *first = nir_iand_imm(b, high, (1u << STELA_METAL_LEVEL_SHIFT) - 1);
   if (!level)
      return first;
   nir_def *levels = nir_iadd_imm(b, nir_ushr_imm(b, high, STELA_METAL_LEVEL_SHIFT), 1);
   return nir_bcsel(b, nir_ult(b, level, levels), nir_iadd(b, first, level), nir_imm_int(b, 0));
}

/* The resource ID at offset in the stage's table. */
static nir_def *table_id(nir_builder *b, const struct stela_metal_stage *stage, unsigned offset)
{
   return load(b, stela_metal_load_table(b, stage->table), offset, 64);
}

nir_deref_instr *stela_metal_bind_texture_id(nir_builder *b, nir_def *id,
                                             const struct glsl_type *type, nir_def *level,
                                             void *stage)
{
   (void)stage;
   bool image = glsl_type_is_image(type);
   bool buffer = glsl_get_sampler_dim(type) == GLSL_SAMPLER_DIM_BUF;
   enum stela_metal_heap_array array =
      image ? (buffer ? STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS : STELA_METAL_HEAP_STORAGE_IMAGES)
            : (buffer ? STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS : STELA_METAL_HEAP_SAMPLED_IMAGES);
   nir_def *index = image ? storage_level(b, id, level) : id_half(b, id, false);
   return heap_element(b, index, array, type, image ? nir_var_image : nir_var_uniform);
}

nir_deref_instr *stela_metal_bind_sampler_id(nir_builder *b, nir_def *id, bool integer,
                                             void *stage)
{
   (void)stage;
   return heap_element(b, id_half(b, id, integer), STELA_METAL_HEAP_SAMPLERS,
                       glsl_bare_sampler_type(), nir_var_uniform);
}

nir_deref_instr *stela_metal_bind_texture(nir_builder *b, const struct stela_air_texture *texture,
                                          const struct glsl_type *type, nir_def *level,
                                          void *stage)
{
   if (texture->index >= STELA_METAL_TEXTURES)
      return NULL;
   return stela_metal_bind_texture_id(
      b, table_id(b, stage, STELA_METAL_TABLE_TEXTURES + 8u * texture->index), type, level,
      stage);
}

nir_def *stela_metal_texture_levels(nir_builder *b, const struct stela_air_texture *texture,
                                    nir_def *id, void *stage)
{
   if (!id) {
      if (texture->index >= STELA_METAL_TEXTURES)
         return NULL;
      id = table_id(b, stage, STELA_METAL_TABLE_TEXTURES + 8u * texture->index);
   }
   return nir_iadd_imm(b, nir_ushr_imm(b, id_half(b, id, true), STELA_METAL_LEVEL_SHIFT), 1);
}

nir_deref_instr *stela_metal_bind_sampler(nir_builder *b, const struct stela_air_sampler *sampler,
                                          bool integer, void *stage)
{
   if (sampler->index >= STELA_METAL_SAMPLERS)
      return NULL;
   return stela_metal_bind_sampler_id(
      b, table_id(b, stage, STELA_METAL_TABLE_SAMPLERS + 8u * sampler->index), integer, stage);
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
   return nir_bcsel(b, nir_ult_imm(b, element, length), load(b, address, first, 64),
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

/* A buffer slot of the record's table of the stage, and a vertex buffer's
 * stride word, zero for the pipeline's. */
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
   if (command->binding.stage != STELA_AIR_VERTEX)
      return;
   nir_def *words = load(b, record->buffer, STELA_METAL_INDIRECT_WORDS, 32);
   nir_def *word_count = load(b, record->buffer, STELA_METAL_INDIRECT_WORD_COUNT, 32);
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
   *arguments = load_push(&b, 64, STELA_METAL_PUSH_ARGUMENTS);
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
 * the class's. */
static void resolve_vertex_buffers(nir_builder *b, nir_def *arguments, nir_def *header,
                                   nir_def *record, nir_def *sequence, nir_def *class,
                                   nir_def *inherit_buffers, nir_variable *counter)
{
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
   }
   pop_count(b, counter, index);
}

nir_shader *stela_metal_resolve_kernel(const nir_shader_compiler_options *options)
{
   nir_def *arguments, *thread;
   nir_builder b = kernel(options, "stela_metal_resolve", STELA_METAL_RESOLVE_COUNT, &arguments,
                          &thread);
   nir_variable *counter = nir_local_variable_create(b.impl, glsl_uint_type(), "counter");
   nir_def *header = load(&b, arguments, STELA_METAL_RESOLVE_HEADER, 64);
   nir_def *command = nir_iadd(&b, thread, load(&b, arguments, STELA_METAL_RESOLVE_FIRST, 32));
   nir_def *stride = load(&b, header, STELA_METAL_INDIRECT_STRIDE, 32);
   nir_def *record = nir_iadd(&b, nir_iadd_imm(&b, header, STELA_METAL_INDIRECT_HEADER_BYTES),
                              nir_imul(&b, nir_u2u64(&b, command), nir_u2u64(&b, stride)));
   nir_def *range = load(&b, arguments, STELA_METAL_RESOLVE_RANGE, 64);
   nir_def *location = load(&b, range, 0, 32);
   /* location <= command < location + length, without the sum's overflow,
    * and within the buffer. */
   nir_def *in_range = nir_iand(&b, nir_uge(&b, command, location),
                                nir_ult(&b, nir_isub(&b, command, location), load(&b, range, 4, 32)));
   nir_def *selected = nir_iand(&b, in_range,
                                nir_ult(&b, command, load(&b, header, STELA_METAL_INDIRECT_COUNT, 32)));
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
   *address = load(b, table, STELA_METAL_TABLE_BUFFER_ADDRESSES + 8u * buffer, 64);
   *length = load(b, table, STELA_METAL_TABLE_BUFFER_LENGTHS + 8u * buffer, 64);
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
   nir_def *arguments = load_push(b, 64, STELA_METAL_PUSH_ARGUMENTS);
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
   if (layout->stride == STELA_METAL_STRIDE_DYNAMIC)
      return NULL;
   nir_def *region = load_push(b, 64, STELA_METAL_PUSH_ARGUMENTS);
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
   return fetch_element(b, attribute, element, nir_imm_int(b, (int)layout->stride), inside);
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
   nir_def *arguments = load_push(&b, 64, STELA_METAL_PUSH_ARGUMENTS);

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
      nir_def *scale = load(&b, arguments, STELA_METAL_TESSELLATION_FACTOR_SCALE, 32);
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
