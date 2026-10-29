/* SPDX-License-Identifier: MIT */
#include "metal_abi.h"
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

/* The heap element of the resource ID at offset in the stage's table. */
static nir_deref_instr *heap_element(nir_builder *b, const struct stela_metal_stage *stage,
                                     unsigned offset, bool high,
                                     enum stela_metal_heap_array array,
                                     const struct glsl_type *type, nir_variable_mode mode)
{
   nir_def *id = load(b, stela_metal_load_table(b, stage->table), offset, 64);
   nir_def *index = high ? nir_unpack_64_2x32_split_y(b, id) : nir_unpack_64_2x32_split_x(b, id);
   return nir_build_deref_array(b, nir_build_deref_var(b, heap(b->shader, array, type, mode)),
                                index);
}

nir_deref_instr *stela_metal_bind_texture(nir_builder *b, const struct stela_air_texture *texture,
                                          const struct glsl_type *type, void *stage)
{
   if (texture->index >= STELA_METAL_TEXTURES)
      return NULL;
   bool image = glsl_type_is_image(type);
   bool buffer = glsl_get_sampler_dim(type) == GLSL_SAMPLER_DIM_BUF;
   enum stela_metal_heap_array array =
      image ? (buffer ? STELA_METAL_HEAP_STORAGE_TEXEL_BUFFERS : STELA_METAL_HEAP_STORAGE_IMAGES)
            : (buffer ? STELA_METAL_HEAP_UNIFORM_TEXEL_BUFFERS : STELA_METAL_HEAP_SAMPLED_IMAGES);
   return heap_element(b, stage, STELA_METAL_TABLE_TEXTURES + 8u * texture->index, image, array,
                       type, image ? nir_var_image : nir_var_uniform);
}

nir_deref_instr *stela_metal_bind_sampler(nir_builder *b, const struct stela_air_sampler *sampler,
                                          bool integer, void *stage)
{
   if (sampler->index >= STELA_METAL_SAMPLERS)
      return NULL;
   return heap_element(b, stage, STELA_METAL_TABLE_SAMPLERS + 8u * sampler->index, integer,
                       STELA_METAL_HEAP_SAMPLERS, glsl_bare_sampler_type(), nir_var_uniform);
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

static nir_shader *finish(nir_builder *b)
{
   nir_pop_if(b, NULL);
   nir_lower_vars_to_ssa(b->shader);
   nir_remove_dead_variables(b->shader, nir_var_function_temp, NULL);
   nir_validate_shader(b->shader, "Metal internal kernel");
   return b->shader;
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
