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
   }
   return NULL;
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

nir_shader *stela_metal_tessellation_vertex(const nir_shader_compiler_options *options)
{
   nir_builder b = nir_builder_init_simple_shader(MESA_SHADER_VERTEX, options,
                                                  "stela_metal_tessellation_vertex");
   nir_variable *patch = nir_variable_create(b.shader, nir_var_shader_out, glsl_uvec_type(2),
                                             "patch");
   patch->data.location = VARYING_SLOT_VAR0;
   patch->data.interpolation = INTERP_MODE_FLAT;
   nir_def *instance = nir_iadd(&b, nir_load_instance_id(&b), nir_load_base_instance(&b));
   nir_store_var(&b, patch, nir_vec2(&b, nir_load_vertex_id(&b), instance), 0x3);
   return validated(&b);
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
      b.shader, nir_var_shader_in, glsl_array_type(glsl_uvec_type(2), 32, 0), "patch");
   input->data.location = VARYING_SLOT_VAR0;
   input->data.interpolation = INTERP_MODE_FLAT;
   nir_variable *outputs[2] = {
      patch_output(b.shader, glsl_array_type(glsl_float_type(), 4, 0),
                   VARYING_SLOT_TESS_LEVEL_OUTER, "outer"),
      patch_output(b.shader, glsl_array_type(glsl_float_type(), 2, 0),
                   VARYING_SLOT_TESS_LEVEL_INNER, "inner"),
   };
   nir_variable *patch_ids = patch_output(b.shader, glsl_uvec_type(2), VARYING_SLOT_PATCH0,
                                          "patch_id");

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
   nir_store_var(&b, patch_ids, nir_vec2(&b, id, instance), 0x3);
   return validated(&b);
}
