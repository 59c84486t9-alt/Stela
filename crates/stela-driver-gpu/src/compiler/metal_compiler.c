/* SPDX-License-Identifier: MIT */
#include "metal_compiler.h"
#include "threadgroup.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static_assert(sizeof(struct stela_metal_reflection) == STELA_METAL_REFLECTION_BYTES,
              "metal/compiler.rs mirrors the reflection");
static_assert(sizeof(struct stela_metal_target) == STELA_METAL_TARGET_BYTES,
              "metal/compiler.rs mirrors the target");
static_assert(sizeof(struct stela_metal_linked_varying) == STELA_METAL_LINKED_VARYING_BYTES,
              "metal/compiler.rs mirrors the linked varyings");
static_assert(sizeof(struct stela_metal_specialization) == STELA_METAL_SPECIALIZATION_BYTES,
              "metal/compiler.rs mirrors the specialization");
static_assert(sizeof(struct stela_air_constant_value) == STELA_METAL_CONSTANT_VALUE_BYTES,
              "metal/compiler.rs mirrors the constant values");
static_assert(sizeof(struct stela_air_module) == STELA_METAL_MODULE_BYTES,
              "metal/compiler.rs mirrors the linked modules");
static_assert(sizeof(struct stela_air_linked_function) == STELA_METAL_LINKED_FUNCTION_BYTES,
              "metal/compiler.rs mirrors the linked functions");
static_assert(sizeof(struct stela_metal_tessellation) == STELA_METAL_PIPELINE_TESSELLATION_BYTES,
              "metal/compiler.rs mirrors the pipeline tessellation");
static_assert(sizeof(struct stela_metal_stage_in) == STELA_METAL_STAGE_IN_BYTES,
              "metal/compiler.rs mirrors the stage-in layout");
static_assert(STELA_METAL_FUNCTION_CONSTANTS == AIR_MAX_FUNCTION_CONSTANTS,
              "the reflection holds every function constant the frontend admits");
static_assert(sizeof(struct stela_air_constexpr_sampler) == STELA_METAL_CONSTEXPR_SAMPLER_BYTES,
              "metal/compiler.rs mirrors the constexpr samplers");
static_assert(STELA_METAL_SAMPLER_STATES == AIR_MAX_SAMPLER_STATES,
              "a module's states fit the listing");
static_assert(sizeof(struct stela_metal_bindings) == STELA_METAL_BINDINGS_BYTES,
              "metal/compiler.rs mirrors the bindings");
static_assert(STELA_METAL_BINDINGS == AIR_MAX_ARGUMENTS, "every argument may be a binding");

/* Reports the first error; always false. */
static bool
fail(struct stela_air_error *error, enum stela_air_error_kind kind, const char *detail)
{
   if (error->kind == STELA_AIR_OK) {
      error->kind = kind;
      snprintf(error->detail, sizeof(error->detail), "%s", detail);
   }
   return false;
}

/* The function stages of stela_air_entry_stage's stages: kernels, then
 * enum stela_air_stage. */
static const enum stela_metal_function_stage function_stages[] = {
   STELA_METAL_KERNEL, STELA_METAL_VERTEX, STELA_METAL_FRAGMENT, STELA_METAL_OBJECT,
   STELA_METAL_MESH, STELA_METAL_VISIBLE,
};

static uint32_t
buffer_access(enum stela_air_buffer_access access)
{
   return (access & STELA_AIR_READ ? STELA_METAL_ACCESS_READ : 0) |
          (access & STELA_AIR_WRITE ? STELA_METAL_ACCESS_WRITE : 0);
}

static uint32_t
texture_access(enum stela_air_texture_access access)
{
   switch (access) {
   case STELA_AIR_TEXTURE_SAMPLE: return STELA_METAL_ACCESS_SAMPLE;
   case STELA_AIR_TEXTURE_READ: return STELA_METAL_ACCESS_READ;
   case STELA_AIR_TEXTURE_WRITE: return STELA_METAL_ACCESS_WRITE;
   default: return STELA_METAL_ACCESS_READ | STELA_METAL_ACCESS_WRITE;
   }
}

/* A reflection in progress. */
struct reflecting {
   const char *entry;
   struct stela_metal_reflection *out;
   struct stela_air_error *error;
   bool found;
};

/* Copies bytes into names, which hold *used of capacity bytes, at *offset. */
static bool
copy_name(struct stela_air_error *error, char *names, uint32_t *used, uint32_t capacity,
          const char *bytes, size_t size, uint32_t *offset)
{
   if (size > capacity - *used)
      return fail(error, STELA_AIR_LIMIT, "reflected names exceed their capacity");
   memcpy(names + *used, bytes, size);
   *offset = *used;
   *used += (uint32_t)size;
   return true;
}

static bool
add_name(struct reflecting *r, const char *bytes, size_t size, uint32_t *offset)
{
   return copy_name(r->error, r->out->names, &r->out->names_bytes, STELA_METAL_NAME_BYTES, bytes,
                    size, offset);
}

static bool
module_facts(struct reflecting *r, const struct stela_air_inspection *info)
{
   struct stela_metal_reflection *out = r->out;
   out->commands = !!(info->commands & STELA_AIR_COMMANDS_ENCODE);
   out->command_barriers = !!(info->commands & STELA_AIR_COMMANDS_BARRIERS);
   for (unsigned i = 0; i < info->function_constant_count; i++) {
      const struct stela_air_function_constant *constant = &info->function_constants[i];
      struct stela_metal_function_constant *row = &out->function_constants[i];
      *row = (struct stela_metal_function_constant){
         .index = constant->index, .name_bytes = (uint32_t)constant->name_bytes,
         .type_bytes = (uint32_t)constant->type_bytes, .required = constant->required};
      if (!add_name(r, constant->name, constant->name_bytes, &row->name) ||
          !add_name(r, constant->type, constant->type_bytes, &row->type))
         return false;
   }
   out->function_constant_count = info->function_constant_count;
   if (!info->ident)
      return true;
   r->out->ident_bytes = (uint32_t)info->ident_bytes;
   return add_name(r, info->ident, info->ident_bytes, &r->out->ident);
}

static bool
add_buffer(struct reflecting *r, const struct stela_air_buffer *buffer, bool argument_buffer)
{
   struct stela_metal_reflection *out = r->out;
   if (buffer->address_space == 3) {
      if (out->threadgroup_count == STELA_METAL_BUFFERS)
         return fail(r->error, STELA_AIR_LIMIT, "threadgroup buffers exceed the table");
      out->threadgroup[out->threadgroup_count++] = (struct stela_metal_threadgroup_use){
         buffer->index, buffer->type_size};
      return true;
   }
   if (out->buffer_count == STELA_METAL_BUFFERS)
      return fail(r->error, STELA_AIR_LIMIT, "buffers exceed the table");
   out->function_tables |= buffer->function_table;
   out->buffers[out->buffer_count++] = (struct stela_metal_buffer_use){
      buffer->index, buffer_access(buffer->access), argument_buffer};
   return true;
}

/* A texture argument's slots: an array's, one per element. */
static bool
add_texture(struct reflecting *r, const struct stela_air_texture *texture)
{
   struct stela_metal_reflection *out = r->out;
   for (unsigned i = 0; i < (texture->length ? texture->length : 1); i++) {
      if (out->texture_count == STELA_METAL_TEXTURES)
         return fail(r->error, STELA_AIR_LIMIT, "textures exceed the table");
      out->textures[out->texture_count++] = (struct stela_metal_texture_use){
         texture->index + i, texture_access(texture->access), texture->type, texture->primitive};
   }
   return true;
}

static bool
add_sampler(struct reflecting *r, const struct stela_air_sampler *sampler)
{
   struct stela_metal_reflection *out = r->out;
   for (unsigned i = 0; i < (sampler->length ? sampler->length : 1); i++) {
      if (out->sampler_count == STELA_METAL_SAMPLERS)
         return fail(r->error, STELA_AIR_LIMIT, "samplers exceed the table");
      out->samplers[out->sampler_count++] = sampler->index + i;
   }
   return true;
}

static bool
add_attribute(struct reflecting *r, unsigned location, enum stela_air_primitive primitive,
              unsigned components, bool patch_control_point, bool active, const char *name,
              size_t name_bytes)
{
   struct stela_metal_reflection *out = r->out;
   if (out->attribute_count == STELA_METAL_ATTRIBUTES)
      return fail(r->error, STELA_AIR_LIMIT, "attributes exceed the table");
   struct stela_metal_attribute_use *attribute = &out->attributes[out->attribute_count++];
   *attribute = (struct stela_metal_attribute_use){
      .index = location, .primitive = primitive, .components = components,
      .patch_control_point = patch_control_point, .active = active,
      .name_bytes = (uint32_t)name_bytes};
   return add_name(r, name, name_bytes, &attribute->name);
}

static bool
reflect_kernel(const struct stela_air_inspection *info, const struct stela_air_entry *entry,
               void *data)
{
   struct reflecting *r = data;
   if (entry->name_bytes != strlen(r->entry) || memcmp(entry->name, r->entry, entry->name_bytes))
      return true;
   r->found = true;
   r->out->max_total_threads = entry->max_threads;
   r->out->threadgroup_bytes = entry->threadgroup_bytes;
   for (unsigned i = 0; i < entry->argument_count; i++) {
      const struct stela_air_argument_info *argument = &entry->arguments[i];
      bool added = argument->absent ? true :
                   argument->kind == 1 ? add_buffer(r, &argument->buffer, argument->argument_buffer) :
                   argument->kind == 3 ? add_texture(r, &argument->texture) :
                   argument->kind == 4 ? add_sampler(r, &argument->sampler) :
                   argument->kind == 5 ?
                                         add_attribute(r, argument->location, argument->primitive,
                                                       argument->type_components, false,
                                                       argument->used, argument->name,
                                                       argument->name_bytes) :
                                         true;
      if (!added)
         return false;
   }
   return module_facts(r, info);
}

static bool
add_varying(struct reflecting *r, const struct stela_air_stage_io *io)
{
   struct stela_metal_reflection *out = r->out;
   if (out->varying_count == STELA_METAL_VARYINGS)
      return fail(r->error, STELA_AIR_LIMIT, "varyings exceed the linkable slots");
   struct stela_metal_varying *varying = &out->varyings[out->varying_count++];
   *varying = (struct stela_metal_varying){
      .identifier_bytes = (uint32_t)io->identifier_bytes, .primitive = io->primitive,
      .components = io->components, .per_primitive = io->per_primitive};
   return add_name(r, io->identifier, io->identifier_bytes, &varying->identifier);
}

static bool
add_input(struct reflecting *r, const struct stela_air_stage_io *io)
{
   struct stela_metal_reflection *out = r->out;
   if (io->absent)
      return true;
   switch (io->semantic) {
   case STELA_AIR_STAGE_BUFFER: return add_buffer(r, &io->buffer, io->argument_buffer);
   case STELA_AIR_STAGE_TEXTURE: return add_texture(r, &io->texture);
   case STELA_AIR_STAGE_SAMPLER: return add_sampler(r, &io->sampler);
   case STELA_AIR_VARYING:
      out->interpolants |= io->interpolant;
      return add_varying(r, io);
   case STELA_AIR_BARYCENTRIC:
      out->barycentrics = 1;
      return true;
   case STELA_AIR_ATTACHMENT:
      out->attachment_reads |= 1u << io->location;
      return true;
   case STELA_AIR_VERTEX_INPUT:
      return add_attribute(r, io->location, io->primitive, io->components, false, io->used,
                           io->name, io->name_bytes);
   case STELA_AIR_CONTROL_POINTS:
      for (unsigned i = 0; i < io->member_count; i++) {
         const struct stela_air_struct_member *member = &io->members[i];
         if (!add_attribute(r, member->location, member->primitive, member->components, true,
                            !member->unused, member->name, member->name_bytes))
            return false;
      }
      return true;
   case STELA_AIR_STAGE_BUILTIN:
      out->amplification |= io->builtin == STELA_AIR_AMPLIFICATION_ID;
      return true;
   default:
      /* The position, the payload, the mesh and its grid. */
      return true;
   }
}

static bool
add_output(struct reflecting *r, const struct stela_air_stage_io *io)
{
   struct stela_metal_reflection *out = r->out;
   switch (io->semantic) {
   case STELA_AIR_VARYING: return add_varying(r, io);
   case STELA_AIR_RENDER_TARGET:
      if (out->color_output_count == STELA_METAL_COLOR_OUTPUTS)
         return fail(r->error, STELA_AIR_LIMIT, "render targets exceed the attachments");
      out->color_outputs[out->color_output_count++] = (struct stela_metal_color_output){
         io->location, io->primitive, io->index};
      return true;
   case STELA_AIR_DEPTH: out->writes_depth = 1; return true;
   case STELA_AIR_STENCIL: out->writes_stencil = 1; return true;
   case STELA_AIR_SAMPLE_MASK: out->writes_sample_mask = 1; return true;
   default: return true;
   }
}

static bool
reflect_stage(const struct stela_air_inspection *info, const struct stela_air_stage_entry *entry,
              void *data)
{
   struct reflecting *r = data;
   r->found = true;
   r->out->max_total_threads = entry->max_threads;
   r->out->threadgroup_bytes = entry->threadgroup_bytes;
   r->out->discards = entry->discards;
   r->out->patch = entry->patch;
   r->out->patch_control_points = entry->patch_control_points;
   for (unsigned i = 0; i < entry->input_count; i++) {
      if (!add_input(r, &entry->inputs[i]))
         return false;
   }
   for (unsigned i = 0; i < entry->output_count; i++) {
      if (!add_output(r, &entry->outputs[i]))
         return false;
   }
   return module_facts(r, info);
}

/* Inspects entry, which the AIR list naming it gives *stage: a kernel's
 * visitor sees every kernel, a stage's only entry. *found reports whether a
 * visitor took entry. */
static bool
inspect_entry(const void *air, size_t size, const char *entry,
              const struct stela_air_constants *constants, stela_air_visit_entry kernel,
              stela_air_visit_stage stage_entry, void *data, const bool *found, unsigned *stage,
              struct stela_air_error *error)
{
   if (!stela_air_entry_stage(air, size, entry, stage, error))
      return false;
   bool inspected = *stage ? stela_air_inspect_stage(air, size, constants, entry,
                                                     (enum stela_air_stage)*stage, stage_entry,
                                                     data, error) :
                             stela_air_inspect(air, size, constants, AIR_MAX_METADATA_OPERANDS,
                                               kernel, data, error);
   /* A receiver's refusal is reported as the inspector's; keep the cause. */
   return inspected ? *found || fail(error, STELA_AIR_ARGUMENT, "entry is not an AIR kernel") :
                      false;
}

struct listing {
   stela_metal_visit_function visit;
   void *data;
};

static bool
list_function(void *data, const char *name, size_t name_bytes, unsigned stage)
{
   struct listing *listing = data;
   return listing->visit(listing->data, name, name_bytes, function_stages[stage]);
}

bool
stela_metal_functions(const void *air, size_t size, stela_metal_visit_function visit, void *data,
                      struct stela_air_error *error)
{
   struct listing listing = {visit, data};
   return stela_air_functions(air, size, list_function, &listing, error);
}

bool
stela_metal_stitch(const struct stela_air_stitch_source *sources, uint32_t source_count,
                   const struct stela_air_stitch_graph *graphs, uint32_t graph_count,
                   stela_air_visit_bytes visit, void *data, struct stela_air_error *error)
{
   return stela_air_stitch(sources, source_count, graphs, graph_count, visit, data, error);
}

/* Reflects entry, and selects its stage by the AIR list that names it. */
static bool
reflect(const void *air, size_t size, const char *entry,
        const struct stela_air_constants *constants, struct reflecting *r)
{
   *r->out = (struct stela_metal_reflection){0};
   unsigned stage = 0;
   bool reflected = inspect_entry(air, size, entry, constants, reflect_kernel, reflect_stage, r,
                                  &r->found, &stage, r->error);
   r->out->stage = function_stages[stage];
   return reflected;
}

bool
stela_metal_reflect(const void *air, size_t size, const char *entry,
                    const struct stela_air_constant_value *constants, uint32_t constant_count,
                    struct stela_metal_reflection *reflection, struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   struct reflecting r = {.entry = entry, .out = reflection, .error = error ? error : &local};
   *r.error = (struct stela_air_error){0};
   struct stela_air_constants values = {constants, constant_count};
   return reflection && entry && (constants || !constant_count) ?
             reflect(air, size, entry, constants ? &values : NULL, &r) :
             fail(r.error, STELA_AIR_INPUT, "invalid reflection request");
}

/* A binding reflection in progress: the structure each member row is or
 * points to, whose members follow once every row before it is filled. */
struct binding_reflection {
   const char *entry;
   const struct stela_air_inspection *info;
   struct stela_metal_bindings *out;
   const struct stela_air_layout *layouts[STELA_METAL_MEMBERS];
   struct stela_air_error *error;
   bool found;
};

static bool
binding_name(struct binding_reflection *r, const char *bytes, size_t size, uint32_t *offset)
{
   return copy_name(r->error, r->out->names, &r->out->names_bytes, STELA_METAL_BINDING_NAME_BYTES,
                    bytes, size, offset);
}

static bool
add_member(const struct stela_air_layout_member *member, void *data)
{
   struct binding_reflection *r = data;
   struct stela_metal_bindings *out = r->out;
   if (out->member_count == STELA_METAL_MEMBERS)
      return fail(r->error, STELA_AIR_LIMIT, "reflected members exceed their capacity");
   bool texture = member->kind == STELA_AIR_FIELD_TEXTURE;
   struct stela_metal_member *row = &out->members[out->member_count];
   *row = (struct stela_metal_member){
      .offset = member->offset, .size = member->size, .elements = member->elements,
      .count = member->count, .name_bytes = (uint32_t)member->name_bytes,
      .type_bytes = (uint32_t)member->type_name_bytes, .argument = member->argument,
      .kind = member->kind, .id = member->id,
      .access = texture ? texture_access(member->texture.access) :
                          buffer_access(member->buffer.access),
      .size_pointed = member->buffer.type_size, .alignment_pointed = member->buffer.type_alignment,
      .texture_type = member->texture.type, .primitive = member->texture.primitive,
      .depth = member->texture.depth,
   };
   r->layouts[out->member_count++] = member->layout;
   return binding_name(r, member->name, member->name_bytes, &row->name) &&
          binding_name(r, member->type_name, member->type_name_bytes, &row->type);
}

/* Appends layout's members, as *first and *count. */
static bool
add_members(struct binding_reflection *r, const struct stela_air_layout *layout, uint32_t *first,
            uint32_t *count)
{
   *first = r->out->member_count;
   if (layout && !stela_air_layout_members(r->info, layout, add_member, r))
      return false;
   *count = r->out->member_count - *first;
   return true;
}

static bool
add_binding(struct binding_reflection *r, enum stela_metal_binding_kind kind, unsigned index,
            unsigned length, const char *name, size_t name_bytes, const char *type,
            size_t type_bytes, bool used, const struct stela_air_layout *layout,
            struct stela_metal_binding binding)
{
   struct stela_metal_bindings *out = r->out;
   if (out->binding_count == STELA_METAL_BINDINGS)
      return fail(r->error, STELA_AIR_LIMIT, "bindings exceed the arguments");
   binding.kind = kind;
   binding.index = index;
   binding.count = length ? length : 1;
   binding.used = used;
   binding.name_bytes = (uint32_t)name_bytes;
   binding.type_bytes = (uint32_t)type_bytes;
   struct stela_metal_binding *row = &out->bindings[out->binding_count++];
   *row = binding;
   return binding_name(r, name, name_bytes, &row->name) &&
          binding_name(r, type, type_bytes, &row->type) &&
          add_members(r, layout, &row->members, &row->member_count);
}

static bool
add_buffer_binding(struct binding_reflection *r, const struct stela_air_buffer *buffer,
                   bool argument_buffer, const char *name, size_t name_bytes, const char *type,
                   size_t type_bytes, bool used, const struct stela_air_layout *layout)
{
   enum stela_metal_binding_kind kind =
      buffer->address_space == 3 ? STELA_METAL_BINDING_THREADGROUP :
      buffer->address_space == 6 ? STELA_METAL_BINDING_OBJECT_PAYLOAD :
      buffer->function_table ? STELA_METAL_BINDING_FUNCTION_TABLE : STELA_METAL_BINDING_BUFFER;
   return add_binding(r, kind, buffer->index, 0, name, name_bytes, type, type_bytes, used, layout,
                      (struct stela_metal_binding){
                         .access = buffer_access(buffer->access),
                         .argument_buffer = argument_buffer, .size = buffer->type_size,
                         .alignment = buffer->type_alignment});
}

static bool
add_texture_binding(struct binding_reflection *r, const struct stela_air_texture *texture,
                    const char *name, size_t name_bytes, const char *type, size_t type_bytes,
                    bool used)
{
   return add_binding(r, STELA_METAL_BINDING_TEXTURE, texture->index, texture->length, name,
                      name_bytes, type, type_bytes, used, NULL,
                      (struct stela_metal_binding){
                         .access = texture_access(texture->access), .texture_type = texture->type,
                         .primitive = texture->primitive, .depth = texture->depth});
}

static bool
add_sampler_binding(struct binding_reflection *r, const struct stela_air_sampler *sampler,
                    const char *name, size_t name_bytes, const char *type, size_t type_bytes,
                    bool used)
{
   return add_binding(r, STELA_METAL_BINDING_SAMPLER, sampler->index, sampler->length, name,
                      name_bytes, type, type_bytes, used, NULL,
                      (struct stela_metal_binding){.access = STELA_METAL_ACCESS_READ});
}

/* Fills the members of the structures member rows are or point to, each
 * after every row before it, so that each structure's are contiguous. */
static bool
nested_members(struct binding_reflection *r)
{
   for (uint32_t i = 0; i < r->out->member_count; i++) {
      struct stela_metal_member *row = &r->out->members[i];
      if (!add_members(r, r->layouts[i], &row->members, &row->member_count))
         return false;
   }
   return true;
}

static bool
bind_kernel(const struct stela_air_inspection *info, const struct stela_air_entry *entry,
            void *data)
{
   struct binding_reflection *r = data;
   if (entry->name_bytes != strlen(r->entry) || memcmp(entry->name, r->entry, entry->name_bytes))
      return true;
   r->found = true;
   r->info = info;
   for (unsigned i = 0; i < entry->argument_count; i++) {
      const struct stela_air_argument_info *a = &entry->arguments[i];
      bool added = a->absent ? true :
                   a->kind == 1 ? add_buffer_binding(r, &a->buffer, a->argument_buffer, a->name,
                                                     a->name_bytes, a->type_name,
                                                     a->type_name_bytes, a->used, a->layout) :
                   a->kind == 3 ? add_texture_binding(r, &a->texture, a->name, a->name_bytes,
                                                      a->type_name, a->type_name_bytes, a->used) :
                   a->kind == 4 ? add_sampler_binding(r, &a->sampler, a->name, a->name_bytes,
                                                      a->type_name, a->type_name_bytes, a->used) :
                                  true;
      if (!added)
         return false;
   }
   return nested_members(r);
}

static bool
bind_stage(const struct stela_air_inspection *info, const struct stela_air_stage_entry *entry,
           void *data)
{
   struct binding_reflection *r = data;
   r->found = true;
   r->info = info;
   for (unsigned i = 0; i < entry->input_count; i++) {
      const struct stela_air_stage_io *io = &entry->inputs[i];
      bool added = io->absent ? true :
                   io->semantic == STELA_AIR_STAGE_BUFFER || io->semantic == STELA_AIR_PAYLOAD ?
                      add_buffer_binding(r, &io->buffer, io->argument_buffer, io->name,
                                         io->name_bytes, io->type_name, io->type_name_bytes,
                                         io->used, io->layout) :
                   io->semantic == STELA_AIR_STAGE_TEXTURE ?
                      add_texture_binding(r, &io->texture, io->name, io->name_bytes,
                                          io->type_name, io->type_name_bytes, io->used) :
                   io->semantic == STELA_AIR_STAGE_SAMPLER ?
                      add_sampler_binding(r, &io->sampler, io->name, io->name_bytes,
                                          io->type_name, io->type_name_bytes, io->used) :
                      true;
      if (!added)
         return false;
   }
   return nested_members(r);
}

bool
stela_metal_reflect_bindings(const void *air, size_t size, const char *entry,
                             const struct stela_air_constant_value *constants,
                             uint32_t constant_count, struct stela_metal_bindings *bindings,
                             struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   error = error ? error : &local;
   *error = (struct stela_air_error){0};
   if (!bindings || !entry || (!constants && constant_count))
      return fail(error, STELA_AIR_INPUT, "invalid binding reflection request");
   struct binding_reflection *r = calloc(1, sizeof(*r));
   if (!r)
      return fail(error, STELA_AIR_ALLOCATION, "binding reflection allocation failed");
   *r = (struct binding_reflection){.entry = entry, .out = bindings, .error = error};
   bindings->binding_count = bindings->member_count = bindings->names_bytes = 0;
   struct stela_air_constants values = {constants, constant_count};
   unsigned stage = 0;
   bool reflected = inspect_entry(air, size, entry, constants ? &values : NULL, bind_kernel,
                                  bind_stage, r, &r->found, &stage, error);
   free(r);
   return reflected;
}

bool
stela_metal_sampler_states(const void *air, size_t size,
                           uint64_t states[STELA_METAL_SAMPLER_STATES], uint32_t *count,
                           struct stela_air_error *error)
{
   unsigned listed;
   bool valid = stela_air_sampler_states(air, size, states, &listed, error);
   *count = listed;
   return valid;
}

/* The binding data of the metal_abi callbacks, which read its first member,
 * and of the threadgroup callback. */
struct binding {
   struct stela_metal_stage stage;
   const struct stela_metal_specialization *specialization;
};

/* The dispatch's setThreadgroupMemoryLength:atIndex: of the buffer. */
static bool
bind_threadgroup(const struct stela_air_buffer *buffer, struct stela_air_threadgroup_view *view,
                 void *data)
{
   const struct stela_metal_specialization *specialization =
      ((const struct binding *)data)->specialization;
   for (unsigned i = 0; i < specialization->threadgroup_length_count; i++) {
      const struct stela_metal_threadgroup_length *length = &specialization->threadgroup_lengths[i];
      if (length->index != buffer->index)
         continue;
      *view = (struct stela_air_threadgroup_view){
         .size = length->bytes,
         .alignment = MAX2(buffer->type_alignment, STELA_METAL_THREADGROUP_ALIGNMENT),
         .available_access = STELA_AIR_READ_WRITE,
      };
      return length->bytes != 0;
   }
   return false;
}

/* stela_air_fetch_attribute over the pipeline's stage-in layout: at a
 * patch's IDs for post-tessellation vertex functions, else at a kernel's
 * position in the grid. */
static nir_def *
fetch_attribute(nir_builder *b, unsigned location, nir_def *at, nir_def *point, bool integer,
                void *data)
{
   const struct stela_metal_specialization *specialization =
      ((const struct binding *)data)->specialization;
   if (!specialization->stage_in)
      return NULL;
   if (specialization->tessellation)
      return stela_metal_fetch_patch_attribute(b, specialization->stage_in,
                                               specialization->tessellation, location, at, point,
                                               integer);
   return point ? NULL : stela_metal_fetch_stage_in(b, specialization->stage_in, location, at, integer);
}

static enum stela_metal_table
stage_table(enum stela_metal_function_stage stage)
{
   switch (stage) {
   case STELA_METAL_FRAGMENT: return STELA_METAL_TABLE_FRAGMENT;
   case STELA_METAL_MESH: return STELA_METAL_TABLE_MESH;
   default: return STELA_METAL_TABLE_PRIMARY;
   }
}

/* The stage's rows of the pipeline's varyings: those it reads or writes, at
 * their linked locations, of its own types. */
static bool
varying_rows(const struct stela_metal_reflection *reflection,
             const struct stela_metal_specialization *specialization,
             struct stela_air_varying_slot *rows, unsigned *count, struct stela_air_error *error)
{
   *count = 0;
   if (specialization->varying_count > STELA_METAL_VARYINGS)
      return fail(error, STELA_AIR_LIMIT, "linked varyings exceed the slots");
   for (unsigned i = 0; i < reflection->varying_count; i++) {
      const struct stela_metal_varying *varying = &reflection->varyings[i];
      const char *identifier = reflection->names + varying->identifier;
      unsigned location = 0;
      while (location < specialization->varying_count &&
             (specialization->varyings[location].identifier_bytes != varying->identifier_bytes ||
              memcmp(specialization->varyings[location].identifier, identifier,
                     varying->identifier_bytes)))
         location++;
      if (location == specialization->varying_count)
         return fail(error, STELA_AIR_ARGUMENT, "a varying is missing from the pipeline's linkage");
      const struct stela_metal_linked_varying *linked = &specialization->varyings[location];
      rows[(*count)++] = (struct stela_air_varying_slot){
         .identifier = linked->identifier, .identifier_bytes = linked->identifier_bytes,
         .primitive = varying->primitive, .components = varying->components,
         .location = location, .per_primitive = linked->per_primitive,
      };
   }
   return true;
}

nir_shader *
stela_metal_compile_reflected(const void *air, size_t size, const char *entry,
                              const struct stela_metal_target *target,
                              const struct stela_metal_specialization *specialization,
                              const struct stela_metal_reflection *reflection,
                              struct stela_air_error *error)
{
   struct stela_air_error local = {0};
   if (!error)
      error = &local;
   *error = (struct stela_air_error){0};
   if (!entry || !target || !target->nir || !specialization ||
       (specialization->threadgroup_length_count && !specialization->threadgroup_lengths) ||
       (specialization->varying_count && !specialization->varyings) ||
       (specialization->constant_count && !specialization->constants) ||
       (specialization->module_count && !specialization->modules) ||
       (specialization->linked_function_count && !specialization->linked_functions) ||
       (specialization->sampler_count && !specialization->samplers)) {
      fail(error, STELA_AIR_INPUT, "invalid compilation request");
      return NULL;
   }
   struct stela_metal_reflection *owned_reflection = NULL;
   nir_shader *shader = NULL;
   if (!reflection) {
      owned_reflection = malloc(sizeof(*owned_reflection));
      if (!owned_reflection) {
         fail(error, STELA_AIR_ALLOCATION, "reflection allocation failed");
         return NULL;
      }
      struct reflecting r = {.entry = entry, .out = owned_reflection, .error = error};
      struct stela_air_constants constants = {specialization->constants,
                                              specialization->constant_count};
      if (!reflect(air, size, entry, &constants, &r))
         goto done;
      reflection = owned_reflection;
   }
   enum stela_metal_function_stage stage = reflection->stage;
   if (stage == STELA_METAL_VISIBLE) {
      fail(error, STELA_AIR_ARGUMENT, "visible functions compile into the functions that link them");
      goto done;
   }
   bool compute = stage == STELA_METAL_KERNEL || stage == STELA_METAL_OBJECT ||
                  stage == STELA_METAL_MESH;
   /* A post-tessellation vertex function is its pipeline's evaluation
    * stage, which no vertex stage can take the place of. */
   const struct stela_metal_tessellation *tessellation = specialization->tessellation;
   bool patch = reflection->patch != STELA_AIR_PATCH_NONE;
   if (patch && !tessellation) {
      fail(error, STELA_AIR_ARGUMENT, "post-tessellation vertex functions need tessellation stages");
      goto done;
   }
   if (tessellation && (!patch || tessellation->quad != (reflection->patch == STELA_AIR_PATCH_QUAD))) {
      fail(error, STELA_AIR_INPUT, "tessellation of another patch");
      goto done;
   }
   /* Only kernels and patch functions fetch their stage-in. */
   const struct stela_metal_stage_in *stage_in = specialization->stage_in;
   if (stage_in && !patch && stage != STELA_METAL_KERNEL) {
      fail(error, STELA_AIR_INPUT, "stage-in for a function that does not fetch it");
      goto done;
   }
   struct binding binding = {{stage_table(stage)}, specialization};
   struct stela_air_options resources = {
      .max_instructions = target->max_instructions,
      .bind_buffer = stela_metal_bind_buffer,
      .binding_data = &binding,
      .fp_profile = STELA_AIR_FP_METAL,
      .max_private_bytes = target->max_private_bytes,
      .max_constant_bytes = target->max_constant_bytes,
      .bind_texture = stela_metal_bind_texture,
      .bind_sampler = stela_metal_bind_sampler,
      .bind_attachment = stela_metal_bind_attachment,
      .bind_texture_id = stela_metal_bind_texture_id,
      .bind_sampler_id = stela_metal_bind_sampler_id,
      .resource_id = stela_metal_resource_id,
      .constexpr_samplers = specialization->samplers,
      .constexpr_sampler_count = specialization->sampler_count,
      .texture_levels = stela_metal_texture_levels,
      .texture_null = stela_metal_texture_null,
      .command_count = stela_metal_command_count,
      .encode_command = stela_metal_encode_command,
      .load_device_value = stela_metal_load_device_value,
      .fetch_attribute = patch || stage_in ? fetch_attribute : NULL,
      .constants = specialization->constants,
      .constant_count = specialization->constant_count,
      .modules = specialization->modules,
      .module_count = specialization->module_count,
      .linked_functions = specialization->linked_functions,
      .linked_function_count = specialization->linked_function_count,
      .max_call_stack_depth = specialization->max_call_stack_depth,
   };
   if (compute) {
      memcpy(resources.workgroup_size, specialization->workgroup_size,
             sizeof(resources.workgroup_size));
      resources.bind_threadgroup = bind_threadgroup;
      resources.max_threadgroup_bytes = target->max_threadgroup_bytes;
   }
   if (specialization->dynamic_threadgroups) {
      if (stage != STELA_METAL_KERNEL || specialization->threadgroup_length_count) {
         fail(error, STELA_AIR_INPUT, "dynamic threadgroups of a kernel without lengths");
         goto done;
      }
      /* Threadgroup buffers share what the function's own variables leave. */
      uint64_t free_bytes = target->max_threadgroup_bytes -
                            MIN2(reflection->threadgroup_bytes, target->max_threadgroup_bytes);
      resources.dynamic_shape = true;
      resources.bind_threadgroup = NULL;
      resources.dynamic_threadgroup_bytes = (unsigned)(free_bytes & ~(uint64_t)15);
      resources.threadgroup_offset = stela_metal_threadgroup_offset;
   }
   if (stage == STELA_METAL_KERNEL) {
      shader = stela_air_to_nir(air, size, entry, target->nir, &resources, error);
      goto done;
   }
   struct stela_air_varying_slot rows[STELA_METAL_VARYINGS];
   unsigned row_count;
   if (!varying_rows(reflection, specialization, rows, &row_count, error))
      goto done;
   static const enum stela_air_stage air_stages[] = {
      [STELA_METAL_VERTEX] = STELA_AIR_VERTEX, [STELA_METAL_FRAGMENT] = STELA_AIR_FRAGMENT,
      [STELA_METAL_MESH] = STELA_AIR_MESH, [STELA_METAL_OBJECT] = STELA_AIR_OBJECT,
   };
   struct stela_air_stage_options options = {
      .stage = air_stages[stage],
      .resources = resources,
      .varyings = rows,
      .varying_count = row_count,
      .max_varying_slots = target->max_varying_slots,
      .amplified = specialization->amplified,
      .launched_by_grid = specialization->launched_by_grid,
      .max_payload_bytes = target->max_payload_bytes,
      .max_mesh_vertices = target->max_mesh_vertices,
      .max_mesh_primitives = target->max_mesh_primitives,
   };
   shader = stela_air_stage_to_nir(air, size, entry, target->nir, &options, error);
done:
   free(owned_reflection);
   return shader;
}

nir_shader *
stela_metal_compile(const void *air, size_t size, const char *entry,
                    const struct stela_metal_target *target,
                    const struct stela_metal_specialization *specialization,
                    struct stela_air_error *error)
{
   return stela_metal_compile_reflected(air, size, entry, target, specialization, NULL, error);
}

void
stela_metal_tessellation_stages(const struct stela_metal_target *target,
                                const struct stela_metal_tessellation *tessellation,
                                nir_shader *stages[2])
{
   stages[0] = stela_metal_tessellation_vertex(target->nir);
   stages[1] = stela_metal_tessellation_control(target->nir, tessellation);
}

void
stela_metal_release(nir_shader *shader)
{
   ralloc_free(shader);
}
