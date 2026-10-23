/* SPDX-License-Identifier: MIT */
/* Actual local C -> owned Rust input -> shared LLVM metadata integration.
 * No Objective-C, device, framework compiler, GPU or transport is invoked. */
#ifdef NDEBUG
#error "This ownership test requires active assertions"
#endif
#include "../input.h"
#include "../../../compiler/air_metadata.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct inspection {
   unsigned entries;
   bool expect_complete;
};
static bool visit(const struct stela_air_inspection *module,
                  const struct stela_air_entry *entry, void *data)
{
   struct inspection *state = data;
   assert(module->target && module->target_bytes && entry->name && entry->name_bytes);
   assert(entry->reflection_complete == state->expect_complete);
   assert(entry->argument_count <= AIR_MAX_ARGUMENTS);
   printf("entry=%u air=2.%u msl=%u.%u complete=%u arguments=%u\n", state->entries,
      module->air_minor,module->language_major,module->language_minor,
      entry->reflection_complete,entry->argument_count);
   for (unsigned i = 0; i < entry->argument_count; i++) {
      const struct stela_air_argument_info *arg = &entry->arguments[i];
      if (arg->kind != 1) continue;
      assert(arg->buffer.argument < entry->argument_count);
      if (state->expect_complete)
         assert(arg->name && arg->name_bytes && arg->plain_buffer_type &&
                arg->type_components && arg->type_components <= 4 &&
                arg->primitive >= STELA_AIR_CHAR && arg->primitive <= STELA_AIR_FLOAT);
      printf("argument=%u binding=%u space=%u access=%u size=%u align=%u primitive=%u lanes=%u used=%u\n",
         arg->buffer.argument,arg->buffer.index,arg->buffer.address_space,arg->buffer.access,
         arg->buffer.type_size,arg->buffer.type_alignment,arg->primitive,arg->type_components,arg->used);
   }
   state->entries++;
   return true;
}
int main(int argc, char **argv)
{
   assert(argc == 3 && (!strcmp(argv[2],"complete") || !strcmp(argv[2],"incomplete")));
   FILE *file = fopen(argv[1],"rb");
   assert(file && !fseek(file,0,SEEK_END));
   long length = ftell(file);
   assert(length >= 4 && length <= 64*1024*1024 && !fseek(file,0,SEEK_SET));
   uint8_t *bytes = malloc((size_t)length);
   assert(bytes && fread(bytes,1,(size_t)length,file) == (size_t)length && !fclose(file));
   struct stela_metal_input_limits limits = {
      .size=sizeof(limits),.abi=1,.kind=STELA_METAL_INPUT_RAW_AIR,.max_entries=256,.max_bytes=64*1024*1024,
   };
   struct stela_metal_input *input = NULL;
   struct stela_metal_input_error error = {0};
   assert(!stela_metal_input_open(&limits,bytes,(uint64_t)length,&input,&error));
   memset(bytes,0,(size_t)length); free(bytes); /* Retained view must remain original. */
   struct stela_metal_input_info info = {.size=sizeof(info),.abi=1};
   struct stela_metal_input_view view = {.size=sizeof(view),.abi=1};
   assert(!stela_metal_input_info(input,&info,&error));
   assert(!stela_metal_input_original(input,&view,&error) && view.original_offset == 0 &&
          view.length == (uint64_t)length);
   assert(!stela_metal_input_air(input,0,&view,&error) && view.length >= 4);
   printf("original_bytes=%llu original_sha256=",(unsigned long long)info.original_bytes);
   for (unsigned i = 0; i < 32; i++) printf("%02x",info.original_sha256[i]);
   puts("");
   struct inspection state = {.expect_complete=!strcmp(argv[2],"complete")};
   struct stela_air_error metadata_error;
   if (!stela_air_inspect(view.bytes,(size_t)view.length,256,visit,&state,&metadata_error)) {
      fprintf(stderr,"AIR inspection refused (%u): %s\n",metadata_error.kind,metadata_error.detail);
      abort();
   }
   assert(state.entries);
   stela_metal_input_destroy(&input); assert(!input);
   return 0;
}
