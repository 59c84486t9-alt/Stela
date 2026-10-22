/* SPDX-License-Identifier: MIT */
#include "library_assembly.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INPUT_LIMIT (64u * 1024u * 1024u)
#define ENTRY_LIMIT 256u
#define STRING_LIMIT 4096u
#define TARGET_LIMIT 1024u
#define ENTRY_FLAGS (STELA_METAL_ENTRY_NO_CONSTANTS | STELA_METAL_ENTRY_PLAIN_BUFFERS | \
                     STELA_METAL_ENTRY_COMPLETE_REFLECTION)
struct stela_metal_assembly {
   struct stela_metal_input *input;
   struct stela_metal_input_view original;
   struct stela_metal_library_manifest manifest;
   struct stela_metal_function_record *records;
   void **blocks;
   char *target;
   unsigned capacity, inspection_entries;
   uint64_t metadata_bytes, metadata_limit;
};
struct visit_context {
   struct stela_metal_assembly *owner;
   struct stela_metal_assembly_error *error;
   const struct stela_msl_request *request; /* Borrowed for this call only. */
   const struct stela_metal_function_record *group; /* Archive module group. */
   struct stela_metal_input_view raw;
   uint8_t raw_sha256[32];
};
static void reset_error(struct stela_metal_assembly_error *error)
{
   *error = (struct stela_metal_assembly_error) {
      .size=sizeof(*error),.abi=STELA_METAL_ASSEMBLY_ABI,
   };
}
static enum stela_metal_assembly_status
report(struct stela_metal_assembly_error *error, enum stela_metal_assembly_status status,
       const char *format, ...)
{
   if (error->status == STELA_METAL_ASSEMBLY_OK) {
      error->status = status;
      va_list args; va_start(args,format);
      vsnprintf(error->detail,sizeof(error->detail),format,args);
      va_end(args);
   }
   return status;
}
static enum stela_metal_assembly_status
input_error(struct stela_metal_assembly_error *error, const struct stela_metal_input_error *input)
{
   error->input_status = input->status; error->input_offset = input->offset;
   enum stela_metal_assembly_status status =
      input->status == STELA_METAL_INPUT_LIMIT ? STELA_METAL_ASSEMBLY_LIMIT :
      input->status == STELA_METAL_INPUT_ALLOCATION ? STELA_METAL_ASSEMBLY_ALLOCATION :
      input->status == STELA_METAL_INPUT_ABI_MISMATCH ? STELA_METAL_ASSEMBLY_ABI_MISMATCH :
      input->status == STELA_METAL_INPUT_INVALID ? STELA_METAL_ASSEMBLY_INPUT : STELA_METAL_ASSEMBLY_CONTAINER;
   return report(error,status,
      "Canonical input refused (status %u, parser %u, original offset %llu)",
      input->status,input->parser_kind,(unsigned long long)input->offset);
}
static bool nonzero(const uint8_t *bytes, size_t count)
{
   uint8_t result = 0;
   for (size_t i = 0; i < count; i++) result |= bytes[i];
   return result != 0;
}
static void hash(const void *bytes, size_t size, uint8_t digest[32])
{
   /* All source/input/raw ranges are independently bounded to 64MiB. */
   CC_SHA256(bytes,(CC_LONG)size,digest);
}
static bool charge(struct stela_metal_assembly *owner, size_t bytes,
                   struct stela_metal_assembly_error *error)
{
   if (bytes > owner->metadata_limit-owner->metadata_bytes) {
      report(error,STELA_METAL_ASSEMBLY_LIMIT,"Retained metadata budget exceeded"); return false;
   }
   owner->metadata_bytes += bytes;
   return true;
}
static bool text(const char *bytes, size_t size)
{
   if (!bytes) return !size;
   if (size > STRING_LIMIT || memchr(bytes,0,size)) return false;
   /* Use the real hosted string implementation; do not normalize/rewrite bytes. */
   CFStringRef string = CFStringCreateWithBytes(kCFAllocatorDefault,(const UInt8 *)bytes,
      (CFIndex)size,kCFStringEncodingUTF8,false);
   if (!string) return false;
   CFRelease(string);
   return true;
}
static bool span(uint64_t offset, uint64_t size, uint64_t limit)
{
   return size && offset <= limit && size <= limit-offset;
}
/* Only the observed AIR macOS triple syntax is admitted. Header version fields
 * represent major/minor only: preserve the actual patch, do not invent one or
 * infer Metal feature support/deployment compatibility from this consistency. */
static bool target_version(const struct stela_air_inspection *info, unsigned version[3])
{
   char prefix[40];
   snprintf(prefix,sizeof(prefix),"air64_v2%u-apple-macosx",info->air_minor);
   size_t at = strlen(prefix);
   if (info->target_bytes <= at || memcmp(info->target,prefix,at)) return false;
   for (unsigned part = 0; part < 3; part++) {
      unsigned value = 0, digits = 0;
      while (at < info->target_bytes && info->target[at] >= '0' && info->target[at] <= '9') {
         unsigned digit = (unsigned)(info->target[at++]-'0');
         if (value > (UINT16_MAX-digit)/10) return false;
         value = value*10+digit; digits++;
      }
      if (!digits) return false;
      version[part] = value;
      if (part < 2 && (at == info->target_bytes || info->target[at++] != '.')) return false;
   }
   return at == info->target_bytes && version[0];
}
static bool same_wrapped_module(const struct stela_metal_function_record *a,
                                const struct stela_metal_function_record *b)
{
   return a->entry.module_offset == b->entry.module_offset &&
          a->entry.module_bytes == b->entry.module_bytes &&
          !memcmp(a->entry.module_sha256,b->entry.module_sha256,32);
}
static bool same_module(const struct stela_metal_function_record *a,
                        const struct stela_metal_function_record *b)
{
   return same_wrapped_module(a,b) && a->air_offset == b->air_offset && a->air_bytes == b->air_bytes;
}
static bool module_identity(struct visit_context *context, const struct stela_air_inspection *info)
{
   struct stela_metal_assembly *owner = context->owner;
   unsigned version[3];
   if (info->target_bytes > TARGET_LIMIT || !target_version(info,version)) {
      report(context->error,STELA_METAL_ASSEMBLY_IDENTITY,"Unsupported AIR target encoding"); return false;
   }
   if (context->request) {
      const struct stela_msl_request *request = context->request;
      if (info->air_minor != 9 || info->language_major != request->language_version >> 16 ||
          info->language_minor != (request->language_version & 0xffff) ||
          !info->fast_math || !info->denorms_disable ||
          strlen(request->target_triple) != info->target_bytes ||
          memcmp(request->target_triple,info->target,info->target_bytes)) {
         report(context->error,STELA_METAL_ASSEMBLY_SOURCE,"AIR facts differ from the qualified source request"); return false;
      }
   } else if (version[0] != owner->manifest.input.minimum_os_major ||
              version[1] != owner->manifest.input.minimum_os_minor) {
      report(context->error,STELA_METAL_ASSEMBLY_IDENTITY,"MTLB and AIR target OS version fields disagree"); return false;
   }
   if (owner->target) {
      if (owner->manifest.target_bytes != info->target_bytes ||
          memcmp(owner->target,info->target,info->target_bytes)) {
         report(context->error,STELA_METAL_ASSEMBLY_IDENTITY,"Selected AIR modules have different targets"); return false;
      }
   } else {
      if (!charge(owner,info->target_bytes+1,context->error)) return false;
      owner->target = malloc(info->target_bytes+1);
      if (!owner->target) {
         report(context->error,STELA_METAL_ASSEMBLY_ALLOCATION,"Target copy allocation failed"); return false;
      }
      memcpy(owner->target,info->target,info->target_bytes); owner->target[info->target_bytes] = 0;
      owner->manifest.target = (const uint8_t *)owner->target;
      owner->manifest.target_bytes = info->target_bytes;
   }
   return true;
}
static char *copy_text(char **cursor, const char *bytes, size_t count)
{
   if (!bytes) return NULL;
   char *result = *cursor;
   memcpy(result,bytes,count); result[count] = 0; *cursor += count+1;
   return result;
}
static bool copy_entry(struct visit_context *context, const struct stela_air_entry *entry,
                       unsigned index)
{
   struct stela_metal_assembly *owner = context->owner;
   if (index >= owner->capacity || entry->argument_count > AIR_MAX_ARGUMENTS) {
      report(context->error,STELA_METAL_ASSEMBLY_LIMIT,"Entry/argument budget exceeded"); return false;
   }
   if (!entry->reflection_complete || !entry->name_bytes ||
       !text(entry->name,entry->name_bytes)) {
      report(context->error,STELA_METAL_ASSEMBLY_REFLECTION,"Incomplete/unrepresentable function reflection"); return false;
   }
   size_t size = entry->argument_count*sizeof(struct stela_air_argument_info)+entry->name_bytes+1;
   for (unsigned i = 0; i < entry->argument_count; i++) {
      const struct stela_air_argument_info *arg = &entry->arguments[i];
      if (!text(arg->name,arg->name_bytes) || !text(arg->type_name,arg->type_name_bytes)) {
         report(context->error,STELA_METAL_ASSEMBLY_REFLECTION,"Unrepresentable argument reflection strings"); return false;
      }
      /* Bounded above by 128 arguments and 4096 bytes/string before addition. */
      size += arg->name ? arg->name_bytes+1 : 0;
      size += arg->type_name ? arg->type_name_bytes+1 : 0;
   }
   if (!charge(owner,size,context->error)) return false;
   void *block = malloc(size);
   if (!block) {
      report(context->error,STELA_METAL_ASSEMBLY_ALLOCATION,"Reflection copy allocation failed"); return false;
   }
   owner->blocks[index] = block;
   struct stela_air_argument_info *args = block;
   char *cursor = (char *)(args+entry->argument_count);
   struct stela_metal_function_record *record = &owner->records[index];
   record->size = sizeof(*record); record->abi = STELA_METAL_LIBRARY_ABI;
   record->flags = ENTRY_FLAGS;
   record->name = (const uint8_t *)copy_text(&cursor,entry->name,entry->name_bytes);
   record->name_bytes = entry->name_bytes; record->argument_count = entry->argument_count;
   record->arguments = args;
   for (unsigned i = 0; i < entry->argument_count; i++) {
      args[i] = entry->arguments[i];
      args[i].name = copy_text(&cursor,args[i].name,args[i].name_bytes);
      args[i].type_name = copy_text(&cursor,args[i].type_name,args[i].type_name_bytes);
   }
   return true;
}
static bool visit_entry(const struct stela_air_inspection *info,
                        const struct stela_air_entry *entry, void *data)
{
   struct visit_context *context = data;
   struct stela_metal_assembly *owner = context->owner;
   if (!context->group) {
      unsigned index = owner->manifest.entry_count;
      if (!module_identity(context,info)) return false;
      if (index >= owner->capacity) {
         report(context->error,STELA_METAL_ASSEMBLY_LIMIT,"Source entry budget exceeded"); return false;
      }
      struct stela_metal_function_record *record = &owner->records[index];
      record->entry = (struct stela_metal_input_entry) {
         .size=sizeof(record->entry),.abi=STELA_METAL_INPUT_ABI,.kind=2,
         .air_major=2,.air_minor=info->air_minor,
         .language_major=info->language_major,.language_minor=info->language_minor,
         .module_offset=0,.module_bytes=owner->original.length,
      };
      memcpy(record->entry.module_sha256,owner->manifest.input.original_sha256,32);
      record->air_offset = context->raw.original_offset; record->air_bytes = context->raw.length;
      memcpy(record->air_sha256,context->raw_sha256,32);
      if (!copy_entry(context,entry,index)) return false;
      owner->manifest.entry_count++;
      return true;
   }
   for (unsigned i = 0; i < owner->manifest.entry_count; i++) {
      struct stela_metal_function_record *record = &owner->records[i];
      if (!same_module(context->group,record) || record->name_bytes != entry->name_bytes ||
          memcmp(record->name,entry->name,entry->name_bytes)) continue;
      if (record->flags || record->entry.air_major != 2 || record->entry.air_minor != info->air_minor ||
          record->entry.language_major != info->language_major ||
          record->entry.language_minor != info->language_minor) {
         report(context->error,STELA_METAL_ASSEMBLY_IDENTITY,"MTLB NAME/TYPE/VERS differ from selected AIR entry"); return false;
      }
      return module_identity(context,info) && copy_entry(context,entry,i);
   }
   return true; /* Extra nonexported AIR entries are not fabricated as exports. */
}
static bool inspect(struct visit_context *context, uint64_t offset, uint64_t size)
{
   struct stela_metal_assembly *owner = context->owner;
   if (!span(offset,size,owner->original.length)) {
      report(context->error,STELA_METAL_ASSEMBLY_IDENTITY,"Selected AIR is outside the original input"); return false;
   }
   struct stela_air_error error;
   if (!stela_air_inspect(owner->original.bytes+offset,(size_t)size,owner->inspection_entries,
                          visit_entry,context,&error)) {
      if (!context->error->status) {
         context->error->air_kind = error.kind; context->error->air_instruction = error.instruction;
         report(context->error,STELA_METAL_ASSEMBLY_AIR,"%s",error.detail);
      }
      return false;
   }
   return true;
}
static struct stela_metal_assembly *open_input(const struct stela_metal_assembly_options *options,
   uint32_t kind, const void *bytes, size_t count, struct stela_metal_assembly_error *error)
{
   struct stela_metal_input *input = NULL;
   struct stela_metal_input_limits limits = {.size=sizeof(limits),.abi=STELA_METAL_INPUT_ABI,
      .kind=kind,.max_entries=options->max_entries,.max_bytes=options->max_input_bytes};
   struct stela_metal_input_error input_status;
   if (stela_metal_input_open(&limits,bytes,count,&input,&input_status)) {
      input_error(error,&input_status); return NULL;
   }
   struct stela_metal_input_info info = {.size=sizeof(info),.abi=STELA_METAL_INPUT_ABI};
   if (stela_metal_input_info(input,&info,&input_status)) {
      input_error(error,&input_status); stela_metal_input_destroy(&input); return NULL;
   }
   unsigned capacity = kind == STELA_METAL_INPUT_MTLB ? info.entry_count : options->max_entries;
   size_t base = sizeof(struct stela_metal_assembly)+capacity*(sizeof(struct stela_metal_function_record)+sizeof(void *));
   if (!capacity || base > options->max_metadata_bytes) {
      report(error,STELA_METAL_ASSEMBLY_LIMIT,"No compute entries or retained owner budget exceeded");
      stela_metal_input_destroy(&input); return NULL;
   }
   struct stela_metal_assembly *owner = calloc(1,sizeof(*owner));
   if (!owner) {
      report(error,STELA_METAL_ASSEMBLY_ALLOCATION,"Owner allocation failed");
      stela_metal_input_destroy(&input); return NULL;
   }
   owner->input = input; owner->capacity = capacity; owner->inspection_entries = options->max_entries;
   owner->metadata_bytes = base; owner->metadata_limit = options->max_metadata_bytes;
   owner->manifest = (struct stela_metal_library_manifest) {
      .size=sizeof(owner->manifest),.abi=STELA_METAL_LIBRARY_ABI,.input=info,
   };
   owner->records = calloc(capacity,sizeof(*owner->records));
   owner->blocks = calloc(capacity,sizeof(*owner->blocks));
   if (!owner->records || !owner->blocks) {
      report(error,STELA_METAL_ASSEMBLY_ALLOCATION,"Entry table allocation failed"); goto fail;
   }
   owner->manifest.entries = owner->records;
   owner->original = (struct stela_metal_input_view){.size=sizeof(owner->original),.abi=STELA_METAL_INPUT_ABI};
   if (stela_metal_input_original(input,&owner->original,&input_status)) {
      input_error(error,&input_status); goto fail;
   }
   if (!owner->original.bytes || owner->original.original_offset ||
       owner->original.length != info.original_bytes) {
      report(error,STELA_METAL_ASSEMBLY_IDENTITY,"Canonical original view and input info disagree"); goto fail;
   }
   return owner;
fail:
   stela_metal_assembly_destroy(&owner); return NULL;
}
static bool valid_options(const struct stela_metal_assembly_options *options,
                           struct stela_metal_assembly **output,
                           struct stela_metal_assembly_error *error)
{
   if (!options || !output || *output) {
      report(error,STELA_METAL_ASSEMBLY_INPUT,"Options and empty owning output slot are required"); return false;
   }
   if (options->size != sizeof(*options) || options->abi != STELA_METAL_ASSEMBLY_ABI || options->reserved) {
      report(error,STELA_METAL_ASSEMBLY_ABI_MISMATCH,"Invalid assembly options ABI/reserved fields"); return false;
   }
   if (!options->max_entries || options->max_entries > ENTRY_LIMIT ||
       options->max_input_bytes < 4 || options->max_input_bytes > INPUT_LIMIT ||
       !options->max_metadata_bytes || options->max_metadata_bytes > INPUT_LIMIT) {
      report(error,STELA_METAL_ASSEMBLY_LIMIT,"Invalid assembly entry/input/metadata bounds"); return false;
   }
   return true;
}
struct stela_metal_assembly_options stela_metal_assembly_default_options(void)
{
   return (struct stela_metal_assembly_options) {
      .size=sizeof(struct stela_metal_assembly_options),.abi=STELA_METAL_ASSEMBLY_ABI,
      .max_entries=ENTRY_LIMIT,.max_input_bytes=INPUT_LIMIT,.max_metadata_bytes=16u*1024u*1024u,
   };
}
enum stela_metal_assembly_status stela_metal_assemble_archive(
   const struct stela_metal_assembly_options *options, const void *bytes, size_t count,
   struct stela_metal_assembly **output, struct stela_metal_assembly_error *error)
{
   struct stela_metal_assembly_error local;
   if (!error) error = &local;
   reset_error(error);
   if (!valid_options(options,output,error)) return error->status;
   struct stela_metal_assembly *owner = open_input(options,STELA_METAL_INPUT_MTLB,bytes,count,error);
   if (!owner) return error->status;
   const struct stela_metal_input_info *info = &owner->manifest.input;
   if (info->platform != 0x8001 || info->target_os != 0x81 || info->format_major != 2 || info->library_kind) {
      report(error,STELA_METAL_ASSEMBLY_CONTAINER,"Requires an observed macOS MTLB2 executable header"); goto fail;
   }
   owner->manifest.entry_count = info->entry_count;
   for (unsigned i = 0; i < info->entry_count; i++) {
      struct stela_metal_function_record *record = &owner->records[i];
      record->entry = (struct stela_metal_input_entry){.size=sizeof(record->entry),.abi=STELA_METAL_INPUT_ABI};
      struct stela_metal_input_view name = {.size=sizeof(name),.abi=STELA_METAL_INPUT_ABI};
      struct stela_metal_input_view raw = {.size=sizeof(raw),.abi=STELA_METAL_INPUT_ABI};
      struct stela_metal_input_error input_status;
      if (stela_metal_input_entry(owner->input,i,&record->entry,&input_status) ||
          stela_metal_input_name(owner->input,i,&name,&input_status)) {
         input_error(error,&input_status); goto fail;
      }
      struct stela_metal_input_entry_metadata metadata = {.size=sizeof(metadata),.abi=STELA_METAL_INPUT_ABI};
      if (stela_metal_input_entry_metadata(owner->input,i,&metadata,&input_status)) {
         input_error(error,&input_status); goto fail;
      }
      /* Canonical parsing already requires exactly one each of NAME, TYPE,
       * HASH, MDSZ, OFFT, VERS. Only those six function tags and absent/ENDT-only
       * metadata streams are qualified here. AIR reflection cannot prove an
       * archive has no CNST/ARGR/RETR or unknown extension requirements. */
      if (metadata.function_tags != 6 || metadata.public_tags || metadata.private_tags || metadata.header_tags) {
         report(error,STELA_METAL_ASSEMBLY_REFLECTION,"Unqualified MTLB function/public/private/header metadata"); goto fail;
      }
      if (record->entry.kind != 2) {
         report(error,STELA_METAL_ASSEMBLY_IDENTITY,"Selected MTLB entry is not a compute kernel"); goto fail;
      }
      record->name = name.bytes; record->name_bytes = name.length;
      unsigned cached;
      for (cached = 0; cached < i; cached++) {
         if (same_wrapped_module(record,&owner->records[cached])) break;
      }
      if (cached < i) {
         /* Immutable original range plus exact expected HASH equality reuses
          * the earlier canonical selected-module hash/framing proof. */
         record->air_offset = owner->records[cached].air_offset;
         record->air_bytes = owner->records[cached].air_bytes;
         memcpy(record->air_sha256,owner->records[cached].air_sha256,32);
         continue;
      }
      if (stela_metal_input_air(owner->input,i,&raw,&input_status)) {
         input_error(error,&input_status); goto fail;
      }
      if (!span(raw.original_offset,raw.length,owner->original.length) ||
          raw.original_offset < record->entry.module_offset || raw.length > record->entry.module_bytes ||
          raw.original_offset-record->entry.module_offset > record->entry.module_bytes-raw.length) {
         report(error,STELA_METAL_ASSEMBLY_IDENTITY,"Canonical AIR range is outside its selected module"); goto fail;
      }
      if (raw.bytes != owner->original.bytes+raw.original_offset) {
         report(error,STELA_METAL_ASSEMBLY_IDENTITY,"Canonical raw view does not retain original storage"); goto fail;
      }
      record->air_offset = raw.original_offset; record->air_bytes = raw.length;
      hash(raw.bytes,(size_t)raw.length,record->air_sha256);
   }
   /* One LLVM inspection per shared original module, not one per export.
    * Every selected entry has a canonical or identical cached HASH proof. */
   for (unsigned i = 0; i < info->entry_count; i++) {
      if (owner->records[i].flags) continue;
      struct visit_context context = {.owner=owner,.error=error,.group=&owner->records[i]};
      if (!inspect(&context,context.group->air_offset,context.group->air_bytes)) goto fail;
      for (unsigned j = 0; j < info->entry_count; j++) {
         if (same_module(context.group,&owner->records[j]) && !owner->records[j].flags) {
            report(error,STELA_METAL_ASSEMBLY_IDENTITY,"MTLB NAME is absent from selected AIR kernel entries"); goto fail;
         }
      }
   }
   *output = owner;
   return STELA_METAL_ASSEMBLY_OK;
fail:
   stela_metal_assembly_destroy(&owner); return error->status;
}
enum stela_metal_assembly_status stela_metal_assemble_source(
   const struct stela_metal_assembly_options *options, const struct stela_msl_apple_config *config,
   const struct stela_msl_request *request, const struct stela_msl_output *compiled,
   struct stela_metal_assembly **output, struct stela_metal_assembly_error *error)
{
   struct stela_metal_assembly_error local;
   if (!error) error = &local;
   reset_error(error);
   if (!valid_options(options,output,error)) return error->status;
   struct stela_msl_error source_error;
   if (stela_msl_apple_validate_request(config,request,&source_error) != STELA_MSL_OK)
      return report(error,STELA_METAL_ASSEMBLY_SOURCE,"%s",source_error.detail);
   if (!compiled || !compiled->air || compiled->air_bytes < 4 || compiled->air_bytes > config->max_air_bytes ||
       !nonzero(compiled->build.gpucompiler_uuid,16) || !nonzero(compiled->build.implementation_uuid,16) ||
       !nonzero(compiled->build.llvm_uuid,16) || !nonzero(compiled->build.lazy_library_sha256,32) ||
       !nonzero(compiled->build.metal_stdlib_sha256,32) || !nonzero(compiled->build.metal_types_sha256,32))
      return report(error,STELA_METAL_ASSEMBLY_SOURCE,"Successful trusted compiler output/build identity required");
   uint8_t source_hash[32]; hash(request->source,request->source_bytes,source_hash);
   if (memcmp(source_hash,compiled->source_sha256,32))
      return report(error,STELA_METAL_ASSEMBLY_SOURCE,"Source request/output digest mismatch");
   struct stela_metal_assembly *owner = open_input(options,STELA_METAL_INPUT_RAW_AIR,compiled->air,compiled->air_bytes,error);
   if (!owner) return error->status;
   if (memcmp(owner->manifest.input.original_sha256,compiled->air_sha256,32)) {
      report(error,STELA_METAL_ASSEMBLY_SOURCE,"Original compiler output digest mismatch"); goto fail;
   }
   owner->manifest.flags = STELA_METAL_LIBRARY_SOURCE_COMPILED;
   owner->manifest.compiler_profile = config->profile;
   owner->manifest.request_language = request->language_version;
   owner->manifest.request_fast_math = request->fast_math;
   memcpy(owner->manifest.source_sha256,source_hash,32); owner->manifest.build = compiled->build;
   struct stela_metal_input_view raw = {.size=sizeof(raw),.abi=STELA_METAL_INPUT_ABI};
   struct stela_metal_input_error input_status;
   if (stela_metal_input_air(owner->input,0,&raw,&input_status)) {
      input_error(error,&input_status); goto fail;
   }
   if (!span(raw.original_offset,raw.length,owner->original.length) ||
       raw.bytes != owner->original.bytes+raw.original_offset) {
      report(error,STELA_METAL_ASSEMBLY_IDENTITY,"Canonical source AIR view does not retain original storage"); goto fail;
   }
   struct visit_context context = {.owner=owner,.error=error,.request=request,.raw=raw};
   hash(raw.bytes,(size_t)raw.length,context.raw_sha256);
   if (!inspect(&context,raw.original_offset,raw.length)) goto fail;
   *output = owner;
   return STELA_METAL_ASSEMBLY_OK;
fail:
   stela_metal_assembly_destroy(&owner); return error->status;
}
const struct stela_metal_library_manifest *stela_metal_assembly_manifest(const struct stela_metal_assembly *owner)
{
   return owner ? &owner->manifest : NULL;
}
enum stela_metal_assembly_status stela_metal_assembly_original(
   const struct stela_metal_assembly *owner, struct stela_metal_input_view *view,
   struct stela_metal_assembly_error *error)
{
   struct stela_metal_assembly_error local;
   if (!error) error = &local;
   reset_error(error);
   if (!owner || !view) return report(error,STELA_METAL_ASSEMBLY_INPUT,"Owner and complete writable view required");
   if (view->size != sizeof(*view) || view->abi != STELA_METAL_INPUT_ABI)
      return report(error,STELA_METAL_ASSEMBLY_ABI_MISMATCH,"Invalid original view ABI");
   *view = owner->original;
   return STELA_METAL_ASSEMBLY_OK;
}
void stela_metal_assembly_destroy(struct stela_metal_assembly **slot)
{
   if (!slot || !*slot) return;
   struct stela_metal_assembly *owner = *slot; *slot = NULL;
   if (owner->blocks)
      for (unsigned i = 0; i < owner->capacity; i++) free(owner->blocks[i]);
   free(owner->blocks); free(owner->records); free(owner->target);
   stela_metal_input_destroy(&owner->input);
   free(owner);
}
