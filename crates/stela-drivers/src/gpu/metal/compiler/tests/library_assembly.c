/* SPDX-License-Identifier: MIT */
/* Same-source C -> canonical Rust -> real LLVM -> owned manifest tests.
 * Original LLVM/MTLB fixtures are not Apple compiler output or a GPU reference.
 * Optional source mode consumes the retained genuine adapter result unchanged. */
#include "../library_assembly.h"
#include "../../../common/mesa/src/stela/tests/air_test_fixture.h"
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <errno.h>
#ifdef NDEBUG
#error "Assembly ownership tests require active assertions"
#endif
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); abort(); } } while (0)
_Static_assert(sizeof(struct stela_msl_build_identity) == 144,"fixed-byte build identity fixture");
_Static_assert(sizeof(struct stela_metal_assembly_options) == 32,"assembly options ABI");
_Static_assert(sizeof(struct stela_metal_assembly_error) == 288,"assembly error ABI");

/* Optional test-object-only macro renaming in library_assembly.c replaces its
 * direct libc allocation calls with these. Rust/LLVM/CF keep their real normal
 * allocators. This is NOT a shipping allocator or public fault-injection API. */
static size_t allocation_attempts, fail_allocation, live_allocations;
void *stela_assembly_test_malloc(size_t size);
void *stela_assembly_test_calloc(size_t count, size_t size);
void stela_assembly_test_free(void *pointer);
void *stela_assembly_test_malloc(size_t size)
{
   allocation_attempts++;
   if (fail_allocation && allocation_attempts == fail_allocation) return NULL;
   void *pointer = malloc(size); if (pointer) live_allocations++;
   return pointer;
}
void *stela_assembly_test_calloc(size_t count, size_t size)
{
   allocation_attempts++;
   if (fail_allocation && allocation_attempts == fail_allocation) return NULL;
   void *pointer = calloc(count,size); if (pointer) live_allocations++;
   return pointer;
}
void stela_assembly_test_free(void *pointer)
{
   if (pointer) { CHECK(live_allocations); live_allocations--; }
   free(pointer);
}
struct bytes { uint8_t *data; size_t count; };
static void append(struct bytes *b, const void *data, size_t count)
{
   CHECK(count <= SIZE_MAX-b->count);
   b->data = realloc(b->data,b->count+count); CHECK(b->data);
   memcpy(b->data+b->count,data,count); b->count += count;
}
static void put16(void *data, uint16_t value)
{
   uint8_t *p = data; p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
}
static void put32(void *data, uint32_t value)
{
   uint8_t *p = data; for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(value >> (8*i));
}
static void put64(void *data, uint64_t value)
{
   uint8_t *p = data; for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(value >> (8*i));
}
static void tag(struct bytes *b, const char name[4], const void *data, size_t count)
{
   CHECK(count <= UINT16_MAX);
   uint8_t size[2]; put16(size,(uint16_t)count);
   append(b,name,4); append(b,size,2); append(b,data,count);
}
static void digest(const void *data, size_t size, uint8_t output[32])
{
   CHECK(size <= 64u*1024u*1024u); CC_SHA256(data,(CC_LONG)size,output);
}
struct specification {
   const char *name;
   uint8_t kind;
   uint16_t air_minor, language_major, language_minor;
   const void *module; size_t module_bytes;
   bool wrong_hash;
   const char *function_tag, *public_tag, *private_tag, *header_tag;
};
static struct bytes archive(const struct specification *entries, unsigned count,
                            uint16_t major, uint16_t minor)
{
   CHECK(count && count <= 256);
   struct bytes records = {0}, code = {0};
   uint64_t offsets[256];
   for (unsigned i = 0; i < count; i++) {
      unsigned same;
      for (same = 0; same < i; same++)
         if (entries[same].module == entries[i].module && entries[same].module_bytes == entries[i].module_bytes) break;
      offsets[i] = same < i ? offsets[same] : code.count;
      if (same == i) append(&code,entries[i].module,entries[i].module_bytes);
      struct bytes record = {0}; uint8_t zero[4] = {0}; append(&record,zero,4);
      tag(&record,"NAME",entries[i].name,strlen(entries[i].name)+1);
      tag(&record,"TYPE",&entries[i].kind,1);
      uint8_t hash[32]; digest(entries[i].module,entries[i].module_bytes,hash);
      if (entries[i].wrong_hash) hash[0] ^= 1;
      tag(&record,"HASH",hash,32);
      uint8_t size[8]; put64(size,entries[i].module_bytes); tag(&record,"MDSZ",size,8);
      uint8_t positions[24] = {0}; put64(positions+16,offsets[i]); tag(&record,"OFFT",positions,24);
      uint8_t versions[8]; put16(versions,2); put16(versions+2,entries[i].air_minor);
      put16(versions+4,entries[i].language_major); put16(versions+6,entries[i].language_minor);
      tag(&record,"VERS",versions,8);
      if (entries[i].function_tag) tag(&record,entries[i].function_tag,"retained",8);
      append(&record,"ENDT",4);
      CHECK(record.count <= UINT32_MAX); put32(record.data,(uint32_t)record.count);
      append(&records,record.data,record.count); free(record.data);
   }
   struct bytes result = {0}; uint8_t header[88] = {0}; memcpy(header,"MTLB",4);
   put16(header+4,0x8001); put16(header+6,2); put16(header+8,9);
   header[11] = 0x81; put16(header+12,major); put16(header+14,minor);
   put64(header+24,88); put64(header+32,records.count);
   struct bytes extension = {0}, public = {0}, private = {0};
   /* Own fixture writer only; parser/admission facts come from canonical Rust. */
   if (entries[0].header_tag) {
      if (strcmp(entries[0].header_tag,"NONE")) tag(&extension,entries[0].header_tag,"identity",8);
      append(&extension,"ENDT",4);
   }
   struct bytes *groups[] = {&public,&private};
   const char *keys[] = {entries[0].public_tag,entries[0].private_tag};
   for (unsigned i = 0; i < 2; i++) if (keys[i]) {
      uint8_t zero[4] = {0}; append(groups[i],zero,4);
      if (strcmp(keys[i],"NONE")) tag(groups[i],keys[i],"unimplemented",13);
      append(groups[i],"ENDT",4); put32(groups[i]->data,(uint32_t)groups[i]->count);
   }
   size_t start = 88+4+records.count+extension.count;
   put64(header+40,start); put64(header+48,public.count);
   put64(header+56,start+public.count); put64(header+64,private.count);
   put64(header+72,start+public.count+private.count); put64(header+80,code.count);
   put64(header+16,start+public.count+private.count+code.count); append(&result,header,sizeof(header));
   uint8_t n[4]; put32(n,count); append(&result,n,4);
   append(&result,records.data,records.count);
   if (extension.count) append(&result,extension.data,extension.count);
   if (public.count) append(&result,public.data,public.count);
   if (private.count) append(&result,private.data,private.count);
   append(&result,code.data,code.count);
   free(extension.data); free(public.data); free(private.data);
   free(records.data); free(code.data); return result;
}
static char *replace(const char *text, const char *from, const char *to)
{
   const char *at = strstr(text,from); CHECK(at);
   size_t prefix = (size_t)(at-text), tail = strlen(at+strlen(from));
   char *result = malloc(prefix+strlen(to)+tail+1); CHECK(result);
   memcpy(result,text,prefix); memcpy(result+prefix,to,strlen(to));
   memcpy(result+prefix+strlen(to),at+strlen(from),tail+1); return result;
}
static struct specification specification(LLVMMemoryBufferRef module, const char *name)
{
   return (struct specification) {.name=name,.kind=2,.air_minor=8,.language_major=4,.language_minor=0,
      .module=LLVMGetBufferStart(module),.module_bytes=LLVMGetBufferSize(module)};
}
static struct stela_metal_assembly *create(const struct bytes *input, enum stela_metal_assembly_status expected)
{
   struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error;
   struct stela_metal_assembly *owner = NULL;
   enum stela_metal_assembly_status status = stela_metal_assemble_archive(&options,input->data,input->count,&owner,&error);
   if (status != expected) fprintf(stderr,"Assembly status %u expected %u: %s\n",status,expected,error.detail);
   CHECK(status == expected && error.status == status && error.abi == 1 && error.size == sizeof(error));
   CHECK((owner != NULL) == (status == STELA_METAL_ASSEMBLY_OK));
   return owner;
}
static void destroy(struct stela_metal_assembly **owner)
{
   stela_metal_assembly_destroy(owner); CHECK(!*owner);
   stela_metal_assembly_destroy(owner); stela_metal_assembly_destroy(NULL);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
   CHECK(live_allocations == 0);
#endif
}
static void check_manifest(const struct stela_metal_library_manifest *m, unsigned count)
{
   CHECK(m && m->size == sizeof(*m) && m->abi == 1 && !m->reserved && m->entry_count == count);
   CHECK(m->target && m->target_bytes && m->entries);
   for (unsigned i = 0; i < count; i++) {
      const struct stela_metal_function_record *r = &m->entries[i];
      CHECK(r->size == sizeof(*r) && r->abi == 1 && r->flags == 7 && !r->reserved && !r->reserved_arguments);
      CHECK(r->entry.size == sizeof(r->entry) && r->entry.abi == 1 && r->entry.kind == 2 && !r->entry.reserved);
      CHECK(r->name && r->name_bytes && strlen((const char *)r->name) == r->name_bytes);
      CHECK(r->air_bytes >= 4 && r->air_offset < m->input.original_bytes &&
            r->air_bytes <= m->input.original_bytes-r->air_offset);
      CHECK(r->argument_count <= AIR_MAX_ARGUMENTS);
      for (unsigned a = 0; a < r->argument_count; a++) {
         const struct stela_air_argument_info *arg = &r->arguments[a];
         CHECK(arg->buffer.argument < r->argument_count);
         if (arg->name) CHECK(strlen(arg->name) == arg->name_bytes);
         if (arg->type_name) CHECK(strlen(arg->type_name) == arg->type_name_bytes);
         if (arg->kind == 1) CHECK(arg->plain_buffer_type && arg->buffer.type_size && arg->buffer.type_alignment);
      }
   }
}
static void unit_tests(void)
{
   LLVMMemoryBufferRef module = stela_air_test_bitcode(stela_air_test_store_body,"");
   struct specification s = specification(module,"kernel");
   struct bytes input = archive(&s,1,26,7); uint8_t original_hash[32]; digest(input.data,input.count,original_hash);
   struct stela_metal_assembly *owner = create(&input,STELA_METAL_ASSEMBLY_OK);
   memset(input.data,0,input.count); free(input.data); LLVMDisposeMemoryBuffer(module);
   /* Destroyed caller bytes AND LLVM buffers/contexts must not own any view. */
   const struct stela_metal_library_manifest *m = stela_metal_assembly_manifest(owner); check_manifest(m,1);
   CHECK(!m->flags && !m->compiler_profile && !m->request_language && !m->request_fast_math);
   CHECK(!memcmp(m->input.original_sha256,original_hash,32));
   CHECK(m->target_bytes == strlen("air64_v28-apple-macosx26.7.0") &&
      !memcmp(m->target,"air64_v28-apple-macosx26.7.0",m->target_bytes));
   const struct stela_air_argument_info *arg = &m->entries[0].arguments[1];
   CHECK(arg->buffer.argument == 1 && arg->buffer.index == 7 && arg->buffer.address_space == 1 &&
      arg->buffer.access == STELA_AIR_READ_WRITE && arg->buffer.type_size == 4 && arg->buffer.type_alignment == 4);
   CHECK(arg->primitive == STELA_AIR_UINT && arg->type_components == 1 && arg->used &&
      !strcmp(arg->name,"output") && !strcmp(arg->type_name,"uint"));
   struct stela_metal_input_view view = {.size=sizeof(view),.abi=1}; struct stela_metal_assembly_error error;
   CHECK(!stela_metal_assembly_original(owner,&view,&error) && !view.original_offset && view.length == m->input.original_bytes);
   uint8_t actual_hash[32]; digest(view.bytes,(size_t)view.length,actual_hash); CHECK(!memcmp(actual_hash,original_hash,32));
   digest(view.bytes+m->entries[0].entry.module_offset,(size_t)m->entries[0].entry.module_bytes,actual_hash);
   CHECK(!memcmp(actual_hash,m->entries[0].entry.module_sha256,32));
   digest(view.bytes+m->entries[0].air_offset,(size_t)m->entries[0].air_bytes,actual_hash);
   CHECK(!memcmp(actual_hash,m->entries[0].air_sha256,32));
   view.abi = 2; view.length = 123;
   CHECK(stela_metal_assembly_original(owner,&view,&error) == STELA_METAL_ASSEMBLY_ABI_MISMATCH && view.length == 123);
   struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
   CHECK(stela_metal_assemble_archive(&options,NULL,0,&owner,&error) == STELA_METAL_ASSEMBLY_INPUT &&
      stela_metal_assembly_manifest(owner) == m); destroy(&owner); CHECK(!stela_metal_assembly_manifest(NULL));

   module = stela_air_test_bitcode(stela_air_test_store_body,""); s = specification(module,"kernel");
   for (unsigned wrong = 0; wrong < 5; wrong++) {
      struct specification bad = s;
      if (wrong == 0) bad.name = "absent";
      if (wrong == 1) bad.kind = 0;
      if (wrong == 2) bad.air_minor = 9;
      if (wrong == 3) bad.language_minor = 1;
      if (wrong == 4) bad.wrong_hash = true;
      input = archive(&bad,1,26,7);
      owner = create(&input,wrong == 4 ? STELA_METAL_ASSEMBLY_CONTAINER : STELA_METAL_ASSEMBLY_IDENTITY);
      CHECK(!owner); free(input.data);
   }
   for (unsigned wrong = 0; wrong < 4; wrong++) {
      input = archive(&s,1,26,7);
      if (wrong == 0) input.data[4] = 0;
      if (wrong == 1) input.data[11] = 0x82;
      if (wrong == 2) put16(input.data+12,25);
      if (wrong == 3) put16(input.data+14,0);
      owner = create(&input,wrong < 2 ? STELA_METAL_ASSEMBLY_CONTAINER : STELA_METAL_ASSEMBLY_IDENTITY);
      CHECK(!owner); free(input.data);
   }
   /* Unknown tags are retained by the parser, never treated as no constants or
    * complete reflection by the assembler, even when AIR reflection is plain. */
   for (unsigned unknown = 0; unknown < 8; unknown++) {
      struct specification bad = s;
      if (unknown == 0) bad.function_tag = "FUTR";
      if (unknown == 1) bad.function_tag = "CNST";
      if (unknown == 2) bad.public_tag = "CNST";
      if (unknown == 3) bad.public_tag = "ARGR";
      if (unknown == 4) bad.public_tag = "RETR";
      if (unknown == 5) bad.private_tag = "DEBI";
      if (unknown == 6) bad.header_tag = "UUID";
      if (unknown == 7) bad.header_tag = "FUTR";
      input = archive(&bad,1,26,7);
      owner = create(&input,STELA_METAL_ASSEMBLY_REFLECTION); CHECK(!owner); free(input.data);
   }
   struct specification empty = s; empty.public_tag = "NONE"; empty.private_tag = "NONE"; empty.header_tag = "NONE";
   input = archive(&empty,1,26,7); owner = create(&input,STELA_METAL_ASSEMBLY_OK);
   check_manifest(stela_metal_assembly_manifest(owner),1); destroy(&owner); free(input.data);
   input = archive(&s,1,26,7);
   for (unsigned bad = 0; bad < 5; bad++) {
      options = stela_metal_assembly_default_options();
      if (bad == 0) options.abi++;
      if (bad == 1) options.reserved = 1;
      if (bad == 2) options.max_entries = 0;
      if (bad == 3) options.max_input_bytes = 3;
      if (bad == 4) options.max_metadata_bytes = 1;
      allocation_attempts = 0;
      CHECK(stela_metal_assemble_archive(&options,input.data,input.count,&owner,&error) ==
         (bad < 2 ? STELA_METAL_ASSEMBLY_ABI_MISMATCH : STELA_METAL_ASSEMBLY_LIMIT) && !owner);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
      CHECK(!allocation_attempts && !live_allocations);
#endif
   }
   free(input.data); LLVMDisposeMemoryBuffer(module);

   char *metadata = replace(stela_air_test_metadata,"!\"uint\", !\"air.arg_name\", !\"output\"",
      "!\"UnknownStructure\", !\"air.arg_name\", !\"output\"");
   module = stela_air_test_custom_bitcode(stela_air_test_prefix,stela_air_test_store_body,metadata,""); free(metadata);
   s = specification(module,"kernel"); input = archive(&s,1,26,7);
   owner = create(&input,STELA_METAL_ASSEMBLY_REFLECTION); CHECK(!owner); free(input.data); LLVMDisposeMemoryBuffer(module);
   metadata = replace(stela_air_test_metadata,"!\"output\"","!\"out\\00put\"");
   module = stela_air_test_custom_bitcode(stela_air_test_prefix,stela_air_test_store_body,metadata,""); free(metadata);
   s = specification(module,"kernel"); input = archive(&s,1,26,7);
   owner = create(&input,STELA_METAL_ASSEMBLY_REFLECTION); CHECK(!owner); free(input.data); LLVMDisposeMemoryBuffer(module);
   metadata = replace(stela_air_test_metadata,"!\"output\"","!\"out\\FF\"");
   module = stela_air_test_custom_bitcode(stela_air_test_prefix,stela_air_test_store_body,metadata,""); free(metadata);
   s = specification(module,"kernel"); input = archive(&s,1,26,7);
   owner = create(&input,STELA_METAL_ASSEMBLY_REFLECTION); CHECK(!owner); free(input.data); LLVMDisposeMemoryBuffer(module);
   metadata = replace(stela_air_test_metadata,"i32 2, i32 8, i32 0","i32 2, i32 7, i32 0");
   module = stela_air_test_custom_bitcode(stela_air_test_prefix,stela_air_test_store_body,metadata,""); free(metadata);
   s = specification(module,"kernel"); input = archive(&s,1,26,7);
   owner = create(&input,STELA_METAL_ASSEMBLY_AIR); CHECK(!owner); free(input.data); LLVMDisposeMemoryBuffer(module);
   module = stela_air_test_bitcode(stela_air_test_store_body,"@unimplemented = constant i32 1\n");
   s = specification(module,"kernel"); input = archive(&s,1,26,7);
   owner = create(&input,STELA_METAL_ASSEMBLY_REFLECTION); CHECK(!owner); free(input.data); LLVMDisposeMemoryBuffer(module);

   char *prefix = replace(stela_air_test_prefix,"macosx26.7.0","macosx26.7.3");
   module = stela_air_test_custom_bitcode(prefix,stela_air_test_store_body,stela_air_test_metadata,""); free(prefix);
   s = specification(module,"kernel"); input = archive(&s,1,26,7); owner = create(&input,STELA_METAL_ASSEMBLY_OK);
   CHECK(strstr((const char *)stela_metal_assembly_manifest(owner)->target,"26.7.3"));
   destroy(&owner); free(input.data); LLVMDisposeMemoryBuffer(module);

   /* Reversed archive export order, both names in ONE shared original module. */
   metadata = replace(stela_air_test_metadata,"!air.kernel = !{!2}","!air.kernel = !{!2,!11}");
   module = stela_air_test_custom_bitcode(stela_air_test_prefix,stela_air_test_store_body,metadata,
      "define void @second(i32 %tid, ptr addrspace(1) %out) { ret void }\n!11 = !{ptr @second,!3,!4}\n"); free(metadata);
   struct specification two[] = {specification(module,"second"),specification(module,"kernel")};
   /* Shared AIR can contain more kernels than the archive exports. Check the
    * complete module within the explicit inspection budget; export only NAME. */
   input = archive(&two[1],1,26,7); owner = create(&input,STELA_METAL_ASSEMBLY_OK);
   check_manifest(stela_metal_assembly_manifest(owner),1); destroy(&owner); free(input.data);
   input = archive(two,2,26,7); allocation_attempts = 0;
   owner = create(&input,STELA_METAL_ASSEMBLY_OK); size_t successful_allocations = allocation_attempts;
   m = stela_metal_assembly_manifest(owner); check_manifest(m,2);
   CHECK(!strcmp((const char *)m->entries[0].name,"second") && !strcmp((const char *)m->entries[1].name,"kernel"));
   CHECK(m->entries[0].air_offset == m->entries[1].air_offset &&
      m->entries[0].entry.module_offset == m->entries[1].entry.module_offset &&
      !memcmp(m->entries[0].air_sha256,m->entries[1].air_sha256,32));
   CHECK(!m->entries[0].arguments[1].used && m->entries[1].arguments[1].used); destroy(&owner);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
   CHECK(successful_allocations >= 6);
   for (size_t fail = 1; fail <= successful_allocations; fail++) {
      allocation_attempts = 0; fail_allocation = fail;
      owner = create(&input,STELA_METAL_ASSEMBLY_ALLOCATION); CHECK(!owner && !live_allocations);
   }
   fail_allocation = 0;
#else
   (void)successful_allocations;
#endif
   /* Exhaust the metadata budget only after copying the first shared-module
    * export; no partial manifest or live owned C allocation may escape. */
   options = stela_metal_assembly_default_options(); options.max_metadata_bytes = 1200; allocation_attempts = 0;
   CHECK(stela_metal_assemble_archive(&options,input.data,input.count,&owner,&error) == STELA_METAL_ASSEMBLY_LIMIT && !owner);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
   CHECK(allocation_attempts == 5 && !live_allocations);
#endif
   /* A second record sharing a range cannot bypass a different expected HASH. */
   two[1].wrong_hash = true; struct bytes bad_hash = archive(two,2,26,7);
   owner = create(&bad_hash,STELA_METAL_ASSEMBLY_CONTAINER); CHECK(!owner); free(bad_hash.data);
   free(input.data); LLVMDisposeMemoryBuffer(module);

   /* Different original modules must agree on the full target, including patch. */
   module = stela_air_test_bitcode(stela_air_test_store_body,"");
   prefix = replace(stela_air_test_prefix,"@kernel","@second"); char *target = replace(prefix,"26.7.0","26.7.3"); free(prefix);
   metadata = replace(stela_air_test_metadata,"@kernel","@second");
   LLVMMemoryBufferRef second = stela_air_test_custom_bitcode(target,stela_air_test_store_body,metadata,""); free(target); free(metadata);
   two[0] = specification(module,"kernel"); two[1] = specification(second,"second"); input = archive(two,2,26,7);
   owner = create(&input,STELA_METAL_ASSEMBLY_IDENTITY); CHECK(!owner);
   free(input.data); LLVMDisposeMemoryBuffer(module); LLVMDisposeMemoryBuffer(second);
   puts("assembly original LLVM/MTLB ownership, identity, reflection, target and failure tests passed");
}
static struct bytes read_file(const char *path, size_t maximum)
{
   FILE *f = fopen(path,"rb"); CHECK(f && !fseek(f,0,SEEK_END)); long n = ftell(f);
   CHECK(n > 0 && (uint64_t)n <= maximum && !fseek(f,0,SEEK_SET));
   struct bytes bytes = {.data=malloc((size_t)n),.count=(size_t)n}; CHECK(bytes.data);
   CHECK(fread(bytes.data,1,bytes.count,f) == bytes.count && !fclose(f)); return bytes;
}
static unsigned number(const char *text)
{
   char *end; errno = 0; unsigned long n = strtoul(text,&end,10);
   CHECK(!errno && *text && !*end && n <= UINT16_MAX); return (unsigned)n;
}
static void original_archive(int argc, char **argv)
{
   CHECK(argc == 10); /* --archive AIR NAME AIRminor MSLmajor MSLminor OSmajor OSminor expected-refusal */
   struct bytes module = read_file(argv[2],64u*1024u*1024u);
   struct specification s = {.name=argv[3],.kind=2,.air_minor=(uint16_t)number(argv[4]),
      .language_major=(uint16_t)number(argv[5]),.language_minor=(uint16_t)number(argv[6]),
      .module=module.data,.module_bytes=module.count};
   struct bytes input = archive(&s,1,(uint16_t)number(argv[7]),(uint16_t)number(argv[8]));
   bool refusal = !strcmp(argv[9],"refuse-reflection"); CHECK(refusal || !strcmp(argv[9],"complete"));
   struct stela_metal_assembly *owner = create(&input,refusal ? STELA_METAL_ASSEMBLY_REFLECTION : STELA_METAL_ASSEMBLY_OK);
   if (owner) {
      const struct stela_metal_library_manifest *m = stela_metal_assembly_manifest(owner); check_manifest(m,1);
      uint8_t expected[32]; digest(module.data,module.count,expected);
      CHECK(!memcmp(expected,m->entries[0].entry.module_sha256,32));
      printf("original-air-manifest entry=%s bytes=%zu air=2.%u language=%u.%u target=%s original_module_sha256=",
         argv[3],module.count,s.air_minor,s.language_major,s.language_minor,m->target);
      for (unsigned i = 0; i < 32; i++) printf("%02x",expected[i]); puts(""); destroy(&owner);
   } else puts("original-air-manifest explicit incomplete-reflection refusal");
   free(input.data); free(module.data);
}
static void original_archive_pair(int argc, char **argv)
{
   CHECK(argc == 11); /* --archive-pair AIR NAME1 NAME2 AIRminor MSLmajor MSLminor OSmajor OSminor complete */
   CHECK(!strcmp(argv[10],"complete"));
   struct bytes module = read_file(argv[2],64u*1024u*1024u);
   struct specification specs[2];
   for (unsigned i = 0; i < 2; i++) specs[i] = (struct specification){
      .name=argv[3+i],.kind=2,.air_minor=(uint16_t)number(argv[5]),
      .language_major=(uint16_t)number(argv[6]),.language_minor=(uint16_t)number(argv[7]),
      .module=module.data,.module_bytes=module.count};
   struct bytes input = archive(specs,2,(uint16_t)number(argv[8]),(uint16_t)number(argv[9]));
   struct stela_metal_assembly *owner = create(&input,STELA_METAL_ASSEMBLY_OK);
   const struct stela_metal_library_manifest *m = stela_metal_assembly_manifest(owner);check_manifest(m,2);
   uint8_t expected[32];digest(module.data,module.count,expected);
   CHECK(m->entries[0].entry.module_offset==m->entries[1].entry.module_offset &&
         m->entries[0].air_offset==m->entries[1].air_offset);
   for(unsigned i=0;i<2;i++) CHECK(!memcmp(expected,m->entries[i].entry.module_sha256,32)&&
      m->entries[i].name_bytes==strlen(specs[i].name)&&!memcmp(m->entries[i].name,specs[i].name,m->entries[i].name_bytes));
   memset(module.data,0,module.count);free(module.data);memset(input.data,0,input.count);free(input.data);
   check_manifest(stela_metal_assembly_manifest(owner),2);
   printf("original-air-manifest-pair entries=%s,%s module_bytes=%zu original_module_sha256=",specs[0].name,specs[1].name,module.count);
   for(unsigned i=0;i<32;i++)printf("%02x",expected[i]);puts("");destroy(&owner);
}
static void original_source(int argc, char **argv)
{
   CHECK(argc == 5); /* --source ORIGINAL_MSL ORIGINAL_ADAPTER_AIR RESULT_IDENTITY_208_BYTES */
   struct bytes source = read_file(argv[2],64u*1024u*1024u), air = read_file(argv[3],64u*1024u*1024u);
   struct bytes build = read_file(argv[4],208); CHECK(build.count == 208);
   struct stela_msl_output compiled = {.air=air.data,.air_bytes=air.count};
   /* Independent original producer receipt: no rehash-to-bless edited files. */
   memcpy(compiled.source_sha256,build.data,32); memcpy(compiled.air_sha256,build.data+32,32);
   memcpy(&compiled.build,build.data+64,144); free(build.data);
   const struct stela_msl_build_identity expected_build = compiled.build;
   uint8_t expected_source_hash[32], expected_air_hash[32];
   memcpy(expected_source_hash,compiled.source_sha256,32); memcpy(expected_air_hash,compiled.air_sha256,32);
   struct stela_msl_apple_config config = stela_msl_apple_default_config();
   struct stela_msl_request request = {.source=source.data,.source_bytes=source.count,
      .language_version=0x40001,.fast_math=true,.target_triple="air64_v29-apple-macosx27.2.0"};
   struct stela_metal_assembly_options options = stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error; struct stela_metal_assembly *owner = NULL;
   for (unsigned bad = 0; bad < 7; bad++) {
      struct stela_msl_output wrong = compiled; struct stela_msl_request wrong_request = request;
      struct stela_msl_apple_config wrong_config = config;
      if (bad == 0) wrong.air_sha256[0] ^= 1;
      if (bad == 1) wrong.source_sha256[0] ^= 1;
      if (bad == 2) memset(wrong.build.gpucompiler_uuid,0,16);
      if (bad == 3) wrong_request.fast_math = false;
      if (bad == 4) wrong_request.target_triple = "air64_v29-apple-macosx27.3.0";
      if (bad == 5) wrong_request.language_version = 0x30001;
      if (bad == 6) wrong_config.profile = 0;
      CHECK(stela_metal_assemble_source(&options,&wrong_config,&wrong_request,&wrong,&owner,&error) == STELA_METAL_ASSEMBLY_SOURCE && !owner);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
      CHECK(!live_allocations);
#endif
   }
   allocation_attempts = 0;
   enum stela_metal_assembly_status status = stela_metal_assemble_source(&options,&config,&request,&compiled,&owner,&error);
   if (status) fprintf(stderr,"Source assembly refused: %s\n",error.detail);
   CHECK(!status && owner); size_t successful_allocations = allocation_attempts;
   const struct stela_metal_library_manifest *m = stela_metal_assembly_manifest(owner);
   unsigned entries = m->entry_count; check_manifest(m,entries);
   CHECK(m->flags == STELA_METAL_LIBRARY_SOURCE_COMPILED && m->compiler_profile == 1 &&
      m->request_language == request.language_version && m->request_fast_math == 1 &&
      !memcmp(&m->build,&compiled.build,sizeof(m->build)) && !memcmp(m->source_sha256,compiled.source_sha256,32) &&
      !memcmp(m->input.original_sha256,compiled.air_sha256,32));
   for (unsigned i = 0; i < entries; i++) CHECK(m->entries[i].entry.module_offset == 0 &&
      m->entries[i].entry.module_bytes == air.count && !memcmp(m->entries[i].entry.module_sha256,compiled.air_sha256,32));
   destroy(&owner);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
   CHECK(successful_allocations >= 5);
   for (size_t fail = 1; fail <= successful_allocations; fail++) {
      allocation_attempts = 0; fail_allocation = fail;
      CHECK(stela_metal_assemble_source(&options,&config,&request,&compiled,&owner,&error) == STELA_METAL_ASSEMBLY_ALLOCATION &&
         !owner && !live_allocations);
   }
   fail_allocation = 0;
#else
   (void)successful_allocations;
#endif
   CHECK(!stela_metal_assemble_source(&options,&config,&request,&compiled,&owner,&error));
   memset(source.data,0,source.count); free(source.data); memset(air.data,0,air.count); free(air.data);
   memset(&compiled,0,sizeof(compiled)); memset(&request,0,sizeof(request));
   m = stela_metal_assembly_manifest(owner); check_manifest(m,entries);
   CHECK(!memcmp(&m->build,&expected_build,sizeof(expected_build)) &&
      !memcmp(m->source_sha256,expected_source_hash,32) && !memcmp(m->input.original_sha256,expected_air_hash,32));
   CHECK(m->target_bytes == strlen("air64_v29-apple-macosx27.2.0") && !memcmp(m->target,"air64_v29-apple-macosx27.2.0",m->target_bytes));
   printf("original-source-manifest entries=%u profile=%u original_bytes=%llu original_sha256=",
      m->entry_count,m->compiler_profile,(unsigned long long)m->input.original_bytes);
   for (unsigned i = 0; i < 32; i++) printf("%02x",m->input.original_sha256[i]); puts(""); destroy(&owner);
}
static const char stage_fixture[] =
 "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
 "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
 "%Input = type { <4 x float> }\n"
 "define <{<4 x float>,<4 x float>}> @test_vertex(i32 %id, ptr addrspace(2) %buffer) {\n"
 " %index = zext i32 %id to i64\n"
 " %p = getelementptr %Input, ptr addrspace(2) %buffer, i64 %index, i32 0\n"
 " %position = load <4 x float>, ptr addrspace(2) %p, align 16\n"
 " %a = insertvalue <{<4 x float>,<4 x float>}> undef, <4 x float> %position, 0\n"
 " %b = insertvalue <{<4 x float>,<4 x float>}> %a, <4 x float> <float 1.0,float 0.5,float 0.25,float 0.0>, 1\n"
 " ret <{<4 x float>,<4 x float>}> %b\n}\n"
 "define <4 x float> @test_fragment(<4 x float> %position, <4 x float> %color) { ret <4 x float> %color }\n"
 "!air.vertex = !{!0}\n!air.fragment = !{!10}\n"
 "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
 "!air.compile_options = !{!23,!24,!25}\n"
 "!0 = !{ptr @test_vertex,!1,!4}\n!1 = !{!2,!3}\n"
 "!2 = !{!\"air.position\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"pos\"}\n"
 "!3 = !{!\"air.vertex_output\",!\"test.opaque.link\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"colour\"}\n"
 "!4 = !{!5,!6}\n!5 = !{i32 0,!\"air.vertex_id\",!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"id\"}\n"
 "!6 = !{i32 1,!\"air.buffer\",!\"air.location_index\",i32 0,i32 1,!\"air.read\",!\"air.address_space\",i32 2,"
 "!\"air.struct_type_info\",!7,!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"Input\",!\"air.arg_name\",!\"vertices\"}\n"
 "!7 = !{i32 0,i32 16,i32 0,!\"float4\",!\"position\"}\n"
 "!10 = !{ptr @test_fragment,!11,!13}\n!11 = !{!12}\n!12 = !{!\"air.render_target\",i32 0,i32 0,!\"air.arg_type_name\",!\"float4\"}\n"
 "!13 = !{!14,!15}\n"
 "!14 = !{i32 0,!\"air.position\",!\"air.center\",!\"air.no_perspective\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"position\",!\"air.arg_unused\"}\n"
 "!15 = !{i32 1,!\"air.fragment_input\",!\"test.opaque.link\",!\"air.center\",!\"air.perspective\",!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"color\"}\n"
 "!20 = !{i32 2,i32 9,i32 0}\n!21 = !{!\"Metal\",i32 4,i32 1,i32 0}\n"
 "!22 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
 "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

static void check_stage(struct stela_metal_assembly *owner, enum stela_air_stage stage,
                         uint32_t archive_index, const char *name)
{
   CHECK(owner && !stela_metal_assembly_manifest(owner));
   const struct stela_metal_stage_view *v=stela_metal_assembly_stage(owner);
   CHECK(v && v->size==sizeof(*v) && v->abi==1 && v->archive_index==archive_index && !v->reserved);
   const struct stela_metal_function_record *r=v->identity;
   CHECK(r && r->size==sizeof(*r) && r->abi==1 && !r->flags && !r->argument_count && !r->arguments);
   CHECK(r->entry.kind==(stage==STELA_AIR_VERTEX?0u:1u) && r->entry.air_minor==9 && r->entry.language_major==4 && r->entry.language_minor==1);
   CHECK(r->name_bytes==strlen(name) && !memcmp(r->name,name,r->name_bytes));
   CHECK(v->reflection->stage==stage && v->reflection->name==(const char *)r->name);
   CHECK(v->reflection->input_count==2 || v->reflection->input_count==3);
   CHECK(v->reflection->output_count==(stage==STELA_AIR_VERTEX?2u:1u));
   CHECK(v->reflection->framebuffer_fetch_present && v->reflection->framebuffer_fetch_enabled);
   const struct stela_metal_library_manifest *m=v->provenance;
   CHECK(m && !m->entries && !m->entry_count && m->target_bytes==strlen("air64_v29-apple-macosx27.2.0") &&
      !memcmp(m->target,"air64_v29-apple-macosx27.2.0",m->target_bytes));
   struct stela_metal_input_view original={.size=sizeof(original),.abi=1};
   CHECK(!stela_metal_assembly_original(owner,&original,NULL));
   CHECK(r->air_offset<=original.length && r->air_bytes<=original.length-r->air_offset);
   uint8_t hash[32]; digest(original.bytes,original.length,hash);CHECK(!memcmp(hash,m->input.original_sha256,32));
   digest(original.bytes+r->air_offset,r->air_bytes,hash);CHECK(!memcmp(hash,r->air_sha256,32));
   digest(original.bytes+r->entry.module_offset,r->entry.module_bytes,hash);CHECK(!memcmp(hash,r->entry.module_sha256,32));
   if(stage==STELA_AIR_VERTEX) {
      const struct stela_air_stage_io *buffer=&v->reflection->inputs[1];
      CHECK(buffer->semantic==STELA_AIR_STAGE_BUFFER && buffer->buffer.address_space==2 && buffer->buffer.access==STELA_AIR_READ);
      CHECK(buffer->member_count && buffer->members && buffer->members[0].name && buffer->members[0].type_name);
      CHECK(buffer->members[0].name_bytes==strlen(buffer->members[0].name));
      CHECK(v->reflection->outputs[1].identifier && v->reflection->outputs[1].identifier_bytes);
   } else CHECK(v->reflection->inputs[1].identifier && v->reflection->inputs[1].identifier_bytes);
}
static struct stela_metal_assembly *stage_archive(const struct bytes *input, unsigned index,
   enum stela_air_stage stage, enum stela_metal_assembly_status expected)
{
   struct stela_metal_assembly_options options=stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error;struct stela_metal_assembly *owner=NULL;
   enum stela_metal_assembly_status status=stela_metal_assemble_selected_stage_archive(&options,input->data,input->count,index,stage,&owner,&error);
   if(status!=expected)fprintf(stderr,"Stage archive expected%u got%u: %s\n",expected,status,error.detail);
   CHECK(status==expected && (!!owner)==(status==STELA_METAL_ASSEMBLY_OK));
   return owner;
}
static void stage_archive_tests(LLVMMemoryBufferRef module, const char *vertex, const char *fragment)
{
   size_t baseline_live=live_allocations; (void)baseline_live;
   struct specification specs[2];
   const char *names[]={vertex,fragment};
   for(unsigned i=0;i<2;i++) specs[i]=(struct specification){.name=names[i],.kind=(uint8_t)i,.air_minor=9,
      .language_major=4,.language_minor=1,.module=LLVMGetBufferStart(module),.module_bytes=LLVMGetBufferSize(module)};
   struct bytes input=archive(specs,2,27,2);
   struct stela_metal_assembly *owners[2]={NULL,NULL};
   for(unsigned i=0;i<2;i++) {
      enum stela_air_stage stage=i?STELA_AIR_FRAGMENT:STELA_AIR_VERTEX;
      allocation_attempts=0;owners[i]=stage_archive(&input,i,stage,STELA_METAL_ASSEMBLY_OK);
      size_t attempts=allocation_attempts;check_stage(owners[i],stage,i,names[i]);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
      CHECK(attempts>=5);
      size_t live_before=live_allocations;
      for(size_t fail=1;fail<=attempts;fail++) {
         allocation_attempts=0;fail_allocation=fail;
         CHECK(!stage_archive(&input,i,stage,STELA_METAL_ASSEMBLY_ALLOCATION));CHECK(live_allocations==live_before);
      }
      fail_allocation=0;
#else
      (void)attempts;
#endif
      struct stela_metal_assembly_options options=stela_metal_assembly_default_options();
      struct stela_metal_assembly_error error;
      struct stela_metal_assembly *existing=owners[i];
      CHECK(stela_metal_assemble_selected_stage_archive(&options,input.data,input.count,i,stage,&owners[i],&error)==STELA_METAL_ASSEMBLY_INPUT && owners[i]==existing);
      CHECK(!stage_archive(&input,i,i?STELA_AIR_VERTEX:STELA_AIR_FRAGMENT,STELA_METAL_ASSEMBLY_IDENTITY));
   }
   memset(input.data,0,input.count);free(input.data);
   for(unsigned i=0;i<2;i++) {check_stage(owners[i],i?STELA_AIR_FRAGMENT:STELA_AIR_VERTEX,i,names[i]);stela_metal_assembly_destroy(&owners[i]);stela_metal_assembly_destroy(&owners[i]);}
   for(unsigned bad=0;bad<8;bad++) {
      struct specification wrong=specs[0];unsigned major=27,minor=2;
      if(bad==0)wrong.kind=2;
      if(bad==1)wrong.name="absent_stage";
      if(bad==2)wrong.air_minor=8;
      if(bad==3)wrong.wrong_hash=true;
      if(bad==4)wrong.function_tag="CNST";
      if(bad==5)wrong.public_tag="ARGR";
      if(bad==6)minor=3;
      if(bad==7)wrong.header_tag="ARGR";
      input=archive(&wrong,1,(uint16_t)major,(uint16_t)minor);
      enum stela_metal_assembly_status expected=bad==1?STELA_METAL_ASSEMBLY_AIR:bad==3?STELA_METAL_ASSEMBLY_CONTAINER:
         bad==4||bad==5||bad==7?STELA_METAL_ASSEMBLY_REFLECTION:STELA_METAL_ASSEMBLY_IDENTITY;
      CHECK(!stage_archive(&input,0,STELA_AIR_VERTEX,expected));free(input.data);
#ifdef STELA_ASSEMBLY_ALLOC_TEST
      CHECK(live_allocations==baseline_live);
#endif
   }
   input=archive(specs,2,27,2);
   struct stela_metal_assembly_options options=stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error;struct stela_metal_assembly *none=NULL;
   options.max_entries=1;allocation_attempts=0;
   CHECK(stela_metal_assemble_selected_stage_archive(&options,input.data,input.count,0,STELA_AIR_VERTEX,&none,&error)==STELA_METAL_ASSEMBLY_LIMIT && !none);
   CHECK(!allocation_attempts);
   options=stela_metal_assembly_default_options();options.max_metadata_bytes=1;
   CHECK(stela_metal_assemble_selected_stage_archive(&options,input.data,input.count,0,STELA_AIR_VERTEX,&none,&error)==STELA_METAL_ASSEMBLY_LIMIT && !none);
   free(input.data);
   puts("selected-stage archive: trueTYPE0/1 ownedIO/members/provenance, lifetimes, identity/reflection/budget/OOM refusals passed");
}
static void stage_unit_tests(void)
{
   LLVMMemoryBufferRef module=stela_air_test_custom_bitcode("",stage_fixture,"","");
   stage_archive_tests(module,"test_vertex","test_fragment");LLVMDisposeMemoryBuffer(module);
   CHECK(!stela_metal_assembly_stage(NULL));
}
static void stage_original_source(int argc,char **argv)
{
   CHECK(argc==5);
   struct bytes source=read_file(argv[2],64u*1024u*1024u),air=read_file(argv[3],64u*1024u*1024u),identity=read_file(argv[4],208);
   CHECK(identity.count==208);
   struct stela_msl_output compiled={.air=air.data,.air_bytes=air.count};
   memcpy(compiled.source_sha256,identity.data,32);memcpy(compiled.air_sha256,identity.data+32,32);memcpy(&compiled.build,identity.data+64,144);free(identity.data);
   struct stela_msl_request request={.source=source.data,.source_bytes=source.count,.language_version=0x40001,.fast_math=true,.target_triple="air64_v29-apple-macosx27.2.0"};
   struct stela_msl_apple_config config=stela_msl_apple_default_config();
   struct stela_metal_assembly_options options=stela_metal_assembly_default_options();
   struct stela_metal_assembly_error error;struct stela_metal_assembly *owners[2]={NULL,NULL};
   const struct stela_msl_build_identity expected_build=compiled.build;
   uint8_t expected_source[32];memcpy(expected_source,compiled.source_sha256,32);
   const char *names[]={"vertexShader","fragmentShader"};
   for(unsigned i=0;i<2;i++) {
      enum stela_air_stage stage=i?STELA_AIR_FRAGMENT:STELA_AIR_VERTEX;
      allocation_attempts=0;
      CHECK(!stela_metal_assemble_selected_stage_source(&options,&config,&request,&compiled,names[i],strlen(names[i]),stage,&owners[i],&error));
      size_t attempts=allocation_attempts;
      check_stage(owners[i],stage,UINT32_MAX,names[i]);
      const struct stela_metal_library_manifest *p=stela_metal_assembly_stage(owners[i])->provenance;
      CHECK(p->flags==STELA_METAL_LIBRARY_SOURCE_COMPILED && p->compiler_profile==1 && p->request_language==0x40001 && p->request_fast_math==1 &&
         !memcmp(p->source_sha256,compiled.source_sha256,32) && !memcmp(&p->build,&compiled.build,sizeof(p->build)));
#ifdef STELA_ASSEMBLY_ALLOC_TEST
      size_t live_before=live_allocations;
      for(size_t fail=1;fail<=attempts;fail++) {
         allocation_attempts=0;fail_allocation=fail;struct stela_metal_assembly *none=NULL;
         CHECK(stela_metal_assemble_selected_stage_source(&options,&config,&request,&compiled,names[i],strlen(names[i]),stage,&none,&error)==STELA_METAL_ASSEMBLY_ALLOCATION && !none && live_allocations==live_before);
      }
      fail_allocation=0;
#else
      (void)attempts;
#endif
      for(unsigned bad=0;bad<5;bad++) {
         struct stela_metal_assembly *none=NULL;struct stela_msl_output wrong=compiled;
         struct stela_msl_request req=request;
         if(bad==0)wrong.air_sha256[0]^=1;
         if(bad==1)wrong.source_sha256[0]^=1;
         if(bad==2)memset(wrong.build.llvm_uuid,0,16);
         if(bad==3)req.target_triple="air64_v29-apple-macosx27.3.0";
         if(bad==4)req.fast_math=false;
         CHECK(stela_metal_assemble_selected_stage_source(&options,&config,&req,&wrong,names[i],strlen(names[i]),stage,&none,&error)==STELA_METAL_ASSEMBLY_SOURCE && !none);
      }
   }
   for(unsigned bad=0;bad<4;bad++) {
      struct stela_metal_assembly *none=NULL;
      const char *name=bad==0?"absent_stage":bad==1?"bad\xffname":"vertexShader";
      size_t length=bad==2?0:strlen(name);
      enum stela_air_stage stage=bad==3?0:STELA_AIR_VERTEX;
      enum stela_metal_assembly_status expected=bad==0?STELA_METAL_ASSEMBLY_AIR:STELA_METAL_ASSEMBLY_INPUT;
      CHECK(stela_metal_assemble_selected_stage_source(&options,&config,&request,&compiled,name,length,stage,&none,&error)==expected && !none);
   }
   /* Preserve the exact captured module under a synthetic MTLB framing too. */
   LLVMMemoryBufferRef raw=LLVMCreateMemoryBufferWithMemoryRangeCopy((const char *)air.data,air.count,"unchanged-original-triangle");
   stage_archive_tests(raw,names[0],names[1]);LLVMDisposeMemoryBuffer(raw);
   memset(source.data,0,source.count);free(source.data);memset(air.data,0,air.count);free(air.data);
   memset(&compiled,0,sizeof(compiled));memset(&request,0,sizeof(request));
   for(unsigned i=0;i<2;i++) {
      check_stage(owners[i],i?STELA_AIR_FRAGMENT:STELA_AIR_VERTEX,UINT32_MAX,names[i]);
      const struct stela_metal_library_manifest *p=stela_metal_assembly_stage(owners[i])->provenance;
      CHECK(!memcmp(&p->build,&expected_build,sizeof(expected_build)) && !memcmp(p->source_sha256,expected_source,32));
      stela_metal_assembly_destroy(&owners[i]);stela_metal_assembly_destroy(&owners[i]);
   }
#ifdef STELA_ASSEMBLY_ALLOC_TEST
   CHECK(!live_allocations);
#endif
   puts("selected-stage original Apple triangle source: exact trustedreceipt/source/AIR/build/request copied, caller storage destroyed");
}

int main(int argc, char **argv)
{
   unit_tests();
   stage_unit_tests();
   if (argc > 1 && !strcmp(argv[1],"--archive")) original_archive(argc,argv);
   else if (argc > 1 && !strcmp(argv[1],"--source")) original_source(argc,argv);
   else if (argc > 1 && !strcmp(argv[1],"--stage-source")) stage_original_source(argc,argv);
   else if (argc > 1 && !strcmp(argv[1],"--archive-pair")) original_archive_pair(argc,argv);
   else CHECK(argc == 1);
   return 0;
}
