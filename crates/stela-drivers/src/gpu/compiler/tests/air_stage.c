/* SPDX-License-Identifier: MIT */
#include "air_to_nir.h"
#include "llvm-c/BitReader.h"
#include "air_test_fixture.h"
#include "util/ralloc.h"
#include "util/mesa-blake3.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"%s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)

/* Original LLVM test source. Actual Apple compiler output is an unchanged,
 * externally supplied acceptance input and is never embedded in this file. */
static const char fixture[] =
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
static const nir_shader_compiler_options nir_options = {0};
/* Lexical outputs are a finite trace only after all control flow specializes. */
static bool finite_effect_body(nir_function_impl *impl)
{ return impl->structured && exec_list_length(&impl->body)==1; }
struct snapshot {
   struct stela_air_stage_entry entry;
   struct stela_air_stage_io inputs[AIR_MAX_ARGUMENTS], outputs[AIR_MAX_ARGUMENTS];
   struct stela_air_struct_member members[AIR_MAX_ARGUMENTS];
   char text[65536]; size_t used; unsigned member_count;
};
static const char *copy_text(struct snapshot *s, const char *p, size_t n)
{
   if (!p) { CHECK(!n); return NULL; }
   CHECK(n + 1 <= sizeof(s->text) - s->used);
   char *out = s->text + s->used; memcpy(out,p,n); out[n] = 0; s->used += n+1; return out;
}
static bool capture(const struct stela_air_inspection *info,const struct stela_air_stage_entry *entry,void *data)
{
   CHECK(info->air_minor == 9 && info->language_major == 4 && info->language_minor == 1);
   struct snapshot *s = data; *s = (struct snapshot){0}; s->entry = *entry;
   s->entry.name = copy_text(s,entry->name,entry->name_bytes);
   s->entry.inputs = s->inputs; s->entry.outputs = s->outputs;
   for (unsigned direction=0;direction<2;direction++) {
      unsigned n = direction ? entry->output_count : entry->input_count;
      const struct stela_air_stage_io *in = direction ? entry->outputs : entry->inputs;
      struct stela_air_stage_io *out = direction ? s->outputs : s->inputs;
      CHECK(n <= AIR_MAX_ARGUMENTS);
      for(unsigned i=0;i<n;i++) {
         out[i] = in[i];
         out[i].name = copy_text(s,in[i].name,in[i].name_bytes);
         out[i].type_name = copy_text(s,in[i].type_name,in[i].type_name_bytes);
         out[i].identifier = copy_text(s,in[i].identifier,in[i].identifier_bytes);
         CHECK(in[i].member_count <= AIR_MAX_ARGUMENTS-s->member_count);
         out[i].members = in[i].member_count ? &s->members[s->member_count] : NULL;
         for(unsigned m=0;m<in[i].member_count;m++) {
            struct stela_air_struct_member *a = &s->members[s->member_count++]; *a = in[i].members[m];
            a->name = copy_text(s,a->name,a->name_bytes); a->type_name = copy_text(s,a->type_name,a->type_name_bytes);
         }
      }
   }
   return true;
}
static bool count_stage_callback(const struct stela_air_inspection *a,
                                 const struct stela_air_stage_entry *b,void *data)
{ (void)a; (void)b; (*(unsigned *)data)++; return true; }
static LLVMMemoryBufferRef bitcode(const char *text)
{ return stela_air_test_custom_bitcode("",text,"",""); }
static bool bind(const struct stela_air_buffer *buffer,unsigned *slot,void *data)
{
   unsigned *calls=data;
   CHECK(buffer->address_space==2 && buffer->access==STELA_AIR_READ && buffer->index<2);
   (*calls)++; *slot=buffer->index; return true;
}
static struct stela_air_stage_options options(enum stela_air_stage stage,const struct stela_air_varying_slot *map,unsigned count,unsigned *calls)
{
   return (struct stela_air_stage_options){.stage=stage,.resources={.max_instructions=10000,
      .bind_ssbo=bind,.ssbo_count=2,.binding_data=calls,.fp_profile=STELA_AIR_FP_APPLE_32023_922_AIR29_MSL41},
      .varyings=map,.varying_count=count,.max_varying_slots=16};
}
static nir_shader *translate(LLVMMemoryBufferRef b,const char *name,const struct stela_air_stage_options *o)
{
   struct stela_air_error e;
   nir_shader *n=stela_air_stage_to_nir(LLVMGetBufferStart(b),LLVMGetBufferSize(b),name,&nir_options,o,&e);
   if(!n)fprintf(stderr,"translate %s: %u ordinal%u %s\n",name,e.kind,e.instruction,e.detail);
   CHECK(n && e.kind==STELA_AIR_OK); return n;
}
static void fold(nir_shader *nir)
{
   bool progress;
   do { progress=nir_opt_constant_folding(nir); progress|=nir_opt_dead_cf(nir);
      progress|=nir_opt_remove_phis(nir); progress|=nir_opt_copy_prop(nir); progress|=nir_opt_dce(nir);
   }while(progress);
   nir_validate_shader(nir,"stage fixture specialization");
}
static void replace_def(nir_intrinsic_instr *i,nir_def *v)
{ nir_def_rewrite_uses(&i->def,v); nir_instr_remove(&i->instr); }
static uint32_t bits(float f) { uint32_t u; memcpy(&u,&f,4); return u; }

/* Specialized inputs only in this semantics test. Production retains genuine
 * builtin IDs, bounded loads and interpolation. This is no runtime interpreter. */
static void specialize(nir_shader *nir,unsigned vertex,const uint32_t *words,unsigned bytes,
                       uint32_t width,uint32_t height,bool fragment)
{
   nir_foreach_function_impl(impl,nir) nir_foreach_block(block,impl) nir_foreach_instr_safe(instr,block) {
      if(instr->type!=nir_instr_type_intrinsic)continue;
      nir_intrinsic_instr *i=nir_instr_as_intrinsic(instr);
      nir_builder b=nir_builder_at(nir_before_instr(instr));
      if(i->intrinsic==nir_intrinsic_load_vertex_id) replace_def(i,nir_imm_int(&b,vertex));
      else if(i->intrinsic==nir_intrinsic_get_ssbo_size) {
         CHECK(nir_src_is_const(i->src[0])); unsigned slot=nir_src_as_uint(i->src[0]); CHECK(slot<2);
         replace_def(i,nir_imm_int(&b,slot ? 8 : bytes));
      } else if(fragment && i->intrinsic==nir_intrinsic_load_deref) {
         nir_variable *v=nir_intrinsic_get_var(i,0);
         if(v->data.mode==nir_var_shader_in) {
            CHECK(v->data.location==VARYING_SLOT_VAR0 && v->data.interpolation==INTERP_MODE_SMOOTH);
            nir_def *c[4];for(unsigned k=0;k<4;k++)c[k]=nir_imm_int(&b,words[k]);
            replace_def(i,nir_vec(&b,c,4));
         }
      }
   }
   fold(nir);
   if(!fragment) {
      nir_foreach_function_impl(impl,nir) nir_foreach_block(block,impl) nir_foreach_instr_safe(instr,block) {
         if(instr->type!=nir_instr_type_intrinsic)continue;
         nir_intrinsic_instr *i=nir_instr_as_intrinsic(instr);if(i->intrinsic!=nir_intrinsic_load_ssbo)continue;
         CHECK(nir_src_is_const(i->src[0]) && nir_src_is_const(i->src[1]));
         unsigned slot=nir_src_as_uint(i->src[0]),offset=nir_src_as_uint(i->src[1]);
         unsigned n=i->def.num_components; CHECK(i->def.bit_size==32 && !(offset%4) && slot<2);
         nir_builder b=nir_builder_at(nir_before_instr(instr));nir_def *c[4];
         for(unsigned k=0;k<n;k++) {
            CHECK(offset+4*k+4<=(slot?8:bytes));
            c[k]=nir_imm_int(&b,slot ? (offset/4+k ? height : width) : words[offset/4+k]);
         }
         replace_def(i,nir_vec(&b,c,n));
      }
      fold(nir);
   }
}
static void outputs(nir_shader *nir,const uint32_t *position,const uint32_t *color)
{
   unsigned stores=0;
   nir_foreach_function_impl(impl,nir) CHECK(finite_effect_body(impl));
   nir_foreach_function_impl(impl,nir) nir_foreach_block(block,impl) nir_foreach_instr(instr,block) {
      if(instr->type!=nir_instr_type_intrinsic)continue;
      nir_intrinsic_instr *i=nir_instr_as_intrinsic(instr);
      CHECK(i->intrinsic!=nir_intrinsic_load_ssbo && i->intrinsic!=nir_intrinsic_store_ssbo &&
            i->intrinsic!=nir_intrinsic_load_vertex_id);
      if(i->intrinsic!=nir_intrinsic_store_deref)continue;
      nir_variable *v=nir_intrinsic_get_var(i,0);CHECK(v->data.mode==nir_var_shader_out);
      const uint32_t *expected=v->data.location==VARYING_SLOT_POS ? position : color;
      CHECK(expected && nir_src_is_const(i->src[1]));
      nir_const_value *values=nir_src_as_const_value(i->src[1]);
      for(unsigned k=0;k<4;k++)CHECK(values[k].u32==expected[k]);
      stores++;
   }
   CHECK(stores==(position?2:1));
}
static char *change(const char *source,const char *old,const char *replacement)
{
   const char *p=strstr(source,old);CHECK(p);size_t first=(size_t)(p-source);
   char *r=malloc(strlen(source)-strlen(old)+strlen(replacement)+1);CHECK(r);
   memcpy(r,source,first);strcpy(r+first,replacement);strcpy(r+first+strlen(replacement),p+strlen(old));return r;
}
static void refusal(const char *text,const char *entry,enum stela_air_stage stage,
                    const struct stela_air_stage_options *o,enum stela_air_error_kind expected)
{
   LLVMMemoryBufferRef b=bitcode(text);struct stela_air_error e;
   struct stela_air_stage_options actual=*o;actual.stage=stage;
   nir_shader *n=stela_air_stage_to_nir(LLVMGetBufferStart(b),LLVMGetBufferSize(b),entry,&nir_options,&actual,&e);
   if(n || e.kind!=expected)fprintf(stderr,"refusal expected%u got%u %s\n",expected,e.kind,e.detail);
   CHECK(!n && e.kind==expected);LLVMDisposeMemoryBuffer(b);
}
static nir_def *stage_binding_prelude(nir_builder *b,const struct stela_air_buffer *buffer,void *data)
{
   unsigned mode=*(unsigned *)data;
   CHECK(buffer->address_space==2 && buffer->access==STELA_AIR_READ);
   nir_def *address=nir_imm_int64(b,0x100000); /* Compile fixture only. */
   if(mode==1) {
      nir_if *region=nir_push_if(b,nir_imm_true(b));
      nir_def *yes=nir_imm_int64(b,0x100000);
      nir_push_else(b,region);nir_def *no=nir_imm_int64(b,0x200000);
      nir_pop_if(b,region);address=nir_if_phi(b,yes,no);
   } else if(mode==2) nir_jump(b,nir_jump_return);
   return address;
}
static void stage_binding_prelude_contract(void)
{
   /* Buffer-first descriptors make the next vertex-ID instruction expose a
    * terminal callback immediately, before any output variable is stored. */
   for(unsigned order=0;order<2;order++) {
      char *text=order?change(fixture,"!4 = !{!5,!6}","!4 = !{!6,!5}"):NULL;
      LLVMMemoryBufferRef raw=bitcode(text?text:fixture);free(text);
      struct snapshot vs,fs; struct stela_air_error link_error;
      CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),
         "test_vertex",STELA_AIR_VERTEX,capture,&vs,&link_error));
      CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),
         "test_fragment",STELA_AIR_FRAGMENT,capture,&fs,&link_error));
      struct stela_air_varying_slot map[16]; unsigned count=0;
      CHECK(stela_air_link_stage_io(&vs.entry,&fs.entry,16,map,16,&count,&link_error) && count==1);
      for(unsigned mode=0;mode<3;mode++) {
         struct stela_air_stage_options o=options(STELA_AIR_VERTEX,map,count,NULL);
         o.resources.bind_ssbo=NULL;o.resources.ssbo_count=0;
         o.resources.bind_buffer=stage_binding_prelude;o.resources.binding_data=&mode;
         struct stela_air_error e;
         nir_shader *nir=stela_air_stage_to_nir(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),
            "test_vertex",&nir_options,&o,&e);
         if (!nir && !mode) fprintf(stderr,"prelude order%u: %u %s\n",order,e.kind,e.detail);
         if(!mode) {CHECK(nir && e.kind==STELA_AIR_OK);nir_validate_shader(nir,"valid stage binding prelude");ralloc_free(nir);}
         else CHECK(!nir && e.kind==STELA_AIR_CONTROL_FLOW && e.detail[0]);
      }
      LLVMDisposeMemoryBuffer(raw);
   }
}
static void run(LLVMMemoryBufferRef raw,const char *vsname,const char *fsname,bool original)
{
   struct snapshot vs,fs;struct stela_air_error e;
   CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),vsname,STELA_AIR_VERTEX,capture,&vs,&e));
   CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),fsname,STELA_AIR_FRAGMENT,capture,&fs,&e));
   CHECK(vs.entry.output_count==2 && fs.entry.output_count==1);
   CHECK(vs.entry.framebuffer_fetch_present && vs.entry.framebuffer_fetch_enabled &&
         fs.entry.framebuffer_fetch_present && fs.entry.framebuffer_fetch_enabled);
   struct stela_air_varying_slot map[16];unsigned count=0;
   CHECK(stela_air_link_stage_io(&vs.entry,&fs.entry,16,map,16,&count,&e) && count==1);
   unsigned calls=0;struct stela_air_stage_options vo=options(STELA_AIR_VERTEX,map,count,&calls);
   struct stela_air_stage_options fo=options(STELA_AIR_FRAGMENT,map,count,&calls);
   fo.resources.bind_ssbo=NULL; fo.resources.ssbo_count=0;
   uint32_t words[24]={0},position[4]={bits(.5f),bits(-.25f),0,bits(1.f)};
   uint32_t color[4]={bits(.25f),bits(.5f),bits(.75f),bits(1.f)};
   unsigned stride=original?8:4;
   for(unsigned i=0;i<3;i++) {
      unsigned off=i*stride;
      if(original) {words[off]=bits(32.f);words[off+1]=bits(-32.f);memcpy(words+off+4,color,16);}
      else memcpy(words+off,position,16);
   }
   uint32_t synthetic_color[4]={bits(1.f),bits(.5f),bits(.25f),0};
   for(unsigned vertex=0;vertex<3;vertex++) {
      nir_shader *n=translate(raw,vsname,&vo);CHECK(n->info.stage==MESA_SHADER_VERTEX);
      specialize(n,vertex,words,3*stride*4,128,256,false);
      outputs(n,position,original?color:synthetic_color);ralloc_free(n);
   }
   nir_shader *f=translate(raw,fsname,&fo);CHECK(f->info.stage==MESA_SHADER_FRAGMENT && f->info.fs.origin_upper_left);
   specialize(f,0,color,16,0,0,true);outputs(f,NULL,color);ralloc_free(f);
   CHECK(calls==(original?6:3));
   /* All render-specific option errors must happen before a binding callback. */
   unsigned before=calls;
   struct stela_air_stage_options bad=vo;bad.resources.workgroup_size[0]=1;
   CHECK(!stela_air_stage_to_nir(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),vsname,&nir_options,&bad,&e) && e.kind==STELA_AIR_INPUT);
   bad=vo;bad.resources.max_threadgroup_bytes=16;
   CHECK(!stela_air_stage_to_nir(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),vsname,&nir_options,&bad,&e) && e.kind==STELA_AIR_INPUT);
   struct stela_air_varying_slot duplicate[2]={map[0],map[0]};bad=vo;bad.varyings=duplicate;bad.varying_count=2;
   CHECK(!stela_air_stage_to_nir(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),vsname,&nir_options,&bad,&e) && e.kind==STELA_AIR_ARGUMENT);
   CHECK(calls==before);
   if(!original) {
      const struct {const char *old,*replacement;enum stela_air_error_kind error;} cases[]={
         {"i32 2,!\"air.struct_type_info\"","i32 1,!\"air.struct_type_info\"",STELA_AIR_ARGUMENT},
         {"i32 0,i32 16,i32 0,!\"float4\"","i32 4,i32 16,i32 0,!\"float4\"",STELA_AIR_TYPE},
         {"!\"air.read\",!\"air.address_space\"","!\"air.write\",!\"air.address_space\"",STELA_AIR_ARGUMENT},
         {"<float 1.0,float 0.5,float 0.25,float 0.0>","<float 1.0,float poison,float 0.25,float 0.0>",STELA_AIR_INSTRUCTION},
         {"%Input = type { <4 x float> }","%Input = type { <4 x i32> }",STELA_AIR_TYPE},
         {"e-p:64:64-i32:32", "e-p:64:64-p2:32:32-i32:32", STELA_AIR_TARGET},
         {"getelementptr %Input", "getelementptr <vscale x 4 x float>", STELA_AIR_TYPE},
      };
      for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
         char *text=change(fixture,cases[i].old,cases[i].replacement);
         refusal(text,vsname,STELA_AIR_VERTEX,&vo,cases[i].error);free(text);
      }
   }
   printf("AIR stage %s: exact vertex positions/stride/color and fragment dataflow; metadata/link/options/refusals passed\n",original?"original-apple-triangle":"original-llvm-fixture");
}
static void
link_and_option_failures(LLVMMemoryBufferRef raw, const char *vsname, const char *fsname)
{
   struct snapshot vs, fs;
   struct stela_air_error e;
   CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw), vsname,
      STELA_AIR_VERTEX, capture, &vs, &e));
   CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw), fsname,
      STELA_AIR_FRAGMENT, capture, &fs, &e));
   struct stela_air_varying_slot rows[2]; unsigned n = 0;
   CHECK(stela_air_link_stage_io(&vs.entry, &fs.entry, 16, rows, 2, &n, &e) && n == 1);
   struct stela_air_varying_slot saved = rows[0], bad[2];
   unsigned calls = 0;
   struct stela_air_stage_options o = options(STELA_AIR_VERTEX, bad, 1, &calls);
   for (unsigned test = 0; test < 9; test++) {
      bad[0] = saved; bad[1] = saved; o.varying_count = 1; o.max_varying_slots = 16;
      o.resources.max_instructions = 10000;
      switch (test) {
      case 0: bad[0].identifier = "wrong"; bad[0].identifier_bytes = 5; break;
      case 1: bad[0].components = 3; break;
      case 2: bad[0].location = 16; break;
      case 3: bad[0].identifier = "\xc0\xaf"; bad[0].identifier_bytes = 2; break;
      case 4: o.varying_count = 2; bad[1].location = 1; break;
      case 5: o.varying_count = 2; bad[1].identifier = "other"; bad[1].identifier_bytes = 5; break;
      case 6: o.max_varying_slots = 33; break;
      case 7: o.max_varying_slots = 0; break;
      case 8: o.resources.max_instructions = 1; break;
      }
      nir_shader *nir = stela_air_stage_to_nir(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw),
         vsname, &nir_options, &o, &e);
      CHECK(!nir && e.kind != STELA_AIR_OK && calls == 0);
   }
   /* Link failure is atomic even when the caller supplies sentinel row/count. */
   struct stela_air_stage_io saved_input = fs.inputs[1];
   fs.inputs[1].components = 3; n = 123;
   rows[0] = saved; rows[0].location = 9;
   CHECK(!stela_air_link_stage_io(&vs.entry, &fs.entry, 16, rows, 2, &n, &e));
   CHECK(n == 123 && rows[0].location == 9);
   fs.inputs[1] = saved_input;
   CHECK(!stela_air_inspect_stage(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw),
      vsname, STELA_AIR_FRAGMENT, capture, &fs, &e) && e.kind == STELA_AIR_METADATA);
   char *vector_id = change(fixture, "i32 %id, ptr", "<3 x i32> %id, ptr");
   char *unused_id = change(vector_id, "%index = zext i32 %id to i64", "%index = zext i32 0 to i64");
   free(vector_id); LLVMMemoryBufferRef malformed = bitcode(unused_id);
   unsigned callbacks = 0;
   CHECK(!stela_air_inspect_stage(LLVMGetBufferStart(malformed),LLVMGetBufferSize(malformed),
      "test_vertex",STELA_AIR_VERTEX,count_stage_callback,&callbacks,&e) && e.kind == STELA_AIR_ARGUMENT);
   CHECK(callbacks == 0);
   o = options(STELA_AIR_VERTEX,rows,1,&callbacks); rows[0] = saved;
   CHECK(!stela_air_stage_to_nir(LLVMGetBufferStart(malformed),LLVMGetBufferSize(malformed),
      "test_vertex",&nir_options,&o,&e) && e.kind == STELA_AIR_ARGUMENT && callbacks == 0);
   LLVMDisposeMemoryBuffer(malformed); free(unused_id);
   puts("Stage maps/types/UTF8/locations/options/budgets refuse before callbacks; linkage failure atomic");
}

static void
primitive_layout_semantics(void)
{
   char *a = change(fixture, "!\"air.struct_type_info\",!7,", "");
   char *vector = change(a, "!\"Input\"", "!\"float4\""); free(a);
   a = change(vector, "getelementptr %Input", "getelementptr <4 x float>"); free(vector); vector = a;
   char *scalar = change(vector,
      " %p = getelementptr <4 x float>, ptr addrspace(2) %buffer, i64 %index, i32 0\n %position = load <4 x float>, ptr addrspace(2) %p, align 16",
      " %position = fadd <4 x float> zeroinitializer, zeroinitializer");
   a = change(scalar, "i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\"",
      "i32 4,!\"air.arg_type_align_size\",i32 4,!\"air.arg_type_name\",!\"uint\""); free(scalar); scalar = a;
   const char *sources[] = {vector, scalar};
   const char *layouts[] = {"v128:128", "i32:32"};
   const char *overaligned[] = {"v128:256", "i32:64"};
   for (unsigned i = 0; i < 2; i++) {
      LLVMMemoryBufferRef raw = bitcode(sources[i]); struct snapshot vs, fs; struct stela_air_error e;
      CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw),
         "test_vertex", STELA_AIR_VERTEX, capture, &vs, &e));
      CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw),
         "test_fragment", STELA_AIR_FRAGMENT, capture, &fs, &e));
      struct stela_air_varying_slot map[16]; unsigned count = 0, callbacks = 0;
      CHECK(stela_air_link_stage_io(&vs.entry, &fs.entry, 16, map, 16, &count, &e));
      struct stela_air_stage_options o = options(STELA_AIR_VERTEX, map, count, &callbacks);
      nir_shader *nir = translate(raw, "test_vertex", &o); ralloc_free(nir);
      LLVMDisposeMemoryBuffer(raw);
      char *bad = change(sources[i], layouts[i], overaligned[i]); raw = bitcode(bad); free(bad);
      callbacks = 0;
      CHECK(!stela_air_inspect_stage(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw),
         "test_vertex", STELA_AIR_VERTEX, count_stage_callback, &callbacks, &e) && e.kind == STELA_AIR_TYPE);
      CHECK(callbacks == 0);
      CHECK(!stela_air_stage_to_nir(LLVMGetBufferStart(raw), LLVMGetBufferSize(raw),
         "test_vertex", &nir_options, &o, &e) && e.kind == STELA_AIR_TYPE && callbacks == 0);
      LLVMDisposeMemoryBuffer(raw);
   }
   free(vector); free(scalar);
   puts("Primitive float4 and unused uint reflection require exact original DataLayout before callbacks");
}

static char *
fragment_body(const char *body, const char *extra)
{
   char *first = change(fixture, "{ ret <4 x float> %color }", body);
   char *text = malloc(strlen(first) + strlen(extra) + 1); CHECK(text);
   strcpy(text, first); strcat(text, extra); free(first); return text;
}

static void
arithmetic_and_lane_semantics(void)
{
   LLVMMemoryBufferRef initial = bitcode(fixture);
   struct snapshot vs, fs; struct stela_air_error e;
   CHECK(stela_air_inspect_stage(LLVMGetBufferStart(initial), LLVMGetBufferSize(initial),
      "test_vertex", STELA_AIR_VERTEX, capture, &vs, &e));
   CHECK(stela_air_inspect_stage(LLVMGetBufferStart(initial), LLVMGetBufferSize(initial),
      "test_fragment", STELA_AIR_FRAGMENT, capture, &fs, &e));
   LLVMDisposeMemoryBuffer(initial);
   struct stela_air_varying_slot map[16]; unsigned count = 0, calls = 0;
   CHECK(stela_air_link_stage_io(&vs.entry, &fs.entry, 16, map, 16, &count, &e));
   struct stela_air_stage_options o = options(STELA_AIR_FRAGMENT, map, count, &calls);
   o.resources.bind_ssbo = NULL; o.resources.ssbo_count = 0;
   const struct {uint32_t a, b, result;} divisions[] = {
      {0x3f800000, 0x40000000, 0x3f000000}, /* 1/2 */
      {0x3f800001, 0x40400000, 0x3eaaaaac}, /* nearest finite rounding */
      {0x7f7fffff, 0x40000000, 0x7effffff},
      {0x00800000, 0x40000000, 0}, /* FTZ result */
      {1, 0x3f800000, 0}, /* FTZ input */
      {0x80000000, 0x3f800000, 0x80000000}, /* conservative signed-zero */
      {0x3f800000, 0x7f7fffff, 0},
   };
   for (unsigned i = 0; i < sizeof(divisions) / sizeof(divisions[0]); i++) {
      float af, bf; double ad, bd; uint64_t ab, bb;
      memcpy(&af, &divisions[i].a, 4); memcpy(&bf, &divisions[i].b, 4);
      ad = af; bd = bf; memcpy(&ab, &ad, 8); memcpy(&bb, &bd, 8);
      char body[1024];
      snprintf(body, sizeof(body), "{\n %%q = fdiv fast float 0x%016llx, 0x%016llx\n"
         " %%out = insertelement <4 x float> zeroinitializer, float %%q, i32 0\n ret <4 x float> %%out\n}",
         (unsigned long long)ab, (unsigned long long)bb);
      char *text = fragment_body(body, ""); LLVMMemoryBufferRef raw = bitcode(text); free(text);
      nir_shader *nir = translate(raw, "test_fragment", &o);
      unsigned divisions_seen = 0;
      nir_foreach_function_impl(impl, nir) nir_foreach_block(block, impl) nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_alu && nir_instr_as_alu(instr)->op == nir_op_fdiv) {
            CHECK(nir_instr_as_alu(instr)->fp_math_ctrl == (nir_fp_preserve_signed_zero | nir_fp_no_transform));
            divisions_seen++;
         }
      }
      CHECK(divisions_seen == 1);
      fold(nir); uint32_t result[4] = {divisions[i].result,0,0,0}; outputs(nir, NULL, result);
      ralloc_free(nir); LLVMDisposeMemoryBuffer(raw);
      char *precise = fragment_body("{\n %q = fdiv float 1.0, 2.0\n %out = insertelement <4 x float> zeroinitializer, float %q, i32 0\n ret <4 x float> %out\n}", "");
      refusal(precise, "test_fragment", STELA_AIR_FRAGMENT, &o, STELA_AIR_INSTRUCTION); free(precise);
   }
   const uint32_t integers[] = {16777217, UINT32_MAX, 2147483649u, 0};
   const uint32_t float_bits[] = {0x4b800000, 0x4f800000, 0x4f000000, 0};
   for (unsigned width = 2; width <= 4; width++) {
      char values[192] = "", body[2048], extra[256], extension[512] = "";
      for (unsigned i = 0; i < width; i++) {
         char value[40]; snprintf(value, sizeof(value), "%si32 %u", i ? "," : "", integers[i]); strcat(values, value);
      }
      if (width < 4) snprintf(extension, sizeof(extension),
         " %%out = shufflevector <%u x float> %%v, <%u x float> zeroinitializer, <4 x i32> <i32 0,i32 1,i32 %u,i32 %u>\n", width, width, width == 3 ? 2 : 2, width == 3 ? 3 : 3);
      snprintf(body, sizeof(body), "{\n %%v = call fast <%u x float> @air.convert.f.v%uf32.u.v%ui32(<%u x i32> <%s>)\n%s ret <4 x float> %%%s\n}",
         width, width, width, width, values, extension, width == 4 ? "v" : "out");
      snprintf(extra, sizeof(extra), "\ndeclare <%u x float> @air.convert.f.v%uf32.u.v%ui32(<%u x i32>)\n", width, width, width, width);
      char *text = fragment_body(body, extra); LLVMMemoryBufferRef raw = bitcode(text); free(text);
      nir_shader *nir = translate(raw, "test_fragment", &o); fold(nir);
      uint32_t result[4] = {0}; memcpy(result, float_bits, width * 4); outputs(nir, NULL, result);
      ralloc_free(nir); LLVMDisposeMemoryBuffer(raw);
      char guarded_extra[512]; snprintf(guarded_extra, sizeof(guarded_extra),
         "\ndeclare <%u x float> @air.convert.f.v%uf32.u.v%ui32(<%u x i32>) strictfp\n", width, width, width, width);
      text = fragment_body(body, guarded_extra);
      refusal(text, "test_fragment", STELA_AIR_FRAGMENT, &o, STELA_AIR_TYPE); free(text);
   }
   /* Partial vector constants first occur in a branch, then recur outside it.
    * Both uses must rematerialize at legal dominators, never cache branch SSA. */
   const char *branch = "{\n %a = extractelement <4 x float> %color, i32 0\n"
      " %condition = fcmp oeq float %a, 1.0\n br i1 %condition, label %yes, label %no\n"
      "yes:\n %inside = shufflevector <4 x float> <float 3.0,float poison,float poison,float poison>, <4 x float> poison, <4 x i32> zeroinitializer\n"
      " %x = extractelement <4 x float> %inside, i32 0\n br label %merge\n"
      "no:\n br label %merge\nmerge:\n %chosen = phi float [%x,%yes],[2.0,%no]\n"
      " %outside = shufflevector <4 x float> <float 3.0,float poison,float poison,float poison>, <4 x float> poison, <4 x i32> zeroinitializer\n"
      " %out = insertelement <4 x float> %outside, float %chosen, i32 0\n ret <4 x float> %out\n}";
   char *text = fragment_body(branch, ""); LLVMMemoryBufferRef raw = bitcode(text); free(text);
   for (unsigned arm = 0; arm < 2; arm++) {
      nir_shader *nir = translate(raw, "test_fragment", &o);
      uint32_t input[4] = {arm ? bits(0.f) : bits(1.f),0,0,0};
      specialize(nir, 0, input, 16, 0, 0, true);
      uint32_t result[4] = {arm ? bits(2.f) : bits(3.f),bits(3.f),bits(3.f),bits(3.f)};
      outputs(nir, NULL, result); ralloc_free(nir);
   }
   LLVMDisposeMemoryBuffer(raw);
   /* Both real return sites publish only their own render outputs. */
   const char *early = "{\n %a = extractelement <4 x float> %color, i32 0\n"
      " %condition = fcmp oeq float %a, 1.0\n br i1 %condition, label %yes, label %no\n"
      "yes:\n ret <4 x float> <float 7.0,float 8.0,float 9.0,float 10.0>\n"
      "no:\n ret <4 x float> <float 11.0,float 12.0,float 13.0,float 14.0>\n}";
   text = fragment_body(early, ""); raw = bitcode(text); free(text);
   for (unsigned arm = 0; arm < 2; arm++) {
      nir_shader *nir = translate(raw, "test_fragment", &o);
      uint32_t input[4] = {arm ? bits(0.f) : bits(1.f),0,0,0};
      specialize(nir, 0, input, 16, 0, 0, true);
      uint32_t result[4];
      for (unsigned lane = 0; lane < 4; lane++)
         result[lane] = bits((arm ? 11.f : 7.f) + lane);
      outputs(nir, NULL, result); ralloc_free(nir);
   }
   LLVMDisposeMemoryBuffer(raw);
   /* One lexical output can sit behind a nonterminating path. The old output
    * count/value check alone accepted this unspecialized shader as finite. */
   const char *guarded_return = "{\n %a = extractelement <4 x float> %color, i32 0\n"
      " %condition = fcmp oeq float %a, 1.0\n br i1 %condition, label %spin, label %done\n"
      "spin:\n br label %spin\ndone:\n ret <4 x float> <float 11.0,float 12.0,float 13.0,float 14.0>\n}";
   text = fragment_body(guarded_return, ""); raw = bitcode(text); free(text);
   nir_shader *guarded = translate(raw, "test_fragment", &o);
   unsigned output_stores = 0;
   nir_foreach_function_impl(impl, guarded) {
      CHECK(!finite_effect_body(impl));
      nir_foreach_block(block, impl) nir_foreach_instr(instr, block) {
         if (instr->type == nir_instr_type_intrinsic)
            output_stores += nir_instr_as_intrinsic(instr)->intrinsic == nir_intrinsic_store_deref;
      }
   }
   CHECK(output_stores == 1);
   uint32_t terminating_input[4] = {0}, terminating_output[4];
   for (unsigned lane = 0; lane < 4; lane++)
      terminating_output[lane] = bits(11.f + lane);
   specialize(guarded, 0, terminating_input, 16, 0, 0, true);
   outputs(guarded, NULL, terminating_output);
   ralloc_free(guarded); LLVMDisposeMemoryBuffer(raw);
   text = fragment_body("{\n %bad = shufflevector <4 x float> poison, <4 x float> %color, <4 x i32> <i32 0,i32 5,i32 6,i32 7>\n ret <4 x float> %bad\n}", "");
   refusal(text, "test_fragment", STELA_AIR_FRAGMENT, &o, STELA_AIR_INSTRUCTION); free(text);
   puts("Stage FP32 fastdivision rounding/FTZ/zero and uint2/3/4conversion boundaries; both conditional PHI paths, masked/escaping poison passed");
}

struct strict_stage_bindings { unsigned count, expected_count, indices[2]; };
static bool strict_stage_bind(const struct stela_air_buffer *buffer,unsigned *slot,void *data)
{
   struct strict_stage_bindings *b=data;
   CHECK(buffer->address_space==2 && buffer->access==STELA_AIR_READ);
   CHECK(b->count<b->expected_count && buffer->index==b->indices[b->count]);
   *slot=b->count++;return true;
}
static nir_def *never_stage_bind(nir_builder *builder,const struct stela_air_buffer *buffer,void *data)
{
   (void)builder;(void)buffer;
   struct strict_stage_bindings *b=data;b->count++;
   CHECK(!"unused stage declaration invoked resource callback");return NULL;
}
static char *unused_buffer_fixture(bool fragment,bool all_unused,bool dead_use)
{
   char *a,*b;
   if(fragment) {
      a=change(fixture,"<4 x float> %color) { ret <4 x float> %color }",
         all_unused?"<4 x float> %color, ptr addrspace(2) %fs_buffer, ptr addrspace(2) %fs_unused) { ret <4 x float> %color }":
         "<4 x float> %color, ptr addrspace(2) %fs_buffer, ptr addrspace(2) %fs_unused) { %loaded = load <4 x float>, ptr addrspace(2) %fs_buffer, align 16\n ret <4 x float> %loaded }");
      b=change(a,"!13 = !{!14,!15}","!13 = !{!14,!15,!16,!17}");free(a);a=b;
   } else {
      a=change(fixture,"ptr addrspace(2) %buffer) {","ptr addrspace(2) %buffer, ptr addrspace(2) %unused) {");
      b=change(a,"!4 = !{!5,!6}","!4 = !{!5,!6,!8}");free(a);a=b;
      if(all_unused) {
         b=change(a," %p = getelementptr %Input, ptr addrspace(2) %buffer, i64 %index, i32 0\n %position = load <4 x float>, ptr addrspace(2) %p, align 16",
            " %position = fadd <4 x float> zeroinitializer, zeroinitializer");free(a);a=b;
      }
      if(dead_use) {
         b=change(a," %index = zext i32 %id to i64",
            " %dead = getelementptr <4 x float>, ptr addrspace(2) %unused, i64 0\n %index = zext i32 %id to i64");free(a);a=b;
      }
   }
   const char *extra=fragment?
      "\n!16 = !{i32 2,!\"air.buffer\",!\"air.location_index\",i32 4,i32 1,!\"air.read\",!\"air.address_space\",i32 2,!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"fs_buffer\"}\n"
      "!17 = !{i32 3,!\"air.buffer\",!\"air.location_index\",i32 9,i32 1,!\"air.read\",!\"air.address_space\",i32 2,!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"unused\"}\n":
      "\n!8 = !{i32 2,!\"air.buffer\",!\"air.location_index\",i32 7,i32 1,!\"air.read\",!\"air.address_space\",i32 2,!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"unused\"}\n";
   b=malloc(strlen(a)+strlen(extra)+1);CHECK(b);strcpy(b,a);strcat(b,extra);free(a);return b;
}
static void unused_stage_buffer_semantics(void)
{
   const uint32_t position[4]={bits(.125f),bits(-.5f),bits(.75f),bits(1.f)};
   const uint32_t color[4]={bits(1.f),bits(.5f),bits(.25f),0},zero[4]={0};
   for(unsigned mode=0;mode<5;mode++) {
      bool fragment=mode==1||mode==3,all_unused=mode==2||mode==3,dead_use=mode==4;
      char *text=unused_buffer_fixture(fragment,all_unused,dead_use);
      LLVMMemoryBufferRef raw=bitcode(text);struct snapshot vs,fs;struct stela_air_error error;
      CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),"test_vertex",STELA_AIR_VERTEX,capture,&vs,&error));
      CHECK(stela_air_inspect_stage(LLVMGetBufferStart(raw),LLVMGetBufferSize(raw),"test_fragment",STELA_AIR_FRAGMENT,capture,&fs,&error));
      struct snapshot *selected=fragment?&fs:&vs;
      CHECK(selected->entry.input_count==(fragment?4u:3u));
      unsigned buffer_at=fragment?2:1,unused_at=fragment?3:2;
      CHECK(selected->inputs[buffer_at].used==!all_unused && selected->inputs[unused_at].used==dead_use);
      struct stela_air_varying_slot map[16];unsigned count=0;
      CHECK(stela_air_link_stage_io(&vs.entry,&fs.entry,16,map,16,&count,&error));
      struct strict_stage_bindings bindings={.expected_count=all_unused?0u:dead_use?2u:1u,
         .indices={fragment?4u:0u,7u}};
      struct stela_air_stage_options o=options(fragment?STELA_AIR_FRAGMENT:STELA_AIR_VERTEX,map,count,NULL);
      o.resources.binding_data=&bindings;o.resources.bind_ssbo=all_unused?NULL:strict_stage_bind;
      o.resources.ssbo_count=bindings.expected_count;
      o.resources.bind_buffer=all_unused?never_stage_bind:NULL;
      nir_shader *nir=translate(raw,fragment?"test_fragment":"test_vertex",&o);
      CHECK(bindings.count==bindings.expected_count && nir->info.num_ssbos==bindings.expected_count);
      if(all_unused) {
         nir_foreach_function_impl(impl,nir) nir_foreach_block(block,impl) nir_foreach_instr(instr,block) {
            CHECK(instr->type!=nir_instr_type_undef);
            if(instr->type==nir_instr_type_intrinsic) {
               nir_intrinsic_op op=nir_instr_as_intrinsic(instr)->intrinsic;
               CHECK(op!=nir_intrinsic_get_ssbo_size && op!=nir_intrinsic_load_ssbo && op!=nir_intrinsic_store_ssbo);
            }
         }
         o.resources.bind_buffer=NULL;
         nir_shader *unbound=translate(raw,fragment?"test_fragment":"test_vertex",&o);
         CHECK(!unbound->info.num_ssbos && bindings.count==0);ralloc_free(unbound);
      }
      if(!fragment && !dead_use) {
         const struct {const char *old,*replacement;enum stela_air_error_kind kind;} bad[]={
            {"i32 7,i32 1,!\"air.read\"","i32 7,i32 1,!\"air.write\"",STELA_AIR_ARGUMENT},
            {"ptr addrspace(2) %unused","ptr addrspace(1) %unused",STELA_AIR_ARGUMENT},
            {"!\"float4\",!\"air.arg_name\",!\"unused\"","!\"unknown\",!\"air.arg_name\",!\"unused\"",STELA_AIR_ARGUMENT},
            {"!\"air.arg_type_size\",i32 16,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"unused\"",
             "!\"air.arg_type_size\",i32 8,!\"air.arg_type_align_size\",i32 16,!\"air.arg_type_name\",!\"float4\",!\"air.arg_name\",!\"unused\"",STELA_AIR_ARGUMENT},
            {"v128:128","v128:256",STELA_AIR_TYPE},
         };
         for(unsigned k=0;k<sizeof(bad)/sizeof(bad[0]);k++) {
            char *invalid=change(text,bad[k].old,bad[k].replacement);bindings.count=0;
            refusal(invalid,"test_vertex",STELA_AIR_VERTEX,&o,bad[k].kind);
            CHECK(bindings.count==0);free(invalid);
         }
      }
      LLVMDisposeMemoryBuffer(raw);memset(text,0,strlen(text));free(text);
      memset(&vs,0,sizeof(vs));memset(&fs,0,sizeof(fs));memset(map,0,sizeof(map));
      /* Returned NIR may outlive input/borrowed reflection/map. Only test clones
       * receive constant resource contents through the original NIR passes. */
      if(fragment && all_unused) specialize(nir,0,color,16,0,0,true);
      else specialize(nir,0,position,16,0,0,false);
      outputs(nir,fragment?NULL:all_unused?zero:position,fragment?all_unused?color:position:color);
      ralloc_free(nir);
   }
   puts("Stage used/unused VS+FS: exact resource counts, zero callbacks/SSBO/undef for unused, dead LLVM uses retained, malformed-unused refusal and returned-NIR lifetimes");
}

static LLVMMemoryBufferRef file(const char *path)
{
   FILE *f=fopen(path,"rb");CHECK(f && !fseek(f,0,SEEK_END));long n=ftell(f);
   CHECK(n>=4 && n<=AIR_MAX_BITCODE_BYTES && !fseek(f,0,SEEK_SET));
   char *b=malloc((size_t)n);CHECK(b && fread(b,1,(size_t)n,f)==(size_t)n && !fclose(f));
   uint8_t hash[32];_mesa_blake3_compute(b,(size_t)n,hash);printf("input bytes%ld blake3",n);
   for(unsigned i=0;i<32;i++)printf("%02x",hash[i]);puts("");
   LLVMMemoryBufferRef result=LLVMCreateMemoryBufferWithMemoryRangeCopy(b,(size_t)n,"unchanged-stage-input");free(b);return result;
}
int main(int argc,char **argv)
{
   glsl_type_singleton_init_or_ref();
   LLVMMemoryBufferRef b=bitcode(fixture);run(b,"test_vertex","test_fragment",false);
   link_and_option_failures(b,"test_vertex","test_fragment");LLVMDisposeMemoryBuffer(b);
   stage_binding_prelude_contract();
   unused_stage_buffer_semantics();
   primitive_layout_semantics();
   arithmetic_and_lane_semantics();
   if(argc==5 && !strcmp(argv[1],"--input") && !strcmp(argv[3],"--texture")) {
      b=file(argv[2]);run(b,"vertexShader","fragmentShader",true);LLVMDisposeMemoryBuffer(b);
      b=file(argv[4]);struct stela_air_error e;
      struct snapshot snapshot;
      CHECK(!stela_air_inspect_stage(LLVMGetBufferStart(b),LLVMGetBufferSize(b),"samplingShader",STELA_AIR_FRAGMENT,capture,&snapshot,&e));
      CHECK(e.kind==STELA_AIR_METADATA || e.kind==STELA_AIR_TARGET || e.kind==STELA_AIR_ARGUMENT);
      printf("Original sampled texture remains typedunsupported: %u %s\n",e.kind,e.detail);LLVMDisposeMemoryBuffer(b);
   } else CHECK(argc==1);
   glsl_type_singleton_decref();puts("AIR stage semantics passed");return 0;
}
