/* SPDX-License-Identifier: MIT */
/* Original LLVM fixtures and existing NIR optimization; no GPU interpreter. */
#include "../threadgroup.h"
#include "compiler/air_to_nir.h"
#include "compiler/tests/air_test_fixture.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef NDEBUG
#error "Threadgroup semantics require active assertions"
#endif
static const nir_shader_compiler_options nir_options = {.max_unroll_iterations = 32};
static LLVMMemoryBufferRef fixture(void)
{
    const char *prefix = "target datalayout = \"e-p:64:64-i64:64-n8:16:32\"\n"
        "target triple = \"air64_v29-apple-macosx27.2.0\"\n"
        "@used = internal addrspace(3) global [3 x i8] undef, align 1\n"
        "@unused = internal addrspace(3) global [4096 x i8] undef, align 256\n"
        "declare void @air.wg.barrier(i32,i32,i32) convergent nounwind\n"
        "define void @kernel(i32 %tid,ptr addrspace(1) %out,ptr addrspace(3) %first,ptr addrspace(3) %second,ptr addrspace(3) %dead) {\n";
    const char *body = "store i32 11,ptr addrspace(3) %first,align 4\n"
        "store i32 22,ptr addrspace(3) %second,align 4\n"
        "%p = getelementptr i32,ptr addrspace(3) %first,i64 31\nstore i32 33,ptr addrspace(3) %p,align 4\n"
        "%bit = and i32 %tid,1\n%zero = icmp eq i32 %bit,0\n%index = select i1 %zero,i64 63,i64 64\n"
        "%q = getelementptr i32,ptr addrspace(3) %second,i64 %index\nstore i32 44,ptr addrspace(3) %q,align 4\n"
        "store i8 55,ptr addrspace(3) @used,align 1\n"
        "call void @air.wg.barrier(i32 2,i32 5,i32 1) convergent\n"
        "%a = load i32,ptr addrspace(3) %first,align 4\n%b = load i32,ptr addrspace(3) %second,align 4\n"
        "%sum = add i32 %a,%b\nstore i32 %sum,ptr addrspace(1) %out,align 4\nret void\n";
    const char *metadata = "}\n!air.version = !{!0}\n!air.language_version = !{!1}\n!air.kernel = !{!2}\n"
        "!llvm.ident = !{!10}\n!llvm.module.flags = !{!11}\n"
        "!0 = !{i32 2,i32 9,i32 0}\n!1 = !{!\"Metal\",i32 4,i32 1,i32 0}\n"
        "!2 = !{ptr @kernel,!3,!4}\n!3 = !{}\n!4 = !{!5,!6,!7,!8,!9}\n"
        "!5 = !{i32 0,!\"air.thread_position_in_grid\",!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"tid\"}\n"
        "!6 = !{i32 1,!\"air.buffer\",!\"air.location_index\",i32 7,i32 1,!\"air.read_write\",!\"air.address_space\",i32 1,!\"air.arg_type_size\",i32 4,!\"air.arg_type_align_size\",i32 4,!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"output\"}\n"
        "!7 = !{i32 2,!\"air.buffer\",!\"air.location_index\",i32 7,i32 1,!\"air.read_write\",!\"air.address_space\",i32 3,!\"air.arg_type_size\",i32 4,!\"air.arg_type_align_size\",i32 4,!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"first\"}\n"
        "!8 = !{i32 3,!\"air.buffer\",!\"air.location_index\",i32 3,i32 1,!\"air.read_write\",!\"air.address_space\",i32 3,!\"air.arg_type_size\",i32 4,!\"air.arg_type_align_size\",i32 4,!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"second\"}\n"
        "!9 = !{i32 4,!\"air.buffer\",!\"air.location_index\",i32 11,i32 1,!\"air.read_write\",!\"air.address_space\",i32 3,!\"air.arg_type_size\",i32 4,!\"air.arg_type_align_size\",i32 4,!\"air.arg_type_name\",!\"uint\",!\"air.arg_name\",!\"dead\"}\n"
        "!10 = !{!\"Apple metal version 32023.922 (metalfe-32023.922.4)\"}\n"
        "!11 = !{i32 7,!\"air.max_threadgroup_buffers\",i32 31}\n";
    return stela_air_test_custom_bitcode(prefix,body,metadata,"");
}
struct bindings {struct stela_metal_threadgroup_specialization shared; unsigned callbacks;};
static bool inspect(const struct stela_air_inspection *module,const struct stela_air_entry *entry,void *data)
{
    (void)module;struct bindings *b=data;assert(entry->reflection_complete);
    const struct stela_metal_threadgroup_request_row rows[]={{.index=3,.bytes=256},{.index=11,.bytes=16},{.index=7,.bytes=128}};
    const struct stela_metal_threadgroup_request request={.size=sizeof(request),.abi=STELA_METAL_THREADGROUP_ABI,.count=3,.rows=rows};
    assert(stela_metal_threadgroup_normalize(entry->arguments,entry->argument_count,&request,512,&b->shared)==STELA_METAL_THREADGROUP_OK);
    assert(b->shared.count==3&&!entry->arguments[4].used);return true;
}
static bool bind_shared(const struct stela_air_buffer *buffer,struct stela_air_threadgroup_view *view,void *data)
{
    struct bindings *b=data;
    for(unsigned i=0;i<b->shared.count;i++) {
        const struct stela_metal_threadgroup_binding *row=&b->shared.bindings[i];
        if(row->buffer.argument==buffer->argument){assert(row->buffer.index==buffer->index);b->callbacks++;
            *view=(struct stela_air_threadgroup_view){.size=row->bytes,.alignment=row->alignment,.available_access=STELA_AIR_READ_WRITE};return true;}
    }
    return false;
}
static nir_def *bind_buffer(nir_builder *b,const struct stela_air_buffer *buffer,void *data)
{
    (void)data;assert(buffer->argument==1&&buffer->index==7&&buffer->address_space==1);
    return nir_imm_int64(b,0x100000); /* Semantic fixture only, never production ABI. */
}
static void specialize(nir_shader *nir,unsigned tid)
{
    nir_builder b=nir_builder_at(nir_after_impl(nir_shader_get_entrypoint(nir)));
    nir_foreach_function_impl(impl,nir) {
        nir_foreach_block(block,impl) {
            nir_foreach_instr_safe(instr,block) {
                if(instr->type!=nir_instr_type_intrinsic)continue;
                nir_intrinsic_instr *in=nir_instr_as_intrinsic(instr);
                if(in->intrinsic==nir_intrinsic_load_local_invocation_id||in->intrinsic==nir_intrinsic_load_workgroup_id){
                    b.cursor=nir_before_instr(instr);nir_def *v=nir_imm_ivec3(&b,in->intrinsic==nir_intrinsic_load_local_invocation_id?(int32_t)tid:0,0,0);
                    nir_def_rewrite_uses(&in->def,v);nir_instr_remove(instr);
                }
            }
        }
    }
    bool progress;
    do{progress=nir_opt_constant_folding(nir);progress|=nir_opt_copy_prop(nir);progress|=nir_opt_dce(nir);progress|=nir_opt_dead_cf(nir);}while(progress);
    nir_validate_shader(nir,"independent dynamic view boundaries");
}
static void effects(nir_shader *nir,unsigned tid)
{
    specialize(nir,tid);unsigned stores=0,loads=0,barriers=0;
    const unsigned offsets[]={0,128,124,380,400},values[]={11,22,33,44,55};
    nir_foreach_function_impl(impl,nir)nir_foreach_block(block,impl)nir_foreach_instr(instr,block) {
        if(instr->type!=nir_instr_type_intrinsic)continue;
        nir_intrinsic_instr *in=nir_instr_as_intrinsic(instr);
        if(in->intrinsic==nir_intrinsic_store_shared){unsigned expected=stores;if(tid&&stores==3)expected++;
            assert(!barriers&&nir_src_is_const(in->src[0])&&nir_src_is_const(in->src[1])&&expected<5);
            assert(nir_src_as_uint(in->src[0])==values[expected]&&nir_src_as_uint(in->src[1])+(uint32_t)nir_intrinsic_base(in)==offsets[expected]);stores++;
        }else if(in->intrinsic==nir_intrinsic_barrier){assert(stores==(tid?4u:5u));
            assert(nir_intrinsic_execution_scope(in)==SCOPE_WORKGROUP&&nir_intrinsic_memory_scope(in)==SCOPE_WORKGROUP&&
                nir_intrinsic_memory_semantics(in)==NIR_MEMORY_ACQ_REL&&nir_intrinsic_memory_modes(in)==nir_var_mem_shared);barriers++;
        }else if(in->intrinsic==nir_intrinsic_load_shared){assert(barriers==1);loads++;}
    }
    assert(stores==(tid?4u:5u)&&loads==2&&barriers==1);
}
int main(int argc,char **argv)
{
    assert(argc==1||(argc==3&&!strcmp(argv[1],"--export")));
    LLVMMemoryBufferRef input=fixture();struct bindings b={0};struct stela_air_error error;
    assert(stela_air_inspect(LLVMGetBufferStart(input),LLVMGetBufferSize(input),8,inspect,&b,&error));
    glsl_type_singleton_init_or_ref();
    for(unsigned tid=0;tid<2;tid++) {
        struct stela_air_options options={.workgroup_size={64,1,1},.max_instructions=4096,.bind_buffer=bind_buffer,
            .bind_threadgroup=bind_shared,.binding_data=&b,.max_threadgroup_bytes=512};b.callbacks=0;
        nir_shader *nir=stela_air_to_nir(LLVMGetBufferStart(input),LLVMGetBufferSize(input),"kernel",&nir_options,&options,&error);
        if(!nir)fprintf(stderr,"AIR%u %s\n",error.kind,error.detail);
        assert(nir&&b.callbacks==3&&nir->info.shared_size==403);effects(nir,tid);ralloc_free(nir);
        options.max_threadgroup_bytes=400;
        assert(!stela_air_to_nir(LLVMGetBufferStart(input),LLVMGetBufferSize(input),"kernel",&nir_options,&options,&error)&&error.kind==STELA_AIR_LIMIT);
    }
    if(argc==3){FILE *f=fopen(argv[2],"wx");assert(f);assert(LLVMGetBufferSize(input)<65536);
        assert(fwrite(LLVMGetBufferStart(input),1,LLVMGetBufferSize(input),f)==LLVMGetBufferSize(input)&&!fclose(f));}
    glsl_type_singleton_decref();LLVMDisposeMemoryBuffer(input);
    puts("original LLVM dynamic views: distinct regions, last-valid/OOB path effects, barrier ordering, unused global and combined limit passed");return 0;
}
