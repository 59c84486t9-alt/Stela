/* SPDX-License-Identifier: MIT */
/* The Metal device's compiler service: reflection and compilation of
 * kernels, linked vertex and fragment functions, and object and mesh
 * functions. Original LLVM IR fixtures, one AIR module per function as
 * libraries hold them; no Apple output. */
#include "../metal_compiler.h"
#include "air_effect_oracle.h"
#include "air_test_fixture.h"
#include "compiler/nir/nir_serialize.h"
#include "util/blob.h"
#include "util/ralloc.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef NDEBUG
#error "These tests require active assertions"
#endif

static const nir_shader_compiler_options nir_options = {.max_unroll_iterations = 32};

static const char *module =
   "target datalayout = \"e-p:64:64-i32:32-i64:64-f32:32-v128:128-n8:16:32\"\n"
   "target triple = \"air64_v29-apple-macosx27.2.0\"\n";

#define IDENT "Apple metal version 32023.922 (metalfe-32023.922.4)"

static const char *versions =
   "!air.version = !{!20}\n!air.language_version = !{!21}\n!llvm.ident = !{!22}\n"
   "!air.compile_options = !{!23, !24, !25}\n"
   "!20 = !{i32 2, i32 9, i32 0}\n!21 = !{!\"Metal\", i32 4, i32 1, i32 0}\n"
   "!22 = !{!\"" IDENT "\"}\n"
   "!23 = !{!\"air.compile.denorms_disable\"}\n!24 = !{!\"air.compile.fast_math_enable\"}\n"
   "!25 = !{!\"air.compile.framebuffer_fetch_enable\"}\n";

/* Each thread stores its index to a static and a dynamic threadgroup array
 * and copies it out after a barrier. */
static const char *kernel =
   "@scratch = internal addrspace(3) global [16 x i32] undef, align 16\n"
   "declare void @air.wg.barrier(i32, i32) convergent\n"
   "define void @kernel(ptr addrspace(1) %data, ptr addrspace(3) %shared, i32 %tid) {\n"
   "%i = zext i32 %tid to i64\n"
   "%p = getelementptr i32, ptr addrspace(3) %shared, i64 %i\n"
   "store i32 %tid, ptr addrspace(3) %p, align 4\n"
   "store i32 %tid, ptr addrspace(3) @scratch, align 16\n"
   "call void @air.wg.barrier(i32 2, i32 1) convergent\n"
   "%v = load i32, ptr addrspace(3) %p, align 4\n"
   "%q = getelementptr i32, ptr addrspace(1) %data, i64 %i\n"
   "store i32 %v, ptr addrspace(1) %q, align 4\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @kernel, !3, !4, !5}\n!3 = !{}\n!5 = !{!\"air.max_work_group_size\", i32 64}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 2, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"shared\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

/* Stores its stage-in value at its thread position; it never reads its
 * index. */
static const char *staged =
   "define void @staged(<4 x float> %value, <2 x i32> %index, ptr addrspace(1) %out, i32 %tid) {\n"
   "%i = zext i32 %tid to i64\n"
   "%q = getelementptr <4 x float>, ptr addrspace(1) %out, i64 %i\n"
   "store <4 x float> %value, ptr addrspace(1) %q, align 16\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @staged, !3, !4}\n!3 = !{}\n!4 = !{!40, !41, !42, !43}\n"
   "!40 = !{i32 0, !\"air.stage_in\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"value\"}\n"
   "!41 = !{i32 1, !\"air.stage_in\", !\"air.location_index\", i32 1, i32 1,"
   " !\"air.arg_type_name\", !\"uint2\", !\"air.arg_name\", !\"index\"}\n"
   "!42 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"out\"}\n"
   "!43 = !{i32 3, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

/* Stores its position in its threadgroup, the threadgroup's shape and its
 * position in the grid, and its column to its threadgroup buffer. */
static const char *shaped =
   "define void @shaped(ptr addrspace(1) %out, ptr addrspace(3) %shared, <3 x i32> %local,"
   " <3 x i32> %shape, <3 x i32> %grid) {\n"
   "store <3 x i32> %local, ptr addrspace(1) %out, align 16\n"
   "%s = getelementptr i8, ptr addrspace(1) %out, i64 16\n"
   "store <3 x i32> %shape, ptr addrspace(1) %s, align 16\n"
   "%g = getelementptr i8, ptr addrspace(1) %out, i64 32\n"
   "store <3 x i32> %grid, ptr addrspace(1) %g, align 16\n"
   "%x = extractelement <3 x i32> %local, i32 0\n"
   "store i32 %x, ptr addrspace(3) %shared, align 4\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @shaped, !3, !4}\n!3 = !{}\n!4 = !{!40, !41, !42, !43, !44}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 16, !\"air.arg_type_name\", !\"uint3\", !\"air.arg_name\", !\"out\"}\n"
   "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"shared\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_threadgroup\", !\"air.arg_type_name\", !\"uint3\","
   " !\"air.arg_name\", !\"local\"}\n"
   "!43 = !{i32 3, !\"air.threads_per_threadgroup\", !\"air.arg_type_name\", !\"uint3\","
   " !\"air.arg_name\", !\"shape\"}\n"
   "!44 = !{i32 4, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint3\","
   " !\"air.arg_name\", !\"grid\"}\n";

/* Stores the scale constant where it is defined and the required enabled
 * constant is set, in the form Metal.jl's library builder reads. */
static const char *constants =
   "@scale = external addrspace(2) constant i32\n"
   "@enabled = external addrspace(2) constant i8\n"
   "declare i1 @air.is_function_constant_defined(ptr addrspace(2))\n"
   "define void @constants(ptr addrspace(1) %data, i32 %tid) {\n"
   "%defined = call i1 @air.is_function_constant_defined(ptr addrspace(2) @scale)\n"
   "%e = load i8, ptr addrspace(2) @enabled, align 1\n"
   "%on = icmp ne i8 %e, 0\n"
   "%both = and i1 %defined, %on\n"
   "br i1 %both, label %scaled, label %done\n"
   "scaled:\n%s = load i32, ptr addrspace(2) @scale, align 4\n"
   "%i = zext i32 %tid to i64\n"
   "%q = getelementptr i32, ptr addrspace(1) %data, i64 %i\n"
   "store i32 %s, ptr addrspace(1) %q, align 4\n"
   "br label %done\n"
   "done:\nret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @constants, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!air.function_constants = !{!50, !51}\n"
   "!50 = !{ptr addrspace(2) @scale, !\"uint\", !\"scale\", i32 0, i1 false}\n"
   "!51 = !{ptr addrspace(2) @enabled, !\"bool\", !\"enabled\", i32 3, i1 true}\n";

/* Stores a program-scope constant derived from width, as Apple's compiler
 * records `constant int derived = is_function_constant_defined(width) ?
 * width * 2 : 8;`: twice width when it is defined, else eight. */
#define DERIVED(twice)                                                                      \
   "@width = linkonce_odr hidden addrspace(2) externally_initialized constant i32 undef,"   \
   " section \"air.fc_initializer\", align 4\n"                                             \
   "@twice_width = internal unnamed_addr addrspace(2) global i32 0, align 4\n"              \
   "@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }]"                          \
   " [{ i32, ptr, ptr } { i32 65535, ptr @init, ptr null }]\n"                              \
   "declare i1 @air.is_function_constant_defined(ptr addrspace(2))\n"                       \
   "declare i32 @air.unknown(i32)\n"                                                        \
   "declare float @air.convert.f.f32.s.i32(i32)\n"                                          \
   "declare i32 @air.convert.s.i32.f.f32(float)\n"                                          \
   "define void @derived(ptr addrspace(1) %data) {\n"                                       \
   "%v = load i32, ptr addrspace(2) @twice_width, align 4\n"                                \
   "store i32 %v, ptr addrspace(1) %data, align 4\n"                                        \
   "ret void\n}\n"                                                                          \
   "define internal void @init() section \"air.static_init\" {\n"                           \
   "%w = load i32, ptr addrspace(2) @width, align 4\n"                                      \
   "%defined = call i1 @air.is_function_constant_defined(ptr addrspace(2) @width)\n"        \
   twice                                                                                    \
   "%v = select i1 %defined, i32 %x, i32 8\n"                                               \
   "store i32 %v, ptr addrspace(2) @twice_width, align 4\n"                                 \
   "ret void\n}\n"                                                                          \
   "!air.kernel = !{!2}\n"                                                                  \
   "!2 = !{ptr @derived, !3, !4}\n!3 = !{}\n!4 = !{!40}\n"                                  \
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\"," \
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\"," \
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n"              \
   "!air.function_constants = !{!50}\n"                                                     \
   "!50 = !{ptr addrspace(2) @width, !\"int\", !\"width\", i32 0}\n"

static const char *derived = DERIVED("%x = shl nsw i32 %w, 1\n");
/* The same through AIR's conversions, as `int(float(width) * 2)`. */
static const char *converted = DERIVED("%f = call float @air.convert.f.f32.s.i32(i32 %w)\n"
                                       "%d = fmul fast float %f, 2.000000e+00\n"
                                       "%x = call i32 @air.convert.s.i32.f.f32(float %d)\n");
/* A constructor whose helper needs the ordinary inlining path. */
static const char *derived_with_helper = DERIVED("%x = call i32 @twice(i32 %w)\n")
   "define internal i32 @twice(i32 %w) {\n%x = shl nsw i32 %w, 1\nret i32 %x\n}\n";
/* A constructor that calls an AIR function, which no constant folds. */
static const char *called = DERIVED("%x = call i32 @air.unknown(i32 %w)\n");

/* A [[function_constant(use_tint)]] buffer and one for !use_tint at the
 * same index, as Apple's compiler records them: each argument names an
 * internal predicate the constructor computes and llvm.compiler.used keeps.
 * The kernel reads the buffer whose constant holds, branching as `branch`
 * says on use_tint, %on. */
#define CONDITIONAL(branch, predicate)                                                     \
   "@use_tint.init = linkonce_odr hidden addrspace(2) externally_initialized constant i8"  \
   " undef, section \"air.fc_initializer\", align 1\n"                                     \
   "@use_tint = internal unnamed_addr addrspace(2) global i8 undef, align 1\n"             \
   "@tinted = internal addrspace(2) global i8 0, align 1\n"                                \
   "@untinted = internal addrspace(2) global i8 0, align 1\n"                              \
   "@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }]"                         \
   " [{ i32, ptr, ptr } { i32 65535, ptr @init, ptr null }]\n"                             \
   "@llvm.compiler.used = appending global [2 x ptr] [ptr addrspacecast"                   \
   " (ptr addrspace(2) @tinted to ptr), ptr addrspacecast (ptr addrspace(2) @untinted"     \
   " to ptr)], section \"llvm.metadata\"\n"                                                \
   "declare i8 @air.normalize_function_constant_predicate.i8(i8)\n"                        \
   "define void @conditional(ptr addrspace(1) %data, ptr addrspace(1) %tint,"              \
   " ptr addrspace(1) %plain) {\n"                                                         \
   "%u = load i8, ptr addrspace(2) @use_tint, align 1\n"                                   \
   "%on = icmp ne i8 %u, 0\n"                                                              \
   branch                                                                                  \
   "tinted:\n%t = load i32, ptr addrspace(1) %tint, align 4\n"                             \
   "store i32 %t, ptr addrspace(1) %data, align 4\nret void\n"                             \
   "untinted:\n%p = load i32, ptr addrspace(1) %plain, align 4\n"                          \
   "store i32 %p, ptr addrspace(1) %data, align 4\nret void\n}\n"                          \
   "define internal void @init() section \"air.static_init\" {\n"                          \
   "%v = load i8, ptr addrspace(2) @use_tint.init, align 1\n"                              \
   "store i8 %v, ptr addrspace(2) @use_tint, align 1\n"                                    \
   "%t = call i8 @air.normalize_function_constant_predicate.i8(i8 %v)\n"                   \
   "store i8 %t, ptr addrspace(2) @tinted, align 1\n"                                      \
   "%n = xor i8 %t, 1\n"                                                                   \
   "store i8 %n, ptr addrspace(2) @untinted, align 1\n"                                    \
   "ret void\n}\n"                                                                         \
   "!air.kernel = !{!2}\n"                                                                 \
   "!2 = !{ptr @conditional, !3, !4}\n!3 = !{}\n!4 = !{!40, !41, !42}\n"                   \
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1,"                \
   " !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4,"   \
   " !\"air.arg_type_align_size\", i32 4, !\"air.arg_type_name\", !\"int\","               \
   " !\"air.arg_name\", !\"data\"}\n"                                                      \
   "!41 = !{i32 1, !\"air.function_constant\", !43, !\"air.buffer\","                      \
   " !\"air.location_index\", i32 1, i32 1, !\"air.read\", !\"air.address_space\", i32 1," \
   " !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"                  \
   " !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"tint\"}\n"                    \
   "!42 = !{i32 2, !\"air.function_constant\", !44, !\"air.buffer\","                      \
   " !\"air.location_index\", i32 1, i32 1, !\"air.read_write\", !\"air.address_space\","  \
   " i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"           \
   " !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"plain\"}\n"                   \
   "!43 = !{ptr addrspace(2) @tinted, !\"" predicate "\", !\"use_tint\"}\n"                \
   "!44 = !{ptr addrspace(2) @untinted, !\"bool\", !\"untinted\"}\n"                       \
   "!air.function_constants = !{!50}\n"                                                    \
   "!50 = !{ptr addrspace(2) @use_tint.init, !\"bool\", !\"use_tint\", i32 0}\n"

static const char *conditional =
   CONDITIONAL("br i1 %on, label %tinted, label %untinted\n", "bool");
/* A shader helper uses the same function constant as its leaf constructor. */
static const char *conditional_with_helper =
   CONDITIONAL("%choose = call i1 @choose_tint(i1 %on)\n"
               "br i1 %choose, label %tinted, label %untinted\n", "bool")
   "define internal i1 @choose_tint(i1 %enabled) {\n"
   "%raw = load i8, ptr addrspace(2) @use_tint.init, align 1\n"
   "%selected = icmp ne i8 %raw, 0\n"
   "%both = and i1 %selected, %enabled\nret i1 %both\n}\n";
/* One reading tint whatever use_tint is. */
static const char *unguarded = CONDITIONAL("br label %tinted\n", "bool");
/* One whose read Apple's compiler hoists ahead of what decides it. */
static const char *hoisted =
   CONDITIONAL("%h = load i32, ptr addrspace(1) %tint, align 4\n"
               "%s = select i1 %on, i32 %h, i32 undef\n"
               "store i32 %s, ptr addrspace(1) %data, align 4\n"
               "br i1 %on, label %tinted, label %untinted\n", "bool");
/* One whose predicate is not a bool. */
static const char *mistyped =
   CONDITIONAL("br i1 %on, label %tinted, label %untinted\n", "int");

/* A fragment function that reads a [[function_constant(use_tint)]] buffer on
 * one side of a run-time test. With use_tint false that side cannot run, and
 * the test and its read go with it. */
static const char *absent_path =
   "@use_tint.init = linkonce_odr hidden addrspace(2) externally_initialized constant i8"
   " undef, section \"air.fc_initializer\", align 1\n"
   "@tinted = internal addrspace(2) global i8 0, align 1\n"
   "@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }]"
   " [{ i32, ptr, ptr } { i32 65535, ptr @init, ptr null }]\n"
   "@llvm.compiler.used = appending global [1 x ptr] [ptr addrspacecast"
   " (ptr addrspace(2) @tinted to ptr)], section \"llvm.metadata\"\n"
   "declare i8 @air.normalize_function_constant_predicate.i8(i8)\n"
   "define <4 x float> @absent_path(<4 x float> %position, ptr addrspace(2) %tint) {\n"
   "%x = extractelement <4 x float> %position, i64 0\n"
   "%left = fcmp olt float %x, 0.0\n"
   "br i1 %left, label %read, label %done\n"
   "read:\n%t = load <4 x float>, ptr addrspace(2) %tint, align 16\nbr label %done\n"
   "done:\n%c = phi <4 x float> [ %t, %read ], [ %position, %0 ]\n"
   "ret <4 x float> %c\n}\n"
   "define internal void @init() section \"air.static_init\" {\n"
   "%v = load i8, ptr addrspace(2) @use_tint.init, align 1\n"
   "%t = call i8 @air.normalize_function_constant_predicate.i8(i8 %v)\n"
   "store i8 %t, ptr addrspace(2) @tinted, align 1\n"
   "ret void\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @absent_path, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.render_target\", i32 1, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.position\", !\"air.center\", !\"air.no_perspective\","
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!41 = !{i32 1, !\"air.function_constant\", !43, !\"air.buffer\","
   " !\"air.location_index\", i32 0, i32 1, !\"air.read\", !\"air.address_space\", i32 2,"
   " !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 16,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"tint\"}\n"
   "!43 = !{ptr addrspace(2) @tinted, !\"bool\", !\"use_tint\"}\n"
   "!air.function_constants = !{!50}\n"
   "!50 = !{ptr addrspace(2) @use_tint.init, !\"bool\", !\"use_tint\", i32 0}\n";

/* A kernel as Metal 2.4 records one, in a Debug build: its buffer leaves its
 * address space to its type, and its simdgroup barrier has the older scope. */
static const char *older_kernel =
   "declare void @air.simdgroup.barrier(i32, i32) convergent\n"
   "define void @older(ptr addrspace(1) %data, i32 %tid) !dbg !62 {\n"
   "call void @air.simdgroup.barrier(i32 0, i32 1) convergent, !dbg !63\n"
   "store i32 %tid, ptr addrspace(1) %data, align 4, !dbg !63\n"
   "ret void, !dbg !63\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @older, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!llvm.dbg.cu = !{!60}\n!llvm.module.flags = !{!64, !67}\n!llvm_utils.workingdir = !{!68}\n"
   "!60 = distinct !DICompileUnit(language: DW_LANG_C_plus_plus_14, file: !61,"
   " emissionKind: LineTablesOnly)\n"
   "!61 = !DIFile(filename: \"a.metal\", directory: \"/\")\n"
   "!62 = distinct !DISubprogram(name: \"older\", scope: !61, file: !61, line: 1,"
   " type: !65, unit: !60, spFlags: DISPFlagDefinition)\n"
   "!63 = !DILocation(line: 2, scope: !62)\n"
   "!64 = !{i32 2, !\"Debug Info Version\", i32 3}\n"
   "!65 = !DISubroutineType(types: !66)\n!66 = !{}\n"
   "!67 = !{i32 7, !\"Dwarf Version\", i32 4}\n!68 = !{!\"/\"}\n";

/* A kernel as -O0 records one, keeping its values in memory, its matrices in
 * aggregates and its switch to be lowered. */
static const char *unoptimized_kernel =
   "define void @unoptimized(ptr addrspace(1) %data, i32 %tid) noinline optnone {\n"
   "entry:\n"
   "%slot = alloca i32, align 4\n"
   "store i32 %tid, ptr %slot, align 4\n"
   "%id = load i32, ptr %slot, align 4\n"
   "%flags = or i32 1, 2\n"
   "call void @air.wg.barrier(i32 %flags, i32 1) convergent\n"
   "%first = insertvalue {[2 x <2 x float>]} poison, <2 x float> zeroinitializer, 0, 0\n"
   "%second = insertvalue {[2 x <2 x float>]} %first, <2 x float> <float 1.0, float 2.0>, 0, 1\n"
   "%rows = extractvalue {[2 x <2 x float>]} %second, 0\n"
   "%row = extractvalue [2 x <2 x float>] %rows, 1\n"
   "%lane = extractelement <2 x float> %row, i32 %id\n"
   "%written = insertelement <2 x float> %row, float %lane, i32 %id\n"
   "switch i32 %id, label %done [i32 1, label %one]\n"
   "one:\n"
   "store <2 x float> %written, ptr addrspace(1) %data, align 8\n"
   "store <2 x i16> bitcast (<1 x float> splat (float 1.0) to <2 x i16>), ptr addrspace(1) %data, align 4\n"
   "br label %done\n"
   "done:\n"
   "ret void\n}\n"
   "declare void @air.wg.barrier(i32, i32) convergent\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @unoptimized, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.arg_type_size\", i32 8, !\"air.arg_type_align_size\", i32 8,"
   " !\"air.arg_type_name\", !\"float2\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

/* A position and a varying only a true function constant keeps. */
static const char *optional_output =
   "@fog = internal addrspace(2) global i8 undef, align 1\n"
   "@fog.init = linkonce_odr hidden addrspace(2) externally_initialized constant i8 undef,"
   " section \"air.fc_initializer\", align 1\n"
   "@fogged = internal addrspace(2) global i8 0, align 1\n"
   "@llvm.global_ctors = appending global [1 x { i32, ptr, ptr }]"
   " [{ i32, ptr, ptr } { i32 65535, ptr @init, ptr null }]\n"
   "@llvm.compiler.used = appending global [1 x ptr] [ptr addrspacecast (ptr addrspace(2) @fogged"
   " to ptr)], section \"llvm.metadata\"\n"
   "declare i8 @air.normalize_function_constant_predicate.i8(i8)\n"
   "define <{ <4 x float>, float }> @optional(<4 x float> %p) {\n"
   "%a = insertvalue <{ <4 x float>, float }> undef, <4 x float> %p, 0\n"
   "%b = insertvalue <{ <4 x float>, float }> %a, float 1.0, 1\n"
   "ret <{ <4 x float>, float }> %b\n}\n"
   "define internal void @init() section \"air.static_init\" {\n"
   "%v = load i8, ptr addrspace(2) @fog.init, align 1\n"
   "store i8 %v, ptr addrspace(2) @fog, align 1\n"
   "%t = call i8 @air.normalize_function_constant_predicate.i8(i8 %v)\n"
   "store i8 %t, ptr addrspace(2) @fogged, align 1\n"
   "ret void\n}\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @optional, !3, !4}\n!3 = !{!30, !31}\n!4 = !{!40}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"p\"}\n"
   "!31 = !{!\"air.function_constant\", !32, !\"air.vertex_output\", !\"generated(f)\","
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"f\"}\n"
   "!32 = !{ptr addrspace(2) @fogged, !\"bool\", !\"fog\"}\n"
   "!40 = !{i32 0, !\"air.vertex_input\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"in\"}\n"
   "!air.function_constants = !{!50}\n"
   "!50 = !{ptr addrspace(2) @fog.init, !\"bool\", !\"fog\", i32 0}\n";

/* Lanes Apple's compiler leaves poison in a splat, and a value it freezes. */
static const char *undefined_lanes =
   "define void @lanes(ptr addrspace(1) %data, i32 %tid) {\n"
   "%f = uitofp i32 %tid to float\n"
   "%a = insertelement <4 x float> poison, float %f, i64 0\n"
   "%s = shufflevector <4 x float> %a, <4 x float> undef, <4 x i32> <i32 0, i32 0, i32 0, i32 poison>\n"
   "%m = fmul fast <4 x float> %s, %s\n"
   "store <4 x float> %m, ptr addrspace(1) %data, align 16\n"
   "%n = extractelement <4 x float> %s, i64 3\n"
   "%g = freeze <4 x float> %s\n"
   "%x = extractelement <4 x float> %g, i64 3\n"
   "%y = fadd fast float %n, %x\n"
   "%c = icmp eq i32 %tid, 0\n"
   "%z = select i1 %c, float undef, float %y\n"
   "store float %z, ptr addrspace(1) %data, align 4\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @lanes, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

/* Texture and sampler array arguments, which a function reflects slot by
 * slot, reading the width of the second texture. */
static const char *arrays =
   "declare i32 @air.get_width_texture_2d(ptr addrspace(1), i32)\n"
   "define void @arrays(ptr byval([3 x ptr addrspace(1)]) %t, ptr byval([2 x ptr addrspace(2)]) %s,"
   " ptr addrspace(1) %data) {\n"
   "%h = getelementptr inbounds [3 x ptr addrspace(1)], ptr %t, i64 0, i64 1\n"
   "%x = load ptr addrspace(1), ptr %h, align 8\n"
   "%w = call i32 @air.get_width_texture_2d(ptr addrspace(1) %x, i32 0)\n"
   "store i32 %w, ptr addrspace(1) %data, align 4\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @arrays, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7}\n"
   "!5 = !{i32 0, !\"air.texture\", !\"air.location_index\", i32 2, i32 3, !\"air.read\","
   " !\"air.arg_type_name\", !\"array<texture2d<half, read>, 3>\", !\"air.arg_name\", !\"t\"}\n"
   "!6 = !{i32 1, !\"air.sampler\", !\"air.location_index\", i32 1, i32 2,"
   " !\"air.arg_type_name\", !\"array<sampler, 2>\", !\"air.arg_name\", !\"s\"}\n"
   "!7 = !{i32 2, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n";

/* A kernel binding a uniform structure, which inlines an array of another,
 * an argument buffer of a texture array, a buffer and a constant, a texture,
 * a sampler and a threadgroup buffer; it reads only the uniforms. */
static const char *bound =
   "define void @bound(ptr addrspace(2) %u, ptr addrspace(2) %args, ptr addrspace(1) %rw,"
   " ptr addrspace(2) %s, ptr addrspace(3) %tg, ptr addrspace(1) %out) {\n"
   "%v = load float, ptr addrspace(2) %u, align 16\n"
   "store float %v, ptr addrspace(1) %out, align 4\n"
   "ret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @bound, !3, !4}\n!3 = !{}\n!4 = !{!5, !6, !7, !8, !9, !10}\n"
   "!5 = !{i32 0, !\"air.buffer\", !\"air.buffer_size\", i32 128, !\"air.location_index\", i32 0,"
   " i32 1, !\"air.read\", !\"air.address_space\", i32 2, !\"air.struct_type_info\", !30,"
   " !\"air.arg_type_size\", i32 128, !\"air.arg_type_align_size\", i32 16,"
   " !\"air.arg_type_name\", !\"Uniforms\", !\"air.arg_name\", !\"u\"}\n"
   "!30 = !{i32 0, i32 64, i32 0, !\"float4x4\", !\"mvp\", !\"air.struct_type_info\", !31,"
   " i32 64, i32 16, i32 2, !\"Inner\", !\"inner\", i32 96, i32 4, i32 3, !\"int\", !\"k\"}\n"
   "!31 = !{i32 0, i32 8, i32 0, !\"float2\", !\"uv\", i32 8, i32 2, i32 0, !\"half\", !\"h\"}\n"
   "!6 = !{i32 1, !\"air.indirect_buffer\", !\"air.buffer_size\", i32 32, !\"air.location_index\","
   " i32 1, i32 1, !\"air.read\", !\"air.address_space\", i32 2, !\"air.struct_type_info\", !32,"
   " !\"air.arg_type_size\", i32 32, !\"air.arg_type_align_size\", i32 8,"
   " !\"air.arg_type_name\", !\"Args\", !\"air.arg_name\", !\"args\"}\n"
   "!32 = !{i32 0, i32 16, i32 0, !\"array<texture2d<float, sample>, 2>\", !\"ts\","
   " !\"air.indirect_argument\", !33, i32 16, i32 8, i32 0, !\"float\", !\"d\","
   " !\"air.indirect_argument\", !34, i32 24, i32 4, i32 0, !\"float\", !\"c\","
   " !\"air.indirect_argument\", !35}\n"
   "!33 = !{i32 0, !\"air.texture\", !\"air.location_index\", i32 0, i32 2, !\"air.sample\","
   " !\"air.arg_type_name\", !\"array<texture2d<float, sample>, 2>\", !\"air.arg_name\", !\"ts\"}\n"
   "!34 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 2, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"d\"}\n"
   "!35 = !{i32 2, !\"air.indirect_constant\", !\"air.location_index\", i32 3, i32 1,"
   " !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"c\"}\n"
   "!7 = !{i32 2, !\"air.texture\", !\"air.location_index\", i32 1, i32 1, !\"air.read_write\","
   " !\"air.arg_type_name\", !\"texture2d<float, read_write>\", !\"air.arg_name\", !\"rw\"}\n"
   "!8 = !{i32 3, !\"air.sampler\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"sampler\", !\"air.arg_name\", !\"s\"}\n"
   "!9 = !{i32 4, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 3, !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\","
   " i32 16, !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"tg\"}\n"
   "!10 = !{i32 5, !\"air.buffer\", !\"air.location_index\", i32 2, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"float\", !\"air.arg_name\", !\"out\"}\n";

/* A kernel calling a [[noinline]] helper, which calls a visible function, and
 * one calling a function that recurses. */
static const char *calls =
   "define i32 @doubled(i32 %x) {\n%y = shl i32 %x, 1\nret i32 %y\n}\n"
   "define internal i32 @helper(i32 %x) noinline {\n"
   "%d = call i32 @doubled(i32 %x)\n%y = add i32 %d, 1\nret i32 %y\n}\n"
   "define internal i32 @countdown(i32 %x) noinline {\n"
   "entry:\n%zero = icmp eq i32 %x, 0\nbr i1 %zero, label %done, label %next\n"
   "next:\n%less = sub i32 %x, 1\n%r = call i32 @countdown(i32 %less)\nbr label %done\n"
   "done:\n%v = phi i32 [0, %entry], [%r, %next]\nret i32 %v\n}\n"
   "define void @calls(ptr addrspace(1) %data, i32 %tid) {\n"
   "%v = call i32 @helper(i32 %tid)\n"
   "store i32 %v, ptr addrspace(1) %data, align 4\nret void\n}\n"
   "define void @recurses(ptr addrspace(1) %data, i32 %tid) {\n"
   "%v = call i32 @countdown(i32 %tid)\n"
   "store i32 %v, ptr addrspace(1) %data, align 4\nret void\n}\n"
   "!air.kernel = !{!2, !5}\n!air.visible = !{!6}\n"
   "!2 = !{ptr @calls, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n!5 = !{ptr @recurses, !3, !4}\n"
   "!6 = !{ptr @doubled, !7, !8, !9}\n!7 = !{!70}\n!8 = !{!80}\n"
   "!9 = !{!\"air.stitching_info\"}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n"
   "!70 = !{!\"air.visible_output\", !\"air.arg_type_name\", !\"int\"}\n"
   "!80 = !{i32 0, !\"air.visible_input\", !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"x\"}\n";

/* A kernel calling handle tid & 1 of its visible function table, then an
 * external function a linked module defines, and a function of its own the
 * table can name. */
#define TABLES(call)                                                                        \
   "declare ptr @air.get_function_pointer_visible_function_table(ptr addrspace(1), i32)\n"  \
   "declare i32 @air.get_size_visible_function_table(ptr addrspace(1))\n"                  \
   "declare i32 @external(i32)\n"                                                         \
   "define i32 @doubled(i32 %x) {\n%y = shl i32 %x, 1\nret i32 %y\n}\n"                     \
   "define void @tables(ptr addrspace(1) %table, ptr addrspace(1) %data, i32 %tid) {\n"     \
   "%which = and i32 %tid, 1\n"                                                           \
   "%f = call ptr @air.get_function_pointer_visible_function_table(ptr addrspace(1) %table," \
   " i32 %which)\n"                                                                       \
   call                                                                                   \
   "%w = call i32 @external(i32 %v)\n"                                                    \
   "store i32 %w, ptr addrspace(1) %data, align 4\nret void\n}\n"                         \
   "!air.kernel = !{!2}\n!air.visible = !{!5}\n"                                          \
   "!2 = !{ptr @tables, !3, !4}\n!3 = !{}\n!4 = !{!40, !41, !42}\n"                        \
   "!5 = !{ptr @doubled, !6, !7}\n!6 = !{!60}\n!7 = !{!70}\n"                              \
   "!40 = !{i32 0, !\"air.visible_function_table\", !\"air.location_index\", i32 0, i32 1," \
   " !\"air.read\", !\"air.arg_type_name\", !\"visible_function_table\", !\"air.arg_name\"," \
   " !\"table\"}\n"                                                                       \
   "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read_write\"," \
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\"," \
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n"              \
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","    \
   " !\"air.arg_name\", !\"tid\"}\n"                                                       \
   "!60 = !{!\"air.visible_output\", !\"air.arg_type_name\", !\"int\"}\n"                   \
   "!70 = !{i32 0, !\"air.visible_input\", !\"air.arg_type_name\", !\"int\", !\"air.arg_name\"," \
   " !\"x\"}\n"

static const char *tables = TABLES("%v = call i32 %f(i32 %tid)\n");
/* A call through a bitcast of the pointer to its own type, as Apple's
 * compiler emits it. */
static const char *recast = TABLES("%g = bitcast ptr %f to ptr\n%v = call i32 %g(i32 %tid)\n");
/* A call with the table's size. */
static const char *sized =
   TABLES("%n = call i32 @air.get_size_visible_function_table(ptr addrspace(1) %table)\n"
          "%v = call i32 %f(i32 %n)\n");
/* A table's pointer used as other than a callee. */
static const char *escaping = TABLES("%v = ptrtoint ptr %f to i32\n");
/* The library linked with it: the external function and two visible
 * functions, one of another type. */
static const char *linked =
   "define i32 @external(i32 %x) {\n%y = add i32 %x, 7\nret i32 %y\n}\n"
   "define i32 @negated(i32 %x) {\n%y = sub i32 0, %x\nret i32 %y\n}\n"
   "define i64 @wide(i64 %x) {\nret i64 %x\n}\n"
   "!air.visible = !{}\n";

/* A kernel storing over the value its data holds what handle 1 of its
 * table returns for it: @down adds 2 per call it makes through the table
 * until its argument is zero, and @split adds 1 per call it makes twice. */
static const char *recursive =
   "declare ptr @air.get_function_pointer_visible_function_table(ptr addrspace(1), i32)\n"
   "define i32 @down(ptr addrspace(1) %table, i32 %x) {\n"
   "entry:\n%zero = icmp eq i32 %x, 0\nbr i1 %zero, label %done, label %next\n"
   "next:\n%f = call ptr @air.get_function_pointer_visible_function_table(ptr addrspace(1)"
   " %table, i32 0)\n%less = sub i32 %x, 1\n"
   "%r = call i32 %f(ptr addrspace(1) %table, i32 %less)\n%s = add i32 %r, 2\nbr label %done\n"
   "done:\n%v = phi i32 [0, %entry], [%s, %next]\nret i32 %v\n}\n"
   "define i32 @split(ptr addrspace(1) %table, i32 %x) {\n"
   "entry:\n%zero = icmp eq i32 %x, 0\nbr i1 %zero, label %done, label %next\n"
   "next:\n%f = call ptr @air.get_function_pointer_visible_function_table(ptr addrspace(1)"
   " %table, i32 0)\n%less = sub i32 %x, 1\n"
   "%a = call i32 %f(ptr addrspace(1) %table, i32 %less)\n"
   "%b = call i32 %f(ptr addrspace(1) %table, i32 %less)\n"
   "%s = add i32 %a, %b\n%t = add i32 %s, 1\nbr label %done\n"
   "done:\n%v = phi i32 [0, %entry], [%t, %next]\nret i32 %v\n}\n"
   "define void @recursive(ptr addrspace(1) %table, ptr addrspace(1) %data) {\n"
   "%f = call ptr @air.get_function_pointer_visible_function_table(ptr addrspace(1) %table,"
   " i32 0)\n%n = load i32, ptr addrspace(1) %data, align 4\n"
   "%v = call i32 %f(ptr addrspace(1) %table, i32 %n)\n"
   "store i32 %v, ptr addrspace(1) %data, align 4\nret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @recursive, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.visible_function_table\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.read\", !\"air.arg_type_name\", !\"visible_function_table\", !\"air.arg_name\","
   " !\"table\"}\n"
   "!41 = !{i32 1, !\"air.buffer\", !\"air.location_index\", i32 1, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n";

/* Stores the external function of its bias constant: a library with an
 * offset constant of the same index defines it, adding the offset. */
static const char *biased =
   "@bias = external addrspace(2) constant i32\n"
   "declare i32 @external(i32)\n"
   "define void @biased(ptr addrspace(1) %data) {\n"
   "%b = load i32, ptr addrspace(2) @bias, align 4\n"
   "%w = call i32 @external(i32 %b)\n"
   "store i32 %w, ptr addrspace(1) %data, align 4\nret void\n}\n"
   "!air.kernel = !{!2}\n"
   "!2 = !{ptr @biased, !3, !4}\n!3 = !{}\n!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n"
   "!air.function_constants = !{!50}\n"
   "!50 = !{ptr addrspace(2) @bias, !\"int\", !\"bias\", i32 0, i1 true}\n";
static const char *offsets =
   "@offset = external addrspace(2) constant i32\n"
   "define i32 @external(i32 %x) {\n"
   "%o = load i32, ptr addrspace(2) @offset, align 4\n"
   "%y = add i32 %x, %o\nret i32 %y\n}\n"
   "!air.visible = !{}\n"
   "!air.function_constants = !{!90}\n"
   "!90 = !{ptr addrspace(2) @offset, !\"int\", !\"offset\", i32 0, i1 true}\n";

/* A kernel that makes one call on command 0 of an argument buffer's
 * indirect command buffer. */
#define COMMANDS(command) \
   "declare void @air." command "_render_command(ptr addrspace(1), i32)\n" \
   "define void @commands(ptr addrspace(1) %icb) {\n" \
   "%cb = load ptr addrspace(1), ptr addrspace(1) %icb, align 8\n" \
   "call void @air." command "_render_command(ptr addrspace(1) %cb, i32 0)\n" \
   "ret void\n}\n" \
   "!air.kernel = !{!0}\n!0 = !{ptr @commands, !1, !2}\n!1 = !{}\n!2 = !{!3}\n" \
   "!3 = !{i32 0, !\"air.indirect_buffer\", !\"air.buffer_size\", i32 8, !\"air.location_index\"," \
   " i32 0, i32 1, !\"air.read_write\", !\"air.address_space\", i32 1, !\"air.struct_type_info\", !4," \
   " !\"air.arg_type_size\", i32 8, !\"air.arg_type_align_size\", i32 8, !\"air.arg_type_name\"," \
   " !\"Commands\", !\"air.arg_name\", !\"icb\"}\n" \
   "!4 = !{i32 0, i32 8, i32 0, !\"command_buffer\", !\"commands\", !\"air.indirect_argument\", !5}\n" \
   "!5 = !{i32 0, !\"air.command_buffer\", !\"air.location_index\", i32 0, i32 1," \
   " !\"air.arg_type_name\", !\"command_buffer\", !\"air.arg_name\", !\"commands\"}\n"
static const char *resets = COMMANDS("reset");
static const char *barriers = COMMANDS("set_barrier");

#define VERTEX_RESULT "<{ <4 x float>, <2 x float> }>"

static const char *vertex =
   "define " VERTEX_RESULT " @vertex(<4 x float> %p) {\n"
   "%uv = shufflevector <4 x float> %p, <4 x float> %p, <2 x i32> <i32 0, i32 1>\n"
   "%a0 = insertvalue " VERTEX_RESULT " undef, <4 x float> %p, 0\n"
   "%a1 = insertvalue " VERTEX_RESULT " %a0, <2 x float> %uv, 1\n"
   "ret " VERTEX_RESULT " %a1\n}\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @vertex, !3, !4}\n!3 = !{!30, !31}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!31 = !{!\"air.vertex_output\", !\"user(uv)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.vertex_input\", !\"air.location_index\", i32 3, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"p\"}\n";

/* Returns its first vertex input; it never reads the second. */
static const char *unread =
   "define <4 x float> @unread(<4 x float> %p, <4 x float> %q) {\n"
   "ret <4 x float> %p\n}\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @unread, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.vertex_input\", !\"air.location_index\", i32 0, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"p\"}\n"
   "!41 = !{i32 1, !\"air.vertex_input\", !\"air.location_index\", i32 1, i32 1,"
   " !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"q\"}\n";

#define CONTROL_POINT "{ <4 x float>, <2 x float> }"

/* A triangle patch's function at the position of a control point its
 * patch ID selects; it never reads the points' second member. */
static const char *patch =
   "define <4 x float> @patch(ptr %points, <3 x float> %at, i32 %id) {\n"
   "%point = call " CONTROL_POINT " @control_point(i32 %id, ptr %points)\n"
   "%position = extractvalue " CONTROL_POINT " %point, 0\n"
   "ret <4 x float> %position\n}\n"
   "declare " CONTROL_POINT " @control_point(i32, ptr) section \"air.externally_defined\"\n"
   "!air.vertex = !{!2}\n"
   "!2 = !{ptr @patch, !3, !4, !5}\n!3 = !{!30}\n"
   "!30 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.patch_control_point_input\", !43, !44, !45}\n"
   "!43 = !{!\"air.patch_control_point_function\", ptr @control_point}\n"
   "!44 = !{!\"air.location_index\", i32 1, i32 1, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"position\"}\n"
   "!45 = !{!\"air.location_index\", i32 2, i32 1, !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\", !\"air.arg_unused\"}\n"
   "!41 = !{i32 1, !\"air.position_in_patch\", !\"air.arg_type_name\", !\"float3\","
   " !\"air.arg_name\", !\"at\"}\n"
   "!42 = !{i32 2, !\"air.patch_id\", !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"id\"}\n"
   "!5 = !{!\"air.patch\", !\"triangle\", !\"air.patch_control_point\", i32 3}\n";

/* Discards fragments left of the origin. */
static const char *fragment =
   "declare void @air.discard_fragment()\n"
   "define <4 x float> @fragment(<2 x float> %uv) {\n"
   "%x = extractelement <2 x float> %uv, i64 0\n"
   "%left = fcmp olt float %x, 0.0\n"
   "br i1 %left, label %discard, label %shade\n"
   "discard:\ncall void @air.discard_fragment()\nbr label %shade\n"
   "shade:\n%c = shufflevector <2 x float> %uv, <2 x float> %uv, <4 x i32> <i32 0, i32 1, i32 0, i32 1>\n"
   "ret <4 x float> %c\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @fragment, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.render_target\", i32 1, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.fragment_input\", !\"user(uv)\", !\"air.center\", !\"air.perspective\","
   " !\"air.arg_type_name\", !\"float2\", !\"air.arg_name\", !\"uv\"}\n";

/* Returns the color its render target holds: programmable blending. */
static const char *blended =
   "define <4 x float> @blended(<4 x float> %previous) {\nret <4 x float> %previous\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @blended, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!4 = !{!40}\n"
   "!40 = !{i32 0, !\"air.render_target\", i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"previous\"}\n";

/* Reads its barycentric coordinates and interpolates its uv at the
 * centroid. */
static const char *pulled =
   "declare <2 x float> @air.interpolate_centroid_perspective.v2f32(ptr addrspace(1))\n"
   "define <4 x float> @pulled(ptr addrspace(1) %uv, <3 x float> %bary) {\n"
   "%c = call <2 x float> @air.interpolate_centroid_perspective.v2f32(ptr addrspace(1) %uv)\n"
   "%x = extractelement <2 x float> %c, i64 0\n"
   "%v = insertelement <3 x float> %bary, float %x, i64 0\n"
   "%r = shufflevector <3 x float> %v, <3 x float> %v, <4 x i32> <i32 0, i32 1, i32 2, i32 0>\n"
   "ret <4 x float> %r\n}\n"
   "!air.fragment = !{!2}\n"
   "!2 = !{ptr @pulled, !3, !4}\n!3 = !{!30}\n"
   "!30 = !{!\"air.render_target\", i32 0, i32 0, !\"air.arg_type_name\", !\"float4\","
   " !\"air.arg_name\", !\"color\"}\n"
   "!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.fragment_input\", !\"user(uv)\", !\"air.interpolation_function\","
   " !\"air.perspective\", !\"air.arg_type_name\", !\"float2\", !\"air.arg_name\", !\"uv\"}\n"
   "!41 = !{i32 1, !\"air.barycentric_coord\", !\"air.center\", !\"air.perspective\","
   " !\"air.arg_type_name\", !\"float3\", !\"air.arg_name\", !\"bary\"}\n";

static const char *object =
   "declare void @air.set_threadgroups_per_grid_mesh_properties(ptr addrspace(3), <3 x i32>)\n"
   "define void @object(ptr addrspace(6) %payload, ptr addrspace(3) %grid) {\n"
   "store i32 7, ptr addrspace(6) %payload, align 4\n"
   "call void @air.set_threadgroups_per_grid_mesh_properties(ptr addrspace(3) %grid,"
   " <3 x i32> <i32 1, i32 1, i32 1>)\n"
   "ret void\n}\n"
   "!air.object = !{!2}\n"
   "!2 = !{ptr @object, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!40 = !{i32 0, !\"air.payload\", !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mtl_payload\"}\n"
   "!41 = !{i32 1, !\"air.mesh_grid_properties\", !\"air.arg_type_name\", !\"mesh_grid_properties\","
   " !\"air.arg_name\", !\"grid\"}\n";

static const char *mesh =
   "declare void @air.set_position_mesh(ptr addrspace(7), i32, <4 x float>)\n"
   "declare void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7), i32, i32, <2 x float>)\n"
   "declare void @air.set_primitive_count_mesh(ptr addrspace(7), i32)\n"
   "define void @mesh(ptr addrspace(7) %m, ptr addrspace(6) %payload, i32 %tid) {\n"
   "%s = load i32, ptr addrspace(6) %payload, align 4\n"
   "call void @air.set_position_mesh(ptr addrspace(7) %m, i32 %tid, <4 x float> zeroinitializer)\n"
   "call void @air.set_vertex_data_mesh.v2f32(ptr addrspace(7) %m, i32 0, i32 %tid,"
   " <2 x float> zeroinitializer)\n"
   "call void @air.set_primitive_count_mesh(ptr addrspace(7) %m, i32 %s)\n"
   "ret void\n}\n"
   "!air.mesh = !{!2}\n"
   "!2 = !{ptr @mesh, !3, !4}\n!3 = !{}\n!4 = !{!40, !41, !42}\n"
   "!40 = !{i32 0, !\"air.mesh\", !50, !\"air.arg_type_name\", !\"mesh<>\", !\"air.arg_name\", !\"mtl_mesh\"}\n"
   "!50 = !{!\"air.mesh_type_info\", !51, !52, i32 3, i32 1, !\"air.triangle\"}\n"
   "!51 = !{!60, !61}\n!52 = !{}\n"
   "!60 = !{!\"air.position\", !\"air.arg_type_name\", !\"float4\", !\"air.arg_name\", !\"position\"}\n"
   "!61 = !{!\"air.mesh_vertex_data\", i32 0, !\"user(uv)\", !\"air.arg_type_name\", !\"float2\","
   " !\"air.arg_name\", !\"uv\"}\n"
   "!41 = !{i32 1, !\"air.payload\", !\"air.arg_type_size\", i32 16, !\"air.arg_type_align_size\", i32 4,"
   " !\"air.arg_type_name\", !\"uint\", !\"air.arg_name\", !\"mtl_payload\"}\n"
   "!42 = !{i32 2, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

static const struct stela_metal_target target = {
   .nir = &nir_options, .max_instructions = 10000, .max_threadgroup_bytes = 32768,
   .max_private_bytes = 4096, .max_constant_bytes = 65536, .max_varying_slots = 16,
   .max_payload_bytes = 16384, .max_mesh_vertices = 256, .max_mesh_primitives = 256,
};

/* A fixture's bitcode: its code and metadata, then the versions. */
static LLVMMemoryBufferRef
bitcode(const char *fixture)
{
   const char *metadata = strstr(fixture, "\n!air.") + 1;
   char *body = ralloc_strndup(NULL, fixture, metadata - fixture);
   char *tail = ralloc_asprintf(body, "%s%s", metadata, versions);
   LLVMMemoryBufferRef input = stela_air_test_custom_bitcode(module, body, tail, "");
   ralloc_free(body);
   return input;
}

/* Reflects entry specialized with the function constant values, or
 * unspecialized with NULL values. */
static bool
reflect_specialized(const char *fixture, const char *entry,
                    const struct stela_air_constant_value *values, unsigned count,
                    struct stela_metal_reflection *reflection, struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(fixture);
   bool reflected = stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), entry,
                                        values, count, reflection, error);
   if (!reflected)
      fprintf(stderr, "%s: %u %s\n", entry, error->kind, error->detail);
   LLVMDisposeMemoryBuffer(input);
   return reflected;
}

static bool
count_function(void *data, const char *name, size_t name_bytes,
               enum stela_metal_function_stage stage)
{
   (void)stage;
   *(unsigned *)data += name && name_bytes;
   return true;
}

/* The functions a fixture lists, zero when it cannot be listed. */
static unsigned
listed_functions(const char *fixture)
{
   LLVMMemoryBufferRef input = bitcode(fixture);
   unsigned count = 0;
   bool listed = stela_metal_functions(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                       count_function, &count, NULL);
   LLVMDisposeMemoryBuffer(input);
   return listed ? count : 0;
}

static bool
list_function(void *data, const char *name, size_t name_bytes,
              enum stela_metal_function_stage stage)
{
   (void)name_bytes;
   assert(!strcmp(name, "vertex") && stage == STELA_METAL_VERTEX);
   (*(unsigned *)data)++;
   return true;
}

static bool
reflect(const char *fixture, const char *entry, struct stela_metal_reflection *reflection,
        struct stela_air_error *error)
{
   return reflect_specialized(fixture, entry, NULL, 0, reflection, error);
}

static nir_shader *
compile(const char *fixture, const char *entry, const struct stela_metal_specialization *specialization,
        struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(fixture);
   nir_shader *shader = stela_metal_compile(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                            entry, &target, specialization, error);
   LLVMDisposeMemoryBuffer(input);
   return shader;
}

static const char *
name(const struct stela_metal_reflection *reflection, uint32_t offset, uint32_t bytes)
{
   static char text[STELA_METAL_NAME_BYTES + 1];
   memcpy(text, reflection->names + offset, bytes);
   text[bytes] = 0;
   return text;
}

static void
kernels_reflect_and_compile_their_threadgroup_memory(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(kernel, "kernel", &reflection, &error));
   assert(reflection.stage == STELA_METAL_KERNEL && reflection.max_total_threads == 64);
   assert(reflection.buffer_count == 1 && reflection.buffers[0].index == 2);
   assert(reflection.buffers[0].access == (STELA_METAL_ACCESS_READ | STELA_METAL_ACCESS_WRITE));
   assert(reflection.threadgroup_count == 1 && reflection.threadgroup[0].index == 0 &&
          reflection.threadgroup[0].bytes == 4);
   assert(reflection.threadgroup_bytes == 64);
   assert(!strcmp(name(&reflection, reflection.ident, reflection.ident_bytes), IDENT));

   const struct stela_metal_threadgroup_length lengths[] = {{0, 256}};
   struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .threadgroup_length_count = 1, .threadgroup_lengths = lengths,
   };
   nir_shader *shader = compile(kernel, "kernel", &specialization, &error);
   if (!shader)
      fprintf(stderr, "kernel: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_COMPUTE);
   assert(shader->info.shared_size >= 256 + 64);
   stela_metal_release(shader);

   /* Each threadgroup buffer needs its dispatch's length. */
   specialization.threadgroup_length_count = 0;
   assert(!compile(kernel, "kernel", &specialization, &error) && error.kind != STELA_AIR_OK);
}

static nir_variable *
varying(nir_shader *shader, nir_variable_mode mode, int location)
{
   nir_foreach_variable_with_modes(var, shader, mode) {
      if (var->data.location == location)
         return var;
   }
   return NULL;
}

/* A library of source has no container to list its functions. */
static void
modules_list_their_functions(void)
{
   LLVMMemoryBufferRef input = bitcode(vertex);
   unsigned count = 0;
   assert(stela_metal_functions(LLVMGetBufferStart(input), LLVMGetBufferSize(input), list_function,
                                &count, NULL));
   LLVMDisposeMemoryBuffer(input);
   assert(count == 1);
}

static void
discovery_reports_malformed_metadata(void)
{
   struct stela_air_error error;
   unsigned listed = 0;
   const char header[] = "BC\xc0\xde";
   assert(!stela_metal_functions(header, sizeof(header) - 1, count_function, &listed, &error));
   assert(error.kind == STELA_AIR_BITCODE && !listed);
   uint64_t states[STELA_METAL_SAMPLER_STATES];
   uint32_t count = 1;
   assert(!stela_metal_sampler_states(header, sizeof(header) - 1, states, &count, &error));
   assert(error.kind == STELA_AIR_BITCODE && !count);

   char *fixture = ralloc_asprintf(NULL, "%s!air.visible = !{!90}\n!90 = !{null}\n", kernel);
   LLVMMemoryBufferRef input = bitcode(fixture);
   ralloc_free(fixture);
   assert(!stela_metal_functions(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                 count_function, &listed, &error));
   assert(error.kind == STELA_AIR_METADATA);
   LLVMDisposeMemoryBuffer(input);
}

static void
reflection_requires_a_unique_listed_entry(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   char *fixture = ralloc_asprintf(NULL, "%s!air.visible = !{!2}\n", kernel);
   LLVMMemoryBufferRef input = bitcode(fixture);
   ralloc_free(fixture);
   assert(!stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                               "kernel", NULL, 0, &reflection, &error));
   assert(error.kind == STELA_AIR_METADATA && strstr(error.detail, "entry listed more than once"));
   LLVMDisposeMemoryBuffer(input);

   input = bitcode(kernel);
   assert(!stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                               "air.wg.barrier", NULL, 0, &reflection, &error));
   assert(error.kind == STELA_AIR_ARGUMENT);
   LLVMDisposeMemoryBuffer(input);
}

static void
render_stages_compile_at_their_linked_locations(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(vertex, "vertex", &reflection, &error));
   assert(reflection.stage == STELA_METAL_VERTEX && reflection.varying_count == 1);
   assert(reflection.attribute_count == 1 && reflection.attributes[0].index == 3 &&
          reflection.attributes[0].components == 4 && !reflection.attributes[0].patch_control_point &&
          reflection.attributes[0].active);
   assert(!strcmp(name(&reflection, reflection.attributes[0].name,
                       reflection.attributes[0].name_bytes), "p"));
   const struct stela_metal_varying *uv = &reflection.varyings[0];
   assert(!strcmp(name(&reflection, uv->identifier, uv->identifier_bytes), "user(uv)"));
   assert(uv->primitive == STELA_AIR_FLOAT && uv->components == 2 && !uv->per_primitive);

   assert(reflect(fragment, "fragment", &reflection, &error));
   assert(reflection.stage == STELA_METAL_FRAGMENT && reflection.discards);
   assert(reflection.varying_count == 1 && reflection.color_output_count == 1);
   assert(reflection.color_outputs[0].index == 1 && !reflection.color_outputs[0].dual_source);

   /* user(uv) is the second linked varying. */
   const struct stela_metal_linked_varying linked[] = {
      {"user(color)", 11, 0}, {"user(uv)", 8, 0},
   };
   const struct stela_metal_specialization specialization = {.varyings = linked, .varying_count = 2};
   nir_shader *shaders[2] = {
      compile(vertex, "vertex", &specialization, &error),
      compile(fragment, "fragment", &specialization, &error),
   };
   assert(shaders[0] && shaders[1]);
   assert(varying(shaders[0], nir_var_shader_out, VARYING_SLOT_VAR0 + 1));
   assert(varying(shaders[1], nir_var_shader_in, VARYING_SLOT_VAR0 + 1));
   for (unsigned i = 0; i < 2; i++)
      stela_metal_release(shaders[i]);

   assert(!reflection.barycentrics && !reflection.interpolants);
   /* Interpolants link as varyings. */
   assert(reflect(pulled, "pulled", &reflection, &error));
   assert(reflection.barycentrics && reflection.interpolants && reflection.varying_count == 1);
   nir_shader *pulling = compile(pulled, "pulled", &specialization, &error);
   assert(pulling && varying(pulling, nir_var_shader_in, VARYING_SLOT_VAR0 + 1));
   stela_metal_release(pulling);

   /* An input the function never reads is reflected inactive and not fetched. */
   assert(reflect(unread, "unread", &reflection, &error));
   assert(reflection.attribute_count == 2 && reflection.attributes[0].active &&
          !reflection.attributes[1].active);
   nir_shader *reading = compile(unread, "unread", &specialization, &error);
   assert(reading && varying(reading, nir_var_shader_in, VERT_ATTRIB_GENERIC0) &&
          !varying(reading, nir_var_shader_in, VERT_ATTRIB_GENERIC0 + 1));
   stela_metal_release(reading);

   /* A varying the pipeline did not link is refused. */
   const struct stela_metal_specialization unlinked = {.varyings = linked, .varying_count = 1};
   assert(!compile(fragment, "fragment", &unlinked, &error) && error.kind == STELA_AIR_ARGUMENT);
   /* As are entries no AIR list names. */
   assert(!reflect(vertex, "missing", &reflection, &error) && error.kind == STELA_AIR_ARGUMENT);
   /* A function reading its render target says so, for its pipeline's draws. */
   assert(reflect(blended, "blended", &reflection, &error));
   assert(reflection.attachment_reads == 1u);
}

static void
patch_functions_compile_behind_their_tessellation_stages(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(patch, "patch", &reflection, &error));
   assert(reflection.stage == STELA_METAL_VERTEX && reflection.patch == STELA_AIR_PATCH_TRIANGLE &&
          reflection.patch_control_points == 3);
   /* The control points' members, of which the function reads the first. */
   assert(reflection.attribute_count == 2 && reflection.attributes[0].index == 1 &&
          reflection.attributes[0].components == 4 && reflection.attributes[0].patch_control_point &&
          reflection.attributes[0].active);
   assert(reflection.attributes[1].index == 2 && !reflection.attributes[1].active);
   assert(!strcmp(name(&reflection, reflection.attributes[1].name,
                       reflection.attributes[1].name_bytes), "uv"));

   const struct stela_metal_specialization plain = {0};
   assert(!compile(patch, "patch", &plain, &error) && error.kind == STELA_AIR_ARGUMENT);
   struct stela_metal_tessellation tessellation = {
      .partition = STELA_METAL_PARTITION_INTEGER, .max_factor = 16};
   struct stela_metal_stage_in stage_in = {0};
   stage_in.attributes[1] = (struct stela_metal_stage_in_attribute){31, 0, 4};
   stage_in.layouts[4] = (struct stela_metal_stage_in_layout){
      16, STELA_METAL_STEP_PER_PATCH_CONTROL_POINT, 1};
   const struct stela_metal_specialization specialization = {
      .tessellation = &tessellation, .stage_in = &stage_in};
   nir_shader *shader = compile(patch, "patch", &specialization, &error);
   if (!shader)
      fprintf(stderr, "patch: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_TESS_EVAL);
   assert(shader->info.tess._primitive_mode == TESS_PRIMITIVE_TRIANGLES);
   stela_metal_release(shader);

   /* The pipeline tessellates the function's patch, from a layout with its
    * attributes; no other function tessellates. */
   tessellation.quad = true;
   assert(!compile(patch, "patch", &specialization, &error) && error.kind == STELA_AIR_INPUT);
   tessellation.quad = false;
   stage_in.attributes[1].format = 0;
   assert(!compile(patch, "patch", &specialization, &error) && error.kind == STELA_AIR_ARGUMENT);
   assert(!compile(vertex, "vertex", &specialization, &error) && error.kind == STELA_AIR_INPUT);

   nir_shader *stages[2];
   stela_metal_tessellation_stages(&target, &tessellation, stages);
   assert(stages[0]->info.stage == MESA_SHADER_VERTEX);
   assert(stages[1]->info.stage == MESA_SHADER_TESS_CTRL);
   for (unsigned i = 0; i < 2; i++)
      stela_metal_release(stages[i]);
}

static void
kernels_compile_with_their_stage_in(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(staged, "staged", &reflection, &error));
   /* Both attributes, of which the kernel reads the first. */
   assert(reflection.stage == STELA_METAL_KERNEL && reflection.attribute_count == 2 &&
          reflection.attributes[0].index == 0 && reflection.attributes[0].components == 4 &&
          reflection.attributes[0].active);
   assert(reflection.attributes[1].index == 1 && !reflection.attributes[1].active);
   assert(!strcmp(name(&reflection, reflection.attributes[1].name,
                       reflection.attributes[1].name_bytes), "index"));

   struct stela_metal_stage_in stage_in = {0};
   stage_in.attributes[0] = (struct stela_metal_stage_in_attribute){31, 0, 2};
   stage_in.layouts[2] = (struct stela_metal_stage_in_layout){
      16, STELA_METAL_STEP_THREAD_POSITION_IN_GRID_X, 1};
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .stage_in = &stage_in};
   nir_shader *shader = compile(staged, "staged", &specialization, &error);
   if (!shader)
      fprintf(stderr, "staged: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_COMPUTE);
   stela_metal_release(shader);

   /* The layout provides what the kernel reads, and only kernels and patch
    * functions fetch theirs. */
   const struct stela_metal_specialization plain = {.workgroup_size = {64, 1, 1}};
   assert(!compile(staged, "staged", &plain, &error) && error.kind == STELA_AIR_ARGUMENT);
   const struct stela_metal_specialization fetched = {.stage_in = &stage_in};
   assert(!compile(vertex, "vertex", &fetched, &error) && error.kind == STELA_AIR_INPUT);
}

static void
mesh_stages_compile_with_their_launch(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(object, "object", &reflection, &error));
   assert(reflection.stage == STELA_METAL_OBJECT && !reflection.buffer_count);
   assert(reflect(mesh, "mesh", &reflection, &error));
   assert(reflection.stage == STELA_METAL_MESH && reflection.varying_count == 1);

   const struct stela_metal_specialization launch = {
      .workgroup_size = {32, 1, 1}, .launched_by_grid = 1,
   };
   nir_shader *shader = compile(object, "object", &launch, &error);
   if (!shader)
      fprintf(stderr, "object: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_TASK);
   stela_metal_release(shader);

   const struct stela_metal_linked_varying linked[] = {{"user(uv)", 8, 0}};
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {32, 1, 1}, .varyings = linked, .varying_count = 1,
   };
   shader = compile(mesh, "mesh", &specialization, &error);
   if (!shader)
      fprintf(stderr, "mesh: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.stage == MESA_SHADER_MESH);
   assert(varying(shader, nir_var_shader_out, VARYING_SLOT_VAR0));
   stela_metal_release(shader);
}

static void
function_constants_reflect_and_specialize(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(constants, "constants", &reflection, &error));
   assert(reflection.function_constant_count == 2);
   const struct stela_metal_function_constant *scale = &reflection.function_constants[0];
   const struct stela_metal_function_constant *enabled = &reflection.function_constants[1];
   assert(!strcmp(name(&reflection, scale->name, scale->name_bytes), "scale"));
   assert(!strcmp(name(&reflection, scale->type, scale->type_bytes), "uint"));
   assert(scale->index == 0 && !scale->required);
   assert(!strcmp(name(&reflection, enabled->type, enabled->type_bytes), "bool"));
   assert(enabled->index == 3 && enabled->required);

   const uint32_t seven = 7;
   const uint8_t on = 1;
   const struct stela_air_constant_value values[] = {{0, &seven, 4}, {3, &on, 1}, {9, &on, 1}};
   struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .constants = values, .constant_count = 3,
   };
   nir_shader *shader = compile(constants, "constants", &specialization, &error);
   if (!shader)
      fprintf(stderr, "constants: %u %s\n", error.kind, error.detail);
   /* Every read folds to its value; none is left in constant data. */
   assert(shader && shader->constant_data_size == 0);
   assert(reflect_specialized(constants, "constants", values, 3, &reflection, &error));
   LLVMMemoryBufferRef input = bitcode(constants);
   nir_shader *prepared = stela_metal_compile_reflected(
      LLVMGetBufferStart(input), LLVMGetBufferSize(input), "constants",
      &target, &specialization, &reflection, &error);
   LLVMDisposeMemoryBuffer(input);
   assert(prepared);
   struct blob normal, reused;
   blob_init(&normal);
   blob_init(&reused);
   nir_serialize(&normal, shader, true);
   nir_serialize(&reused, prepared, true);
   assert(!normal.out_of_memory && !reused.out_of_memory);
   assert(normal.size == reused.size && !memcmp(normal.data, reused.data, normal.size));
   blob_finish(&normal);
   blob_finish(&reused);
   stela_metal_release(prepared);
   stela_metal_release(shader);

   /* scale is optional, and its definedness test folds to false. */
   specialization.constants = &values[1];
   specialization.constant_count = 1;
   shader = compile(constants, "constants", &specialization, &error);
   assert(shader);
   stela_metal_release(shader);

   /* enabled is required. */
   specialization.constants = values;
   specialization.constant_count = 1;
   assert(!compile(constants, "constants", &specialization, &error) &&
          error.kind == STELA_AIR_ARGUMENT);
   /* Values take their constant's size, once each. */
   const struct stela_air_constant_value wide[] = {{3, &seven, 4}};
   specialization.constants = wide;
   assert(!compile(constants, "constants", &specialization, &error) && error.kind == STELA_AIR_INPUT);
   const struct stela_air_constant_value twice[] = {{3, &on, 1}, {3, &on, 1}};
   specialization.constants = twice;
   specialization.constant_count = 2;
   assert(!compile(constants, "constants", &specialization, &error) && error.kind == STELA_AIR_INPUT);
}

/* Whether the shader stores the constant value. */
static bool
stores_constant(nir_shader *shader, uint32_t value)
{
   nir_opt_constant_folding(shader);
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            if (instr->type != nir_instr_type_intrinsic)
               continue;
            nir_intrinsic_instr *store = nir_instr_as_intrinsic(instr);
            if (store->intrinsic == nir_intrinsic_store_global &&
                nir_src_is_const(store->src[0]) && nir_src_as_uint(store->src[0]) == value)
               return true;
         }
      }
   }
   return false;
}

static void
derived_constants_are_constructed_from_their_function_constants(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(derived, "derived", &reflection, &error));
   assert(reflection.function_constant_count == 1);

   const int32_t five = 5;
   const struct stela_air_constant_value values[] = {{0, &five, 4}};
   struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .constants = values, .constant_count = 1,
   };
   nir_shader *shader = compile(derived, "derived", &specialization, &error);
   if (!shader)
      fprintf(stderr, "derived: %u %s\n", error.kind, error.detail);
   /* Its value folds into the store; none is left in constant data. */
   assert(shader && stores_constant(shader, 10) && !shader->constant_data_size);
   stela_metal_release(shader);

   shader = compile(converted, "derived", &specialization, &error);
   assert(shader && stores_constant(shader, 10));
   stela_metal_release(shader);

   assert(reflect_specialized(derived_with_helper, "derived", values, 1, &reflection, &error));
   shader = compile(derived_with_helper, "derived", &specialization, &error);
   assert(shader && stores_constant(shader, 10));
   stela_metal_release(shader);

   /* Without width, its definedness test selects eight. */
   specialization.constant_count = 0;
   shader = compile(derived, "derived", &specialization, &error);
   assert(shader && stores_constant(shader, 8));
   stela_metal_release(shader);

   /* Constructors are evaluated, never run. */
   assert(reflect(called, "derived", &reflection, &error));
   assert(!compile(called, "derived", &specialization, &error) && error.kind == STELA_AIR_INSTRUCTION &&
          strstr(error.detail, "program-scope constants"));
}

static void
constructed_globals_are_bounded(void)
{
   char *fixture = ralloc_strdup(NULL, derived);
   for (unsigned i = 0; i < AIR_MAX_ARGUMENTS; i++)
      assert(ralloc_asprintf_append(&fixture, "@extra%u = internal addrspace(2) global i32 0\n", i));
   LLVMMemoryBufferRef input = bitcode(fixture);
   ralloc_free(fixture);
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   const struct stela_air_constant_value unused = {0};
   assert(!stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                               "derived", &unused, 0, &reflection, &error));
   assert(error.kind == STELA_AIR_INSTRUCTION && strstr(error.detail, "program-scope constants"));
   LLVMDisposeMemoryBuffer(input);
}

static void
constructor_priorities_are_integer_literals(void)
{
   const char *priority = strstr(derived, "65535");
   assert(priority);
   const char *invalid[] = {"undef", "poison"};
   for (unsigned i = 0; i < ARRAY_SIZE(invalid); i++) {
      char *fixture = ralloc_asprintf(NULL, "%.*s%s%s", (int)(priority - derived), derived,
                                      invalid[i], priority + strlen("65535"));
      LLVMMemoryBufferRef input = bitcode(fixture);
      ralloc_free(fixture);
      struct stela_metal_reflection reflection;
      struct stela_air_error error;
      assert(!stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                  "derived", NULL, 0, &reflection, &error));
      assert(error.kind == STELA_AIR_METADATA && strstr(error.detail, "invalid AIR constructor list"));
      LLVMDisposeMemoryBuffer(input);
   }
}

static unsigned
count_intrinsic(nir_shader *shader, nir_intrinsic_op op)
{
   unsigned count = 0;
   nir_foreach_function_impl(impl, shader) {
      nir_foreach_block(block, impl) {
         nir_foreach_instr(instr, block) {
            count += instr->type == nir_instr_type_intrinsic &&
                     nir_instr_as_intrinsic(instr)->intrinsic == op;
         }
      }
   }
   return count;
}

/* Arguments a false function constant makes absent: reflection leaves
 * them out, folding removes the paths that read them, and another argument
 * takes their index. */
static void
function_constants_select_arguments(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   /* Unspecialized, it declares only what no constant can leave out. */
   assert(reflect(conditional, "conditional", &reflection, &error));
   assert(reflection.buffer_count == 1);
   for (uint8_t on = 0; on < 2; on++) {
      const struct stela_air_constant_value value = {0, &on, sizeof(on)};
      assert(reflect_specialized(conditional, "conditional", &value, 1, &reflection, &error));
      uint32_t access = on ? STELA_METAL_ACCESS_READ :
                             STELA_METAL_ACCESS_READ | STELA_METAL_ACCESS_WRITE;
      assert(reflection.buffer_count == 2 && reflection.buffers[1].index == 1 &&
             reflection.buffers[1].access == access);
      assert(reflect_specialized(conditional_with_helper, "conditional", &value, 1,
                                 &reflection, &error));
      assert(reflection.buffer_count == 2 && reflection.buffers[1].index == 1 &&
             reflection.buffers[1].access == access);
      const struct stela_metal_specialization specialization = {
         .workgroup_size = {64, 1, 1}, .constants = &value, .constant_count = 1,
      };
      nir_shader *shader = compile(conditional, "conditional", &specialization, &error);
      if (!shader)
         fprintf(stderr, "conditional: %u %s\n", error.kind, error.detail);
      assert(shader);
      stela_metal_release(shader);

      shader = compile(hoisted, "conditional", &specialization, &error);
      assert(shader);
      stela_metal_release(shader);

      /* A function that reads an absent argument reads nothing. */
      shader = compile(unguarded, "conditional", &specialization, &error);
      assert(shader);
      stela_metal_release(shader);
   }
   assert(!reflect(mistyped, "conditional", &reflection, &error) &&
          error.kind == STELA_AIR_METADATA && strstr(error.detail, "predicate"));
   /* A render stage drops the path that must reach an absent buffer. */
   for (uint8_t on = 0; on < 2; on++) {
      const struct stela_air_constant_value value = {0, &on, sizeof(on)};
      const struct stela_metal_specialization specialization = {
         .constants = &value, .constant_count = 1,
      };
      nir_shader *shader = compile(absent_path, "absent_path", &specialization, &error);
      if (!shader)
         fprintf(stderr, "absent_path: %u %s\n", error.kind, error.detail);
      assert(shader);
      assert(!count_intrinsic(shader, nir_intrinsic_load_global) == !on);
      stela_metal_release(shader);
   }
}

/* An output a false function constant makes absent is not one. */
static void
function_constants_select_outputs(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   for (uint8_t on = 0; on < 2; on++) {
      const struct stela_air_constant_value value = {0, &on, sizeof(on)};
      assert(reflect_specialized(optional_output, "optional", &value, 1, &reflection, &error));
      const struct stela_metal_linked_varying varying = {"generated(f)", 12, 0};
      const struct stela_metal_specialization specialization = {
         .constants = &value, .constant_count = 1, .varyings = &varying, .varying_count = 1,
      };
      nir_shader *shader = compile(optional_output, "optional", &specialization, &error);
      if (!shader)
         fprintf(stderr, "optional: %u %s\n", error.kind, error.detail);
      assert(shader);
      unsigned outputs = 0;
      nir_foreach_shader_out_variable(variable, shader)
         outputs++;
      assert(outputs == 1u + on);
      stela_metal_release(shader);
   }
}

static void
older_kernels_compile(void)
{
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   struct stela_air_error error;
   nir_shader *shader = compile(older_kernel, "older", &specialization, &error);
   if (!shader)
      fprintf(stderr, "older: %u %s\n", error.kind, error.detail);
   assert(shader);
   stela_metal_release(shader);
}

static void
unoptimized_kernels_compile(void)
{
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   struct stela_air_error error;
   nir_shader *shader = compile(unoptimized_kernel, "unoptimized", &specialization, &error);
   if (!shader)
      fprintf(stderr, "unoptimized: %u %s\n", error.kind, error.detail);
   assert(shader && !shader->scratch_size);
   stela_metal_release(shader);
}

static void
undefined_lanes_read_as_anything(void)
{
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   struct stela_air_error error;
   nir_shader *shader = compile(undefined_lanes, "lanes", &specialization, &error);
   if (!shader)
      fprintf(stderr, "lanes: %u %s\n", error.kind, error.detail);
   assert(shader);
   stela_metal_release(shader);
}

static void
arrays_reflect_each_slot(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(arrays, "arrays", &reflection, &error));
   assert(reflection.texture_count == 3 && reflection.sampler_count == 2);
   for (unsigned i = 0; i < 3; i++) {
      assert(reflection.textures[i].index == 2 + i);
      assert(reflection.textures[i].primitive == STELA_AIR_HALF);
   }
   assert(reflection.samplers[0] == 1 && reflection.samplers[1] == 2);

   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   nir_shader *shader = compile(arrays, "arrays", &specialization, &error);
   if (!shader)
      fprintf(stderr, "arrays: %u %s\n", error.kind, error.detail);
   assert(shader);
   stela_metal_release(shader);
}

static const char *
binding_name(const struct stela_metal_bindings *bindings, uint32_t offset, uint32_t bytes)
{
   static char text[STELA_METAL_BINDING_NAME_BYTES + 1];
   memcpy(text, bindings->names + offset, bytes);
   text[bytes] = 0;
   return text;
}

#define NAMED(row, text) (!strcmp(binding_name(&bindings, (row)->name, (row)->name_bytes), text))
#define TYPED(row, text) (!strcmp(binding_name(&bindings, (row)->type, (row)->type_bytes), text))

static void
bindings_reflect_their_structures(void)
{
   static struct stela_metal_bindings bindings;
   struct stela_air_error error;
   LLVMMemoryBufferRef input = bitcode(bound);
   bool reflected = stela_metal_reflect_bindings(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                                 "bound", NULL, 0, &bindings, &error);
   if (!reflected)
      fprintf(stderr, "bound: %u %s\n", error.kind, error.detail);
   assert(reflected && bindings.binding_count == 6);
   const struct stela_metal_binding *u = &bindings.bindings[0];
   assert(u->kind == STELA_METAL_BINDING_BUFFER && u->index == 0 && u->count == 1 && u->used);
   assert(u->access == STELA_METAL_ACCESS_READ && !u->argument_buffer);
   assert(u->size == 128 && u->alignment == 16 && NAMED(u, "u") && TYPED(u, "Uniforms"));
   assert(u->members == 0 && u->member_count == 3);
   const struct stela_metal_member *inner = &bindings.members[1];
   assert(NAMED(&bindings.members[0], "mvp") && TYPED(&bindings.members[0], "float4x4"));
   assert(NAMED(inner, "inner") && inner->offset == 64 && inner->size == 16 &&
          inner->elements == 2 && !inner->argument);
   assert(bindings.members[2].offset == 96 && bindings.members[2].elements == 3 &&
          bindings.members[2].member_count == 0);

   const struct stela_metal_binding *args = &bindings.bindings[1];
   assert(args->argument_buffer && !args->used && args->members == 3 && args->member_count == 3);
   const struct stela_metal_member *ts = &bindings.members[3];
   assert(ts->argument && ts->kind == STELA_AIR_FIELD_TEXTURE && ts->id == 0 && ts->count == 2);
   assert(ts->texture_type == STELA_AIR_TEXTURE_2D && ts->primitive == STELA_AIR_FLOAT &&
          ts->access == STELA_METAL_ACCESS_SAMPLE);
   const struct stela_metal_member *d = &bindings.members[4];
   assert(d->kind == STELA_AIR_FIELD_BUFFER && d->id == 2 && d->size_pointed == 4 &&
          d->alignment_pointed == 4 &&
          d->access == (STELA_METAL_ACCESS_READ | STELA_METAL_ACCESS_WRITE));
   assert(bindings.members[5].kind == STELA_AIR_FIELD_DATA && bindings.members[5].id == 3);
   /* A nested structure's members follow its parents'. */
   assert(inner->members == 6 && inner->member_count == 2 && bindings.member_count == 8);
   assert(NAMED(&bindings.members[7], "h") && bindings.members[7].offset == 8);

   const struct stela_metal_binding *rw = &bindings.bindings[2];
   assert(rw->kind == STELA_METAL_BINDING_TEXTURE && rw->index == 1 && rw->count == 1 &&
          rw->texture_type == STELA_AIR_TEXTURE_2D && rw->primitive == STELA_AIR_FLOAT &&
          !rw->depth && rw->access == (STELA_METAL_ACCESS_READ | STELA_METAL_ACCESS_WRITE));
   assert(bindings.bindings[3].kind == STELA_METAL_BINDING_SAMPLER &&
          NAMED(&bindings.bindings[3], "s"));
   const struct stela_metal_binding *tg = &bindings.bindings[4];
   assert(tg->kind == STELA_METAL_BINDING_THREADGROUP && tg->size == 16 && tg->alignment == 16);
   assert(bindings.bindings[5].index == 2 && bindings.bindings[5].used);

   assert(!stela_metal_reflect_bindings(LLVMGetBufferStart(input), LLVMGetBufferSize(input),
                                        "missing", NULL, 0, &bindings, &error) &&
          error.kind == STELA_AIR_ARGUMENT);
   LLVMDisposeMemoryBuffer(input);
}

#undef NAMED
#undef TYPED

/* Calls to the module's functions are inlined; recursion is refused. */
static void
defined_functions_inline_into_their_callers(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(calls, "calls", &reflection, &error) && reflection.buffer_count == 1);
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   nir_shader *shader = compile(calls, "calls", &specialization, &error);
   if (!shader)
      fprintf(stderr, "calls: %u %s\n", error.kind, error.detail);
   assert(shader);
   stela_metal_release(shader);

   assert(reflect(calls, "recurses", &reflection, &error));
   assert(!compile(calls, "recurses", &specialization, &error) &&
          error.kind == STELA_AIR_INSTRUCTION && strstr(error.detail, "recursive"));
}

/* A module with no direct call edges still checks unsupported calls during lowering. */
static void
unresolved_calls_are_rejected_without_a_call_graph(void)
{
   const char *callees[] = {"@external", "null"};
   const char *errors[] = {"unresolved external function external", "only from visible function tables"};
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   for (unsigned i = 0; i < ARRAY_SIZE(callees); i++) {
      char *fixture = ralloc_asprintf(NULL,
         "declare void @external()\ndefine void @unresolved() {\ncall void %s()\nret void\n}\n"
         "!air.kernel = !{!2}\n!2 = !{ptr @unresolved, !3, !3}\n!3 = !{}\n", callees[i]);
      struct stela_air_error error;
      assert(!compile(fixture, "unresolved", &specialization, &error));
      assert(error.kind == STELA_AIR_INSTRUCTION && strstr(error.detail, errors[i]));
      ralloc_free(fixture);
   }
}

/* os_log.log_error("hi %d %f %ld", ...) through the method Apple's compiler
 * defines for it, in a kernel, with a float its call promotes and a long. */
static const char *logging =
   "@sub = private addrspace(2) constant [4 x i8] c\"sub\\00\"\n"
   "@cat = private addrspace(2) constant [4 x i8] c\"cat\\00\"\n"
   "@ptr = private addrspace(2) constant [3 x i8] c\"%p\\00\"\n"
   "@fmt = private addrspace(2) constant [13 x i8] c\"hi %d %f %ld\\00\"\n"
   "%log = type { ptr addrspace(2), ptr addrspace(2) }\n"
   "@log = internal addrspace(2) global %log { ptr addrspace(2) @sub, ptr addrspace(2) @cat }\n"
   "@default = external addrspace(2) global %log\n"
   "@llvm.global_ctors = appending global [0 x { i32, ptr, ptr }] zeroinitializer\n"
   "declare void @llvm.va_start.p0(ptr)\ndeclare void @llvm.va_end.p0(ptr)\n"
   "declare void @air.os_log(ptr addrspace(2), ptr addrspace(2), i32, ptr addrspace(2), ptr, i64)\n"
   "define linkonce_odr void @log_error(ptr addrspace(2) %o, ptr addrspace(2) %f, i64 %n, ...) {\n"
   "%list = alloca ptr, align 8\ncall void @llvm.va_start.p0(ptr %list)\n"
   "%s = load ptr addrspace(2), ptr addrspace(2) %o, align 8\n"
   "%g = getelementptr inbounds %log, ptr addrspace(2) %o, i64 0, i32 1\n"
   "%c = load ptr addrspace(2), ptr addrspace(2) %g, align 8\n"
   "%l = load ptr, ptr %list, align 8\n"
   "call void @air.os_log(ptr addrspace(2) %s, ptr addrspace(2) %c, i32 16, ptr addrspace(2) %f,"
   " ptr %l, i64 %n)\n"
   "call void @llvm.va_end.p0(ptr %list)\nret void\n}\n"
   "define void @logs(ptr addrspace(1) %data, i32 %tid) {\n"
   "%t = uitofp i32 %tid to float\n%d = fpext float %t to double\n%w = zext i32 %tid to i64\n"
   "call void (ptr addrspace(2), ptr addrspace(2), i64, ...) @log_error(ptr addrspace(2) @log,"
   " ptr addrspace(2) @fmt, i64 20, i32 %tid, double %d, i64 %w)\n"
   "call void (ptr addrspace(2), ptr addrspace(2), i64, ...) @log_error(ptr addrspace(2) @default,"
   " ptr addrspace(2) @fmt, i64 4, i32 %tid)\n"
   "call void (ptr addrspace(2), ptr addrspace(2), i64, ...) @log_error(ptr addrspace(2) @default,"
   " ptr addrspace(2) @ptr, i64 8, ptr addrspace(1) %data)\n"
   "ret void\n}\n"
   "define void @promotes(ptr addrspace(1) %data, i32 %tid) {\n"
   "%t = uitofp i32 %tid to float\n%d = fpext float %t to double\n"
   "%f = fptrunc double %d to float\n"
   "store float %f, ptr addrspace(1) %data, align 4\nret void\n}\n"
   "!air.kernel = !{!2, !5}\n"
   "!2 = !{ptr @logs, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n!5 = !{ptr @promotes, !3, !4}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

static void
os_log_appends_self_contained_records(void)
{
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(logging, "logs", &reflection, &error));
   nir_shader *shader = compile(logging, "logs", &specialization, &error);
   assert(shader);
   /* Each call reads whether the buffer is past its capacity, reserves its
    * record and writes at least its six words. */
   assert(count_intrinsic(shader, nir_intrinsic_load_global) >= 6);
   assert(count_intrinsic(shader, nir_intrinsic_global_atomic) >= 3);
   assert(count_intrinsic(shader, nir_intrinsic_store_global) >= 18);
   stela_metal_release(shader);
   /* A double any other instruction reads is no promotion. */
   assert(!compile(logging, "promotes", &specialization, &error));
}

static const char *stitching_kernel =
   "declare i32 @quadrupled.MTL_VISIBLE_FN_REF(i32) section \"air.externally_defined\"\n"
   "define void @stitches(ptr addrspace(1) %data, i32 %tid) {\n"
   "%v = call i32 @quadrupled.MTL_VISIBLE_FN_REF(i32 %tid)\n"
   "store i32 %v, ptr addrspace(1) %data, align 4\nret void\n}\n"
   "!air.kernel = !{!2}\n!air.visible_function_references = !{!5}\n"
   "!2 = !{ptr @stitches, !3, !4}\n!3 = !{}\n!4 = !{!40, !41}\n"
   "!5 = !{!\"air.visible_function_reference\", ptr @quadrupled.MTL_VISIBLE_FN_REF,"
   " !\"quadrupled\"}\n"
   "!40 = !{i32 0, !\"air.buffer\", !\"air.location_index\", i32 0, i32 1, !\"air.read_write\","
   " !\"air.address_space\", i32 1, !\"air.arg_type_size\", i32 4, !\"air.arg_type_align_size\","
   " i32 4, !\"air.arg_type_name\", !\"int\", !\"air.arg_name\", !\"data\"}\n"
   "!41 = !{i32 1, !\"air.thread_position_in_grid\", !\"air.arg_type_name\", !\"uint\","
   " !\"air.arg_name\", !\"tid\"}\n";

/* Keeps the bitcode of LLVM's wrapper for a Darwin target, as `metal/library.rs`
 * reads it from a library. */
static void
keep_stitched(void *data, const void *bytes, size_t size)
{
   uint32_t wrapper[5];
   assert(size >= sizeof(wrapper));
   memcpy(wrapper, bytes, sizeof(wrapper));
   assert(wrapper[0] == 0x0b17c0de && wrapper[2] + wrapper[3] <= size);
   *(LLVMMemoryBufferRef *)data = LLVMCreateMemoryBufferWithMemoryRangeCopy(
      (const char *)bytes + wrapper[2], wrapper[3], "stitched");
}

static bool
visible_quadrupled(void *data, const char *name, size_t name_bytes,
                   enum stela_metal_function_stage stage)
{
   assert(name_bytes == 10 && !memcmp(name, "quadrupled", 10) && stage == STELA_METAL_VISIBLE);
   (*(unsigned *)data)++;
   return true;
}

/* quadrupled(x) = doubled(doubled(x)) is a visible function of its own module,
 * which a pipeline links with the module it calls. */
static void
stitched_functions_call_their_nodes_in_order(void)
{
   LLVMMemoryBufferRef source = bitcode(calls);
   struct stela_air_stitch_source sources[] = {
      {LLVMGetBufferStart(source), LLVMGetBufferSize(source), "doubled"},
      {LLVMGetBufferStart(source), LLVMGetBufferSize(source), "calls"},
   };
   const uint32_t first = 0, second = 1;
   const struct stela_air_stitch_node nodes[] = {
      {.function = STELA_AIR_STITCH_INPUT},
      {.function = 0, .arguments = &first, .argument_count = 1},
      {.function = 0, .arguments = &second, .argument_count = 1},
   };
   const struct stela_air_stitch_graph graph = {"quadrupled", nodes, 3, 2};
   struct stela_air_error error;
   LLVMMemoryBufferRef stitched = NULL;
   assert(stela_metal_stitch(sources, 1, &graph, 1, keep_stitched, &stitched, &error));

   unsigned listed = 0;
   assert(stela_metal_functions(LLVMGetBufferStart(stitched), LLVMGetBufferSize(stitched),
                                visible_quadrupled, &listed, &error));
   assert(listed == 1);

   const struct stela_air_module modules[] = {
      {LLVMGetBufferStart(stitched), LLVMGetBufferSize(stitched)},
      {LLVMGetBufferStart(source), LLVMGetBufferSize(source)},
   };
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .modules = modules, .module_count = 2,
   };
   nir_shader *shader = compile(stitching_kernel, "stitches", &specialization, &error);
   assert(shader);
   stela_metal_release(shader);

   /* Without the module it calls, the function is undefined. */
   const struct stela_metal_specialization unlinked = {
      .workgroup_size = {64, 1, 1}, .modules = modules, .module_count = 1,
   };
   assert(!compile(stitching_kernel, "stitches", &unlinked, &error));

   /* Only visible functions stitch, with as many arguments as they take. */
   assert(!stela_metal_stitch(&sources[1], 1, &graph, 1, keep_stitched, &stitched, &error) &&
          strstr(error.detail, "not visible"));
   const struct stela_air_stitch_node calling_nothing[] = {
      {.function = 0, .argument_count = 0},
   };
   const struct stela_air_stitch_graph short_call = {"short", calling_nothing, 1,
                                                     STELA_AIR_STITCH_NO_OUTPUT};
   assert(!stela_metal_stitch(sources, 1, &short_call, 1, keep_stitched, &stitched, &error) &&
          strstr(error.detail, "number of arguments"));
   LLVMDisposeMemoryBuffer(stitched);
   LLVMDisposeMemoryBuffer(source);
}

/* compile() with the modules and linked functions of a pipeline. */
static nir_shader *
compile_linked(const char *fixture, const char *entry, const char *const *modules,
               unsigned module_count, const char *const *functions, unsigned function_count,
               struct stela_air_error *error)
{
   LLVMMemoryBufferRef buffers[2];
   struct stela_air_module linked_modules[2];
   struct stela_air_linked_function linked_functions[4];
   assert(module_count <= 2 && function_count <= 4);
   for (unsigned i = 0; i < module_count; i++) {
      buffers[i] = bitcode(modules[i]);
      linked_modules[i] = (struct stela_air_module){LLVMGetBufferStart(buffers[i]),
                                                    LLVMGetBufferSize(buffers[i])};
   }
   for (unsigned i = 0; i < function_count; i++)
      linked_functions[i] = (struct stela_air_linked_function){functions[i], strlen(functions[i])};
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .modules = linked_modules, .module_count = module_count,
      .linked_functions = linked_functions, .linked_function_count = function_count,
   };
   nir_shader *shader = compile(fixture, entry, &specialization, error);
   for (unsigned i = 0; i < module_count; i++)
      LLVMDisposeMemoryBuffer(buffers[i]);
   return shader;
}

/* Calls through visible function tables dispatch over the linked functions,
 * and external functions resolve to the linked modules'. */
static void
linked_functions_resolve_tables_and_externals(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(tables, "tables", &reflection, &error));
   assert(reflection.function_tables == 1 && reflection.buffer_count == 2);
   /* A visible function reflects as no stage, and compiles only linked. */
   assert(reflect(tables, "doubled", &reflection, &error));
   assert(reflection.stage == STELA_METAL_VISIBLE && !reflection.buffer_count);
   const struct stela_metal_specialization none = {0};
   assert(!compile(tables, "doubled", &none, &error) && error.kind == STELA_AIR_ARGUMENT);

   const char *functions[] = {"doubled", "negated", "wide"};
   nir_shader *shader = compile_linked(tables, "tables", &linked, 1, functions, 3, &error);
   if (!shader)
      fprintf(stderr, "tables: %u %s\n", error.kind, error.detail);
   assert(shader);
   stela_metal_release(shader);
   shader = compile_linked(recast, "tables", &linked, 1, functions, 3, &error);
   assert(shader);
   stela_metal_release(shader);
   shader = compile_linked(sized, "tables", &linked, 1, functions, 3, &error);
   assert(shader);
   stela_metal_release(shader);

   /* Without the library, the external function is unresolved. */
   assert(!compile_linked(tables, "tables", NULL, 0, functions, 1, &error));
   assert(error.kind == STELA_AIR_INSTRUCTION && strstr(error.detail, "unresolved external function external"));
   /* A linked function no module defines. */
   const char *missing[] = {"doubled", "missing"};
   assert(!compile_linked(tables, "tables", &linked, 1, missing, 2, &error));
   assert(error.kind == STELA_AIR_ARGUMENT && strstr(error.detail, "not defined"));
   /* A table's pointer that escapes its calls. */
   assert(!compile_linked(escaping, "tables", &linked, 1, functions, 3, &error));
   assert(error.kind == STELA_AIR_INSTRUCTION && strstr(error.detail, "only called"));
   /* A library's kernel of the kernel's name is its own. */
   const char *sharing[] = {linked, "define void @tables() {\nret void\n}\n!air.kernel = !{!0}\n"
                                    "!0 = !{ptr @tables, !1, !1}\n!1 = !{}\n"};
   shader = compile_linked(tables, "tables", sharing, 2, functions, 3, &error);
   assert(shader);
   stela_metal_release(shader);
   /* A library that defines the kernel's own function again. */
   const char *twice[] = {linked, "define i32 @doubled(i32 %x) {\nret i32 %x\n}\n!air.visible = !{}\n"};
   assert(!compile_linked(tables, "tables", twice, 2, functions, 3, &error));
}

/* compile() of biased, linking offsets with values, or NULL for none. */
static nir_shader *
compile_biased(const struct stela_air_constant_value *offset, unsigned offset_count,
               struct stela_air_error *error)
{
   const uint32_t five = 5;
   const struct stela_air_constant_value bias = {0, &five, sizeof(five)};
   LLVMMemoryBufferRef buffer = bitcode(offsets);
   const struct stela_air_module module = {LLVMGetBufferStart(buffer), LLVMGetBufferSize(buffer),
                                           offset, offset_count};
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .constant_count = 1, .constants = &bias,
      .modules = &module, .module_count = 1,
   };
   nir_shader *shader = compile(biased, "biased", &specialization, error);
   LLVMDisposeMemoryBuffer(buffer);
   return shader;
}

/* A linked module takes its own function constant values, apart from the
 * function's. */
static void
linked_modules_specialize_their_function_constants(void)
{
   struct stela_air_error error;
   const uint32_t seven = 7;
   const struct stela_air_constant_value offset = {0, &seven, sizeof(seven)};
   nir_shader *shader = compile_biased(&offset, 1, &error);
   if (!shader)
      fprintf(stderr, "biased: %u %s\n", error.kind, error.detail);
   assert(shader && stores_constant(shader, 5 + 7));
   stela_metal_release(shader);

   assert(!compile_biased(NULL, 0, &error) && error.kind == STELA_AIR_INPUT &&
          strstr(error.detail, "have no values"));
   assert(!compile_biased(&offset, 0, &error) && error.kind == STELA_AIR_ARGUMENT &&
          strstr(error.detail, "required function constant"));
}

/* Kernels that encode indirect commands reflect so, and whether they may
 * set a command's barrier. */
static void
command_encoding_reflects_barriers(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(kernel, "kernel", &reflection, &error));
   assert(!reflection.commands && !reflection.command_barriers);
   assert(reflect(resets, "commands", &reflection, &error));
   assert(reflection.commands && !reflection.command_barriers);
   assert(reflect(barriers, "commands", &reflection, &error));
   assert(reflection.commands && reflection.command_barriers);
   const struct stela_metal_specialization specialization = {.workgroup_size = {64, 1, 1}};
   nir_shader *shader = compile(barriers, "commands", &specialization, &error);
   if (!shader)
      fprintf(stderr, "commands: %u %s\n", error.kind, error.detail);
   assert(shader);
   stela_metal_release(shader);
}

static void
put32(uint8_t *bytes, uint32_t value)
{
   memcpy(bytes, &value, sizeof(value));
}

static void
put64(uint8_t *bytes, uint64_t value)
{
   memcpy(bytes, &value, sizeof(value));
}

#define BASE 0x10000ull
#define TABLE 0x0u
#define DISPATCH 0x700u
#define OUT 0x800u

/* One invocation of the shaped kernel, as the local_index thread of
 * workgroup 1 of a dispatch whose arguments shape its threadgroups 4 by 2
 * and place its threadgroup buffer at 48 bytes: its effects. */
static unsigned
run_shaped(nir_shader *shader, uint32_t local_index, struct air_effect_store *trace,
           unsigned capacity)
{
   static uint8_t memory[0x900];
   uint8_t push[STELA_METAL_PUSH_BYTES] = {0};
   memset(memory, 0, sizeof(memory));
   put64(push + STELA_METAL_PUSH_TABLES, BASE + TABLE);
   put64(push + STELA_METAL_PUSH_ARGUMENTS, BASE + DISPATCH);
   put64(memory + TABLE + STELA_METAL_TABLE_BUFFER_ADDRESSES, BASE + OUT);
   const uint32_t shape[] = {4, 2, 1};
   for (unsigned i = 0; i < 3; i++)
      put32(memory + DISPATCH + STELA_METAL_DISPATCH_SHAPE + 4 * i, shape[i]);
   put32(memory + DISPATCH + STELA_METAL_DISPATCH_OFFSETS + 4, 48);
   const struct air_effect_environment environment = {
      .base = BASE, .bytes = memory, .size = sizeof(memory), .push = push,
      .push_size = sizeof(push), .local_index = local_index, .workgroup = {1, 0, 0},
   };
   struct air_effect_run run = air_effect_execute_in(shader, 100000, trace, capacity, &environment);
   if (run.status != AIR_EFFECT_COMPLETE)
      fprintf(stderr, "shaped: %s\n", run.detail);
   assert(run.status == AIR_EFFECT_COMPLETE);
   return run.stores;
}

static void
expect_store(const struct air_effect_store *store, bool shared, uint64_t address,
             const uint32_t *values, unsigned components)
{
   assert(store->shared == shared && store->address == address);
   assert(store->bits == 32 && store->components == components);
   for (unsigned i = 0; i < components; i++)
      assert(store->values[i].u32 == values[i]);
}

/* What recursive stores over 3 with function linked at handle 1 and calls
 * through tables nested at most depth deep, or ~0u if it fails to compile. */
static uint32_t
recursion_result(const char *function, uint32_t depth, struct stela_air_error *error)
{
   const struct stela_air_linked_function linked = {function, strlen(function)};
   const struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .linked_functions = &linked, .linked_function_count = 1,
      .max_call_stack_depth = depth,
   };
   nir_shader *shader = compile(recursive, "recursive", &specialization, error);
   if (!shader)
      return ~0u;
   enum { FUNCTIONS = 0x100, DATA = 0x200 };
   static uint8_t memory[0x300];
   uint8_t push[STELA_METAL_PUSH_BYTES] = {0};
   memset(memory, 0, sizeof(memory));
   put64(push + STELA_METAL_PUSH_TABLES, BASE + TABLE);
   put64(memory + TABLE + STELA_METAL_TABLE_BUFFER_ADDRESSES, BASE + FUNCTIONS);
   put64(memory + TABLE + STELA_METAL_TABLE_BUFFER_ADDRESSES + 8, BASE + DATA);
   put64(memory + FUNCTIONS, 2);
   put64(memory + FUNCTIONS + 8, 1);
   put32(memory + DATA, 3);
   const struct air_effect_environment environment = {
      .base = BASE, .bytes = memory, .size = sizeof(memory), .push = push,
      .push_size = sizeof(push),
   };
   /* The oracle reads the invocation's linear index and SSA values, and
    * refuses undefined ones, which structurizing leaves in its path
    * variables and for the paths a phi does not take. */
   const nir_lower_compute_system_values_options linear = {.lower_cs_local_id_to_index = true};
   nir_lower_compute_system_values(shader, &linear);
   nir_lower_vars_to_ssa(shader);
   nir_lower_undef_to_zero(shader, NULL);
   nir_opt_dce(shader);
   struct air_effect_store trace[1];
   struct air_effect_run run = air_effect_execute_in(shader, 100000, trace, 1, &environment);
   stela_metal_release(shader);
   if (run.status != AIR_EFFECT_COMPLETE)
      fprintf(stderr, "recursive: %s\n", run.detail);
   assert(run.status == AIR_EFFECT_COMPLETE && run.stores == 1);
   assert(trace[0].address == BASE + DATA && trace[0].bits == 32 && trace[0].components == 1);
   return trace[0].values[0].u32;
}

/* Recursion through function tables runs to the pipeline's call stack
 * depth, and a call nested deeper calls none. */
static void
recursion_unrolls_to_the_call_stack_depth(void)
{
   struct stela_air_error error;
   assert(recursion_result("down", 4, &error) == 6);
   assert(recursion_result("down", 9, &error) == 6);
   assert(recursion_result("down", 2, &error) == 4);
   assert(recursion_result("down", 1, &error) == 2);
   assert(recursion_result("down", 0, &error) == 0);
   /* Two calls per level: 1 + 2 * (1 + 2 * 1). */
   assert(recursion_result("split", 3, &error) == 7);
   /* Unrolling past the compilation budget, or the depth Stela unrolls. */
   assert(recursion_result("split", 40, &error) == ~0u && error.kind == STELA_AIR_LIMIT &&
          strstr(error.detail, "instruction budget"));
   assert(recursion_result("down", 1000, &error) == ~0u && error.kind == STELA_AIR_LIMIT &&
          strstr(error.detail, "call stack depth"));
}

/* A kernel of indirect commands takes each dispatch's threadgroup shape
 * and threadgroup buffer placement, and its threads past the shape skip
 * it. */
static void
dynamic_kernels_take_their_dispatch_shape(void)
{
   struct stela_air_error error;
   struct stela_metal_specialization specialization = {
      .workgroup_size = {64, 1, 1}, .dynamic_threadgroups = 1,
   };
   nir_shader *shader = compile(shaped, "shaped", &specialization, &error);
   if (!shader)
      fprintf(stderr, "shaped: %u %s\n", error.kind, error.detail);
   assert(shader && shader->info.workgroup_size[0] == 64);
   /* The threadgroup buffers share all of the target's threadgroup memory. */
   assert(shader->info.shared_size == target.max_threadgroup_bytes);

   struct air_effect_store trace[8];
   assert(run_shaped(shader, 5, trace, ARRAY_SIZE(trace)) == 4);
   expect_store(&trace[0], false, BASE + OUT, (const uint32_t[]){1, 1, 0}, 3);
   expect_store(&trace[1], false, BASE + OUT + 16, (const uint32_t[]){4, 2, 1}, 3);
   expect_store(&trace[2], false, BASE + OUT + 32, (const uint32_t[]){5, 1, 0}, 3);
   expect_store(&trace[3], true, 48, (const uint32_t[]){1}, 1);
   assert(run_shaped(shader, 8, trace, ARRAY_SIZE(trace)) == 0);
   stela_metal_release(shader);

   /* Dynamic threadgroups are a kernel's, which takes no lengths. */
   const struct stela_metal_threadgroup_length lengths[] = {{1, 16}};
   specialization.threadgroup_length_count = 1;
   specialization.threadgroup_lengths = lengths;
   assert(!compile(shaped, "shaped", &specialization, &error) && error.kind == STELA_AIR_INPUT);
   const struct stela_metal_specialization dynamic = {.dynamic_threadgroups = 1};
   assert(!compile(fragment, "fragment", &dynamic, &error) &&
          error.kind == STELA_AIR_INPUT);
}

int
main(void)
{
   glsl_type_singleton_init_or_ref();
   modules_list_their_functions();
   discovery_reports_malformed_metadata();
   reflection_requires_a_unique_listed_entry();
   kernels_reflect_and_compile_their_threadgroup_memory();
   dynamic_kernels_take_their_dispatch_shape();
   render_stages_compile_at_their_linked_locations();
   patch_functions_compile_behind_their_tessellation_stages();
   kernels_compile_with_their_stage_in();
   mesh_stages_compile_with_their_launch();
   function_constants_reflect_and_specialize();
   derived_constants_are_constructed_from_their_function_constants();
   constructed_globals_are_bounded();
   constructor_priorities_are_integer_literals();
   function_constants_select_outputs();
   older_kernels_compile();
   unoptimized_kernels_compile();
   undefined_lanes_read_as_anything();
   function_constants_select_arguments();
   arrays_reflect_each_slot();
   bindings_reflect_their_structures();
   defined_functions_inline_into_their_callers();
   unresolved_calls_are_rejected_without_a_call_graph();
   stitched_functions_call_their_nodes_in_order();
   os_log_appends_self_contained_records();
   linked_functions_resolve_tables_and_externals();
   recursion_unrolls_to_the_call_stack_depth();
   linked_modules_specialize_their_function_constants();
   command_encoding_reflects_barriers();
   glsl_type_singleton_decref();
   puts("metal compiler: ok");
   return 0;
}
