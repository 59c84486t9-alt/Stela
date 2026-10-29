/* SPDX-License-Identifier: MIT */
/* The Metal device's compiler service: reflection and compilation of
 * kernels, linked vertex and fragment functions, and object and mesh
 * functions. Original LLVM IR fixtures, one AIR module per function as
 * libraries hold them; no Apple output. */
#include "../metal_compiler.h"
#include "air_effect_oracle.h"
#include "air_test_fixture.h"
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
/* A constructor that calls an AIR function, which no constant folds. */
static const char *called = DERIVED("%x = call i32 @air.unknown(i32 %w)\n");

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
   "!6 = !{ptr @doubled, !7, !8}\n!7 = !{!70}\n!8 = !{!80}\n"
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

static bool
reflect(const char *fixture, const char *entry, struct stela_metal_reflection *reflection,
        struct stela_air_error *error)
{
   LLVMMemoryBufferRef input = bitcode(fixture);
   bool reflected = stela_metal_reflect(LLVMGetBufferStart(input), LLVMGetBufferSize(input), entry,
                                        reflection, error);
   if (!reflected)
      fprintf(stderr, "%s: %u %s\n", entry, error->kind, error->detail);
   LLVMDisposeMemoryBuffer(input);
   return reflected;
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

static void
render_stages_compile_at_their_linked_locations(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(vertex, "vertex", &reflection, &error));
   assert(reflection.stage == STELA_METAL_VERTEX && reflection.varying_count == 1);
   assert(reflection.attribute_count == 1 && reflection.attributes[0].index == 3 &&
          reflection.attributes[0].components == 4);
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

   /* A varying the pipeline did not link is refused. */
   const struct stela_metal_specialization unlinked = {.varyings = linked, .varying_count = 1};
   assert(!compile(fragment, "fragment", &unlinked, &error) && error.kind == STELA_AIR_ARGUMENT);
   /* As are entries no AIR list names. */
   assert(!reflect(vertex, "missing", &reflection, &error) && error.kind == STELA_AIR_ARGUMENT);
}

static void
patch_functions_compile_behind_their_tessellation_stages(void)
{
   struct stela_metal_reflection reflection;
   struct stela_air_error error;
   assert(reflect(patch, "patch", &reflection, &error));
   assert(reflection.stage == STELA_METAL_VERTEX && reflection.patch == STELA_AIR_PATCH_TRIANGLE &&
          reflection.patch_control_points == 3);
   /* The control points' members the function reads. */
   assert(reflection.attribute_count == 1 && reflection.attributes[0].index == 1 &&
          reflection.attributes[0].components == 4);

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
   /* The attributes the kernel reads. */
   assert(reflection.stage == STELA_METAL_KERNEL && reflection.attribute_count == 1 &&
          reflection.attributes[0].index == 0 && reflection.attributes[0].components == 4);

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

/* The value of the shader's one 32-bit constant datum. */
static int32_t
datum(const nir_shader *shader)
{
   int32_t value;
   assert(shader->constant_data_size == sizeof(value));
   memcpy(&value, shader->constant_data, sizeof(value));
   return value;
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
   assert(shader && datum(shader) == 10);
   stela_metal_release(shader);

   /* Without width, its definedness test selects eight. */
   specialization.constant_count = 0;
   shader = compile(derived, "derived", &specialization, &error);
   assert(shader && datum(shader) == 8);
   stela_metal_release(shader);

   /* Constructors are evaluated, never run. */
   assert(reflect(called, "derived", &reflection, &error));
   assert(!compile(called, "derived", &specialization, &error) && error.kind == STELA_AIR_INSTRUCTION &&
          strstr(error.detail, "program-scope constants"));
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
   /* A library that defines the kernel's own function again. */
   const char *twice[] = {linked, "define i32 @doubled(i32 %x) {\nret i32 %x\n}\n!air.visible = !{}\n"};
   assert(!compile_linked(tables, "tables", twice, 2, functions, 3, &error));
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
   put64(memory + FUNCTIONS, 1);
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
   kernels_reflect_and_compile_their_threadgroup_memory();
   dynamic_kernels_take_their_dispatch_shape();
   render_stages_compile_at_their_linked_locations();
   patch_functions_compile_behind_their_tessellation_stages();
   kernels_compile_with_their_stage_in();
   mesh_stages_compile_with_their_launch();
   function_constants_reflect_and_specialize();
   derived_constants_are_constructed_from_their_function_constants();
   arrays_reflect_each_slot();
   defined_functions_inline_into_their_callers();
   linked_functions_resolve_tables_and_externals();
   recursion_unrolls_to_the_call_stack_depth();
   linked_modules_specialize_their_function_constants();
   command_encoding_reflects_barriers();
   glsl_type_singleton_decref();
   puts("metal compiler: ok");
   return 0;
}
