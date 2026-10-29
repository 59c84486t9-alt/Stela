/* SPDX-License-Identifier: MIT */
#include "../threadgroup.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifdef NDEBUG
#error "Threadgroup value tests require active assertions"
#endif
static struct stela_air_argument_info argument(unsigned ordinal, unsigned index, unsigned alignment)
{
    return (struct stela_air_argument_info){.kind = 1, .plain_buffer_type = true,
        .buffer = {.argument = ordinal, .index = index, .address_space = 3,
            .access = STELA_AIR_READ_WRITE, .type_size = 4, .type_alignment = alignment}};
}
static void refusal(const struct stela_air_argument_info *args, unsigned count,
    const struct stela_metal_threadgroup_request *request, unsigned max_bytes,
    enum stela_metal_threadgroup_status expected)
{
    struct stela_metal_threadgroup_specialization result, original;
    memset(&result, 0xa5, sizeof(result)); original = result;
    assert(stela_metal_threadgroup_normalize(args, count, request, max_bytes, &result) == expected);
    assert(!memcmp(&result, &original, sizeof(result)));
}
int main(void)
{
    struct stela_air_argument_info args[] = {argument(4, 7, 4), argument(1, 3, 16), argument(2, 7, 4)};
    args[2].buffer.address_space = 1; /* Same numeric AS1/AS3 index is legal. */
    struct stela_metal_threadgroup_request_row rows[] = {{.index = 3, .bytes = 256}, {.index = 7, .bytes = 128}};
    struct stela_metal_threadgroup_request request = {.size = sizeof(request),
        .abi = STELA_METAL_THREADGROUP_ABI, .count = 2, .rows = rows};
    struct stela_metal_threadgroup_specialization result;
    assert(stela_metal_threadgroup_normalize(args, 3, &request, 384, &result) == STELA_METAL_THREADGROUP_OK);
    assert(result.count == 2 && result.bindings[0].buffer.argument == 4 && result.bindings[0].buffer.index == 7 &&
        result.bindings[0].bytes == 128 && result.bindings[0].alignment == 16 &&
        result.bindings[1].buffer.argument == 1 && result.bindings[1].bytes == 256);
    assert(stela_metal_threadgroup_matches(&result, &request));
    args[0].buffer.type_size = 16; assert(result.bindings[0].buffer.type_size == 4); args[0].buffer.type_size = 4;
    struct stela_metal_threadgroup_request_row saved = rows[0]; rows[0] = rows[1]; rows[1] = saved;
    assert(stela_metal_threadgroup_matches(&result, &request));
    rows[0].bytes = 144; assert(!stela_metal_threadgroup_matches(&result, &request)); rows[0].bytes = 128;
    assert(!stela_metal_threadgroup_matches(&result, NULL));
    refusal(args, 3, NULL, 384, STELA_METAL_THREADGROUP_UNSUPPORTED);
    refusal(args, 3, &request, 383, STELA_METAL_THREADGROUP_LIMIT);
    for (unsigned i = 0; i < 5; i++) {
        const uint64_t invalid[] = {0, 3, 15, 17, UINT64_MAX};
        rows[0].bytes = invalid[i]; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_UNSUPPORTED);
    }
    rows[0].bytes = UINT64_C(0x100000000);
    refusal(args, 3, &request, UINT32_MAX, STELA_METAL_THREADGROUP_LIMIT); rows[0].bytes = 128;
    rows[0].reserved = 1; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID); rows[0].reserved = 0;
    rows[0].index = 3; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID); rows[0].index = 7;
    rows[0].index = 9; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_UNSUPPORTED); rows[0].index = 7;
    request.count = 1; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_UNSUPPORTED); request.count = 2;
    request.size--; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID); request.size++;
    request.abi++; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID); request.abi--;
    request.reserved = 1; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID); request.reserved = 0;
    request.count = AIR_MAX_ARGUMENTS + 1; request.rows = (const void *)(uintptr_t)1;
    refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID);
    request.count = 2; request.rows = NULL; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_INVALID);
    request.rows = rows;
    refusal((const void *)(uintptr_t)1, AIR_MAX_ARGUMENTS + 1, &request, 384, STELA_METAL_THREADGROUP_INVALID);
    args[0].plain_buffer_type = false; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_UNSUPPORTED);
    args[0].plain_buffer_type = true; args[0].buffer.type_alignment = 3;
    refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_UNSUPPORTED); args[0].buffer.type_alignment = 4;
    args[0].buffer.type_size = 256; refusal(args, 3, &request, 384, STELA_METAL_THREADGROUP_UNSUPPORTED);
    args[0].buffer.type_size = 4;
    assert(stela_metal_threadgroup_normalize(NULL, 0, NULL, 0, &result) == STELA_METAL_THREADGROUP_OK && !result.count);
    assert(stela_metal_threadgroup_matches(&result, NULL));
    refusal(NULL, 0, &request, 384, STELA_METAL_THREADGROUP_INVALID);
    puts("threadgroup exact-index/length/alignment ownership, equality, budgets and atomic refusals passed");
    return 0;
}
