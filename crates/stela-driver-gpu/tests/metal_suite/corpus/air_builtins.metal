// AIR builtins that no public header declares, which Apple's frameworks
// call. Each `stela_air__NAME` function is a placeholder the suite's build
// renames to AIR's `air.NAME`, with `__` for each `.`, in the library's IR.
#include <metal_stdlib>
using namespace metal;

/* SIMD-group asynchronous copies: a tile smaller than its destination,
 * padded with zeros and with its edge, a 1D run, a tile of every other
 * source element, and tiles read at offsets past their source's end and
 * before its start, padded with zeros and with its edge. */
struct _simdgroup_event_t;
thread _simdgroup_event_t *stela_air__simdgroup_async_copy_2d__p3i8__p1i8(
    ulong, ulong, threadgroup void *, ulong, ulong, ulong2, const device void *, ulong, ulong,
    ulong2, long2, int);
thread _simdgroup_event_t *stela_air__simdgroup_async_copy_1d__p3i8__p1i8(
    ulong, ulong, threadgroup void *, const device void *, ulong);
void stela_air__wait_simdgroup_events(int, thread _simdgroup_event_t **);

kernel void async_copies(device const uint *src [[buffer(0)]], device uint *out [[buffer(1)]],
                         ushort lane [[thread_index_in_simdgroup]])
{
    threadgroup uint tiles[6 * 64];
    for (uint i = lane; i < 6 * 64; i += 32)
        tiles[i] = 0xdead;
    threadgroup_barrier(mem_flags::mem_threadgroup);
    thread _simdgroup_event_t *events[6];
    events[0] = stela_air__simdgroup_async_copy_2d__p3i8__p1i8(
        4, 4, tiles, 8, 1, ulong2(8, 8), src, 13, 1, ulong2(5, 3), long2(0), 0);
    events[1] = stela_air__simdgroup_async_copy_2d__p3i8__p1i8(
        4, 4, tiles + 64, 8, 1, ulong2(8, 8), src, 13, 1, ulong2(5, 3), long2(0), 1);
    events[2] = stela_air__simdgroup_async_copy_1d__p3i8__p1i8(4, 4, tiles + 128, src, 20);
    events[3] = stela_air__simdgroup_async_copy_2d__p3i8__p1i8(
        4, 4, tiles + 192, 4, 1, ulong2(4, 2), src, 13, 2, ulong2(4, 2), long2(0), 0);
    events[4] = stela_air__simdgroup_async_copy_2d__p3i8__p1i8(
        4, 4, tiles + 256, 8, 1, ulong2(8, 8), src, 13, 1, ulong2(5, 3), long2(2, 1), 0);
    events[5] = stela_air__simdgroup_async_copy_2d__p3i8__p1i8(
        4, 4, tiles + 320, 8, 1, ulong2(8, 8), src, 13, 1, ulong2(5, 3), long2(-2, -1), 1);
    stela_air__wait_simdgroup_events(6, events);
    for (uint i = lane; i < 6 * 64; i += 32)
        out[i] = tiles[i];
}
