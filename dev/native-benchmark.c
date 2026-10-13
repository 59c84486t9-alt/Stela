/* Own optimizing C baseline and timing loop, not production runtime code. */
#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    uint64_t x[31];
    uint64_t sp;
    uint32_t nzcv;
    uint32_t reserved;
    uint64_t v[32][2];
    uint32_t fpcr, fpsr;
} GuestState;

_Static_assert(sizeof(GuestState) == 784, "GuestState ABI size changed");
_Static_assert(offsetof(GuestState, sp) == 248, "GuestState SP offset changed");
_Static_assert(offsetof(GuestState, nzcv) == 256, "GuestState NZCV offset changed");

_Static_assert(offsetof(GuestState, v) == 264, "GuestState V offset changed");
_Static_assert(offsetof(GuestState, fpcr) == 776, "GuestState FPCR offset changed");
_Static_assert(offsetof(GuestState, fpsr) == 780, "GuestState FPSR offset changed");

typedef void (*Leaf)(GuestState *);

void bench_integer(GuestState *restrict state) {
    uint64_t remaining = state->x[12];
    uint64_t next = state->x[13];
    uint64_t sum = 0;
    while (remaining) {
        sum += next;
        next += 3;
        --remaining;
    }
    state->x[0] = sum;
    state->x[1] = remaining;
    state->x[2] = next;
}

void bench_sum(GuestState *restrict state) {
    uint64_t count = state->x[12];
    const uint64_t *input = (const uint64_t *)(uintptr_t)state->x[10];
    uint64_t sum = 0;
    uint64_t last = state->x[2];
    for (uint64_t i = 0; i < count; ++i) {
        last = input[i];
        sum += last;
    }
    state->x[2] = last;
    state->x[0] = sum;
    state->x[1] = 0;
    state->x[3] = state->x[10] + count * sizeof(uint64_t);
}

void bench_copy_sum(GuestState *restrict state) {
    uint64_t count = state->x[12];
    const uint64_t *input = (const uint64_t *)(uintptr_t)state->x[10];
    uint64_t *output = (uint64_t *)(uintptr_t)state->x[11];
    uint64_t sum = 0;
    uint64_t last = state->x[2];
    for (uint64_t i = 0; i < count; ++i) {
        last = input[i];
        output[i] = last;
        sum += last;
    }
    state->x[2] = last;
    state->x[0] = sum;
    state->x[1] = 0;
    state->x[3] = state->x[10] + count * sizeof(uint64_t);
    state->x[4] = state->x[11] + count * sizeof(uint64_t);
}

/* Mirrors every touched register, including skipped-loop temporaries and the
 * final CMP flags. All products, subtraction and negation use uint64_t modulo
 * arithmetic; signed overflow is detected from bit patterns without C UB.
 */
void bench_mix(GuestState *restrict state) {
    uint64_t count = state->x[12];
    const uint64_t *input = (const uint64_t *)(uintptr_t)state->x[10];
    uint64_t hash = state->x[13];
    uint64_t last = state->x[2];
    uint64_t product = state->x[4];
    uint64_t selected = state->x[7];
    uint64_t tweaked = state->x[8];
    uint32_t nzcv = state->nzcv;
    for (uint64_t i = 0; i < count; ++i) {
        last = input[i];
        hash = hash * UINT64_C(0x9e37) + last;
        product = last * UINT64_C(0x85eb);
        uint64_t difference = hash - product;
        uint64_t negative = difference >> 63;
        uint64_t zero = difference == 0;
        uint64_t carry = hash >= product;
        uint64_t overflow = ((hash ^ product) & (hash ^ difference)) >> 63;
        nzcv = (uint32_t)((negative << 31) | (zero << 30) | (carry << 29) | (overflow << 28));
        selected = carry && !zero ? hash : product;
        tweaked = carry ? selected : ~hash;
        hash = negative ? tweaked : UINT64_C(0) - selected;
    }
    state->x[0] = hash;
    state->x[1] = 0;
    state->x[2] = last;
    state->x[3] = state->x[10] + count * sizeof(uint64_t);
    state->x[4] = product;
    state->x[5] = UINT64_C(0x9e37);
    state->x[6] = UINT64_C(0x85eb);
    state->x[7] = selected;
    state->x[8] = tweaked;
    state->nzcv = nzcv;
}

/* Empty body for indirect-call/checksum/timer overhead context. Its result is
 * retained GuestState x0; no subtraction from workload timings is performed. */
void bench_empty(GuestState *state) {
    (void)state;
}

static clockid_t timing_clock(void) {
#ifdef CLOCK_MONOTONIC_RAW
    return CLOCK_MONOTONIC_RAW;
#else
    return CLOCK_MONOTONIC;
#endif
}

uint64_t stela_clock_resolution_ns(void) {
    struct timespec resolution;
    if (clock_getres(timing_clock(), &resolution)) return UINT64_MAX;
    return (uint64_t)resolution.tv_sec * UINT64_C(1000000000) + (uint64_t)resolution.tv_nsec;
}

static int nanoseconds(uint64_t *value) {
    struct timespec now;
    if (clock_gettime(timing_clock(), &now)) return -1;
    *value = (uint64_t)now.tv_sec * UINT64_C(1000000000) + (uint64_t)now.tv_nsec;
    return 0;
}

/* Opaque function pointer calls remain inside C; Python is outside the timer.
 * The per-call checksum/state reads and indirect-call cost affect both paths.
 * Data and count registers persist between calls; each function resets its own
 * working registers, making repeated calls valid without state copying.
 */
uint64_t stela_benchmark(Leaf function, GuestState *state, uint64_t calls,
                           uint64_t *checksum) {
    uint64_t start, end, total = 0;
    if (!function || !state || !checksum || !calls || nanoseconds(&start))
        return UINT64_MAX;
    for (uint64_t i = 0; i < calls; ++i) {
        function(state);
        total += state->x[0];
    }
    if (nanoseconds(&end) || end < start) return UINT64_MAX;
    *checksum = total;
    return end - start;
}
