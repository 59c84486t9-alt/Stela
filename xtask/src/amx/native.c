// Bounded native Apple AMX qualification against the pinned corsix/amx model.
// Includes its MIT-licensed hardware helpers, Copyright (c) 2022 Peter Cawley;
// see LICENSES/MIT.txt.
// Build with the unmodified 483714bb sources (including test.c) on arm64 macOS.
// This runner qualifies M1 only. It does not probe privileged AMX controls.
static int corsix_unbounded_main(void) __attribute__((unused));
#define main corsix_unbounded_main
#include "test.c"
#undef main
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

typedef void (*test_fn)(amx_state*, uint64_t, ldst_test_buffer*);
typedef struct { const char* name; test_fn run; } native_case;
enum {
    FPCR_ROUND_SHIFT = 22, FPCR_FZ = 1u << 24, FPCR_DN = 1u << 25,
    FPCR_FZ16 = 1u << 19, FPCR_AHP = 1u << 26,
    FPSR_CUMULATIVE_AND_QC = (1u << 27) | 0x9f,
};
static uint64_t requested_fpcr, requested_fpsr, observed_fpcr, observed_fpsr;
static void select_environment(unsigned mode) {
    requested_fpcr = ((mode & 3) << FPCR_ROUND_SHIFT) |
        ((mode & 4) ? FPCR_DN : 0) | ((mode & 8) ? FPCR_FZ : 0) |
        ((mode & 16) ? FPCR_FZ16 : 0) | ((mode & 32) ? FPCR_AHP : 0);
    requested_fpsr = (mode & 64) ? FPSR_CUMULATIVE_AND_QC : 0;
}
static void write_fpcr(uint64_t value) { __asm__ volatile("msr fpcr, %0" : : "r"(value) : "memory"); }
static void write_fpsr(uint64_t value) { __asm__ volatile("msr fpsr, %0" : : "r"(value) : "memory"); }
static void before_native(void) {
    write_fpcr(requested_fpcr);
    write_fpsr(requested_fpsr);
}
static void after_native(void) {
    __asm__ volatile("mrs %0, fpcr" : "=r"(observed_fpcr) : : "memory");
    __asm__ volatile("mrs %0, fpsr" : "=r"(observed_fpsr) : : "memory");
    // The reference always computes with RN, DN, no flush/alternative-half.
    // Snapshot native status first: the reference's scalar FP may change it.
    write_fpcr(FPCR_DN);
    write_fpsr(0);
}

// Same safe transfer domain as test.c. Keep native execution separate from
// scalar reference arithmetic so FPCR/FPSR observations are not contaminated.
#define NATIVE_BINDING(op, transfer) \
    static void native_##op(amx_state* state, uint64_t operand, ldst_test_buffer* buf) { \
        extern void emulate_##op(amx_state*, uint64_t); \
        if (transfer) { \
            operand &= (0xffull << 56) | 0xff; \
            if ((operand & (1ull << 62)) && ((#op)[7] != 'I')) operand &= ~0x7full; \
            operand += (uint64_t)buf; \
        } \
        before_native(); \
        op(operand); \
        after_native(); \
        if (transfer) operand += sizeof(ldst_test_buffer); \
        emulate_##op(state, operand); \
    }
NATIVE_BINDING(AMX_LDX, true) NATIVE_BINDING(AMX_LDY, true)
NATIVE_BINDING(AMX_LDZ, true) NATIVE_BINDING(AMX_LDZI, true)
NATIVE_BINDING(AMX_STX, true) NATIVE_BINDING(AMX_STY, true)
NATIVE_BINDING(AMX_STZ, true) NATIVE_BINDING(AMX_STZI, true)
NATIVE_BINDING(AMX_EXTRX, false) NATIVE_BINDING(AMX_EXTRY, false)
NATIVE_BINDING(AMX_MAC16, false)
NATIVE_BINDING(AMX_FMA16, false) NATIVE_BINDING(AMX_FMA32, false)
NATIVE_BINDING(AMX_FMA64, false) NATIVE_BINDING(AMX_FMS16, false)
NATIVE_BINDING(AMX_FMS32, false) NATIVE_BINDING(AMX_FMS64, false)
NATIVE_BINDING(AMX_VECINT, false) NATIVE_BINDING(AMX_VECFP, false)
NATIVE_BINDING(AMX_MATINT, false) NATIVE_BINDING(AMX_MATFP, false)
NATIVE_BINDING(AMX_GENLUT, false)
#undef NATIVE_BINDING
#define CASE(op) { #op, native_##op }
static const native_case cases[] = {
    CASE(AMX_LDX), CASE(AMX_LDY), CASE(AMX_LDZ), CASE(AMX_LDZI),
    CASE(AMX_STX), CASE(AMX_STY), CASE(AMX_STZ), CASE(AMX_STZI),
    CASE(AMX_EXTRX), CASE(AMX_EXTRY), CASE(AMX_MAC16),
    CASE(AMX_FMA16), CASE(AMX_FMA32), CASE(AMX_FMA64),
    CASE(AMX_FMS16), CASE(AMX_FMS32), CASE(AMX_FMS64),
    CASE(AMX_VECINT), CASE(AMX_VECFP), CASE(AMX_MATINT),
    CASE(AMX_MATFP), CASE(AMX_GENLUT),
};
#undef CASE

// Same discriminating instruction sequence as corsix test.c, with every
// source byte initialized. This is an observed behavioral signature, not IDR.
static unsigned generation_signature(void) {
    __attribute__((aligned(256))) uint8_t buf[256] = {0};
    buf[64] = 3;
    buf[65] = 2;
    buf[129] = 1;
    AMX_SET();
    AMX_LDX(PTR_ROW_FLAGS(buf, 48, 1));
    AMX_VECINT((2ull << 47) + (1ull << 31) + (129ull << 10));
    AMX_STZ(PTR_ROW_FLAGS(buf, 0, 0));
    AMX_CLR();
    return 1 + buf[0];
}

static int compare_case(size_t index, unsigned chains, unsigned steps, unsigned inject) {
    amx_state original, expected, actual;
    __attribute__((aligned(256))) ldst_test_buffer buffers[2];
    rand_init();
    uint64_t old_fpcr = fpcr_init();
    uint64_t old_fpsr;
    __asm__ volatile("mrs %0, fpsr" : "=r"(old_fpsr));
    write_fpcr(FPCR_DN);
    for (unsigned chain = 0; chain < chains; ++chain) {
        rand_fill(&original, sizeof(original));
        memcpy(&expected, &original, sizeof(expected));
        rand_fill(buffers, sizeof(buffers[0]));
        memcpy(buffers + 1, buffers, sizeof(buffers[0]));
        AMX_SET();
        inject_state(&original);
        for (unsigned step = 0; step < steps; ++step) {
            uint64_t operand = rand_next();
            select_environment(step & 127);
            cases[index].run(&expected, operand, buffers);
            capture_state(&actual);
            if (inject == 1 && chain == 0 && step == 0) actual.z[0].u8[0] ^= 1;
            if (inject == 2 && chain == 0 && step == 0) observed_fpsr ^= 1;
            if (observed_fpcr != requested_fpcr || observed_fpsr != requested_fpsr ||
                memcmp(&actual, &expected, sizeof(actual)) ||
                memcmp(buffers, buffers + 1, sizeof(buffers[0]))) {
                AMX_CLR();
                fpcr_restore(old_fpcr);
                write_fpsr(old_fpsr);
                printf("{\"operation\":\"%s\",\"status\":\"mismatch\","
                       "\"chain\":%u,\"step\":%u,\"operand\":\"%016llx\","
                       "\"fpcr_requested\":%llu,\"fpcr_observed\":%llu,"
                       "\"fpsr_requested\":%llu,\"fpsr_observed\":%llu}\n",
                       cases[index].name, chain, step, (unsigned long long)operand,
                       (unsigned long long)requested_fpcr, (unsigned long long)observed_fpcr,
                       (unsigned long long)requested_fpsr, (unsigned long long)observed_fpsr);
                return 1;
            }
        }
        AMX_CLR();
    }
    fpcr_restore(old_fpcr);
    write_fpsr(old_fpsr);
    printf("{\"operation\":\"%s\",\"status\":\"pass\",\"chains\":%u,\"steps\":%u,\"environment_period\":128}\n",
           cases[index].name, chains, steps);
    return 0;
}

static unsigned fp_bytes(size_t index) {
    if (index == 11 || index == 14) return 2;
    if (index == 12 || index == 15) return 4;
    if (index == 13 || index == 16) return 8;
    return 0;
}

static int compare_fp_edges(size_t index) {
    // +/-zero, min/max subnormal, min normal, one, nextafter(one), max finite,
    // +/-infinity, quiet/signaling NaN. Each environment starts with fresh state.
    static const uint64_t edges[3][12] = {
        {0, 0x8000, 1, 0x3ff, 0x400, 0x3c00, 0x3c01, 0x7bff,
         0x7c00, 0xfc00, 0x7e01, 0x7c01},
        {0, 0x80000000, 1, 0x7fffff, 0x800000, 0x3f800000, 0x3f800001,
         0x7f7fffff, 0x7f800000, 0xff800000, 0x7fc00001, 0x7f800001},
        {0, 0x8000000000000000ull, 1, 0xfffffffffffffull, 0x10000000000000ull,
         0x3ff0000000000000ull, 0x3ff0000000000001ull, 0x7fefffffffffffffull,
         0x7ff0000000000000ull, 0xfff0000000000000ull, 0x7ff8000000000001ull,
         0x7ff0000000000001ull},
    };
    unsigned bytes = fp_bytes(index), format = bytes == 2 ? 0 : bytes == 4 ? 1 : 2;
    amx_state initial, expected, actual;
    __attribute__((aligned(256))) ldst_test_buffer buffers[2] = {0};
    for (unsigned edge = 0; edge < 12; ++edge) {
        for (unsigned offset = 0; offset < sizeof(initial); offset += bytes) {
            unsigned bank = offset < 512 ? 0 : offset < 1024 ? 3 : 7;
            memcpy((uint8_t*)&initial + offset, &edges[format][(edge + bank) % 12], bytes);
        }
        for (unsigned mode = 0; mode < 128; ++mode) {
            select_environment(mode);
            for (unsigned alu = 0; alu < 8; ++alu) {
                for (unsigned vector = 0; vector < 2; ++vector) {
                    uint64_t operand = ((uint64_t)alu << 27) | ((uint64_t)vector << 63);
                    memcpy(&expected, &initial, sizeof(initial));
                    AMX_SET();
                    inject_state(&initial);
                    cases[index].run(&expected, operand, buffers);
                    capture_state(&actual);
                    AMX_CLR();
                    if (observed_fpcr != requested_fpcr || observed_fpsr != requested_fpsr ||
                        memcmp(&actual, &expected, sizeof(actual))) {
                        printf("{\"operation\":\"%s\",\"status\":\"edge-mismatch\","
                               "\"edge\":%u,\"environment\":%u,\"alu\":%u,\"vector\":%u}\n",
                               cases[index].name, edge, mode, alu, vector);
                        return 1;
                    }
                }
            }
        }
    }
    printf("{\"operation\":\"%s\",\"status\":\"pass\",\"edge_steps\":24576}\n",
           cases[index].name);
    return 0;
}

static bool bound(const char* text, unsigned* value) {
    char* end;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 10);
    if (errno || !*text || *end || parsed < 1 || parsed > 4096) return false;
    *value = (unsigned)parsed;
    return true;
}

int main(int argc, char** argv) {
    unsigned chains, steps;
    unsigned inject = argc == 4 && strcmp(argv[3], "--inject-mismatch") == 0 ? 1 :
        argc == 4 && strcmp(argv[3], "--inject-status-mismatch") == 0 ? 2 :
        argc == 4 && strcmp(argv[3], "--inject-signal") == 0 ? 3 : 0;
    bool edges = argc == 4 && strcmp(argv[3], "--fp-edges") == 0;
    if ((argc != 3 && !inject && !edges) || !bound(argv[1], &chains) || !bound(argv[2], &steps)) {
        fprintf(stderr, "usage: native-amx CHAINS STEPS [--fp-edges|--inject-mismatch|"
                        "--inject-status-mismatch|--inject-signal] (1..4096 each)\n");
        return 2;
    }
    // Buffered output must never be duplicated across forks.
    setvbuf(stdout, NULL, _IONBF, 0);
    int failed = 0;
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        if (edges && !fp_bytes(index)) continue;
        pid_t child = fork();
        if (child < 0) { perror("fork"); return 2; }
        if (child == 0) {
            unsigned signature = generation_signature();
            if (signature != AMX_VER_M1) {
                printf("{\"operation\":\"%s\",\"status\":\"unqualified-generation\",\"signature\":%u}\n",
                       cases[index].name, signature);
                _exit(2);
            }
            AMX_VER = AMX_VER_M1;
            if (inject == 3) { raise(SIGILL); _exit(2); }
            if (edges) _exit(compare_fp_edges(index));
            _exit(compare_case(index, chains, steps, inject));
        }
        int status;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited < 0) { perror("waitpid"); return 2; }
        if (WIFSIGNALED(status)) {
            printf("{\"operation\":\"%s\",\"status\":\"signal\",\"signal\":%d}\n",
                   cases[index].name, WTERMSIG(status));
            failed = 1;
        } else if (!WIFEXITED(status) || WEXITSTATUS(status)) failed = 1;
    }
    return failed;
}
