/* Native fault observer for emitted code. Test-only; no guest fault handler. */
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

struct guest_state { uint64_t x[31], sp; uint32_t nzcv, reserved; uint64_t v[32][2]; uint32_t fpcr, fpsr; };
_Static_assert(sizeof(struct guest_state) == 784, "GuestState ABI");
_Static_assert(offsetof(struct guest_state, v) == 264, "V register ABI offset");
_Static_assert(offsetof(struct guest_state, fpcr) == 776, "FPCR ABI offset");
_Static_assert(offsetof(struct guest_state, fpsr) == 780, "FPSR ABI offset");
static struct guest_state state;
static unsigned char *ram;
static size_t page_size, observed_bytes;

static void output(const void *data, size_t length) {
    const unsigned char *bytes = data;
    while (length) {
        ssize_t count = write(STDOUT_FILENO, bytes, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) _exit(91);
        bytes += count;
        length -= (size_t)count;
    }
}

static void capture(int number, siginfo_t *info, void *context) {
    ucontext_t *uc = context;
#if defined(__APPLE__) && defined(__x86_64__)
    uint64_t pc = uc->uc_mcontext->__ss.__rip;
#elif defined(__linux__) && defined(__x86_64__)
    uint64_t pc = (uint64_t)uc->uc_mcontext.gregs[REG_RIP];
#else
#error "Native memory fault observer requires x86-64 Darwin or Linux"
#endif
    uint64_t result[] = {(uint64_t)number, pc, (uintptr_t)info->si_addr};
    output(result, sizeof(result));
    output(&state, sizeof(state));
    output(ram, observed_bytes);
    _exit(0);
}

int main(int argc, char **argv) {
    uintptr_t mapping_base = 0;
    if (argc >= 3 && !strcmp(argv[argc - 2], "--mapping-base")) {
        char *end = NULL;
        errno = 0;
        unsigned long long value = strtoull(argv[argc - 1], &end, 0);
        if (errno || !end || *end || end == argv[argc - 1] || !value ||
            argv[argc - 1][0] < '0' || argv[argc - 1][0] > '9' || value > UINTPTR_MAX) return 17;
        mapping_base = (uintptr_t)value;
        argc -= 2;
    }
    if (argc != 5 && argc != 6) return 2;
    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (mapping_base && (mapping_base % page_size || mapping_base > UINTPTR_MAX - 3 * page_size)) return 17;
    observed_bytes = page_size;
    FILE *file = fopen(argv[1], "rb");
    if (!file || fseek(file, 0, SEEK_END)) return 3;
    long length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET)) return 4;
    void *code = mmap(NULL, (size_t)length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || fread(code, 1, (size_t)length, file) != (size_t)length) return 5;
    fclose(file);
    if (mprotect(code, (size_t)length, PROT_READ | PROT_EXEC)) return 6;
    unsigned char *mapping = mmap((void *)mapping_base, 3 * page_size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED) return 7;
    /* A hint may be refused; never replace an existing mapping with MAP_FIXED. */
    if (mapping_base && (uintptr_t)mapping != mapping_base) return 18;
    ram = mapping + page_size;
    if (mprotect(ram, page_size, PROT_READ | PROT_WRITE)) return 8;
    memset(ram, 0xa5, page_size);
    for (unsigned i = 0; i < 31; i++) state.x[i] = UINT64_C(0xf0123456789abcd0) + i;
    state.sp = (uintptr_t)(ram + 512);
    state.nzcv = 0xa0000000;
    for (unsigned i = 0; i < 32; i++) {
        state.v[i][0] = UINT64_C(0x123456789abcdef0) ^ i;
        state.v[i][1] = UINT64_C(0xfedcba9876543210) ^ ((uint64_t)i << 32);
    }
    state.fpcr = 0x03c00000;
    state.fpsr = 0x0800001f;
    uintptr_t target = (uintptr_t)(ram + page_size);
    if (!strcmp(argv[2], "readonly")) {
        target = (uintptr_t)(ram + 512);
        if (mprotect(ram, page_size, PROT_READ)) return 9;
    } else if (!strcmp(argv[2], "crossing")) {
        unsigned distance = 4;
        if (argc == 6) {
            char *end = NULL;
            errno = 0;
            unsigned long value = strtoul(argv[5], &end, 10);
            if (errno || !end || *end || end == argv[5] ||
                (value != 1 && value != 2 && value != 4 && value != 8 && value != 16) ||
                argv[5][0] < '0' || argv[5][0] > '9') return 14;
            distance = (unsigned)value;
        }
        target -= distance;
    } else if (!strcmp(argv[2], "pair_second") || !strcmp(argv[2], "pair_readonly")) {
        if (argc != 6) return 13;
        int distance = atoi(argv[5]);
        if (distance != 4 && distance != 8 && distance != 16) return 14;
        target -= (unsigned)distance;
        if (!strcmp(argv[2], "pair_readonly")) {
            if (mprotect(ram + page_size, page_size, PROT_READ | PROT_WRITE)) return 15;
            memset(ram + page_size, 0xa5, page_size);
            if (mprotect(ram + page_size, page_size, PROT_READ)) return 16;
            observed_bytes = 2 * page_size;
        }
    } else if (!strcmp(argv[2], "sp_alignment8")) {
        target = (uintptr_t)(ram + 520);
    } else if (!strcmp(argv[2], "sp_alignment")) {
        target = (uintptr_t)(ram + 513);
    } else if (strcmp(argv[2], "guard")) return 10;
    int rn = atoi(argv[3]);
    int pre_offset = atoi(argv[4]);
    uint64_t base = (uint64_t)target - (uint64_t)(int64_t)pre_offset;
    if (!strncmp(argv[2], "sp_alignment", 12)) base = target;
    if (rn == 31) state.sp = base;
    else if (rn >= 0 && rn < 31) state.x[rn] = base;
    else return 11;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = capture;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) || sigaction(SIGBUS, &action, NULL) || sigaction(SIGILL, &action, NULL)) return 12;
    uint64_t header[] = {(uintptr_t)code, (uintptr_t)ram, page_size};
    output(header, sizeof(header));
    output(&state, sizeof(state));
    ((void (*)(struct guest_state *))code)(&state);
    // A missing fault is observable as signal=0, rather than a passing result.
    uint64_t result[] = {0, 0, 0};
    output(result, sizeof(result));
    output(&state, sizeof(state));
    output(ram, observed_bytes);
    return 0;
}
