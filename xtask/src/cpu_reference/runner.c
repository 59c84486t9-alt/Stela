/*
 * CPU reference runner for `cargo xtask cpu-reference`: runs each case's
 * A64 words at EL0 on Apple silicon (macOS, arm64) and reports the final
 * architectural state.
 *
 * Input (stdin) and output (stdout) are fixed little-endian records whose
 * layout `xtask/src/cpu_reference/record.rs` shares. Each case's words go
 * into a MAP_JIT page between a prologue that loads X0-X30, NZCV, FPCR, FPSR
 * and V0-V31 from the record and an epilogue that stores them back. The
 * words must not touch SP or branch outside themselves. Registers named by
 * the case's memory mask hold offsets into the case's 256-byte buffer: the
 * runner adds the buffer's address before the run and subtracts it after.
 * A signal (SIGILL, SIGBUS, SIGSEGV, SIGFPE, SIGTRAP) ends the case with its
 * number, si_code, fault address and PC offset; the state is then the input.
 */
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum { WORDS = 32, MEMORY = 256, PAGE = 16384 };

struct state {
    uint64_t x[31];
    uint64_t nzcv;
    uint64_t fpcr;
    uint64_t fpsr;
    uint64_t v[32][2];
};

struct input {
    uint32_t count;
    uint32_t memory_registers;
    uint32_t words[WORDS];
    uint64_t pad;
    struct state state;
    uint8_t memory[MEMORY];
};

struct output {
    struct state state;
    uint8_t memory[MEMORY];
    int32_t signal;
    int32_t code;
    uint64_t fault_address;
    uint64_t fault_pc;
};

_Static_assert(sizeof(struct state) == 784, "state layout");
_Static_assert(sizeof(struct input) == 1184, "input layout");
_Static_assert(sizeof(struct output) == 1064, "output layout");
_Static_assert(__builtin_offsetof(struct state, v) == 272, "vector offset");

/* Position-independent stubs, copied around each case's words. */
extern const uint32_t stela_prologue[], stela_prologue_end[];
extern const uint32_t stela_epilogue[], stela_epilogue_end[];
__asm__(
    ".text\n.p2align 2\n.globl _stela_prologue\n_stela_prologue:\n"
    "sub sp, sp, #0xc0\n"
    "stp x19, x20, [sp, #0x00]\nstp x21, x22, [sp, #0x10]\n"
    "stp x23, x24, [sp, #0x20]\nstp x25, x26, [sp, #0x30]\n"
    "stp x27, x28, [sp, #0x40]\nstp x29, x30, [sp, #0x50]\n"
    "stp d8, d9, [sp, #0x60]\nstp d10, d11, [sp, #0x70]\n"
    "stp d12, d13, [sp, #0x80]\nstp d14, d15, [sp, #0x90]\n"
    "str x0, [sp, #0xa0]\n"
    "ldr x1, [x0, #256]\nmsr fpcr, x1\n"
    "ldr x1, [x0, #264]\nmsr fpsr, x1\n"
    "ldr x1, [x0, #248]\nmsr nzcv, x1\n"
    "add x1, x0, #272\n"
    "ldp q0, q1, [x1, #0]\nldp q2, q3, [x1, #32]\nldp q4, q5, [x1, #64]\n"
    "ldp q6, q7, [x1, #96]\nldp q8, q9, [x1, #128]\nldp q10, q11, [x1, #160]\n"
    "ldp q12, q13, [x1, #192]\nldp q14, q15, [x1, #224]\nldp q16, q17, [x1, #256]\n"
    "ldp q18, q19, [x1, #288]\nldp q20, q21, [x1, #320]\nldp q22, q23, [x1, #352]\n"
    "ldp q24, q25, [x1, #384]\nldp q26, q27, [x1, #416]\nldp q28, q29, [x1, #448]\n"
    "ldp q30, q31, [x1, #480]\n"
    "ldp x1, x2, [x0, #8]\nldp x3, x4, [x0, #24]\nldp x5, x6, [x0, #40]\n"
    "ldp x7, x8, [x0, #56]\nldp x9, x10, [x0, #72]\nldp x11, x12, [x0, #88]\n"
    "ldp x13, x14, [x0, #104]\nldp x15, x16, [x0, #120]\nldp x17, x18, [x0, #136]\n"
    "ldp x19, x20, [x0, #152]\nldp x21, x22, [x0, #168]\nldp x23, x24, [x0, #184]\n"
    "ldp x25, x26, [x0, #200]\nldp x27, x28, [x0, #216]\nldp x29, x30, [x0, #232]\n"
    "ldr x0, [x0]\n"
    ".globl _stela_prologue_end\n_stela_prologue_end:\n"
    ".globl _stela_epilogue\n_stela_epilogue:\n"
    "str x0, [sp, #-16]!\n"
    "ldr x0, [sp, #0xb0]\n"
    "stp x1, x2, [x0, #8]\nstp x3, x4, [x0, #24]\nstp x5, x6, [x0, #40]\n"
    "stp x7, x8, [x0, #56]\nstp x9, x10, [x0, #72]\nstp x11, x12, [x0, #88]\n"
    "stp x13, x14, [x0, #104]\nstp x15, x16, [x0, #120]\nstp x17, x18, [x0, #136]\n"
    "stp x19, x20, [x0, #152]\nstp x21, x22, [x0, #168]\nstp x23, x24, [x0, #184]\n"
    "stp x25, x26, [x0, #200]\nstp x27, x28, [x0, #216]\nstp x29, x30, [x0, #232]\n"
    "mrs x1, nzcv\nstr x1, [x0, #248]\n"
    "mrs x1, fpcr\nstr x1, [x0, #256]\n"
    "mrs x1, fpsr\nstr x1, [x0, #264]\n"
    "add x1, x0, #272\n"
    "stp q0, q1, [x1, #0]\nstp q2, q3, [x1, #32]\nstp q4, q5, [x1, #64]\n"
    "stp q6, q7, [x1, #96]\nstp q8, q9, [x1, #128]\nstp q10, q11, [x1, #160]\n"
    "stp q12, q13, [x1, #192]\nstp q14, q15, [x1, #224]\nstp q16, q17, [x1, #256]\n"
    "stp q18, q19, [x1, #288]\nstp q20, q21, [x1, #320]\nstp q22, q23, [x1, #352]\n"
    "stp q24, q25, [x1, #384]\nstp q26, q27, [x1, #416]\nstp q28, q29, [x1, #448]\n"
    "stp q30, q31, [x1, #480]\n"
    "ldr x1, [sp], #16\nstr x1, [x0]\n"
    "msr fpcr, xzr\nmsr fpsr, xzr\n"
    "ldp x19, x20, [sp, #0x00]\nldp x21, x22, [sp, #0x10]\n"
    "ldp x23, x24, [sp, #0x20]\nldp x25, x26, [sp, #0x30]\n"
    "ldp x27, x28, [sp, #0x40]\nldp x29, x30, [sp, #0x50]\n"
    "ldp d8, d9, [sp, #0x60]\nldp d10, d11, [sp, #0x70]\n"
    "ldp d12, d13, [sp, #0x80]\nldp d14, d15, [sp, #0x90]\n"
    "add sp, sp, #0xc0\nret\n"
    ".globl _stela_epilogue_end\n_stela_epilogue_end:\n");

static sigjmp_buf recovery;
static volatile sig_atomic_t caught;
static volatile int32_t caught_code;
static volatile uint64_t caught_address, caught_pc;

static void handler(int signal, siginfo_t *info, void *context) {
    ucontext_t *user = context;
    caught = signal;
    caught_code = info->si_code;
    caught_address = (uint64_t)info->si_addr;
    caught_pc = user->uc_mcontext->__ss.__pc;
    siglongjmp(recovery, 1);
}

static int read_all(void *buffer, size_t bytes) {
    uint8_t *cursor = buffer;
    while (bytes) {
        ssize_t got = read(0, cursor, bytes);
        if (got <= 0)
            return got == 0 && cursor == buffer ? 0 : -1;
        cursor += got;
        bytes -= (size_t)got;
    }
    return 1;
}

static void write_all(const void *buffer, size_t bytes) {
    const uint8_t *cursor = buffer;
    while (bytes) {
        ssize_t put = write(1, cursor, bytes);
        if (put <= 0)
            exit(2);
        cursor += put;
        bytes -= (size_t)put;
    }
}

int main(void) {
    uint32_t *page = mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (page == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    struct sigaction action = {0};
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO | SA_NODEFER;
    int signals[] = {SIGILL, SIGBUS, SIGSEGV, SIGFPE, SIGTRAP};
    for (size_t i = 0; i < sizeof signals / sizeof *signals; i++)
        sigaction(signals[i], &action, NULL);
    size_t prologue = (size_t)(stela_prologue_end - stela_prologue);
    size_t epilogue = (size_t)(stela_epilogue_end - stela_epilogue);
    static uint8_t memory[MEMORY] __attribute__((aligned(64)));
    struct input in;
    int status;
    while ((status = read_all(&in, sizeof in)) == 1) {
        if (in.count > WORDS)
            return 3;
        pthread_jit_write_protect_np(0);
        memcpy(page, stela_prologue, prologue * 4);
        memcpy(page + prologue, in.words, in.count * 4);
        memcpy(page + prologue + in.count, stela_epilogue, epilogue * 4);
        pthread_jit_write_protect_np(1);
        sys_icache_invalidate(page, (prologue + in.count + epilogue) * 4);
        struct output out = {0};
        struct state state = in.state;
        memcpy(memory, in.memory, MEMORY);
        for (int r = 0; r < 31; r++)
            if (in.memory_registers >> r & 1)
                state.x[r] += (uint64_t)memory;
        caught = 0;
        if (sigsetjmp(recovery, 1) == 0) {
            ((void (*)(struct state *))page)(&state);
            for (int r = 0; r < 31; r++)
                if (in.memory_registers >> r & 1)
                    state.x[r] -= (uint64_t)memory;
            out.state = state;
        } else {
            __asm__ volatile("msr fpcr, xzr\nmsr fpsr, xzr");
            out.state = in.state;
            out.signal = caught;
            out.code = caught_code;
            out.fault_address = caught_address - (uint64_t)memory;
            out.fault_pc = caught_pc - (uint64_t)(page + prologue);
        }
        memcpy(out.memory, memory, MEMORY);
        write_all(&out, sizeof out);
    }
    return status == 0 ? 0 : 4;
}
