// M1 AMX transfer observations, isolated to each child's guarded mappings.
// Uses the pinned MIT corsix/amx helpers, Copyright (c) 2022 Peter Cawley;
// see LICENSES/MIT.txt.
static int corsix_unbounded_main(void) __attribute__((unused));
#define main corsix_unbounded_main
#include "test.c"
#undef main
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <unistd.h>

enum { MAX_PAGE = 65536, AMX_BASE = 0x201000, OP_MASK = ~31u };
typedef struct {
    amx_state before, after;
    uint8_t memory_before[MAX_PAGE], memory_after[MAX_PAGE];
    _STRUCT_MCONTEXT64 context;
    uint64_t address, operand, signal_address;
    uint32_t signal, signal_code, instruction, context_bytes, phase, after_valid;
} observation;
static observation* result;
static unsigned selected_op;
enum { PHASE_SETUP, PHASE_TRANSFER, PHASE_CAPTURE, PHASE_DONE };

static void fault(int signo, siginfo_t* info, void* raw_context) {
    ucontext_t* context = raw_context;
    // Only resume the one selected transfer. A setup/capture fault remains an
    // explicit child failure with after_valid=0, never an invented state.
    if (result->phase != PHASE_TRANSFER || result->signal) _exit(128 + signo);
    result->signal = (uint32_t)signo;
    result->signal_code = (uint32_t)info->si_code;
    result->signal_address = (uint64_t)info->si_addr;
    result->context_bytes = sizeof(result->context);
    volatile uint8_t* out = (volatile uint8_t*)&result->context;
    const volatile uint8_t* in = (const volatile uint8_t*)context->uc_mcontext;
    for (size_t i = 0; i < sizeof(result->context); ++i) out[i] = in[i];
    uint64_t pc = context->uc_mcontext->__ss.__pc;
    result->instruction = *(const volatile uint32_t*)pc;
    if ((result->instruction & OP_MASK) != (AMX_BASE + (selected_op << 5)))
        _exit(128 + signo);
    // Resume immediately after the faulting word; ordinary signal return
    // restores the OS's saved state. This observes that OS boundary as well.
    context->uc_mcontext->__ss.__pc = pc + sizeof(uint32_t);
}

static void transfer(unsigned op, uint64_t operand) {
    switch (op) {
    case 0: AMX_LDX(operand); break;
    case 1: AMX_LDY(operand); break;
    case 2: AMX_STX(operand); break;
    case 3: AMX_STY(operand); break;
    case 4: AMX_LDZ(operand); break;
    case 5: AMX_STZ(operand); break;
    case 6: AMX_LDZI(operand); break;
    case 7: AMX_STZI(operand); break;
    default: _exit(2);
    }
}

static int child(unsigned op, uint64_t operand, uint8_t* page, size_t page_bytes, int protection) {
    struct sigaction action = {0};
    action.sa_sigaction = fault;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGBUS, &action, NULL) || sigaction(SIGSEGV, &action, NULL) ||
        sigaction(SIGILL, &action, NULL)) return 2;
    selected_op = op;
    AMX_SET();
    inject_state(&result->before);
    if (mprotect(page, page_bytes, protection)) return 2;
    result->phase = PHASE_TRANSFER;
    __asm__ volatile("" : : : "memory");
    transfer(op, operand);
    __asm__ volatile("" : : : "memory");
    result->phase = PHASE_CAPTURE;
    capture_state(&result->after);
    AMX_CLR();
    result->after_valid = 1;
    if (mprotect(page, page_bytes, PROT_READ | PROT_WRITE)) return 2;
    memcpy(result->memory_after, page, page_bytes);
    result->phase = PHASE_DONE;
    return 0;
}

static const char* names[8] = {"LDX", "LDY", "STX", "STY", "LDZ", "STZ", "LDZI", "STZI"};
static unsigned failures, case_id;
static uint64_t output_offset;
static FILE* output;

static void observe(unsigned op, unsigned multiple, int offset, unsigned position, int protection,
                    uint8_t* page, size_t page_bytes) {
    memset(result, 0, sizeof(*result));
    rand_init();
    rand_fill(&result->before, sizeof(result->before));
    rand_fill(page, page_bytes);
    memcpy(result->memory_before, page, page_bytes);
    uint64_t address = (uint64_t)page + (position == 1 ? page_bytes : 128) + offset;
    if (position == 2) address = (uint64_t)page + offset;
    unsigned row = case_id % 3 == 0 ? 0 : case_id % 3 == 1 ? 7 : 63;
    uint64_t operand = address | ((uint64_t)row << 56) | ((uint64_t)multiple << 62);
    result->address = address;
    result->operand = operand;
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(2); }
    if (pid == 0) _exit(child(op, operand, page, page_bytes, protection));
    int status;
    pid_t waited;
    do { waited = waitpid(pid, &status, 0); } while (waited < 0 && errno == EINTR);
    if (waited < 0) { perror("waitpid"); exit(2); }
    bool complete = WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
        result->phase == PHASE_DONE && result->after_valid;
    if (!complete) ++failures;
    size_t memory_changes = 0, state_changes = 0;
    if (complete) {
        for (size_t i = 0; i < page_bytes; ++i)
            memory_changes += result->memory_before[i] != result->memory_after[i];
        const uint8_t* before = (const uint8_t*)&result->before;
        const uint8_t* after = (const uint8_t*)&result->after;
        for (size_t i = 0; i < sizeof(result->before); ++i) state_changes += before[i] != after[i];
    }
    // Exact payload layout is declared in every JSON record, not inferred from
    // C struct padding: before/after AMX, before/after page, raw fault context.
    size_t bytes = sizeof(result->before) * 2 + page_bytes * 2 + result->context_bytes;
    if (fwrite(&result->before, sizeof(result->before), 1, output) != 1 ||
        fwrite(&result->after, sizeof(result->after), 1, output) != 1 ||
        fwrite(result->memory_before, page_bytes, 1, output) != 1 ||
        fwrite(result->memory_after, page_bytes, 1, output) != 1 ||
        (result->context_bytes && fwrite(&result->context, result->context_bytes, 1, output) != 1)) {
        perror("payload write"); exit(2);
    }
    printf("{\"case\":%u,\"op\":%u,\"name\":\"%s\",\"multiple\":%u,\"row\":%u,"
           "\"offset\":%d,\"position\":%u,\"protection\":%d,\"complete\":%s,"
           "\"wait_status\":%d,\"phase\":%u,\"after_valid\":%u,"
           "\"page\":\"%llx\",\"address\":\"%llx\",\"operand\":\"%llx\","
           "\"signal\":%u,\"signal_code\":%u,\"signal_address\":\"%llx\","
           "\"far\":\"%llx\",\"esr\":%u,\"exception\":%u,\"word\":%u,"
           "\"memory_changes\":%zu,\"state_changes\":%zu,\"payload_offset\":%llu,"
           "\"payload_bytes\":%zu,\"amx_bytes\":%zu,\"page_bytes\":%zu,\"context_bytes\":%u}\n",
           case_id++, op, names[op], multiple, row, offset, position, protection,
           complete ? "true" : "false", status, result->phase, result->after_valid,
           (unsigned long long)page, (unsigned long long)address, (unsigned long long)operand,
           result->signal, result->signal_code, (unsigned long long)result->signal_address,
           (unsigned long long)result->context.__es.__far, result->context.__es.__esr,
           result->context.__es.__exception, result->instruction, memory_changes, state_changes,
           (unsigned long long)output_offset, bytes, sizeof(result->before), page_bytes,
           result->context_bytes);
    output_offset += bytes;
}

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: native-transfers OUTPUT.bin\n"); return 2; }
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 128 || page_size > MAX_PAGE) return 2;
    size_t page_bytes = (size_t)page_size;
    uint8_t* mapping = mmap(NULL, page_bytes * 3, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    result = mmap(NULL, sizeof(*result), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    if (mapping == MAP_FAILED || result == MAP_FAILED) return 2;
    uint8_t* page = mapping + page_bytes;
    if (mprotect(page, page_bytes, PROT_READ | PROT_WRITE)) return 2;
    output = fopen(argv[1], "wbx");
    if (!output) { perror("output"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    for (unsigned op = 0; op < 8; ++op) {
        for (unsigned multiple = 0; multiple < 2; ++multiple) {
            for (int offset = 0; offset < 128; ++offset)
                observe(op, multiple, offset, 0, PROT_READ | PROT_WRITE, page, page_bytes);
            const int tails[] = {0, -1, -31, -32, -63, -64, -65, -127, -128};
            for (size_t i = 0; i < sizeof(tails) / sizeof(tails[0]); ++i)
                observe(op, multiple, tails[i], 1, PROT_READ | PROT_WRITE, page, page_bytes);
            observe(op, multiple, -1, 2, PROT_READ | PROT_WRITE, page, page_bytes);
            observe(op, multiple, -64, 2, PROT_READ | PROT_WRITE, page, page_bytes);
            observe(op, multiple, 0, 0, PROT_READ, page, page_bytes);
            observe(op, multiple, 0, 0, PROT_NONE, page, page_bytes);
        }
    }
    if (fclose(output)) return 2;
    munmap(mapping, page_bytes * 3);
    munmap(result, sizeof(*result));
    return failures ? 1 : 0;
}
