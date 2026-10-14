/* Native fault observer for emitted code. Test-only; no guest fault handler. */
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#define _DARWIN_C_SOURCE
#include <errno.h>
#ifdef STELA_ATOMIC_CONCURRENCY
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#endif
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
enum { MAX_STRUCTURE_TRANSFER_BYTES = 64 };

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


#ifdef STELA_ATOMIC_CONCURRENCY
/* Fixed atomic evidence cases; no production runtime or arbitrary scheduler. */
enum { ATOMIC_RAM_BYTES = 8192, ATOMIC_MAX_THREADS = 4, ATOMIC_MAX_ITERATIONS = 256,
       ATOMIC_HISTORY = 0, ATOMIC_TICKETS = 1, ATOMIC_CAS = 2, ATOMIC_SWAP = 3,
       ATOMIC_LITMUS = 4, ATOMIC_ATTEMPTS_PER_INCREMENT = 32,
       ATOMIC_SCALAR_MAX_BYTES = sizeof(uint64_t), ATOMIC_PAIR_BYTES = 2 * sizeof(uint64_t),
       BITS_PER_BYTE = 8 };
#define ATOMIC_PLAN_MAGIC UINT64_C(0x314e414c504d5441)
#define ATOMIC_RESULT_MAGIC UINT64_C(0x31544c53524d5441)
struct atomic_plan {
    uint64_t magic;
    uint32_t kind, threads, iterations, entries, width, flags;
    uint64_t offsets[ATOMIC_MAX_THREADS];
    struct guest_state initial[ATOMIC_MAX_THREADS];
    unsigned char memory[ATOMIC_RAM_BYTES];
};
_Static_assert(offsetof(struct atomic_plan, initial) == 64, "Atomic plan framing");
struct atomic_record {
    uint64_t thread, iteration, begin, end;
    struct guest_state initial, final;
};
_Static_assert(sizeof(struct atomic_record) == 1600, "Atomic record framing");
struct atomic_context {
    struct atomic_plan plan;
    unsigned char *code, *alias;
    struct guest_state states[ATOMIC_MAX_THREADS];
    struct atomic_record *records;
    unsigned char *snapshots;
    size_t capacity, used[ATOMIC_MAX_THREADS];
    atomic_uint start, done[ATOMIC_MAX_THREADS], failed;
    atomic_uint_fast64_t sequence;
};
struct atomic_worker_argument { struct atomic_context *context; unsigned thread; };

static void atomic_reset_state(struct atomic_context *context, unsigned thread) {
    context->states[thread] = context->plan.initial[thread];
    uintptr_t address = (uintptr_t)(((context->plan.flags & 1) && (thread & 1)) ? context->alias : ram);
    /* All fixed test programs reserve X5/X6 as data bases. */
    context->states[thread].x[5] += address;
    context->states[thread].x[6] += address;
}

static void *atomic_worker(void *opaque) {
    struct atomic_worker_argument *argument = opaque;
    struct atomic_context *context = argument->context;
    unsigned thread = argument->thread;
    struct guest_state *current = &context->states[thread];
    void (*function)(struct guest_state *) = (void (*)(struct guest_state *))(context->code + context->plan.offsets[thread]);
    /* Only scalar CAS counters consume this mask. Pair histories can use 128 bits;
       never shift a 64-bit value by their width, even on that unused path. */
    uint64_t mask = context->plan.width < ATOMIC_SCALAR_MAX_BYTES ? (UINT64_C(1) << (context->plan.width * BITS_PER_BYTE)) - 1 : UINT64_MAX;
    size_t calls = 0;
    for (unsigned iteration = 0; iteration < context->plan.iterations; iteration++) {
        unsigned gate = context->plan.kind == ATOMIC_LITMUS ? iteration + 1 : 1;
        while (atomic_load_explicit(&context->start, memory_order_acquire) != gate) sched_yield();
        unsigned attempt = 0;
        for (;;) {
            if (calls >= context->capacity || attempt++ == ATOMIC_ATTEMPTS_PER_INCREMENT) {
                atomic_store(&context->failed, 1);
                goto finished;
            }
            if (context->plan.kind == ATOMIC_CAS) current->x[1] = (current->x[0] + 1) & mask;
            struct atomic_record *record = &context->records[thread * context->capacity + calls++];
            record->thread = thread;
            record->iteration = iteration;
            record->initial = *current;
            record->begin = atomic_fetch_add(&context->sequence, 1);
            function(current);
            record->end = atomic_fetch_add(&context->sequence, 1);
            record->final = *current;
            if (context->plan.kind == ATOMIC_SWAP) current->x[0] = current->x[1];
            if (context->plan.kind != ATOMIC_CAS || current->x[0] == record->initial.x[0]) break;
        }
        if (context->plan.kind == ATOMIC_CAS) current->x[0] = current->x[1];
        if (context->plan.kind == ATOMIC_LITMUS) atomic_store_explicit(&context->done[thread], iteration + 1, memory_order_release);
    }
finished:
    context->used[thread] = calls;
    if (context->plan.kind != ATOMIC_LITMUS || atomic_load(&context->failed))
        atomic_store_explicit(&context->done[thread], context->plan.iterations, memory_order_release);
    return NULL;
}

static int atomic_concurrency(const char *native_path, const char *plan_path) {
    struct atomic_context *context = calloc(1, sizeof(*context));
    if (!context) return 30;
    FILE *file = fopen(plan_path, "rb");
    if (!file || fread(&context->plan, 1, sizeof(context->plan), file) != sizeof(context->plan) || fgetc(file) != EOF) return 31;
    fclose(file);
    struct atomic_plan *plan = &context->plan;
    if (plan->magic != ATOMIC_PLAN_MAGIC || plan->kind > ATOMIC_LITMUS || plan->threads < 2 || plan->threads > ATOMIC_MAX_THREADS ||
        plan->entries != plan->threads || !plan->iterations || plan->iterations > ATOMIC_MAX_ITERATIONS || plan->flags > 1 ||
        (plan->width != 1 && plan->width != 2 && plan->width != 4 && plan->width != 8 &&
         !(plan->width == ATOMIC_PAIR_BYTES && plan->kind == ATOMIC_HISTORY)) ||
        (plan->kind == ATOMIC_HISTORY && plan->iterations * plan->threads > 16)) return 32;
    file = fopen(native_path, "rb");
    if (!file || fseek(file, 0, SEEK_END)) return 33;
    long length = ftell(file);
    if (length <= 0 || fseek(file, 0, SEEK_SET)) return 34;
    context->code = mmap(NULL, (size_t)length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (context->code == MAP_FAILED || fread(context->code, 1, (size_t)length, file) != (size_t)length) return 35;
    fclose(file);
    if (mprotect(context->code, (size_t)length, PROT_READ | PROT_EXEC)) return 36;
    for (unsigned thread = 0; thread < plan->threads; thread++) if (plan->offsets[thread] >= (uint64_t)length) return 37;
    char backing[] = "/tmp/stela-atomic-XXXXXX";
    int descriptor = mkstemp(backing);
    if (descriptor < 0) return 38;
    if (unlink(backing) || ftruncate(descriptor, ATOMIC_RAM_BYTES)) return 39;
    ram = mmap(NULL, ATOMIC_RAM_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
    context->alias = mmap(NULL, ATOMIC_RAM_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
    close(descriptor);
    if (ram == MAP_FAILED || context->alias == MAP_FAILED) return 40;
    context->capacity = plan->iterations * (plan->kind == ATOMIC_CAS ? ATOMIC_ATTEMPTS_PER_INCREMENT : 1);
    context->records = calloc(plan->threads * context->capacity, sizeof(*context->records));
    size_t snapshots = plan->kind == ATOMIC_LITMUS ? plan->iterations : 1;
    context->snapshots = malloc(snapshots * ATOMIC_RAM_BYTES);
    if (!context->records || !context->snapshots) return 41;
    atomic_init(&context->start, 0);
    atomic_init(&context->failed, 0);
    atomic_init(&context->sequence, 0);
    for (unsigned thread = 0; thread < plan->threads; thread++) atomic_init(&context->done[thread], 0);
    memcpy(ram, plan->memory, ATOMIC_RAM_BYTES);
    pthread_t threads[ATOMIC_MAX_THREADS];
    struct atomic_worker_argument arguments[ATOMIC_MAX_THREADS];
    for (unsigned thread = 0; thread < plan->threads; thread++) {
        atomic_reset_state(context, thread);
        arguments[thread] = (struct atomic_worker_argument){context, thread};
        if (pthread_create(&threads[thread], NULL, atomic_worker, &arguments[thread])) return 42;
    }
    if (plan->kind == ATOMIC_LITMUS) {
        for (unsigned iteration = 0; iteration < plan->iterations; iteration++) {
            memcpy(ram, plan->memory, ATOMIC_RAM_BYTES);
            for (unsigned thread = 0; thread < plan->threads; thread++) atomic_reset_state(context, thread);
            atomic_store_explicit(&context->start, iteration + 1, memory_order_release);
            for (unsigned thread = 0; thread < plan->threads; thread++)
                while (atomic_load_explicit(&context->done[thread], memory_order_acquire) != iteration + 1) sched_yield();
            memcpy(context->snapshots + iteration * ATOMIC_RAM_BYTES, ram, ATOMIC_RAM_BYTES);
        }
    } else atomic_store_explicit(&context->start, 1, memory_order_release);
    for (unsigned thread = 0; thread < plan->threads; thread++) if (pthread_join(threads[thread], NULL)) return 43;
    if (plan->kind != ATOMIC_LITMUS) memcpy(context->snapshots, ram, ATOMIC_RAM_BYTES);
    size_t records = 0;
    for (unsigned thread = 0; thread < plan->threads; thread++) records += context->used[thread];
    uint64_t header[] = {ATOMIC_RESULT_MAGIC, (uintptr_t)context->code, (uintptr_t)ram, (uintptr_t)context->alias,
                         plan->threads, plan->iterations, records, snapshots, atomic_load(&context->failed)};
    output(header, sizeof(header));
    for (unsigned thread = 0; thread < plan->threads; thread++)
        output(context->records + thread * context->capacity, context->used[thread] * sizeof(*context->records));
    output(context->states, plan->threads * sizeof(struct guest_state));
    output(context->snapshots, snapshots * ATOMIC_RAM_BYTES);
    return atomic_load(&context->failed) ? 44 : 0;
}

#endif

int main(int argc, char **argv) {
#ifdef STELA_ATOMIC_CONCURRENCY
    if (argc == 4 && !strcmp(argv[1], "--atomic-concurrency")) return atomic_concurrency(argv[2], argv[3]);
#endif
    const char *initial_state_path = NULL;
    if (argc >= 3 && !strcmp(argv[argc - 2], "--initial-state")) { initial_state_path = argv[argc - 1]; argc -= 2; }
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
    if (initial_state_path) {
        FILE *initial_file = fopen(initial_state_path, "rb");
        if (!initial_file || fread(&state, 1, sizeof(state), initial_file) != sizeof(state) || fgetc(initial_file) != EOF) return 19;
        fclose(initial_file);
    }
    uintptr_t target = (uintptr_t)(ram + page_size);
    if (!strcmp(argv[2], "readonly")) {
        target = (uintptr_t)(ram + 512);
        if (mprotect(ram, page_size, PROT_READ)) return 9;
    } else if (!strcmp(argv[2], "mapped")) {
        if (argc != 6) return 13;
        char *end = NULL;
        errno = 0;
        unsigned long offset = strtoul(argv[5], &end, 10);
        if (errno || !end || *end || end == argv[5] || offset > 15 || argv[5][0] < '0' || argv[5][0] > '9') return 14;
        target = (uintptr_t)(ram + 512 + offset);
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
    } else if (!strcmp(argv[2], "structure_crossing")) {
        if (argc != 6) return 13;
        char *end = NULL;
        errno = 0;
        unsigned long distance = strtoul(argv[5], &end, 10);
        if (errno || !end || *end || end == argv[5] || distance < 1 || distance > MAX_STRUCTURE_TRANSFER_BYTES ||
            argv[5][0] < '0' || argv[5][0] > '9') return 14;
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
