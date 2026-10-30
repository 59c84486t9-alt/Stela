/*
 * The kext's runtime: the kmod_info its prelink entry names, and the
 * static-destructor registration clang's Darwin code generation calls.
 *
 * Loading runs the kext's C++ constructors, which register its classes and
 * each object's destructor through __cxa_atexit; unloading runs its
 * __mod_term_func, which runs those destructors in reverse. Apple's kext
 * toolchain emits the destructors as term funcs directly; upstream clang
 * always registers them, so the kext keeps the registrations itself.
 * The build passes the identifier and version from Info.plist.
 */
#include <mach/kmod.h>

namespace {

struct Destructor {
	void (*function)(void *);
	void *object;
};

/* More than the kext's static objects with destructors. */
Destructor destructors[16];
unsigned destructorCount;

void
runDestructors()
{
	while (destructorCount > 0) {
		Destructor destructor = destructors[--destructorCount];
		destructor.function(destructor.object);
	}
}

__attribute__((section("__DATA,__mod_term_func,mod_term_funcs"), used))
void (*const termination)() = runDestructors;

kern_return_t
start(kmod_info_t *, void *)
{
	return KERN_SUCCESS;
}

kern_return_t
stop(kmod_info_t *, void *)
{
	return KERN_SUCCESS;
}

} // namespace

extern "C" {
/* The kext's image handle; registrations name it but one kext has one. */
char __dso_handle;

/* Runs only during load, from the constructors, which the kernel serializes. */
int
__cxa_atexit(void (*function)(void *), void *object, void *)
{
	if (destructorCount == sizeof(destructors) / sizeof(destructors[0])) {
		return -1;
	}
	destructors[destructorCount++] = {function, object};
	return 0;
}

kmod_info_t KMOD_INFO_NAME = {
	.next = nullptr,
	.info_version = KMOD_INFO_VERSION,
	.id = UINT32_MAX,
	.name = STELA_KEXT_IDENTIFIER,
	.version = STELA_KEXT_VERSION,
	.reference_count = -1,
	.reference_list = nullptr,
	.address = 0,
	.size = 0,
	.hdr_size = 0,
	.start = start,
	.stop = stop,
};
}
