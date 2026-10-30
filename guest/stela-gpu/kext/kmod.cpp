/*
 * The kext's kmod_info, which its prelink entry names. Loading runs its C++
 * constructors and registers its classes; there is nothing else to start.
 * The build passes the identifier and version from Info.plist.
 */
#include <mach/kmod.h>

extern "C" {
static kern_return_t
start(kmod_info_t *, void *)
{
	return KERN_SUCCESS;
}

static kern_return_t
stop(kmod_info_t *, void *)
{
	return KERN_SUCCESS;
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
