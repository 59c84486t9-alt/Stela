// SPDX-License-Identifier: MIT
/* libdrm, as far as NVK reaches it: thin wrappers of DRM's ioctls, with the
 * entry points of xf86drm.h. Devices come from the host, not from /sys. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <stela/host.h>
#include <xf86drm.h>

#define DRM_MAJOR 226
#define RENDER_MINOR 128

int drmIoctl(int fd, unsigned long request, void *argument)
{
	int result;
	do {
		result = ioctl(fd, request, argument);
	} while (result == -1 && (errno == EINTR || errno == EAGAIN));
	return result;
}

int drmCommandWrite(int fd, unsigned long index, void *data, unsigned long size)
{
	return drmIoctl(fd, DRM_IOW(DRM_COMMAND_BASE + index, char[size]), data) ? -errno : 0;
}

int drmCommandRead(int fd, unsigned long index, void *data, unsigned long size)
{
	return drmIoctl(fd, DRM_IOR(DRM_COMMAND_BASE + index, char[size]), data) ? -errno : 0;
}

int drmCommandWriteRead(int fd, unsigned long index, void *data, unsigned long size)
{
	return drmIoctl(fd, DRM_IOWR(DRM_COMMAND_BASE + index, char[size]), data) ? -errno : 0;
}

int drmGetCap(int fd, uint64_t capability, uint64_t *value)
{
	struct drm_get_cap cap = {.capability = capability};
	int result = drmIoctl(fd, DRM_IOCTL_GET_CAP, &cap);
	if (result)
		return result;
	*value = cap.value;
	return 0;
}

int drmCloseBufferHandle(int fd, uint32_t handle)
{
	struct drm_gem_close close = {.handle = handle};
	return drmIoctl(fd, DRM_IOCTL_GEM_CLOSE, &close);
}

int drmPrimeHandleToFD(int fd, uint32_t handle, uint32_t flags, int *prime_fd)
{
	struct drm_prime_handle prime = {.handle = handle, .flags = flags, .fd = -1};
	int result = drmIoctl(fd, DRM_IOCTL_PRIME_HANDLE_TO_FD, &prime);
	if (result)
		return result;
	*prime_fd = prime.fd;
	return 0;
}

int drmPrimeFDToHandle(int fd, int prime_fd, uint32_t *handle)
{
	struct drm_prime_handle prime = {.fd = prime_fd};
	int result = drmIoctl(fd, DRM_IOCTL_PRIME_FD_TO_HANDLE, &prime);
	if (result)
		return result;
	*handle = prime.handle;
	return 0;
}

/* One string of a version, which the kernel fills after reporting its size. */
static char *version_string(size_t size)
{
	return calloc(size + 1, 1);
}

drmVersionPtr drmGetVersion(int fd)
{
	struct drm_version sizes = {0};
	if (drmIoctl(fd, DRM_IOCTL_VERSION, &sizes))
		return NULL;
	struct drm_version version = sizes;
	drmVersionPtr result = calloc(1, sizeof(*result));
	if (!result)
		return NULL;
	version.name = result->name = version_string(sizes.name_len);
	version.date = result->date = version_string(sizes.date_len);
	version.desc = result->desc = version_string(sizes.desc_len);
	if (!result->name || !result->date || !result->desc ||
	    drmIoctl(fd, DRM_IOCTL_VERSION, &version)) {
		drmFreeVersion(result);
		return NULL;
	}
	result->version_major = version.version_major;
	result->version_minor = version.version_minor;
	result->version_patchlevel = version.version_patchlevel;
	result->name_len = (int)version.name_len;
	result->date_len = (int)version.date_len;
	result->desc_len = (int)version.desc_len;
	return result;
}

void drmFreeVersion(drmVersionPtr version)
{
	if (!version)
		return;
	free(version->name);
	free(version->date);
	free(version->desc);
	free(version);
}

/* A device with its nodes, its strings and its PCI records in one block. */
struct device_block {
	drmDevice device;
	char *nodes[DRM_NODE_MAX];
	drmPciBusInfo bus;
	drmPciDeviceInfo info;
	char render[32];
};

static drmDevicePtr device_at(unsigned int index)
{
	struct stela_libc_drm_device host;
	struct device_block *block = calloc(1, sizeof(*block));
	if (!block)
		return NULL;
	stela_libc_drm_device(index, &host);
	snprintf(block->render, sizeof(block->render), DRM_DIR_NAME "/renderD%u",
		 RENDER_MINOR + index);
	block->nodes[DRM_NODE_RENDER] = block->render;
	block->bus = (drmPciBusInfo){
		.domain = host.segment,
		.bus = host.bus,
		.dev = host.slot,
		.func = host.function,
	};
	block->info = (drmPciDeviceInfo){
		.vendor_id = host.vendor,
		.device_id = host.device,
		.subvendor_id = host.subsystem_vendor,
		.subdevice_id = host.subsystem_device,
		.revision_id = host.revision,
	};
	block->device = (drmDevice){
		.nodes = block->nodes,
		.available_nodes = 1 << DRM_NODE_RENDER,
		.bustype = DRM_BUS_PCI,
		.businfo.pci = &block->bus,
		.deviceinfo.pci = &block->info,
	};
	return &block->device;
}

char *drmGetDeviceNameFromFd2(int fd)
{
	(void)fd;
	return NULL;
}

int drmGetDevices2(uint32_t flags, drmDevicePtr devices[], int max)
{
	(void)flags;
	int count = (int)stela_libc_drm_devices();
	if (!devices)
		return count;
	if (count > max)
		count = max;
	for (int index = 0; index < count; index++) {
		devices[index] = device_at((unsigned int)index);
		if (!devices[index]) {
			drmFreeDevices(devices, index);
			return -ENOMEM;
		}
	}
	return count;
}

int drmGetDeviceFromDevId(dev_t id, uint32_t flags, drmDevicePtr *device)
{
	(void)flags;
	unsigned int index = minor(id) - RENDER_MINOR;
	if (major(id) != DRM_MAJOR || index >= stela_libc_drm_devices())
		return -ENODEV;
	*device = device_at(index);
	return *device ? 0 : -ENOMEM;
}

int drmGetDevice2(int fd, uint32_t flags, drmDevicePtr *device)
{
	struct stat status;
	if (fstat(fd, &status))
		return -errno;
	return drmGetDeviceFromDevId(status.st_rdev, flags, device);
}

void drmFreeDevice(drmDevicePtr *device)
{
	if (device && *device) {
		free(*device);
		*device = NULL;
	}
}

void drmFreeDevices(drmDevicePtr devices[], int count)
{
	for (int index = 0; index < count; index++)
		drmFreeDevice(&devices[index]);
}

int drmDevicesEqual(drmDevicePtr a, drmDevicePtr b)
{
	return a->bustype == b->bustype && !memcmp(a->businfo.pci, b->businfo.pci, sizeof(drmPciBusInfo));
}

int drmSyncobjCreate(int fd, uint32_t flags, uint32_t *handle)
{
	struct drm_syncobj_create create = {.flags = flags};
	int result = drmIoctl(fd, DRM_IOCTL_SYNCOBJ_CREATE, &create);
	if (result)
		return result;
	*handle = create.handle;
	return 0;
}

int drmSyncobjDestroy(int fd, uint32_t handle)
{
	struct drm_syncobj_destroy destroy = {.handle = handle};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_DESTROY, &destroy);
}

static int syncobj_to_fd(int fd, uint32_t handle, uint32_t flags, int *result)
{
	struct drm_syncobj_handle convert = {.handle = handle, .flags = flags, .fd = -1};
	int status = drmIoctl(fd, DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD, &convert);
	if (status)
		return status;
	*result = convert.fd;
	return 0;
}

int drmSyncobjHandleToFD(int fd, uint32_t handle, int *object)
{
	return syncobj_to_fd(fd, handle, 0, object);
}

int drmSyncobjExportSyncFile(int fd, uint32_t handle, int *sync_file)
{
	return syncobj_to_fd(fd, handle, DRM_SYNCOBJ_HANDLE_TO_FD_FLAGS_EXPORT_SYNC_FILE, sync_file);
}

int drmSyncobjFDToHandle(int fd, int object, uint32_t *handle)
{
	struct drm_syncobj_handle convert = {.fd = object};
	int status = drmIoctl(fd, DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &convert);
	if (status)
		return status;
	*handle = convert.handle;
	return 0;
}

int drmSyncobjImportSyncFile(int fd, uint32_t handle, int sync_file)
{
	struct drm_syncobj_handle convert = {
		.handle = handle,
		.fd = sync_file,
		.flags = DRM_SYNCOBJ_FD_TO_HANDLE_FLAGS_IMPORT_SYNC_FILE,
	};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE, &convert);
}

int drmSyncobjWait(int fd, uint32_t *handles, unsigned count, int64_t timeout_ns, unsigned flags,
		   uint32_t *first_signaled)
{
	struct drm_syncobj_wait wait = {
		.handles = (uintptr_t)handles,
		.timeout_nsec = timeout_ns,
		.count_handles = count,
		.flags = flags,
	};
	int result = drmIoctl(fd, DRM_IOCTL_SYNCOBJ_WAIT, &wait);
	if (result < 0)
		return -errno;
	if (first_signaled)
		*first_signaled = wait.first_signaled;
	return result;
}

int drmSyncobjTimelineWait(int fd, uint32_t *handles, uint64_t *points, unsigned count,
			   int64_t timeout_ns, unsigned flags, uint32_t *first_signaled)
{
	struct drm_syncobj_timeline_wait wait = {
		.handles = (uintptr_t)handles,
		.points = (uintptr_t)points,
		.timeout_nsec = timeout_ns,
		.count_handles = count,
		.flags = flags,
	};
	int result = drmIoctl(fd, DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT, &wait);
	if (result < 0)
		return -errno;
	if (first_signaled)
		*first_signaled = wait.first_signaled;
	return result;
}

int drmSyncobjReset(int fd, const uint32_t *handles, uint32_t count)
{
	struct drm_syncobj_array array = {.handles = (uintptr_t)handles, .count_handles = count};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_RESET, &array);
}

int drmSyncobjSignal(int fd, const uint32_t *handles, uint32_t count)
{
	struct drm_syncobj_array array = {.handles = (uintptr_t)handles, .count_handles = count};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_SIGNAL, &array);
}

int drmSyncobjTimelineSignal(int fd, const uint32_t *handles, uint64_t *points, uint32_t count)
{
	struct drm_syncobj_timeline_array array = {
		.handles = (uintptr_t)handles,
		.points = (uintptr_t)points,
		.count_handles = count,
	};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL, &array);
}

int drmSyncobjQuery2(int fd, uint32_t *handles, uint64_t *points, uint32_t count, uint32_t flags)
{
	struct drm_syncobj_timeline_array array = {
		.handles = (uintptr_t)handles,
		.points = (uintptr_t)points,
		.count_handles = count,
		.flags = flags,
	};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_QUERY, &array);
}

int drmSyncobjTransfer(int fd, uint32_t destination, uint64_t destination_point, uint32_t source,
		       uint64_t source_point, uint32_t flags)
{
	struct drm_syncobj_transfer transfer = {
		.src_handle = source,
		.dst_handle = destination,
		.src_point = source_point,
		.dst_point = destination_point,
		.flags = flags,
	};
	return drmIoctl(fd, DRM_IOCTL_SYNCOBJ_TRANSFER, &transfer);
}
