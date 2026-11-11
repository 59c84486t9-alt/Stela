/* SPDX-License-Identifier: MIT */
/* Puts a queue's submissions on Mesa's submit thread, a Linux task of the
 * host's environment: vkQueueSubmit2 then queues the work and returns, and
 * the thread makes the driver's submission (DRM_NOUVEAU_EXEC) where Linux
 * runs, so the processor that committed does not wait for that environment.
 * A submission the driver then fails loses the queue, as Mesa's threaded
 * mode does; every later call and completion query answers the loss.
 *
 * vk_device_enable_threaded_submit() wants no queue yet, for drivers whose
 * queues start deferred; NVK's start immediate, so this checks what it
 * checks and lets the device take threads on demand itself. */
#include "vk_device.h"
#include "vk_physical_device.h"
#include "vk_queue.h"
#include "vk_sync.h"

VkResult stela_nvk_submit_thread(VkQueue handle);

VkResult stela_nvk_submit_thread(VkQueue handle)
{
	VK_FROM_HANDLE(vk_queue, queue, handle);
	struct vk_device *device = queue->base.device;
	/* A wait the thread reorders must be able to wait for its signal's
	 * submission. */
	for (const struct vk_sync_type *const *type = device->physical->supported_sync_types; *type;
	     type++) {
		if (((*type)->features & VK_SYNC_FEATURE_GPU_WAIT) &&
		    !((*type)->features & VK_SYNC_FEATURE_WAIT_PENDING))
			return VK_ERROR_FEATURE_NOT_PRESENT;
	}
	if (!vk_device_supports_threaded_submit(device))
		device->submit_mode = VK_QUEUE_SUBMIT_MODE_THREADED_ON_DEMAND;
	return vk_queue_enable_submit_thread(queue);
}
