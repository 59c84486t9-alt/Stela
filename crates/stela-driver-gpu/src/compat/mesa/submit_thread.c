/* SPDX-License-Identifier: MIT */
/* Puts a queue's submissions on Mesa's submit thread, a Linux task of the
 * host's environment: vkQueueSubmit2 then queues the work and returns, and
 * the thread makes the driver's submission (DRM_NOUVEAU_EXEC) where Linux
 * runs, so the processor that committed does not wait for that environment.
 * A submission the driver refuses short of losing the device still makes its
 * signals (nvk_queue_refuse), so the queue goes on; the caller asks for the
 * failure by a signal once it shows (stela_nvk_submit_failure). The same
 * holds without the thread.
 *
 * vk_device_enable_threaded_submit() wants no queue yet, for drivers whose
 * queues start deferred; NVK's start immediate, so this checks what it
 * checks and lets the device take threads on demand itself. */
#include "nvk_queue.h"
#include "vk_device.h"
#include "vk_physical_device.h"
#include "vk_queue.h"
#include "vk_semaphore.h"
#include "vk_sync.h"

VkResult stela_nvk_submit_thread(VkQueue handle);
VkResult stela_nvk_submit_failure(VkQueue queue_handle, VkSemaphore semaphore_handle, uint64_t value);
uint32_t stela_nvk_forget_failures(VkQueue queue_handle);
void stela_nvk_count_failures(VkQueue queue_handle, uint32_t *outstanding);

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

/* The failure of the refused submission that signaled `value` on
 * `semaphore_handle`, taken once; VK_SUCCESS for every other. */
VkResult stela_nvk_submit_failure(VkQueue queue_handle, VkSemaphore semaphore_handle, uint64_t value)
{
	VK_FROM_HANDLE(vk_queue, queue, queue_handle);
	VK_FROM_HANDLE(vk_semaphore, semaphore, semaphore_handle);
	struct nvk_queue *nvk = container_of(queue, struct nvk_queue, vk);
	return nvk_queue_take_failure(nvk, vk_semaphore_get_active_sync(semaphore), value);
}

/* Drops the kept failures nobody will take; answers how many. */
uint32_t stela_nvk_forget_failures(VkQueue queue_handle)
{
	VK_FROM_HANDLE(vk_queue, queue, queue_handle);
	return nvk_queue_forget_failures(container_of(queue, struct nvk_queue, vk));
}

/* Has the queue raise `*outstanding` by each failure it keeps, before the
 * refused submission's signals are made, and lower it by each it drops
 * unasked; the caller lowers it by those it takes and settles. Before the
 * queue's first submission. */
void stela_nvk_count_failures(VkQueue queue_handle, uint32_t *outstanding)
{
	VK_FROM_HANDLE(vk_queue, queue, queue_handle);
	container_of(queue, struct nvk_queue, vk)->failures_outstanding = outstanding;
}
