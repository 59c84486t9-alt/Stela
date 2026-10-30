// SPDX-License-Identifier: MIT
/* The reference counting of Linux's device model, following Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 drivers/base/core.c. Stela's
 * owners create and attach devices, so no bus, class or sysfs side exists. */
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/mutex.h>

static void device_release(struct kobject *kobj)
{
	struct device *dev = kobj_to_dev(kobj);

	if (dev->release)
		dev->release(dev);
	else if (dev->type && dev->type->release)
		dev->type->release(dev);
	else if (dev->class && dev->class->dev_release)
		dev->class->dev_release(dev);
	else
		WARN(1, "a device has no release function\n");
}

static const struct kobj_type device_ktype = {
	.release = device_release,
};

void device_initialize(struct device *dev)
{
	kobject_init(&dev->kobj, &device_ktype);
	INIT_LIST_HEAD(&dev->dma_pools);
	mutex_init(&dev->mutex);
	spin_lock_init(&dev->devres_lock);
	INIT_LIST_HEAD(&dev->devres_head);
}

int dev_set_name(struct device *dev, const char *fmt, ...)
{
	va_list arguments;

	va_start(arguments, fmt);
	int error = kobject_set_name_vargs(&dev->kobj, fmt, arguments);
	va_end(arguments);
	return error;
}

struct device *get_device(struct device *dev)
{
	return dev ? kobj_to_dev(kobject_get(&dev->kobj)) : NULL;
}

void put_device(struct device *dev)
{
	if (dev)
		kobject_put(&dev->kobj);
}

#ifdef STELA_LINUX_DEVICE_TEST
#include <stela/linux.h>
#include <stela/test.h>

static unsigned int released;

static void release(struct device *dev)
{
	(void)dev;
	released++;
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);
	struct device dev = {.release = release};
	device_initialize(&dev);
	assert(get_device(&dev) == &dev && !get_device(NULL));
	put_device(&dev);
	assert(!released);
	put_device(NULL);
	put_device(&dev);
	assert(released == 1);
	stela_linux_exit();
	printf("Linux device references: the last put releases the device passed\n");
	return 0;
}
#endif
