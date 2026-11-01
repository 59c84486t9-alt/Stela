// SPDX-License-Identifier: MIT
/* Exact original device membership under one kernel owner. No device name,
 * BDF, firmware name or current driver name selects an authority. */
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <stela/catalogue.h>
#include <stela/linux.h>
#include <stela/pci.h>

struct entry {
	struct list_head node;
	struct device *device;
	struct device *root;
	void *authority;
	void (*release_authority)(void *);
	bool closing;
};
static const struct stela_linux_owner *kernel_owner;
static bool ready, canonical_environment;
/* Irreversible: 0 = untouched, 1 = legacy activity, 2 = canonical claim.
 * Even a finished legacy environment/entry does not qualify global adoption. */
static unsigned int bootstrap;
static LIST_HEAD(devices);
static u64 quarantined;

int stela_linux_kernel_claim(const struct stela_linux_owner *owner)
{
	if (!owner)
		return -EINVAL;
	if (stela_linux_pci_devices_present())
		return -EBUSY;
	unsigned int fresh = 0;
	if (!__atomic_compare_exchange_n(&bootstrap, &fresh, 2, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
		return fresh == 2 ? -EALREADY : -EBUSY;
	__atomic_store_n(&kernel_owner, owner, __ATOMIC_RELEASE);
	return 0;
}
int stela_linux_kernel_environment(const struct stela_linux_owner *owner)
{
	if (!owner)
		return -EINVAL;
	const struct stela_linux_owner *claimed = __atomic_load_n(&kernel_owner, __ATOMIC_ACQUIRE);
	if (claimed) {
		if (owner != claimed)
			return -EPERM;
		bool expected = false;
		return __atomic_compare_exchange_n(&canonical_environment, &expected, true, false,
			__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) ? 0 : -EALREADY;
	}
	unsigned int fresh = 0;
	if (__atomic_compare_exchange_n(&bootstrap, &fresh, 1, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) || fresh == 1)
		return 0;
	return -EPERM;
}
bool stela_linux_kernel_owner_allowed(const struct stela_linux_owner *owner)
{
	if (__atomic_load_n(&bootstrap, __ATOMIC_ACQUIRE) != 2)
		return true;
	return owner && owner == __atomic_load_n(&kernel_owner, __ATOMIC_ACQUIRE) &&
		__atomic_load_n(&ready, __ATOMIC_ACQUIRE);
}
int stela_linux_kernel_prepare_resource(void)
{
	unsigned int fresh = 0;
	if (__atomic_compare_exchange_n(&bootstrap, &fresh, 1, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) || fresh == 1)
		return 0;
	return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) ? 0 : -EPERM;
}
int stela_linux_kernel_entry(const struct stela_linux_owner *owner)
{
	unsigned int fresh = 0;
	if (__atomic_compare_exchange_n(&bootstrap, &fresh, 1, false,
		__ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) || fresh == 1)
		return 0;
	return stela_linux_kernel_owner_allowed(owner) ? 0 : -EPERM;
}
int stela_linux_kernel_ready(const struct stela_linux_owner *owner)
{
	if (!owner || __atomic_load_n(&kernel_owner, __ATOMIC_ACQUIRE) != owner ||
	    !__atomic_load_n(&canonical_environment, __ATOMIC_ACQUIRE))
		return -EPERM;
	__atomic_store_n(&ready, true, __ATOMIC_RELEASE);
	return 0;
}
bool stela_linux_kernel_catalogue_active(void)
{
	return __atomic_load_n(&bootstrap, __ATOMIC_ACQUIRE) == 2;
}
static bool ours(void)
{
	return __atomic_load_n(&ready, __ATOMIC_ACQUIRE) &&
           stela_linux_owner() == __atomic_load_n(&kernel_owner, __ATOMIC_ACQUIRE);
}
static struct entry *find(const struct device *dev)
{
	struct entry *entry;
	list_for_each_entry(entry, &devices, node)
		if (entry->device == dev)
			return entry;
	return NULL;
}
static struct device *retain(struct device *dev)
{
	return dev && kobject_get_unless_zero(&dev->kobj) ? dev : NULL;
}
int stela_linux_device_bind(struct device *dev, void *authority,
                           void (*release_authority)(void *))
{
	if (!ours() || !stela_linux_quiescent())
		return -EPERM;
	if (!dev || !authority || !release_authority || !dev->kobj.state_initialized)
		return -EINVAL;
	if (find(dev))
		return -EEXIST;
	struct entry *entry = kzalloc_obj(*entry);
	if (!entry)
		return -ENOMEM;
	if (!ours() || !stela_linux_quiescent() || find(dev)) {
		kfree(entry);
		return -EEXIST;
	}
	entry->device = dev;
	entry->root = dev;
	entry->authority = authority;
	entry->release_authority = release_authority;
	list_add_tail(&entry->node, &devices);
	return 0;
}
int stela_linux_device_inherit(struct device *dev)
{
	if (!stela_linux_kernel_catalogue_active())
		return 0;
	if (!ours() || !stela_linux_quiescent())
		return -EPERM;
	if (find(dev))
		return 0;
	struct entry *parent = find(dev->parent);
	if (!parent)
		return 0; /* ordinary devices acquire no firmware authority */
	struct entry *root = find(parent->root);
	if (parent->closing || !root || root->closing)
		return -ENODEV;
	/* device_add retains the actual parent before this call; root keeps the
     * exact native source while a sleepable allocation is attempted. */
	if (!retain(parent->root))
		return -ENODEV;
	struct device *root_device = parent->root;
	struct entry *entry = kzalloc_obj(*entry);
	if (!entry) {
		put_device(root_device);
		return -ENOMEM;
	}
	parent = find(dev->parent);
	root = find(root_device);
	if (!ours() || !stela_linux_quiescent() || find(dev) ||
		!parent || parent->closing || parent->root != root_device ||
		!root || root->closing) {
		kfree(entry);
		put_device(root_device);
		return -ENODEV;
	}
	entry->device = dev;
	entry->root = parent->root;
	entry->authority = parent->authority;
	list_add_tail(&entry->node, &devices);
	return 0;
}
bool stela_linux_device_publish_allowed(struct device *dev)
{
	if (!stela_linux_kernel_catalogue_active())
		return true; /* existing non-canonical GPU composition is not migrated */
	if (!ours())
		return false;
	struct entry *entry = find(dev);
	return entry && !entry->closing;
}
void stela_linux_device_close(struct device *dev)
{
	if (!stela_linux_kernel_catalogue_active())
		return;
	if (!ours() || !stela_linux_quiescent())
		stela_linux_fatal("device close outside canonical process owner");
	struct entry *entry = find(dev);
	if (entry)
		entry->closing = true;
}
int stela_linux_device_acquire(struct device *dev, struct stela_linux_device_lease *lease)
{
	if (!lease)
		return -EINVAL;
	lease->device = NULL;
	lease->authority = NULL;
	if (!stela_linux_kernel_catalogue_active() || !ours())
		return -EPERM;
	struct entry *entry = find(dev);
	struct entry *root = entry ? find(entry->root) : NULL;
	if (!entry || entry->closing || !root || root->closing || !retain(dev))
		return -ENODEV;
	lease->device = dev;
	lease->authority = entry->authority;
	return 0;
}
int stela_linux_device_release(struct stela_linux_device_lease *lease)
{
	if (!ours() || !stela_linux_quiescent())
		return -EPERM;
	if (!lease || !lease->device)
		return -EINVAL;
	struct device *dev = lease->device;
	lease->device = NULL;
	lease->authority = NULL;
	put_device(dev);
	return 0;
}
bool stela_linux_device_release_begin(struct device *dev,
                                     struct stela_linux_device_retirement *retired)
{
	retired->entry = NULL;
	if (!stela_linux_kernel_catalogue_active())
		return true;
	if (!ours() || !stela_linux_quiescent()) {
		u64 value = __atomic_load_n(&quarantined, __ATOMIC_RELAXED);
		while (value != ~(u64)0 &&
               !__atomic_compare_exchange_n(&quarantined, &value, value + 1, false,
                                             __ATOMIC_RELAXED, __ATOMIC_RELAXED))
			;
		return false; /* retain C storage and every source owner */
	}
	struct entry *entry = find(dev);
	if (entry) {
		list_del(&entry->node);
		retired->entry = entry;
	}
	return true;
}
void stela_linux_device_release_end(struct stela_linux_device_retirement *retired)
{
	struct entry *entry = retired->entry;
	if (!entry)
		return;
	retired->entry = NULL;
	struct device *root = entry->root;
	bool child = root != entry->device;
	void *authority = entry->authority;
	void (*release_authority)(void *) = entry->release_authority;
	kfree(entry);
	/* No lookup/list borrow or access to a released original device follows. */
	if (child)
		put_device(root);
	else
		release_authority(authority);
}
u64 stela_linux_device_quarantined_releases(void)
{
	return __atomic_load_n(&quarantined, __ATOMIC_RELAXED);
}


#ifdef STELA_LINUX_CATALOGUE_TEST
#include <linux/pci.h>
#include <stela/test.h>

struct peer {
	struct device device;
	unsigned int released;
};
struct source { unsigned int *released; };
static unsigned int source_releases, host_releases, probes;
static struct peer root, child, unknown, global_device;
static void release_peer(struct device *device)
{
	struct peer *peer = container_of(device, struct peer, device);
	peer->released++;
}
static struct source *source(void)
{
	struct source *value = calloc(1, sizeof(*value));
	assert(value);
	value->released = &source_releases;
	return value;
}
static void release_source(void *opaque)
{
	struct source *value = opaque;
	(*value->released)++;
	free(value);
}
static void initialize(struct peer *peer)
{
	memset(peer, 0, sizeof(*peer));
	peer->device.release = release_peer;
	device_initialize(&peer->device);
}
static void child_keeps_original_root(void)
{
	initialize(&root);
	initialize(&child);
	initialize(&unknown);
	assert(!stela_linux_device_bind(&root.device, source(), release_source));
	child.device.parent = &root.device;
	assert(!dev_set_name(&child.device, "same-visible-name"));
	assert(!device_add(&child.device));
	struct stela_linux_device_lease lease, rejected;
	assert(!stela_linux_device_acquire(&child.device, &lease));
	assert(stela_linux_device_acquire(&unknown.device, &rejected) == -ENODEV);
	assert(!rejected.device && !rejected.authority);
	device_del(&child.device);
	assert(stela_linux_device_acquire(&child.device, &rejected) == -ENODEV);
	put_device(&root.device);
	put_device(&child.device);
	assert(!root.released && !child.released && !source_releases);
	assert(!stela_linux_device_release(&lease));
	assert(child.released == 1 && root.released == 1 && source_releases == 1);
	put_device(&unknown.device);
}
static void closing_root_refuses_live_child(void)
{
	unsigned int before = source_releases;
	initialize(&root);
	initialize(&child);
	assert(!stela_linux_device_bind(&root.device, source(), release_source));
	child.device.parent = &root.device;
	assert(!dev_set_name(&child.device, "arbitrary-child"));
	assert(!device_add(&child.device));
	stela_linux_device_close(&root.device);
	struct stela_linux_device_lease refused;
	assert(stela_linux_device_acquire(&child.device, &refused) == -ENODEV);
	assert(!refused.device && !refused.authority);
	device_del(&child.device);
	put_device(&child.device);
	put_device(&root.device);
	assert(child.released == 1 && root.released == 1 && source_releases == before + 1);
}
static void explicit_global_and_root_close(void)
{
	unsigned int before = source_releases;
	initialize(&root);
	initialize(&global_device);
	struct source *pci = source(), *global = source();
	assert(!stela_linux_device_bind(&root.device, pci, release_source));
	/* Explicit original global device, with no name interpretation. */
	assert(!stela_linux_device_bind(&global_device.device, global, release_source));
	struct stela_linux_device_lease first, second, refused;
	assert(!stela_linux_device_acquire(&root.device, &first));
	assert(!stela_linux_device_acquire(&global_device.device, &second));
	assert(first.authority == pci && second.authority == global && first.authority != second.authority);
	stela_linux_device_close(&root.device);
	assert(stela_linux_device_acquire(&root.device, &refused) == -ENODEV);
	assert(!stela_linux_device_release(&first));
	assert(!stela_linux_device_release(&second));
	put_device(&root.device);
	put_device(&global_device.device);
	assert(source_releases == before + 2);
}
static int read_config(void *context, int where, int size, u32 *value)
{
	(void)context; (void)size;
	*value = where == PCI_VENDOR_ID ? 0x1234U :
             where == PCI_DEVICE_ID ? 0x5678U : 0;
	return PCIBIOS_SUCCESSFUL;
}
static int enroll_peer(void *context, struct device *device)
{
	assert(context == &host_releases);
	return stela_linux_device_bind(device, source(), release_source);
}
static void host_release(void *context)
{
	assert(context == &host_releases);
	host_releases++;
}
static int probe(struct pci_dev *device, const struct pci_device_id *id)
{
	(void)id;
	struct stela_linux_device_lease lease;
	assert(!stela_linux_device_acquire(&device->dev, &lease));
	assert(lease.device == &device->dev && lease.authority);
	assert(!stela_linux_device_release(&lease));
	probes++;
	return 0;
}
static void enrolled_before_probe(void)
{
	unsigned int before = source_releases;
	static const struct pci_device_id ids[] = {
		{ .vendor = 0x1234U, .device = 0x5678U,
		  .subvendor = (u32)PCI_ANY_ID, .subdevice = (u32)PCI_ANY_ID },
		{ }
	};
	struct pci_driver driver = {.name = "catalogue-reference-peer", .id_table = ids, .probe = probe};
	assert(!__pci_register_driver(&driver, NULL, "catalogue-reference-peer"));
	struct stela_linux_pci_function function = {
		.context = &host_releases, .read_config = read_config,
		.release_context = host_release, .enroll = enroll_peer,
	};
	int error = -1;
	struct pci_dev *device = stela_linux_pci_attach(&function, &error);
	assert(device && !error && probes == 1);
	struct stela_linux_device_lease lease;
	assert(!stela_linux_device_acquire(&device->dev, &lease));
	stela_linux_pci_remove_device(device);
	assert(!host_releases);
	assert(!stela_linux_device_release(&lease));
	assert(host_releases == 1 && source_releases == before + 1);
	pci_unregister_driver(&driver);
	/* A canonical owner refuses an unenrolled root before probe. */
	function.enroll = NULL;
	device = stela_linux_pci_attach(&function, &error);
	assert(!device && error == -EPERM && probes == 1 && host_releases == 1);
}
int main(void)
{
	static const struct stela_linux_services services = {};
	static const struct stela_linux_owner owner = {.services = &services};
	static const struct stela_linux_owner other = {.services = &services};
	assert(!stela_linux_kernel_claim(&owner));
	assert(stela_linux_kernel_claim(&other) == -EALREADY);
	assert(stela_linux_kernel_ready(&owner) == -EPERM);
	assert(stela_linux_kernel_prepare_resource() == -EPERM);
	assert(stela_linux_kernel_environment(&other) == -EPERM);
	assert(!stela_linux_kernel_environment(&owner));
	assert(stela_linux_kernel_environment(&owner) == -EALREADY);
	assert(!stela_linux_kernel_owner_allowed(&owner));
	assert(!stela_linux_kernel_ready(&owner));
	assert(stela_linux_kernel_owner_allowed(&owner));
	assert(!stela_linux_kernel_prepare_resource());
	assert(!stela_linux_kernel_owner_allowed(&other));
	stela_linux_enter(&owner);
	child_keeps_original_root();
	closing_root_refuses_live_child();
	explicit_global_and_root_close();
	enrolled_before_probe();
	assert(!stela_linux_device_quarantined_releases());
	stela_linux_exit();
	printf("Linux catalogue: original refs, pre-probe enrollment, exact roots/global authority passed\n");
	return 0;
}
#endif

#ifdef STELA_LINUX_CATALOGUE_LEGACY_TEST
#include <stela/test.h>
int main(void)
{
	static const struct stela_linux_services services = {};
	static const struct stela_linux_owner owner = {.services = &services};
	/* Real entry/exit with zero presented devices is still irreversible
	 * legacy kernel activity, not proof its global resources can be adopted. */
	stela_linux_enter(&owner);
	stela_linux_exit();
	assert(!stela_linux_pci_devices_present());
	assert(stela_linux_kernel_claim(&owner) == -EBUSY);
	return 0;
}
#endif

#ifdef STELA_LINUX_CATALOGUE_TASK_TEST
#include <stela/test.h>
#include <stela/task.h>
int main(void)
{
	struct stela_linux_task *task = stela_linux_task_allocate();
	assert(task);
	stela_linux_task_release(task);
	assert(stela_linux_kernel_claim(&stela_linux_bare) == -EBUSY);
	return 0;
}
#endif

#ifdef STELA_LINUX_CATALOGUE_WORKQUEUE_TEST
#include <linux/workqueue.h>
#include <stela/test.h>
int main(void)
{
	/* GFP_KERNEL allocation requires the actual entered process owner. */
	stela_linux_enter(&stela_linux_bare);
	struct workqueue_struct *wq = alloc_workqueue("legacy-catalogue-peer", 0, 1);
	assert(wq);
	stela_linux_exit();
	/* The real global queue survives its allocating legacy entry. */
	assert(stela_linux_kernel_claim(&stela_linux_bare) == -EBUSY);
	stela_linux_enter(&stela_linux_bare);
	destroy_workqueue(wq);
	stela_linux_exit();
	assert(stela_linux_kernel_claim(&stela_linux_bare) == -EBUSY);
	return 0;
}
#endif
