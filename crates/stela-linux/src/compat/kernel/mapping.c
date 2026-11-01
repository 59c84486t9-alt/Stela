// SPDX-License-Identifier: MIT
/* Clients' mappings of Linux's files, with the interfaces of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 mm/memory.c, mm/mmap.c and
 * mm/interval_tree.c. The owner owns the clients' address spaces: each
 * mapping is a VMA for the driver's mmap and fault, and map_user and
 * unmap_user change the page tables. Linux's fault path takes no locks here,
 * so no retry leaves mmap_lock. */
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/interval_tree_generic.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/slab.h>
#include <stela/file.h>
#include <stela/linux.h>

struct stela_linux_mapping {
	struct vm_area_struct vma;
	void *space;
};

static inline unsigned long first_page(const struct vm_area_struct *vma)
{
	return vma->vm_pgoff;
}

static inline unsigned long last_page(const struct vm_area_struct *vma)
{
	return vma->vm_pgoff + vma_pages(vma) - 1;
}

INTERVAL_TREE_DEFINE(struct vm_area_struct, shared.rb, unsigned long, shared.rb_subtree_last,
		     first_page, last_page, static inline, mapped)

const struct vm_operations_struct vma_dummy_vm_ops;

/* Every mapping's mm: Linux code reads it, the owner's space is what counts. */
static struct mm_struct client_mm = {
	.mmap_lock = __RWSEM_INITIALIZER(client_mm.mmap_lock),
};

/* The write-back protection a VMA's page table entries start from. */
pgprot_t vm_get_page_prot(vm_flags_t vm_flags)
{
	pteval_t bits = _PAGE_PRESENT | _PAGE_USER | _PAGE_ACCESSED;

	if (vm_flags & VM_WRITE)
		bits |= _PAGE_RW;
	if (!(vm_flags & VM_EXEC))
		bits |= _PAGE_NX;
	return __pgprot(bits);
}

int stela_linux_mmap(struct file *file, void *space, unsigned long address, size_t size,
		     u64 offset, bool writable, struct stela_linux_mapping **result)
{
	if (!PAGE_ALIGNED(address) || !PAGE_ALIGNED(size) || !PAGE_ALIGNED(offset) || !size)
		return -EINVAL;
	if (!file->f_op->mmap)
		return -ENODEV;
	struct stela_linux_mapping *mapping = kmalloc_obj(*mapping);

	if (!mapping)
		return -ENOMEM;
	struct vm_area_struct *vma = &mapping->vma;

	mapping->space = space;
	vma_init(vma, &client_mm);
	vma->vm_start = address;
	vma->vm_end = address + size;
	vma->vm_pgoff = offset >> PAGE_SHIFT;
	vm_flags_init(vma, VM_READ | VM_MAYREAD | VM_SHARED | VM_MAYSHARE |
			   (writable ? VM_WRITE | VM_MAYWRITE : 0));
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_file = get_file(file);
	int error = file->f_op->mmap(file, vma);

	/* An exporter's mmap may have redirected the mapping to its own file. */
	file = vma->vm_file;
	if (error) {
		fput(file);
		kfree(mapping);
		return error;
	}
	i_mmap_lock_write(file->f_mapping);
	mapped_insert(vma, &file->f_mapping->i_mmap);
	i_mmap_unlock_write(file->f_mapping);
	*result = mapping;
	return 0;
}

int stela_linux_map(int fd, void *space, unsigned long address, size_t size, u64 offset,
		    struct stela_linux_mapping **result)
{
	struct file *file = fget((unsigned int)fd);

	if (!file)
		return -EBADF;
	int error = stela_linux_mmap(file, space, address, size, offset, true, result);

	fput(file);
	if (error)
		return error;
	for (size_t at = 0; at < size; at += PAGE_SIZE) {
		if (!stela_linux_refault(*result, address + at, true)) {
			stela_linux_munmap(*result);
			return -EFAULT;
		}
	}
	return 0;
}

void vma_set_file(struct vm_area_struct *vma, struct file *file)
{
	get_file(file);
	swap(vma->vm_file, file);
	fput(file);
}

void stela_linux_munmap(struct stela_linux_mapping *mapping)
{
	struct vm_area_struct *vma = &mapping->vma;
	struct file *file = vma->vm_file;
	const struct stela_linux_owner *owner = stela_linux_owner();

	i_mmap_lock_write(file->f_mapping);
	mapped_remove(vma, &file->f_mapping->i_mmap);
	i_mmap_unlock_write(file->f_mapping);
	owner->services->unmap_user(owner->context, mapping->space, vma->vm_start,
				    vma->vm_end - vma->vm_start);
	if (vma->vm_ops && vma->vm_ops->close)
		vma->vm_ops->close(vma);
	fput(file);
	kfree(mapping);
}

vm_fault_t stela_linux_fault(struct stela_linux_mapping *mapping, unsigned long address,
			     bool write)
{
	struct vm_area_struct *vma = &mapping->vma;

	if (address < vma->vm_start || address >= vma->vm_end ||
	    (write && !(vma->vm_flags & VM_WRITE)) || !vma->vm_ops || !vma->vm_ops->fault)
		return VM_FAULT_SIGSEGV;
	address &= PAGE_MASK;
	struct vm_fault vmf = {
		.vma = vma,
		.address = address,
		.pgoff = vma->vm_pgoff + ((address - vma->vm_start) >> PAGE_SHIFT),
		.flags = FAULT_FLAG_USER | (write ? FAULT_FLAG_WRITE : 0),
	};

	return vma->vm_ops->fault(&vmf);
}

bool stela_linux_refault(struct stela_linux_mapping *mapping, unsigned long address, bool write)
{
	return !(stela_linux_fault(mapping, address, write) & VM_FAULT_ERROR);
}

vm_fault_t vmf_insert_pfn_prot(struct vm_area_struct *vma, unsigned long addr, unsigned long pfn,
			       pgprot_t pgprot)
{
	const struct stela_linux_owner *owner = stela_linux_owner();
	const struct stela_linux_mapping *mapping =
		container_of(vma, struct stela_linux_mapping, vma);

	if (addr < vma->vm_start || addr >= vma->vm_end)
		return VM_FAULT_SIGBUS;
	int error = owner->services->map_user(owner->context, mapping->space, addr, pfn,
					      pgprot_val(pgprot));

	return !error ? VM_FAULT_NOPAGE : error == -ENOMEM ? VM_FAULT_OOM : VM_FAULT_SIGBUS;
}

/* Clients fault the range back in, and reach wherever it moved to. */
void unmap_mapping_range(struct address_space *mapping, loff_t const holebegin,
			 loff_t const holelen, int even_cows)
{
	(void)even_cows;
	const struct stela_linux_owner *owner = stela_linux_owner();
	unsigned long first = (unsigned long)(holebegin >> PAGE_SHIFT);
	unsigned long count = (unsigned long)(PAGE_ALIGN(holelen) >> PAGE_SHIFT);
	unsigned long last = count ? first + count - 1 : ULONG_MAX;
	struct vm_area_struct *vma;

	i_mmap_lock_read(mapping);
	for (vma = mapped_iter_first(&mapping->i_mmap, first, last); vma;
	     vma = mapped_iter_next(vma, first, last)) {
		const struct stela_linux_mapping *client =
			container_of(vma, struct stela_linux_mapping, vma);
		unsigned long from = max(first, vma->vm_pgoff);
		unsigned long to = min(last, last_page(vma));

		owner->services->unmap_user(owner->context, client->space,
					    vma->vm_start + ((from - vma->vm_pgoff) << PAGE_SHIFT),
					    (to - from + 1) << PAGE_SHIFT);
	}
	i_mmap_unlock_read(mapping);
}

#ifdef STELA_LINUX_MAPPING_TEST
#include <linux/anon_inodes.h>
#include <stela/test.h>

#define SPACE ((void *)0x1000)
#define BASE 0x10000UL
#define PFN 0x500UL

static unsigned long inserted_address, inserted_pfn, removed_address, removed_size;
static pgprot_t inserted_prot;
static unsigned int closes, mmaps;
static int mmap_error, map_error;

static int map_user(void *context, void *space, unsigned long address, unsigned long pfn,
		    u64 prot)
{
	(void)context;
	assert(space == SPACE);
	inserted_address = address;
	inserted_pfn = pfn;
	inserted_prot = __pgprot(prot);
	return map_error;
}

static void unmap_user(void *context, void *space, unsigned long address, size_t size)
{
	(void)context;
	assert(space == SPACE);
	removed_address = address;
	removed_size = size;
}

static const struct stela_linux_services services = {
	.map_user = map_user,
	.unmap_user = unmap_user,
};
static const struct stela_linux_owner owner = {.services = &services};

static vm_fault_t fault(struct vm_fault *vmf)
{
	assert(vmf->pgoff == 4 && (vmf->flags & FAULT_FLAG_USER));
	return vmf_insert_pfn_prot(vmf->vma, vmf->address, PFN + vmf->pgoff,
				   pgprot_writecombine(vmf->vma->vm_page_prot));
}

static void close_area(struct vm_area_struct *vma)
{
	(void)vma;
	closes++;
}

static const struct vm_operations_struct operations = {.fault = fault, .close = close_area};

static struct file *exporter;

static int test_mmap(struct file *file, struct vm_area_struct *vma)
{
	(void)file;
	mmaps++;
	vma->vm_ops = &operations;
	if (exporter)
		vma_set_file(vma, exporter);
	return mmap_error;
}

static const struct file_operations fops = {.mmap = test_mmap};

int main(void)
{
	stela_linux_enter(&owner);
	struct file *file = anon_inode_getfile("test", &fops, NULL, O_RDWR);
	struct stela_linux_mapping *mapping;

	assert(!IS_ERR(file));
	assert(stela_linux_mmap(file, SPACE, BASE + 1, PAGE_SIZE, 0, true, &mapping) == -EINVAL);
	mmap_error = -EPERM;
	assert(stela_linux_mmap(file, SPACE, BASE, PAGE_SIZE, 0, true, &mapping) == -EPERM);
	mmap_error = 0;
	assert(!stela_linux_mmap(file, SPACE, BASE, 4 * PAGE_SIZE, 3 * PAGE_SIZE, false, &mapping));

	/* A read fault at page 1 of the mapping is page 4 of the file. */
	assert(stela_linux_fault(mapping, BASE + 4 * PAGE_SIZE, false) == VM_FAULT_SIGSEGV);
	assert(stela_linux_fault(mapping, BASE + PAGE_SIZE + 9, true) == VM_FAULT_SIGSEGV);
	assert(stela_linux_fault(mapping, BASE + PAGE_SIZE + 9, false) == VM_FAULT_NOPAGE);
	assert(inserted_address == BASE + PAGE_SIZE && inserted_pfn == PFN + 4);
	assert(pgprot_val(inserted_prot) & _PAGE_PWT);
	assert(!(pgprot_val(inserted_prot) & _PAGE_RW));
	map_error = -ENOMEM;
	assert(stela_linux_fault(mapping, BASE + PAGE_SIZE, false) == VM_FAULT_OOM);
	map_error = -EIO;
	assert(stela_linux_fault(mapping, BASE + PAGE_SIZE, false) == VM_FAULT_SIGBUS);

	/* File pages 4-5 overlap pages 1-2 of the mapping; pages 1-2 of the file
	 * lie before it. */
	unmap_mapping_range(file->f_mapping, 4 * PAGE_SIZE, 2 * PAGE_SIZE, 1);
	assert(removed_address == BASE + PAGE_SIZE && removed_size == 2 * PAGE_SIZE);
	removed_size = 0;
	unmap_mapping_range(file->f_mapping, PAGE_SIZE, 2 * PAGE_SIZE, 1);
	assert(!removed_size);
	unmap_mapping_range(file->f_mapping, 0, 0, 1);
	assert(removed_address == BASE && removed_size == 4 * PAGE_SIZE);

	stela_linux_munmap(mapping);
	assert(closes == 1 && mmaps == 2);
	removed_size = 0;
	unmap_mapping_range(file->f_mapping, 0, 0, 1);
	assert(!removed_size);

	/* A mapping an exporter redirects lives on the exporter's file. */
	struct file *own = anon_inode_getfile("exporter", &fops, NULL, O_RDWR);
	assert(!IS_ERR(own));
	exporter = own;
	assert(!stela_linux_mmap(file, SPACE, BASE, PAGE_SIZE, 0, true, &mapping));
	assert(mapping->vma.vm_file == exporter);
	unmap_mapping_range(file->f_mapping, 0, 0, 1);
	assert(!removed_size);
	unmap_mapping_range(exporter->f_mapping, 0, 0, 1);
	assert(removed_size == PAGE_SIZE);
	stela_linux_munmap(mapping);
	fput(exporter);
	fput(file);
	stela_linux_exit();
	printf("Linux client mappings passed\n");
	return 0;
}
#endif
