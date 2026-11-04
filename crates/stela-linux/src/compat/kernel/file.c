// SPDX-License-Identifier: MIT
/* Linux's files, with the interfaces of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 fs/file.c, fs/file_table.c,
 * fs/anon_inodes.c, fs/char_dev.c and fs/libfs.c. Stela has no filesystem:
 * a file is an inode for its driver's mapping and a reference count, its
 * drivers reach it through their file_operations, and a pseudo filesystem's
 * mount is the superblock its dentries take their operations from. */
#include <linux/anon_inodes.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/kdev_t.h>
#include <linux/llist.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/shmem_fs.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <stela/file.h>
#include <unsupported.h>

static struct inode *inode_of_mode(umode_t mode)
{
	struct inode *inode = kmalloc_obj(*inode, GFP_KERNEL);

	if (!inode)
		return ERR_PTR(-ENOMEM);
	inode_init_once(inode);
	atomic_set(&inode->i_count, 1);
	inode->i_mode = mode;
	inode->i_mapping = &inode->i_data;
	inode->i_data.host = inode;
	return inode;
}

struct inode *alloc_anon_inode(struct super_block *sb)
{
	(void)sb;
	return inode_of_mode(S_IRUSR | S_IWUSR);
}

void ihold(struct inode *inode)
{
	atomic_inc(&inode->i_count);
}

void iput(struct inode *inode)
{
	if (inode && atomic_dec_and_test(&inode->i_count)) {
		if (S_ISCHR(inode->i_mode))
			cd_forget(inode);
		kfree(inode);
	}
}

void inode_set_bytes(struct inode *inode, loff_t bytes)
{
	inode->i_blocks = (blkcnt_t)(bytes >> 9);
	inode->i_bytes = (unsigned short)(bytes & 511);
}

extern struct kmem_cache *__filp_cache;
struct file *alloc_empty_file(int flags, const struct cred *cred);
void file_free(struct file *file);
static const struct file_operations empty_file_operations;

/* Takes over the caller's inode reference. */
static struct file *new_file(struct inode *inode, const struct file_operations *fops,
			     unsigned int flags, void *private_data)
{
	if (unlikely(!__filp_cache)) {
		iput(inode);
		return ERR_PTR(-ENODEV);
	}
	struct file *file = alloc_empty_file((int)flags, current_cred());

	if (IS_ERR(file)) {
		iput(inode);
		return file;
	}
	file->f_inode = inode;
	file->f_mapping = inode->i_mapping;
	file->f_op = fops ? fops : &empty_file_operations;
	file->private_data = private_data;
	return file;
}

static void release(struct file *file)
{
	if (file->f_op && file->f_op->release)
		file->f_op->release(file->f_inode, file);
	if (file->f_op && S_ISCHR(file->f_inode->i_mode)) {
		cdev_put(file->f_inode->i_cdev);
		fops_put(file->f_op);
	}
	iput(file->f_inode);

	struct dentry *dentry = file->f_path.dentry;

	if (dentry) {
		if (dentry->d_op && dentry->d_op->d_release)
			dentry->d_op->d_release(dentry);
		iput(dentry->d_inode);
		kfree(dentry);
	}
	file_free(file);
}

static LLIST_HEAD(release_pending);

static void release_later(struct work_struct *work)
{
	(void)work;
	struct llist_node *pending = llist_del_all(&release_pending);
	struct file *file, *next;

	llist_for_each_entry_safe(file, next, pending, f_llist)
		release(file);
}

static DECLARE_WORK(release_worker, release_later);

static void release_last_reference(struct file *file)
{
	if (!in_atomic() && !irqs_disabled()) {
		release(file);
		return;
	}

	/* Like Linux's delayed fput, the dead file carries its own queue node.
	 * The empty-to-nonempty producer schedules the drain, including when
	 * new files arrive while an earlier batch is being released. */
	if (llist_add(&file->f_llist, &release_pending))
		schedule_work(&release_worker);
}

void fput(struct file *file)
{
	if (file_ref_put(&file->f_ref))
		release_last_reference(file);
}

void fput_close(struct file *file)
{
	if (file_ref_put_close(&file->f_ref))
		release_last_reference(file);
}

struct file *anon_inode_getfile(const char *name, const struct file_operations *fops, void *priv,
				int flags)
{
	(void)name;
	struct inode *inode = alloc_anon_inode(NULL);

	return IS_ERR(inode) ? ERR_CAST(inode) : new_file(inode, fops, (unsigned int)flags, priv);
}

/* The dentry holds the caller's inode reference, as Linux's does, and the
 * file its own. A failure leaves the caller's reference with the caller. */
struct file *alloc_file_pseudo(struct inode *inode, struct vfsmount *mount, const char *name,
			       int flags, const struct file_operations *fops)
{
	struct dentry *dentry = kzalloc_obj(*dentry);

	if (!dentry)
		return ERR_PTR(-ENOMEM);
	ihold(inode);

	struct file *file = new_file(inode, fops, (unsigned int)flags, NULL);

	if (IS_ERR(file)) {
		kfree(dentry);
		return file;
	}
	dentry->__d_name = (struct qstr)QSTR_INIT((const unsigned char *)name, (u32)strlen(name));
	dentry->d_inode = inode;
	dentry->d_sb = mount->mnt_sb;
	dentry->d_op = mount->mnt_sb->__s_d_op;
	file->__f_path = (struct path){.mnt = mount, .dentry = dentry};
	return file;
}

/* An object with no backing store, as nouveau's GEM objects take one only for
 * their size and mapping offset. Pages for it are what the OPEN list's shmem
 * entries would serve. */
struct file *shmem_file_setup(const char *name, loff_t size, vma_flags_t flags)
{
	(void)name;
	(void)flags;
	struct inode *inode = inode_of_mode(S_IFREG | S_IRUSR | S_IWUSR);

	if (IS_ERR(inode))
		return ERR_CAST(inode);
	inode->i_size = size;
	return new_file(inode, NULL, O_RDWR, NULL);
}

struct file *shmem_file_setup_with_mnt(struct vfsmount *mount, const char *name, loff_t size,
				       vma_flags_t flags)
{
	(void)mount;
	return shmem_file_setup(name, size, flags);
}

loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
	(void)whence;
	(void)offset;
	return file->f_pos;
}

void stela_linux_fd_close(int fd)
{
	close_fd((unsigned int)fd);
}

int stela_linux_fd_dup(int fd)
{
	struct file *file = fget((unsigned int)fd);

	if (!file)
		return -EBADF;
	int copy = get_unused_fd_flags(0);

	if (copy < 0)
		fput(file);
	else
		fd_install((unsigned int)copy, file);
	return copy;
}

long stela_linux_fd_device(int fd)
{
	struct file *file = fget((unsigned int)fd);

	if (!file)
		return -EBADF;
	long device = file_inode(file)->i_rdev;

	fput(file);
	return device;
}

static DECLARE_WAIT_QUEUE_HEAD(stela_linux_waiters);

void stela_linux_wait(const volatile unsigned int *word, unsigned int value, u64 nanoseconds)
{
	if (nanoseconds == U64_MAX)
		wait_event(stela_linux_waiters, READ_ONCE(*word) != value);
	else
		wait_event_timeout(stela_linux_waiters, READ_ONCE(*word) != value,
				   nsecs_to_jiffies64(nanoseconds) + 1);
}

void stela_linux_wake(void)
{
	wake_up_all(&stela_linux_waiters);
}

long stela_linux_ioctl(int fd, unsigned int request, void *argument)
{
	struct file *file = fget((unsigned int)fd);

	if (!file)
		return -EBADF;
	long result = file->f_op->unlocked_ioctl ?
			      file->f_op->unlocked_ioctl(file, request, (unsigned long)argument) :
			      -ENOTTY;

	fput(file);
	return result;
}

int stela_linux_chrdev_open(dev_t device, unsigned int flags, struct file **result)
{
	if (unlikely(!__filp_cache))
		return -ENXIO;
	struct inode *inode = inode_of_mode(S_IFCHR | S_IRUSR | S_IWUSR);
	if (IS_ERR(inode))
		return (int)PTR_ERR(inode);
	inode->i_rdev = device;
	struct file *file = new_file(inode, &def_chr_fops, flags, NULL);
	if (IS_ERR(file))
		return (int)PTR_ERR(file);
	file->f_mode |= FMODE_READ | FMODE_WRITE;
	int error = def_chr_fops.open(inode, file);
	if (error) {
		/* chrdev_open already dropped any cdev reference it acquired. */
		file->f_op = NULL;
		fput(file);
		return error;
	}
	*result = file;
	return 0;
}

int stela_linux_open(dev_t device, unsigned int flags)
{
	struct file *file;
	int error = stela_linux_chrdev_open(device, flags, &file);

	if (error)
		return error;
	int fd = get_unused_fd_flags(flags);

	if (fd < 0)
		fput(file);
	else
		fd_install((unsigned int)fd, file);
	return fd;
}

struct pseudo_fs_context *init_pseudo(struct fs_context *context, unsigned long magic)
{
	struct pseudo_fs_context *pseudo = kzalloc_obj(*pseudo);

	if (pseudo) {
		pseudo->magic = magic;
		context->fs_private = pseudo;
	}
	return pseudo;
}

struct vfsmount *kern_mount(struct file_system_type *type)
{
	struct fs_context context = {.fs_type = type};
	struct vfsmount *mount = kzalloc_obj(*mount);
	struct super_block *block = kzalloc_obj(*block);
	int error = mount && block ? type->init_fs_context(&context) : -ENOMEM;

	if (error) {
		kfree(block);
		kfree(mount);
		return ERR_PTR(error);
	}
	struct pseudo_fs_context *pseudo = context.fs_private;
	error = get_anon_bdev(&block->s_dev);
	if (error) {
		kfree(pseudo);
		kfree(block);
		kfree(mount);
		return ERR_PTR(error);
	}

	block->s_magic = pseudo->magic;
	block->__s_d_op = pseudo->dops;
	mount->mnt_sb = block;
	kfree(pseudo);
	return mount;
}

void kern_unmount(struct vfsmount *mount)
{
	if (IS_ERR_OR_NULL(mount))
		return;
	free_anon_bdev(mount->mnt_sb->s_dev);
	kfree(mount->mnt_sb);
	kfree(mount);
}

int simple_pin_fs(struct file_system_type *type, struct vfsmount **mount, int *count)
{
	if (!*mount) {
		struct vfsmount *pinned = kern_mount(type);

		if (IS_ERR(pinned))
			return (int)PTR_ERR(pinned);
		*mount = pinned;
	}
	++*count;
	return 0;
}

void simple_release_fs(struct vfsmount **mount, int *count)
{
	if (--*count)
		return;
	kern_unmount(*mount);
	*mount = NULL;
}

/* Nothing tears a superblock down through its filesystem; kern_unmount frees it. */
STELA_UNSUPPORTED(void, kill_anon_super, struct super_block *)
/* Opening a second file on a path, which only DRM leases do. */
STELA_UNSUPPORTED(struct file *, dentry_open, const struct path *, int, const struct cred *)

#ifdef STELA_LINUX_FILE_TEST
#include <linux/init_task.h>
#include <linux/statfs.h>
#include <stela/linux.h>
#include <stela/page.h>
#include <stela/page_test.h>
#include <stela/test.h>

extern void __init chrdev_init(void);

static unsigned int opens, releases;
static int open_error;

static int test_open(struct inode *inode, struct file *file)
{
	assert(imajor(inode) == 226 && iminor(inode) == 3 && file->f_mapping == &inode->i_data);
	opens++;
	return open_error;
}

static int test_release(struct inode *inode, struct file *file)
{
	(void)inode;
	(void)file;
	releases++;
	return 0;
}

static const struct file_operations fops = {.open = test_open, .release = test_release};

static unsigned int dentries;

static void test_d_release(struct dentry *dentry)
{
	assert(dentry->d_fsdata == &dentries && dentry->d_sb->s_magic == 0x7e57);
	dentries++;
}

static const struct dentry_operations dentry_ops = {.d_release = test_d_release};

static int test_init_fs_context(struct fs_context *context)
{
	struct pseudo_fs_context *pseudo = init_pseudo(context, 0x7e57);

	if (!pseudo)
		return -ENOMEM;
	pseudo->dops = &dentry_ops;
	return 0;
}

static struct file_system_type test_fs = {
	.name = "test",
	.init_fs_context = test_init_fs_context,
};

/* Component-only binding for the original fdtable and resource limits. */
struct task_struct *__wrap_stela_linux_current(void);
struct task_struct *__wrap_stela_linux_current(void)
{
	return &init_task;
}

int main(void)
{
	stela_linux_enter(&stela_linux_bare);

	/* The final put closes the reference before its owner can free it. */
	file_ref_t reference;
	file_ref_init(&reference, 1);
	assert(file_ref_get(&reference));
	assert(!file_ref_put(&reference));
	assert(file_ref_put(&reference));
	assert((unsigned long)atomic_long_read(&reference.refcnt) == FILE_REF_DEAD);
	assert(!file_ref_get(&reference));

	stela_test_register_pages();
	files_init();
	chrdev_init();

	/* Recycle the same type-stable slot without publishing stale fields. */
	struct file *first = anon_inode_getfile("first", NULL, &opens, O_RDWR);
	assert(!IS_ERR(first) && first->f_cred == current_cred());
	first->f_pos = 99;
	fput(first);
	assert(!file_ref_get(&first->f_ref));
	struct file *reused = anon_inode_getfile("reused", NULL, NULL, O_RDONLY);
	assert(reused == first && !reused->f_pos && !reused->private_data);
	fput(reused);

	struct file *file;

	assert(stela_linux_chrdev_open(MKDEV(226, 3), 0, &file) == -ENXIO);
	assert(!__register_chrdev(226, 0, 8, "test", &fops));
	assert(stela_linux_chrdev_open(MKDEV(226, 8), 0, &file) == -ENXIO);
	open_error = -EPERM;
	assert(stela_linux_chrdev_open(MKDEV(226, 3), 0, &file) == -EPERM);
	assert(opens == 1 && !releases);
	open_error = 0;
	assert(!stela_linux_chrdev_open(MKDEV(226, 3), 0, &file));

	/* A descriptor holds its own reference; closing it drops that one. */
	int fd = get_unused_fd_flags(O_CLOEXEC);
	assert(fd == 0 && !fget(0) && get_unused_fd_flags(0) == 1);
	put_unused_fd(1);
	fd_install(0, get_file(file));
	assert(get_close_on_exec(0));
	struct file *looked_up = fget_task(&init_task, 0);
	assert(looked_up == file);
	fput(looked_up);
	struct fd borrowed = fdget(0);
	assert(fd_file(borrowed) == file);
	fdput(borrowed);
	assert(fd_empty(fdget(5)));
	stela_linux_fd_close(0);
	assert(!fget(0) && !releases);
	/* Cross the embedded table boundary and preserve the installed entry. */
	assert(get_unused_fd_flags(0) == 0);
	fd_install(0, get_file(file));
	for (unsigned int index = 1; index <= NR_OPEN_DEFAULT; index++)
		assert(get_unused_fd_flags(O_CLOEXEC) == (int)index);
	looked_up = fget_task(&init_task, 0);
	assert(looked_up == file && !get_close_on_exec(0));
	fput(looked_up);
	stela_linux_fd_close(0);
	fd_install(NR_OPEN_DEFAULT, get_file(file));
	assert(get_close_on_exec(NR_OPEN_DEFAULT));
	looked_up = fget_task(&init_task, NR_OPEN_DEFAULT);
	assert(looked_up == file);
	fput(looked_up);
	stela_linux_fd_close(NR_OPEN_DEFAULT);
	for (unsigned int index = 1; index < NR_OPEN_DEFAULT; index++)
		put_unused_fd(index);

	fput(file);
	assert(releases == 1);

	/* A client's descriptor, by what its system calls would do. */
	fd = stela_linux_open(MKDEV(226, 3), 0);
	assert(fd >= 0 && stela_linux_fd_device(fd) == MKDEV(226, 3));
	int copy = stela_linux_fd_dup(fd);
	assert(copy >= 0 && copy != fd);
	assert(stela_linux_ioctl(fd, 7, NULL) == -ENOTTY);
	stela_linux_fd_close(fd);
	assert(releases == 1);
	__unregister_chrdev(226, 0, 8, "test");
	assert(stela_linux_chrdev_open(MKDEV(226, 3), 0, &file) == -ENXIO);
	stela_linux_fd_close(copy);
	assert(releases == 2);
	assert(stela_linux_fd_dup(fd) == -EBADF && stela_linux_fd_device(fd) == -EBADF);
	assert(stela_linux_ioctl(fd, 7, NULL) == -EBADF);
	releases = 1;

	struct file *anonymous = anon_inode_getfile("test", &fops, &opens, O_RDWR);
	assert(!IS_ERR(anonymous) && anonymous->private_data == &opens);
	fput(anonymous);
	assert(releases == 2);

	struct file *object = shmem_file_setup("test", 8192, EMPTY_VMA_FLAGS);
	assert(!IS_ERR(object) && file_inode(object)->i_size == 8192);
	fput(object);

	struct vfsmount *mount = NULL;
	int count = 0;
	assert(!simple_pin_fs(&test_fs, &mount, &count) && mount && count == 1);
	struct vfsmount *pinned = mount;
	dev_t first_device = mount->mnt_sb->s_dev;
	assert(first_device && !MAJOR(first_device));
	struct vfsmount *other = kern_mount(&test_fs);
	assert(!IS_ERR(other) && other->mnt_sb->s_dev != first_device);
	kern_unmount(other);
	assert(!simple_pin_fs(&test_fs, &mount, &count) && mount == pinned && count == 2);
	simple_release_fs(&mount, &count);
	assert(mount == pinned);
	simple_release_fs(&mount, &count);
	assert(!mount && !count);

	/* A pseudo file's dentry is released after its file, with its inode. */
	mount = kern_mount(&test_fs);
	assert(!IS_ERR(mount) && mount->mnt_sb->s_dev == first_device);
	struct inode *inode = alloc_anon_inode(mount->mnt_sb);
	inode_set_bytes(inode, 1025);
	assert(inode->i_blocks == 2 && inode->i_bytes == 1);
	struct file *pseudo = alloc_file_pseudo(inode, mount, "dmabuf", O_RDWR, &fops);
	assert(!IS_ERR(pseudo) && pseudo->f_mode & FMODE_WRITE);
	struct kstatfs stats = {0};
	assert(!simple_statfs(pseudo->f_path.dentry, &stats));
	assert(stats.f_type == 0x7e57 && stats.f_bsize == PAGE_SIZE && stats.f_namelen == NAME_MAX);
	assert(pseudo->f_path.mnt == mount && !strcmp((const char *)pseudo->f_path.dentry->d_name.name, "dmabuf"));
	pseudo->f_path.dentry->d_fsdata = &dentries;
	fput(pseudo);
	assert(releases == 3 && dentries == 1);
	kern_unmount(mount);

	char name[8];
	assert(!strcmp(dynamic_dname(name, sizeof(name), "/%s", "ab"), "/ab"));
	assert(PTR_ERR(dynamic_dname(name, 3, "/%s", "ab")) == -ENAMETOOLONG);
	char long_name[96];
	char *formatted = dynamic_dname(long_name, sizeof(long_name), "%080u", 1U);
	assert(formatted == long_name + 15 && strlen(formatted) == 80 && formatted[79] == '1');
	stela_linux_exit();
	printf("Linux files and descriptors passed\n");
	return 0;
}
#endif
