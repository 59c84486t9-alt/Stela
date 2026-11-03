// SPDX-License-Identifier: MIT
/* Copies to and from clients, with the interfaces of Linux
 * cc9de5d4b5ab6459f5774946aa3195ad51236fa8 lib/usercopy.c and mm/util.c. A
 * user pointer belongs to the client the running ioctl serves, in an address
 * space only the owner can reach. An owner without clients has no valid user
 * pointer, so every copy faults. */
#include <linux/bug.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <stela/linux.h>

unsigned long raw_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	if (!owner->services->copy_from_user)
		return n;
	return owner->services->copy_from_user(owner->context, to, (const void __force *)from, n);
}

unsigned long raw_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	const struct stela_linux_owner *owner = stela_linux_owner();

	if (!owner->services->copy_to_user)
		return n;
	return owner->services->copy_to_user(owner->context, (void __force *)to, from, n);
}

/* As Linux's: what a faulting copy did not reach reads as zeroes. */
unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long left = raw_copy_from_user(to, from, n);

	if (left)
		memset((char *)to + (n - left), 0, left);
	return left;
}

unsigned long _copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return raw_copy_to_user(to, from, n);
}

void __copy_overflow(int size, unsigned long count)
{
	WARN(1, "Buffer overflow detected (%d < %lu)!\n", size, count);
}

static void *duplicate(void *copy, const void __user *source, size_t size)
{
	if (!copy)
		return ERR_PTR(-ENOMEM);
	if (copy_from_user(copy, source, size)) {
		kvfree(copy);
		return ERR_PTR(-EFAULT);
	}
	return copy;
}

void *memdup_user(const void __user *source, size_t size)
{
	return duplicate(kmalloc(size, GFP_USER | __GFP_NOWARN), source, size);
}

void *vmemdup_user(const void __user *source, size_t size)
{
	return duplicate(kvmalloc(size, GFP_USER), source, size);
}

void *memdup_user_nul(const void __user *source, size_t size)
{
	char *copy = duplicate(kmalloc(size + 1, GFP_USER), source, size);

	if (!IS_ERR(copy))
		copy[size] = '\0';
	return copy;
}

long strncpy_from_user(char *destination, const char __user *source, long count)
{
	long copied = 0;

	/* Stage each word so the destination is only written through its NUL.
	 * A client provider may refuse the whole word at a mapping boundary. */
	while (count - copied >= (long)sizeof(unsigned long)) {
		char word[sizeof(unsigned long)];

		if (raw_copy_from_user(word, source + copied, sizeof(word)))
			break;
		char *end = memchr(word, 0, sizeof(word));

		if (end) {
			size_t length = (size_t)(end - word);

			memcpy(destination + copied, word, length + 1);
			return copied + (long)length;
		}
		memcpy(destination + copied, word, sizeof(word));
		copied += (long)sizeof(word);
	}

	for (; copied < count; copied++) {
		char byte;

		if (raw_copy_from_user(&byte, source + copied, 1))
			return -EFAULT;
		destination[copied] = byte;
		if (!byte)
			return copied;
	}
	return copied;
}

/* The string ends where a read of it does: no bound is known beforehand. */
char *strndup_user(const char __user *source, long limit)
{
	char *copy = kmalloc((size_t)limit, GFP_USER | __GFP_NOWARN);

	if (!copy)
		return ERR_PTR(-ENOMEM);
	for (long i = 0; i < limit; i++) {
		if (copy_from_user(copy + i, source + i, 1)) {
			kfree(copy);
			return ERR_PTR(-EFAULT);
		}
		if (!copy[i])
			return copy;
	}
	kfree(copy);
	return ERR_PTR(-EINVAL);
}

#ifdef STELA_LINUX_USERCOPY_TEST
#include <stela/test.h>

static char client[8] = "abcdefg";
static unsigned long limit = sizeof(client);

/* The fake client's memory ends at limit. */
static unsigned long read_client(void *context, void *to, const void *from, unsigned long n)
{
	(void)context;
	unsigned long reachable = (unsigned long)(client + limit - (const char *)from);
	unsigned long done = min(n, reachable);

	memcpy(to, from, done);
	return n - done;
}

static unsigned long write_client(void *context, void *to, const void *from, unsigned long n)
{
	(void)context;
	memcpy(to, from, n);
	return 0;
}

int main(void)
{
	char buffer[8];
	const struct stela_linux_services services = {
		.copy_from_user = read_client,
		.copy_to_user = write_client,
	};
	const struct stela_linux_owner owner = {.services = &services};

	stela_linux_enter(&stela_linux_bare);
	memset(buffer, 'x', sizeof(buffer));
	assert(copy_from_user(buffer, (const char __user *)client, 4) == 4 && !buffer[0]);
	assert(copy_to_user((char __user *)client, buffer, 4) == 4);
	stela_linux_exit();

	stela_linux_enter(&owner);
	limit = 3;
	memset(buffer, 'x', sizeof(buffer));
	assert(copy_from_user(buffer, (const char __user *)client, 5) == 2);
	assert(!memcmp(buffer, "abc\0\0x", 6));
	assert(PTR_ERR(memdup_user((const char __user *)client, 5)) == -EFAULT);
	assert(PTR_ERR(vmemdup_user((const char __user *)client, 5)) == -EFAULT);
	limit = sizeof(client);
	assert(!copy_to_user((char __user *)client, "XY", 2) && client[1] == 'Y');
	char *copy = memdup_user_nul((const char __user *)client, 3);
	assert(!strcmp(copy, "XYc"));
	kfree(copy);
	copy = vmemdup_user((const char __user *)client, 2);
	assert(copy[0] == 'X');
	kvfree(copy);
	copy = strndup_user((const char __user *)client, sizeof(client));
	assert(!strcmp(copy, "XYcdefg"));
	kfree(copy);
	assert(PTR_ERR(strndup_user((const char __user *)client, 3)) == -EINVAL);
	limit = 3;
	assert(PTR_ERR(strndup_user((const char __user *)client, sizeof(client))) == -EFAULT);

	memset(buffer, 'x', sizeof(buffer));
	assert(strncpy_from_user(buffer, client, sizeof(buffer)) == -EFAULT);
	assert(!memcmp(buffer, "XYcxxxxx", sizeof(buffer)));
	client[2] = 0;
	assert(strncpy_from_user(buffer, client, sizeof(buffer)) == 2);
	assert(!memcmp(buffer, "XY\0x", 4));
	limit = sizeof(client);
	assert(strncpy_from_user(buffer, client, sizeof(buffer)) == 2);
	assert(strncpy_from_user(buffer, client, 2) == 2);
	assert(strncpy_from_user(buffer, client, 0) == 0);
	stela_linux_exit();
	printf("Linux user copies passed\n");
	return 0;
}
#endif
