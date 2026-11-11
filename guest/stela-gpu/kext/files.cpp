#include "files.h"

#include <IOKit/IOLib.h>
#include <sys/errno.h>
#include <sys/fcntl.h>

/*
 * Opens `path` without following its last component, and only as a regular
 * file: anything else, a FIFO or a device someone placed there, answers
 * EFTYPE. A file that exists is looked at before it is opened, so a device
 * is never opened; the open does not block, so a FIFO swapped in meanwhile
 * cannot hold the thread, and is refused once open.
 */
static int
openRegular(const char *path, int flags, int mode, vnode_t *vnode, vfs_context_t context)
{
	vnode_t found = NULLVP;
	int error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &found, context);
	if (!error) {
		bool regular = vnode_isreg(found);
		vnode_put(found);
		if (!regular) {
			return EFTYPE;
		}
	} else if (error != ENOENT || !(flags & O_CREAT)) {
		return error;
	}
	error = vnode_open(path, flags | O_NOFOLLOW | O_NONBLOCK, mode, 0, vnode, context);
	if (!error && !vnode_isreg(*vnode)) {
		vnode_close(*vnode, flags & (FREAD | FWRITE), context);
		*vnode = NULLVP;
		return EFTYPE;
	}
	return error;
}

int
stelaDigestFile(const char *path, vfs_context_t context, char *buffer, unsigned char digest[SHA256_DIGEST_LENGTH],
    off_t *length)
{
	vnode_t file = NULLVP;
	int error = openRegular(path, FREAD, 0, &file, context);
	if (error) {
		return error;
	}
	SHA256_CTX hash;
	SHA256_Init(&hash);
	off_t offset = 0;
	for (;;) {
		int left = 0;
		error = vn_rdwr(UIO_READ, file, buffer, kStelaChunk, offset, UIO_SYSSPACE, IO_NOAUTH,
		    vfs_context_ucred(context), &left, vfs_context_proc(context));
		if (error || left == kStelaChunk) {
			break;
		}
		SHA256_Update(&hash, buffer, kStelaChunk - left);
		offset += kStelaChunk - left;
	}
	vnode_close(file, FREAD, context);
	if (!error) {
		SHA256_Final(digest, &hash);
		*length = offset;
	}
	return error;
}

int
stelaMatches(const char *path, const unsigned char sha256[SHA256_DIGEST_LENGTH], unsigned long length,
    vfs_context_t context, char *buffer, bool *same)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	off_t found = 0;
	int error = stelaDigestFile(path, context, buffer, digest, &found);
	*same = !error && found == off_t(length) && !memcmp(digest, sha256, sizeof digest);
	return error;
}

int
stelaWriteFile(const char *path, const unsigned char *bytes, unsigned long length, unsigned mode,
    vfs_context_t context)
{
	vnode_t vnode = NULLVP;
	int error = openRegular(path, FWRITE | O_CREAT | O_TRUNC, int(mode), &vnode, context);
	if (error) {
		return error;
	}
	for (unsigned long offset = 0; !error && offset < length;) {
		int chunk = int(IOMin(length - offset, (unsigned long)kStelaChunk));
		int left = 0;
		// A write does not modify its source.
		error = vn_rdwr(UIO_WRITE, vnode, const_cast<char *>(reinterpret_cast<const char *>(bytes + offset)),
		    chunk, offset, UIO_SYSSPACE, IO_NOAUTH | IO_SYNC, vfs_context_ucred(context), &left,
		    vfs_context_proc(context));
		if (!error && left != 0) {
			error = EIO;
		}
		offset += chunk;
	}
	int closed = vnode_close(vnode, FWRITE, context);
	return error ? error : closed;
}

int
stelaReadFile(const char *path, char *buffer, int capacity, int *length, vfs_context_t context)
{
	vnode_t file = NULLVP;
	int error = openRegular(path, FREAD, 0, &file, context);
	if (error) {
		return error;
	}
	int left = 0;
	// One byte past the capacity tells a full buffer from a longer file.
	char probe = 0;
	error = vn_rdwr(UIO_READ, file, buffer, capacity, 0, UIO_SYSSPACE, IO_NOAUTH, vfs_context_ucred(context), &left,
	    vfs_context_proc(context));
	if (!error && left == 0) {
		int beyond = 0;
		error = vn_rdwr(UIO_READ, file, &probe, 1, capacity, UIO_SYSSPACE, IO_NOAUTH, vfs_context_ucred(context),
		    &beyond, vfs_context_proc(context));
		if (!error && beyond == 0) {
			error = EFBIG;
		}
	}
	vnode_close(file, FREAD, context);
	if (!error) {
		*length = capacity - left;
	}
	return error;
}
