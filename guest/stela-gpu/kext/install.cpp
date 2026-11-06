/*
 * The Metal plugin the kext carries (stela/bundle.h), installed over the one
 * in /Library/GPUBundles before the accelerator is published, so Metal only
 * ever loads the plugin whose code this boot's trust cache lists.
 *
 * The kernel lets a kext open, create and write files but not create
 * directories. The kext rewrites a stale file in place, which keeps its
 * inode with its restricted flag and extended attributes, and creates a
 * missing one; a plugin whose directories are absent it reports instead.
 */
#include "StelaGPU.h"

#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <libkern/crypto/sha2.h>
#include <stela/bundle.h>
#include <stela/gate.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>

/*
 * The plugin on the Data volume, which /Library is a firmlink to. Looking
 * there waits for the volume to mount, where /Library would find the system
 * volume's directory beneath it.
 */
static const char kPlugins[] = "/System/Volumes/Data/Library/GPUBundles";
static const char kPlugin[] = "/System/Volumes/Data/Library/GPUBundles/StelaGPU.bundle/";
/* How often the installer looks for the Data volume, in milliseconds. */
static const unsigned kMountPoll = 50;
/* The bytes read or written at a time. */
static const int kChunk = 64 * 1024;

/* The SHA-256 and length of `path`'s bytes, through `buffer` of kChunk bytes. */
static int
digestFile(const char *path, vfs_context_t context, char *buffer, unsigned char digest[SHA256_DIGEST_LENGTH],
    off_t *length)
{
	vnode_t file = NULLVP;
	int error = vnode_open(path, FREAD | O_NOFOLLOW, 0, 0, &file, context);
	if (error) {
		return error;
	}
	SHA256_CTX hash;
	SHA256_Init(&hash);
	off_t offset = 0;
	for (;;) {
		int left = 0;
		error = vn_rdwr(UIO_READ, file, buffer, kChunk, offset, UIO_SYSSPACE, IO_NOAUTH,
		    vfs_context_ucred(context), &left, vfs_context_proc(context));
		if (error || left == kChunk) {
			break;
		}
		SHA256_Update(&hash, buffer, kChunk - left);
		offset += kChunk - left;
	}
	vnode_close(file, FREAD, context);
	if (!error) {
		SHA256_Final(digest, &hash);
		*length = offset;
	}
	return error;
}

/* Whether `path` holds `file`'s bytes, through `buffer` of kChunk bytes. */
static int
matches(const char *path, const stela_bundle_file &file, vfs_context_t context, char *buffer, bool *same)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	off_t length = 0;
	int error = digestFile(path, context, buffer, digest, &length);
	*same = !error && length == off_t(file.length) && !memcmp(digest, file.sha256, sizeof digest);
	return error;
}

/* Writes `file`'s bytes to `path` in place, creating it if absent. */
static int
writeFile(const char *path, const stela_bundle_file &file, vfs_context_t context)
{
	vnode_t vnode = NULLVP;
	int error = vnode_open(path, FWRITE | O_CREAT | O_TRUNC | O_NOFOLLOW, file.mode, 0, &vnode, context);
	if (error) {
		return error;
	}
	for (unsigned long offset = 0; !error && offset < file.length;) {
		int bytes = int(IOMin(file.length - offset, (unsigned long)kChunk));
		int left = 0;
		// A write does not modify its source.
		error = vn_rdwr(UIO_WRITE, vnode, const_cast<char *>(reinterpret_cast<const char *>(file.bytes + offset)),
		    bytes, offset, UIO_SYSSPACE, IO_NOAUTH | IO_SYNC, vfs_context_ucred(context), &left,
		    vfs_context_proc(context));
		if (!error && left != 0) {
			error = EIO;
		}
		offset += bytes;
	}
	int closed = vnode_close(vnode, FWRITE, context);
	return error ? error : closed;
}

/* Installs each file that differs, answering the gate's BUNDLE report. */
static uint64_t
install(vfs_context_t context, char *buffer)
{
	uint64_t report = STELA_GATE_BUNDLE_CURRENT;
	for (const stela_bundle_file &file : stela_bundle_files) {
		char path[256];
		snprintf(path, sizeof path, "%s%s", kPlugin, file.path);
		bool same = false;
		int error = matches(path, file, context, buffer, &same);
		if (same) {
			continue;
		}
		if (error && error != ENOENT) {
			IOLog("StelaGPU: reading %s failed: %d\n", path, error);
			return STELA_GATE_BUNDLE_FAILED;
		}
		error = writeFile(path, file, context);
		if (error == ENOENT) {
			IOLog("StelaGPU: %s cannot be created: its directory is absent\n", path);
			return STELA_GATE_BUNDLE_MISSING;
		}
		if (!error) {
			error = matches(path, file, context, buffer, &same);
		}
		if (!error && !same) {
			error = EIO;
		}
		if (error) {
			IOLog("StelaGPU: writing %s failed: %d\n", path, error);
			return STELA_GATE_BUNDLE_FAILED;
		}
		IOLog("StelaGPU: installed %s from stela.efi\n", path);
		report = STELA_GATE_BUNDLE_UPDATED;
	}
	return report;
}

bool
StelaGPU::isStopping()
{
	IOLockLock(lock);
	bool stopped = stopping;
	IOLockUnlock(lock);
	return stopped;
}

void
StelaGPU::installPlugin(void *parameter, wait_result_t)
{
	auto gpu = static_cast<StelaGPU *>(parameter);
	uint64_t report = STELA_GATE_BUNDLE_FAILED;
	vfs_context_t context = vfs_context_create(nullptr);
	auto buffer = static_cast<char *>(IOMallocData(kChunk));
	bool stopping = false;
	if (context && buffer) {
		vnode_t plugins = NULLVP;
		while (!(stopping = gpu->isStopping()) && vnode_lookup(kPlugins, 0, &plugins, context) != 0) {
			IOSleep(kMountPoll);
		}
		if (!stopping) {
			vnode_put(plugins);
			report = install(context, buffer);
		}
	} else {
		IOLog("StelaGPU: the plugin's installer cannot allocate\n");
	}
	if (buffer) {
		IOFreeData(buffer, kChunk);
	}
	if (context) {
		vfs_context_rele(context);
	}
	IOLockLock(gpu->lock);
	stopping = gpu->stopping;
	if (!stopping) {
		gpu->write(STELA_GATE_BUNDLE, report);
	}
	IOLockUnlock(gpu->lock);
	if (!stopping && (report == STELA_GATE_BUNDLE_CURRENT || report == STELA_GATE_BUNDLE_UPDATED)) {
		gpu->registerService();
	}
	gpu->release();
}
