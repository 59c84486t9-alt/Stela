#include "app_delivery.h"
#include "files.h"

#include <IOKit/IOLib.h>
#include <stela/app.h>
#include <sys/errno.h>

#if STELA_APP_PRESENT

/* The longest identifier or version compared; longer ones are not Stela's. */
static const unsigned long kStringBytes = 64;

/* Fills `installed` from the app at STELA_APP_PATH, through `buffer`. */
static int
inspect(struct stela_app_installed *installed, char identifier[kStringBytes], char version[kStringBytes],
    vfs_context_t context, char *buffer)
{
	vnode_t app = NULLVP;
	int error = vnode_lookup(STELA_APP_PATH, VNODE_LOOKUP_NOFOLLOW, &app, context);
	if (error == ENOENT) {
		return 0;
	}
	if (error) {
		return error;
	}
	installed->present = 1;
	bool directory = vnode_isdir(app);
	vnode_put(app);
	if (!directory) {
		return 0;
	}
	int length = 0;
	error = stelaReadFile(STELA_APP_PATH "/Contents/Info.plist", buffer, kStelaChunk, &length, context);
	if (error == ENOENT || error == EFBIG || error == ELOOP || error == EFTYPE) {
		return 0;
	}
	if (error) {
		return error;
	}
	installed->readable = stela_app_plist_string(buffer, length, "CFBundleIdentifier", identifier, kStringBytes) &&
	    stela_app_plist_string(buffer, length, "CFBundleShortVersionString", version, kStringBytes);
	installed->identifier = identifier;
	installed->version = version;
	if (!installed->readable) {
		return 0;
	}
	installed->files_match = 1;
	for (const stela_app_file &file : stela_app_files) {
		char path[256];
		int written = snprintf(path, sizeof path, "%s/%s", STELA_APP_PATH, file.path);
		if (written < 0 || size_t(written) >= sizeof path) {
			// `cargo xtask guest` refuses such paths; a cut one would never match.
			return ENAMETOOLONG;
		}
		bool same = false;
		error = stelaMatches(path, file.sha256, file.length, context, buffer, &same);
		// Something else in the file's place (a link, a FIFO) differs.
		if (error && error != ENOENT && error != ELOOP && error != EFTYPE) {
			return error;
		}
		if (!same) {
			installed->files_match = 0;
			break;
		}
	}
	return 0;
}

/* Writes `length` bytes to `path` unless it holds them already, and checks them. */
static int
stage(const char *path, const unsigned char *bytes, unsigned long length, const unsigned char sha256[32], unsigned mode,
    vfs_context_t context, char *buffer)
{
	bool same = false;
	int error = stelaMatches(path, sha256, length, context, buffer, &same);
	if (same) {
		return 0;
	}
	if (error && error != ENOENT) {
		return error;
	}
	error = stelaWriteFile(path, bytes, length, mode, context);
	if (!error) {
		error = stelaMatches(path, sha256, length, context, buffer, &same);
	}
	return !error && !same ? EIO : error;
}

const char *
stelaDeliverApp(vfs_context_t context, char *buffer)
{
	struct stela_app_installed installed = {0, 0, "", "", 0};
	char identifier[kStringBytes] = "";
	char version[kStringBytes] = "";
	int error = inspect(&installed, identifier, version, context, buffer);
	if (error) {
		IOLog("StelaGPU: reading %s failed: %d; Stela.app is not staged\n", STELA_APP_PATH, error);
		return STELA_APP_FAILED_REPORT;
	}
	switch (stela_app_decide(&installed, STELA_APP_IDENTIFIER, STELA_APP_VERSION)) {
	case STELA_APP_CURRENT:
		IOLog("StelaGPU: Stela.app %s (%s) is current\n", STELA_APP_VERSION, STELA_APP_REVISION);
		return STELA_APP_CURRENT_REPORT;
	case STELA_APP_KEEP_NEWER:
		IOLog("StelaGPU: keeping the installed Stela.app %s, newer than this build's %s\n", version,
		    STELA_APP_VERSION);
		return STELA_APP_NEWER_REPORT;
	case STELA_APP_KEEP_FOREIGN:
		IOLog("StelaGPU: %s is not a Stela.app this build can compare; leaving it\n", STELA_APP_PATH);
		return STELA_APP_FOREIGN_REPORT;
	case STELA_APP_INSTALL:
		break;
	}
	// The archive first: the job installs only after this boot's report,
	// which follows both files' checks.
	error = stage(STELA_APP_ARCHIVE_PATH, stela_app_archive, sizeof stela_app_archive, stela_app_archive_sha256, 0600,
	    context, buffer);
	if (!error) {
		error = stage(STELA_APP_JOB_PATH, stela_app_job, sizeof stela_app_job, stela_app_job_sha256, 0644, context,
		    buffer);
	}
	if (error) {
		IOLog("StelaGPU: staging Stela.app failed: %d\n", error);
		return STELA_APP_FAILED_REPORT;
	}
	IOLog("StelaGPU: staged Stela.app %s (%s) for its install job\n", STELA_APP_VERSION, STELA_APP_REVISION);
	return STELA_APP_STAGED;
}

#else

const char *
stelaDeliverApp(vfs_context_t, char *)
{
	IOLog("StelaGPU: this stela.efi carries no Stela.app; nothing is installed or changed\n");
	return STELA_APP_ABSENT_REPORT;
}

#endif
