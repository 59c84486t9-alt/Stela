#include "compression.h"
#include "compression_policy.h"
#include "files.h"

#include <IOKit/IOLib.h>
#include <stela/compression.h>
#include <sys/errno.h>

void
stelaTellNoCompression(vfs_context_t context, char *buffer)
{
	int length = 0;
	int error = stelaReadFile(STELA_COMPRESSION_PREFERENCES_PATH, buffer, kStelaChunk, &length, context);
	if (!error && stela_compression_key_named(buffer, length, STELA_COMPRESSION_KEY)) {
		IOLog("StelaGPU: this GPU has no universal buffer compression; the global preferences name "
		      "%s already\n",
		    STELA_COMPRESSION_KEY);
		return;
	}
	// A list too long to read here, or none yet: the job looks for itself.
	if (error && error != ENOENT && error != EFBIG) {
		IOLog("StelaGPU: reading %s failed: %d\n", STELA_COMPRESSION_PREFERENCES_PATH, error);
	}
	error = stelaStage(STELA_COMPRESSION_JOB_PATH, stela_compression_job, sizeof stela_compression_job,
	    stela_compression_job_sha256, 0644, context, buffer);
	if (error) {
		IOLog("StelaGPU: this GPU has no universal buffer compression; staging the job that sets %s "
		      "failed: %d\n",
		    STELA_COMPRESSION_KEY, error);
		return;
	}
	IOLog("StelaGPU: this GPU has no universal buffer compression; staged the job that sets %s in the "
	      "global preferences\n",
	    STELA_COMPRESSION_KEY);
}
