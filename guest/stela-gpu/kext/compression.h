/*
 * StelaGPU has no universal buffer compression (compression_policy.h). The
 * kext says so once per boot, and while the any-user global preferences do
 * not yet name CoreVideo's `disable-buffer-compression`, stages a one-shot
 * launchd job (stela/compression.h, from `cargo xtask guest`) that sets it
 * with Apple's `defaults` as root and removes its own plist. A value the
 * owner set is kept: the kext and the job leave a named key alone.
 */
#pragma once

#include <sys/vnode.h>

/*
 * Logs the unsupported condition and stages the job when needed, through
 * `buffer` of kStelaChunk bytes. Only for a mounted Data volume.
 */
void stelaTellNoCompression(vfs_context_t context, char *buffer);
