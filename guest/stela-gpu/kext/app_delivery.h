/*
 * Stela.app delivery: the packaged app `cargo xtask guest` embeds
 * (stela/app.h) reaches /Applications through a one-shot install job.
 *
 * A kext cannot create or rename a directory, and an app is a tree of them,
 * so the kext only stages: once the Data volume is mounted it compares the
 * installed app with the payload, and when the payload should replace it,
 * writes the payload's archive and the job's plist (each only when its
 * bytes differ) and reports `staged` in the StelaGPU service's StelaApp
 * property. launchd runs the job's script with Apple's own tools as root at
 * boot: it waits for that report, extracts, checks the signature, renames
 * the app into place and then removes its archive and plist.
 */
#pragma once

#include "app_policy.h"

#include <sys/vnode.h>

/*
 * Decides about the installed app and stages the payload when it should be
 * installed, through `buffer` of kStelaChunk bytes, logging the outcome once.
 * Answers the StelaApp report. Only for a mounted Data volume.
 */
const char *stelaDeliverApp(vfs_context_t context, char *buffer);
