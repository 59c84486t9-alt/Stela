/* SPDX-License-Identifier: GPL-2.0 */
#ifndef STELA_LINUX_DEBUGFS_H
#define STELA_LINUX_DEBUGFS_H
/* Stela has no debugfs; drivers keep the blob they would publish there. */
/* Copyright (C) 2004 IBM Inc. and Greg Kroah-Hartman; from debugfs.h. */
struct debugfs_blob_wrapper {
	void *data;
	unsigned long size;
};
#endif
