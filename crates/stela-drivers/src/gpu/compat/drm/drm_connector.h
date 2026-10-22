/* SPDX-License-Identifier: MIT */
#ifndef STELA_DRM_CONNECTOR_H
#define STELA_DRM_CONNECTOR_H
#include <uapi/drm/drm_mode.h>
struct drm_device;

/* Copyright © 2016 Intel Corporation; from drm_connector.h. */
enum drm_connector_status {
	connector_status_connected = 1,
	connector_status_disconnected = 2,
	connector_status_unknown = 3,
};

/* The connector state unchanged sources read; Stela builds no KMS state. A
 * source that walks connectors declares the iterator calls it uses. */
struct drm_connector {
	enum drm_connector_status status;
	int dpms;
};
struct drm_connector_list_iter {
	struct drm_device *dev;
	struct drm_connector *conn;
};
static void drm_connector_list_iter_begin(struct drm_device *dev,
					  struct drm_connector_list_iter *iter);
static struct drm_connector *
drm_connector_list_iter_next(struct drm_connector_list_iter *iter);
static void drm_connector_list_iter_end(struct drm_connector_list_iter *iter);

/* Copyright © 2016 Intel Corporation; from drm_connector.h. */
#define drm_for_each_connector_iter(connector, iter) \
	while ((connector = drm_connector_list_iter_next(iter)))
#endif
