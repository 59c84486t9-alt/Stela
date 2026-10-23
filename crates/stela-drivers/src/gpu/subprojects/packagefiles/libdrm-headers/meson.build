# SPDX-License-Identifier: MIT
# libdrm's headers alone, the version Mesa's own wrap pins. Mesa's AMD support
# code uses libdrm's types but Stela never calls it, and libdrm builds only on
# DRM systems, so this replaces libdrm's build rather than configuring it.
project('libdrm-headers', 'c', version : '2.4.133')

meson.override_dependency('libdrm_amdgpu', declare_dependency(
  include_directories : include_directories('.', 'include/drm', 'amdgpu'),
  version : meson.project_version(),
))
