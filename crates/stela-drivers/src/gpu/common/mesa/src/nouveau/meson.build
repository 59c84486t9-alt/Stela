# Copyright © 2021 Ilia Mirkin
# SPDX-License-Identifier: MIT

subdir('headers')
if not with_stela_nvidia
  subdir('drm')
  subdir('winsys')
endif
if with_nouveau_vk or with_stela_nvidia
  subdir('rust')
  subdir('nil')
  subdir('compiler')
endif
if with_tools.contains('drm-shim')
  subdir('drm-shim')
endif

if with_nouveau_vk
  subdir('cubin')
  subdir('mme')
  subdir('vulkan')
endif
