# SPDX-License-Identifier: MIT
# Stela's GPU compilers and their probes over Mesa's shader compilers, which
# build as the subproject `subprojects/mesa` (the `third_party/mesa` submodule)
# without graphics API frontends, window systems or device I/O.
project(
  'stela-gpu',
  ['c', 'cpp'],
  license : 'MIT',
  meson_version : '>= 1.7.0',
  # Mesa's own defaults, which its subproject cannot set for the build.
  default_options : [
    'buildtype=debugoptimized',
    'b_ndebug=if-release',
    'c_std=c11',
    'cpp_std=c++17',
  ],
)

fs = import('fs')
compilers = get_option('compilers')
with_nvidia = compilers.contains('nvidia')
with_amd = compilers.contains('amd')
with_intel = compilers.contains('intel')
with_amd_llvm = get_option('amd-llvm')
if with_amd_llvm and not with_amd
  error('amd-llvm requires the amd compilers')
endif

# Addrlib's Apple branch needs Apple's private addrExtDef.h; its public
# HAVE_TSERVER branch takes the normal C runtime headers instead.
if with_amd and host_machine.system() == 'darwin'
  add_global_arguments('-DHAVE_TSERVER', language : ['c', 'cpp'])
endif
if with_amd
  # Mesa's AMD support code uses libdrm's types but Stela never calls libdrm,
  # which builds only on DRM systems: its headers alone, from the submodule.
  libdrm = '../../../third_party/libdrm'
  if not fs.is_file(libdrm / 'xf86drm.h')
    error('third_party/libdrm is missing; run `cargo xtask gpu fetch`')
  endif
  meson.override_dependency('libdrm_amdgpu', declare_dependency(
    include_directories : include_directories(libdrm, libdrm / 'include/drm',
                                              libdrm / 'amdgpu'),
    version : '2.4.133',
  ))
endif
# A plain `git submodule update` checks Mesa out without Stela's series.
if not fs.read('subprojects/mesa/meson.options').contains('stela-compilers')
  error('third_party/mesa lacks Stela\'s patch series; run `cargo xtask gpu fetch`')
endif
mesa = subproject(
  'mesa',
  default_options : {
    'stela-compilers' : compilers,
    'platforms' : [],
    'gallium-drivers' : [],
    'vulkan-drivers' : [],
    'opengl' : false,
    'gles1' : 'disabled',
    'gles2' : 'disabled',
    'egl' : 'disabled',
    'gbm' : 'disabled',
    'glx' : 'disabled',
    'video-codecs' : [],
    'build-tests' : false,
    'intel-elk' : true,
    'llvm' : with_amd_llvm ? 'enabled' : 'disabled',
    'shared-llvm' : 'enabled',
    'draw-use-llvm' : false,
  },
)

# Stela's sources include Mesa's headers, so they compile as Mesa's do.
add_project_arguments(mesa.get_variable('pre_args'),
                      mesa.get_variable('c_cpp_args'), language : ['c', 'cpp'])
add_project_arguments(mesa.get_variable('c_args'), language : 'c')
add_project_arguments(mesa.get_variable('cpp_args'), language : 'cpp')
# Every target here, including the unchanged Mesa sources Stela builds itself,
# compiles without warnings.
add_project_arguments('-Werror', language : ['c', 'cpp'])

if with_amd_llvm
  dep_llvm = mesa.get_variable('dep_llvm')
  if not dep_llvm.version().version_compare('>=23.0') or dep_llvm.version().version_compare('>=24.0')
    error('The AMD LLVM backend currently requires LLVM 23')
  endif
endif

# The submodules, outside this project's source tree.
third_party = fs.parent(fs.parent(fs.parent(meson.project_source_root()))) / 'third_party'

subdir('compiler')
