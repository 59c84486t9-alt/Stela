# SPDX-License-Identifier: MIT
# These executables exercise the real compiler and its complete link closure.
# They do not open a device, submit GPU work, or expose a Metal device.
# Hosted source compilation is independent of Mesa and the physical backend.
# Resolve matching Apple LLVM functions dynamically; never link host LLVM here.
stela_apple_source = static_library(
  'stela_apple_source',
  '../../../../metal/compiler/apple_source.c',
  include_directories : include_directories('llvm/include'),
  dependencies : [dep_thread, dep_dl],
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
stela_apple_source_test = executable(
  'stela_apple_source_test',
  '../../../../metal/compiler/apple_source_test.c',
  link_with : stela_apple_source,
  dependencies : [dep_thread, dep_dl],
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
test('stela_apple_source_boundary', stela_apple_source_test, suite : 'stela')

stela_air_llvm = get_option('stela-air-llvm-library')
if stela_air_llvm != ''
  if not ['darwin', 'linux'].contains(host_machine.system())
    error('The AIR compiler currently requires a native Darwin or Linux LLVM 23 library')
  endif
  if not fs.is_absolute(stela_air_llvm) or not fs.is_file(stela_air_llvm)
    error('stela-air-llvm-library must name an existing absolute shared-library path')
  endif
  stela_air_llvm_dep = declare_dependency(
    include_directories : include_directories('llvm/include'),
    link_args : [stela_air_llvm],
  )
  stela_air = static_library(
    'stela_air_to_nir',
    'air_to_nir.c',
    include_directories : [inc_include, inc_src],
    dependencies : [idep_nir, idep_mesautil, stela_air_llvm_dep],
    c_args : ['-Werror'],
  )
  idep_stela_air = declare_dependency(
    link_with : [stela_air],
    include_directories : include_directories('.'),
    dependencies : [idep_nir, idep_mesautil, stela_air_llvm_dep],
  )
  stela_air_test_dependencies = [idep_stela_air]
  stela_air_test_links = []
  stela_air_test_args = ['-Werror']
  if with_stela_nvidia
    stela_air_test_dependencies += [idep_nak]
    stela_air_test_links += [_libnak_rs]
    stela_air_test_args += ['-DSTELA_AIR_TEST_NAK']
    stela_air_input_nak_probe = executable(
      'stela_air_input_nak_probe',
      'air_input_nak_probe.c',
      include_directories : [inc_include, inc_src],
      dependencies : [idep_stela_air, idep_nak],
      link_with : [_libnak_rs],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  stela_air_test = executable(
    'stela_air_test',
    'air_to_nir_test.c',
    include_directories : [inc_include, inc_src],
    dependencies : stela_air_test_dependencies,
    link_with : stela_air_test_links,
    c_args : stela_air_test_args,
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_air_to_nir', stela_air_test, suite : 'stela')
  stela_air_ssbo_test = executable(
    'stela_air_ssbo_test',
    'air_ssbo_test.c',
    include_directories : [inc_include, inc_src],
    dependencies : [idep_stela_air],
    c_args : ['-Werror'],
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_air_ssbo', stela_air_ssbo_test, suite : 'stela')
  if with_stela_amd
    if with_stela_amd_llvm
      stela_air_amd_llvm_probe = executable(
        'stela_air_amd_llvm_probe',
        '../../../../amd/tests/air_llvm_probe.c',
        include_directories : [inc_include, inc_src, inc_amd, inc_amd_common,
                               include_directories('.')],
        # Keep the full matching development headers. idep_stela_air exposes
        # the narrow C-only header set, unsuitable for this C++ LLVM backend.
        dependencies : [idep_nir, idep_mesautil, dep_llvm, idep_amd_generated_headers],
        link_with : [stela_air, libamd_common_llvm, libamd_compiler_support],
        c_args : ['-Werror'],
        build_rpath : fs.parent(stela_air_llvm),
      )
      test('stela_air_amd_llvm', stela_air_amd_llvm_probe, suite : 'stela')
    endif
    stela_air_aco_probe = executable(
      'stela_air_aco_probe',
      'air_aco_probe.c',
      include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers] +
                     (with_stela_amd_llvm ? [dep_llvm] : []),
      link_with : [libamd_compiler_support],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_aco', stela_air_aco_probe, suite : 'stela')
  endif
  if with_stela_intel
    stela_air_brw_probe = executable(
      'stela_air_brw_probe',
      '../../../../intel/stela/tests/air_brw_probe.c',
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw, idep_intel_dev],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_brw', stela_air_brw_probe, suite : 'stela')
    stela_air_elk_probe = executable(
      'stela_air_elk_probe',
      '../../../../intel/stela/tests/air_elk_probe.c',
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_elk,
                      idep_intel_compiler_gen, idep_intel_dev],
      link_with : [libisl],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_elk', stela_air_elk_probe, suite : 'stela')
  endif
endif

if with_stela_nvidia
  stela_nv_compute = static_library(
    'stela_nv_compute',
    ['nvidia_compute.c', stela_nv_compute_headers],
    include_directories : [inc_include, inc_src,
                           include_directories('../nouveau/headers', '../nouveau/headers/nvidia/classes')],
    dependencies : [idep_nak, idep_nir_headers, idep_mesautil],
    c_args : ['-Werror'],
  )
  if stela_air_llvm != ''
    stela_nv_compute_probe = executable(
      'stela_nv_compute_probe',
      'nvidia_compute_probe.c',
      include_directories : [inc_include, inc_src,
                             include_directories('../nouveau/headers', '../nouveau/headers/nvidia/classes')],
      dependencies : [idep_stela_air, idep_nak],
      link_with : [stela_nv_compute, _libnak_rs],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_nv_compute', stela_nv_compute_probe, suite : 'stela')
  endif
  stela_nak_probe = executable(
    'stela_nak_probe',
    'nak_probe.c',
    include_directories : [inc_include, inc_src],
    dependencies : [idep_nak, idep_nir, idep_mesautil],
    link_with : [_libnak_rs],
  )
  test('stela_nak_codegen', stela_nak_probe, suite : 'stela')
endif

if with_stela_intel
  stela_intel_surface = static_library(
    'stela_intel_surface',
    '../../../../intel/stela/hosted/surface.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [libisl],
    c_args : ['-Werror'],
  )
  stela_intel_surface_probe = executable(
    'stela_intel_surface_probe',
    '../../../../intel/stela/tests/surface.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_surface', stela_intel_surface_probe, suite : 'stela')
  stela_elk_probe = executable(
    'stela_elk_probe',
    'elk_probe.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [idep_intel_compiler_elk, idep_intel_compiler_gen,
                    idep_intel_dev, idep_mesautil],
    link_with : [libisl],
  )
  test('stela_elk_codegen', stela_elk_probe, suite : 'stela')
  stela_brw_probe = executable(
    'stela_brw_probe',
    'brw_probe.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_dev, idep_mesautil],
  )
  test('stela_brw_codegen', stela_brw_probe, suite : 'stela')
endif

if with_stela_amd
  stela_amd_buffer = static_library(
    'stela_amd_buffer',
    '../../../../amd/stela/buffer.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_compiler_support],
    c_args : ['-Werror'],
  )
  stela_amd_buffer_probe = executable(
    'stela_amd_buffer_probe',
    '../../../../amd/tests/buffer_test.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_buffer, libamd_compiler_support],
    c_args : ['-Werror'],
  )
  test('stela_amd_buffer', stela_amd_buffer_probe, suite : 'stela')
  stela_amd_commands = static_library(
    'stela_amd_commands',
    'amd_commands.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_command_support],
  )

  stela_amd_commands_probe = executable(
    'stela_amd_commands_probe',
    'amd_commands_probe.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_commands, libamd_command_support],
  )
  test('stela_amd_commands', stela_amd_commands_probe, suite : 'stela')

  stela_aco_probe = executable(
    'stela_aco_probe',
    'aco_probe.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_aco, idep_nir, idep_mesautil, idep_amd_generated_headers] +
                   (with_stela_amd_llvm ? [dep_llvm] : []),
    link_with : [libamd_compiler_support],
  )
  test('stela_aco_codegen', stela_aco_probe, suite : 'stela')
endif
