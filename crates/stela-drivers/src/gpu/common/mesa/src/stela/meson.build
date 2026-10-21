# SPDX-License-Identifier: MIT
# These executables exercise the real compiler and its complete link closure.
# They do not open a device, submit GPU work, or expose a Metal device.
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
    stela_air_aco_probe = executable(
      'stela_air_aco_probe',
      'air_aco_probe.c',
      include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers],
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
    dependencies : [idep_aco, idep_nir, idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_compiler_support],
  )
  test('stela_aco_codegen', stela_aco_probe, suite : 'stela')
endif
