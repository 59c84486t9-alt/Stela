# SPDX-License-Identifier: MIT
# These executables exercise the real compiler and its complete link closure.
# They do not open a device, submit GPU work, or expose a Metal device.
# Hosted source compilation is independent of Mesa and the physical backend.
# Resolve matching Apple LLVM functions dynamically; never link host LLVM here.
# Stela links unchanged upstream sources and archives whose unused functions
# reach device and OS services it does not provide; the linker drops them.
#
# `cargo xtask gpu compilers` builds every target defined here and runs every
# test in suite 'stela'. Tests also in 'stela-air-input' compile a raw AIR
# input given as --input FILE --entry NAME --fp-profile NAME; tests in
# 'stela-owned-air' accept the owned compilers' threadgroup input modes.
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

# Mesa's targets and include directories, and its source tree for the few
# unchanged sources and generators Stela builds itself. Meson keeps a
# subproject's files to the subproject, so those are named through the
# submodule rather than `subprojects/mesa`.
mesa_src = third_party / 'mesa/src'
# LLVM's C API headers, with Stela's statement of the build configuration
# they include.
llvm_include = include_directories('llvm/include', third_party / 'llvm/llvm/include')
inc_gpu = include_directories('..')
foreach name : ['inc_include', 'inc_src', 'idep_mesautil', 'idep_nir',
                'idep_nir_headers', 'dep_thread', 'dep_dl', 'dep_m', 'prog_python']
  set_variable(name, mesa.get_variable(name))
endforeach
if with_nvidia
  foreach name : ['_libnak_rs', 'idep_nak', 'idep_nil']
    set_variable(name, mesa.get_variable(name))
  endforeach
  nvidia_headers = include_directories(mesa_src / 'nouveau/headers',
                                       mesa_src / 'nouveau/headers/nvidia/classes')
  # The compute classes' generated push-buffer headers.
  nv_classes = mesa.get_variable('nv_classes')
  stela_nv_compute_headers = []
  foreach i : range(nv_classes.length())
    if ['cla0c0', 'clc6c0'].contains(nv_classes[i])
      stela_nv_compute_headers += mesa.get_variable('cl_generated')[i][0]
    endif
  endforeach
endif
if with_amd
  foreach name : ['inc_amd', 'inc_amd_common', 'inc_gallium', 'idep_aco',
                  'idep_amd_generated_headers', 'libamd_common', 'cpp_args_addrlib',
                  'no_override_init_args']
    set_variable(name, mesa.get_variable(name))
  endforeach
  if with_amd_llvm
    libamd_common_llvm = mesa.get_variable('libamd_common_llvm')
  endif
endif
if with_intel
  foreach name : ['inc_intel', 'inc_gallium', 'idep_intel_compiler_brw',
                  'idep_intel_compiler_elk', 'idep_intel_compiler_gen',
                  'idep_intel_dev', 'idep_genxml', 'libisl', 'gen_pack_header_deps']
    set_variable(name, mesa.get_variable(name))
  endforeach
  intel_genxml = mesa_src / 'intel/genxml'
endif

stela_sections = cc.get_supported_arguments(['-ffunction-sections', '/Gy'])
stela_dead_strip = cpp.get_supported_link_arguments(
  ['-Wl,-dead_strip', '-Wl,--gc-sections', '/OPT:REF'])
# NAK reads its frontend's constant-buffer layout from globals NVK defines;
# Stela defines its own.
if with_nvidia
  stela_nak = [_libnak_rs, static_library(
    'stela_nak_layout',
    '../nvidia/hosted/nak_layout.c',
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : [idep_nak, idep_nir_headers],
    c_args : ['-Werror'],
  )]
endif
# With LLVM, ACO disassembles through the AMD LLVM helpers.
stela_aco_links = []
if with_amd_llvm
  stela_aco_links = [libamd_common_llvm]
endif

stela_apple_source = static_library(
  'stela_apple_source',
  'apple_source.c',
  include_directories : llvm_include,
  dependencies : [dep_thread, dep_dl],
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
stela_apple_source_test = executable(
  'stela_apple_source_test',
  'tests/apple_source.c',
  link_with : stela_apple_source,
  dependencies : [dep_thread, dep_dl],
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
test('stela_apple_source_boundary', stela_apple_source_test, suite : 'stela')

# Value normalization owns no LLVM, NIR or driver state.
stela_metal_threadgroup = static_library(
  'stela_metal_threadgroup',
  'threadgroup.c',
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
stela_metal_threadgroup_test = executable(
  'stela_metal_threadgroup_test',
  'tests/threadgroup.c',
  link_with : stela_metal_threadgroup,
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
test('stela_metal_threadgroup_values', stela_metal_threadgroup_test, suite : 'stela')

if with_amd_llvm
  stela_amd_llvm_float = static_library(
    'stela_amd_llvm_float',
    '../amd/hosted/llvm_float.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_nir, idep_mesautil, dep_llvm, idep_amd_generated_headers],
    c_args : ['-Werror'],
  )
  stela_amd_llvm_float_probe = executable(
    'stela_amd_llvm_float_probe',
    '../amd/tests/llvm_float.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_nir, idep_mesautil, dep_llvm, idep_amd_generated_headers],
    link_with : [stela_amd_llvm_float],
    c_args : ['-Werror'],
  )
  test('stela_amd_llvm_float', stela_amd_llvm_float_probe, suite : 'stela')
endif

stela_air_llvm = get_option('air-llvm-library')
if stela_air_llvm != ''
  if not ['darwin', 'linux'].contains(host_machine.system())
    error('The AIR compiler currently requires a native Darwin or Linux LLVM 23 library')
  endif
  if not fs.is_absolute(stela_air_llvm) or not fs.is_file(stela_air_llvm)
    error('stela-air-llvm-library must name an existing absolute shared-library path')
  endif
  stela_air_llvm_dep = declare_dependency(
    include_directories : llvm_include,
    link_args : [stela_air_llvm],
  )
  stela_air = static_library(
    'stela_air_to_nir',
    ['air_to_nir.c', 'air_metadata.c'],
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : [idep_nir, idep_mesautil, stela_air_llvm_dep],
    c_args : ['-Werror'],
  )
  stela_metal_input = get_option('metal-input-library')
  if stela_metal_input != ''
    if host_machine.system() != 'darwin' or not fs.is_absolute(stela_metal_input) or not fs.is_file(stela_metal_input)
      error('Metal assembly requires a matching Darwin Rust input static library')
    endif
    stela_metal_assembly = static_library(
      'stela_metal_assembly',
      'library_assembly.c',
      dependencies : [stela_air_llvm_dep],
      c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
    )
    # Ordinary archive extraction pulls the shared metadata inspector alone;
    # this local owner does not depend on NIR or any vendor compiler backend.
    stela_metal_assembly_test = executable(
      'stela_metal_assembly_test',
      'tests/library_assembly.c',
      dependencies : [stela_air_llvm_dep, dependency('appleframeworks', modules : ['CoreFoundation'])],
      link_with : [stela_metal_assembly, stela_air, stela_apple_source],
      link_args : [stela_metal_input, '-lresolv', '-liconv'],
      c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_metal_library_assembly', stela_metal_assembly_test, suite : 'stela')
  endif
  idep_stela_air = declare_dependency(
    link_with : [stela_air],
    include_directories : include_directories('.'),
    dependencies : [idep_nir, idep_mesautil, stela_air_llvm_dep],
  )
  stela_metal_threadgroup_nir_test = executable(
    'stela_metal_threadgroup_nir_test',
    'tests/threadgroup_nir.c',
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : [idep_stela_air],
    link_with : stela_metal_threadgroup,
    c_args : ['-Wall', '-Wextra', '-Werror', '-Wno-missing-field-initializers'],
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_metal_threadgroup_nir', stela_metal_threadgroup_nir_test, suite : 'stela')
  stela_air_test_dependencies = [idep_stela_air]
  stela_air_test_links = []
  stela_air_test_args = ['-Werror']
  if with_nvidia
    stela_air_test_dependencies += [idep_nak]
    stela_air_test_links += stela_nak
    stela_air_test_args += ['-DSTELA_AIR_TEST_NAK']
    stela_air_input_nak_probe = executable(
      'stela_air_input_nak_probe',
      'tests/air_input_nak_probe.c',
      include_directories : [inc_include, inc_src, inc_gpu],
      dependencies : [idep_stela_air, idep_nak],
      link_with : stela_nak,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_input_nak', stela_air_input_nak_probe,
         suite : ['stela', 'stela-air-input'])
  endif
  stela_air_test = executable(
    'stela_air_test',
    'tests/air_to_nir.c',
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : stela_air_test_dependencies,
    link_with : stela_air_test_links,
    c_args : stela_air_test_args,
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_air_to_nir', stela_air_test, suite : 'stela')
  stela_air_ssbo_test = executable(
    'stela_air_ssbo_test',
    'tests/air_ssbo.c',
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : [idep_stela_air],
    c_args : ['-Werror'],
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_air_ssbo', stela_air_ssbo_test, suite : 'stela')
  stela_air_stage_test = executable(
    'stela_air_stage_test',
    'tests/air_stage.c',
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : [idep_stela_air],
    c_args : ['-Werror'],
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_air_stage', stela_air_stage_test, suite : 'stela')
  if with_nvidia
    stela_nv_air_render_probe = executable(
      'stela_nv_air_render_probe',
      '../nvidia/tests/air_render.c',
      include_directories : [inc_include, inc_src, inc_gpu],
      dependencies : [idep_stela_air, idep_nak],
      link_with : stela_nak,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  if with_amd
    if with_amd_llvm
      stela_air_amd_llvm_probe = executable(
        'stela_air_amd_llvm_probe',
        '../amd/tests/air_llvm_probe.c',
        include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common,
                               include_directories('.')],
        # Keep the full matching development headers. idep_stela_air exposes
        # the narrow C-only header set, unsuitable for this C++ LLVM backend.
        dependencies : [idep_nir, idep_mesautil, dep_llvm, idep_amd_generated_headers],
        link_with : [stela_air, libamd_common_llvm, libamd_common,
                     stela_amd_llvm_float],
        link_args : stela_dead_strip,
        c_args : ['-Werror'],
        build_rpath : fs.parent(stela_air_llvm),
      )
      test('stela_air_amd_llvm', stela_air_amd_llvm_probe,
           suite : ['stela', 'stela-air-input'])
    endif
    stela_air_aco_probe = executable(
      'stela_air_aco_probe',
      'tests/air_aco_probe.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers] +
                     (with_amd_llvm ? [dep_llvm] : []),
      link_with : [libamd_common] + stela_aco_links,
      link_args : stela_dead_strip,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_aco', stela_air_aco_probe, suite : ['stela', 'stela-air-input'])
    # Original legacy-VS, NGG and PS lowerings for the offline render probe.
    stela_amd_render_lowering = static_library(
      'stela_amd_render_lowering',
      files(mesa_src / 'amd/common/nir/ac_nir_cull.c', mesa_src / 'amd/common/nir/ac_nir_lower_legacy_vs.c',
            mesa_src / 'amd/common/nir/ac_nir_lower_ngg.c', mesa_src / 'amd/common/nir/ac_nir_lower_ps_early.c',
            mesa_src / 'amd/common/nir/ac_nir_lower_ps_late.c', mesa_src / 'amd/common/nir/ac_nir_lower_resinfo.c',
            mesa_src / 'amd/common/nir/ac_nir_prerast_utils.c'),
      include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
      dependencies : [idep_nir_headers, idep_mesautil, idep_amd_generated_headers],
      c_args : [no_override_init_args],
      gnu_symbol_visibility : 'hidden',
    )
    # Needs unchanged Apple VS/FS inputs; `cargo xtask gpu compilers` runs it
    # when they are supplied.
    stela_amd_air_render_probe = executable(
      'stela_amd_air_render_probe',
      '../amd/tests/air_render.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers] +
                     (with_amd_llvm ? [dep_llvm] : []),
      link_with : [stela_amd_render_lowering, libamd_common] + stela_aco_links,
      link_args : stela_dead_strip,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  if with_intel
    stela_intel_air_render_probe = executable(
      'stela_intel_air_render_probe',
      ['../intel/tests/air_render.c',
       '../intel/tests/air_render_elk.c'],
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [libisl],
      c_args : ['-Werror', '-UNDEBUG'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    stela_air_brw_probe = executable(
      'stela_air_brw_probe',
      '../intel/tests/air_brw_probe.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw, idep_intel_dev],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_brw', stela_air_brw_probe, suite : ['stela', 'stela-air-input'])
    stela_air_elk_probe = executable(
      'stela_air_elk_probe',
      '../intel/tests/air_elk_probe.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_elk,
                      idep_intel_compiler_gen, idep_intel_dev],
      link_with : [libisl],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_air_elk', stela_air_elk_probe, suite : ['stela', 'stela-air-input'])
  endif
endif

if with_nvidia
  stela_nv_image = static_library(
    'stela_nv_image',
    ['../nvidia/hosted/image.c', '../nvidia/hosted/copy.c'],
    include_directories : [inc_include, inc_src, inc_gpu, nvidia_headers],
    dependencies : [idep_nil, idep_mesautil],
    c_args : ['-Werror'],
  )
  stela_nv_image_probe = executable(
    'stela_nv_image_probe',
    '../nvidia/tests/image.c',
    include_directories : [inc_include, inc_src, inc_gpu, nvidia_headers],
    dependencies : [idep_nil, idep_mesautil],
    link_with : [stela_nv_image],
    c_args : ['-Werror'],
  )
  test('stela_nv_image', stela_nv_image_probe, suite : 'stela')
  stela_nv_image_copy_probe = executable(
    'stela_nv_image_copy_probe',
    '../nvidia/tests/copy.c',
    include_directories : [inc_include, inc_src, inc_gpu, nvidia_headers],
    dependencies : [idep_nil, idep_mesautil],
    link_with : [stela_nv_image],
    c_args : ['-Werror'],
  )
  test('stela_nv_image_copy', stela_nv_image_copy_probe, suite : 'stela')
  stela_nv_sampler = static_library(
    'stela_nv_sampler',
    '../nvidia/hosted/sampler.c',
    include_directories : [inc_include, inc_src, inc_gpu, nvidia_headers],
    dependencies : [idep_nil, idep_mesautil, dep_m],
    c_args : ['-Werror'],
  )
  stela_nv_sampler_probe = executable(
    'stela_nv_sampler_probe',
    '../nvidia/tests/sampler.c',
    include_directories : [inc_include, inc_src, inc_gpu, nvidia_headers],
    dependencies : [idep_nil, idep_mesautil, dep_m],
    link_with : [stela_nv_sampler, stela_nv_image],
    c_args : ['-Werror'],
  )
  test('stela_nv_sampler', stela_nv_sampler_probe, suite : 'stela')
  stela_nv_compute = static_library(
    'stela_nv_compute',
    ['nvidia_compute.c', stela_nv_compute_headers],
    include_directories : [inc_include, inc_src, inc_gpu,
                           nvidia_headers],
    dependencies : [idep_nak, idep_nir_headers, idep_mesautil],
    c_args : ['-Werror'],
  )
  if stela_air_llvm != ''
    stela_nv_compute_probe = executable(
      'stela_nv_compute_probe',
      'tests/nvidia_compute_probe.c',
      include_directories : [inc_include, inc_src, inc_gpu,
                             nvidia_headers],
      dependencies : [idep_stela_air, idep_nak],
      link_with : [stela_nv_compute, stela_nak],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_nv_compute', stela_nv_compute_probe, suite : 'stela')
    # Explicit retained raw inputs and a fresh artifact directory are supplied
    # by xtask. A missing fixture must never select a synthetic replacement.
    stela_nv_air_threadgroup_probe = executable(
      'stela_nv_air_threadgroup_probe',
      '../nvidia/tests/air_threadgroup.c',
      include_directories : [inc_include, inc_src, inc_gpu,
                             nvidia_headers],
      dependencies : [idep_stela_air, idep_nak, idep_mesautil],
      link_with : [stela_nv_compute, stela_nak],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  if stela_air_llvm != '' and stela_metal_input != ''
    stela_nv_air = static_library(
      'stela_nv_air',
      '../nvidia/hosted/air_compile.c',
      include_directories : [inc_include, inc_src, inc_gpu, nvidia_headers],
      dependencies : [idep_stela_air, idep_nak, idep_nir_headers],
      link_with : [stela_metal_assembly, stela_metal_threadgroup, stela_nak],
      c_args : ['-Werror'],
    )
    stela_nv_air_compile_test = executable(
      'stela_nv_air_compile_test',
      '../nvidia/tests/air_compile.c',
      include_directories : [inc_include, inc_src, inc_gpu,
                             nvidia_headers],
      dependencies : [idep_stela_air, idep_nak, idep_nir_headers,
                      dependency('appleframeworks', modules : ['CoreFoundation'])],
      link_with : [stela_nv_air, stela_nv_compute, stela_apple_source, stela_nak],
      link_args : [stela_metal_input, '-lresolv', '-liconv'],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_nv_air_owned', stela_nv_air_compile_test,
         suite : ['stela', 'stela-owned-air'])
    # The test includes render_compile.c itself so it can feed synthetic NIR to
    # the private upload-image path; the second variant denies its allocations.
    foreach variant : [['', []], ['_alloc', ['-DSTELA_NV_RENDER_ALLOC_TEST']]]
      stela_nv_render_test = executable(
        'stela_nv_air_render_owned' + variant[0],
        '../nvidia/tests/air_render_owned.c',
        include_directories : [inc_include, inc_src, inc_gpu,
                               nvidia_headers],
        dependencies : [idep_stela_air, idep_nak, idep_nir_headers, idep_mesautil,
                        dependency('appleframeworks', modules : ['CoreFoundation'])],
        link_with : [stela_metal_assembly, stela_apple_source, stela_nak],
        link_args : [stela_metal_input, '-lresolv', '-liconv'],
        c_args : ['-Werror'] + variant[1],
        build_rpath : fs.parent(stela_air_llvm),
      )
      test('stela_nv_air_render_owned' + variant[0], stela_nv_render_test, suite : 'stela')
    endforeach
  endif
  stela_nak_probe = executable(
    'stela_nak_probe',
    'tests/nak_probe.c',
    include_directories : [inc_include, inc_src, inc_gpu],
    dependencies : [idep_nak, idep_nir, idep_mesautil],
    link_with : stela_nak,
  )
  test('stela_nak_codegen', stela_nak_probe, suite : 'stela')
endif

if with_intel
  stela_intel_surface = static_library(
    'stela_intel_surface',
    ['../intel/hosted/surface.c',
     '../intel/hosted/image.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev, idep_genxml],
    link_with : [libisl],
    c_args : ['-Werror'],
  )
  stela_intel_surface_probe = executable(
    'stela_intel_surface_probe',
    '../intel/tests/surface.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_surface', stela_intel_surface_probe, suite : 'stela')
  stela_intel_image_bits = custom_target(
    'stela_intel_image_bits',
    input : [intel_genxml / 'gen_bits_header.py',
             intel_genxml / 'gen70.xml', intel_genxml / 'gen75.xml',
             intel_genxml / 'gen80.xml', intel_genxml / 'gen90.xml',
             intel_genxml / 'gen110.xml', intel_genxml / 'gen120.xml',
             intel_genxml / 'gen125.xml', intel_genxml / 'xe2.xml',
             intel_genxml / 'xe3.xml', intel_genxml / 'xe3p.xml'],
    output : 'image_bits.h',
    command : [prog_python, '@INPUT0@', '--include-symbols',
      'RENDER_SURFACE_STATE::Surface Base Address,RENDER_SURFACE_STATE::Surface Pitch,RENDER_SURFACE_STATE::Surface QPitch,RENDER_SURFACE_STATE::Width,RENDER_SURFACE_STATE::Height,RENDER_SURFACE_STATE::Depth,RENDER_SURFACE_STATE::Surface Format,RENDER_SURFACE_STATE::Surface Type,RENDER_SURFACE_STATE::Minimum Array Element,RENDER_SURFACE_STATE::Render Target View Extent,RENDER_SURFACE_STATE::Surface Min LOD,RENDER_SURFACE_STATE::MIP Count / LOD,RENDER_SURFACE_STATE::Auxiliary Surface Mode,RENDER_SURFACE_STATE::Number of Multisamples,RENDER_SURFACE_STATE::Surface Array',
      '-o', '@OUTPUT@', '@INPUT1@', '@INPUT2@', '@INPUT3@', '@INPUT4@', '@INPUT5@',
      '@INPUT6@', '@INPUT7@', '@INPUT8@', '@INPUT9@', '@INPUT10@'],
    depend_files : gen_pack_header_deps,
  )
  stela_intel_image_probe = executable(
    'stela_intel_image_probe',
    ['../intel/tests/image.c', stela_intel_image_bits],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_image', stela_intel_image_probe, suite : 'stela')
  stela_intel_image_copy = static_library(
    'stela_intel_image_copy',
    '../intel/hosted/image_copy.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  stela_intel_image_copy_probe = executable(
    'stela_intel_image_copy_probe',
    '../intel/tests/image_copy.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_image_copy, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_image_copy', stela_intel_image_copy_probe, suite : 'stela')

  stela_intel_sampler = static_library(
    'stela_intel_sampler',
    ['../intel/hosted/sampler.c',
     '../intel/hosted/sampler80.c', '../intel/hosted/sampler90.c',
     '../intel/hosted/sampler110.c', '../intel/hosted/sampler120.c',
     '../intel/hosted/sampler125.c', '../intel/hosted/sampler200.c',
     '../intel/hosted/sampler300.c', '../intel/hosted/sampler350.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel, inc_gallium,
                           include_directories(intel_genxml)],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev, idep_genxml],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  stela_intel_sampler_bits = custom_target(
    'stela_intel_sampler_bits',
    input : [intel_genxml / 'gen_bits_header.py',
             intel_genxml / 'gen80.xml', intel_genxml / 'gen90.xml',
             intel_genxml / 'gen110.xml', intel_genxml / 'gen120.xml',
             intel_genxml / 'gen125.xml', intel_genxml / 'xe2.xml',
             intel_genxml / 'xe3.xml', intel_genxml / 'xe3p.xml'],
    output : 'sampler_bits.h',
    command : [prog_python, '@INPUT0@', '--include-symbols',
      'SAMPLER_STATE::Texture LOD Bias,SAMPLER_STATE::Min Mode Filter,SAMPLER_STATE::Mag Mode Filter,SAMPLER_STATE::Mip Mode Filter,SAMPLER_STATE::LOD PreClamp Mode,SAMPLER_STATE::Min LOD,SAMPLER_STATE::Max LOD,SAMPLER_STATE::TCX Address Control Mode,SAMPLER_STATE::TCY Address Control Mode,SAMPLER_STATE::TCZ Address Control Mode,SAMPLER_STATE::U Address Min Filter Rounding Enable,SAMPLER_STATE::U Address Mag Filter Rounding Enable,SAMPLER_STATE::V Address Min Filter Rounding Enable,SAMPLER_STATE::V Address Mag Filter Rounding Enable,SAMPLER_STATE::R Address Min Filter Rounding Enable,SAMPLER_STATE::R Address Mag Filter Rounding Enable,SAMPLER_STATE::Border Color Pointer,SAMPLER_STATE::Shadow Function,SAMPLER_STATE::Sampler Disable,SAMPLER_STATE::Non-normalized Coordinate Enable,SAMPLER_STATE::Cube Surface Control Mode,SAMPLER_STATE::Maximum Anisotropy,SAMPLER_STATE::Anisotropic Algorithm,SAMPLER_STATE::Reduction Type,SAMPLER_STATE::Reduction Type Enable', '-o', '@OUTPUT@', '@INPUT1@', '@INPUT2@', '@INPUT3@', '@INPUT4@',
      '@INPUT5@', '@INPUT6@', '@INPUT7@', '@INPUT8@'],
    depend_files : gen_pack_header_deps,
  )
  stela_intel_sampler_probe = executable(
    'stela_intel_sampler_probe',
    ['../intel/tests/sampler.c', stela_intel_sampler_bits],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel, inc_gallium],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_sampler, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_sampler', stela_intel_sampler_probe, suite : 'stela')

  # The native packet encoders run Mesa's unchanged generator over the packets
  # they select. As in the firmware image, the C library headers its packing
  # helpers include come from Stela's freestanding set.
  stela_intel_encoder_includes = include_directories(
    '../intel/freestanding', '../intel', intel_genxml)
  stela_intel_compute_headers = []
  foreach generation : [['125', 'gen125'], ['200', 'xe2'], ['300', 'xe3'], ['350', 'xe3p']]
    stela_intel_compute_headers += custom_target(
      'stela_intel_compute_@0@_pack'.format(generation[0]),
      input : [intel_genxml / 'gen_pack_header.py',
               intel_genxml / '@0@.xml'.format(generation[1])],
      output : 'gen@0@_compute_pack.h'.format(generation[0]),
      command : [prog_python, '@INPUT@', '--include-symbols',
                 'COMPUTE_WALKER,COMPUTE_WALKER_BODY,INTERFACE_DESCRIPTOR_DATA,POSTSYNC_DATA,PREF_SLM_ALLOCATION_SIZE'],
      capture : true,
      depend_files : gen_pack_header_deps,
    )
  endforeach
  stela_intel_gpgpu_headers = []
  foreach generation : ['70', '75', '80', '90', '110', '120']
    stela_intel_gpgpu_headers += custom_target(
      'stela_intel_gpgpu_@0@_pack'.format(generation),
      input : [intel_genxml / 'gen_pack_header.py',
               intel_genxml / 'gen@0@.xml'.format(generation)],
      output : 'gen@0@_dispatch_pack.h'.format(generation),
      command : [prog_python, '@INPUT@', '--include-symbols',
                 'GPGPU_WALKER,MEDIA_STATE_FLUSH'],
      capture : true,
      depend_files : gen_pack_header_deps,
    )
  endforeach
  stela_intel_gpgpu_native = static_library(
    'stela_intel_gpgpu_native',
    ['../intel/dispatch.c',
     '../intel/dispatch/gen70.c',
     '../intel/dispatch/gen75.c',
     '../intel/dispatch/gen80.c',
     '../intel/dispatch/gen90.c',
     '../intel/dispatch/gen110.c',
     '../intel/dispatch/gen120.c', stela_intel_gpgpu_headers],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel,
                           stela_intel_encoder_includes],
    c_args : ['-Werror'],
  )
  stela_intel_compute_native = static_library(
    'stela_intel_compute_native',
    ['../intel/compute_dispatch.c',
     '../intel/dispatch/compute125.c',
     '../intel/dispatch/compute200.c',
     '../intel/dispatch/compute300.c',
     '../intel/dispatch/compute350.c', stela_intel_compute_headers],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel,
                           stela_intel_encoder_includes],
    c_args : ['-Werror'],
  )
  # Keep these original policy TUs intact; stela_dead_strip removes their
  # unused device-query entry points.
  stela_intel_compute_policy = static_library(
    'stela_intel_compute_policy',
    ['../intel/hosted/compute.c',
     mesa_src / 'intel/common/intel_common.c', mesa_src / 'intel/common/intel_compute_slm.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_dev, idep_mesautil],
    link_with : [libisl],
    c_args : ['-Werror'] + stela_sections,
  )
  stela_intel_compute_program_probe = executable(
    'stela_intel_compute_program_probe',
    '../intel/tests/compute_program.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_dev, idep_mesautil],
    link_with : [stela_intel_compute_policy, stela_intel_compute_native, libisl],
    c_args : ['-Werror'],
    link_args : stela_dead_strip,
  )
  test('stela_intel_compute_program', stela_intel_compute_program_probe, suite : 'stela')
  # The hosted legacy producer reuses the same original SLM policy archive and
  # the single native walker archive. Full hosted packers come from idep_genxml;
  # no new algorithm, duplicated policy TU or private header generator exists.
  stela_intel_legacy_compute = static_library(
    'stela_intel_legacy_compute',
    ['../intel/hosted/legacy_compute.c',
     '../intel/hosted/legacy70.c',
     '../intel/hosted/legacy75.c',
     '../intel/hosted/legacy80.c',
     '../intel/hosted/legacy90.c',
     '../intel/hosted/legacy110.c',
     '../intel/hosted/legacy120.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel,
                           include_directories(intel_genxml)],
    dependencies : [dep_m, idep_genxml, idep_intel_compiler_brw,
                    idep_intel_compiler_elk, idep_intel_dev, idep_mesautil],
    link_with : [stela_intel_compute_policy, stela_intel_gpgpu_native, libisl],
    c_args : ['-Werror'],
  )
  stela_intel_legacy_compute_program_probe = executable(
    'stela_intel_legacy_compute_program_probe',
    ['../intel/tests/legacy_compute_program.c',
     '../intel/tests/legacy_elk_validate.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_compiler_elk,
                    idep_intel_compiler_gen, idep_intel_dev, idep_mesautil],
    link_with : [stela_intel_legacy_compute],
    c_args : ['-Werror'],
    link_args : stela_dead_strip,
  )
  test('stela_intel_legacy_compute_program', stela_intel_legacy_compute_program_probe,
       suite : 'stela')
  if stela_air_llvm != '' and stela_metal_input != ''
    stela_intel_air = static_library(
      'stela_intel_air',
      ['../intel/hosted/air_compile.c',
       '../intel/hosted/air_validate_elk.c'],
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [stela_metal_assembly, stela_metal_threadgroup],
      c_args : ['-Werror'],
    )
    stela_intel_air_compile_test = executable(
      'stela_intel_air_compile_test',
      '../intel/tests/air_compile.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel,
                             include_directories('../intel/hosted')],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil,
                      dependency('appleframeworks', modules : ['CoreFoundation'])],
      link_with : [stela_intel_air, stela_intel_surface,
                   stela_intel_compute_policy, stela_intel_compute_native,
                   stela_intel_legacy_compute, stela_intel_gpgpu_native,
                   libisl, stela_apple_source],
      link_args : [stela_metal_input, '-lresolv', '-liconv'] + stela_dead_strip,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_intel_air_owned', stela_intel_air_compile_test,
         suite : ['stela', 'stela-owned-air'])
    test('stela_intel_air_gen7_shared', stela_intel_air_compile_test,
         args : ['--gen7-shared'], suite : 'stela')
    # Needs the unchanged Apple triangle and the Intel render probe's
    # artifacts; `cargo xtask gpu compilers` runs both variants with them.
    # The test includes air_graphics.c itself; the second variant denies its
    # allocations.
    foreach variant : [['', []], ['_alloc', ['-DSTELA_INTEL_GRAPHICS_ALLOCATION_TEST']]]
      executable(
        'stela_intel_air_graphics_test' + variant[0],
        '../intel/tests/air_graphics.c',
        include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
        dependencies : [idep_stela_air, idep_intel_compiler_brw,
                        idep_intel_compiler_elk, idep_intel_compiler_gen,
                        idep_intel_dev, idep_mesautil,
                        dependency('appleframeworks', modules : ['CoreFoundation'])],
        link_with : [stela_intel_air, stela_intel_surface,
                     stela_intel_compute_policy, stela_intel_compute_native,
                     stela_intel_legacy_compute, stela_intel_gpgpu_native,
                     libisl, stela_apple_source],
        link_args : [stela_metal_input, '-lresolv', '-liconv'] + stela_dead_strip,
        c_args : ['-Werror'] + variant[1],
        build_rpath : fs.parent(stela_air_llvm),
      )
    endforeach
  endif
  if stela_air_llvm != ''
    stela_intel_fp_controls_probe = executable(
      'stela_intel_fp_controls_probe',
      ['../intel/tests/fp_controls.c',
       '../intel/tests/fp_controls_elk.c',
       '../intel/tests/legacy_elk_validate.c'],
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [stela_intel_compute_policy, stela_intel_compute_native,
                   stela_intel_legacy_compute, libisl],
      c_args : ['-Werror'],
      link_args : stela_dead_strip,
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_intel_fp_controls', stela_intel_fp_controls_probe, suite : 'stela')
    stela_intel_threadgroup_bits = custom_target(
      'stela_intel_threadgroup_bits',
      input : [intel_genxml / 'gen_bits_header.py',
               intel_genxml / 'gen70.xml', intel_genxml / 'gen75.xml',
               intel_genxml / 'gen80.xml', intel_genxml / 'gen90.xml',
               intel_genxml / 'gen110.xml', intel_genxml / 'gen120.xml',
               intel_genxml / 'gen125.xml', intel_genxml / 'xe2.xml',
               intel_genxml / 'xe3.xml', intel_genxml / 'xe3p.xml'],
      output : 'threadgroup_bits.h',
      command : [prog_python, '@INPUT0@', '--include-symbols',
        'COMPUTE_WALKER::body,COMPUTE_WALKER_BODY::Interface Descriptor,INTERFACE_DESCRIPTOR_DATA::Shared Local Memory Size,INTERFACE_DESCRIPTOR_DATA::Number Of Barriers,INTERFACE_DESCRIPTOR_DATA::Number of Threads in GPGPU Thread Group,INTERFACE_DESCRIPTOR_DATA::Preferred SLM Allocation Size,INTERFACE_DESCRIPTOR_DATA::Barrier Enable',
        '-o', '@OUTPUT@', '@INPUT1@', '@INPUT2@', '@INPUT3@', '@INPUT4@', '@INPUT5@',
        '@INPUT6@', '@INPUT7@', '@INPUT8@', '@INPUT9@', '@INPUT10@'],
      depend_files : gen_pack_header_deps,
    )
    stela_intel_air_threadgroup_probe = executable(
      'stela_intel_air_threadgroup_probe',
      ['../intel/tests/air_threadgroup.c',
       '../intel/tests/air_threadgroup_elk.c',
       '../intel/tests/legacy_elk_validate.c', stela_intel_threadgroup_bits],
      include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [stela_intel_compute_policy, stela_intel_compute_native,
                   stela_intel_legacy_compute, libisl],
      c_args : ['-Werror'],
      link_args : stela_dead_strip,
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  stela_elk_probe = executable(
    'stela_elk_probe',
    'tests/elk_probe.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [idep_intel_compiler_elk, idep_intel_compiler_gen,
                    idep_intel_dev, idep_mesautil],
    link_with : [libisl],
  )
  test('stela_elk_codegen', stela_elk_probe, suite : 'stela')
  stela_brw_probe = executable(
    'stela_brw_probe',
    'tests/brw_probe.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_dev, idep_mesautil],
  )
  test('stela_brw_codegen', stela_brw_probe, suite : 'stela')
endif

if with_amd
  stela_amd_sampler = static_library(
    'stela_amd_sampler',
    '../amd/hosted/sampler.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_common],
    c_args : ['-Werror'],
  )
  stela_amd_sampler_probe = executable(
    'stela_amd_sampler_probe',
    '../amd/tests/sampler.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_sampler, libamd_common],
    link_args : stela_dead_strip,
    c_args : ['-Werror'],
  )
  test('stela_amd_sampler', stela_amd_sampler_probe, suite : 'stela')
  stela_amd_surface_probe = executable(
    'stela_amd_surface_probe',
    ['../amd/tests/surface.c', mesa_src / 'amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_common],
    link_args : stela_dead_strip,
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_surface', stela_amd_surface_probe, suite : 'stela')
  stela_amd_buffer = static_library(
    'stela_amd_buffer',
    '../amd/hosted/buffer.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_common],
    c_args : ['-Werror'],
  )
  stela_amd_buffer_probe = executable(
    'stela_amd_buffer_probe',
    '../amd/tests/buffer.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_buffer, libamd_common],
    link_args : stela_dead_strip,
    c_args : ['-Werror'],
  )
  test('stela_amd_buffer', stela_amd_buffer_probe, suite : 'stela')
  stela_amd_image = static_library(
    'stela_amd_image',
    ['../amd/hosted/image.c', '../amd/hosted/image_resource.c',
     '../amd/hosted/image_copy.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_buffer, libamd_common],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  stela_amd_image_probe = executable(
    'stela_amd_image_probe',
    ['../amd/tests/image.c', mesa_src / 'amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_image],
    link_args : stela_dead_strip,
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_image', stela_amd_image_probe, suite : 'stela')
  stela_amd_image_resource_probe = executable(
    'stela_amd_image_resource_probe',
    ['../amd/tests/image_resource.c', mesa_src / 'amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_image],
    link_args : stela_dead_strip,
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_image_resource', stela_amd_image_resource_probe, suite : 'stela')
  stela_amd_image_copy_probe = executable(
    'stela_amd_image_copy_probe',
    ['../amd/tests/image_copy.c', mesa_src / 'amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_image],
    link_args : stela_dead_strip,
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_image_copy', stela_amd_image_copy_probe, suite : 'stela')
  stela_amd_commands = static_library(
    'stela_amd_commands',
    'amd_commands.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_common],
  )

  stela_amd_compute = static_library(
    'stela_amd_compute',
    ['../amd/hosted/compute.c', '../amd/hosted/compute_policy.c',
     '../amd/hosted/llvm_compute.c'],
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_nir_headers, idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_buffer, stela_amd_commands, libamd_common],
    c_args : ['-Werror'],
  )
  stela_amd_compute_probe = executable(
    'stela_amd_compute_probe',
    '../amd/tests/compute.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_aco, idep_nir, idep_mesautil, idep_amd_generated_headers] +
                   (with_amd_llvm ? [dep_llvm] : []),
    link_with : [stela_amd_compute] + stela_aco_links + (with_amd_llvm ? [stela_amd_llvm_float] : []),
    link_args : stela_dead_strip,
    c_args : ['-Werror', '-DSTELA_AMD_TEST_LLVM=' + (with_amd_llvm ? '1' : '0')],
  )
  test('stela_amd_compute', stela_amd_compute_probe, suite : 'stela')
  if stela_air_llvm != '' and stela_metal_input != ''
    stela_amd_air = static_library(
      'stela_amd_air',
      '../amd/hosted/air_compile.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers] +
                     (with_amd_llvm ? [dep_llvm] : []),
      link_with : [stela_metal_assembly, stela_metal_threadgroup, stela_amd_buffer, libamd_common] + stela_aco_links,
      c_args : ['-Werror'],
    )
    stela_amd_air_compile_test = executable(
      'stela_amd_air_compile_test',
      '../amd/tests/air_compile.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers,
                      dependency('appleframeworks', modules : ['CoreFoundation'])] +
                     (with_amd_llvm ? [dep_llvm] : []),
      link_with : [stela_amd_air, stela_amd_compute, stela_apple_source] + stela_aco_links,
      link_args : [stela_metal_input, '-lresolv', '-liconv'] + stela_dead_strip,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_amd_air_owned', stela_amd_air_compile_test,
         suite : ['stela', 'stela-owned-air'])
  endif
  if stela_air_llvm != '' and with_amd_llvm
    stela_amd_air_threadgroup_probe = executable(
      'stela_amd_air_threadgroup_probe',
      '../amd/tests/air_shared.c',
      include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common,
                             include_directories('.')],
      dependencies : [idep_nir, idep_aco, idep_mesautil, dep_llvm,
                      idep_amd_generated_headers],
      link_with : [stela_air, stela_amd_compute, stela_amd_llvm_float,
                   libamd_common_llvm, libamd_common],
      link_args : stela_dead_strip,
      c_args : ['-Werror', '-DSTELA_AMD_TEST_LLVM=1'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif

  stela_amd_commands_probe = executable(
    'stela_amd_commands_probe',
    'tests/amd_commands_probe.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_commands, libamd_common],
    link_args : stela_dead_strip,
  )
  test('stela_amd_commands', stela_amd_commands_probe, suite : 'stela')

  stela_aco_probe = executable(
    'stela_aco_probe',
    'tests/aco_probe.c',
    include_directories : [inc_include, inc_src, inc_gpu, inc_amd, inc_amd_common],
    dependencies : [idep_aco, idep_nir, idep_mesautil, idep_amd_generated_headers] +
                   (with_amd_llvm ? [dep_llvm] : []),
    link_with : [libamd_common] + stela_aco_links,
    link_args : stela_dead_strip,
  )
  test('stela_aco_codegen', stela_aco_probe, suite : 'stela')
endif
