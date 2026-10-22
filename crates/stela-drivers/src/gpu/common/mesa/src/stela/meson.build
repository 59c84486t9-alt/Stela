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

# Value normalization owns no LLVM, NIR or driver state.
stela_metal_threadgroup = static_library(
  'stela_metal_threadgroup',
  '../../../../metal/compiler/threadgroup.c',
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
stela_metal_threadgroup_test = executable(
  'stela_metal_threadgroup_test',
  '../../../../metal/compiler/tests/threadgroup.c',
  link_with : stela_metal_threadgroup,
  c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
)
test('stela_metal_threadgroup_values', stela_metal_threadgroup_test, suite : 'stela')

if with_stela_amd_llvm
  stela_amd_llvm_float = static_library(
    'stela_amd_llvm_float',
    '../../../../amd/stela/llvm_float.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_nir, idep_mesautil, dep_llvm, idep_amd_generated_headers],
    c_args : ['-Werror'],
  )
  stela_amd_llvm_float_probe = executable(
    'stela_amd_llvm_float_probe',
    '../../../../amd/tests/llvm_float_test.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_nir, idep_mesautil, dep_llvm, idep_amd_generated_headers],
    link_with : [stela_amd_llvm_float],
    c_args : ['-Werror'],
  )
  test('stela_amd_llvm_float', stela_amd_llvm_float_probe, suite : 'stela')
endif

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
    ['air_to_nir.c', 'air_metadata.c'],
    include_directories : [inc_include, inc_src],
    dependencies : [idep_nir, idep_mesautil, stela_air_llvm_dep],
    c_args : ['-Werror'],
  )
  stela_metal_input = get_option('stela-metal-input-library')
  if stela_metal_input != ''
    if host_machine.system() != 'darwin' or not fs.is_absolute(stela_metal_input) or not fs.is_file(stela_metal_input)
      error('Metal assembly requires a matching Darwin Rust input static library')
    endif
    stela_metal_assembly = static_library(
      'stela_metal_assembly',
      '../../../../metal/compiler/library_assembly.c',
      dependencies : [stela_air_llvm_dep],
      c_args : ['-Wall', '-Wextra', '-Werror', '-Wconversion'],
    )
    # Ordinary archive extraction pulls the shared metadata inspector alone;
    # this local owner does not depend on NIR or any vendor compiler backend.
    stela_metal_assembly_test = executable(
      'stela_metal_assembly_test',
      '../../../../metal/compiler/tests/library_assembly.c',
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
    '../../../../metal/compiler/tests/threadgroup_nir.c',
    include_directories : [inc_include, inc_src],
    dependencies : [idep_stela_air],
    link_with : stela_metal_threadgroup,
    c_args : ['-Wall', '-Wextra', '-Werror', '-Wno-missing-field-initializers'],
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_metal_threadgroup_nir', stela_metal_threadgroup_nir_test, suite : 'stela')
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
  stela_air_stage_test = executable(
    'stela_air_stage_test',
    'air_stage_test.c',
    include_directories : [inc_include, inc_src],
    dependencies : [idep_stela_air],
    c_args : ['-Werror'],
    build_rpath : fs.parent(stela_air_llvm),
  )
  test('stela_air_stage', stela_air_stage_test, suite : 'stela')
  if with_stela_nvidia
    stela_nv_air_render_probe = executable(
      'stela_nv_air_render_probe',
      '../../../../nvidia/stela/tests/air_render.c',
      include_directories : [inc_include, inc_src],
      dependencies : [idep_stela_air, idep_nak],
      link_with : [_libnak_rs],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
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
        link_with : [stela_air, libamd_common_llvm, libamd_compiler_support,
                     stela_amd_llvm_float],
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
    stela_intel_air_render_probe = executable(
      'stela_intel_air_render_probe',
      ['../../../../intel/stela/tests/air_render.c',
       '../../../../intel/stela/tests/air_render_elk.c'],
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [libisl],
      c_args : ['-Werror', '-UNDEBUG'],
      build_rpath : fs.parent(stela_air_llvm),
    )
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
  stela_nv_image = static_library(
    'stela_nv_image',
    ['../../../../nvidia/stela/hosted/image.c', '../../../../nvidia/stela/hosted/copy.c'],
    include_directories : [inc_include, inc_src, include_directories('../nouveau/headers')],
    dependencies : [idep_nil, idep_mesautil],
    c_args : ['-Werror'],
  )
  stela_nv_image_probe = executable(
    'stela_nv_image_probe',
    '../../../../nvidia/stela/tests/image.c',
    include_directories : [inc_include, inc_src, include_directories('../nouveau/headers')],
    dependencies : [idep_nil, idep_mesautil],
    link_with : [stela_nv_image],
    c_args : ['-Werror'],
  )
  test('stela_nv_image', stela_nv_image_probe, suite : 'stela')
  stela_nv_image_copy_probe = executable(
    'stela_nv_image_copy_probe',
    '../../../../nvidia/stela/tests/copy.c',
    include_directories : [inc_include, inc_src, include_directories('../nouveau/headers')],
    dependencies : [idep_nil, idep_mesautil],
    link_with : [stela_nv_image],
    c_args : ['-Werror'],
  )
  test('stela_nv_image_copy', stela_nv_image_copy_probe, suite : 'stela')
  stela_nv_sampler = static_library(
    'stela_nv_sampler',
    '../../../../nvidia/stela/hosted/sampler.c',
    include_directories : [inc_include, inc_src, include_directories('../nouveau/headers')],
    dependencies : [idep_nil, idep_mesautil, dep_m],
    c_args : ['-Werror'],
  )
  stela_nv_sampler_probe = executable(
    'stela_nv_sampler_probe',
    '../../../../nvidia/stela/tests/sampler.c',
    include_directories : [inc_include, inc_src, include_directories('../nouveau/headers')],
    dependencies : [idep_nil, idep_mesautil, dep_m],
    link_with : [stela_nv_sampler, stela_nv_image],
    c_args : ['-Werror'],
  )
  test('stela_nv_sampler', stela_nv_sampler_probe, suite : 'stela')
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
    # Explicit retained raw inputs and a fresh artifact directory are supplied
    # by xtask. A missing fixture must never select a synthetic replacement.
    stela_nv_air_threadgroup_probe = executable(
      'stela_nv_air_threadgroup_probe',
      '../../../../nvidia/stela/tests/air_threadgroup.c',
      include_directories : [inc_include, inc_src,
                             include_directories('../nouveau/headers', '../nouveau/headers/nvidia/classes')],
      dependencies : [idep_stela_air, idep_nak, idep_mesautil],
      link_with : [stela_nv_compute, _libnak_rs],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  if stela_air_llvm != '' and stela_metal_input != ''
    stela_nv_air = static_library(
      'stela_nv_air',
      '../../../../nvidia/stela/hosted/air_compile.c',
      include_directories : [inc_include, inc_src, include_directories('../nouveau/headers')],
      dependencies : [idep_stela_air, idep_nak, idep_nir_headers],
      link_with : [stela_metal_assembly, stela_metal_threadgroup, _libnak_rs],
      c_args : ['-Werror'],
    )
    stela_nv_air_compile_test = executable(
      'stela_nv_air_compile_test',
      '../../../../nvidia/stela/tests/air_compile.c',
      include_directories : [inc_include, inc_src,
                             include_directories('../nouveau/headers', '../nouveau/headers/nvidia/classes')],
      dependencies : [idep_stela_air, idep_nak, idep_nir_headers,
                      dependency('appleframeworks', modules : ['CoreFoundation'])],
      link_with : [stela_nv_air, stela_nv_compute, stela_apple_source, _libnak_rs],
      link_args : [stela_metal_input, '-lresolv', '-liconv'],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_nv_air_owned', stela_nv_air_compile_test, suite : 'stela')
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
    ['../../../../intel/stela/hosted/surface.c',
     '../../../../intel/stela/hosted/image.c'],
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev, idep_genxml],
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
  stela_intel_image_bits = custom_target(
    'stela_intel_image_bits',
    input : ['../intel/genxml/gen_bits_header.py',
             '../intel/genxml/gen70.xml', '../intel/genxml/gen75.xml',
             '../intel/genxml/gen80.xml', '../intel/genxml/gen90.xml',
             '../intel/genxml/gen110.xml', '../intel/genxml/gen120.xml',
             '../intel/genxml/gen125.xml', '../intel/genxml/xe2.xml',
             '../intel/genxml/xe3.xml', '../intel/genxml/xe3p.xml'],
    output : 'image_bits.h',
    command : [prog_python, '@INPUT0@', '--include-symbols',
      'RENDER_SURFACE_STATE::Surface Base Address,RENDER_SURFACE_STATE::Surface Pitch,RENDER_SURFACE_STATE::Surface QPitch,RENDER_SURFACE_STATE::Width,RENDER_SURFACE_STATE::Height,RENDER_SURFACE_STATE::Depth,RENDER_SURFACE_STATE::Surface Format,RENDER_SURFACE_STATE::Surface Type,RENDER_SURFACE_STATE::Minimum Array Element,RENDER_SURFACE_STATE::Render Target View Extent,RENDER_SURFACE_STATE::Surface Min LOD,RENDER_SURFACE_STATE::MIP Count / LOD,RENDER_SURFACE_STATE::Auxiliary Surface Mode,RENDER_SURFACE_STATE::Number of Multisamples,RENDER_SURFACE_STATE::Surface Array',
      '-o', '@OUTPUT@', '@INPUT1@', '@INPUT2@', '@INPUT3@', '@INPUT4@', '@INPUT5@',
      '@INPUT6@', '@INPUT7@', '@INPUT8@', '@INPUT9@', '@INPUT10@'],
    depend_files : gen_pack_header_deps,
  )
  stela_intel_image_probe = executable(
    'stela_intel_image_probe',
    ['../../../../intel/stela/tests/image.c', stela_intel_image_bits],
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_image', stela_intel_image_probe, suite : 'stela')
  stela_intel_image_copy = static_library(
    'stela_intel_image_copy',
    '../../../../intel/stela/hosted/image_copy.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  stela_intel_image_copy_probe = executable(
    'stela_intel_image_copy_probe',
    '../../../../intel/stela/tests/image_copy.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_image_copy, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_image_copy', stela_intel_image_copy_probe, suite : 'stela')

  stela_intel_sampler = static_library(
    'stela_intel_sampler',
    ['../../../../intel/stela/hosted/sampler.c',
     '../../../../intel/stela/hosted/sampler80.c', '../../../../intel/stela/hosted/sampler90.c',
     '../../../../intel/stela/hosted/sampler110.c', '../../../../intel/stela/hosted/sampler120.c',
     '../../../../intel/stela/hosted/sampler125.c', '../../../../intel/stela/hosted/sampler200.c',
     '../../../../intel/stela/hosted/sampler300.c', '../../../../intel/stela/hosted/sampler350.c'],
    include_directories : [inc_include, inc_src, inc_intel, inc_gallium,
                           include_directories('../intel/genxml')],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev, idep_genxml],
    link_with : [stela_intel_surface, libisl],
    c_args : ['-Werror'],
  )
  stela_intel_sampler_bits = custom_target(
    'stela_intel_sampler_bits',
    input : ['../intel/genxml/gen_bits_header.py',
             '../intel/genxml/gen80.xml', '../intel/genxml/gen90.xml',
             '../intel/genxml/gen110.xml', '../intel/genxml/gen120.xml',
             '../intel/genxml/gen125.xml', '../intel/genxml/xe2.xml',
             '../intel/genxml/xe3.xml', '../intel/genxml/xe3p.xml'],
    output : 'sampler_bits.h',
    command : [prog_python, '@INPUT0@', '--include-symbols',
      'SAMPLER_STATE::Texture LOD Bias,SAMPLER_STATE::Min Mode Filter,SAMPLER_STATE::Mag Mode Filter,SAMPLER_STATE::Mip Mode Filter,SAMPLER_STATE::LOD PreClamp Mode,SAMPLER_STATE::Min LOD,SAMPLER_STATE::Max LOD,SAMPLER_STATE::TCX Address Control Mode,SAMPLER_STATE::TCY Address Control Mode,SAMPLER_STATE::TCZ Address Control Mode,SAMPLER_STATE::U Address Min Filter Rounding Enable,SAMPLER_STATE::U Address Mag Filter Rounding Enable,SAMPLER_STATE::V Address Min Filter Rounding Enable,SAMPLER_STATE::V Address Mag Filter Rounding Enable,SAMPLER_STATE::R Address Min Filter Rounding Enable,SAMPLER_STATE::R Address Mag Filter Rounding Enable,SAMPLER_STATE::Border Color Pointer,SAMPLER_STATE::Shadow Function,SAMPLER_STATE::Sampler Disable,SAMPLER_STATE::Non-normalized Coordinate Enable,SAMPLER_STATE::Cube Surface Control Mode,SAMPLER_STATE::Maximum Anisotropy,SAMPLER_STATE::Anisotropic Algorithm,SAMPLER_STATE::Reduction Type,SAMPLER_STATE::Reduction Type Enable', '-o', '@OUTPUT@', '@INPUT1@', '@INPUT2@', '@INPUT3@', '@INPUT4@',
      '@INPUT5@', '@INPUT6@', '@INPUT7@', '@INPUT8@'],
    depend_files : gen_pack_header_deps,
  )
  stela_intel_sampler_probe = executable(
    'stela_intel_sampler_probe',
    ['../../../../intel/stela/tests/sampler.c', stela_intel_sampler_bits],
    include_directories : [inc_include, inc_src, inc_intel, inc_gallium],
    dependencies : [dep_m, idep_mesautil, idep_intel_dev],
    link_with : [stela_intel_sampler, libisl],
    c_args : ['-Werror'],
  )
  test('stela_intel_sampler', stela_intel_sampler_probe, suite : 'stela')

  # The native integer encoders use the same retained XML generator as the
  # hosted packers. Explicit struct dependencies keep the narrow prologue free
  # of unrelated floating-point state, without replacing packing algorithms.
  stela_intel_compute_headers = []
  foreach generation : [['125', 'gen125'], ['200', 'xe2'], ['300', 'xe3'], ['350', 'xe3p']]
    stela_intel_compute_headers += custom_target(
      'stela_intel_compute_@0@_pack'.format(generation[0]),
      input : ['../intel/genxml/gen_pack_header.py',
               '../intel/genxml/@0@.xml'.format(generation[1])],
      output : 'gen@0@_compute_pack.h'.format(generation[0]),
      command : [prog_python, '@INPUT@', '--include-symbols',
                 'COMPUTE_WALKER,COMPUTE_WALKER_BODY,INTERFACE_DESCRIPTOR_DATA,POSTSYNC_DATA,PREF_SLM_ALLOCATION_SIZE',
                 '--helpers-include', 'genxml_native.h'],
      capture : true,
      depend_files : gen_pack_header_deps,
    )
  endforeach
  stela_intel_gpgpu_headers = []
  foreach generation : ['70', '75', '80', '90', '110', '120']
    stela_intel_gpgpu_headers += custom_target(
      'stela_intel_gpgpu_@0@_pack'.format(generation),
      input : ['../intel/genxml/gen_pack_header.py',
               '../intel/genxml/gen@0@.xml'.format(generation)],
      output : 'gen@0@_dispatch_pack.h'.format(generation),
      command : [prog_python, '@INPUT@', '--include-symbols',
                 'GPGPU_WALKER,MEDIA_STATE_FLUSH', '--helpers-include', 'genxml_native.h'],
      capture : true,
      depend_files : gen_pack_header_deps,
    )
  endforeach
  stela_intel_gpgpu_native = static_library(
    'stela_intel_gpgpu_native',
    ['../../../../intel/stela/dispatch.c',
     '../../../../intel/stela/dispatch/gen70.c',
     '../../../../intel/stela/dispatch/gen75.c',
     '../../../../intel/stela/dispatch/gen80.c',
     '../../../../intel/stela/dispatch/gen90.c',
     '../../../../intel/stela/dispatch/gen110.c',
     '../../../../intel/stela/dispatch/gen120.c', stela_intel_gpgpu_headers],
    include_directories : [inc_src, inc_intel,
                           include_directories('../../../../intel/stela', '../intel/genxml')],
    c_args : ['-Werror'],
  )
  stela_intel_compute_native = static_library(
    'stela_intel_compute_native',
    ['../../../../intel/stela/compute_dispatch.c',
     '../../../../intel/stela/dispatch/compute125.c',
     '../../../../intel/stela/dispatch/compute200.c',
     '../../../../intel/stela/dispatch/compute300.c',
     '../../../../intel/stela/dispatch/compute350.c', stela_intel_compute_headers],
    include_directories : [inc_src, inc_intel,
                           include_directories('../../../../intel/stela', '../intel/genxml')],
    c_args : ['-Werror'],
  )
  # Keep these original policy TUs intact. Function-section dead stripping
  # removes unused device-query entry points; no Linux OS stubs are supplied.
  stela_intel_policy_sections = cc.get_supported_arguments(['-ffunction-sections', '/Gy'])
  stela_intel_policy_gc = cpp.get_supported_link_arguments(
    ['-Wl,-dead_strip', '-Wl,--gc-sections', '/OPT:REF'])
  stela_intel_compute_policy = static_library(
    'stela_intel_compute_policy',
    ['../../../../intel/stela/hosted/compute.c',
     '../intel/common/intel_common.c', '../intel/common/intel_compute_slm.c'],
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_dev, idep_mesautil],
    link_with : [libisl],
    c_args : ['-Werror'] + stela_intel_policy_sections,
  )
  stela_intel_compute_program_probe = executable(
    'stela_intel_compute_program_probe',
    '../../../../intel/stela/tests/compute_program.c',
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_dev, idep_mesautil],
    link_with : [stela_intel_compute_policy, stela_intel_compute_native, libisl],
    c_args : ['-Werror'],
    link_args : stela_intel_policy_gc,
  )
  test('stela_intel_compute_program', stela_intel_compute_program_probe, suite : 'stela')
  # The hosted legacy producer reuses the same original SLM policy archive and
  # the single native walker archive. Full hosted packers come from idep_genxml;
  # no new algorithm, duplicated policy TU or private header generator exists.
  stela_intel_legacy_compute = static_library(
    'stela_intel_legacy_compute',
    ['../../../../intel/stela/hosted/legacy_compute.c',
     '../../../../intel/stela/hosted/legacy70.c',
     '../../../../intel/stela/hosted/legacy75.c',
     '../../../../intel/stela/hosted/legacy80.c',
     '../../../../intel/stela/hosted/legacy90.c',
     '../../../../intel/stela/hosted/legacy110.c',
     '../../../../intel/stela/hosted/legacy120.c'],
    include_directories : [inc_include, inc_src, inc_intel,
                           include_directories('../intel/genxml')],
    dependencies : [dep_m, idep_genxml, idep_intel_compiler_brw,
                    idep_intel_compiler_elk, idep_intel_dev, idep_mesautil],
    link_with : [stela_intel_compute_policy, stela_intel_gpgpu_native, libisl],
    c_args : ['-Werror'],
  )
  stela_intel_legacy_compute_program_probe = executable(
    'stela_intel_legacy_compute_program_probe',
    ['../../../../intel/stela/tests/legacy_compute_program.c',
     '../../../../intel/stela/tests/legacy_elk_validate.c'],
    include_directories : [inc_include, inc_src, inc_intel],
    dependencies : [idep_intel_compiler_brw, idep_intel_compiler_elk,
                    idep_intel_compiler_gen, idep_intel_dev, idep_mesautil],
    link_with : [stela_intel_legacy_compute],
    c_args : ['-Werror'],
    link_args : stela_intel_policy_gc,
  )
  test('stela_intel_legacy_compute_program', stela_intel_legacy_compute_program_probe,
       suite : 'stela')
  if stela_air_llvm != '' and stela_metal_input != ''
    stela_intel_air = static_library(
      'stela_intel_air',
      ['../../../../intel/stela/hosted/air_compile.c',
       '../../../../intel/stela/hosted/air_validate_elk.c'],
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [stela_metal_assembly, stela_metal_threadgroup],
      c_args : ['-Werror'],
    )
    stela_intel_air_compile_test = executable(
      'stela_intel_air_compile_test',
      '../../../../intel/stela/tests/air_compile.c',
      include_directories : [inc_include, inc_src, inc_intel,
                             include_directories('../../../../intel/stela/hosted')],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil,
                      dependency('appleframeworks', modules : ['CoreFoundation'])],
      link_with : [stela_intel_air, stela_intel_surface,
                   stela_intel_compute_policy, stela_intel_compute_native,
                   stela_intel_legacy_compute, stela_intel_gpgpu_native,
                   libisl, stela_apple_source],
      link_args : [stela_metal_input, '-lresolv', '-liconv'] + stela_intel_policy_gc,
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_intel_air_owned', stela_intel_air_compile_test, suite : 'stela')
  endif
  if stela_air_llvm != ''
    stela_intel_fp_controls_probe = executable(
      'stela_intel_fp_controls_probe',
      ['../../../../intel/stela/tests/fp_controls.c',
       '../../../../intel/stela/tests/fp_controls_elk.c',
       '../../../../intel/stela/tests/legacy_elk_validate.c'],
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [stela_intel_compute_policy, stela_intel_compute_native,
                   stela_intel_legacy_compute, libisl],
      c_args : ['-Werror'],
      link_args : stela_intel_policy_gc,
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_intel_fp_controls', stela_intel_fp_controls_probe, suite : 'stela')
    stela_intel_threadgroup_bits = custom_target(
      'stela_intel_threadgroup_bits',
      input : ['../intel/genxml/gen_bits_header.py',
               '../intel/genxml/gen70.xml', '../intel/genxml/gen75.xml',
               '../intel/genxml/gen80.xml', '../intel/genxml/gen90.xml',
               '../intel/genxml/gen110.xml', '../intel/genxml/gen120.xml',
               '../intel/genxml/gen125.xml', '../intel/genxml/xe2.xml',
               '../intel/genxml/xe3.xml', '../intel/genxml/xe3p.xml'],
      output : 'threadgroup_bits.h',
      command : [prog_python, '@INPUT0@', '--include-symbols',
        'COMPUTE_WALKER::body,COMPUTE_WALKER_BODY::Interface Descriptor,INTERFACE_DESCRIPTOR_DATA::Shared Local Memory Size,INTERFACE_DESCRIPTOR_DATA::Number Of Barriers,INTERFACE_DESCRIPTOR_DATA::Number of Threads in GPGPU Thread Group,INTERFACE_DESCRIPTOR_DATA::Preferred SLM Allocation Size,INTERFACE_DESCRIPTOR_DATA::Barrier Enable',
        '-o', '@OUTPUT@', '@INPUT1@', '@INPUT2@', '@INPUT3@', '@INPUT4@', '@INPUT5@',
        '@INPUT6@', '@INPUT7@', '@INPUT8@', '@INPUT9@', '@INPUT10@'],
      depend_files : gen_pack_header_deps,
    )
    stela_intel_air_threadgroup_probe = executable(
      'stela_intel_air_threadgroup_probe',
      ['../../../../intel/stela/tests/air_threadgroup.c',
       '../../../../intel/stela/tests/air_threadgroup_elk.c',
       '../../../../intel/stela/tests/legacy_elk_validate.c', stela_intel_threadgroup_bits],
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [idep_stela_air, idep_intel_compiler_brw,
                      idep_intel_compiler_elk, idep_intel_compiler_gen,
                      idep_intel_dev, idep_mesautil],
      link_with : [stela_intel_compute_policy, stela_intel_compute_native,
                   stela_intel_legacy_compute, libisl],
      c_args : ['-Werror'],
      link_args : stela_intel_policy_gc,
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif
  stela_intel_compute_packet_probe = executable(
    'stela_intel_compute_packet_probe',
    '../../../../intel/stela/tests/compute_dispatch.c',
    link_with : [stela_intel_compute_native],
    c_args : ['-Werror'],
  )
  test('stela_intel_compute_packet', stela_intel_compute_packet_probe, suite : 'stela')
  foreach generation : ['125', '200', '300', '350']
    stela_intel_compute_packer_probe = executable(
      'stela_intel_compute_packer_@0@_probe'.format(generation),
      '../../../../intel/stela/tests/compute_dispatch_mesa.c',
      include_directories : [inc_include, inc_src, inc_intel],
      dependencies : [dep_m, idep_genxml, idep_mesautil],
      link_with : [stela_intel_compute_native],
      c_args : ['-Werror', '-DGFX_VERx10=@0@'.format(generation)],
    )
    test('stela_intel_compute_packer_@0@'.format(generation),
         stela_intel_compute_packer_probe, suite : 'stela')
  endforeach
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
  stela_amd_sampler = static_library(
    'stela_amd_sampler',
    '../../../../amd/stela/sampler.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_compiler_support],
    c_args : ['-Werror'],
  )
  stela_amd_sampler_probe = executable(
    'stela_amd_sampler_probe',
    '../../../../amd/tests/sampler_test.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_sampler, libamd_compiler_support],
    c_args : ['-Werror'],
  )
  test('stela_amd_sampler', stela_amd_sampler_probe, suite : 'stela')
  stela_amd_surface = static_library(
    'stela_amd_surface',
    '../amd/common/ac_surface.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamdgpu_addrlib, libamd_compiler_support],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  stela_amd_surface_probe = executable(
    'stela_amd_surface_probe',
    ['../../../../amd/tests/surface_host_test.c', '../amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_surface],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_surface', stela_amd_surface_probe, suite : 'stela')
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
  stela_amd_image = static_library(
    'stela_amd_image',
    ['../../../../amd/stela/image.c', '../../../../amd/stela/image_resource.c',
     '../../../../amd/stela/image_copy.c'],
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_surface, stela_amd_buffer, libamd_compiler_support],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  stela_amd_image_probe = executable(
    'stela_amd_image_probe',
    ['../../../../amd/tests/image_test.c', '../amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_image],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_image', stela_amd_image_probe, suite : 'stela')
  stela_amd_image_resource_probe = executable(
    'stela_amd_image_resource_probe',
    ['../../../../amd/tests/image_resource_test.c', '../amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_image],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_image_resource', stela_amd_image_resource_probe, suite : 'stela')
  stela_amd_image_copy_probe = executable(
    'stela_amd_image_copy_probe',
    ['../../../../amd/tests/image_copy_test.c', '../amd/common/amdgpu_devices.c'],
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common, inc_gallium],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_image],
    c_args : cpp_args_addrlib + ['-Werror'],
  )
  test('stela_amd_image_copy', stela_amd_image_copy_probe, suite : 'stela')
  stela_amd_commands = static_library(
    'stela_amd_commands',
    'amd_commands.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_mesautil, idep_amd_generated_headers],
    link_with : [libamd_command_support],
  )

  stela_amd_compute = static_library(
    'stela_amd_compute',
    ['../../../../amd/stela/compute.c', '../../../../amd/stela/compute_policy.c',
     '../../../../amd/stela/llvm_compute.c'],
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_nir_headers, idep_mesautil, idep_amd_generated_headers],
    link_with : [stela_amd_buffer, stela_amd_commands, libamd_compiler_support],
    c_args : ['-Werror'],
  )
  stela_amd_compute_probe = executable(
    'stela_amd_compute_probe',
    '../../../../amd/tests/compute_test.c',
    include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
    dependencies : [idep_aco, idep_nir, idep_mesautil, idep_amd_generated_headers] +
                   (with_stela_amd_llvm ? [dep_llvm] : []),
    link_with : [stela_amd_compute] + (with_stela_amd_llvm ? [stela_amd_llvm_float] : []),
    c_args : ['-Werror', '-DSTELA_AMD_TEST_LLVM=' + (with_stela_amd_llvm ? '1' : '0')],
  )
  test('stela_amd_compute', stela_amd_compute_probe, suite : 'stela')
  if stela_air_llvm != '' and stela_metal_input != ''
    stela_amd_air = static_library(
      'stela_amd_air',
      '../../../../amd/stela/air_compile.c',
      include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers] +
                     (with_stela_amd_llvm ? [dep_llvm] : []),
      link_with : [stela_metal_assembly, stela_metal_threadgroup, stela_amd_buffer, libamd_compiler_support],
      c_args : ['-Werror'],
    )
    stela_amd_air_compile_test = executable(
      'stela_amd_air_compile_test',
      '../../../../amd/tests/air_compile.c',
      include_directories : [inc_include, inc_src, inc_amd, inc_amd_common],
      dependencies : [idep_stela_air, idep_aco, idep_amd_generated_headers,
                      dependency('appleframeworks', modules : ['CoreFoundation'])] +
                     (with_stela_amd_llvm ? [dep_llvm] : []),
      link_with : [stela_amd_air, stela_amd_compute, stela_apple_source],
      link_args : [stela_metal_input, '-lresolv', '-liconv'],
      c_args : ['-Werror'],
      build_rpath : fs.parent(stela_air_llvm),
    )
    test('stela_amd_air_owned', stela_amd_air_compile_test, suite : 'stela')
  endif
  if stela_air_llvm != '' and with_stela_amd_llvm
    stela_amd_air_threadgroup_probe = executable(
      'stela_amd_air_threadgroup_probe',
      '../../../../amd/tests/air_shared_test.c',
      include_directories : [inc_include, inc_src, inc_amd, inc_amd_common,
                             include_directories('.')],
      dependencies : [idep_nir, idep_aco, idep_mesautil, dep_llvm,
                      idep_amd_generated_headers],
      link_with : [stela_air, stela_amd_compute, stela_amd_llvm_float,
                   libamd_common_llvm, libamd_compiler_support, libamd_command_support],
      c_args : ['-Werror', '-DSTELA_AMD_TEST_LLVM=1'],
      build_rpath : fs.parent(stela_air_llvm),
    )
  endif

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
