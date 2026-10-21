# SPDX-License-Identifier: MIT
# These executables exercise the real compiler and its complete link closure.
# They do not open a device, submit GPU work, or expose a Metal device.
if with_stela_nvidia
  stela_nak_probe = executable(
    'stela_nak_probe',
    'nak_probe.c',
    include_directories : [inc_include, inc_src],
    dependencies : [idep_nak, idep_nir, idep_mesautil],
    link_with : [_libnak_rs],
  )
  test('stela_nak_codegen', stela_nak_probe, suite : 'stela')
endif
