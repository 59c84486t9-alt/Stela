#!/usr/bin/env python3
"""Report Apple-silicon translation evidence without inventing a completion denominator."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from evidence import write_evidence
import a64_checklist
import apple_isa

ROOT = Path(__file__).resolve().parents[1]
STATUSES = ('implemented', 'partial', 'unsupported')
RET = 0xd65f03c0
BLOCK_ABI = 'x86_64-sysv-guest-state-v2-block-exit-direct-ram'
SERVICE_ABI = BLOCK_ABI + '-apple-arm64e-software-pauth-clock-v1'
SCALABLE_PROFILE = 'apple-sme2-streaming-v1'
DECLARED_SCALABLE_PROFILE = 'sme-streaming-v2'
SCALABLE_PROFILE_IDS = (SCALABLE_PROFILE, DECLARED_SCALABLE_PROFILE)
# Architectural names accepted by scalable/features.rs; no feature implication.
SCALABLE_FEATURES = (
    'FEAT_BF16', 'FEAT_FAMINMAX', 'FEAT_I8MM', 'FEAT_SME', 'FEAT_SME2',
    'FEAT_SME2p1', 'FEAT_SME_B16B16', 'FEAT_SME_F16F16', 'FEAT_SME_F64F64',
    'FEAT_SME_F8F16', 'FEAT_SME_FA64', 'FEAT_SME_I16I64', 'FEAT_SVE_B16B16',
)
SCALABLE_DECLARATION_FIELDS = ('features', 'max_svl_bytes', 'zt0_enabled', 'dit')
CONTEXT_LEAF_ABI = 'x86_64-sysv-guest-state-v1-context-direct-ram'
CONTEXT_ENTRY_PREFIX_BYTES = 13
SCALABLE_VECTOR_BYTES = (16, 32, 64, 128, 256)
SCALABLE_GUEST_BASE = 0x10000000


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def repository_path(value):
    if not isinstance(value, str) or not value:
        raise ValueError('Evidence/source paths must be nonempty repository-relative paths')
    path = Path(value)
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Evidence/source paths must stay inside the repository')
    return path


def digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Expected a lowercase SHA-256 identity')
    return value


def _publication_entries(text, start, *, object_members):
    """Locate JSON member/element spans without rewriting their UTF-8 text."""
    opening, closing = ('{', '}') if object_members else ('[', ']')
    whitespace = ' \t\r\n'
    def skip(position):
        while position < len(text) and text[position] in whitespace:
            position += 1
        return position
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON object key in publication input')
            result[key] = value
        return result
    def non_json(value):
        raise ValueError('Non-JSON numeric constant in publication input: ' + value)
    decoder = json.JSONDecoder(object_pairs_hook=unique, parse_constant=non_json)
    position = skip(start)
    if position >= len(text) or text[position] != opening:
        raise ValueError('Publication container has the wrong JSON type')
    entries = []
    position += 1
    while True:
        entry_start = position
        position = skip(position)
        if position < len(text) and text[position] == closing:
            if entries:
                raise ValueError('Publication input has a trailing comma')
            return entries, position + 1
        key = None
        if object_members:
            key, position = decoder.raw_decode(text, position)
            if not isinstance(key, str):
                raise ValueError('Publication object key must be a string')
            position = skip(position)
            if position >= len(text) or text[position] != ':':
                raise ValueError('Publication object member has no colon')
            position = skip(position + 1)
        value_start = position
        value, value_end = decoder.raw_decode(text, value_start)
        position = skip(value_end)
        entry_end = position if position < len(text) and text[position] == ',' else value_end
        entries.append((key, value, entry_start, value_start, value_end, entry_end))
        if position < len(text) and text[position] == closing:
            return entries, position + 1
        if position >= len(text) or text[position] != ',':
            raise ValueError('Publication container has an invalid separator')
        position += 1


def validate_registry_preservation(base_path, candidate_path, *, owned_form_ids,
                                   owned_evidence_group_ids, owned_execution_profile_keys=(),
                                   allow_compiler_recipe_update=False, allow_registry_version_update=False):
    """Check a reviewed-registry publication without rewriting either input.

    Existing IDs and their order cannot be removed. Unowned rows, groups,
    specialization contracts and other metadata retain exact text, including
    Unicode escapes and indentation. New/updated IDs require explicit ownership;
    version and global compiler-recipe changes are separate deny-default flags.
    Builders should serialize new tracked text with ensure_ascii=False, then call
    this guard as well as the semantic registry/evidence validators.
    """
    if type(allow_compiler_recipe_update) is not bool or type(allow_registry_version_update) is not bool:
        raise ValueError('Publication metadata permissions must be explicit booleans')
    def owned(values):
        if isinstance(values, (str, bytes)):
            raise ValueError('Publication ownership must be a sequence of nonempty IDs')
        try:
            values = list(values)
        except TypeError as error:
            raise ValueError('Publication ownership must be an iterable of IDs') from error
        if any(not isinstance(value, str) or not value for value in values) or len(set(values)) != len(values):
            raise ValueError('Publication ownership IDs must be nonempty and unique')
        return set(values)
    permissions = {'forms': owned(owned_form_ids), 'evidence_groups': owned(owned_evidence_group_ids),
                   'execution_profiles': owned(owned_execution_profile_keys)}
    if Path(base_path).samefile(candidate_path):
        raise ValueError('Publication base and candidate must be distinct files')
    base_data, candidate_data = Path(base_path).read_bytes(), Path(candidate_path).read_bytes()
    base_text, candidate_text = base_data.decode('utf-8'), candidate_data.decode('utf-8')
    base_entries, base_end = _publication_entries(base_text, 0, object_members=True)
    candidate_entries, candidate_end = _publication_entries(candidate_text, 0, object_members=True)
    if base_text[base_end:].strip(' \t\r\n') or candidate_text[candidate_end:].strip(' \t\r\n'):
        raise ValueError('Publication input contains trailing non-JSON text')
    def by_key(entries):
        result = {}
        for entry in entries:
            if entry[0] in result:
                raise ValueError('Duplicate top-level publication key')
            result[entry[0]] = entry
        return result
    base, candidate = by_key(base_entries), by_key(candidate_entries)
    if (not all(key in base and key in candidate for key in ('forms', 'evidence_groups'))
            or set(base) - set(candidate)):
        raise ValueError('Publication removed required or existing metadata')
    additions = set(candidate) - set(base)
    if additions - {'execution_profiles'} or ('execution_profiles' in additions and not permissions['execution_profiles']):
        raise ValueError('Publication added undeclared top-level metadata')
    if [key for key in candidate if key in base] != list(base):
        raise ValueError('Publication reordered existing metadata keys')
    if (base_text[:base_entries[0][2]] != candidate_text[:candidate_entries[0][2]]
            or base_text[base_entries[-1][4]:] != candidate_text[candidate_entries[-1][4]:]):
        raise ValueError('Publication changed outer JSON framing')
    changes = {}
    for name, entry in candidate.items():
        previous = base.get(name)
        if previous is not None:
            suffix = candidate_text[entry[4]:entry[5]]
            final_to_nonfinal = (previous is base_entries[-1] and entry is not candidate_entries[-1]
                and suffix == base_text[previous[4]:base_end - 1])
            if (base_text[previous[2]:previous[3]] != candidate_text[entry[2]:entry[3]]
                    or (base_text[previous[4]:previous[5]] != suffix and not final_to_nonfinal)):
                raise ValueError('Publication changed metadata member framing: ' + name)
        if name not in permissions:
            allowed = ((name == 'compiler_fingerprint_sources' and allow_compiler_recipe_update)
                       or (name == 'registry_version' and allow_registry_version_update))
            if name == 'registry_version' and allowed and (not isinstance(previous[1], str)
                    or not isinstance(entry[1], str) or not entry[1]):
                raise ValueError('Publication version update must retain a nonempty string')
            if name == 'compiler_fingerprint_sources' and allowed and (not isinstance(entry[1], list)
                    or not entry[1] or any(not isinstance(path, str) or not path for path in entry[1])
                    or len(set(entry[1])) != len(entry[1])):
                raise ValueError('Publication compiler recipe must retain unique nonempty paths')
            if not allowed and base_text[previous[3]:previous[4]] != candidate_text[entry[3]:entry[4]]:
                raise ValueError('Publication changed unowned metadata: ' + name)
            continue
        object_members = name != 'forms'
        current_items, _ = _publication_entries(candidate_text, entry[3], object_members=object_members)
        prior_items = [] if previous is None else _publication_entries(
            base_text, previous[3], object_members=object_members)[0]
        def identify(items):
            result = {}
            for item in items:
                value = item[1]
                identity = item[0] if object_members else value.get('id') if isinstance(value, dict) else None
                if not isinstance(value, dict) or not isinstance(identity, str) or not identity or identity in result:
                    raise ValueError('Publication entries need unique nonempty object IDs: ' + name)
                result[identity] = item
            return result
        if previous is not None and not prior_items and not current_items and (
                base_text[previous[3]:previous[4]] != candidate_text[entry[3]:entry[4]]):
            raise ValueError('Publication changed empty container framing: ' + name)
        if prior_items and current_items and (
                base_text[prior_items[-1][4]:previous[4]] != candidate_text[current_items[-1][4]:entry[4]]):
            raise ValueError('Publication changed container closing framing: ' + name)
        before, after = identify(prior_items), identify(current_items)
        if set(before) - set(after):
            raise ValueError('Publication removed existing IDs: ' + name)
        if [identity for identity in after if identity in before] != list(before):
            raise ValueError('Publication reordered existing IDs: ' + name)
        if permissions[name] - set(after):
            raise ValueError('Publication ownership names an absent candidate ID: ' + name)
        added, updated, preserved = [], [], []
        for identity, item in after.items():
            old = before.get(identity)
            unchanged = False
            if old is not None:
                prefix_value_same = base_text[old[2]:old[4]] == candidate_text[item[2]:item[4]]
                suffix = candidate_text[item[4]:item[5]]
                suffix_same = base_text[old[4]:old[5]] == suffix
                # A prior final entry may retain its container's original
                # closing whitespace before the new comma of an owned append.
                final_to_nonfinal = (old is prior_items[-1] and item is not current_items[-1]
                    and suffix == base_text[old[4]:previous[4] - 1])
                unchanged = prefix_value_same and (suffix_same or final_to_nonfinal)
            changed = not unchanged
            if changed and identity not in permissions[name]:
                raise ValueError('Publication changed or added an unowned ID: ' + name + '/' + identity)
            (added if old is None else updated if changed else preserved).append(identity)
        changes[name] = {'added': added, 'updated': updated, 'preserved': preserved}
    if permissions['execution_profiles'] and 'execution_profiles' not in candidate:
        raise ValueError('Publication ownership names absent execution profiles')
    def metadata_changed(name):
        before, after = base.get(name), candidate.get(name)
        return (None if before is None else base_text[before[3]:before[4]]) != (
            None if after is None else candidate_text[after[3]:after[4]])
    return {'kind': 'reviewed_registry_publication_preservation', 'passed': True,
            'base_sha256': hashlib.sha256(base_data).hexdigest(),
            'candidate_sha256': hashlib.sha256(candidate_data).hexdigest(), 'entries': changes,
            'compiler_recipe_changed': metadata_changed('compiler_fingerprint_sources'),
            'registry_version_changed': metadata_changed('registry_version')}


def validate_registry(registry):
    if registry.get('schema_version') != 2 or registry.get('kind') != 'reviewed_apple_silicon_instruction_forms':
        raise ValueError('Unsupported Apple-silicon reviewed-form registry')
    target = registry.get('target_profile', {})
    if (target.get('vendor') != 'Apple' or target.get('guest_architectures') != ['arm64', 'arm64e']
            or target.get('host_architecture') != 'x86_64'):
        raise ValueError('Registry must target Apple arm64/arm64e to native x86_64')
    if target.get('required_isa_inventory_complete') is not False or target.get('required_isa_form_count') is not None:
        raise ValueError('An incomplete reviewed list cannot establish a required Apple ISA denominator')
    if not registry.get('registry_version') or not registry.get('instruction_sources') or not target.get('inventory_limits'):
        raise ValueError('Reviewed forms require versioned source facts and inventory limits')
    profile = registry.get('profile', {}).get('id')
    if not profile or not registry.get('profile', {}).get('outside_scope'):
        raise ValueError('Support needs an explicit bounded execution profile')
    scalable_profiles = None
    if profile in SCALABLE_PROFILE_IDS or 'execution_profiles' in registry:
        scalable_profiles = validate_scalable_profiles(registry['profile'], registry.get('execution_profiles'))
    evidence = registry.get('evidence_groups', {})
    rows = {}
    for row in registry.get('forms', []):
        identity = row.get('id')
        if not isinstance(identity, str) or not identity or identity in rows:
            raise ValueError('Reviewed form IDs must be unique and nonempty')
        if row.get('alias') is not False:
            raise ValueError('Aliases cannot inflate reviewed support counts')
        if not row.get('category') or not row.get('source_file') or not row.get('source_sha256'):
            raise ValueError('Reviewed forms need their instruction source facts')
        digest(row['source_sha256'])
        mask, value = int(row['encoding_mask'], 16), int(row['encoding_value'], 16)
        if not 0 <= mask <= 0xffffffff or not 0 <= value <= 0xffffffff or value & ~mask:
            raise ValueError('Invalid reviewed encoding mask/value')
        if row.get('status') not in STATUSES:
            raise ValueError('Unknown support status')
        if (not row.get('scope') or not isinstance(row.get('profile'), str)
                or (row.get('profile') not in scalable_profiles
                if scalable_profiles is not None else row.get('profile') != profile)):
            raise ValueError('Form support scope/profile missing')
        row_contract = scalable_profiles[row['profile']] if scalable_profiles is not None else None
        if row['status'] != 'unsupported':
            if not row.get('review') or not row.get('compiler_sources') or not row.get('smoke_samples'):
                raise ValueError('Support requires reviewed implementation and smoke samples')
            if not row.get('evidence_groups') or any(group not in evidence for group in row['evidence_groups']):
                raise ValueError('Support requires a native differential evidence group')
            for source in row['compiler_sources']:
                repository_path(source)
            for sample in row['smoke_samples']:
                validate_sample(row, sample)
                if row_contract is not None:
                    validate_scalable_sample(sample, row_contract)
            if row['status'] == 'partial' and not row.get('rejected_samples'):
                raise ValueError('Partial forms need a rejected scope-boundary sample')
            if row_contract is not None:
                for sample in row.get('rejected_samples', []):
                    validate_scalable_sample(sample, row_contract)
        rows[identity] = row
    return rows


def validate_sample(form, sample):
    word = int(sample['word'], 16)
    if not 0 <= word <= 0xffffffff or word & int(form['encoding_mask'], 16) != int(form['encoding_value'], 16):
        raise ValueError(f'Smoke does not match canonical form: {form["id"]}')
    # Official byte-register forms distinguish an extended operand from LSL,
    # although the extended form's !=011 constraint cannot fit a fixed mask.
    reguse = form.get('docvars', {}).get('reguse') if form['id'].endswith('_ldst_regoff') else None
    if reguse == 'ext-reg' and ((word >> 13) & 7) not in (2, 6, 7):
        raise ValueError('Extended-register smoke has the wrong operand form')
    if reguse == 'shifted-reg' and ((word >> 13) & 7) != 3:
        raise ValueError('Shifted-register smoke has the wrong operand form')
    expected = sample.get('expected_mnemonics')
    if not isinstance(expected, list) or not expected:
        raise ValueError('Smoke needs an independent decoded mnemonic expectation')
    consumed = sample.get('consumed_source_bytes', 4)
    if type(consumed) is not int or consumed not in (4, 8):
        raise ValueError('Smoke must declare a valid instruction/RET boundary')
    return word


def summarize(rows):
    categories = {}
    overall = Counter({status: 0 for status in STATUSES})
    for row in rows.values():
        counts = categories.setdefault(row['category'], Counter({status: 0 for status in STATUSES}))
        counts[row['status']] += 1
        overall[row['status']] += 1
    def finish(counts):
        return {**dict(counts), 'reviewed_forms': sum(counts.values())}
    return {'categories': {key: finish(counts) for key, counts in sorted(categories.items())},
            'reviewed': finish(overall), 'required_isa_forms': None,
            'required_isa_completion_percentage': None, 'overall_completion_percentage': None,
            'complete_binaries': {'verified': 0, 'full_binary_harness_available': False,
                                  'required_total': None, 'completion_percentage': None,
                                  'evidence_requirement': 'Stela full Mach-O load and native execution with validated process behavior; leaf fixtures do not qualify.'}}


def validate_scalable_configuration(svl_bytes, svcr):
    if type(svl_bytes) is not int or svl_bytes not in SCALABLE_VECTOR_BYTES:
        raise ValueError('Scalable probe requires an explicit supported SVL')
    if type(svcr) is not int or svcr not in (0, 1, 2, 3):
        raise ValueError('Scalable probe requires an explicit supported SVCR')


def scalable_execution_profile(guest_profile, svl_bytes, svcr, *, features=None,
                               max_svl_bytes=None, zt0_enabled=None, dit=None):
    validate_scalable_configuration(svl_bytes, svcr)
    execution = {'id': guest_profile, 'svl_bytes': svl_bytes, 'svcr': svcr}
    declaration = (features, max_svl_bytes, zt0_enabled, dit)
    if guest_profile == SCALABLE_PROFILE:
        if any(value is not None for value in declaration):
            raise ValueError('V1 scalable profile does not accept V2 declarations')
        return execution
    if guest_profile != DECLARED_SCALABLE_PROFILE:
        raise ValueError('Unknown scalable guest profile')
    if (not isinstance(features, list) or not features
            or any(not isinstance(feature, str) or feature not in SCALABLE_FEATURES for feature in features)
            or len(set(features)) != len(features)):
        raise ValueError('V2 scalable profile requires explicit unique known architectural features')
    if 'FEAT_SME' not in features:
        raise ValueError('V2 scalable profile requires FEAT_SME')
    if 'FEAT_SME2p1' in features and 'FEAT_SME2' not in features:
        raise ValueError('FEAT_SME2p1 requires explicit FEAT_SME2')
    if type(max_svl_bytes) is not int or max_svl_bytes not in SCALABLE_VECTOR_BYTES or svl_bytes > max_svl_bytes:
        raise ValueError('V2 scalable profile requires a supported maximum SVL covering the current SVL')
    if type(zt0_enabled) is not bool or type(dit) is not bool or dit is not False:
        raise ValueError('V2 scalable profile requires explicit ZT0 permission and DIT=false')
    if zt0_enabled and 'FEAT_SME2' not in features:
        raise ValueError('ZT0 permission requires explicit FEAT_SME2')
    execution.update(features=sorted(features), max_svl_bytes=max_svl_bytes,
                     zt0_enabled=zt0_enabled, dit=dit)
    return execution


def scalable_declaration(profile):
    return {key: profile[key] for key in SCALABLE_DECLARATION_FIELDS if key in profile}


def validate_scalable_profile(profile):
    common = {'id', 'compiler_command', 'abi', 'svl_bytes', 'svcr', 'description', 'outside_scope',
              'decoder_mattrs'}
    if (not isinstance(profile, dict) or set(profile) - common - set(SCALABLE_DECLARATION_FIELDS)
            or profile.get('compiler_command') != 'compile-leaf' or profile.get('abi') != CONTEXT_LEAF_ABI):
        raise ValueError('Scalable registry must declare only supported context-leaf profile fields')
    execution = scalable_execution_profile(profile.get('id'), profile.get('svl_bytes'), profile.get('svcr'),
                                            **scalable_declaration(profile))
    if 'decoder_mattrs' in profile:
        attrs = profile['decoder_mattrs']
        if (not isinstance(attrs, list) or not attrs
                or any(not isinstance(attr, str) for attr in attrs) or len(set(attrs)) != len(attrs)):
            raise ValueError('Independent decoder attributes must be an explicit unique list')
        import a64_disassembly
        if any(not a64_disassembly.FEATURE_NAME.fullmatch(attr) for attr in attrs):
            raise ValueError('Unsupported independent decoder attribute syntax')
    return execution


def validate_scalable_profiles(default_profile, execution_profiles=None):
    default = validate_scalable_profile(default_profile)
    profiles = {default_profile['id']: default_profile}
    identities = {json.dumps({key: value for key, value in default.items() if key not in ('svl_bytes', 'svcr')},
                             sort_keys=True)}
    if execution_profiles is not None:
        if not isinstance(execution_profiles, dict) or not execution_profiles:
            raise ValueError('Execution profiles must be a nonempty specialization-key mapping')
        for key, contract in execution_profiles.items():
            if not isinstance(key, str) or not key or key in profiles:
                raise ValueError('Execution profile keys must be unique and distinct from the default profile')
            execution = validate_scalable_profile(contract)
            if not contract.get('outside_scope'):
                raise ValueError('Execution profile specialization needs explicit scope limits')
            identity = json.dumps({name: value for name, value in execution.items()
                                   if name not in ('svl_bytes', 'svcr')}, sort_keys=True)
            if identity in identities:
                raise ValueError('Duplicate semantic execution-profile contract')
            identities.add(identity)
            profiles[key] = contract
    return profiles


def validate_scalable_sample(sample, contract):
    allowed = {'word', 'expected_mnemonics', 'consumed_source_bytes', 'svl_bytes', 'svcr', 'reason'}
    if set(sample) - allowed:
        raise ValueError('Samples must use declared fields and select guest features/controls through the row profile')
    return scalable_execution_profile(contract['id'], sample.get('svl_bytes'), sample.get('svcr'),
                                       **scalable_declaration(contract))


def validate_context_manifest(manifest, source_data, native_bytes, svl_bytes, svcr,
                              guest_profile=SCALABLE_PROFILE,
                              expected_target_cpu='x86_64-baseline', **declaration):
    if (type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 2 or manifest.get('kind') != 'raw_arm64_leaf_aot'
            or manifest.get('abi') != CONTEXT_LEAF_ABI):
        raise ValueError('Compiler scalable probe schema/ABI mismatch')
    expected = scalable_execution_profile(guest_profile, svl_bytes, svcr, **declaration)
    profile = manifest.get('execution_profile')
    if (not isinstance(profile, dict) or profile != expected
            or any(type(profile.get(key)) is not type(value) for key, value in expected.items())):
        raise ValueError('Compiler scalable probe execution profile mismatch')
    instructions = len(source_data) // 4
    if (not isinstance(expected_target_cpu, str) or not expected_target_cpu
            or manifest.get('target_cpu') != expected_target_cpu or type(manifest.get('guest_base')) is not int or manifest['guest_base'] != SCALABLE_GUEST_BASE
            or type(manifest.get('guest_instructions')) is not int
            or manifest['guest_instructions'] != instructions
            or type(manifest.get('native_bytes')) is not int or manifest['native_bytes'] != native_bytes):
        raise ValueError('Compiler scalable probe source/native metadata mismatch')
    prefix = manifest.get('entry_prefix_bytes')
    source_map = manifest.get('source_map')
    if (type(prefix) is not int or prefix != CONTEXT_ENTRY_PREFIX_BYTES or prefix >= native_bytes
            or not isinstance(source_map, list) or len(source_map) != instructions):
        raise ValueError('Compiler scalable probe source map missing or invalid')
    previous = prefix
    for index, entry in enumerate(source_map):
        if (not isinstance(entry, list) or len(entry) != 2
                or type(entry[0]) is not int or entry[0] != SCALABLE_GUEST_BASE + index * 4
                or type(entry[1]) is not int or not previous <= entry[1] < native_bytes
                or (index == 0 and entry[1] != prefix)):
            raise ValueError('Compiler scalable probe source map boundary mismatch')
        previous = entry[1]


def compile_probe(cli, word, directory, expect_failure=None, run=subprocess.run, mode='leaf',
                  expected_source_bytes=4, guest_profile=None, svl_bytes=None, svcr=None,
                  features=None, max_svl_bytes=None, zt0_enabled=None, dit=None):
    if mode not in ('leaf', 'block', 'service', 'scalable'):
        raise ValueError('Unknown compiler probe mode')
    if type(expected_source_bytes) is not int or expected_source_bytes not in (4, 8):
        raise ValueError('Invalid declared compiler probe boundary')
    if mode == 'scalable':
        execution = scalable_execution_profile(guest_profile, svl_bytes, svcr, features=features,
            max_svl_bytes=max_svl_bytes, zt0_enabled=zt0_enabled, dit=dit)
    elif any(value is not None for value in (guest_profile, svl_bytes, svcr, features,
                                            max_svl_bytes, zt0_enabled, dit)):
        raise ValueError('Scalable configuration requires the context compiler lane')
    source = directory / 'source.arm64'
    source.write_bytes(struct.pack('<II', word, RET))
    output = directory / 'native'
    compiler_mode = 'leaf' if mode == 'scalable' else 'block' if mode == 'service' else mode
    command = [str(cli), 'compile-' + compiler_mode, str(source), '--output-dir', str(output)]
    if mode != 'leaf':
        command.extend(['--guest-base', '0x10000000'])
    if mode == 'scalable':
        command.extend(['--guest-profile', guest_profile, '--svl-bytes', str(svl_bytes),
                        '--svcr', str(svcr), '--cpu-target', 'baseline'])
        if guest_profile == DECLARED_SCALABLE_PROFILE:
            for feature in execution['features']:
                command.extend(['--guest-feature', feature])
            command.extend(['--max-svl-bytes', str(max_svl_bytes),
                            '--zt0-enabled', str(zt0_enabled).lower()])
    if mode == 'service':
        command.extend(['--software-pauth', '--software-clock'])
    process = run(command,
                  capture_output=True, text=True, timeout=30)
    if expect_failure:
        if process.returncode == 0 or expect_failure not in process.stderr or output.exists():
            raise ValueError(f'Expected unsupported scope boundary {word:#x}: {process.stderr}')
        return {'word': f'0x{word:08x}', 'rejected': True, 'reason': expect_failure}
    if process.returncode != 0:
        raise ValueError(f'Reviewed supported form no longer emits {word:#x}: {process.stderr}')
    manifest = json.loads(process.stdout)
    source_data = source.read_bytes()
    if mode in ('block', 'service'):
        if manifest.get('abi') != (SERVICE_ABI if mode == 'service' else BLOCK_ABI):
            raise ValueError('Compiler block probe ABI mismatch')
        consumed = manifest.get('source_bytes')
        if type(consumed) is not int or consumed != expected_source_bytes:
            raise ValueError('Compiler block probe differs from the declared consumed boundary')
        source_data = source_data[:consumed]
    if manifest.get('source_sha256') != hashlib.sha256(source_data).hexdigest():
        raise ValueError('Compiler probe source identity mismatch')
    native = output / 'native.bin'
    if manifest.get('native_sha256') != sha256(native) or native.stat().st_size == 0:
        raise ValueError('Compiler probe native output identity mismatch')
    if mode == 'scalable':
        validate_context_manifest(manifest, source_data, native.stat().st_size, svl_bytes, svcr,
            guest_profile, **({key: execution[key] for key in SCALABLE_DECLARATION_FIELDS}
                             if guest_profile == DECLARED_SCALABLE_PROFILE else {}))
    fingerprint = manifest.get('compiler_source_sha256')
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise ValueError('Compiler probe fingerprint missing')
    if mode == 'scalable':
        digest(fingerprint)
    return {'word': f'0x{word:08x}', 'emitted': True, 'compiler_source_sha256': fingerprint,
            'source_sha256': manifest['source_sha256'], 'native_sha256': manifest['native_sha256'],
            'native_bytes': native.stat().st_size,
            **({'abi': manifest['abi'], 'source_bytes': consumed, 'compiler_mode': mode}
               if mode in ('block', 'service') else {}),
            **({key: manifest[key] for key in ('abi', 'execution_profile', 'source_map', 'entry_prefix_bytes',
                                               'guest_base', 'target_cpu')} if mode == 'scalable' else {})}


def smoke_decoding(decoder, word, identity, canonical_facts=None, independent_rows=None,
                   preferred_aliases=None):
    instruction = next(decoder.disasm(struct.pack('<I', word), 0), None)
    if instruction is not None:
        return instruction.mnemonic, f'{instruction.mnemonic} {instruction.op_str}', 'capstone'
    # CSSC has no reserved operand combinations beyond its fixed encoding bits.
    # This limited alternative uses independently hash-validated Arm facts;
    # it does not claim that the installed Capstone decoded the instruction.
    fact = (canonical_facts or {}).get(identity)
    if (fact is not None and any(feature['feature'] == 'FEAT_CSSC' for feature in fact['features'])
            and word & int(fact['encoding_mask'], 16) == int(fact['encoding_value'], 16)):
        mnemonic = fact['mnemonic'].lower()
        return mnemonic, mnemonic, 'pinned_arm_cssc_fixed_encoding'
    if word in (independent_rows or {}):
        import a64_disassembly
        if fact is None:
            raise ValueError('Independent LLVM decoding requires validated canonical facts')
        return a64_disassembly.validate_canonical(independent_rows[word], identity, fact,
                                                  preferred_aliases=preferred_aliases)
    raise ValueError(f'Independent decoder declined {identity}: {word:#x}')


def smoke_forms(cli, forms, overrides, directory, mode='leaf', canonical_facts=None, profile=None,
                execution_profiles=None, canonical_catalog=None, arm_archive=None):
    profiles = validate_scalable_profiles(profile or {}, execution_profiles) if mode == 'scalable' else {}
    def contract(row=None):
        return profiles[profile['id'] if row is None else row['profile']]
    def options(sample=None, row=None):
        result = {'mode': mode} if mode != 'leaf' else {}
        if mode == 'scalable':
            declaration = contract(row)
            configuration = declaration if sample is None else sample
            result.update(guest_profile=declaration['id'], svl_bytes=configuration['svl_bytes'],
                          svcr=configuration['svcr'], **scalable_declaration(declaration))
        return result
    decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    fingerprint = None
    results = []
    independent_receipts = {}
    preferred_aliases = None
    if mode == 'scalable':
        import a64_disassembly
        declined = {}
        for identity, row in overrides.items():
            if row['status'] == 'unsupported':
                continue
            attrs = tuple(contract(row).get('decoder_mattrs', a64_disassembly.DEFAULT_MATTRS))
            for sample in row['smoke_samples']:
                word = validate_sample(forms[identity], sample)
                if next(decoder.disasm(struct.pack('<I', word), 0), None) is None:
                    declined.setdefault(attrs, set()).add(word)
        for index, (attrs, words) in enumerate(sorted(declined.items())):
            independent_receipts[attrs] = a64_disassembly.decode_words(
                sorted(words), directory / f'llvm-decoding-{index}', mattrs=attrs)
        alias_identities = set()
        for identity, row in overrides.items():
            if row['status'] == 'unsupported':
                continue
            attrs = tuple(contract(row).get('decoder_mattrs', a64_disassembly.DEFAULT_MATTRS))
            decoded = {entry['word']: entry for entry in independent_receipts.get(attrs, {}).get('rows', [])}
            fact = (canonical_facts or {}).get(identity)
            for sample in row['smoke_samples']:
                actual = decoded.get(validate_sample(forms[identity], sample))
                if actual is not None and fact is not None and actual['mnemonic'] != fact['mnemonic'].lower():
                    alias_identities.add(identity)
        if alias_identities:
            if canonical_catalog is None or arm_archive is None:
                raise ValueError('Independent preferred aliases require the validated catalog and pinned Arm archive')
            preferred_aliases = a64_disassembly.PreferredAliases(
                canonical_catalog, arm_archive, sorted(alias_identities))
    for identity, row in overrides.items():
        if row['status'] == 'unsupported':
            continue
        for index, sample in enumerate(row['smoke_samples']):
            word = validate_sample(forms[identity], sample)
            independent_receipt = None
            independent_rows = {}
            if mode == 'scalable':
                attrs = tuple(contract(row).get('decoder_mattrs', a64_disassembly.DEFAULT_MATTRS))
                independent_receipt = independent_receipts.get(attrs)
                if independent_receipt is not None:
                    independent_rows = {entry['word']: entry for entry in independent_receipt['rows']}
            mnemonic, assembly, basis = smoke_decoding(
                decoder, word, identity, canonical_facts, independent_rows, preferred_aliases)
            if mnemonic not in sample['expected_mnemonics']:
                raise ValueError(f'Independent decoder differs for {identity}: {word:#x}')
            location = directory / f'{len(results)}-supported'
            location.mkdir()
            probe_options = options(sample, row)
            if 'consumed_source_bytes' in sample:
                probe_options['expected_source_bytes'] = sample['consumed_source_bytes']
            probe = compile_probe(cli, word, location, **probe_options)
            if fingerprint is not None and fingerprint != probe['compiler_source_sha256']:
                raise ValueError('Compiler changed during ISA progress probes')
            fingerprint = probe['compiler_source_sha256']
            results.append({'id': identity, 'sample': index, 'assembly': assembly,
                            'independent_decode_basis': basis, **probe,
                            **({'independent_decode_receipt': independent_receipt}
                               if basis == 'apple_llvm21_objdump' else {}),
                            **({'independent_preferred_alias_facts': preferred_aliases.evidence()}
                               if basis == 'apple_llvm21_objdump' and preferred_aliases is not None
                               and mnemonic != canonical_facts[identity]['mnemonic'].lower() else {})})
        for index, sample in enumerate(row.get('rejected_samples', [])):
            location = directory / f'{len(results)}-rejected'
            location.mkdir()
            probe = compile_probe(cli, int(sample['word'], 16), location, sample['reason'],
                                  **options(sample, row))
            results.append({'id': identity, 'scope_boundary_sample': index, **probe})
    if fingerprint is None:
        location = directory / 'compiler-identity'
        location.mkdir()
        probe = compile_probe(cli, RET, location, **options())
        fingerprint = probe['compiler_source_sha256']
        if mode == 'scalable':
            results.append({'compiler_identity_only': True, **probe})
    return fingerprint, results


def validate_evidence(registry, overrides, compiler, root=ROOT, executable_hash=None):
    names = sorted({name for row in overrides.values() if row['status'] != 'unsupported'
                    for name in row['evidence_groups']})
    results = {}
    for name in names:
        group = registry['evidence_groups'][name]
        path = root / repository_path(group['report'])
        report_data = path.read_bytes()
        report = json.loads(report_data)
        if report.get('passed') is not True or report.get('kind') != group['kind']:
            raise ValueError(f'Native differential evidence missing or failed: {name}')
        if report.get('compiler_source_sha256') != compiler:
            raise ValueError(f'Stale native differential compiler evidence: {name}')
        comparison_keys = (('single_block_state_exit_comparisons',)
                           if group['kind'] == 'arm64_block_control_flow_differential'
                           else ('state_comparisons', 'state_and_memory_comparisons',
                                 'register_state_comparisons', 'three_way_register_state_comparisons'))
        comparison_field = group.get('comparison_field')
        if comparison_field is not None:
            comparison_keys = (comparison_field,)
        comparisons = next((report[key] for key in comparison_keys if key in report), None)
        if type(comparisons) is not int or comparisons <= 0:
            raise ValueError(f'Native differential evidence has no comparisons: {name}')
        harness = root / repository_path(group['harness'])
        harness_hash = sha256(harness)
        recorded = report.get('harness_source_sha256', report.get('sources_sha256', {}).get(group['harness']))
        if recorded != harness_hash:
            raise ValueError(f'Stale differential harness evidence: {name}')
        shared = {}
        if 'sources_sha256' in report:
            shared.update(report['sources_sha256'])
        if 'shared_runner_sha256' in report:
            shared['dev/differential.py'] = report['shared_runner_sha256']
        if 'shared_sources_sha256' in report:
            declared = report['shared_sources_sha256']
            if not isinstance(declared, dict):
                raise ValueError('Shared differential source identities must be a mapping')
            for source, digest in declared.items():
                source_path = Path(source)
                if source_path.is_absolute() or '..' in source_path.parts:
                    raise ValueError('Shared source must be a repository-relative path')
                if not (root / source_path).is_file():
                    source_path = Path('dev') / source_path
                if str(source_path) in shared and shared[str(source_path)] != digest:
                    raise ValueError('Conflicting shared differential source identities')
                shared[str(source_path)] = digest
        for source in group.get('required_shared_sources', []):
            if str(repository_path(source)) not in shared:
                raise ValueError(f'Differential report does not bind required shared source: {source}')
        if group.get('abi') is not None and report.get('abi') != group['abi']:
            raise ValueError(f'Differential ABI mismatch: {name}')
        for source, digest in shared.items():
            if sha256(root / source) != digest:
                raise ValueError(f'Stale shared differential source evidence: {source}')
        results[name] = {'report': group['report'], 'report_sha256': hashlib.sha256(report_data).hexdigest(),
                         'harness': group['harness'], 'harness_source_sha256': harness_hash,
                         'report_binds_harness_hash': True,
                         'shared_sources_sha256': shared,
                         'native_comparisons': comparisons, 'compiler_source_sha256': compiler,
                         'comparison_field': comparison_field}
        for key in group.get('required_positive_counts', []):
            if type(report.get(key)) is not int or report[key] <= 0:
                raise ValueError(f'Differential evidence missing positive count {key}')
            results[name][key] = report[key]
        for key, expected in group.get('required_measurements', {}).items():
            value = report
            # Slash-separated paths preserve literal dots in CPU profile names.
            parts = key[1:].split('/') if key.startswith('/') else key.split('.')
            for part in parts:
                value = value.get(part) if isinstance(value, dict) else None
            if type(value) is not int or value != expected:
                raise ValueError(f'Differential evidence missing required measurement {key}')
        if group.get('require_current_executable') and report.get('compiler_executable_sha256') != executable_hash:
            raise ValueError('Stale service runtime executable evidence')
        if group['kind'] == 'arm64_block_control_flow_differential':
            if executable_hash is not None and report.get('compiler_executable_sha256') != executable_hash:
                raise ValueError('Stale native block runtime executable evidence')
            for key in ('multiblock_state_exit_comparisons', 'rust_runtime_execution_comparisons'):
                if type(report.get(key)) is not int or report[key] <= 0:
                    raise ValueError(f'Block differential evidence missing {key}')
                results[name][key] = report[key]
    sources = sorted({path for row in overrides.values() if row['status'] != 'unsupported'
                      for path in row['compiler_sources']})
    return results, {path: sha256(root / path) for path in sources}


def validate_current_compiler(registry, compiler, root=ROOT):
    paths = registry.get('compiler_fingerprint_sources')
    if not isinstance(paths, list) or not paths or len(set(paths)) != len(paths):
        raise ValueError('Registry needs the ordered compiler fingerprint source recipe')
    sources = {str(repository_path(path)): (root / repository_path(path)).read_bytes() for path in paths}
    if hashlib.sha256(b''.join(sources.values())).hexdigest() != compiler:
        raise ValueError('Built compiler fingerprint differs from current source bytes')
    return {path: hashlib.sha256(data).hexdigest() for path, data in sources.items()}


def markdown(report):
    if 'apple_codegen_candidates' in report:
        row = report['apple_codegen_candidates']['summary']['union']
        apple = report['apple_specific_extensions']
        checkpoint = report.get('last_verified_checkpoint')
        checkpoint_row, basis = '', ''
        if report.get('implementation_only'):
            checkpoint_text = (f"{checkpoint['implemented']:,} / {checkpoint['total']:,}; compiler `{checkpoint['compiler_source_sha256'][:12]}`"
                               if checkpoint else 'Pending')
            checkpoint_row = f'| Last full instruction-verification checkpoint | {checkpoint_text} |\n'
            basis = 'Current counts reflect reviewed implementation and emission smoke checks. Full regression verification is deferred to integration checkpoints. '
        return ('| Measurement | Current evidence |\n| --- | --- |\n'
                f"| Apple M1–M5 candidate forms implemented | **{row['implemented']:,} / {row['total']:,} ({row['implementation_percentage']:.2f}%)** |\n"
                f"| Candidate forms partially implemented | {row['partial']:,} |\n"
                f"| Candidate forms unimplemented | {row['unsupported']:,} |\n" + checkpoint_row +
                f"| Apple-specific extension groups | {apple['implemented']} implemented / {apple['tracked']} tracked; inventory open |\n"
                f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n\n"
                f"Pinned LLVM Apple CPU models mapped to Arm **2026-06**; compiler `{report['compiler_source_sha256'][:12]}`. " + basis +
                'Canonical encoding forms count once across reviewed execution profiles; aliases are excluded and partial forms earn no credit. '
                'This candidate inventory includes streaming SVE through SME, without general non-streaming SVE. '
                'Full hardware membership, M6 and Apple-private additions remain open; reviewed-profile instruction coverage does not establish complete CPU, application or macOS compatibility.\n\n'
                '[Apple profile inventory](tests/isa/apple-codegen-profiles.json) · '
                '[Arm reference checklist](tests/isa/a64-documented-checklist.json) · '
                '[Apple extensions](tests/isa/apple-specific-extensions.json) · '
                '[Scope and evidence](docs/development.md#apple-code-generation-candidate-inventory).\n')
    if 'documented_isa' in report:
        row = report['documented_isa']['summary']
        apple = report['apple_specific_extensions']
        return ('| Measurement | Current evidence |\n| --- | --- |\n'
                f"| Documented A64 ISA implemented | **{row['implemented']:,} / {row['total']:,} ({row['implementation_percentage']:.2f}%)** |\n"
                f"| Documented forms partially implemented | {row['partial']:,} |\n"
                f"| Documented forms unimplemented | {row['unsupported']:,} |\n"
                f"| Apple-specific extension groups | {apple['implemented']} implemented / {apple['tracked']} tracked; inventory open |\n"
                f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n\n"
                f"Arm reference **2026-06**; compiler `{report['compiler_source_sha256'][:12]}`. "
                'Each canonical encoding form counts once across reviewed execution profiles; aliases are excluded and partial forms earn no credit. '
                'The fixed denominator includes optional and privileged A64 extensions, including forms beyond Apple hardware. '
                'This measures documented ISA implementation, not macOS or application completion.\n\n'
                '[Complete checklist](tests/isa/a64-documented-checklist.json) · '
                '[Apple extensions](tests/isa/apple-specific-extensions.json) · '
                '[Scope and evidence](docs/development.md#documented-a64-checklist).\n')
    row = report['summary']['reviewed']
    block = report.get('block_profile_evidence')
    block_rows = ''
    if block:
        counts = block['summary']['reviewed']
        groups = block['native_differential_evidence'].values()
        comparisons = sum(group['native_comparisons'] for group in groups
                          if group.get('comparison_field') != 'trap_state_exit_comparisons')
        traps = sum(group['native_comparisons'] for group in groups
                    if group.get('comparison_field') == 'trap_state_exit_comparisons')
        block_rows = (f"| Block-profile instruction forms implemented | {counts['implemented']:,} |\n"
                      f"| Native block state/exit comparisons | {comparisons:,} |\n")
        if counts['partial']:
            block_rows += f"| Block-profile forms partially implemented | {counts['partial']:,} |\n"
        if traps:
            block_rows += f"| Native synchronous-trap boundary comparisons | {traps:,} |\n"
    return ('| Measurement | Current evidence |\n| --- | --- |\n'
            f"| Leaf-profile instruction forms implemented | {row['implemented']:,} |\n"
            f"| Leaf-profile instruction forms partially implemented | {row['partial']:,} |\n"
            + block_rows +
            '| Required Apple-silicon ISA inventory | Incomplete; total unknown |\n'
            '| Required ISA completion | Unknown |\n'
            f"| Complete binaries verified through Stela | {report['summary']['complete_binaries']['verified']:,} |\n"
            '| Overall compatibility completion | Unknown |\n\n'
            f"Snapshot {report['measured_at_utc'].split('T')[0]} UTC; compiler `{report['compiler_source_sha256'][:12]}`.\n\n"
            'Reviewed forms cover bounded leaf/private-RAM and block-exit profiles, with aliases excluded. '
            'Profile counts overlap and are not added. '
            'They are an implementation count, not a percentage of the required Apple ISA. '
            'Complete binaries require full loading and execution; leaf tests do not qualify. '
            '[Scope and evidence](docs/development.md).\n')


def write_markdown(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as pending:
        pending.write(content)
        name = pending.name
    try:
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def update_readme(path, fragment):
    path = Path(path)
    text = path.read_text()
    start, end = '<!-- stela-instruction-progress:start -->', '<!-- stela-instruction-progress:end -->'
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError('README needs exactly one progress marker pair')
    first, last = text.index(start) + len(start), text.index(end)
    if first > last:
        raise ValueError('README progress markers reversed')
    updated = text[:first] + '\n' + fragment.rstrip() + '\n' + text[last:]
    if path.read_text() != text:
        raise ValueError('README changed during update')
    write_markdown(path, updated)


def previous_checkpoint(path, root=ROOT):
    """Smoke-only updates preserve an archived verified baseline without advancing it."""
    path = Path(path)
    if not path.exists():
        return None
    data = path.read_bytes()
    previous = json.loads(data)
    digest = hashlib.sha256(data).hexdigest()
    archived = root / '.stela/evidence' / path.stem / (digest + '.json')
    if not archived.exists() or archived.read_bytes() != data:
        raise ValueError('Previous checkpoint is not bound to its evidence archive')
    if previous.get('implementation_only'):
        return previous.get('last_verified_checkpoint')
    if previous.get('kind') != 'apple_silicon_translation_progress' or not previous.get('native_differential_evidence'):
        return None
    row = previous['apple_codegen_candidates']['summary']['union']
    return {'implemented': row['implemented'], 'total': row['total'],
            'compiler_source_sha256': previous['compiler_source_sha256'],
            'measured_at_utc': previous['measured_at_utc'], 'report_sha256': digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, default=ROOT / 'tests/isa/apple-silicon-reviewed-forms.json')
    parser.add_argument('--block-registry', type=Path, default=ROOT / 'tests/isa/apple-silicon-block-forms.json')
    parser.add_argument('--service-registry', type=Path, default=ROOT / 'tests/isa/a64-service-forms.json')
    parser.add_argument('--scalable-registry', type=Path, default=ROOT / 'tests/isa/apple-silicon-scalable-forms.json')
    parser.add_argument('--checklist', type=Path, default=ROOT / 'tests/isa/a64-documented-checklist.json')
    parser.add_argument('--arm-archive', type=Path,
                        default=ROOT / '.stela/isa/ISA_A64_xml_A_profile-2026-06.tar.gz',
                        help='Pinned June 2026 Arm XML archive; required only for preferred-alias LLVM rows')
    parser.add_argument('--apple-profiles', type=Path, default=ROOT / 'tests/isa/apple-codegen-profiles.json')
    parser.add_argument('--cli', type=Path, default=ROOT / 'target/debug/stela')
    parser.add_argument('--output', type=Path, default=ROOT / '.stela/progress/apple-silicon.json')
    parser.add_argument('--markdown-output', type=Path)
    parser.add_argument('--update-readme', action='store_true')
    parser.add_argument('--implementation-only', action='store_true',
                        help='Refresh implementation/emission counts while retaining the full verification checkpoint')
    args = parser.parse_args()
    checkpoint = previous_checkpoint(args.output) if args.implementation_only else None
    registry_data = args.registry.read_bytes()
    registry = json.loads(registry_data)
    rows = validate_registry(registry)
    block_data = args.block_registry.read_bytes()
    block_registry = json.loads(block_data)
    block_rows = validate_registry(block_registry)
    service_data = args.service_registry.read_bytes()
    service_registry = json.loads(service_data)
    service_rows = validate_registry(service_registry)
    scalable_data = args.scalable_registry.read_bytes()
    scalable_registry = json.loads(scalable_data)
    scalable_rows = validate_registry(scalable_registry)
    validate_scalable_profile(scalable_registry['profile'])
    catalog_data = args.checklist.read_bytes()
    catalog = json.loads(catalog_data)
    canonical_facts = a64_checklist.validate(catalog)
    apple_profiles_data = args.apple_profiles.read_bytes()
    apple_profiles = json.loads(apple_profiles_data)
    apple = json.loads((ROOT / 'tests/isa/apple-specific-extensions.json').read_bytes())
    if apple.get('kind') != 'apple_specific_extension_ledger' or apple.get('inventory_complete') is not False:
        raise ValueError('Apple additions need a separate explicitly open inventory')
    if len({r['id'] for r in apple['extensions']}) != len(apple['extensions']) or any(r['status'] not in STATUSES for r in apple['extensions']):
        raise ValueError('Invalid Apple extension identity/status')
    if (block_registry['profile'].get('compiler_command') != 'compile-block'
            or block_registry['profile'].get('abi') != BLOCK_ABI):
        raise ValueError('Block registry must declare the native block-exit compiler ABI')
    executable_hash = sha256(args.cli)
    with tempfile.TemporaryDirectory(prefix='stela-apple-progress-') as temporary:
        compiler, probes = smoke_forms(args.cli, rows, rows, Path(temporary), canonical_facts=canonical_facts)
        block_directory = Path(temporary) / 'blocks'
        block_directory.mkdir()
        block_compiler, block_probes = smoke_forms(args.cli, block_rows, block_rows, block_directory,
                                                 mode='block', canonical_facts=canonical_facts)
        service_directory = Path(temporary) / 'services'
        service_directory.mkdir()
        service_compiler, service_probes = smoke_forms(args.cli, service_rows, service_rows, service_directory,
                                                     mode='service', canonical_facts=canonical_facts)
        scalable_directory = Path(temporary) / 'scalable'
        scalable_directory.mkdir()
        scalable_compiler, scalable_probes = smoke_forms(
            args.cli, scalable_rows, scalable_rows, scalable_directory, mode='scalable',
            canonical_facts=canonical_facts, profile=scalable_registry['profile'],
            canonical_catalog=catalog, arm_archive=args.arm_archive,
            **({'execution_profiles': scalable_registry['execution_profiles']}
               if 'execution_profiles' in scalable_registry else {}))
        if any(identity != compiler for identity in (block_compiler, service_compiler, scalable_compiler)):
            raise ValueError('Execution-profile compiler identities differ')
    if args.implementation_only:
        evidence, block_evidence, service_evidence, scalable_evidence = {}, {}, {}, {}
        sources, block_sources, service_sources, scalable_sources = [
            {path: sha256(ROOT / path) for row in group.values() for path in row['compiler_sources']}
            for group in (rows, block_rows, service_rows, scalable_rows)]
    else:
        evidence, sources = validate_evidence(registry, rows, compiler)
        block_evidence, block_sources = validate_evidence(block_registry, block_rows, compiler,
                                                          executable_hash=executable_hash)
        service_evidence, service_sources = validate_evidence(service_registry, service_rows, compiler, executable_hash=executable_hash)
        scalable_evidence, scalable_sources = validate_evidence(
            scalable_registry, scalable_rows, compiler, executable_hash=executable_hash)
    assessed, documented_summary = a64_checklist.assess(
        catalog, [registry, block_registry, service_registry, scalable_registry])
    apple_summary = apple_isa.assess(apple_profiles, assessed)
    assessed['compiler_source_sha256'] = compiler
    assessed['assessment_basis'] = 'reviewed_implementation_and_emission_smoke' if args.implementation_only else 'current_native_differential_evidence'
    assessed['last_verified_checkpoint'] = checkpoint
    assessed['evidence_reports'] = [{k: row[k] for k in ('report', 'report_sha256')}
                                   for group in (evidence, block_evidence, service_evidence, scalable_evidence) for row in group.values()]
    fingerprint_sources = validate_current_compiler(registry, compiler)
    for profile_registry in (block_registry, service_registry, scalable_registry):
        if validate_current_compiler(profile_registry, compiler) != fingerprint_sources:
            raise ValueError('Execution-profile fingerprint recipes differ')
    if (sha256(args.cli) != executable_hash or args.registry.read_bytes() != registry_data
            or args.block_registry.read_bytes() != block_data
            or args.service_registry.read_bytes() != service_data
            or args.scalable_registry.read_bytes() != scalable_data or args.checklist.read_bytes() != catalog_data
            or args.apple_profiles.read_bytes() != apple_profiles_data
            or validate_current_compiler(registry, compiler) != fingerprint_sources
            or any(validate_current_compiler(item, compiler) != fingerprint_sources
                   for item in (block_registry, service_registry, scalable_registry))):
        raise ValueError('Compiler/registry changed during measurement')
    report = {'schema_version': 2, 'kind': 'apple_silicon_translation_progress',
              'implementation_only': args.implementation_only, 'last_verified_checkpoint': checkpoint,
              'measured_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z'),
              'registry_version': registry['registry_version'], 'target_profile': registry['target_profile'],
              'instruction_sources': registry['instruction_sources'],
              'registry_sha256': hashlib.sha256(registry_data).hexdigest(),
              'compiler_source_sha256': compiler, 'compiler_executable_sha256': executable_hash,
              'harness_source_sha256': sha256(__file__), 'compiler_sources_sha256': sources,
              'compiler_fingerprint_sources_sha256': fingerprint_sources,
              'profile': registry['profile'], 'summary': summarize(rows),
              'documented_isa': {'version': catalog['version'], 'facts_sha256': catalog['facts_sha256'],
                                'summary': documented_summary},
              'apple_codegen_candidates': {'version': apple_profiles['version'],
                  'facts_sha256': apple_profiles['facts_sha256'],
                  'inventory_sha256': hashlib.sha256(apple_profiles_data).hexdigest(),
                  'harness_source_sha256': sha256(apple_isa.__file__), 'summary': apple_summary,
                  'inventory_complete': False, 'hardware_membership_verified': False},
              'apple_specific_extensions': {'tracked': len(apple['extensions']),
                  'implemented': sum(r['status'] == 'implemented' for r in apple['extensions']),
                  'inventory_complete': False},
              'service_profile_evidence': {'registry_sha256': hashlib.sha256(service_data).hexdigest(),
                  'native_differential_evidence': service_evidence, 'compiler_sources_sha256': service_sources,
                  'compiler_smoke_probes': service_probes},
              'scalable_profile_evidence': {
                  'registry_version': scalable_registry['registry_version'],
                  'registry_sha256': hashlib.sha256(scalable_data).hexdigest(),
                  'profile': scalable_registry['profile'], 'summary': summarize(scalable_rows),
                  **({'execution_profiles': scalable_registry['execution_profiles']}
                     if 'execution_profiles' in scalable_registry else {}),
                  'counts_are_not_additive': True, 'compiler_sources_sha256': scalable_sources,
                  'native_differential_evidence': scalable_evidence, 'compiler_smoke_probes': scalable_probes,
                  'reviewed_forms': [{'id': identity, 'status': row['status'], 'scope': row['scope'],
                                      **({'profile': row['profile']} if 'execution_profiles' in scalable_registry else {})}
                                     for identity, row in scalable_rows.items()]},
              'block_profile_evidence': {
                  'registry_version': block_registry['registry_version'],
                  'registry_sha256': hashlib.sha256(block_data).hexdigest(),
                  'profile': block_registry['profile'], 'summary': summarize(block_rows),
                  'overlap_with_leaf_form_ids': sorted(set(rows) & set(block_rows)),
                  'counts_are_not_additive': True, 'compiler_sources_sha256': block_sources,
                  'native_differential_evidence': block_evidence, 'compiler_smoke_probes': block_probes,
                  'reviewed_forms': [{'id': identity, 'status': row['status'], 'scope': row['scope']}
                                     for identity, row in block_rows.items()]},
              'native_differential_evidence': evidence, 'compiler_smoke_probes': probes,
              'reviewed_forms': [{'id': identity, 'status': row['status'], 'scope': row['scope']}
                                 for identity, row in rows.items()],
              'limits': 'Headline instruction percentage uses pinned public LLVM Apple M1–M5 code-generation candidate forms mapped to the June2026 Arm reference, deduplicated across reviewed execution profiles. Full Arm reference coverage remains secondary. Partial forms earn no credit. These models do not prove complete Apple hardware/mode/operand availability; M6, Apple-private additions and full CPU/VM conformance remain open. Differential tests establish evidence, not exhaustive correctness or complete application/macOS execution.'}
    archive = write_evidence(args.output, report)
    if args.markdown_output:
        write_markdown(args.markdown_output, markdown(report))
    if args.update_readme:
        a64_checklist.write(args.checklist, assessed)
        update_readme(ROOT / 'README.md', markdown(report))
    print(json.dumps({'report': str(args.output), 'archive': str(archive),
                      'compiler_source_sha256': compiler, 'summary': report['summary'],
                      'block_profile_summary': report['block_profile_evidence']['summary']}, indent=2))


if __name__ == '__main__':
    main()
