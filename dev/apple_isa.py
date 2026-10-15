"""Pinned official Apple compiler features mapped to documented A64 candidates.

Feature exports describe compiler configuration, not complete hardware capability.
Regeneration is offline from factual compiler exports and the pinned Arm archive.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import tarfile
import xml.etree.ElementTree as ET

import a64_checklist

ROOT = Path(__file__).resolve().parents[1]
VERSION = 'apple-clang-m1-m6-arm-2026-06-v2'
FACTS_SHA = '5514bc8738b8c3bd56722292a30f21f2dfc3e54be7689e25fe5003b76e80a394'
SNAPSHOT_VERSION = 'apple-clang-2100.3.34.2-m1-m6-v1'
SNAPSHOT_FACTS_SHA = '92df4b0be28c91f1d98bdebe332df1eae6984b68d31bc6a4a499f64ec4af7f2a'
CPUS = tuple(f'apple-m{number}' for number in range(1, 7))
EXPECTED_COUNTS = {'apple-m1': 1524, 'apple-m2': 1537, 'apple-m3': 1537,
                   'apple-m4': 2931, 'apple-m5': 3119, 'apple-m6': 3231}
UNION_COUNT = 3231
LIMITS = (
    'Official Apple clang enabled-feature exports select candidate canonical forms, '
    'not exhaustive Apple hardware capabilities, assembler operands or per-OS availability. '
    'Untagged reference forms are candidates, including system forms with feature-dependent '
    'operands. Privileged compiler features and accepted HINT/system-register syntax '
    'are not hardware validation. SME admits streaming SVE candidates without enabling '
    'general non-streaming SVE. Mode, operand, FP, memory and exception semantics need '
    'separate verification. Apple-private operations and full hardware membership remain '
    'open. A form count is not application or macOS compatibility.'
)


def snapshot_hash(snapshot):
    return a64_checklist.checksum({key: value for key, value in snapshot.items() if key != 'facts_sha256'})


def load_snapshot(snapshot):
    """Validate exact factual exports; never reconstruct omitted compiler features."""
    fields = {'schema_version', 'kind', 'version', 'publisher', 'tool', 'target',
              'capture_date', 'basis', 'profiles', 'facts_sha256'}
    if (not isinstance(snapshot, dict) or set(snapshot) != fields
            or snapshot.get('schema_version') != 1
            or snapshot.get('kind') != 'apple_clang_enabled_feature_snapshot'
            or snapshot.get('version') != SNAPSHOT_VERSION
            or snapshot.get('facts_sha256') != SNAPSHOT_FACTS_SHA
            or snapshot_hash(snapshot) != SNAPSHOT_FACTS_SHA):
        raise ValueError('Official Apple compiler feature snapshot differs from pinned facts')
    if snapshot['target'] != 'arm64-apple-macos' or set(snapshot['profiles']) != set(CPUS):
        raise ValueError('Official Apple compiler target/CPU inventory differs')
    for cpu, profile in snapshot['profiles'].items():
        if set(profile) != {'command', 'stdout_sha256', 'stderr_sha256', 'architectural_features'}:
            raise ValueError('Unknown compiler feature profile schema')
        command = [snapshot['tool']['path'], '--target=' + snapshot['target'],
                   '-mcpu=' + cpu, '--print-enabled-extensions']
        features = profile['architectural_features']
        if (profile['command'] != command or not isinstance(features, list)
                or any(not isinstance(name, str) or not re.fullmatch(r'FEAT_\w+', name) for name in features)
                or features != sorted(set(features))
                or any(not re.fullmatch(r'[0-9a-f]{64}', profile[name])
                       for name in ('stdout_sha256', 'stderr_sha256'))):
            raise ValueError('Invalid compiler CPU feature export')
    return snapshot


def feature_expression(expression, enabled):
    """Evaluate the pinned predicate grammar without eval; None means operand-dependent."""
    pattern = r"\s*(FEAT_\w+|sz\s*==\s*'0'|&&|\|\||!|\(|\))"
    tokens, position = [], 0
    while position < len(expression):
        match = re.match(pattern, expression[position:])
        if not match:
            if expression[position:].strip():
                raise ValueError('Unreviewed Arm feature predicate')
            break
        tokens.append(match[1])
        position += match.end()
    index = 0

    def atom():
        nonlocal index
        if index == len(tokens):
            raise ValueError('Truncated feature predicate')
        token = tokens[index]
        index += 1
        if token == '!':
            value = atom()
            return None if value is None else not value
        if token == '(':
            value = disjunction()
            if index == len(tokens) or tokens[index] != ')':
                raise ValueError('Unbalanced feature predicate')
            index += 1
            return value
        if token.startswith('FEAT_'):
            return token in enabled
        if token.startswith('sz'):
            return None
        raise ValueError('Invalid feature predicate atom')

    def conjunction():
        nonlocal index
        value = atom()
        while index < len(tokens) and tokens[index] == '&&':
            index += 1
            right = atom()
            value = False if value is False or right is False else None if value is None or right is None else True
        return value

    def disjunction():
        nonlocal index
        value = conjunction()
        while index < len(tokens) and tokens[index] == '||':
            index += 1
            right = conjunction()
            value = True if value is True or right is True else None if value is None or right is None else False
        return value

    value = disjunction()
    if index != len(tokens):
        raise ValueError('Trailing feature predicate input')
    return value


def candidate(row, enabled):
    if not row['features']:
        return True
    if len(row['features']) != 1 or 'feature' not in row['features'][0]:
        raise ValueError('Unreviewed compound/missing form feature predicate')
    return feature_expression(row['features'][0]['feature'], enabled)


def sve_mode_audit(catalog, selected, archive):
    """Retain operation-check facts; this does not prove all operand/mode legality."""
    files = {row['source_file'] for row in catalog['forms'] if row['id'] in selected and row['category'] == 'sve'}
    checks = {}
    with tarfile.open(archive) as handle:
        shared = handle.extractfile(a64_checklist.PREFIX + 'shared_pseudocode.xml').read()
        root = ET.fromstring(shared)
        helpers = {}
        for name in ('CheckSVEEnabled', 'CheckStreamingSVEEnabled'):
            matches = [''.join(node.itertext()) for node in root.findall('.//ps')
                       if f'func {name}()' in ''.join(node.itertext())]
            if len(matches) != 1:
                raise ValueError('Ambiguous/missing shared SVE helper')
            helpers[name] = hashlib.sha256(matches[0].encode()).hexdigest()
        for filename in sorted(files):
            raw = handle.extractfile(a64_checklist.PREFIX + filename).read()
            if hashlib.sha256(raw).hexdigest() != catalog['source_files_sha256'][filename]:
                raise ValueError('SVE source page differs from catalog')
            page = ET.fromstring(raw)
            operations = [''.join(node.itertext()) for node in page.findall('.//ps')
                          if node.attrib.get('secttype') == 'Operation']
            text = '\n'.join(operations)
            names = sorted(set(re.findall(r'\b(Check\w+Enabled)\(', text)))
            if not operations or 'CheckSVEEnabled' not in names:
                raise ValueError('Selected SVE page needs a new execution-mode review')
            checks[filename] = {'operation_checks': names,
                                'conditional_nonstreaming_check': 'CheckNonStreamingSVEEnabled' in names}
    return {'shared_pseudocode_sha256': hashlib.sha256(shared).hexdigest(),
            'helper_text_sha256': helpers, 'pages': checks,
            'scope': 'Every selected SVE page contains CheckSVEEnabled; on SME-only CPUs this requires streaming mode. Conditional non-streaming checks and feature-dependent operands still require per-encoding review. No general SVE support is inferred.'}


def generate(catalog, snapshot, archive):
    a64_checklist.validate(catalog)
    snapshot = load_snapshot(snapshot)
    if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != a64_checklist.ARCHIVE_SHA:
        raise ValueError('Arm archive identity changed')
    profiles, memberships = {}, {}
    for cpu in CPUS:
        source = snapshot['profiles'][cpu]
        architectural = set(source['architectural_features'])
        forms = []
        for row in catalog['forms']:
            membership = candidate(row, architectural)
            if membership is None:
                raise ValueError(f'Unresolved operand membership: {cpu}/{row["id"]}')
            if membership:
                forms.append(row)
                memberships.setdefault(row['id'], []).append(cpu)
        if len(forms) != EXPECTED_COUNTS[cpu]:
            raise ValueError('Pinned Apple compiler candidate count changed')
        profiles[cpu] = {'compiler_cpu': cpu,
            'architectural_features': sorted(architectural),
            'feature_export_stdout_sha256': source['stdout_sha256'],
            'canonical_forms': len(forms), 'mnemonics': len({row['mnemonic'] for row in forms}),
            'categories': dict(sorted(Counter(row['category'] for row in forms).items())),
            'general_nonstreaming_sve': 'FEAT_SVE' in architectural,
            'streaming_sve': 'FEAT_SME' in architectural}
    audit = sve_mode_audit(catalog, memberships, archive)
    forms = [{'id': row['id'], 'cpus': memberships[row['id']],
              'membership_basis': 'untagged_reference_candidate' if not row['features'] else 'official_compiler_feature_predicate',
              'sve_mode': 'streaming_only_candidate' if row['category'] == 'sve' else None}
             for row in catalog['forms'] if row['id'] in memberships]
    if len(forms) != UNION_COUNT:
        raise ValueError('Pinned Apple compiler candidate union changed')
    result = {'schema_version': 2, 'kind': 'apple_codegen_candidate_inventory', 'version': VERSION,
        'arm_catalog_facts_sha256': catalog['facts_sha256'],
        'sources': {'apple_clang_features': {'path': 'tests/isa/apple-clang-features.json',
            'version': SNAPSHOT_VERSION, 'facts_sha256': SNAPSHOT_FACTS_SHA}},
        'compiler': snapshot['tool'], 'target': snapshot['target'],
        'profiles': profiles, 'sve_mode_audit': audit,
        'inventory_complete': False, 'hardware_membership_verified': False,
        'pending_profiles': [], 'limits': LIMITS, 'forms': forms}
    result['facts_sha256'] = inventory_hash(result)
    if result['facts_sha256'] != FACTS_SHA:
        raise ValueError('Pinned Apple compiler profile facts changed')
    return result


def inventory_hash(inventory):
    return a64_checklist.checksum({key: value for key, value in inventory.items() if key != 'facts_sha256'})


def assess(inventory, assessed_catalog):
    rows = a64_checklist.validate(assessed_catalog)
    if (inventory.get('kind') != 'apple_codegen_candidate_inventory' or inventory.get('version') != VERSION
            or inventory.get('schema_version') != 2 or inventory.get('inventory_complete') is not False
            or inventory.get('hardware_membership_verified') is not False
            or inventory.get('arm_catalog_facts_sha256') != assessed_catalog['facts_sha256']
            or inventory.get('facts_sha256') != FACTS_SHA
            or inventory.get('facts_sha256') != inventory_hash(inventory)):
        raise ValueError('Invalid Apple code-generation candidate inventory')
    selected = inventory['forms']
    if len({row['id'] for row in selected}) != len(selected) or any(row['id'] not in rows for row in selected):
        raise ValueError('Duplicate/unknown Apple candidate form')
    summaries = {}
    for cpu in (*CPUS, 'union'):
        forms = [rows[row['id']] for row in selected if cpu == 'union' or cpu in row['cpus']]
        total = UNION_COUNT if cpu == 'union' else EXPECTED_COUNTS[cpu]
        if len(forms) != total:
            raise ValueError('Apple candidate profile membership changed')
        counts = Counter(row['status'] for row in forms)
        summaries[cpu] = {**{status: counts[status] for status in a64_checklist.STATUSES},
                          'total': total, 'implementation_percentage': 100 * counts['implemented'] / total}
    return summaries


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', type=Path, default=ROOT / 'tests/isa/apple-clang-features.json',
                        help='Pinned factual Apple compiler feature snapshot')
    parser.add_argument('--archive', type=Path, default=ROOT / '.stela/isa/ISA_A64_xml_A_profile-2026-06.tar.gz')
    parser.add_argument('--catalog', type=Path, default=ROOT / 'tests/isa/a64-documented-checklist.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/isa/apple-codegen-profiles.json')
    args = parser.parse_args()
    inventory = generate(json.loads(args.catalog.read_bytes()), json.loads(args.features.read_bytes()), args.archive)
    a64_checklist.write(args.output, inventory)
    print(json.dumps({'output': str(args.output), 'facts_sha256': inventory['facts_sha256'],
                      'counts': {cpu: row['canonical_forms'] for cpu, row in inventory['profiles'].items()}}, indent=2))
