"""Pinned Apple LLVM CPU profiles mapped to documented Arm encoding candidates.

Compiler feature models are not a complete hardware-capability inventory. Keep
that distinction in the artifact and in every percentage derived from it.
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
LLVM_COMMIT = 'b4badb65df4ea15fc6ecabd8f9366a96df11dcb5'
VERSION = 'apple-llvm-m1-m5-arm-2026-06-v1'
FACTS_SHA = 'ca64f36c40f05a99c35bd6c9652932b7af86a509f62f93b20ade50fa801b6e91'
SOURCE_HASHES = {
    'AArch64Features.td': '6531064d60165020e4c99ab61e45112ec2aaa77749d6eb2f50979d9c65b29352',
    'AArch64Processors.td': 'c583a1b2463935ad3497a641b0e5bf2714788e2e2bb02bf182d54d9078fa75cd',
}
CPUS = tuple(f'apple-m{number}' for number in range(1, 6))
EXPECTED_COUNTS = {'apple-m1': 1523, 'apple-m2': 1537, 'apple-m3': 1537,
                   'apple-m4': 2931, 'apple-m5': 3119}
LIMITS = (
    'Public LLVM code-generation feature models select candidate canonical forms, '
    'not exhaustive Apple hardware capabilities or per-OS availability. Untagged '
    'reference forms are candidates, including system forms with feature-dependent '
    'operands. Architecture-implied privileged features are not hardware validation. '
    'SME admits streaming SVE candidates without enabling general non-streaming SVE. '
    'Mode, operand, privilege, FP, memory and exception semantics need separate '
    'verification. M6, Apple-private operations and full hardware membership remain '
    'open. A form count is not application or macOS compatibility.'
)


def without_comments(source):
    pattern = r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/'
    return re.sub(pattern, lambda m: m[0] if m[0].startswith('"') else re.sub(r'[^\n]', ' ', m[0]), source)


def balanced_arguments(source, start):
    """Read a TableGen angle argument list, respecting quoted strings."""
    if source[start] != '<':
        raise ValueError('Expected TableGen argument list')
    depth, quoted, escaped = 0, False, False
    for index in range(start, len(source)):
        char = source[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == '<':
            depth += 1
        elif char == '>':
            depth -= 1
            if depth == 0:
                return split_arguments(source[start + 1:index])
    raise ValueError('Unterminated TableGen argument list')


def split_arguments(source):
    result, stack, quoted, escaped, start = [], [], False, False, 0
    for index, char in enumerate(source):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[(<':
            stack.append(char)
        elif char in '])>':
            if not stack or stack.pop() != {']': '[', ')': '(', '>': '<'}[char]:
                raise ValueError('Unbalanced TableGen arguments')
        elif char == ',' and not stack:
            result.append(source[start:index].strip())
            start = index + 1
    if quoted or stack:
        raise ValueError('Unterminated TableGen argument')
    tail = source[start:].strip()
    if tail:
        result.append(tail)
    return result


def literal_features(source):
    source = source.strip()
    if not source.startswith('[') or not source.endswith(']'):
        raise ValueError('Feature dependency must be a literal list')
    values = split_arguments(source[1:-1])
    if any(not re.fullmatch(r'(?:Feature\w+|HasV\w+Ops)', value) for value in values):
        raise ValueError('Unreviewed feature dependency expression')
    return values


def feature_definitions(source):
    source = without_comments(source)
    definitions = {}
    for match in re.finditer(r'\bdef\s+(\w+)\s*:\s*(Architecture64|ExtensionWithMArch|Extension|SubtargetFeature)\s*<', source):
        name, kind = match[1], match[2]
        args = balanced_arguments(source, match.end() - 1)
        if len(args) < 4 or (kind == 'Architecture64' and len(args) != 6):
            raise ValueError('Unexpected feature definition signature')
        dependencies = literal_features(args[4]) if len(args) >= 5 else []
        architectural = []
        if kind in ('Extension', 'ExtensionWithMArch'):
            value = json.loads(args[2])
            architectural = [part.strip() for part in value.split(',') if part.strip()]
            if any(not re.fullmatch(r'FEAT_\w+', part) for part in architectural):
                raise ValueError('Unexpected architectural feature spelling')
        if name in definitions:
            raise ValueError('Duplicate feature definition')
        definitions[name] = {'dependencies': dependencies, 'architectural': architectural}
    return definitions


def cpu_roots(source, cpu):
    source = without_comments(source)
    aliases, models = {}, {}
    for match in re.finditer(r'\b(ProcessorAlias|ProcessorModel)\s*<', source):
        args = balanced_arguments(source, match.end() - 1)
        name = json.loads(args[0])
        if match[1] == 'ProcessorAlias':
            aliases[name] = json.loads(args[1])
        else:
            models[name] = args[2]
    visited = set()
    while cpu in aliases:
        if cpu in visited:
            raise ValueError('Cyclic CPU aliases')
        visited.add(cpu)
        cpu = aliases[cpu]
    model = re.fullmatch(r'ProcessorFeatures\.(\w+)', models.get(cpu, ''))
    if model is None:
        raise ValueError('Unknown or unreviewed Apple CPU model')
    name = model[1]
    match = re.search(r'list\s*<\s*SubtargetFeature\s*>\s+' + re.escape(name) + r'\s*=\s*(\[[^]]*\])\s*;', source)
    if match is None:
        raise ValueError('CPU feature roots are not a reviewed literal list')
    return name, literal_features(match[1])


def feature_closure(definitions, roots):
    complete, active = set(), set()

    def visit(name):
        if name not in definitions:
            raise ValueError(f'Unknown feature dependency: {name}')
        if name in active:
            raise ValueError('Cyclic feature dependencies')
        if name in complete:
            return
        active.add(name)
        for dependency in definitions[name]['dependencies']:
            visit(dependency)
        active.remove(name)
        complete.add(name)

    for root in roots:
        visit(root)
    return complete, {name for feature in complete for name in definitions[feature]['architectural']}


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


def generate(catalog, features, processors, archive):
    a64_checklist.validate(catalog)
    for name, raw in (('AArch64Features.td', features), ('AArch64Processors.td', processors)):
        if hashlib.sha256(raw).hexdigest() != SOURCE_HASHES[name]:
            raise ValueError('LLVM source does not match the pinned commit')
    if hashlib.sha256(Path(archive).read_bytes()).hexdigest() != a64_checklist.ARCHIVE_SHA:
        raise ValueError('Arm archive identity changed')
    definitions = feature_definitions(features.decode())
    profiles, memberships = {}, {}
    for cpu in CPUS:
        model, roots = cpu_roots(processors.decode(), cpu)
        transitive, architectural = feature_closure(definitions, roots)
        forms = []
        for row in catalog['forms']:
            membership = candidate(row, architectural)
            if membership is None:
                raise ValueError(f'Unresolved operand membership: {cpu}/{row["id"]}')
            if membership:
                forms.append(row)
                memberships.setdefault(row['id'], []).append(cpu)
        if len(forms) != EXPECTED_COUNTS[cpu]:
            raise ValueError('Pinned Apple model candidate count changed')
        profiles[cpu] = {'llvm_model': model, 'roots': roots,
            'transitive_llvm_features': sorted(transitive), 'architectural_features': sorted(architectural),
            'canonical_forms': len(forms), 'mnemonics': len({row['mnemonic'] for row in forms}),
            'categories': dict(sorted(Counter(row['category'] for row in forms).items())),
            'general_nonstreaming_sve': 'FEAT_SVE' in architectural,
            'streaming_sve': 'FEAT_SME' in architectural}
    audit = sve_mode_audit(catalog, memberships, archive)
    forms = [{'id': row['id'], 'cpus': memberships[row['id']],
              'membership_basis': 'untagged_reference_candidate' if not row['features'] else 'llvm_feature_predicate',
              'sve_mode': 'streaming_only_candidate' if row['category'] == 'sve' else None}
             for row in catalog['forms'] if row['id'] in memberships]
    result = {'schema_version': 1, 'kind': 'apple_codegen_candidate_inventory', 'version': VERSION,
        'arm_catalog_facts_sha256': catalog['facts_sha256'],
        'sources': {name: {'sha256': digest, 'uri': f'https://raw.githubusercontent.com/llvm/llvm-project/{LLVM_COMMIT}/llvm/lib/Target/AArch64/{name}'}
                    for name, digest in SOURCE_HASHES.items()},
        'llvm_commit': LLVM_COMMIT, 'profiles': profiles, 'sve_mode_audit': audit,
        'inventory_complete': False, 'hardware_membership_verified': False,
        'pending_profiles': ['apple-m6'], 'limits': LIMITS, 'forms': forms}
    result['facts_sha256'] = inventory_hash(result)
    if result['facts_sha256'] != FACTS_SHA:
        raise ValueError('Pinned Apple profile facts changed')
    return result


def inventory_hash(inventory):
    return a64_checklist.checksum({key: value for key, value in inventory.items() if key != 'facts_sha256'})


def assess(inventory, assessed_catalog):
    rows = a64_checklist.validate(assessed_catalog)
    if (inventory.get('kind') != 'apple_codegen_candidate_inventory' or inventory.get('version') != VERSION
            or inventory.get('schema_version') != 1 or inventory.get('inventory_complete') is not False
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
        total = 3119 if cpu == 'union' else EXPECTED_COUNTS[cpu]
        if len(forms) != total:
            raise ValueError('Apple candidate profile membership changed')
        counts = Counter(row['status'] for row in forms)
        summaries[cpu] = {**{status: counts[status] for status in a64_checklist.STATUSES},
                          'total': total, 'implementation_percentage': 100 * counts['implemented'] / total}
    return summaries


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--features', type=Path, default=ROOT / '.stela/isa/llvm-AArch64Features-b4badb65df4e.td')
    parser.add_argument('--processors', type=Path, default=ROOT / '.stela/isa/llvm-AArch64Processors-b4badb65df4e.td')
    parser.add_argument('--archive', type=Path, default=ROOT / '.stela/isa/ISA_A64_xml_A_profile-2026-06.tar.gz')
    parser.add_argument('--catalog', type=Path, default=ROOT / 'tests/isa/a64-documented-checklist.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/isa/apple-codegen-profiles.json')
    args = parser.parse_args()
    inventory = generate(json.loads(args.catalog.read_bytes()), args.features.read_bytes(), args.processors.read_bytes(), args.archive)
    a64_checklist.write(args.output, inventory)
    print(json.dumps({'output': str(args.output), 'facts_sha256': inventory['facts_sha256'],
                      'counts': {cpu: row['canonical_forms'] for cpu, row in inventory['profiles'].items()}}, indent=2))
