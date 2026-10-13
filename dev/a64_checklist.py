"""Versioned factual Arm A64 checklist and deduplicated profile assessment."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tarfile
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_SHA = '63a01a1696483bbe2edfef9e0f0cd053d6c1c619ec0587876cb7a60bb344f354'
PREFIX = 'ISA_A64_xml_A_profile-2026-06/'
VERSION = 'arm-a64-2026-06-v1'
FACTS_SHA = 'fff5ee6ca3eb54bc4c9d52f749373725a0261175d843ab23cebfaa5dd87d0db3'
CATEGORIES = {'general': 'base_integer_system', 'system': 'base_integer_system',
              'advsimd': 'fp_simd', 'float': 'fp_simd', 'fpsimd': 'fp_simd',
              'sve': 'sve', 'sve2': 'sve', 'mortlach': 'sme', 'mortlach2': 'sme'}
FACT_FIELDS = ('id', 'instruction_id', 'mnemonic', 'category', 'source_file',
               'encoding_mask', 'encoding_value', 'features')
STATUSES = ('implemented', 'partial', 'unsupported')


def checksum(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def fixed_bits(boxes):
    bits = {}
    for box in boxes:
        high, width = int(box.attrib['hibit']), int(box.attrib.get('width', 1))
        cells = []
        for cell in box.findall('c'):
            span, value = int(cell.attrib.get('colspan', 1)), ''.join(cell.itertext()).strip()
            cells.extend(value if len(value) == span and set(value) <= set('01x') else '?' * span)
        if len(cells) != width:
            raise ValueError('Unexpected Arm encoding diagram width')
        for index, bit in enumerate(cells):
            if bit in '01':
                position = high - index
                if position in bits and bits[position] != int(bit):
                    raise ValueError('Conflicting fixed encoding bits')
                bits[position] = int(bit)
    return (f'0x{sum(1 << p for p in bits):08x}',
            f'0x{sum(v << p for p, v in bits.items()):08x}')


def extract(archive):
    raw = Path(archive).read_bytes()
    if hashlib.sha256(raw).hexdigest() != ARCHIVE_SHA:
        raise ValueError('Arm archive does not match the pinned June 2026 release')
    forms, sources, aliases, pages = [], {}, 0, set()
    indexed = set()
    with tarfile.open(archive) as handle:
        for member in handle.getmembers():
            if not member.isfile() or not member.name.startswith(PREFIX) or not member.name.endswith('.xml'):
                continue
            data = handle.extractfile(member).read()
            node = ET.fromstring(data)
            filename = member.name.removeprefix(PREFIX)
            if filename in ('index.xml', 'fpsimdindex.xml', 'sveindex.xml', 'mortlachindex.xml'):
                indexed.update(x.attrib['iformfile'] for x in node.findall('.//iform'))
            if node.tag != 'instructionsection' or node.attrib.get('type') not in ('instruction', 'alias'):
                continue
            pages.add(filename)
            if node.attrib['type'] == 'alias':
                aliases += len(node.findall('./classes/iclass/encoding'))
                continue
            sources[filename] = hashlib.sha256(data).hexdigest()
            variables = lambda n: {v.attrib['key']: v.attrib['value'] for v in n.findall('./docvars/docvar')}
            for group in node.findall('./classes/iclass'):
                for encoding in group.findall('encoding'):
                    doc = {**variables(node), **variables(group), **variables(encoding)}
                    if doc['isa'] != 'A64':
                        raise ValueError('Unexpected non-A64 canonical encoding')
                    mask, value = fixed_bits(group.findall('./regdiagram/box') + encoding.findall('./box'))
                    features = {json.dumps(v.attrib, sort_keys=True) for n in (node, group, encoding)
                                for v in n.findall('./arch_variants/arch_variant')}
                    forms.append({'id': encoding.attrib['name'], 'instruction_id': node.attrib['id'],
                        'mnemonic': doc['mnemonic'], 'category': CATEGORIES[doc['instr-class']],
                        'source_file': filename, 'encoding_mask': mask, 'encoding_value': value,
                        'features': [json.loads(v) for v in sorted(features)],
                        'status': 'unsupported', 'profiles': []})
    if indexed != pages or len(forms) != 4332 or aliases != 291:
        raise ValueError('Pinned reference extraction is incomplete')
    forms.sort(key=lambda r: r['id'])
    result = {'schema_version': 1, 'kind': 'documented_a64_instruction_checklist', 'version': VERSION,
        'source': {'publisher': 'Arm Limited', 'release': '2026-06', 'archive_sha256': ARCHIVE_SHA,
                   'archive_bytes': len(raw), 'selected_prefix': PREFIX,
                   'uri': 'https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2026-06.tar.gz'},
        'unit': 'One canonical XML encoding form; widths/addressing modes count separately, aliases and register/immediate combinations do not.',
        'scope': 'Complete documented A64 reference superset, including optional and privileged forms. This is not a claim that every form is required by Apple silicon or that ISA completion establishes macOS compatibility.',
        'excluded_alias_forms': aliases, 'source_files_sha256': dict(sorted(sources.items())), 'forms': forms}
    result['facts_sha256'] = facts_hash(result)
    validate(result)
    return result


def facts_hash(catalog):
    return checksum({'source_files_sha256': catalog['source_files_sha256'],
                     'forms': [{k: row[k] for k in FACT_FIELDS} for row in catalog['forms']]})


def validate(catalog):
    if (catalog.get('kind') != 'documented_a64_instruction_checklist' or catalog.get('schema_version') != 1
            or catalog.get('version') != VERSION or catalog.get('source', {}).get('archive_sha256') != ARCHIVE_SHA
            or len(catalog.get('forms', [])) != 4332 or catalog.get('excluded_alias_forms') != 291):
        raise ValueError('Invalid pinned documented A64 checklist')
    rows = {}
    for row in catalog['forms']:
        if row['id'] in rows or row['status'] not in STATUSES or row['category'] not in CATEGORIES.values():
            raise ValueError('Duplicate form or invalid checklist status/category')
        mask, value = int(row['encoding_mask'], 16), int(row['encoding_value'], 16)
        if not 0 <= mask <= 0xffffffff or value & ~mask or value < 0:
            raise ValueError('Invalid documented fixed encoding bits')
        if row['source_file'] not in catalog['source_files_sha256']:
            raise ValueError('Missing Arm instruction source identity')
        rows[row['id']] = row
    if facts_hash(catalog) != catalog.get('facts_sha256') or catalog['facts_sha256'] != FACTS_SHA:
        raise ValueError('Documented A64 checklist facts changed')
    return rows


def assess(catalog, registries):
    """Merge reviewed profiles by canonical identity, never add their totals."""
    original = validate(catalog)
    result = json.loads(json.dumps(catalog))
    rows = {r['id']: r for r in result['forms']}
    for row in rows.values():
        row.update(status='unsupported', profiles=[])
    for registry in registries:
        for reviewed in registry['forms']:
            row = rows.get(reviewed['id'])
            if row is None:
                raise ValueError('Reviewed form is absent from the documented reference')
            for key in ('encoding_mask', 'encoding_value', 'source_file'):
                if row[key] != reviewed[key]:
                    raise ValueError('Reviewed encoding facts differ from the documented reference')
            if catalog['source_files_sha256'][row['source_file']] != reviewed['source_sha256']:
                raise ValueError('Reviewed instruction source hash differs')
            row['profiles'].append({'profile': reviewed['profile'], 'status': reviewed['status'],
                                    'scope': reviewed['scope']})
            if STATUSES.index(reviewed['status']) < STATUSES.index(row['status']):
                row['status'] = reviewed['status']
    counts = Counter(r['status'] for r in rows.values())
    categories = {name: dict(Counter(r['status'] for r in rows.values() if r['category'] == name))
                  for name in sorted(set(CATEGORIES.values()))}
    summary = {**{s: counts[s] for s in STATUSES}, 'total': len(original),
               'implementation_percentage': 100 * counts['implemented'] / len(original), 'categories': categories}
    result['assessment'] = summary
    return result, summary


def write(path, catalog):
    # One canonical form per line keeps the complete checklist reviewable.
    metadata = {k: v for k, v in catalog.items() if k != 'forms'}
    prefix = json.dumps(metadata, indent=2)[:-2]
    lines = ',\n'.join('    ' + json.dumps(row, separators=(',', ':')) for row in catalog['forms'])
    Path(path).write_text(prefix + ',\n  "forms": [\n' + lines + '\n  ]\n}\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--output', type=Path, default=ROOT / 'tests/isa/a64-documented-checklist.json')
    args = parser.parse_args()
    write(args.output, extract(args.archive))
