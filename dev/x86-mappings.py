#!/usr/bin/env python3
"""Search pinned local Intel mapping references; never a semantic verifier.

`fetch` downloads source snapshots to ignored, content-addressed storage; `build`
indexes them using only the Python standard library. `query` is offline and emits
bounded excerpts. Intrinsics may expand to sequences; XED records are source
patterns, not generated canonical forms or executable semantics. Missing flags,
faults and NaN details require the SDM and differential verification.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import html
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import tarfile
import urllib.request
import xml.etree.ElementTree as ET

DEFAULT_ROOT = Path(__file__).resolve().parent.parent / '.stela/isa/x86'
GUIDE_URL = 'https://www.intel.com/content/dam/develop/public/us/en/include/intrinsics-guide/data-3-6-9.xml'
GUIDE_SHA256 = '048b2430d73c3ebf518fa067749d619c0f86e3ac1d50372f6a83821a5a18aff1'
XED_REVISION = '0bcb6237345c5066726dcc08b3d87928df3b5b26'
XED_SHA256 = '75a432bb687eef39c1a71e0b500c60adee1ad4da465e8cc97e4dbb8483e724e9'
SDM_URL = 'https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html'
GUIDE_PAGE = 'https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html'
SCHEMA = 1
GAPS = [
    'Intrinsics Guide covers intrinsics, not every x86 instruction. Its pseudocode is not a complete flags/faults/NaN specification.',
    'XED source blocks provide encoding taxonomy/operands/flag metadata, not operation semantics. Macros/overrides are not expanded; counts are source patterns, not canonical forms or x86-64-only coverage.',
    'CPUID labels/records do not establish host availability: check CPUID, OS state (including XCR0 for AVX), privilege and instruction mode. Future/vendor-specific entries may be unusable.',
    'No optimality or equivalence is established here; no microarchitecture cost model is included. Consult SDM operation/flags/exceptions; measure emitted binaries and verify architectural state.',
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def immutable(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f'immutable artifact changed: {path}')
    else:
        with path.open('xb') as out:
            out.write(data)


def save_content(root, directory, data, suffix):
    relative = Path(directory) / (digest(data) + suffix)
    immutable(root / relative, data)
    return str(relative)


def write_current(root, value):
    temporary = root / 'current.json.tmp'
    temporary.write_bytes(canonical(value))
    temporary.replace(root / 'current.json')


def safe_artifact(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError('artifact path escapes catalog root')
    return path


def read_current(root):
    return json.loads((root / 'current.json').read_text())


def load_manifest(root, current):
    data = safe_artifact(root, current['manifest']).read_bytes()
    if digest(data) != current['manifest_sha256']:
        raise ValueError('source manifest hash mismatch')
    manifest = json.loads(data)
    for source in manifest['sources']:
        data = safe_artifact(root, source['blob']).read_bytes()
        if len(data) != source['bytes'] or digest(data) != source['sha256']:
            raise ValueError(f"source hash/size mismatch: {source['kind']}")
    return manifest


class NoDtdTreeBuilder(ET.TreeBuilder):
    def doctype(self, name, public_id, system_id):
        raise ValueError('XML DTD/entity declarations are not supported')


def parse_intrinsics(data):
    if len(data) > 64 * 1024 * 1024:
        raise ValueError('XML exceeds 64 MiB limit')
    if re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', data, re.IGNORECASE):
        raise ValueError('XML DTD/entity declarations are not supported')
    document = ET.fromstring(data, parser=ET.XMLParser(target=NoDtdTreeBuilder()))
    if document.tag != 'intrinsics_list' or not document.findall('intrinsic'):
        raise ValueError('source is not Intel Intrinsics Guide XML')
    return document


def fetch(args):
    root = args.root
    sources = []
    urls = [
        ('intrinsics', args.intrinsics_url, args.intrinsics_sha256, '3.6.9' if args.intrinsics_url == GUIDE_URL else None),
        ('xed', f'https://codeload.github.com/intelxed/xed/tar.gz/{args.xed_revision}',
         XED_SHA256 if args.xed_revision == XED_REVISION else None, args.xed_revision),
    ]
    if not re.fullmatch('[0-9a-f]{40}', args.xed_revision):
        raise ValueError('--xed-revision must be an immutable 40-digit Git commit')
    if not re.fullmatch('[0-9a-f]{64}', args.intrinsics_sha256):
        raise ValueError('--intrinsics-sha256 must be a 64-digit SHA256')
    if (root / 'current.json').exists() and not args.refresh:
        current = read_current(root)
        manifest = load_manifest(root, current)
        existing = {s['kind']: s for s in manifest['sources']}
        if all(kind in existing and existing[kind]['url'] == url
               and (not expected or existing[kind]['sha256'] == expected)
               and (kind != 'xed' or existing[kind]['revision'] == revision)
               for kind, url, expected, revision in urls):
            return dict(manifest=current['manifest'], sources=manifest['sources'], reused=True, next='build')
    for kind, url, expected, revision in urls:
        request = urllib.request.Request(url)
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(64 * 1024 * 1024 + 1)
            final_url = response.url
        if len(data) > 64 * 1024 * 1024:
            raise ValueError('source exceeds 64 MiB download limit')
        sha = digest(data)
        if expected and sha != expected:
            raise ValueError(f'{kind} download differs from pinned SHA256: {sha}')
        if kind == 'intrinsics':
            document = parse_intrinsics(data)
            revision = document.get('version')
        else:
            if not any(path == 'datafiles/xed-isa.txt' for path, _ in xed_files(data)):
                raise ValueError('download lacks XED instruction source')
        sources.append(dict(kind=kind, url=url, resolved_url=final_url, revision=revision,
                            retrieved_utc=datetime.now(timezone.utc).isoformat(),
                            bytes=len(data), sha256=sha,
                            blob=save_content(root, 'blobs', data, '.xml' if kind == 'intrinsics' else '.tar.gz')))
    manifest = dict(schema=SCHEMA, sources=sources, gaps=GAPS, sdm=SDM_URL)
    data = canonical(manifest)
    current = dict(manifest=save_content(root, 'manifests', data, '.json'), manifest_sha256=digest(data))
    write_current(root, current)
    return dict(manifest=current['manifest'], sources=sources, next='build')


def plain(value):
    return html.unescape(re.sub('<[^>]+>', '', value)).strip()


def element_text(element):
    return plain(''.join(element.itertext())) if element is not None else ''


def intrinsic_records(data, source):
    document = parse_intrinsics(data)
    for ordinal, node in enumerate(document.findall('intrinsic'), 1):
        instructions = [dict(instruction.attrib) for instruction in node.findall('instruction')]
        parameters = [dict(parameter.attrib) for parameter in node.findall('parameter')]
        record = dict(kind='intrinsic', name=node.get('name'), tech=node.get('tech'),
                      categories=[element_text(c) for c in node.findall('category')],
                      mnemonics=sorted({i['name'].upper() for i in instructions if 'name' in i}),
                      features=[element_text(c) for c in node.findall('CPUID')],
                      parameters=parameters, result=dict(node.find('return').attrib) if node.find('return') is not None else {},
                      instructions=instructions, sequence=node.get('sequence', 'FALSE'),
                      description=element_text(node.find('description')),
                      operation=''.join(node.find('operation').itertext()).strip() if node.find('operation') is not None else '', flags=None,
                      reference=dict(url=source['url'], sha256=source['sha256'],
                                     locator=f"intrinsic[{ordinal}] name={node.get('name')}",
                                     guide=f"{GUIDE_PAGE}#text={node.get('name')}"))
        yield record


def xed_files(data):
    # No archive member is extracted to disk or followed as a symbolic link.
    seen, total_bytes, archive_bytes = set(), 0, 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r|*') as archive:
        for ordinal, member in enumerate(archive, 1):
            if ordinal > 10000:
                raise ValueError('XED archive exceeds 10,000 members')
            archive_bytes += member.size
            if member.size > 16 * 1024 * 1024 or archive_bytes > 128 * 1024 * 1024:
                raise ValueError('XED archive exceeds expanded member/total byte bounds')
            parts = member.name.split('/')
            if member.name.startswith('/') or '..' in parts:
                raise ValueError('unsafe XED archive member path')
            if member.isfile() and '/datafiles/' in member.name and member.name.endswith('.txt'):
                if member.size > 16 * 1024 * 1024:
                    raise ValueError('XED member exceeds 16 MiB')
                total_bytes += member.size
                if total_bytes > 64 * 1024 * 1024:
                    raise ValueError('XED text sources exceed 64 MiB')
                path = member.name.split('/', 1)[1]
                if path in seen:
                    raise ValueError('duplicate XED source member')
                seen.add(path)
                yield path, archive.extractfile(member).read().decode('utf-8')


def cpuid_records(files, source):
    result = {}
    for path, text in files:
        if 'cpuid' not in path:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            match = re.match(r'\s*XED_ISA_SET_([\w]+)([^:]*)\s*:\s*(.*)', line.split('#', 1)[0])
            if match:
                isa, group, raw = match.groups()
                result.setdefault(isa, []).append(dict(group=group.lstrip(',').strip(), raw=raw.strip(),
                    reference=xed_reference(source, path, line_number)))
    return result


def xed_reference(source, path, line):
    return dict(url=f"https://github.com/intelxed/xed/blob/{source['revision']}/{path}#L{line}",
                sha256=source['sha256'], locator=f'{path}:{line}')


def xed_records(text, path, source, cpuid):
    # Preserve blocks/patterns without pretending to expand XED's generator DSL.
    block, start, depth = [], 0, 0
    for line_number, line in enumerate(text.splitlines(), 1):
        clean = line.split('#', 1)[0].strip()
        if clean == '{':
            if depth:
                raise ValueError(f'nested XED block at {path}:{line_number}')
            depth, start, block = 1, line_number, []
        elif clean == '}':
            if not depth:
                continue
            depth = 0
            fields, patterns, pattern = {}, [], None
            for key, value in block:
                if key == 'PATTERN':
                    pattern = dict(pattern=value)
                    patterns.append(pattern)
                elif key in ('OPERANDS', 'IFORM') and pattern is not None:
                    pattern[key.lower()] = value
                else:
                    fields.setdefault(key, []).append(value)
            if 'ICLASS' not in fields:
                continue
            if len(fields['ICLASS']) != 1 or not patterns:
                raise ValueError(f'ambiguous XED instruction at {path}:{start}')
            mnemonic = fields['ICLASS'][0]
            # XED defaults ISA_SET to EXTENSION when it is not explicitly set.
            isa_sets = fields.get('ISA_SET', fields.get('EXTENSION', []))
            yield dict(kind='xed', name=mnemonic, mnemonics=[mnemonic],
                       features=sorted(set(isa_sets + fields.get('EXTENSION', []))),
                       categories=fields.get('CATEGORY', []), fields=fields,
                       patterns=patterns, cpuid={isa: cpuid.get(isa, []) for isa in isa_sets},
                       flags=fields.get('FLAGS'), operation=None,
                       reference=xed_reference(source, path, start))
        elif depth and clean:
            match = re.match(r'([A-Z][A-Z_0-9]*)\s*:\s*(.*)', clean)
            if match:
                block.append(match.groups())
            elif block and line[:1].isspace():
                # Continuations occur in flags/pattern/operand expressions.
                key, value = block[-1]
                block[-1] = key, value + ' ' + clean
            else:
                raise ValueError(f'unparsed XED block line at {path}:{line_number}: {clean}')
    if depth:
        raise ValueError(f'unclosed XED block: {path}')


def feature_key(value):
    return re.sub('[^A-Z0-9]', '', value.upper())


def build(args):
    root, current = args.root, read_current(args.root)
    manifest = load_manifest(root, current)
    sources = {s['kind']: s for s in manifest['sources']}
    xml = safe_artifact(root, sources['intrinsics']['blob']).read_bytes()
    files = sorted(xed_files(safe_artifact(root, sources['xed']['blob']).read_bytes()))
    cpuid = cpuid_records(files, sources['xed'])
    records = list(intrinsic_records(xml, sources['intrinsics']))
    instruction_files = [(path, text) for path, text in files if re.search(r'^\s*ICLASS\s*:', text, re.MULTILINE)]
    for path, text in instruction_files:
        records.extend(xed_records(text, path, sources['xed'], cpuid))
    if not instruction_files or not any(r['kind'] == 'xed' for r in records):
        raise ValueError('no XED instruction source blocks indexed')
    root.mkdir(parents=True, exist_ok=True)
    temporary = root / 'catalog.sqlite.tmp'
    temporary.unlink(missing_ok=True)
    with sqlite3.connect(temporary) as db:
        db.executescript('''CREATE TABLE record(id INTEGER PRIMARY KEY, kind TEXT, name TEXT, body TEXT, search TEXT);
            CREATE TABLE mnemonic(value TEXT, record_id INTEGER); CREATE INDEX mnemonic_value ON mnemonic(value);
            CREATE TABLE feature(value TEXT, record_id INTEGER); CREATE INDEX feature_value ON feature(value);
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT);''')
        for record_id, record in enumerate(records, 1):
            body = json.dumps(record, sort_keys=True)
            db.execute('INSERT INTO record VALUES(?,?,?,?,?)', (record_id, record['kind'], record['name'], body, body.casefold()))
            db.executemany('INSERT INTO mnemonic VALUES(?,?)', [(v.upper(), record_id) for v in record['mnemonics']])
            db.executemany('INSERT INTO feature VALUES(?,?)', [(feature_key(v), record_id) for v in record['features']])
        counts = dict(intrinsics=sum(r['kind'] == 'intrinsic' for r in records),
                      intrinsic_mnemonics=len({m for r in records if r['kind'] == 'intrinsic' for m in r['mnemonics']}),
                      xed_source_blocks=sum(r['kind'] == 'xed' for r in records),
                      xed_source_patterns=sum(len(r.get('patterns', [])) for r in records),
                      xed_mnemonics=len({r['name'] for r in records if r['kind'] == 'xed'}),
                      xed_instruction_files=len(instruction_files), xed_cpuid_isa_sets=len(cpuid),
                      intrinsic_operations=sum(bool(r.get('operation')) for r in records if r['kind'] == 'intrinsic'),
                      intrinsic_sequences=sum(r.get('sequence', '').upper() == 'TRUE' for r in records if r['kind'] == 'intrinsic'),
                      xed_blocks_with_flag_metadata=sum(bool(r.get('flags')) for r in records if r['kind'] == 'xed'),
                      xed_blocks_with_exception_metadata=sum(bool(r['fields'].get('EXCEPTIONS')) for r in records if r['kind'] == 'xed'))
        for key, value in dict(schema=SCHEMA, counts=counts, manifest_sha256=current['manifest_sha256'], gaps=GAPS, sdm=SDM_URL).items():
            db.execute('INSERT INTO metadata VALUES(?,?)', (key, json.dumps(value)))
    data = temporary.read_bytes()
    temporary.unlink()
    current.update(index=save_content(root, 'indexes', data, '.sqlite'), index_sha256=digest(data))
    write_current(root, current)
    return dict(counts=counts, index=current['index'], bytes=len(data), gaps=GAPS, sdm=SDM_URL)


def open_index(root, verify=False):
    current = read_current(root)
    path = safe_artifact(root, current['index'])
    if verify and digest(path.read_bytes()) != current['index_sha256']:
        raise ValueError('index SHA256 mismatch')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    metadata = {k: json.loads(v) for k, v in db.execute('SELECT key,value FROM metadata')}
    if metadata['schema'] != SCHEMA or metadata['manifest_sha256'] != current['manifest_sha256']:
        db.close()
        raise ValueError('stale index: rebuild for current source manifest/schema')
    return db, metadata, current


def query(args):
    db, metadata, current = open_index(args.root)
    clauses, parameters = [], []
    if args.kind != 'all':
        clauses.append('kind=?')
        parameters.append(args.kind)
    for table, values in [('mnemonic', [v.upper() for v in args.mnemonic]),
                          ('feature', [feature_key(v) for v in args.feature])]:
        if values:
            clauses.append(f'id IN (SELECT record_id FROM {table} WHERE value IN ({",".join("?" for _ in values)}))')
            parameters.extend(values)
    for word in args.words:
        clauses.append('instr(search,?)>0')
        parameters.append(word.casefold())
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    with db:
        count = db.execute('SELECT count(*) FROM record' + where, parameters).fetchone()[0]
        rows = db.execute('SELECT body FROM record' + where + ' ORDER BY kind,name,id LIMIT ?', parameters + [args.limit])
        records = [json.loads(row[0]) for row in rows]
    db.close()
    excerpts = []
    for record in records:
        item = {key: record[key] for key in ('kind', 'name', 'mnemonics', 'features', 'categories', 'flags', 'reference')}
        if record['kind'] == 'intrinsic':
            item.update(parameters=record['parameters'], result=record['result'],
                        sequence=record['sequence'], instructions=record['instructions'])
            for key in ('description', 'operation'):
                value = record[key]
                item[key] = value[:args.chars]
                if len(value) > args.chars:
                    item[key + '_truncated_chars'] = len(value) - args.chars
        else:
            item.update(fields=record['fields'], cpuid=record['cpuid'],
                        patterns=record['patterns'][:args.patterns],
                        omitted_patterns=max(0, len(record['patterns']) - args.patterns))
        excerpts.append(item)
    output = dict(matches=count, returned=0, omitted_by_budget=0,
                  index_sha256=current['index_sha256'], results=[], gaps=GAPS, sdm=SDM_URL)
    for ordinal, excerpt in enumerate(excerpts):
        output['results'].append(excerpt)
        output['returned'] = len(output['results'])
        if len(json.dumps(output, ensure_ascii=False)) + 1 > args.budget:
            output['results'].pop()
            output['returned'] = len(output['results'])
            output['omitted_by_budget'] = len(excerpts) - ordinal
            break
    return output


def stats(args):
    db, metadata, current = open_index(args.root, verify=args.command == 'verify')
    db.close()
    manifest = load_manifest(args.root, current) if args.command == 'verify' else json.loads(safe_artifact(args.root, current['manifest']).read_text())
    return dict(**metadata, sources=manifest['sources'], index=current['index'],
                index_sha256=current['index_sha256'], index_bytes=safe_artifact(args.root, current['index']).stat().st_size,
                verified=args.command == 'verify')


def bounded_integer(low, high):
    def parse(value):
        integer = int(value)
        if not low <= integer <= high:
            raise argparse.ArgumentTypeError(f'must be between {low} and {high}')
        return integer
    return parse


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--pretty', action='store_true', help='indent JSON for human reading')
    parser.add_argument('--root', type=Path, default=DEFAULT_ROOT, help=f'local artifact directory (default: {DEFAULT_ROOT})')
    commands = parser.add_subparsers(dest='command', required=True)
    fetch_parser = commands.add_parser('fetch', help='download immutable primary sources (network)')
    fetch_parser.add_argument('--refresh', action='store_true', help='download even when matching verified sources are cached')
    fetch_parser.add_argument('--intrinsics-url', default=GUIDE_URL)
    fetch_parser.add_argument('--intrinsics-sha256', default=GUIDE_SHA256, help='required hash for the selected XML snapshot')
    fetch_parser.add_argument('--xed-revision', default=XED_REVISION, help='immutable Intel XED Git commit')
    commands.add_parser('build', help='validate source hashes and build local SQLite index (offline)')
    commands.add_parser('stats', help='source provenance and honest coverage counts (offline)')
    commands.add_parser('verify', help='verify source, manifest and index SHA256 (offline)')
    query_parser = commands.add_parser('query', help='bounded excerpts (offline); words are ANDed substring matches')
    query_parser.add_argument('words', nargs='*')
    query_parser.add_argument('--mnemonic', action='append', default=[], help='exact mnemonic; repeat for alternatives')
    query_parser.add_argument('--feature', action='append', default=[], help='exact feature label, ignoring punctuation; repeat for alternatives')
    query_parser.add_argument('--kind', choices=('all', 'intrinsic', 'xed'), default='all')
    query_parser.add_argument('--limit', type=bounded_integer(1, 100), default=6)
    query_parser.add_argument('--chars', type=bounded_integer(0, 12000), default=600, help='max characters per description/operation (default: 600)')
    query_parser.add_argument('--budget', type=bounded_integer(2048, 65536), default=8000, help='maximum compact JSON characters including metadata (default: 8000; pretty indentation adds whitespace)')
    query_parser.add_argument('--patterns', type=bounded_integer(1, 20), default=2, help='max XED patterns per result (default: 2)')
    args = parser.parse_args()
    try:
        result = {'fetch': fetch, 'build': build, 'query': query, 'stats': stats, 'verify': stats}[args.command](args)
    except (OSError, ValueError, KeyError, sqlite3.Error, ET.ParseError, tarfile.TarError) as error:
        parser.exit(1, f'x86-mappings: {error}\n')
    json.dump(result, sys.stdout, indent=2 if args.pretty else None, ensure_ascii=False)
    print()


if __name__ == '__main__':
    main()
