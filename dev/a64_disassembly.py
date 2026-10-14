"""Hash-bound LLVM A64 disassembly for encodings unavailable in Capstone.

This adapter records actual independent decoding. Canonical guards constrain the
decoded word to hash-validated Arm facts; they never substitute for decoding or
establish translation semantics, guest feature availability or coverage credit.
"""

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


INSTRUCTION_BYTES = 4
MAXIMUM_BATCH_WORDS = 4096
DEFAULT_MATTRS = ('+sme2', '+sve2p1')
DECODE_BASIS = 'apple_llvm21_objdump'
AARCH64_ELF_MACHINE = 183
ELF_HEADER_BYTES = 64
ELF_SECTION_HEADER = struct.Struct('<IIQQQQIIQQ')
DECODED_LINE = re.compile(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+([a-z][a-z0-9_.]*)(?:\s+(.*?))?\s*$', re.IGNORECASE)
INSTRUCTION_LINE = re.compile(r'^\s*[0-9a-f]+:\s', re.IGNORECASE)
FEATURE_NAME = re.compile(r'^[+-][a-z][a-z0-9]*$')


@dataclass(frozen=True)
class PinnedTool:
    path: Path
    sha256: str
    version_prefix: str


@dataclass(frozen=True)
class Toolchain:
    clang: PinnedTool
    objdump: PinnedTool


XCODE_BIN = Path('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin')
PINNED_APPLE_LLVM21 = Toolchain(
    PinnedTool(XCODE_BIN / 'clang',
               'd2e4bf622758eee1bf7267c060497fb2c41e098d37b0fca8be73898dc7e14eda',
               'Apple clang version 21.0.0'),
    PinnedTool(XCODE_BIN / 'llvm-objdump',
               'c29752d9c31d35d8e102db04869c20ac3d98809a804adc7370c827e64a3446c8',
               'Apple LLVM version 21.0.0'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write_new(path, data):
    with Path(path).open('xb') as output:
        output.write(data)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def tool_identity(tool):
    path = Path(tool.path).resolve(strict=True)
    data = path.read_bytes()
    if digest(data) != tool.sha256:
        raise ValueError('Independent disassembler tool hash differs: ' + str(path))
    version = subprocess.check_output([str(path), '--version'], text=True, timeout=30)
    if not version.splitlines() or not version.splitlines()[0].startswith(tool.version_prefix):
        raise ValueError('Independent disassembler tool version differs: ' + str(path))
    return {'path': str(path), 'sha256': tool.sha256, 'bytes': len(data), 'version': version}


def elf_text(data):
    """Read exact .text bytes from the assembler's little-endian ELF64 object."""
    if (len(data) < ELF_HEADER_BYTES or data[:6] != b'\x7fELF\x02\x01'
            or struct.unpack_from('<H', data, 18)[0] != AARCH64_ELF_MACHINE):
        raise ValueError('Independent assembler did not produce AArch64 ELF64')
    section_offset, = struct.unpack_from('<Q', data, 40)
    entry_bytes, count, names_index = struct.unpack_from('<3H', data, 58)
    if entry_bytes != ELF_SECTION_HEADER.size or not count or names_index >= count:
        raise ValueError('Independent ELF section framing differs')
    if section_offset + count * entry_bytes > len(data):
        raise ValueError('Independent ELF section table is truncated')
    sections = [ELF_SECTION_HEADER.unpack_from(data, section_offset + index * entry_bytes)
                for index in range(count)]
    names = sections[names_index]
    if names[4] + names[5] > len(data):
        raise ValueError('Independent ELF section names are truncated')
    strings = data[names[4]:names[4] + names[5]]
    texts = []
    for section in sections:
        start = section[0]
        end = strings.find(b'\0', start)
        if start >= len(strings) or end < start:
            raise ValueError('Independent ELF section name is invalid')
        if strings[start:end] == b'.text':
            offset, size = section[4:6]
            if offset + size > len(data):
                raise ValueError('Independent ELF text is truncated')
            texts.append(data[offset:offset + size])
    if len(texts) != 1:
        raise ValueError('Independent ELF requires one exact .text section')
    return texts[0]


def parse_disassembly(output, words):
    rows = []
    for line in output.splitlines():
        match = DECODED_LINE.fullmatch(line)
        if match is None:
            if INSTRUCTION_LINE.match(line):
                raise ValueError('LLVM declined or ambiguously decoded an A64 word: ' + line.strip())
            continue
        offset, encoded, mnemonic, operands = match.groups()
        offset, encoded = int(offset, 16), int(encoded, 16)
        index = len(rows)
        if index >= len(words) or offset != index * INSTRUCTION_BYTES or encoded != words[index]:
            raise ValueError('LLVM decoded word/order/offset differs from exact input')
        mnemonic, operands = mnemonic.lower(), (operands or '').strip()
        rows.append({'word': encoded, 'offset': offset, 'mnemonic': mnemonic,
                     'operands': operands, 'assembly': mnemonic + (' ' + operands if operands else '')})
    if len(rows) != len(words):
        raise ValueError('LLVM did not decode every input A64 word')
    return rows


def decode_words(words, directory, *, toolchain=PINNED_APPLE_LLVM21, mattrs=DEFAULT_MATTRS):
    """Decode one bounded batch, retaining tool commands, objects and raw output."""
    adapter_sha256 = digest(Path(__file__).read_bytes())
    words, mattrs = list(words), tuple(mattrs)
    if (not 0 < len(words) <= MAXIMUM_BATCH_WORDS
            or any(type(word) is not int or not 0 <= word < 1 << 32 for word in words)):
        raise ValueError('Independent decoding requires a bounded nonempty u32 word batch')
    if not mattrs or len(set(mattrs)) != len(mattrs) or any(not FEATURE_NAME.fullmatch(value) for value in mattrs):
        raise ValueError('LLVM decoding features must be explicit unique feature names')
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    tools = {'clang': tool_identity(toolchain.clang), 'objdump': tool_identity(toolchain.objdump)}
    source = '.text\n' + '\n'.join(f'.inst 0x{word:08x}' for word in words) + '\n'
    write_new(directory / 'subjects.S', source.encode())
    commands = [
        [tools['clang']['path'], '--target=aarch64-unknown-none-elf', '-c',
         str(directory / 'subjects.S'), '-o', str(directory / 'subjects.o')],
        [tools['objdump']['path'], '--disassemble', '--mattr=' + ','.join(mattrs),
         str(directory / 'subjects.o')],
    ]
    write_new(directory / 'commands.json', json_bytes(commands))
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, timeout=60)
        write_new(directory / f'command-{index}.stdout', result.stdout)
        write_new(directory / f'command-{index}.stderr', result.stderr)
        if result.returncode:
            raise ValueError('Independent LLVM command failed; retained output in ' + str(directory))
    source_bytes = struct.pack('<' + 'I' * len(words), *words)
    if elf_text((directory / 'subjects.o').read_bytes()) != source_bytes:
        raise ValueError('Independent assembler altered the exact subject words')
    rows = parse_disassembly((directory / 'command-1.stdout').read_text(), words)
    write_new(directory / 'decoded.json', json_bytes(rows))
    for identity in tools.values():
        if digest(Path(identity['path']).read_bytes()) != identity['sha256']:
            raise ValueError('Independent LLVM tool changed during decoding')
    if digest(Path(__file__).read_bytes()) != adapter_sha256:
        raise ValueError('Independent LLVM adapter changed during decoding')
    receipt = {'kind': 'independent-apple-llvm21-a64-disassembly-v1', 'passed': True,
               'independent_decode_basis': DECODE_BASIS, 'words': len(words),
               'source_bytes_sha256': digest(source_bytes), 'mattrs': list(mattrs),
               'tools': tools, 'rows': rows,
               'adapter_sha256': adapter_sha256,
               'files': {path.name: {'sha256': digest(path.read_bytes()), 'bytes': path.stat().st_size}
                         for path in sorted(directory.iterdir()) if path.is_file()},
               'limits': 'Actual independent disassembly only; no instruction semantics, guest feature availability, native execution or coverage admission credit.'}
    write_new(directory / 'receipt.json', json_bytes(receipt))
    return receipt


def validate_canonical(row, identity, fact, expected_mnemonics=None):
    """Constrain actual decoding to one caller-supplied validated canonical fact."""
    if fact.get('id') != identity:
        raise ValueError('Independent decoding canonical identity differs')
    word = row.get('word')
    if type(word) is not int or not 0 <= word < 1 << 32:
        raise ValueError('Independent decoded word must fit u32')
    if word & int(fact['encoding_mask'], 16) != int(fact['encoding_value'], 16):
        raise ValueError('Independent decoded word differs from canonical fixed bits')
    mnemonic = row['mnemonic']
    if mnemonic != fact['mnemonic'].lower() or expected_mnemonics is not None and mnemonic not in expected_mnemonics:
        raise ValueError('Independent LLVM mnemonic differs from canonical form')
    if row['assembly'] != mnemonic + (' ' + row['operands'] if row['operands'] else ''):
        raise ValueError('Independent LLVM assembly framing differs')
    return mnemonic, row['assembly'], DECODE_BASIS
