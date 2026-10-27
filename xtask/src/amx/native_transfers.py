"""Independently replay the source-defined M1 transfer effects in native traces.

The row/interleave contract is corsix/amx 483714bb ldst.c/ldst.md (MIT,
Copyright (c) 2022 Peter Cawley; LICENSES/MIT.txt). Fault classifications are
observations, not inferred permission or exception-priority rules for another
CPU or OS.
"""

from collections import Counter
import json
import mmap
from pathlib import Path
import struct


def verify(directory):
    if not __debug__:
        raise RuntimeError("native trace verification requires Python assertions enabled")
    directory = Path(directory)
    rows = [json.loads(line) for line in (directory / "transfers.stdout").read_text().splitlines()]
    categories = Counter()
    offset = 0
    with (directory / "transfers.bin").open("rb") as file, mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for row in rows:
            assert row["complete"] and row["after_valid"] and row["wait_status"] == 0, row
            assert row["amx_bytes"] == 5120 and row["payload_offset"] == offset, row
            state_bytes, page_bytes = row["amx_bytes"], row["page_bytes"]
            before = data[offset:offset + state_bytes]
            after = data[offset + state_bytes:offset + 2 * state_bytes]
            start = offset + 2 * state_bytes
            memory_before = data[start:start + page_bytes]
            memory_after = data[start + page_bytes:start + 2 * page_bytes]
            context = data[start + 2 * page_bytes:offset + row["payload_bytes"]]
            offset += row["payload_bytes"]
            assert len(context) == row["context_bytes"], row
            address, page, operand = (int(row[key], 16) for key in ("address", "page", "operand"))
            op = row["op"]
            store = op in (2, 3, 5, 7)
            multiple = bool(row["multiple"]) and op < 6
            if row["signal"]:
                assert before == after and memory_before == memory_after, row
                assert row["signal"] == 10 and row["signal_code"] == 1, row
                assert len(context) == 816, row  # Pinned arm64 Darwin mcontext ABI.
                far, esr, exception = struct.unpack_from("<QII", context)
                assert (far, esr, exception) == (int(row["far"], 16), row["esr"], row["exception"]), row
                assert far == int(row["signal_address"], 16), row
                word = row["word"]
                assert word & ~31 == 0x201000 + (op << 5), row
                register = word & 31
                assert register < 31 and struct.unpack_from("<Q", context, 16 + register * 8)[0] == operand, row
                if multiple and address % 128:
                    assert esr == 0x92000021 | (int(store) << 6) and far == address, row
                    categories["alignment_store" if store else "alignment_load"] += 1
                else:
                    # Translation/per-page protection is an OS mapping fact;
                    # do not turn its observed FSC into a generic MMU rule.
                    categories[f"os_fault_{esr:08x}"] += 1
                continue
            assert not multiple or address % 128 == 0, row
            assert not context and row["esr"] == 0, row
            expected = bytearray(before)
            expected_memory = bytearray(memory_before)
            memory_offset = address - page
            size = 128 if multiple else 64
            assert 0 <= memory_offset <= page_bytes - size, row
            register_row = row["row"]
            if op < 6:
                bank, count = (0, 8) if op in (0, 2) else (512, 8) if op in (1, 3) else (1024, 64)
                for part in range(2 if multiple else 1):
                    state_offset = bank + ((register_row + part) % count) * 64
                    pointer = memory_offset + part * 64
                    if store:
                        expected_memory[pointer:pointer + 64] = before[state_offset:state_offset + 64]
                    else:
                        expected[state_offset:state_offset + 64] = memory_before[pointer:pointer + 64]
            else:
                even_row, half = register_row & ~1, (register_row & 1) * 8
                for lane in range(16):
                    state_offset = 1024 + (even_row | (lane & 1)) * 64 + (half + lane // 2) * 4
                    pointer = memory_offset + lane * 4
                    if store:
                        expected_memory[pointer:pointer + 4] = before[state_offset:state_offset + 4]
                    else:
                        expected[state_offset:state_offset + 4] = memory_before[pointer:pointer + 4]
            assert after == expected and memory_after == expected_memory, row
            categories["successful_store" if store else "successful_load"] += 1
        assert offset == len(data), (offset, len(data))
    return {"observations": len(rows), "payload_bytes": offset, "categories": dict(sorted(categories.items()))}


if __name__ == "__main__":
    import sys
    print(json.dumps(verify(sys.argv[1]), indent=2))
