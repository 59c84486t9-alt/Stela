"""Bounded full-State and byte-history serialization for memory fixtures."""
from differential import State

MAX_OPERATIONS = 16
MAX_BYTE_WINDOW = 256


def linearization_allowed(history, initial_ram, ram_address, final_ram=None, *, expected_operation, effective_address):
    if len(history) > MAX_OPERATIONS:
        raise ValueError('Memory history exceeds16 operations')
    ranges = []
    for row in history:
        initial, op = State.from_buffer_copy(bytes.fromhex(row['initial_state_hex'])), row['operation']
        start = effective_address(op, initial) - row.get('ram_address', ram_address)
        ranges.append((start, start + op['total_bytes']))
    lower, upper = (min(start for start, _ in ranges), max(end for _, end in ranges)) if ranges else (0, 0)
    if not 0 <= lower <= upper <= len(initial_ram) or upper - lower > MAX_BYTE_WINDOW:
        raise ValueError('Memory history exceeds bounded owned byte window')
    rejected = set()
    def search(remaining, ram):
        if not remaining: return final_ram is None or ram == final_ram
        key = remaining, ram[lower:upper]
        if key in rejected: return False
        for index in remaining:
            row = history[index]
            if any(history[other]['end'] < row['begin'] for other in remaining if other != index): continue
            initial = State.from_buffer_copy(bytes.fromhex(row['initial_state_hex']))
            state, updated, fault = expected_operation(row['operation'], initial, ram, row.get('ram_address', ram_address))
            if fault or bytes(state).hex() != row['final_state_hex']: continue
            if search(tuple(other for other in remaining if other != index), updated): return True
        rejected.add(key)
        return False
    return search(tuple(range(len(history))), bytes(initial_ram))
