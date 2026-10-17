"""Write sample-N.raw: the bytes of `sample(N, 7)` in src/lzfse.rs.

make-samples.sh encodes them with macOS `compression_tool`.
"""
import sys

WORDS = [b"kernel ", b"collection ", b"device ", b"tree ", b"\0\0\0\0", b"stela ", b"\xff\xfe", b"preboot "]
MASK = (1 << 64) - 1


def sample(size, seed):
    state, out = seed, bytearray()
    while len(out) < size:
        state = (state * 6364136223846793005 + 1442695040888963407) & MASK
        pick = state >> 33
        if pick % 5 == 0:
            out.append((pick >> 8) & 0xFF)
        else:
            out += WORDS[pick % len(WORDS)]
    return bytes(out[:size])


for size in map(int, sys.argv[2:]):
    with open(f"{sys.argv[1]}/sample-{size}.raw", "wb") as f:
        f.write(sample(size, 7))
