#!/bin/sh
# Encode the deterministic samples of src/lzfse.rs with Apple's LZFSE encoder
# (macOS compression_tool): 3000 bytes give one LZVN block, 300000 bytes
# LZFSE blocks with packed frequency tables.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 -I "$here/make-samples.py" "$work" 3000 300000
for size in 3000 300000; do
    compression_tool -encode -a lzfse -i "$work/sample-$size.raw" -o "$here/sample-$size.lzfse"
done
