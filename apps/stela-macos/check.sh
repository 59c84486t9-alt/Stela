#!/usr/bin/env bash
# Portable model checks; macOS additionally type-checks and snapshots the native app.
set -euo pipefail
package="$(cd -- "$(dirname -- "$0")" && pwd)"
swift test --package-path "$package" -Xswiftc -warnings-as-errors
if [[ "$(uname -s)" == Darwin ]]; then
    swift build --package-path "$package" -Xswiftc -warnings-as-errors --product Stela
    binary_directory="$(swift build --package-path "$package" --show-bin-path)"
    repository="$(cd -- "$package/../.." && pwd)"
    "$binary_directory/Stela" --render-previews "$repository/target/stela-macos/previews"
fi
