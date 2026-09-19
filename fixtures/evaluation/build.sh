#!/usr/bin/env bash
set -euo pipefail
output=${1:?Usage: build.sh OUTPUT_DIRECTORY}
mkdir -p "$output"
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
for optimization in 0 2 s; do
  cc "-O$optimization" -g "$source_dir/config-loader.c" -o "$output/config-loader-O$optimization.symbols"
  cp "$output/config-loader-O$optimization.symbols" "$output/config-loader-O$optimization"
  strip --strip-all "$output/config-loader-O$optimization"
done
