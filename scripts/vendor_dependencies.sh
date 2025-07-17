#!/usr/bin/env bash
set -euo pipefail

VENDOR_DIR="src/vendor"

# Clean vendor directory
rm -rf "$VENDOR_DIR"
mkdir -p "$VENDOR_DIR"

pip download --no-binary :all: -r src/runtime_requirements.txt -d "$VENDOR_DIR"

echo "Vendored dependencies installed in $VENDOR_DIR"
