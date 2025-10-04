#!/bin/bash

# Build orlp/ed25519 WebAssembly module

set -e

echo "Building orlp/ed25519 WebAssembly module..."

# Compile all orlp source files + our wrapper to WASM
emcc \
  -O3 \
  -s WASM=1 \
  -s EXPORTED_FUNCTIONS='["_orlp_derive_public_key", "_orlp_validate_keypair", "_orlp_sign", "_orlp_verify"]' \
  -s EXPORTED_RUNTIME_METHODS='["ccall", "cwrap", "HEAPU8", "HEAP8", "HEAPU32", "HEAP32"]' \
  -s MODULARIZE=1 \
  -s EXPORT_NAME="OrlpEd25519" \
  -s ALLOW_MEMORY_GROWTH=1 \
  -s NO_EXIT_RUNTIME=1 \
  -I orlp-ed25519/src \
  orlp-ed25519/src/*.c \
  orlp-ed25519-wrapper.c \
  -o orlp-ed25519.js

echo "WebAssembly module built successfully!"
echo "Generated files:"
echo "  - orlp-ed25519.js (JavaScript loader)"
echo "  - orlp-ed25519.wasm (WebAssembly binary)"
