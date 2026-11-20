#!/usr/bin/env bash
# Build release binaries into dist/ (Linux x86_64 + Windows x86_64).
# Needs: rustup target add x86_64-pc-windows-gnu; apt install mingw-w64 libdbus-1-dev pkg-config
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p ccc-hub -p ccc
cargo build --release -p ccc --target x86_64-pc-windows-gnu
mkdir -p dist
cp target/release/ccc-hub dist/ccc-hub-linux-x86_64
cp target/release/ccc dist/ccc-linux-x86_64
cp target/x86_64-pc-windows-gnu/release/ccc.exe dist/ccc-windows-x86_64.exe
ls -la dist
