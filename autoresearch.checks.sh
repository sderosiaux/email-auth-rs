#!/usr/bin/env bash
set -euo pipefail

# Guard: all tests must pass
cargo test --message-format=short 2>&1
