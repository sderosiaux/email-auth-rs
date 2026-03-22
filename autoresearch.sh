#!/usr/bin/env bash
set -euo pipefail

# Run cargo test and count total passing tests
output=$(cargo test --message-format=short 2>&1)
passed=$(echo "$output" | grep -E 'test result:' | awk '{sum += $4} END {print sum+0}')

echo "METRIC passed=${passed}"
