#!/bin/bash
# Create simple badges for benchmarks
# Usage: create-simple-badge.sh <benchmark-results-file> <output-dir> <timestamp>

set -e

BENCHMARK_FILE="$1"
OUTPUT_DIR="$2"
TIMESTAMP="$3"

echo "Creating simple badges from benchmark results..."

# Create combined badge for all benchmarks
echo "{\"schemaVersion\":1,\"label\":\"JWT Benchmarks\",\"message\":\"Updated $TIMESTAMP\",\"color\":\"brightgreen\"}" > "$OUTPUT_DIR/all-benchmarks.json"

# Create last benchmark run badge
echo "{\"schemaVersion\":1,\"label\":\"Last Benchmark Run\",\"message\":\"$TIMESTAMP\",\"color\":\"blue\"}" > "$OUTPUT_DIR/last-run-badge.json"

echo "Simple badges created successfully"