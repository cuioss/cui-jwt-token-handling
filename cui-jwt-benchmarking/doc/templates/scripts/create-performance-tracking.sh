#!/bin/bash
# Create performance tracking data from benchmark results
# Usage: create-performance-tracking.sh <jmh-result-file> <templates-dir> <output-dir> <commit-hash>

set -e

JMH_RESULT_FILE="$1"
TEMPLATES_DIR="$2"
OUTPUT_DIR="$3"
COMMIT_HASH="$4"

if [ ! -f "$JMH_RESULT_FILE" ]; then
  echo "Error: JMH result file not found: $JMH_RESULT_FILE"
  exit 1
fi

echo "Creating performance tracking data..."

# Get environment info
JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
OS_NAME="$(uname -s)"

# Create performance tracking directory
mkdir -p "$OUTPUT_DIR/tracking"

# Run the performance badge script to get metrics
BADGE_OUTPUT=$(bash "$TEMPLATES_DIR/scripts/create-performance-badge.sh" "$JMH_RESULT_FILE" "$OUTPUT_DIR/badges" 2>&1)
echo "$BADGE_OUTPUT"

# Extract metrics from badge script output
PERFORMANCE_SCORE=$(echo "$BADGE_OUTPUT" | grep "PERFORMANCE_SCORE=" | cut -d'=' -f2)
THROUGHPUT_OPS_PER_SEC=$(echo "$BADGE_OUTPUT" | grep "THROUGHPUT_OPS_PER_SEC=" | cut -d'=' -f2)
AVERAGE_TIME_MS=$(echo "$BADGE_OUTPUT" | grep "AVERAGE_TIME_MS=" | cut -d'=' -f2)
ERROR_RESILIENCE_OPS_PER_SEC=$(echo "$BADGE_OUTPUT" | grep "ERROR_RESILIENCE_OPS_PER_SEC=" | cut -d'=' -f2)
AVG_TIME_MICROS=$(echo "$BADGE_OUTPUT" | grep "AVG_TIME_MICROS=" | cut -d'=' -f2)

if [ -z "$PERFORMANCE_SCORE" ] || [ "$PERFORMANCE_SCORE" = "0" ]; then
  echo "Warning: Could not extract valid performance metrics for tracking"
  exit 1
fi

# Create performance run JSON from template using envsubst for safe variable substitution
export TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
export COMMIT_HASH="$COMMIT_HASH"
export PERFORMANCE_SCORE="$PERFORMANCE_SCORE"
export THROUGHPUT_VALUE="$THROUGHPUT_OPS_PER_SEC"
export AVERAGE_TIME_MS="$AVERAGE_TIME_MS"
export ERROR_RESILIENCE_VALUE="$ERROR_RESILIENCE_OPS_PER_SEC"
export THROUGHPUT_OPS_PER_SEC="$THROUGHPUT_OPS_PER_SEC"
export AVG_TIME_MICROS="$AVG_TIME_MICROS"
export ERROR_RESILIENCE_OPS_PER_SEC="$ERROR_RESILIENCE_OPS_PER_SEC"
export JAVA_VERSION="$JAVA_VERSION"
export JVM_ARGS="default"
export OS_NAME="$OS_NAME"

TIMESTAMP_FILE=$(date -u +"%Y%m%d-%H%M%S")
envsubst < "$TEMPLATES_DIR/performance-run.json" > "$OUTPUT_DIR/tracking/performance-$TIMESTAMP_FILE.json"

echo "Created performance tracking file: performance-$TIMESTAMP_FILE.json"

# Export metrics for use by calling script
echo "PERF_SCORE=$PERFORMANCE_SCORE"
echo "PERF_THROUGHPUT=$THROUGHPUT_OPS_PER_SEC"
echo "PERF_LATENCY=$AVERAGE_TIME_MS"
echo "PERF_RESILIENCE=$ERROR_RESILIENCE_OPS_PER_SEC"