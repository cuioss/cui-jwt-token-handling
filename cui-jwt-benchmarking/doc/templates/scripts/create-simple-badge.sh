#!/bin/bash
# Create simple badges for benchmarks
# Usage: create-simple-badge.sh <benchmark-results-file> <output-dir> <timestamp>

set -e

BENCHMARK_FILE="$1"
OUTPUT_DIR="$2"
TIMESTAMP="$3"

echo "Creating simple badges from benchmark results..."

# Function to create a badge for a benchmark
create_badge() {
    local benchmark_name=$1
    local display_name=$2
    local badge_name=$3
    local color=$4

    # Extract benchmark data using jq for reliable JSON parsing
    if [ -f "$BENCHMARK_FILE" ]; then
        local benchmark_entry=$(jq -r '.[] | select(.benchmark == "'"$benchmark_name"'")' "$BENCHMARK_FILE" 2>/dev/null)
        local score=$(echo "$benchmark_entry" | jq -r '.primaryMetric.score' 2>/dev/null || echo "N/A")
        local unit=$(echo "$benchmark_entry" | jq -r '.primaryMetric.scoreUnit' 2>/dev/null || echo "")
        
        echo "Debug: Extracting badge for $benchmark_name: score=$score, unit=$unit"
    else
        echo "Warning: $BENCHMARK_FILE not found"
        local score="N/A"
        local unit=""
    fi

    if [ "$score" != "N/A" ] && [ "$score" != "null" ]; then
        # Convert to appropriate unit and format
        if [[ "$unit" == "us/op" ]]; then
            # Convert microseconds to milliseconds for display
            local score_ms=$(echo "scale=3; $score / 1000" | bc -l)
            local formatted_score=$(printf "%.2f" $score_ms)
            local unit_display="ms"
        elif [[ "$unit" == "ms/op" ]]; then
            local formatted_score=$(printf "%.2f" $score)
            local unit_display="ms"
        elif [[ "$unit" == "ops/s" ]]; then
            # Format ops/s with appropriate scale
            if [ $(echo "$score > 1000" | bc -l) -eq 1 ]; then
                local score_k=$(echo "scale=1; $score / 1000" | bc -l)
                local formatted_score=$(printf "%.1f" $score_k)
                local unit_display="k ops/s"
            else
                local formatted_score=$(printf "%.0f" $score)
                local unit_display="ops/s"
            fi
        else
            local formatted_score=$(printf "%.2f" $score)
            local unit_display="$unit"
        fi

        # Create badge JSON - no timestamp for validator badge, include for others
        if [[ "$badge_name" == "validator-badge" ]]; then
            echo "{\"schemaVersion\":1,\"label\":\"$display_name\",\"message\":\"${formatted_score} ${unit_display}\",\"color\":\"$color\"}" > "$OUTPUT_DIR/$badge_name.json"
        else
            echo "{\"schemaVersion\":1,\"label\":\"$display_name\",\"message\":\"${formatted_score} ${unit_display} ($TIMESTAMP)\",\"color\":\"$color\"}" > "$OUTPUT_DIR/$badge_name.json"
        fi

        # Create badge markdown for README
        echo "[![$display_name](https://img.shields.io/endpoint?url=https://cuioss.github.io/cui-jwt/benchmarks/badges/$badge_name.json)](https://cuioss.github.io/cui-jwt/benchmarks/)" >> "$(dirname "$OUTPUT_DIR")/badge-markdown.txt"

        echo "Created badge for $display_name: $formatted_score $unit_display"
    else
        echo "Warning: Could not find benchmark results for $benchmark_name"
        # Create placeholder badge
        echo "{\"schemaVersion\":1,\"label\":\"$display_name\",\"message\":\"No Data\",\"color\":\"red\"}" > "$OUTPUT_DIR/$badge_name.json"
    fi
}

# Create combined badge for all benchmarks
echo "{\"schemaVersion\":1,\"label\":\"JWT Benchmarks\",\"message\":\"Updated $TIMESTAMP\",\"color\":\"brightgreen\"}" > "$OUTPUT_DIR/all-benchmarks.json"

# Create last benchmark run badge
echo "{\"schemaVersion\":1,\"label\":\"Last Benchmark Run\",\"message\":\"$TIMESTAMP\",\"color\":\"blue\"}" > "$OUTPUT_DIR/last-run-badge.json"

echo "Simple badges created successfully"