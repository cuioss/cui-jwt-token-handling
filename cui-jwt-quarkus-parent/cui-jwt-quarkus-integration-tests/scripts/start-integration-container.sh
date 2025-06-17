#!/bin/bash
# Start JWT Integration Tests using Docker Compose with native container

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$(dirname "$PROJECT_DIR")")"

echo "🚀 Starting JWT Integration Tests with Docker Compose"
echo "Project directory: ${PROJECT_DIR}"
echo "Root directory: ${ROOT_DIR}"

cd "${PROJECT_DIR}"

# Native image should already be built by the Maven lifecycle
echo "📦 Using native image from target directory..."
cd "${PROJECT_DIR}"

# Start with Docker Compose
echo "🐳 Starting Docker container with native image..."
docker compose up -d

# Wait for service to be ready and measure startup time
echo "⏳ Waiting for service to be ready..."
START_TIME=$(date +%s)
for i in {1..30}; do
    if curl -k -s https://localhost:10443/q/health/live > /dev/null 2>&1; then
        END_TIME=$(date +%s)
        TOTAL_TIME=$((END_TIME - START_TIME))
        echo "✅ Service is ready!"
        echo "📈 Actual startup time: ${TOTAL_TIME}s (container + application)"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Service failed to start within 30 seconds"
        echo "Check logs with: docker compose logs"
        exit 1
    fi
    echo "⏳ Waiting... (attempt $i/30)"
    sleep 1
done

# Extract native startup time from logs
NATIVE_STARTUP=$(docker compose logs 2>/dev/null | grep "started in" | sed -n 's/.*started in \([0-9.]*\)s.*/\1/p' | tail -1)
if [ ! -z "$NATIVE_STARTUP" ]; then
    echo "⚡ Native app startup: ${NATIVE_STARTUP}s (application only)"
fi

# Show actual image size
IMAGE_SIZE=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.Size}}" | grep cui-jwt-integration-tests | awk '{print $2}' | head -1)
if [ ! -z "$IMAGE_SIZE" ]; then
    echo "📦 Image size: ${IMAGE_SIZE} (distroless native)"
fi

echo ""
echo "🎉 JWT Integration Tests are running!"
echo ""
echo "📱 Application URLs:"
echo "  🔍 Health Check:   https://localhost:10443/q/health"
echo "  📊 Metrics:        https://localhost:10443/q/metrics"
echo ""
echo "🧪 Quick test commands:"
echo "  curl -k https://localhost:10443/q/health/live"
echo ""
echo "🛑 To stop: ./scripts/stop-integration-container.sh"
echo "📋 To view logs: docker compose logs -f"
