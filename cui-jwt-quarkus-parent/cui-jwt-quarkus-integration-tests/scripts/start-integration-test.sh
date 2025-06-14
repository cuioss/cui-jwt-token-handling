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

# Build native image first
echo "📦 Building native image..."
cd "${ROOT_DIR}"
echo "📍 Building from: $(pwd)"
./mvnw clean package -Dnative -Dquarkus.native.container-build=true -DskipTests -pl cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests
cd "${PROJECT_DIR}"

# Start with Docker Compose
echo "🐳 Starting Docker container with native image..."
docker compose up --build -d

# Wait for service to be ready
echo "⏳ Waiting for service to be ready..."
for i in {1..30}; do
    if curl -k -s https://localhost:10443/q/health/live > /dev/null 2>&1; then
        echo "✅ Service is ready!"
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

echo ""
echo "🎉 JWT Integration Tests are running!"
echo ""
echo "📱 Application URLs:"
echo "  🔍 Health Check:   https://localhost:10443/q/health"
echo "  💚 Live Check:     https://localhost:10443/q/health/live"
echo "  🎫 JWT Status:     https://localhost:10443/jwt/status"
echo "  🏓 JWT Ping:       https://localhost:10443/jwt/ping"
echo "  📊 Metrics:        https://localhost:10443/q/metrics"
echo ""
echo "🧪 Quick test commands:"
echo "  curl -k https://localhost:10443/q/health/live"
echo "  curl -k https://localhost:10443/jwt/status"
echo "  curl -k https://localhost:10443/jwt/ping"
echo ""
echo "🛑 To stop: ./scripts/stop-integration-test.sh"
echo "📋 To view logs: docker compose logs -f"