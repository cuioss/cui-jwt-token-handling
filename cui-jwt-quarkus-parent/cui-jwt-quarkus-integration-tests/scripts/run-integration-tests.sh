#!/bin/bash
# Run complete integration tests using Docker containers

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$(dirname "$PROJECT_DIR")")"

echo "🧪 Running JWT Integration Tests with Docker"
echo "Project directory: ${PROJECT_DIR}"
echo "Root directory: ${ROOT_DIR}"

cd "${PROJECT_DIR}"

# Setup environment
echo "🔧 Setting up environment..."
"${SCRIPT_DIR}/setup-environment.sh"

# Build native image
echo "📦 Building native image..."
cd "${ROOT_DIR}"
echo "📍 Building from: $(pwd)"
./mvnw clean package -Pnative -DskipTests -pl cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests -am
cd "${PROJECT_DIR}"

# Start containers
echo "🐳 Starting Docker containers..."
docker compose up --build -d

# Wait for service to be ready
echo "⏳ Waiting for service to be ready..."
for i in {1..60}; do
    if curl -k -s https://localhost:10443/q/health/live > /dev/null 2>&1; then
        echo "✅ Service is ready!"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "❌ Service failed to start within 60 seconds"
        echo "📋 Container logs:"
        docker compose logs
        docker compose down
        exit 1
    fi
    echo "⏳ Waiting... (attempt $i/60)"
    sleep 1
done

# Run integration tests
echo "🧪 Running integration tests..."
cd "${ROOT_DIR}"
echo "📍 Testing from: $(pwd)"
./mvnw verify -DskipUnitTests=true -Dtest.https.port=10443 -pl cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests
cd "${PROJECT_DIR}"

TEST_RESULT=$?

# Stop containers
echo "🛑 Stopping containers..."
docker compose down

if [ $TEST_RESULT -eq 0 ]; then
    echo ""
    echo "✅ All integration tests passed!"
else
    echo ""
    echo "❌ Some integration tests failed!"
    exit $TEST_RESULT
fi