#!/bin/bash
# Stop JWT Integration Tests Docker containers

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🛑 Stopping JWT Integration Tests Docker containers"

cd "${PROJECT_DIR}"

# Detect which compose file to use
if [[ -f "target/quarkus-app/quarkus-run.jar" ]] && [[ ! -f "target/*-runner" ]]; then
    COMPOSE_FILE="docker-compose-jvm.yml"
    MODE="jvm"
else
    COMPOSE_FILE="docker-compose.yml"
    MODE="native"
fi

# Stop and remove containers
echo "📦 Stopping Docker containers ($MODE mode)..."
docker compose -f "$COMPOSE_FILE" down

# Optional: Clean up images and volumes
if [ "$1" = "--clean" ]; then
    echo "🧹 Cleaning up Docker images and volumes..."
    docker compose -f "$COMPOSE_FILE" down --volumes --rmi all
fi

echo "✅ JWT Integration Tests stopped successfully"

# Show final status
if docker compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
    echo "⚠️  Some containers are still running:"
    docker compose -f "$COMPOSE_FILE" ps
else
    echo "✅ All containers are stopped"
fi