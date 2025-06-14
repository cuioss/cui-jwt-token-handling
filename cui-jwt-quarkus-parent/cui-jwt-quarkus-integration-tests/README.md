# JWT Integration Tests Module

This module provides comprehensive integration tests for the CUI JWT Quarkus extension, including native container testing with HTTPS support.

## Port Configuration

The integration tests are designed to test from the **external perspective**, using Docker port mapping to avoid conflicts:

### Internal vs External Ports

- **Application Internal Port**: `8443` (standard HTTPS port inside the container)
- **External Test Port**: `10443` (non-standard port mapped by Docker to avoid conflicts)

### Maven Configuration

The test port is configured via Maven properties and can be customized:

```xml
<properties>
    <!-- External test port for integration tests -->
    <test.https.port>10443</test.https.port>
</properties>
```

### Test Configuration

All integration tests extend `BaseIntegrationTest` which automatically configures REST Assured to use the external port:

```java
@QuarkusIntegrationTest
class MyIntegrationTest extends BaseIntegrationTest {
    // Tests automatically use the external port configured via Maven
}
```

### Running Tests with Custom Port

```bash
# Run tests with default external port (10443) - from project root
../../mvnw clean verify -pl cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests

# Run tests with custom external port - from project root
../../mvnw clean verify -pl cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests -Dtest.https.port=11443

# Or use the convenience script
./scripts/run-integration-tests.sh
```

## Docker Configuration

### Docker Compose

The provided `docker-compose.yml` handles port mapping:

```yaml
services:
  cui-jwt-integration-tests:
    ports:
      # Map external port 10443 to internal port 8443
      - "10443:8443"
```

### Running with Docker

```bash
# Use the convenience script:
./scripts/start-integration-test.sh

# Or manually (from project root):
../../mvnw clean package -Pnative -pl cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests -am
cd cui-jwt-quarkus-parent/cui-jwt-quarkus-integration-tests
docker compose up --build
```

## Test Structure

### Base Classes

- `BaseIntegrationTest`: Base class that configures REST Assured with external port
- All test classes extend this base to ensure consistent configuration

### Test Categories

1. **HealthCheckIntegrationTest**: Health check endpoints
2. **MetricsIntegrationTest**: Prometheus metrics
3. **NativeIntegrationTest**: Basic native functionality
4. **HttpsJwtValidationTest**: JWT validation over HTTPS

## Certificate Management

Self-signed certificates are automatically generated during the build:

- **keystore.p12**: Private key and certificate
- **truststore.p12**: Trust store for validation
- **localhost.crt**: Certificate in PEM format

Password: `integration-test`

## Key Benefits of External Port Configuration

1. ✅ **Tests from Outside Perspective**: Tests validate the complete system as external clients would access it
2. ✅ **Conflict Avoidance**: Non-standard external port avoids conflicts with running services
3. ✅ **Docker Port Mapping**: Infrastructure handles port mapping, not application code
4. ✅ **Configurable**: External port can be changed via Maven properties without code changes
5. ✅ **Environment Independence**: Different environments can use different external ports

## Usage Examples

### Testing Endpoints

```bash
# Health check (overall)
curl -k https://localhost:10443/q/health

# Liveness check (recommended for health monitoring)
curl -k https://localhost:10443/q/health/live

# JWT validation status
curl -k https://localhost:10443/jwt/validator/status

# Metrics
curl -k https://localhost:10443/q/metrics
```

### Docker Testing

```bash
# Setup environment
./scripts/setup-environment.sh

# Start Docker containers with native image
./scripts/start-integration-test.sh

# Stop Docker containers
./scripts/stop-integration-test.sh

# Run complete integration tests
./scripts/run-integration-tests.sh
```

This configuration ensures that integration tests always validate the complete system from the external perspective while maintaining flexibility for different deployment scenarios.