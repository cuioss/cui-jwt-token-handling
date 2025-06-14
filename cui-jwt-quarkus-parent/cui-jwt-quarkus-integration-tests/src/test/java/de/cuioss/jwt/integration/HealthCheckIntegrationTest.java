/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.integration;

import io.quarkus.test.junit.QuarkusIntegrationTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for health check endpoints.
 * <p>
 * These tests verify that health checks work correctly in the
 * native container environment with proper JWT extension integration.
 */
@QuarkusIntegrationTest
class HealthCheckIntegrationTest extends BaseIntegrationTest {

    @Test
    void shouldProvideOverallHealthStatus() {
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .contentType("application/json")
                .body("status", equalTo("UP"))
                .body("checks", notNullValue())
                .body("checks.size()", greaterThan(0));
    }

    @Test
    void shouldIncludeJwtValidatorHealthCheck() {
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("checks.find { it.name == 'jwt-validator' }.status", equalTo("UP"));
    }

    @Test
    void shouldIncludeJwksEndpointHealthCheck() {
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("checks.find { it.name == 'jwks-endpoints' }.status", equalTo("UP"));
    }

    @Test
    void shouldProvideReadinessCheck() {
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void shouldProvideLivenessCheck() {
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void shouldProvideStartupCheck() {
        given()
                .when()
                .get("/q/health/started")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void shouldIncludeIssuerInformation() {
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("checks.find { it.name == 'jwks-endpoints' }.data", notNullValue())
                .body("checks.find { it.name == 'jwks-endpoints' }.data.issuerCount", greaterThanOrEqualTo(1));
    }

    @Test
    void shouldHandleHealthCheckErrors() {
        // Test that health checks are resilient and don't cause application failure
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503))); // UP or DOWN, but not error
    }
}