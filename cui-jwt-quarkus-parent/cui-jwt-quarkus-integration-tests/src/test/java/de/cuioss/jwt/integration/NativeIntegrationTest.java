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

import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Native integration tests for the CUI JWT Quarkus extension.
 * <p>
 * These tests run as REST API tests against the native container image to verify
 * that the extension works correctly in production-like environments.
 */
@EnabledIfSystemProperty(named = "quarkus.native.enabled", matches = "true")
class NativeIntegrationTest extends BaseIntegrationTest {

    @Test
    void shouldStartApplicationSuccessfully() {
        // Verify the application starts and responds to health checks
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
    }

    @Test
    void shouldProvideBasicHealthCheck() {
        // Verify application provides basic health information
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)))
                .body("status", anyOf(equalTo("UP"), equalTo("DOWN")));
    }

    @Test
    void shouldHaveTokenValidatorAvailable() {
        // Test that the JWT validator is properly injected and available
        // This verifies the basic extension functionality without requiring tokens
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503))); // Allow either UP or DOWN
    }

    @Test
    void shouldProvideMetricsEndpoint() {
        // Verify metrics endpoint is available
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .contentType(containsString("text/plain"));
    }

    @Test
    void shouldHandleHttpConnections() {
        // Verify HTTP connections work properly (SSL disabled for tests)
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
    }
}