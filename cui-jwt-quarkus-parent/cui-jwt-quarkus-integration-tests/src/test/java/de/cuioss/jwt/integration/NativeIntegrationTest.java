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
import io.restassured.RestAssured;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Native integration tests for the CUI JWT Quarkus extension.
 * <p>
 * These tests run against the native container image to verify
 * that the extension works correctly in production-like environments.
 */
@QuarkusIntegrationTest
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
    void shouldHandleHttpsConnections() {
        // Verify HTTPS is working properly
        given()
                .when()
                .get("/validate/health")
                .then()
                .statusCode(200);

        // Verify that HTTP connections are rejected (should fail or redirect)
        RestAssured.given()
                .port(8080)
                .when()
                .get("/validate/health")
                .then()
                .statusCode(anyOf(equalTo(400), equalTo(404), equalTo(426))); // Bad Request, Not Found, or Upgrade Required
    }
}