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
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for metrics endpoints.
 * <p>
 * These tests verify that Prometheus metrics are properly exposed
 * and include JWT validation metrics in the native container environment.
 */
@QuarkusIntegrationTest
class MetricsIntegrationTest extends BaseIntegrationTest {

    @Test
    void shouldExposeMetricsEndpoint() {
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .contentType("text/plain; version=0.0.4; charset=utf-8");
    }

    @Test
    void shouldIncludeJwtValidationMetrics() {
        String metricsResponse = given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .asString();

        // Verify JWT-specific metrics are present
        assertTrue(
                metricsResponse.contains("cui_jwt_validation_errors_total"),
                "Should include JWT validation error metrics"
        );

        assertTrue(
                metricsResponse.contains("cui_jwt_validation_success_total"),
                "Should include JWT validation success metrics"
        );
    }

    @Test
    void shouldIncludeSystemMetrics() {
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .body(containsString("jvm_memory_used_bytes"))
                .body(containsString("process_cpu_usage"));
    }

    @Test
    void shouldIncludeHttpMetrics() {
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .body(containsString("http_server_requests_seconds"))
                .body(containsString("http_server_active_requests"));
    }

    @Test
    void shouldUpdateMetricsAfterValidation() {
        // First, get current metrics
        String initialMetrics = given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .asString();

        // Perform some JWT validations to generate metrics
        String token = given()
                .when()
                .get("/validate/test-token")
                .then()
                .statusCode(200)
                .extract()
                .path("token");

        // Valid token validation
        given()
                .header("Authorization", "Bearer " + token)
                .when()
                .get("/validate")
                .then()
                .statusCode(200);

        // Invalid token validation
        given()
                .header("Authorization", "Bearer invalid.jwt.token")
                .when()
                .get("/validate")
                .then()
                .statusCode(401);

        // Wait a moment for metrics to update
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // Get updated metrics
        String updatedMetrics = given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .asString();

        // Verify metrics have been updated (should have counters > 0)
        assertTrue(
                updatedMetrics.contains("cui_jwt_validation_errors_total"),
                "Should contain error metrics after invalid validation"
        );

        assertTrue(
                updatedMetrics.contains("cui_jwt_validation_success_total"),
                "Should contain success metrics after valid validation"
        );
    }

    @Test
    void shouldProvideMetricsInPrometheusFormat() {
        String metricsResponse = given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .asString();

        // Verify Prometheus format
        assertTrue(
                metricsResponse.contains("# HELP"),
                "Should include Prometheus HELP comments"
        );

        assertTrue(
                metricsResponse.contains("# TYPE"),
                "Should include Prometheus TYPE comments"
        );
    }
}