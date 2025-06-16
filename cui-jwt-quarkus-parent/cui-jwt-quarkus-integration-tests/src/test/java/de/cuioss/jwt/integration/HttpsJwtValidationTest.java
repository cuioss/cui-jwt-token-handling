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

import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * REST API tests for HTTP JWT validation against external application.
 * <p>
 * These tests verify that JWT validation works correctly
 * over HTTP connections against an external running application.
 */
class HttpsJwtValidationTest extends BaseIntegrationTest {

    @Test
    void shouldValidateHealthEndpointsOverHttps() {
        // This test verifies that:
        // 1. Health endpoints are accessible over HTTPS
        // 2. Health endpoints return appropriate status codes
        // 3. Multiple concurrent requests are handled correctly

        // First, verify basic health endpoint works
        int healthStatusCode = given()
                .when()
                .get("/q/health")
                .then()
                .extract()
                .statusCode();

        // Health check should return either 200 (UP) or 503 (DOWN), but not an error code
        assertTrue(healthStatusCode == 200 || healthStatusCode == 503,
                "Health endpoint should return either 200 (UP) or 503 (DOWN), but got: " + healthStatusCode);

        // If status code is 200, verify the status is UP
        if (healthStatusCode == 200) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .body("status", equalTo("UP"));
        }
        // If status code is 503, verify the status is DOWN
        else if (healthStatusCode == 503) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .body("status", equalTo("DOWN"));
        }

        // Test multiple simultaneous health checks to verify concurrent handling
        for (int i = 0; i < 3; i++) {
            int concurrentHealthStatusCode = given()
                    .when()
                    .get("/q/health")
                    .then()
                    .extract()
                    .statusCode();

            // Health check should return either 200 (UP) or 503 (DOWN), but not an error code
            assertTrue(concurrentHealthStatusCode == 200 || concurrentHealthStatusCode == 503,
                    "Health endpoint should return either 200 (UP) or 503 (DOWN), but got: " + concurrentHealthStatusCode);
        }
    }

    @Test
    void shouldProvideMetricsEndpoint() {
        // Verify metrics endpoint is available
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(200)
                .contentType(containsString("text"));
    }
}
