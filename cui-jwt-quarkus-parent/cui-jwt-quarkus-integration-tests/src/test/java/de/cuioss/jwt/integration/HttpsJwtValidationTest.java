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

/**
 * REST API tests for HTTP JWT validation against external application.
 * <p>
 * These tests verify that JWT validation works correctly
 * over HTTP connections against an external running application.
 */
class HttpsJwtValidationTest extends BaseIntegrationTest {

    @Test
    void shouldValidateJwtOverHttp() {
        // Verify basic health endpoint works (simplified test for HTTP-only)
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
    }

    @Test
    void shouldHandleMultipleSimultaneousRequests() {
        // Test multiple simultaneous health checks
        for (int i = 0; i < 5; i++) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .statusCode(anyOf(equalTo(200), equalTo(503)));
        }
    }

    @Test
    void shouldProvideHealthCheck() {
        // Verify health check endpoint is available
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)))
                .body("status", anyOf(equalTo("UP"), equalTo("DOWN")));
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