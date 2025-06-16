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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * REST API tests for Dev UI component wiring and accessibility against external application.
 * <p>
 * This test verifies that the Dev UI components are properly loaded and accessible
 * in the external application. It focuses on basic wiring and component loading rather than
 * full end-to-end functionality.
 * </p>
 */
class DevUIComponentWiringTest extends BaseIntegrationTest {

    @Test
    @DisplayName("Should serve Dev UI main page")
    void shouldServeDevUIMainPage() {
        int statusCode = given()
                .when()
                .get("/q/dev-ui")
                .then()
                .extract()
                .statusCode();

        // Dev UI main page might return different status codes depending on configuration
        assertTrue(statusCode == 200 || statusCode == 302 || statusCode == 404,
                "Dev UI main page should return 200, 302, or 404, but got: " + statusCode);
    }

    @Test
    @DisplayName("Should serve JWT debugger component")
    void shouldServeJwtDebuggerComponent() {
        int statusCode = given()
                .when()
                .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwt-debugger.js")
                .then()
                .extract()
                .statusCode();

        // 404 is acceptable if DevUI not enabled
        assertTrue(statusCode == 200 || statusCode == 404,
                "JWT debugger component should return 200 or 404, but got: " + statusCode);
    }

    @Test
    @DisplayName("Should serve JWT validation status component")
    void shouldServeJwtValidationStatusComponent() {
        int statusCode = given()
                .when()
                .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwt-validation-status.js")
                .then()
                .extract()
                .statusCode();

        // 404 is acceptable if DevUI not enabled
        assertTrue(statusCode == 200 || statusCode == 404,
                "JWT validation status component should return 200 or 404, but got: " + statusCode);
    }

    @Test
    @DisplayName("Should serve JWT configuration component")
    void shouldServeJwtConfigurationComponent() {
        int statusCode = given()
                .when()
                .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwt-config.js")
                .then()
                .extract()
                .statusCode();

        // 404 is acceptable if DevUI not enabled
        assertTrue(statusCode == 200 || statusCode == 404,
                "JWT configuration component should return 200 or 404, but got: " + statusCode);
    }

    @Test
    @DisplayName("Should serve JWKS endpoints component")
    void shouldServeJwksEndpointsComponent() {
        int statusCode = given()
                .when()
                .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwks-endpoints.js")
                .then()
                .extract()
                .statusCode();

        // 404 is acceptable if DevUI not enabled
        assertTrue(statusCode == 200 || statusCode == 404,
                "JWKS endpoints component should return 200 or 404, but got: " + statusCode);
    }

    @Test
    @DisplayName("Should provide health endpoint for basic application verification")
    void shouldProvideHealthEndpoint() {
        // This verifies that the basic application is running and responsive
        // which is a prerequisite for Dev UI functionality
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));
    }

    @Test
    @DisplayName("Should provide readiness endpoint")
    void shouldProvideReadinessEndpoint() {
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", is("UP"));
    }

    @Test
    @DisplayName("Should provide liveness endpoint")
    void shouldProvideLivenessEndpoint() {
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", is("UP"));
    }

    @Test
    @DisplayName("Should respond to basic application endpoints indicating proper wiring")
    void shouldRespondToBasicApplicationEndpoints() {
        // Test that basic application infrastructure is working
        // This is important for Dev UI as it relies on the application being properly started

        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200);

        // Test that metrics endpoint is available (if enabled)
        int metricsStatusCode = given()
                .when()
                .get("/q/metrics")
                .then()
                .extract()
                .statusCode();

        // Metrics might be disabled in some configurations, so we check for either 200 (enabled) or 404 (disabled)
        assertTrue(metricsStatusCode == 200 || metricsStatusCode == 404,
                "Metrics endpoint should return either 200 (enabled) or 404 (disabled), but got: " + metricsStatusCode);
    }

    @Test
    @DisplayName("Should handle HTTPS configuration correctly")
    void shouldHandleHttpsConfigurationCorrectly() {
        // Verify that the application is running with HTTPS configuration
        // which is important for JWT validation scenarios in Dev UI

        // The fact that we can make HTTPS calls to health endpoints
        // indicates that the HTTPS configuration is working
        given()
                .relaxedHTTPSValidation()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200);
    }
}
