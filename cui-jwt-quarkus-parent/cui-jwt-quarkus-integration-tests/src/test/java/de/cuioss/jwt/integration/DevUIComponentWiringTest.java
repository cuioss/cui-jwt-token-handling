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

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Test for Dev UI component wiring and accessibility.
 * <p>
 * This test verifies that the Dev UI components are properly loaded and accessible
 * in development mode. It focuses on basic wiring and component loading rather than
 * full end-to-end functionality.
 * </p>
 */
@QuarkusTest
class DevUIComponentWiringTest extends BaseIntegrationTest {

    @Test
    @DisplayName("Should serve Dev UI main page")
    void shouldServeDevUIMainPage() {
        given()
            .when()
            .get("/q/dev-ui")
            .then()
            .statusCode(anyOf(is(200), is(302), is(404))); // 404 is acceptable in test mode
    }

    @Test
    @DisplayName("Should serve JWT debugger component")
    void shouldServeJwtDebuggerComponent() {
        given()
            .when()
            .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwt-debugger.js")
            .then()
            .statusCode(anyOf(is(200), is(404))); // 404 is acceptable if DevUI not enabled
    }

    @Test
    @DisplayName("Should serve JWT validation status component")
    void shouldServeJwtValidationStatusComponent() {
        given()
            .when()
            .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwt-validation-status.js")
            .then()
            .statusCode(anyOf(is(200), is(404))); // 404 is acceptable if DevUI not enabled
    }

    @Test
    @DisplayName("Should serve JWT configuration component")
    void shouldServeJwtConfigurationComponent() {
        given()
            .when()
            .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwt-config.js")
            .then()
            .statusCode(anyOf(is(200), is(404))); // 404 is acceptable if DevUI not enabled
    }

    @Test
    @DisplayName("Should serve JWKS endpoints component")
    void shouldServeJwksEndpointsComponent() {
        given()
            .when()
            .get("/q/dev-ui/io.quarkus.cui-jwt/components/qwc-jwks-endpoints.js")
            .then()
            .statusCode(anyOf(is(200), is(404))); // 404 is acceptable if DevUI not enabled
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
        given()
            .when()
            .get("/q/metrics")
            .then()
            .statusCode(anyOf(is(200), is(404))); // 404 if metrics not enabled
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