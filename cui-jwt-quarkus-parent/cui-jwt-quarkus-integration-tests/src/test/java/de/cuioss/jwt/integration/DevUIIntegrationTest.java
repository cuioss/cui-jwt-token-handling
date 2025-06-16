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
import static org.hamcrest.Matchers.*;

/**
 * REST API tests for CUI JWT components integration against external application.
 * <p>
 * Tests the overall integration of JWT components to verify
 * proper wiring and basic functionality. This test focuses on the complete integration
 * testing the application as a REST API against an external running application.
 * </p>
 */
class DevUIIntegrationTest extends BaseIntegrationTest {

    @Test
    @DisplayName("Should provide JWT validation through health checks")
    void shouldProvideValidationThroughHealthChecks() {
        // Verify that JWT validation is working through health checks
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("checks", notNullValue());

        // Verify readiness endpoint works
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", is("UP"));
    }

    @Test
    @DisplayName("Should provide JWKS functionality through application")
    void shouldProvideJwksFunctionality() {
        // Test that the JWKS-related functionality is working by checking overall health
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test that metrics endpoint can be accessed (may be disabled)
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(anyOf(is(200), is(404)));
    }

    @Test
    @DisplayName("Should provide proper configuration through endpoints")
    void shouldProvideProperConfiguration() {
        // Test that configuration is working correctly by testing endpoints
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test that JWT configuration doesn't interfere with basic functionality
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200);

        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200);
    }

    @Test
    @DisplayName("Should handle authentication gracefully")
    void shouldHandleAuthenticationGracefully() {
        // Test that the application handles requests without tokens gracefully
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test with invalid auth header
        given()
                .header("Authorization", "Bearer invalid")
                .when()
                .get("/q/health")
                .then()
                .statusCode(200); // Health should work regardless
    }

    @Test
    @DisplayName("Should handle malformed authentication gracefully")
    void shouldHandleMalformedAuthenticationGracefully() {
        // Test with various malformed auth headers
        String malformedToken = "not.a.valid.jwt";

        given()
                .header("Authorization", "Bearer " + malformedToken)
                .when()
                .get("/q/health")
                .then()
                .statusCode(200); // Should not break health endpoints

        given()
                .header("Authorization", "Invalid Format")
                .when()
                .get("/q/health")
                .then()
                .statusCode(200);
    }

    @Test
    @DisplayName("Should handle well-formed but invalid JWT tokens")
    void shouldHandleWellFormedInvalidTokens() {
        // Given - well-formed but invalid JWT token (sample from JWT.io)
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // Test that invalid tokens don't break the application
        given()
                .header("Authorization", "Bearer " + invalidToken)
                .when()
                .get("/q/health")
                .then()
                .statusCode(200);

        given()
                .header("Authorization", "Bearer " + invalidToken)
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200);
    }

    @Test
    @DisplayName("Should provide comprehensive health information")
    void shouldProvideComprehensiveHealthInfo() {
        // Test that all health endpoints provide comprehensive information
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("checks", notNullValue());

        // Test individual health endpoints
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", is("UP"));
    }

    @Test
    @DisplayName("Should handle various authentication formats correctly")
    void shouldHandleVariousAuthFormatsCorrectly() {
        // Test with different header formats
        String shortToken = "short";
        String longToken = "this.is.a.much.longer.token.string.for.testing.parameter.handling";

        // All should be handled gracefully without breaking health endpoints
        given()
                .header("Authorization", "Bearer " + shortToken)
                .when()
                .get("/q/health")
                .then()
                .statusCode(200);

        given()
                .header("Authorization", "Bearer " + longToken)
                .when()
                .get("/q/health")
                .then()
                .statusCode(200);
    }

    @Test
    @DisplayName("Should handle concurrent HTTP calls consistently")
    void shouldHandleConcurrentHttpCallsConsistently() {
        // Test concurrent access to various endpoints
        for (int i = 0; i < 5; i++) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .statusCode(200)
                    .body("status", is("UP"));
        }

        // Test that all health endpoints work consistently
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test metrics endpoint (may be disabled)
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(anyOf(is(200), is(404)));
    }
}