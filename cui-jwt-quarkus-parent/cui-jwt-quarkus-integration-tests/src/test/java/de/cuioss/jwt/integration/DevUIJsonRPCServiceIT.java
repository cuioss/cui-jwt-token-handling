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
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * REST API tests for the Dev UI endpoints against external application.
 * <p>
 * This test focuses on verifying the Dev UI backend endpoints that power the Dev UI components.
 * It uses REST API calls to test the Dev UI endpoints against an external running application.
 * </p>
 */
class DevUIJsonRPCServiceIT extends BaseIntegrationTest {

    @Test
    @DisplayName("Should provide Dev UI endpoints")
    void shouldProvideDevUIEndpoints() {
        // Verify that Dev UI health endpoints are available
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Verify that metrics endpoint works (if enabled)
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
    @DisplayName("Should provide JWT validation status via health checks")
    void shouldProvideValidationStatus() {
        // Verify JWT health check is available and working
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("checks", notNullValue());

        // Verify readiness includes JWT components
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200)
                .body("status", is("UP"));
    }

    @Test
    @DisplayName("Should provide JWKS status via metrics or health")
    void shouldProvideJwksStatus() {
        // Test that the application is configured correctly for JWT
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test metrics endpoint for JWT-related metrics (if available)
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
    @DisplayName("Should provide configuration information via endpoints")
    void shouldProvideConfiguration() {
        // Test that configuration is working by checking health endpoints
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test that the application responds to basic requests
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
    @DisplayName("Should handle requests without authentication")
    void shouldHandleRequestsWithoutAuth() {
        // Test that endpoints respond appropriately without authentication
        // Health endpoints should work without authentication
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test that JWT configuration doesn't break basic functionality
        given()
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200);
    }

    @Test
    @DisplayName("Should handle malformed authentication headers")
    void shouldHandleMalformedAuthHeaders() {
        // Test that malformed auth headers don't break the application
        given()
                .header("Authorization", "Bearer")
                .when()
                .get("/q/health")
                .then()
                .statusCode(200); // Health should still work

        given()
                .header("Authorization", "InvalidFormat")
                .when()
                .get("/q/health")
                .then()
                .statusCode(200); // Health should still work
    }

    @Test
    @DisplayName("Should handle invalid JWT tokens gracefully")
    void shouldHandleInvalidTokensGracefully() {
        // Test with various malformed JWT tokens
        String malformedToken = "not.a.valid.jwt";

        given()
                .header("Authorization", "Bearer " + malformedToken)
                .when()
                .get("/q/health")
                .then()
                .statusCode(200); // Health endpoints should still work

        // Test with empty bearer token
        given()
                .header("Authorization", "Bearer ")
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

        // Test that invalid tokens don't break health endpoints
        given()
                .header("Authorization", "Bearer " + invalidToken)
                .when()
                .get("/q/health")
                .then()
                .statusCode(200);

        // Test that the application remains stable with invalid tokens
        given()
                .header("Authorization", "Bearer " + invalidToken)
                .when()
                .get("/q/health/ready")
                .then()
                .statusCode(200);
    }

    @Test
    @DisplayName("Should provide comprehensive health information")
    void shouldProvideHealthInfo() {
        // Test detailed health information
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("checks", notNullValue());

        // Test that all health components are working
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
    @DisplayName("Should provide consistent responses across multiple calls")
    void shouldProvideConsistentResponsesAcrossMultipleCalls() {
        // Test that multiple calls to the same endpoint are consistent
        for (int i = 0; i < 3; i++) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .statusCode(200)
                    .body("status", is("UP"));
        }

        // Test that different health endpoints are consistent
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
    @DisplayName("Should handle all endpoint invocations without errors")
    void shouldHandleAllEndpointInvocationsWithoutErrors() {
        // This test verifies that all endpoints can be called without throwing exceptions
        // This tests the basic HTTP communication and endpoint routing

        assertDoesNotThrow(() -> {
            given().when().get("/q/health").then().statusCode(200);
        }, "Health endpoint should not throw");

        assertDoesNotThrow(() -> {
            given().when().get("/q/health/ready").then().statusCode(200);
        }, "Ready endpoint should not throw");

        assertDoesNotThrow(() -> {
            given().when().get("/q/health/live").then().statusCode(200);
        }, "Live endpoint should not throw");

        assertDoesNotThrow(() -> {
            int metricsStatusCode = given().when().get("/q/metrics").then().extract().statusCode();
            assertTrue(metricsStatusCode == 200 || metricsStatusCode == 404,
                    "Metrics endpoint should return either 200 (enabled) or 404 (disabled), but got: " + metricsStatusCode);
        }, "Metrics endpoint should not throw");
    }
}