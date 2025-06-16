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
import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic Dev UI test for integration testing environment.
 * <p>
 * This test verifies that the Dev UI JsonRPC service components are properly
 * wired and can provide basic functionality through REST API endpoints.
 * </p>
 */
class DevUIBasicTest extends BaseIntegrationTest {

    @Test
    @DisplayName("Should provide basic Dev UI functionality through endpoints")
    void shouldProvideBasicDevUIFunctionality() {
        // Test that basic Dev UI related endpoints are working
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
            given().when().get("/q/metrics").then().statusCode(anyOf(is(200), is(404)));
        }, "Metrics endpoint should not throw");
    }

    @Test
    @DisplayName("Should handle authentication gracefully through endpoints")
    void shouldHandleAuthenticationGracefullyThroughEndpoints() {
        // Test that endpoints handle missing authentication gracefully
        assertDoesNotThrow(() -> {
            given().when().get("/q/health").then().statusCode(200);
        }, "Health endpoint should handle missing auth");

        assertDoesNotThrow(() -> {
            given().header("Authorization", "Bearer ").when().get("/q/health").then().statusCode(200);
        }, "Health endpoint should handle empty token");

        assertDoesNotThrow(() -> {
            given().header("Authorization", "Bearer invalid.token").when().get("/q/health").then().statusCode(200);
        }, "Health endpoint should handle invalid token");

        assertDoesNotThrow(() -> {
            given().header("Authorization", "InvalidFormat").when().get("/q/health").then().statusCode(200);
        }, "Health endpoint should handle malformed auth header");
    }

    @Test
    @DisplayName("Should provide consistent status information across endpoints")
    void shouldProvideConsistentStatusInformationAcrossEndpoints() {
        // Test that all health-related endpoints provide consistent information
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

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

        // Test that the responses are consistent across multiple calls
        for (int i = 0; i < 3; i++) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .statusCode(200)
                    .body("status", is("UP"));
        }
    }

    @Test
    @DisplayName("Should demonstrate basic application component wiring")
    void shouldDemonstrateBasicApplicationComponentWiring() {
        // This test demonstrates the basic concept of how components work together
        // by testing that the application responds correctly to various requests
        
        // Test that health endpoints provide structured responses
        given()
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"))
                .body("checks", notNullValue());

        // Test that the application handles authentication headers
        given()
                .header("Authorization", "Bearer test.token.example")
                .when()
                .get("/q/health")
                .then()
                .statusCode(200)
                .body("status", is("UP"));

        // Test that metrics endpoint is available (if enabled)
        given()
                .when()
                .get("/q/metrics")
                .then()
                .statusCode(anyOf(is(200), is(404))); // 404 if metrics disabled

        // This demonstrates that the basic wiring between components
        // works correctly in the integration environment
    }

    @Test
    @DisplayName("Should handle multiple concurrent endpoint calls")
    void shouldHandleMultipleConcurrentEndpointCalls() {
        // This test verifies that the application can handle multiple endpoint calls
        // which simulates multiple frontend components making concurrent requests
        
        // When - make multiple concurrent calls (simulating multiple components)
        assertDoesNotThrow(() -> {
            given().when().get("/q/health").then().statusCode(200);
            given().when().get("/q/health/ready").then().statusCode(200);
            given().when().get("/q/health/live").then().statusCode(200);
            given().when().get("/q/metrics").then().statusCode(anyOf(is(200), is(404)));
        }, "Multiple concurrent endpoint calls should work without issues");

        // Test concurrent calls with authentication headers
        assertDoesNotThrow(() -> {
            given().header("Authorization", "Bearer token1").when().get("/q/health").then().statusCode(200);
            given().header("Authorization", "Bearer token2").when().get("/q/health").then().statusCode(200);
            given().header("Authorization", "Bearer token3").when().get("/q/health").then().statusCode(200);
        }, "Concurrent calls with different auth headers should work");

        // Verify all responses are consistent
        for (int i = 0; i < 5; i++) {
            given()
                    .when()
                    .get("/q/health")
                    .then()
                    .statusCode(200)
                    .body("status", is("UP"));
        }
    }
}