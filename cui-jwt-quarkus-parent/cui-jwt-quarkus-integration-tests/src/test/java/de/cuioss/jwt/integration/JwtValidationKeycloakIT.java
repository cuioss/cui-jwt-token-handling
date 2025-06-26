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
import io.restassured.response.Response;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for JWT validation with real Keycloak tokens.
 * This test validates the complete integration between the application,
 * Keycloak authentication, and JWT token validation.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtValidationKeycloakIT extends BaseIntegrationTest {

    private static final String KEYCLOAK_BASE_URL = "http://localhost:10080";

    private String validJwtToken;


    @Test
    @Order(1)
    void httpsConfigurationAndEndpointAvailability() {
        // Test HTTPS configuration and JWT validation endpoint availability
        // This verifies: HTTPS setup, SSL certificates, and basic endpoint functionality
        given()
                .when()
                .get("/jwt/health")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("JWT validation endpoint is healthy"));

        // Test JWT validation endpoint returns proper error for missing token (proves HTTPS works)
        given()
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(400);

        // Test multiple concurrent HTTPS requests
        for (int i = 0; i < 3; i++) {
            int statusCode = given()
                    .when()
                    .post("/jwt/validate")
                    .then()
                    .extract()
                    .statusCode();

            assertEquals(400, statusCode, "JWT endpoint should return 400 for missing token, got: " + statusCode);
        }
    }

    @Test
    @Order(2)
    void keycloakAvailability() {
        // Verify Keycloak is running and accessible
        Response response = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .when()
                .get("/health/ready");

        assertEquals(200, response.statusCode(), "Keycloak should be available");
    }



    @Test
    @Order(3)
    void obtainValidTokenFromKeycloak() {
        // Get a real JWT token from Keycloak
        Response tokenResponse = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", "benchmark-client")
                .formParam("client_secret", "benchmark-secret")
                .formParam("username", "benchmark-user")
                .formParam("password", "benchmark-password")
                .formParam("grant_type", "password")
                .when()
                .post("/realms/benchmark/protocol/openid-connect/token");

        assertEquals(200, tokenResponse.statusCode(),
                "Should be able to obtain token from Keycloak. Response: " + tokenResponse.body().asString());

        Map<String, Object> tokenData = tokenResponse.jsonPath().getMap("");
        validJwtToken = (String) tokenData.get("access_token");

        assertNotNull(validJwtToken, "Access token should not be null");
        assertFalse(validJwtToken.isEmpty(), "Access token should not be empty");
        assertTrue(validJwtToken.contains("."), "Token should be in JWT format with dots");
    }

    @Test
    @Order(4)
    void validateRealKeycloakToken() {
        // First get a token if we don't have one
        if (validJwtToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test JWT validation with real Keycloak token against the configured Keycloak issuer
        given()
                .contentType("application/json")
                .header("Authorization", "Bearer " + validJwtToken)
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Token is valid"));
    }

    @Test
    @Order(5)
    void validateKeycloakTokenWithJwksEndpoint() {
        // First get a token if we don't have one
        if (validJwtToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Verify that the application can fetch JWKS from Keycloak
        // This test ensures the keycloak issuer configuration with JWKS works correctly
        Response jwksResponse = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .when()
                .get("/realms/benchmark/protocol/openid-connect/certs");

        assertEquals(200, jwksResponse.statusCode(), "JWKS endpoint should be accessible");

        // Test JWT validation - this should work via JWKS resolution
        given()
                .header("Authorization", "Bearer " + validJwtToken)
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Token is valid"));
    }

    @Test
    @Order(6)
    void validateRealKeycloakTokenMultipleTimes() {
        // First get a token if we don't have one
        if (validJwtToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test JWT validation multiple times to ensure consistency
        for (int i = 0; i < 3; i++) {
            given()
                        .contentType("application/json")
                    .header("Authorization", "Bearer " + validJwtToken)
                    .when()
                    .post("/jwt/validate")
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true))
                    .body("message", equalTo("Token is valid"));
        }
    }

    @Test
    @Order(7)
    void invalidTokenValidation() {
        // Test with invalid token
        given()
                .contentType("application/json")
                .header("Authorization", "Bearer invalid.token.here")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("message", containsString("Token validation failed"));
    }

    @Test
    @Order(8)
    void missingAuthorizationHeader() {
        // Test without Authorization header
        given()
                .contentType("application/json")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false))
                .body("message", containsString("Missing or invalid Authorization header"));
    }

    @Test
    @Order(9)
    void malformedAuthorizationHeader() {
        // Test with malformed Authorization header
        given()
                .contentType("application/json")
                .header("Authorization", "NotBearer token")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false))
                .body("message", containsString("Missing or invalid Authorization header"));
    }

}