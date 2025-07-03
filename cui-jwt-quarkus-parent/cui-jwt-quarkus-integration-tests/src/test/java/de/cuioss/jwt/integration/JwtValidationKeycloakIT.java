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

    private static final String KEYCLOAK_BASE_URL = "http://localhost:1080";
    private static final String KEYCLOAK_MANAGEMENT_URL = "http://localhost:1090";

    private String validAccessToken;
    private String validIdToken;
    private String validRefreshToken;


    @Test
    @Order(1)
    void httpsConfigurationAndEndpointAvailability() {
        // Test HTTPS configuration and JWT validation endpoint availability
        // This verifies: HTTPS setup, SSL certificates, and basic endpoint functionality

        // Test JWT validation endpoint returns proper error for missing token (proves HTTPS works)
        given()
                .contentType("application/json")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(400);

        // Test multiple concurrent HTTPS requests
        for (int i = 0; i < 3; i++) {
            int statusCode = given()
                    .contentType("application/json")
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
        // Verify Keycloak is running and accessible via management port
        Response response = given()
                .baseUri(KEYCLOAK_MANAGEMENT_URL)
                .when()
                .get("/health/ready");

        assertEquals(200, response.statusCode(), "Keycloak should be available");
    }


    @Test
    @Order(3)
    void obtainValidTokenFromKeycloak() {
        // Get real JWT tokens from Keycloak (access, ID, and refresh tokens)
        Response tokenResponse = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", "benchmark-client")
                .formParam("client_secret", "benchmark-secret")
                .formParam("username", "benchmark-user")
                .formParam("password", "benchmark-password")
                .formParam("grant_type", "password")
                .formParam("scope", "openid profile email") // Request ID token
                .when()
                .post("/realms/benchmark/protocol/openid-connect/token");

        assertEquals(200, tokenResponse.statusCode(),
                "Should be able to obtain tokens from Keycloak. Response: " + tokenResponse.body().asString());

        Map<String, Object> tokenData = tokenResponse.jsonPath().getMap("");

        // Extract all token types
        validAccessToken = (String) tokenData.get("access_token");
        validIdToken = (String) tokenData.get("id_token");
        validRefreshToken = (String) tokenData.get("refresh_token");

        // Validate access token
        assertNotNull(validAccessToken, "Access token should not be null");
        assertFalse(validAccessToken.isEmpty(), "Access token should not be empty");
        assertTrue(validAccessToken.contains("."), "Access token should be in JWT format with dots");

        // Validate ID token
        assertNotNull(validIdToken, "ID token should not be null");
        assertFalse(validIdToken.isEmpty(), "ID token should not be empty");
        assertTrue(validIdToken.contains("."), "ID token should be in JWT format with dots");

        // Validate refresh token
        assertNotNull(validRefreshToken, "Refresh token should not be null");
        assertFalse(validRefreshToken.isEmpty(), "Refresh token should not be empty");
        assertTrue(validRefreshToken.contains("."), "Refresh token should be in JWT format with dots");
    }

    @Test
    @Order(4)
    void validateRealKeycloakAccessToken() {
        // First get tokens if we don't have them
        if (validAccessToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test access token validation with real Keycloak token against the configured Keycloak issuer
        given()
                .contentType("application/json")
                .header("Authorization", "Bearer " + validAccessToken)
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Access token is valid"));
    }

    @Test
    @Order(5)
    void validateRealKeycloakIdToken() {
        // First get tokens if we don't have them
        if (validIdToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test ID token validation with real Keycloak ID token
        given()
                .contentType("application/json")
                .body(Map.of("token", validIdToken))
                .when()
                .post("/jwt/validate/id-token")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("ID token is valid"));
    }

    @Test
    @Order(6)
    void validateRealKeycloakRefreshToken() {
        // First get tokens if we don't have them
        if (validRefreshToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test refresh token validation with real Keycloak refresh token
        given()
                .contentType("application/json")
                .body(Map.of("token", validRefreshToken))
                .when()
                .post("/jwt/validate/refresh-token")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Refresh token is valid"));
    }

    @Test
    @Order(7)
    void validateKeycloakTokenWithJwksEndpoint() {
        // First get tokens if we don't have them
        if (validAccessToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Verify that the application can fetch JWKS from Keycloak
        // This test ensures the keycloak issuer configuration with JWKS works correctly
        Response jwksResponse = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .when()
                .get("/realms/benchmark/protocol/openid-connect/certs");

        assertEquals(200, jwksResponse.statusCode(), "JWKS endpoint should be accessible");

        // Test access token validation - this should work via JWKS resolution
        given()
                .contentType("application/json")
                .header("Authorization", "Bearer " + validAccessToken)
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("message", equalTo("Access token is valid"));
    }

    @Test
    @Order(8)
    void validateRealKeycloakTokenMultipleTimes() {
        // First get tokens if we don't have them
        if (validAccessToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test access token validation multiple times to ensure consistency
        for (int i = 0; i < 3; i++) {
            given()
                    .contentType("application/json")
                    .header("Authorization", "Bearer " + validAccessToken)
                    .when()
                    .post("/jwt/validate")
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true))
                    .body("message", equalTo("Access token is valid"));
        }
    }

    @Test
    @Order(9)
    void invalidTokenValidation() {
        // Test with invalid access token
        given()
                .contentType("application/json")
                .header("Authorization", "Bearer invalid.token.here")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("message", containsString("Access token validation failed"));
    }

    @Test
    @Order(10)
    void invalidIdTokenValidation() {
        // Test with invalid ID token
        given()
                .contentType("application/json")
                .body(Map.of("token", "invalid.id.token"))
                .when()
                .post("/jwt/validate/id-token")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("message", containsString("ID token validation failed"));
    }

    @Test
    @Order(11)
    void invalidRefreshTokenValidation() {
        // Test with invalid refresh token
        given()
                .contentType("application/json")
                .body(Map.of("token", "invalid.refresh.token"))
                .when()
                .post("/jwt/validate/refresh-token")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("message", containsString("Refresh token validation failed"));
    }

    @Test
    @Order(12)
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
    @Order(13)
    void missingIdTokenInBody() {
        // Test without token in request body
        given()
                .contentType("application/json")
                .body(Map.of())
                .when()
                .post("/jwt/validate/id-token")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false))
                .body("message", containsString("Missing or empty ID token in request body"));
    }

    @Test
    @Order(14)
    void missingRefreshTokenInBody() {
        // Test without token in request body
        given()
                .contentType("application/json")
                .body(Map.of())
                .when()
                .post("/jwt/validate/refresh-token")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false))
                .body("message", containsString("Missing or empty refresh token in request body"));
    }

    @Test
    @Order(15)
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