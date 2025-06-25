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
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.*;

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
@QuarkusIntegrationTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtValidationKeycloakIT extends BaseIntegrationTest {

    private static final String KEYCLOAK_BASE_URL = "http://localhost:10080";
    private static final String APPLICATION_BASE_URL = "https://localhost:10443";

    private String validJwtToken;

    @BeforeEach
    void setupRestAssured() {
        RestAssured.baseURI = APPLICATION_BASE_URL;
        RestAssured.useRelaxedHTTPSValidation();
    }

    @Test
    @Order(1)
    void keycloakAvailability() {
        // Verify Keycloak is running and accessible
        Response response = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .when()
                .get("/health/ready");

        assertEquals(200, response.statusCode(), "Keycloak should be available");
    }

    @Test
    @Order(2)
    void applicationAvailability() {
        // Verify application is running
        given()
                .when()
                .get("/q/health/live")
                .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }


    @Test
    @Order(3)
    void obtainValidTokenFromKeycloak() {
        // Get a real JWT token from Keycloak
        Response tokenResponse = given()
                .baseUri(KEYCLOAK_BASE_URL)
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", "benchmark-client")
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

        // Test JWT validation with real Keycloak token
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
    @Order(5)
    void validateRealKeycloakTokenMultipleTimes() {
        // First get a token if we don't have one
        if (validJwtToken == null) {
            obtainValidTokenFromKeycloak();
        }

        // Test JWT validation multiple times to ensure consistency
        for (int i = 0; i < 3; i++) {
            given()
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
    @Order(6)
    void invalidTokenValidation() {
        // Test with invalid token
        given()
                .header("Authorization", "Bearer invalid.token.here")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("message", containsString("Token validation failed"));
    }

    @Test
    @Order(7)
    void missingAuthorizationHeader() {
        // Test without Authorization header
        given()
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false))
                .body("message", containsString("Missing or invalid Authorization header"));
    }

    @Test
    @Order(8)
    void malformedAuthorizationHeader() {
        // Test with malformed Authorization header
        given()
                .header("Authorization", "NotBearer token")
                .when()
                .post("/jwt/validate")
                .then()
                .statusCode(400)
                .body("valid", equalTo(false))
                .body("message", containsString("Missing or invalid Authorization header"));
    }

}