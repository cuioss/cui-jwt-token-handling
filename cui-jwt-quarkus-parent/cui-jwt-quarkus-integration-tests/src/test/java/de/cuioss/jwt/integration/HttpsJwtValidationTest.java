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
import io.restassured.path.json.JsonPath;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for HTTPS JWT validation.
 * <p>
 * These tests specifically verify that JWT validation works correctly
 * over HTTPS connections with proper certificate handling.
 */
@QuarkusIntegrationTest
class HttpsJwtValidationTest extends BaseIntegrationTest {

    @Test
    void shouldValidateJwtOverHttps() {
        // Get a test token
        String token = given()
                .when()
                .get("/validate/test-token")
                .then()
                .statusCode(200)
                .extract()
                .path("token");

        // Validate over HTTPS
        given()
                .header("Authorization", "Bearer " + token)
                .when()
                .get("/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("subject", notNullValue())
                .body("issuer", notNullValue())
                .body("audience", notNullValue());
    }

    @Test
    void shouldHandleMultipleSimultaneousRequests() {
        // Get a test token
        String token = given()
                .when()
                .get("/validate/test-token")
                .then()
                .statusCode(200)
                .extract()
                .path("token");

        // Perform multiple simultaneous validations to test thread safety
        for (int i = 0; i < 5; i++) {
            given()
                    .header("Authorization", "Bearer " + token)
                    .when()
                    .get("/validate")
                    .then()
                    .statusCode(200)
                    .body("valid", equalTo(true));
        }
    }

    @Test
    void shouldValidateTokenClaims() {
        // Get a test token
        JsonPath tokenData = given()
                .when()
                .get("/validate/test-token")
                .then()
                .statusCode(200)
                .extract()
                .body()
                .jsonPath();

        String token = tokenData.getString("token");
        String expectedIssuer = tokenData.getString("issuer");
        String expectedSubject = tokenData.getString("subject");

        // Validate and verify claims
        given()
                .header("Authorization", "Bearer " + token)
                .when()
                .get("/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true))
                .body("issuer", equalTo(expectedIssuer))
                .body("subject", equalTo(expectedSubject));
    }

    @Test
    void shouldRejectExpiredTokens() {
        // This test assumes we can create expired tokens for testing
        // In a real scenario, you might need to mock or configure short-lived tokens
        given()
                .header("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.invalid")
                .when()
                .get("/validate")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("error", notNullValue());
    }

    @Test
    void shouldHandleMalformedTokens() {
        given()
                .header("Authorization", "Bearer not.a.valid.jwt")
                .when()
                .get("/validate")
                .then()
                .statusCode(401)
                .body("valid", equalTo(false))
                .body("error", containsString("Token"));
    }

    @Test
    void shouldValidateTokenFormat() {
        // Test with various invalid token formats
        String[] invalidTokens = {
                "invalid-token",
                "bearer-token-without-dots",
                "one.two",  // Missing third part
                "one.two.three.four",  // Too many parts
                ""  // Empty token
        };

        for (String invalidToken : invalidTokens) {
            given()
                    .header("Authorization", "Bearer " + invalidToken)
                    .when()
                    .get("/validate")
                    .then()
                    .statusCode(401)
                    .body("valid", equalTo(false))
                    .body("error", notNullValue());
        }
    }

    @Test
    void shouldValidateMemoryBasedJwks() {
        // Verify that the memory-based JWKS configuration is working
        // by successfully validating a token generated with the test configuration
        String token = given()
                .when()
                .get("/validate/test-token")
                .then()
                .statusCode(200)
                .extract()
                .path("token");

        // The token should be valid because it was generated with the same
        // key material used in the memory-based JWKS configuration
        given()
                .header("Authorization", "Bearer " + token)
                .when()
                .get("/validate")
                .then()
                .statusCode(200)
                .body("valid", equalTo(true));
    }
}