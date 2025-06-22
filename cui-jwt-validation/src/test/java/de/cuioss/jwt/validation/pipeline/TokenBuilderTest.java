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
package de.cuioss.jwt.validation.pipeline;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenBuilder}.
 */
@EnableGeneratorController
@DisplayName("Tests TokenBuilder functionality")
class TokenBuilderTest {

    private TokenBuilder tokenBuilder;

    @BeforeEach
    void setUp() {
        // Create a simple IssuerConfig for testing
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("https://test-issuer.com")
                .build();

        tokenBuilder = new TokenBuilder(issuerConfig);
    }
    @Nested
    @DisplayName("AccessToken Tests")
    class AccessTokenTests {

        @Test
        @DisplayName("createAccessToken should create AccessTokenContent from DecodedJwt")
        void createAccessTokenShouldCreateAccessTokenContent() {
            // Given a DecodedJwt with ACCESS_TOKEN type
            DecodedJwt decodedJwt = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build()).asDecodedJwt();

            // When creating an AccessTokenContent
            Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(decodedJwt);
            assertTrue(result.isPresent(), "Should return AccessTokenContent");
            AccessTokenContent accessTokenContent = result.get();

            // Verify validation type
            assertEquals(TokenType.ACCESS_TOKEN, accessTokenContent.getTokenType(), "Token type should be ACCESS_TOKEN");

            // Verify raw token
            assertEquals(decodedJwt.getRawToken(), accessTokenContent.getRawToken(), "Raw validation should match");

            // Verify claims are extracted
            assertFalse(accessTokenContent.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(accessTokenContent.getClaims().containsKey(ClaimName.SUBJECT.getName()),
                    "Claims should contain subject");
            assertTrue(accessTokenContent.getClaims().containsKey(ClaimName.ISSUER.getName()),
                    "Claims should contain issuer");
        }

        @Test
        @DisplayName("createAccessToken should handle DecodedJwt with missing body")
        void createAccessTokenShouldHandleDecodedJwtWithMissingBody() {
            // Given a DecodedJwt with null body
            DecodedJwt decodedJwt = new DecodedJwt(null, null, null, new String[]{"", "", ""}, "test-validation");

            // When creating an AccessTokenContent
            Optional<AccessTokenContent> result = tokenBuilder.createAccessToken(decodedJwt);
            assertTrue(result.isEmpty(), "Should return empty Optional when body is missing");
        }
    }

    @Nested
    @DisplayName("IdToken Tests")
    class IdTokenTests {

        @Test
        @DisplayName("createIdToken should create IdTokenContent from DecodedJwt")
        void createIdTokenShouldCreateIdTokenContent() {
            // Given a DecodedJwt with ID_TOKEN type
            DecodedJwt decodedJwt = new TestTokenHolder(TokenType.ID_TOKEN, ClaimControlParameter.builder().build()).asDecodedJwt();

            // When creating an IdTokenContent
            Optional<IdTokenContent> result = tokenBuilder.createIdToken(decodedJwt);
            assertTrue(result.isPresent(), "Should return IdTokenContent");
            IdTokenContent idTokenContent = result.get();

            // Verify validation type
            assertEquals(TokenType.ID_TOKEN, idTokenContent.getTokenType(), "Token type should be ID_TOKEN");

            // Verify raw token
            assertEquals(decodedJwt.getRawToken(), idTokenContent.getRawToken(), "Raw validation should match");

            // Verify claims are extracted
            assertFalse(idTokenContent.getClaims().isEmpty(), "Claims should not be empty");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.SUBJECT.getName()),
                    "Claims should contain subject");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.ISSUER.getName()),
                    "Claims should contain issuer");
            assertTrue(idTokenContent.getClaims().containsKey(ClaimName.AUDIENCE.getName()),
                    "Claims should contain audience");
        }

        @Test
        @DisplayName("createIdToken should handle DecodedJwt with missing body")
        void createIdTokenShouldHandleDecodedJwtWithMissingBody() {
            // Given a DecodedJwt with null body
            DecodedJwt decodedJwt = new DecodedJwt(null, null, null, new String[]{"", "", ""}, "test-validation");

            // When creating an IdTokenContent
            Optional<IdTokenContent> result = tokenBuilder.createIdToken(decodedJwt);
            assertTrue(result.isEmpty(), "Should return empty Optional when body is missing");
        }
    }

    @Nested
    @DisplayName("RefreshToken Claims Tests")
    class RefreshTokenClaimsTests {

        @Test
        @DisplayName("extractClaimsForRefreshToken should extract claims from JsonObject")
        void extractClaimsForRefreshTokenShouldExtractClaims() {
            // Given a JsonObject with claims
            JsonObjectBuilder builder = Json.createObjectBuilder();
            builder.add("sub", "test-subject");
            builder.add("iss", "test-issuer");
            builder.add("custom-claim", "custom-value");
            JsonObject jsonObject = builder.build();

            // When extracting claims
            Map<String, ClaimValue> claims = TokenBuilder.extractClaimsForRefreshToken(jsonObject);
            assertNotNull(claims, "Claims should not be null");
            assertFalse(claims.isEmpty(), "Claims should not be empty");
            assertEquals(3, claims.size(), "Should extract all claims");

            // Verify standard claims
            assertTrue(claims.containsKey("sub"), "Claims should contain subject");
            assertEquals("test-subject", claims.get("sub").getOriginalString(), "Subject claim value should match");

            assertTrue(claims.containsKey("iss"), "Claims should contain issuer");
            assertEquals("test-issuer", claims.get("iss").getOriginalString(), "Issuer claim value should match");

            // Verify custom claim
            assertTrue(claims.containsKey("custom-claim"), "Claims should contain custom claim");
            assertEquals("custom-value", claims.get("custom-claim").getOriginalString(), "Custom claim value should match");
        }

        @Test
        @DisplayName("extractClaimsForRefreshToken should handle empty JsonObject")
        void extractClaimsForRefreshTokenShouldHandleEmptyJsonObject() {
            // Given an empty JsonObject
            JsonObject jsonObject = Json.createObjectBuilder().build();

            // When extracting claims
            Map<String, ClaimValue> claims = TokenBuilder.extractClaimsForRefreshToken(jsonObject);
            assertNotNull(claims, "Claims should not be null");
            assertTrue(claims.isEmpty(), "Claims should be empty");
        }
    }
}
