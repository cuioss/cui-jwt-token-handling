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
package de.cuioss.jwt.validation.test;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("TestTokenHolder Tests")
class TestTokenHolderTest {

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create with default parameters")
        void shouldCreateWithDefaultParameters() {
            // Given
            var tokenType = TokenType.ACCESS_TOKEN;
            var claimControl = ClaimControlParameter.builder().build();

            // When
            var tokenHolder = new TestTokenHolder(tokenType, claimControl);

            // Then
            assertEquals(tokenType, tokenHolder.getTokenType());
            assertNotNull(tokenHolder.getClaims());
            assertFalse(tokenHolder.getClaims().isEmpty());
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.ISSUER.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.EXPIRATION.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.ISSUED_AT.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.TOKEN_ID.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.TYPE.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.SCOPE.getName()));
            assertTrue(tokenHolder.getClaims().containsKey("roles"));
        }

        @Test
        @DisplayName("Should create with missing claims")
        void shouldCreateWithMissingClaims() {
            // Given
            var tokenType = TokenType.ACCESS_TOKEN;
            var claimControl = ClaimControlParameter.builder()
                    .missingIssuer(true)
                    .missingSubject(true)
                    .missingExpiration(true)
                    .missingIssuedAt(true)
                    .missingTokenType(true)
                    .missingScope(true)
                    .build();

            // When
            var tokenHolder = new TestTokenHolder(tokenType, claimControl);

            // Then
            assertEquals(tokenType, tokenHolder.getTokenType());
            assertNotNull(tokenHolder.getClaims());
            assertFalse(tokenHolder.getClaims().isEmpty());
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.ISSUER.getName()));
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()));
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.EXPIRATION.getName()));
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.ISSUED_AT.getName()));
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.TOKEN_ID.getName()));
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.TYPE.getName()));
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.SCOPE.getName()));
            assertTrue(tokenHolder.getClaims().containsKey("roles"));
        }
    }

    @Nested
    @DisplayName("Token Generation Tests")
    class TokenGenerationTests {

        @Test
        @DisplayName("Should generate valid JWT token")
        void shouldGenerateValidJwtToken() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // When
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotNull(rawToken);
            assertFalse(rawToken.isEmpty());

            // Verify token structure (header.payload.signature)
            String[] parts = rawToken.split("\\.");
            assertEquals(3, parts.length);

            // Verify token can be parsed by JWT library
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                    .build()
                    .parseSignedClaims(rawToken);

            assertNotNull(jwt);
            assertNotNull(jwt.getPayload());
            assertEquals(tokenHolder.getIssuer(), jwt.getPayload().get(ClaimName.ISSUER.getName()));
            assertEquals("test-subject", jwt.getPayload().get(ClaimName.SUBJECT.getName()));
        }

        @Test
        @DisplayName("Should cache token and regenerate after mutation")
        void shouldCacheTokenAndRegenerateAfterMutation() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // When - get token first time
            var firstToken = tokenHolder.getRawToken();

            // Then - get token second time (should be cached)
            var secondToken = tokenHolder.getRawToken();
            assertEquals(firstToken, secondToken);

            // When - mutate token
            tokenHolder.withClaim("custom-claim", ClaimValue.forPlainString("custom-value"));

            // Then - get token third time (should be regenerated)
            var thirdToken = tokenHolder.getRawToken();
            assertNotEquals(firstToken, thirdToken);
        }
    }

    @Nested
    @DisplayName("Mutator Tests")
    class MutatorTests {

        @Test
        @DisplayName("Should add claim")
        void shouldAddClaim() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var claimName = "custom-claim";
            var claimValue = ClaimValue.forPlainString("custom-value");

            // When
            tokenHolder.withClaim(claimName, claimValue);

            // Then
            assertTrue(tokenHolder.getClaims().containsKey(claimName));
            assertEquals(claimValue, tokenHolder.getClaims().get(claimName));
        }

        @Test
        @DisplayName("Should remove claim")
        void shouldRemoveClaim() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var claimName = ClaimName.SUBJECT.getName();

            // When
            tokenHolder.withoutClaim(claimName);

            // Then
            assertFalse(tokenHolder.getClaims().containsKey(claimName));
        }

        @Test
        @DisplayName("Should replace all claims")
        void shouldReplaceAllClaims() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var newClaims = Map.of(
                    "claim1", ClaimValue.forPlainString("value1"),
                    "claim2", ClaimValue.forPlainString("value2")
            );

            // When
            tokenHolder.withClaims(newClaims);

            // Then
            assertEquals(2, tokenHolder.getClaims().size());
            assertTrue(tokenHolder.getClaims().containsKey("claim1"));
            assertTrue(tokenHolder.getClaims().containsKey("claim2"));
        }

        @Test
        @DisplayName("Should regenerate claims")
        void shouldRegenerateClaims() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // When - modify claims
            tokenHolder.withoutClaim(ClaimName.SUBJECT.getName());
            tokenHolder.withClaim("custom-claim", ClaimValue.forPlainString("custom-value"));

            // Then - verify claims are modified
            assertFalse(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()));
            assertTrue(tokenHolder.getClaims().containsKey("custom-claim"));

            // When - regenerate claims
            tokenHolder.regenerateClaims();

            // Then - verify claims are regenerated
            assertTrue(tokenHolder.getClaims().containsKey(ClaimName.SUBJECT.getName()));
            assertFalse(tokenHolder.getClaims().containsKey("custom-claim"));
        }
    }

    @Nested
    @DisplayName("Token Type Tests")
    class TokenTypeTests {

        @Test
        @DisplayName("Should create ACCESS_TOKEN")
        void shouldCreateAccessToken() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // When
            var claims = tokenHolder.getClaims();

            // Then
            assertEquals(TokenType.ACCESS_TOKEN, tokenHolder.getTokenType());
            assertEquals(TokenType.ACCESS_TOKEN.getTypeClaimName(),
                    claims.get(ClaimName.TYPE.getName()).getOriginalString());
            assertTrue(claims.containsKey(ClaimName.SCOPE.getName()));
            assertTrue(claims.containsKey("roles"));
        }

        @Test
        @DisplayName("Should create ID_TOKEN")
        void shouldCreateIdToken() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ID_TOKEN, ClaimControlParameter.builder().build());

            // When
            var claims = tokenHolder.getClaims();

            // Then
            assertEquals(TokenType.ID_TOKEN, tokenHolder.getTokenType());
            assertEquals(TokenType.ID_TOKEN.getTypeClaimName(),
                    claims.get(ClaimName.TYPE.getName()).getOriginalString());
            assertTrue(claims.containsKey(ClaimName.AUDIENCE.getName()));
            assertTrue(claims.containsKey(ClaimName.EMAIL.getName()));
            assertTrue(claims.containsKey(ClaimName.NAME.getName()));
            assertTrue(claims.containsKey(ClaimName.PREFERRED_USERNAME.getName()));
        }

        @Test
        @DisplayName("Should create REFRESH_TOKEN")
        void shouldCreateRefreshToken() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.REFRESH_TOKEN, ClaimControlParameter.builder().build());

            // When
            var claims = tokenHolder.getClaims();

            // Then
            assertEquals(TokenType.REFRESH_TOKEN, tokenHolder.getTokenType());
            assertEquals(TokenType.REFRESH_TOKEN.getTypeClaimName(),
                    claims.get(ClaimName.TYPE.getName()).getOriginalString());
        }
    }

    @Nested
    @DisplayName("DecodedJwt Conversion Tests")
    class DecodedJwtConversionTests {

        @Test
        @DisplayName("asDecodedJwt should convert TestTokenHolder to DecodedJwt")
        void asDecodedJwtShouldConvertTestTokenHolderToDecodedJwt() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());
            var rawToken = tokenHolder.getRawToken();

            // When
            var decodedJwt = tokenHolder.asDecodedJwt();

            // Then
            assertNotNull(decodedJwt, "DecodedJwt should not be null");

            // Verify raw token
            assertEquals(rawToken, decodedJwt.getRawToken(), "Raw token should match");

            // Verify parts
            String[] parts = rawToken.split("\\.");
            assertArrayEquals(parts, decodedJwt.getParts(), "Token parts should match");

            // Verify header
            assertTrue(decodedJwt.getHeader().isPresent(), "Header should be present");
            assertEquals(tokenHolder.getKeyId(), decodedJwt.getHeader().get().getString("kid"), "Key ID should match");
            assertEquals(tokenHolder.getSigningAlgorithm().name(), decodedJwt.getHeader().get().getString("alg"), "Algorithm should match");

            // Verify body
            assertTrue(decodedJwt.getBody().isPresent(), "Body should be present");
            assertEquals(tokenHolder.getIssuer(), decodedJwt.getBody().get().getString(ClaimName.ISSUER.getName()), "Issuer should match");
            assertEquals("test-subject", decodedJwt.getBody().get().getString(ClaimName.SUBJECT.getName()), "Subject should match");

            // Verify signature
            assertTrue(decodedJwt.getSignature().isPresent(), "Signature should be present");

            // Verify convenience methods
            assertEquals(tokenHolder.getIssuer(), decodedJwt.getIssuer().orElse(null), "Issuer from convenience method should match");
            assertEquals(tokenHolder.getKeyId(), decodedJwt.getKid().orElse(null), "Key ID from convenience method should match");
            assertEquals(tokenHolder.getSigningAlgorithm().name(), decodedJwt.getAlg().orElse(null), "Algorithm from convenience method should match");
        }

        @Test
        @DisplayName("asDecodedJwt should handle custom claims and headers")
        void asDecodedJwtShouldHandleCustomClaimsAndHeaders() {
            // Given
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder().build());

            // Add custom claim
            String customClaimName = "custom-claim";
            String customClaimValue = "custom-value";
            tokenHolder.withClaim(customClaimName, ClaimValue.forPlainString(customClaimValue));

            // Use custom key ID
            String customKeyId = "custom-key-id";
            tokenHolder.withKeyId(customKeyId);

            // When
            var decodedJwt = tokenHolder.asDecodedJwt();

            // Then
            assertNotNull(decodedJwt, "DecodedJwt should not be null");

            // Verify custom claim
            assertTrue(decodedJwt.getBody().isPresent(), "Body should be present");
            assertEquals(customClaimValue, decodedJwt.getBody().get().getString(customClaimName), "Custom claim should match");

            // Verify custom key ID
            assertTrue(decodedJwt.getHeader().isPresent(), "Header should be present");
            assertEquals(customKeyId, decodedJwt.getHeader().get().getString("kid"), "Custom key ID should match");
            assertEquals(customKeyId, decodedJwt.getKid().orElse(null), "Custom key ID from convenience method should match");
        }
    }

    @Nested
    @DisplayName("Header and Audience Tests")
    class HeaderAndAudienceTests {

        @Test
        @DisplayName("Should expose generated key ID")
        void shouldExposeGeneratedKeyId() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

            // When
            var keyId = tokenHolder.getKeyId();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotNull(keyId);
            assertEquals(InMemoryKeyMaterialHandler.DEFAULT_KEY_ID, keyId);
            assertNotNull(rawToken);

            // Parse the token and verify the key ID in the header
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getPublicKey(
                            InMemoryKeyMaterialHandler.Algorithm.RS256, keyId))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(keyId, jwt.getHeader().get("kid"));
        }

        @Test
        @DisplayName("Should expose generated signing algorithm")
        void shouldExposeGeneratedSigningAlgorithm() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

            // When
            var algorithm = tokenHolder.getSigningAlgorithm();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotNull(algorithm);
            assertEquals(InMemoryKeyMaterialHandler.Algorithm.RS256, algorithm);
            assertNotNull(rawToken);

            // Parse the token and verify it was signed with the correct algorithm
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey(algorithm))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(algorithm.name(), jwt.getHeader().getAlgorithm());
        }

        @Test
        @DisplayName("Should allow changing key ID")
        void shouldAllowChangingKeyId() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var originalKeyId = tokenHolder.getKeyId();
            var newKeyId = "custom-key-id";

            // When
            tokenHolder.withKeyId(newKeyId);
            var updatedKeyId = tokenHolder.getKeyId();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotEquals(originalKeyId, updatedKeyId);
            assertEquals(newKeyId, updatedKeyId);

            // Parse the token and verify the key ID in the header
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getPublicKey(
                            InMemoryKeyMaterialHandler.Algorithm.RS256, newKeyId))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(newKeyId, jwt.getHeader().get("kid"));
        }

        @Test
        @DisplayName("Should allow changing signing algorithm")
        void shouldAllowChangingSigningAlgorithm() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var originalAlgorithm = tokenHolder.getSigningAlgorithm();
            var newAlgorithm = InMemoryKeyMaterialHandler.Algorithm.RS384;

            // When
            tokenHolder.withSigningAlgorithm(newAlgorithm);
            var updatedAlgorithm = tokenHolder.getSigningAlgorithm();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotEquals(originalAlgorithm, updatedAlgorithm);
            assertEquals(newAlgorithm, updatedAlgorithm);

            // Parse the token and verify it was signed with the correct algorithm
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getPublicKey(
                            newAlgorithm, tokenHolder.getKeyId()))
                    .build()
                    .parseSignedClaims(rawToken);

            assertEquals(newAlgorithm.name(), jwt.getHeader().getAlgorithm());
        }

        @Test
        @DisplayName("Should provide public key aligned with key ID and algorithm")
        void shouldProvidePublicKeyAlignedWithKeyIdAndAlgorithm() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var customKeyId = "custom-key-id-for-public-key";
            var customAlgorithm = InMemoryKeyMaterialHandler.Algorithm.RS512;

            // When
            tokenHolder.withKeyId(customKeyId).withSigningAlgorithm(customAlgorithm);
            var publicKey = tokenHolder.getPublicKey();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotNull(publicKey);

            // Verify that the public key can be used to verify the token
            var jwt = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(rawToken);

            assertNotNull(jwt);
            assertEquals(customKeyId, jwt.getHeader().get("kid"));
            assertEquals(customAlgorithm.name(), jwt.getHeader().getAlgorithm());
        }

        @Test
        @DisplayName("Should invalidate cached token when header attributes change")
        void shouldInvalidateCachedTokenWhenHeaderAttributesChange() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

            // When - get token first time
            var firstToken = tokenHolder.getRawToken();

            // Then - get token second time (should be cached)
            var secondToken = tokenHolder.getRawToken();
            assertEquals(firstToken, secondToken);

            // When - change key ID
            tokenHolder.withKeyId("new-key-id");

            // Then - get token third time (should be regenerated)
            var thirdToken = tokenHolder.getRawToken();
            assertNotEquals(firstToken, thirdToken);

            // When - get token fourth time (should be cached again)
            var fourthToken = tokenHolder.getRawToken();
            assertEquals(thirdToken, fourthToken);

            // When - change signing algorithm
            tokenHolder.withSigningAlgorithm(InMemoryKeyMaterialHandler.Algorithm.RS384);

            // Then - get token fifth time (should be regenerated)
            var fifthToken = tokenHolder.getRawToken();
            assertNotEquals(thirdToken, fifthToken);
        }

        @Test
        @DisplayName("Should use custom audience")
        void shouldUseCustomAudience() {
            // Given
            List<String> customAudience = List.of("custom-audience-1", "custom-audience-2");
            var claimControl = ClaimControlParameter.builder().build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

            // Set custom audience using the new method
            tokenHolder.withAudience(customAudience);

            // When
            var claims = tokenHolder.getClaims();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotNull(claims);
            assertTrue(claims.containsKey(ClaimName.AUDIENCE.getName()));

            // Verify the audience claim using the new getter method
            var audience = tokenHolder.getAudience();
            assertEquals(customAudience, audience);

            // Parse the token and verify the audience claim in the JWT
            var jwt = Jwts.parser()
                    .verifyWith(InMemoryKeyMaterialHandler.getDefaultPublicKey())
                    .build()
                    .parseSignedClaims(rawToken);

            // The audience might be a single string or a collection depending on how many values there are
            Object jwtAudience = jwt.getPayload().get(ClaimName.AUDIENCE.getName());
            if (customAudience.size() == 1) {
                assertEquals(customAudience.get(0), jwtAudience);
            } else {
                // Convert both to sets to compare values regardless of collection type
                assertInstanceOf(Collection.class, jwtAudience, "Audience should be a collection");
                @SuppressWarnings("unchecked")
                Collection<String> audienceCollection = (Collection<String>) jwtAudience;
                assertEquals(new HashSet<>(customAudience), new HashSet<>(audienceCollection));
            }
        }

        @Test
        @DisplayName("Should provide public key as JwksLoader")
        void shouldProvidePublicKeyAsLoader() {
            // Given
            var claimControl = ClaimControlParameter.builder()
                    .build();
            var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);
            var customKeyId = "custom-key-id-for-jwks-loader";
            var customAlgorithm = InMemoryKeyMaterialHandler.Algorithm.RS512;

            // When
            tokenHolder.withKeyId(customKeyId).withSigningAlgorithm(customAlgorithm);
            var jwksLoader = tokenHolder.getPublicKeyAsLoader();
            var rawToken = tokenHolder.getRawToken();

            // Then
            assertNotNull(jwksLoader);

            // Verify that the JwksLoader contains the key with the expected ID
            var keyInfo = jwksLoader.getKeyInfo(customKeyId);
            assertTrue(keyInfo.isPresent(), "Key info should be present for key ID: " + customKeyId);

            // Verify that the key from the JwksLoader can be used to verify the token
            var jwt = Jwts.parser()
                    .verifyWith(keyInfo.get().getKey())
                    .build()
                    .parseSignedClaims(rawToken);

            assertNotNull(jwt);
            assertEquals(customKeyId, jwt.getHeader().get("kid"));
            assertEquals(customAlgorithm.name(), jwt.getHeader().getAlgorithm());
        }
    }
}
