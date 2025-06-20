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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.JwtTokenTamperingUtil;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.jwt.validation.test.junit.TestTokenSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests compliance with the JWT specification defined in RFC 7519.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li>CUI-JWT-2.1: RFC 7519 Compliance</li>
 *   <li>CUI-JWT-2.2: JWT Structure</li>
 *   <li>CUI-JWT-2.3: Standard JWT Claims</li>
 * </ul>
 * 
 * @author Oliver Wolff
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 */
@DisplayName("RFC 7519 JWT Compliance Tests")
class RFC7519JWTComplianceTest {


    // No longer need a tokenValidator field as we'll create it on demand using tokenHolder.getIssuerConfig()

    @Nested
    @DisplayName("Section 4.1: Registered Claim Names")
    class RegisteredClaimNamesTests {

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.1: 'iss' (Issuer) Claim")
        void shouldHandleIssuerClaim(TestTokenHolder tokenHolder) {
            // Given
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertEquals(TestTokenHolder.TEST_ISSUER, result.getIssuer(),
                    "Issuer claim should match the expected value");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.2: 'sub' (Subject) Claim")
        void shouldHandleSubjectClaim(TestTokenHolder tokenHolder) {
            // Given
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);
            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertNotNull(result.getSubject(),
                    "Subject claim should be present");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.3: 'aud' (Audience) Claim")
        void shouldHandleAudienceClaim(TestTokenHolder tokenHolder) {
            // Given
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertTrue(result.getAudience().isPresent(), "Audience claim should be present");
            assertEquals(List.of(TestTokenHolder.TEST_CLIENT_ID), result.getAudience().get(),
                    "Audience claim should match the expected value");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 5)
        @DisplayName("4.1.4: 'exp' (Expiration Time) Claim")
        void shouldHandleExpirationTimeClaim(TestTokenHolder tokenHolder) {
            // Given
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertNotNull(result.getExpirationTime(),
                    "Expiration time claim should be present");
            assertFalse(result.isExpired(),
                    "Token should not be expired");
        }

        @Test
        @DisplayName("4.1.5: 'nbf' (Not Before) Claim")
        void shouldHandleNotBeforeClaim() {
            // Given
            Instant notBefore = Instant.now().minus(5, ChronoUnit.MINUTES);
            OffsetDateTime notBeforeDateTime = OffsetDateTime.ofInstant(notBefore, ZoneId.systemDefault());

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Add the notBefore claim
            tokenHolder.withClaim(ClaimName.NOT_BEFORE.getName(),
                    ClaimValue.forDateTime(String.valueOf(notBeforeDateTime.toEpochSecond()), notBeforeDateTime));

            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertTrue(result.getNotBefore().isPresent(),
                    "Not Before claim should be present");
        }

        @Test
        @DisplayName("4.1.6: 'iat' (Issued At) Claim")
        void shouldHandleIssuedAtClaim() {
            // Given
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertNotNull(result.getIssuedAtTime(),
                    "Issued At claim should be present");
        }

        @Test
        @DisplayName("4.1.7: 'jti' (JWT ID) Claim")
        void shouldHandleJwtIdClaim() {
            // Given
            String jwtId = "test-jwt-id";

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Set a specific JWT ID
            tokenHolder.withClaim(ClaimName.TOKEN_ID.getName(), ClaimValue.forPlainString(jwtId));

            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            assertTrue(result.getClaimOption(ClaimName.TOKEN_ID).isPresent(),
                    "JWT ID claim should be present");
            assertEquals(jwtId, result.getClaimOption(ClaimName.TOKEN_ID).get().getOriginalString(),
                    "JWT ID claim should match the expected value");
        }
    }

    @Nested
    @DisplayName("Section 3: JWT Format and Processing Rules")
    class JwtFormatAndProcessingTests {

        @Test
        @DisplayName("3.1: JWT Format - Three-part structure")
        void shouldHandleThreePartStructure() {
            // Given
            String token = TestTokenGenerators.accessTokens().next().getRawToken();
            String[] parts = token.split("\\.");

            // Then
            assertEquals(3, parts.length,
                    "JWT should have three parts: header, payload, and signature");
        }

        @Test
        @DisplayName("3.1: JWT Format - Base64URL encoding")
        void shouldHandleBase64UrlEncoding() {
            // Given
            String token = TestTokenGenerators.accessTokens().next().getRawToken();
            String[] parts = token.split("\\.");

            // Then
            // Verify that each part is Base64URL encoded (no padding, no invalid characters)
            for (String part : parts) {
                assertFalse(part.contains("+"), "Base64URL should not contain '+' character");
                assertFalse(part.contains("/"), "Base64URL should not contain '/' character");
                assertFalse(part.contains("="), "Base64URL should not contain padding '=' character");
            }
        }

        @Test
        @DisplayName("3.2: JWT Header - 'alg' and 'typ' claims")
        void shouldHandleHeaderClaims() {
            // Given
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");
            // Note: The TokenContent interface doesn't provide direct access to header claims
            // This is tested indirectly by the fact that the token is successfully validated
        }
    }

    @Nested
    @DisplayName("Section 7.2: Token Validation")
    class TokenValidationTests {

        @Test
        @DisplayName("7.2: Validate signature")
        void shouldValidateSignature() {
            // Given
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token with valid signature should be parsed successfully");
        }

        @Test
        @DisplayName("7.2: Reject validation with invalid signature")
        void shouldRejectInvalidSignature() {
            // Create a valid token first using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String validToken = tokenHolder.getRawToken();

            // Tamper with the signature using JwtTokenTamperingUtil
            String invalidToken = JwtTokenTamperingUtil.applyTamperingStrategy(
                    validToken,
                    JwtTokenTamperingUtil.TamperingStrategy.MODIFY_SIGNATURE_LAST_CHAR
            );

            // When/Then
            TokenValidator validator = new TokenValidator(tokenHolder.getIssuerConfig());
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(invalidToken),
                    "Token with invalid signature should be rejected");

            assertEquals(SecurityEventCounter.EventType.SIGNATURE_VALIDATION_FAILED, exception.getEventType(),
                    "Exception should have SIGNATURE_VALIDATION_FAILED event type");
        }

        @Test
        @DisplayName("7.2: Validate expiration time")
        void shouldValidateExpirationTime() {
            // Given
            Instant expiredTime = Instant.now().minus(1, ChronoUnit.HOURS);
            OffsetDateTime expiredDateTime = OffsetDateTime.ofInstant(expiredTime, ZoneId.systemDefault());

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Set expired expiration time
            tokenHolder.withClaim(ClaimName.EXPIRATION.getName(),
                    ClaimValue.forDateTime(String.valueOf(expiredDateTime.toEpochSecond()), expiredDateTime));

            String token = tokenHolder.getRawToken();

            // When/Then
            TokenValidator validator = new TokenValidator(tokenHolder.getIssuerConfig());
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(token),
                    "Expired token should be rejected");

            assertEquals(SecurityEventCounter.EventType.TOKEN_EXPIRED, exception.getEventType(),
                    "Exception should have TOKEN_EXPIRED event type");
        }

        @Test
        @DisplayName("7.2: Validate not before time")
        void shouldValidateNotBeforeTime() {
            // Given
            Instant futureTime = Instant.now().plus(1, ChronoUnit.HOURS);
            OffsetDateTime futureDateTime = OffsetDateTime.ofInstant(futureTime, ZoneId.systemDefault());

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Set future not-before time
            tokenHolder.withClaim(ClaimName.NOT_BEFORE.getName(),
                    ClaimValue.forDateTime(String.valueOf(futureDateTime.toEpochSecond()), futureDateTime));

            String token = tokenHolder.getRawToken();

            // When/Then
            TokenValidator validator = new TokenValidator(tokenHolder.getIssuerConfig());
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.createAccessToken(token),
                    "Token not yet valid should be rejected");

            assertEquals(SecurityEventCounter.EventType.TOKEN_NBF_FUTURE, exception.getEventType(),
                    "Exception should have TOKEN_NBF_FUTURE event type");
        }
    }

    @Nested
    @DisplayName("Section 5: JWT Claims Set")
    class JwtClaimsSetTests {

        @Test
        @DisplayName("5.1: JWT Claims Set - JSON object")
        void shouldHandleJsonClaimsSet() {
            // Given
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");

            // Verify that standard claims are accessible
            assertNotNull(result.getIssuer(), "Issuer claim should be accessible");
            assertNotNull(result.getSubject(), "Subject claim should be accessible");
            assertNotNull(result.getExpirationTime(), "Expiration time claim should be accessible");
            assertNotNull(result.getIssuedAtTime(), "Issued at claim should be accessible");
        }

        @Test
        @DisplayName("5.2: JWT Claims Set - Custom claims")
        void shouldHandleCustomClaims() {
            // Given
            String customClaimName = "custom_claim";
            String customClaimValue = "custom_value";

            // Create token using TestTokenHolder
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();

            // Add custom claim
            tokenHolder.withClaim(customClaimName, ClaimValue.forPlainString(customClaimValue));

            String token = tokenHolder.getRawToken();

            // When
            AccessTokenContent result = new TokenValidator(tokenHolder.getIssuerConfig()).createAccessToken(token);

            // Then
            assertNotNull(result, "Token should be parsed successfully");

            // Verify that custom claim is accessible
            assertTrue(result.getClaims().containsKey(customClaimName),
                    "Custom claim should be accessible");
            assertEquals(customClaimValue, result.getClaims().get(customClaimName).getOriginalString(),
                    "Custom claim should have the expected value");
        }
    }
}
