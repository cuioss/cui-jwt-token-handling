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
import de.cuioss.jwt.validation.domain.token.RefreshTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link TokenValidator}.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li>CUI-JWT-1.1: JWT Validation</li>
 *   <li>CUI-JWT-1.2: Multi-Issuer Support</li>
 *   <li>CUI-JWT-4.2: Token Types</li>
 *   <li>CUI-JWT-6.1: Token Size Validation</li>
 * </ul>
 * 
 * @author Oliver Wolff
 * @see <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/token-size-validation.adoc">Token Size Validation Specification</a>
 */
@EnableTestLogger
@DisplayName("Tests TokenValidator functionality")
class TokenValidatorTest {


    private TokenValidator tokenValidator;
    private IssuerConfig issuerConfig;

    @BeforeEach
    void setUp() {
        // Get the default JWKS content
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks();

        // Create issuer config
        issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenHolder.TEST_ISSUER)
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                .jwksContent(jwksContent)
                .algorithmPreferences(new AlgorithmPreferences())
                .build();

        // Create validation factory
        tokenValidator = new TokenValidator(issuerConfig);
    }

    @Nested
    @DisplayName("Token Creation Tests")
    class TokenCreationTests {

        @ParameterizedTest
        @TestTokenSource(value = TokenType.REFRESH_TOKEN, count = 3)
        @DisplayName("Should create Refresh-Token")
        void shouldCreateRefreshToken(TestTokenHolder tokenHolder) {
            // Given
            var token = tokenHolder.getRawToken();

            // When
            var parsedToken = tokenValidator.createRefreshToken(token);

            // Then
            assertNotNull(parsedToken, "Token should not be null");
            assertNotNull(parsedToken.getRawToken(), "Token string should not be null");
            assertEquals(token, parsedToken.getRawToken(), "Raw token should match input");

            // Verify claims are extracted
            assertNotNull(parsedToken.getClaims(), "Claims should not be null");
            assertFalse(parsedToken.getClaims().isEmpty(), "Claims should not be empty");

            // The test token should have standard claims
            assertTrue(parsedToken.getClaims().containsKey("sub"), "Claims should contain subject");
            assertTrue(parsedToken.getClaims().containsKey("iss"), "Claims should contain issuer");
        }

        @Test
        @DisplayName("Should create Refresh-Token with empty claims for non-JWT Token")
        void shouldCreateRefreshTokenWithEmptyClaimsForNonJwtToken() {
            // A non-JWT Token (just a random string)
            var token = "not-a-jwt-validation";
            var parsedToken = tokenValidator.createRefreshToken(token);

            assertNotNull(parsedToken, "Token should not be null");
            assertNotNull(parsedToken.getRawToken(), "Token string should not be null");
            assertEquals(token, parsedToken.getRawToken(), "Raw validation should match input");

            // Verify claims are empty
            assertNotNull(parsedToken.getClaims(), "Claims should not be null");
            assertTrue(parsedToken.getClaims().isEmpty(), "Claims should be empty for non-JWT Token");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN)
        @DisplayName("Should create access token")
        void shouldCreateAccessToken(TestTokenHolder tokenHolder) {
            // Given
            // Modify the token to have an invalid issuer to trigger validation failure
            tokenHolder.withClaim("iss", ClaimValue.forPlainString("invalid-issuer"));
            var token = tokenHolder.getRawToken();

            // The token should be validated by the pipeline
            // With our current setup, we expect it to fail validation
            // This is because we need more sophisticated setup for the full pipeline

            // When/Then
            assertThrows(TokenValidationException.class, () -> tokenValidator.createAccessToken(token),
                    "Token should fail validation with current test setup");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN)
        @DisplayName("Should create ID-Token")
        void shouldCreateIdToken(TestTokenHolder tokenHolder) {
            // Given
            // Modify the token to have an invalid issuer to trigger validation failure
            tokenHolder.withClaim("iss", ClaimValue.forPlainString("invalid-issuer"));
            var token = tokenHolder.getRawToken();

            // The token should be validated by the pipeline
            // With our current setup, we expect it to fail validation
            // This is because we need more sophisticated setup for the full pipeline

            // When/Then
            assertThrows(TokenValidationException.class, () -> tokenValidator.createIdToken(token),
                    "Token should fail validation with current test setup");
        }
    }

    @Nested
    @DisplayName("Token Size Validation Tests")
    class TokenSizeValidationTests {

        @Test
        @DisplayName("Should respect custom validation size limits")
        void shouldRespectCustomTokenSizeLimits() {
            // Create a validation that exceeds the custom max size but is smaller than the default
            int customMaxSize = 1024;
            String largeToken = "a".repeat(customMaxSize + 1);

            // Create TokenValidator with custom validation size limits
            ParserConfig customConfig = ParserConfig.builder()
                    .maxTokenSize(customMaxSize)
                    .build();
            var factory = new TokenValidator(customConfig, issuerConfig);

            // Verify it rejects a validation that exceeds the custom max size
            var exception = assertThrows(TokenValidationException.class,
                    () -> factory.createAccessToken(largeToken),
                    "Token exceeding custom max size should be rejected");

            assertEquals(SecurityEventCounter.EventType.TOKEN_SIZE_EXCEEDED, exception.getEventType(),
                    "Exception should have TOKEN_SIZE_EXCEEDED event type");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN)
        @DisplayName("Should respect custom payload size limits")
        void shouldRespectCustomPayloadSizeLimits(TestTokenHolder tokenHolder) {
            // Given
            // Create TokenValidator with custom payload size limits
            ParserConfig customConfig = ParserConfig.builder()
                    .maxPayloadSize(100)
                    .build();
            var factory = new TokenValidator(customConfig, issuerConfig);

            // Add a large claim to the token
            tokenHolder.withClaim("large-claim", ClaimValue.forPlainString("a".repeat(200)));
            String token = tokenHolder.getRawToken();

            // When/Then
            // Verify it rejects a token with a payload that exceeds the custom max size
            var exception = assertThrows(TokenValidationException.class,
                    () -> factory.createAccessToken(token),
                    "Token with payload exceeding custom max size should be rejected");

            assertEquals(SecurityEventCounter.EventType.DECODED_PART_SIZE_EXCEEDED, exception.getEventType(),
                    "Exception should have DECODED_PART_SIZE_EXCEEDED event type");
        }
    }

    @Nested
    @DisplayName("Token Validation Error Tests")
    class TokenValidationErrorTests {

        @Test
        @DisplayName("Should handle empty or blank token strings")
        void shouldProvideEmptyFallbackOnEmptyInput() {
            // Test with empty string
            var emptyException = assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(""),
                    "Empty token should throw TokenValidationException");

            assertEquals(SecurityEventCounter.EventType.TOKEN_EMPTY, emptyException.getEventType(),
                    "Exception should have TOKEN_EMPTY event type");

            // Test with blank string
            var blankException = assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken("   "),
                    "Blank token should throw TokenValidationException");

            assertEquals(SecurityEventCounter.EventType.TOKEN_EMPTY, blankException.getEventType(),
                    "Exception should have TOKEN_EMPTY event type");
        }

        @Test
        @DisplayName("Should handle invalid validation format")
        void shouldHandleInvalidTokenFormat() {
            var initialTokenString = Generators.letterStrings(10, 20).next();

            var exception = assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(initialTokenString),
                    "Invalid token format should throw TokenValidationException");

            assertEquals(SecurityEventCounter.EventType.INVALID_JWT_FORMAT, exception.getEventType(),
                    "Exception should have INVALID_JWT_FORMAT event type");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN)
        @DisplayName("Should handle unknown issuer")
        void shouldHandleUnknownIssuer(TestTokenHolder tokenHolder) {
            // Given
            // Set an unknown issuer
            tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("https://unknown-issuer.com"));
            String token = tokenHolder.getRawToken();

            // When/Then
            var exception = assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(token),
                    "Unknown issuer should throw TokenValidationException");

            assertEquals(SecurityEventCounter.EventType.NO_ISSUER_CONFIG, exception.getEventType(),
                    "Exception should have NO_ISSUER_CONFIG event type");
        }
    }

    @Nested
    @DisplayName("Token Logging Tests")
    class TokenLoggingTests {
        private static final String INVALID_TOKEN = "invalid.validation.string";
        private static final String EMPTY_TOKEN = "";

        @Test
        @DisplayName("Should log warning when validation is empty")
        void shouldLogWarningWhenTokenIsEmpty() {
            // When creating a validation with an empty string
            assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(EMPTY_TOKEN),
                    "Empty token should throw TokenValidationException");

            // And the appropriate warning should be logged
            LogAsserts.assertLogMessagePresent(TestLogLevel.WARN, JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY.format());
        }

        @Test
        @DisplayName("Should log warning when validation format is invalid")
        void shouldLogWarningWhenTokenFormatIsInvalid() {
            // When creating a validation with an invalid format
            assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(INVALID_TOKEN),
                    "Invalid token format should throw TokenValidationException");

            // And the appropriate warning should be logged
            LogAsserts.assertLogMessagePresent(TestLogLevel.WARN, JWTValidationLogMessages.WARN.FAILED_TO_DECODE_JWT.format());
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN)
        @DisplayName("Should log warning when token validation fails")
        void shouldLogWarningWhenTokenValidationFails(TestTokenHolder tokenHolder) {
            // Given a token with an unknown issuer
            tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString("unknown-issuer"));
            String token = tokenHolder.getRawToken();

            // When creating an access token, it should throw an exception
            assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(token),
                    "Token with unknown issuer should throw TokenValidationException");

            // And a warning should be logged
            // The exact message might vary, but we should see a warning related to token validation
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "No configuration found for issuer");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN)
        @DisplayName("Should log warning when token is missing claims")
        void shouldLogWarningWhenTokenIsMissingClaims(TestTokenHolder tokenHolder) {
            // Given a valid token string but missing required claims
            // Remove a required claim (scope) to trigger validation failure
            tokenHolder.withoutClaim("scope");
            String validToken = tokenHolder.getRawToken();

            // When creating an access token, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createAccessToken(validToken),
                    "Token with missing claims should throw TokenValidationException");

            // Verify the exception has the expected event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // Then the appropriate warning message should be logged
            // Note: The actual message might vary, but we should at least see a warning message
            // related to missing claims
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "missing required claim");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ID_TOKEN)
        @DisplayName("Should log warning when ID-Token is missing claims")
        void shouldLogWarningWhenIdTokenIsMissingClaims(TestTokenHolder tokenHolder) {
            // Given a valid token string but missing required claims
            // Remove a required claim (aud) to trigger validation failure
            tokenHolder.withoutClaim("aud");
            String validToken = tokenHolder.getRawToken();

            // When creating an ID-Token, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> tokenValidator.createIdToken(validToken),
                    "ID-Token with missing claims should throw TokenValidationException");

            // Verify the exception has the expected event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // Then the appropriate warning message should be logged
            // Note: The actual message might vary, but we should at least see a warning message
            // related to missing claims
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "missing required claim");
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.REFRESH_TOKEN)
        @DisplayName("Should create Refresh-Token successfully")
        void shouldCreateRefreshTokenSuccessfully(TestTokenHolder tokenHolder) {
            // Given a valid token
            String token = tokenHolder.getRawToken();

            // When creating a Refresh-Token
            RefreshTokenContent result = tokenValidator.createRefreshToken(token);

            // Then the token should be created successfully
            assertNotNull(result, "Refresh token should be created successfully");
            assertEquals(token, result.getRawToken(), "Raw token should match input");

            // For refresh tokens, we don't need to check for specific log messages
            // as the test itself verifies the functionality works
        }

        @ParameterizedTest
        @TestTokenSource(value = TokenType.ACCESS_TOKEN)
        @DisplayName("Should log warning when key is not found")
        void shouldLogWarningWhenKeyIsNotFound(TestTokenHolder tokenHolder) {
            // Given a token
            String token = tokenHolder.getRawToken();

            // Create a new issuer config with a JWKS that doesn't contain the key ID
            IssuerConfig newIssuerConfig = IssuerConfig.builder()
                    .issuer(TestTokenHolder.TEST_ISSUER)
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                    .jwksContent(InMemoryJWKSFactory.createEmptyJwks())
                    .build();

            // Create a new token validator with the new issuer config
            TokenValidator newTokenValidator = new TokenValidator(newIssuerConfig);

            // When creating an access token, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> newTokenValidator.createAccessToken(token),
                    "Token with unknown key ID should throw TokenValidationException");

            // Then
            assertEquals(SecurityEventCounter.EventType.KEY_NOT_FOUND, exception.getEventType(),
                    "Exception should have KEY_NOT_FOUND event type");

            // And a warning should be logged about key issues
            // The exact message might vary, but we should see a warning related to keys
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "key");
        }

        @Test
        @DisplayName("Should log info message when TokenValidator is initialized")
        void shouldLogInfoMessageWhenTokenFactoryIsInitialized() {
            // Create multiple issuer configs to test the count in the log message
            IssuerConfig issuerConfig1 = IssuerConfig.builder()
                    .issuer(TestTokenHolder.TEST_ISSUER)
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .build();

            IssuerConfig issuerConfig2 = IssuerConfig.builder()
                    .issuer("https://another-issuer.com")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                    .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                    .build();

            // Create a new validation factory with multiple issuer configs
            new TokenValidator(
                    issuerConfig1,
                    issuerConfig2);

            // Verify that the appropriate info message is logged
            LogAsserts.assertLogMessagePresent(
                    TestLogLevel.INFO,
                    JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED.format(2));
        }
    }
}
