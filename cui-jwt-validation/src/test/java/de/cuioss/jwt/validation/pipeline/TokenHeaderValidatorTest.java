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
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenHeaderValidator}.
 */
@EnableTestLogger(debug = TokenHeaderValidator.class, warn = TokenHeaderValidator.class)
@EnableGeneratorController
@DisplayName("Tests TokenHeaderValidator functionality")
class TokenHeaderValidatorTest {

    private static final String EXPECTED_ISSUER = "Token-Test-testIssuer";
    private static final String WRONG_ISSUER = "wrong-issuer";
    private static final SecurityEventCounter SECURITY_EVENT_COUNTER = new SecurityEventCounter();
    private static final NonValidatingJwtParser JWT_PARSER = NonValidatingJwtParser.builder()
            .securityEventCounter(SECURITY_EVENT_COUNTER)
            .build();

    // Helper method to create a TokenHeaderValidator with the shared SecurityEventCounter
    private TokenHeaderValidator createValidator(IssuerConfig issuerConfig) {
        return new TokenHeaderValidator(issuerConfig, SECURITY_EVENT_COUNTER);
    }

    @Nested
    @DisplayName("IssuerConfig Configuration Tests")
    class IssuerConfigConfigurationTests {

        @Test
        @DisplayName("Should create validator with expected issuer")
        void shouldCreateValidatorWithExpectedIssuer() {
            // Given an IssuerConfig with expected issuer
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .build();

            // When creating the validator
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // Then the validator should be created without warnings
            assertNotNull(validator);
            assertEquals(EXPECTED_ISSUER, issuerConfig.getIssuer());
            assertNotNull(issuerConfig.getAlgorithmPreferences());
        }

        @Test
        @DisplayName("Should create validator with custom algorithm preferences")
        void shouldCreateValidatorWithCustomAlgorithmPreferences() {
            // Given an IssuerConfig with custom algorithm preferences
            var customAlgorithmPreferences = new AlgorithmPreferences(List.of("RS256", "ES256"));
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .algorithmPreferences(customAlgorithmPreferences)
                    .build();

            // When creating the validator
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // Then the validator should be created with the custom algorithm preferences
            assertNotNull(validator);
            assertSame(customAlgorithmPreferences, issuerConfig.getAlgorithmPreferences());
        }

    }

    @Nested
    @DisplayName("Algorithm Validation Tests")
    class AlgorithmValidationTests {

        @Test
        @DisplayName("Should validate validation with supported algorithm")
        void shouldValidateTokenWithSupportedAlgorithm() {
            // Given a validator with default algorithm preferences
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a supported algorithm (RS256)
            String token = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN)).getRawToken();
            DecodedJwt decodedJwt = JWT_PARSER.decode(token);

            // When validating the validation, it should not throw an exception
            assertDoesNotThrow(() -> validator.validate(decodedJwt));
        }

        @Test
        @DisplayName("Should reject validation with unsupported algorithm")
        void shouldRejectTokenWithUnsupportedAlgorithm() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM);

            // Given a validator with custom algorithm preferences that only support ES256
            var customAlgorithmPreferences = new AlgorithmPreferences(List.of("ES256"));
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .algorithmPreferences(customAlgorithmPreferences)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with an unsupported algorithm (RS256)
            String token = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN)).getRawToken();
            DecodedJwt decodedJwt = JWT_PARSER.decode(token);
            assertEquals("RS256", decodedJwt.getAlg().orElse(null));

            // When validating the validation, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM, exception.getEventType());

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unsupported algorithm: RS256");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.UNSUPPORTED_ALGORITHM));
        }

        @Test
        @DisplayName("Should reject validation with missing algorithm")
        void shouldRejectTokenWithMissingAlgorithm() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a missing algorithm (manually created since generators always include alg)
            DecodedJwt decodedJwt = new DecodedJwt(null, null, null, new String[]{"", "", ""}, "");

            // When validating the validation, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType());

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: alg");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        }
    }

    @Nested
    @DisplayName("Issuer Validation Tests")
    class IssuerValidationTests {

        @Test
        @DisplayName("Should validate validation with expected issuer")
        void shouldValidateTokenWithExpectedIssuer() {
            // Given a validator with expected issuer
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with the expected issuer
            String token = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN)).getRawToken();
            DecodedJwt decodedJwt = JWT_PARSER.decode(token);
            assertEquals(EXPECTED_ISSUER, decodedJwt.getIssuer().orElse(null));

            // When validating the validation, it should not throw an exception
            assertDoesNotThrow(() -> validator.validate(decodedJwt));
        }

        @Test
        @DisplayName("Should reject validation with wrong issuer")
        void shouldRejectTokenWithWrongIssuer() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.ISSUER_MISMATCH);

            // Given a validator with expected issuer
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a wrong issuer
            DecodedJwt decodedJwt = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN))
                    .withClaim("iss", ClaimValue.forPlainString(WRONG_ISSUER))
                    .asDecodedJwt();

            // When validating the validation, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.ISSUER_MISMATCH, exception.getEventType());

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "Token issuer '" + WRONG_ISSUER + "' does not match expected issuer");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.ISSUER_MISMATCH));
        }

        @Test
        @DisplayName("Should reject validation with missing issuer")
        void shouldRejectTokenWithMissingIssuer() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator with expected issuer
            var issuerConfig = IssuerConfig.builder()
                    .issuer(EXPECTED_ISSUER)
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a missing issuer
            DecodedJwt decodedJwt = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.builder()
                    .missingIssuer(true)
                    .build())
                    .asDecodedJwt();

            // When validating the validation, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Token is missing required claim: iss");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM));
        }

        @Test
        @DisplayName("Should validate issuer when expected issuer is configured")
        void shouldValidateIssuerWhenExpectedIssuerIsConfigured() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.ISSUER_MISMATCH);

            // Given a validator with an expected issuer that doesn't match the validation's issuer
            var issuerConfig = IssuerConfig.builder()
                    .issuer("dummy-issuer")
                    .build();
            TokenHeaderValidator validator = createValidator(issuerConfig);

            // And a validation with a different issuer
            String token = new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN)).getRawToken();
            DecodedJwt decodedJwt = JWT_PARSER.decode(token);
            assertEquals(EXPECTED_ISSUER, decodedJwt.getIssuer().orElse(null));

            // When validating the validation, it should throw an exception
            var exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(decodedJwt));

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.ISSUER_MISMATCH, exception.getEventType());

            // And a warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "Token issuer '" + EXPECTED_ISSUER + "' does not match expected issuer 'dummy-issuer'");

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.ISSUER_MISMATCH));
        }
    }
}
