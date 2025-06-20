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
import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.ClaimControlParameter;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenClaimValidator}.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests TokenClaimValidator functionality")
class TokenClaimValidatorTest {

    private static final String EXPECTED_CLIENT_ID = "test-client-id";

    private static final SecurityEventCounter SECURITY_EVENT_COUNTER = new SecurityEventCounter();

    // Helper method to create a TokenClaimValidator with the shared SecurityEventCounter
    private TokenClaimValidator createValidator(IssuerConfig issuerConfig) {
        return new TokenClaimValidator(issuerConfig, SECURITY_EVENT_COUNTER);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {
        @Test
        @DisplayName("Should create validator with all recommended elements using Sets")
        void shouldCreateValidatorWithAllRecommendedElementsUsingSets() {
            // Given an IssuerConfig with all recommended elements as Sets
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(Set.of(TestTokenHolder.TEST_AUDIENCE))
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();

            // When creating the validator
            TokenClaimValidator validator = createValidator(issuerConfig);

            // Then the validator should be created without warnings
            assertNotNull(validator, "Validator should not be null");
            assertNotNull(validator.getExpectedAudience(), "Expected audience should not be null");
            assertNotNull(validator.getExpectedClientId(), "Expected client ID should not be null");

            // No warnings should be logged for missing recommended elements
        }

        @Test
        @DisplayName("Should log warning when missing expected audience")
        void shouldLogWarningWhenMissingExpectedAudience() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);

            // Given an IssuerConfig without expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();

            // When creating the validator
            TokenClaimValidator validator = createValidator(issuerConfig);

            // Then a warning should be logged for missing expected audience
            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedAudience().isEmpty(), "Expected audience should be empty");

            // Warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT),
                    "MISSING_RECOMMENDED_ELEMENT event should be incremented");
        }

        @Test
        @DisplayName("Should log warning when missing expected client ID")
        void shouldLogWarningWhenMissingExpectedClientId() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);

            // Given an IssuerConfig without expected client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .build();

            // When creating the validator
            TokenClaimValidator validator = createValidator(issuerConfig);

            // Then a warning should be logged for missing expected client ID
            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedClientId().isEmpty(), "Expected client ID should be empty");

            // Warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT),
                    "MISSING_RECOMMENDED_ELEMENT event should be incremented");
        }

        @Test
        @DisplayName("Should log warnings when missing all recommended elements")
        void shouldLogWarningsWhenMissingAllRecommendedElements() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT);

            // Given an IssuerConfig without any recommended elements
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .build();

            // When creating the validator
            TokenClaimValidator validator = createValidator(issuerConfig);

            // Then warnings should be logged for all missing recommended elements
            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedAudience().isEmpty(), "Expected audience should be empty");
            assertTrue(validator.getExpectedClientId().isEmpty(), "Expected client ID should be empty");

            // Warnings should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());
            // Multiple occurrences of the same log message with different parameters
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());

            // Verify security event was recorded twice (once for audience, once for client ID)
            assertEquals(initialCount + 2, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_RECOMMENDED_ELEMENT),
                    "MISSING_RECOMMENDED_ELEMENT event should be incremented twice");
        }
    }

    @Nested
    @DisplayName("Mandatory Claims Validation Tests")
    class MandatoryClaimsValidationTests {
        @Test
        @DisplayName("Should validate validation with all mandatory claims")
        void shouldValidateTokenWithAllMandatoryClaims() {
            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // Create a validation with all mandatory claims using the TestTokenGenerators factory
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));

            // When validating the validation - should not throw an exception
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token should be valid with all mandatory claims");

            // Then the validation should pass
            assertNotNull(result, "Validated token should not be null");
        }

        @Test
        @DisplayName("Should fail validation for validation missing mandatory claims")
        void shouldFailValidationForTokenMissingMandatoryClaims() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // Create a validation missing mandatory claims using the TestTokenHolder with ClaimControlParameter
            TokenContent tokenContent = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder()
                            .missingIssuer(true)
                            .missingSubject(true)
                            .build());

            // When validating the validation - should throw an exception
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(tokenContent),
                    "Token with missing mandatory claims should be rejected");

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());

            // Verify security event was recorded
            assertTrue(SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM) > initialCount,
                    "MISSING_CLAIM event should be incremented");
        }
    }

    @Nested
    @DisplayName("Audience Validation Tests")
    class AudienceValidationTests {
        @Test
        @DisplayName("Should validate token with matching audience")
        void shouldValidateTokenWithMatchingAudience() {
            // Given a validator with expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // When validating a token with a matching audience - should not throw an exception
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token should be valid with matching audience");

            // Then the validation should pass
            assertNotNull(result, "Validated token should not be null");
        }

        @Test
        @DisplayName("Should fail validation for token with non-matching audience for ID-Tokens")
        void shouldFailValidationForTokenWithNonMatchingAudienceForID() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator with expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // When validating a token with a missing audience - should throw an exception
            TokenContent tokenContent = new TestTokenHolder(TokenType.ID_TOKEN,
                    ClaimControlParameter.builder()
                            .missingAudience(true)
                            .build());

            // Then the validation should fail
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(tokenContent),
                    "Token with missing audience should be rejected for ID tokens");

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM),
                    "MISSING_CLAIM event should be incremented");
        }

        @Test
        @DisplayName("Should not fail validation for token with non-matching audience for Access-Tokens")
        void shouldFailValidationForTokenWithNonMatchingAudienceForAccessToken() {
            // Given a validator with expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // When validating a token with a missing audience - should not throw an exception for access tokens
            TestTokenHolder tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder()
                            .missingAudience(true)
                            .build());
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));

            // Then the validation should pass (access tokens can have missing audience)
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token should be valid with missing audience for access-token");

            // Verify the result is not null
            assertNotNull(result, "Validated token should not be null");
        }
    }

    @Nested
    @DisplayName("Authorized Party Validation Tests")
    class AuthorizedPartyValidationTests {
        @Test
        @DisplayName("Should validate token with matching authorized party")
        void shouldValidateTokenWithMatchingAuthorizedParty() {
            // Given a validator with expected client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // When validating a token with a matching authorized party - should not throw an exception
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token should be valid with matching authorized party");

            // Then the validation should pass
            assertNotNull(result, "Validated token should not be null");
        }

        @Test
        @DisplayName("Should fail validation for token with missing authorized party")
        void shouldFailValidationForTokenWithMissingAuthorizedParty() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator with expected client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // When validating a token with a missing authorized party
            // Create a token with a missing authorized party claim
            TokenContent tokenContent = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder()
                            .missingAuthorizedParty(true)
                            .build());

            // Then the validation should fail
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(tokenContent),
                    "Token with missing authorized party should be rejected");

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM),
                    "MISSING_CLAIM event should be incremented");
        }
    }

    @Nested
    @DisplayName("Mutable Claims Validation Tests")
    class MutableClaimsValidationTests {
        @Test
        @DisplayName("Should validate token with valid subject claim")
        void shouldValidateTokenWithValidSubjectClaim() {
            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // Create a token with a valid subject claim
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));
            // Ensure subject claim is present with a valid value
            tokenHolder.withClaim("sub", ClaimValue.forPlainString("valid-subject-id"));

            // When validating the token - should not throw an exception
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token should be valid with valid subject claim");

            // Then the validation should pass
            assertNotNull(result, "Validated token should not be null");
        }

        @Test
        @DisplayName("Should fail validation for token with missing subject claim")
        void shouldFailValidationForTokenWithMissingSubjectClaim() {
            // Get initial count
            long initialCount = SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM);

            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // Create a token with a missing subject claim
            TestTokenHolder tokenContent = new TestTokenHolder(TokenType.ACCESS_TOKEN,
                    ClaimControlParameter.builder()
                            .missingSubject(true)
                            .build());
            // Set the authorized party to match the expected client ID
            tokenContent.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));

            // When validating the token - should throw an exception
            TokenValidationException exception = assertThrows(TokenValidationException.class,
                    () -> validator.validate(tokenContent),
                    "Token with missing subject claim should be rejected");

            // Verify the exception has the correct event type
            assertEquals(SecurityEventCounter.EventType.MISSING_CLAIM, exception.getEventType(),
                    "Exception should have MISSING_CLAIM event type");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTValidationLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());

            // Verify security event was recorded
            assertEquals(initialCount + 1, SECURITY_EVENT_COUNTER.getCount(SecurityEventCounter.EventType.MISSING_CLAIM),
                    "MISSING_CLAIM event should be incremented");
        }

        @Test
        @DisplayName("Should validate token with empty subject claim (current behavior)")
        void shouldValidateTokenWithEmptySubjectClaim() {
            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // Create a token with an empty subject claim
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));
            // Set an empty subject claim
            tokenHolder.withClaim("sub", ClaimValue.forPlainString(""));

            // When validating the token - should not throw an exception (current behavior)
            // This is because ClaimValue.isPresent() only checks if originalString is not null, not if it's empty
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token with empty subject claim is currently accepted");

            // Then the validation should pass
            assertNotNull(result, "Validated token should not be null");

            // Verify the token has an empty subject claim
            assertTrue(result.getClaims().containsKey("sub"), "Token should contain subject claim");
            assertEquals("", result.getClaims().get("sub").getOriginalString(), "Subject claim should be empty");

            // Note: This test documents the current behavior of the library.
            // In a future enhancement, the library could be modified to reject tokens with empty subject claims
            // by updating the ClaimValue.isPresent() method to also check if the string is empty.
        }

        @Test
        @DisplayName("Should validate token with mutable claims but still use subject for identification")
        void shouldValidateTokenWithMutableClaims() {
            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = createValidator(issuerConfig);

            // Create a token with both subject and mutable claims
            TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
            // Set the authorized party to match the expected client ID
            tokenHolder.withClaim("azp", ClaimValue.forPlainString(EXPECTED_CLIENT_ID));
            // Ensure subject claim is present with a valid value
            tokenHolder.withClaim("sub", ClaimValue.forPlainString("valid-subject-id"));
            // Add mutable claims
            tokenHolder.withClaim("email", ClaimValue.forPlainString("user@example.com"));
            tokenHolder.withClaim("name", ClaimValue.forPlainString("Test User"));
            tokenHolder.withClaim("preferred_username", ClaimValue.forPlainString("testuser"));

            // When validating the token - should not throw an exception
            TokenContent result = assertDoesNotThrow(() -> validator.validate(tokenHolder),
                    "Token should be valid with both subject and mutable claims");

            // Then the validation should pass
            assertNotNull(result, "Validated token should not be null");

            // Verify the token has both subject and mutable claims
            assertTrue(result.getClaims().containsKey("sub"), "Token should contain subject claim");
            assertTrue(result.getClaims().containsKey("email"), "Token should contain email claim");
            assertTrue(result.getClaims().containsKey("name"), "Token should contain name claim");
            assertTrue(result.getClaims().containsKey("preferred_username"), "Token should contain preferred_username claim");

            // The library correctly validates the subject claim but doesn't warn about mutable claims
            // This test documents this behavior and serves as a reminder that applications should use
            // the immutable 'sub' claim for user identification rather than mutable claims like email
        }
    }
}
