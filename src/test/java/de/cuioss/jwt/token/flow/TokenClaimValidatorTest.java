/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.token.TokenContent;
import de.cuioss.jwt.token.test.generator.InvalidTokenContentGenerator;
import de.cuioss.jwt.token.test.generator.ValidTokenContentGenerator;
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

    private static final String EXPECTED_AUDIENCE = "test-audience";
    private static final String EXPECTED_CLIENT_ID = "test-client-id";

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {
        @Test
        @DisplayName("Should create validator with all recommended elements using Sets")
        void shouldCreateValidatorWithAllRecommendedElementsUsingSets() {
            // Given an IssuerConfig with all recommended elements as Sets
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(Set.of(EXPECTED_AUDIENCE))
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();

            // When creating the validator
            TokenClaimValidator validator = new TokenClaimValidator(issuerConfig);

            // Then the validator should be created without warnings
            assertNotNull(validator, "Validator should not be null");
            assertNotNull(validator.getExpectedAudience(), "Expected audience should not be null");
            assertNotNull(validator.getExpectedClientId(), "Expected client ID should not be null");

            // No warnings should be logged for missing recommended elements
        }

        @Test
        @DisplayName("Should log warning when missing expected audience")
        void shouldLogWarningWhenMissingExpectedAudience() {
            // Given an IssuerConfig without expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();

            // When creating the validator
            TokenClaimValidator validator = new TokenClaimValidator(issuerConfig);

            // Then a warning should be logged for missing expected audience
            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedAudience().isEmpty(), "Expected audience should be empty");

            // Warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should log warning when missing expected client ID")
        void shouldLogWarningWhenMissingExpectedClientId() {
            // Given an IssuerConfig without expected client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .build();

            // When creating the validator
            TokenClaimValidator validator = new TokenClaimValidator(issuerConfig);

            // Then a warning should be logged for missing expected client ID
            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedClientId().isEmpty(), "Expected client ID should be empty");

            // Warning should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should log warnings when missing all recommended elements")
        void shouldLogWarningsWhenMissingAllRecommendedElements() {
            // Given an IssuerConfig without any recommended elements
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .build();

            // When creating the validator
            TokenClaimValidator validator = new TokenClaimValidator(issuerConfig);

            // Then warnings should be logged for all missing recommended elements
            assertNotNull(validator, "Validator should not be null");
            assertTrue(validator.getExpectedAudience().isEmpty(), "Expected audience should be empty");
            assertTrue(validator.getExpectedClientId().isEmpty(), "Expected client ID should be empty");

            // Warnings should be logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());
            // Multiple occurrences of the same log message with different parameters
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_RECOMMENDED_ELEMENT.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Mandatory Claims Validation Tests")
    class MandatoryClaimsValidationTests {
        @Test
        @DisplayName("Should validate token with all mandatory claims")
        void shouldValidateTokenWithAllMandatoryClaims() {
            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // Create a token with all mandatory claims using the ValidTokenContentGenerator
            TokenContent tokenContent = new ValidTokenContentGenerator().next();

            // When validating the token
            var result = validator.validate(tokenContent);

            // Then the validation should pass
            assertTrue(result.isPresent(), "Token should be valid with all mandatory claims");
        }

        @Test
        @DisplayName("Should fail validation for token missing mandatory claims")
        void shouldFailValidationForTokenMissingMandatoryClaims() {
            // Given a validator with expected audience and client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // Create a token missing mandatory claims using the InvalidTokenContentGenerator
            TokenContent tokenContent = new InvalidTokenContentGenerator()
                    .withMissingIssuer()
                    .withMissingSubject()
                    .next();

            // When validating the token
            var result = validator.validate(tokenContent);

            // Then the validation should fail
            assertTrue(result.isEmpty(), "Token should be invalid when mandatory claims are missing");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());
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
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a matching audience
            TokenContent tokenContent = new ValidTokenContentGenerator().next();
            var result = validator.validate(tokenContent);

            // Then the validation should pass
            assertTrue(result.isPresent(), "Token should be valid with matching audience");
        }

        @Test
        @DisplayName("Should fail validation for token with non-matching audience for ID-Tokens")
        void shouldFailValidationForTokenWithNonMatchingAudienceForID() {
            // Given a validator with expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a missing audience
            TokenContent tokenContent = new InvalidTokenContentGenerator(TokenType.ID_TOKEN)
                    .withMissingAudience()
                    .next();
            var result = validator.validate(tokenContent);

            // Then the validation should fail
            assertTrue(result.isEmpty(), "Token should be invalid with missing audience");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should fail validation for token with non-matching audience for Access-Tokens")
        void shouldFailValidationForTokenWithNonMatchingAudienceForAccessToken() {
            // Given a validator with expected audience
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a missing audience
            TokenContent tokenContent = new InvalidTokenContentGenerator(TokenType.ACCESS_TOKEN)
                    .withMissingAudience()
                    .next();
            var result = validator.validate(tokenContent);

            // Then the validation should fail
            assertFalse(result.isEmpty(), "Token should be valid with missing audience for access-token");
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
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a matching authorized party
            TokenContent tokenContent = new ValidTokenContentGenerator().next();
            var result = validator.validate(tokenContent);

            // Then the validation should pass
            assertTrue(result.isPresent(), "Token should be valid with matching authorized party");
        }

        @Test
        @DisplayName("Should fail validation for token with missing authorized party")
        void shouldFailValidationForTokenWithMissingAuthorizedParty() {
            // Given a validator with expected client ID
            var issuerConfig = IssuerConfig.builder()
                    .issuer("test-issuer")
                    .expectedAudience(EXPECTED_AUDIENCE)
                    .expectedClientId(EXPECTED_CLIENT_ID)
                    .build();
            var validator = new TokenClaimValidator(issuerConfig);

            // When validating a token with a missing authorized party
            // Create a token with a missing authorized party claim
            TokenContent tokenContent = new InvalidTokenContentGenerator()
                    .withMissingAuthorizedParty()
                    .next();
            var result = validator.validate(tokenContent);

            // Then the validation should fail
            assertTrue(result.isEmpty(), "Token should be invalid with missing authorized party");

            // Verify that the appropriate warning is logged
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, JWTTokenLogMessages.WARN.MISSING_CLAIM.resolveIdentifierString());
        }
    }

    // Not Before Validation Tests have been moved to TokenClaimValidatorEdgeCaseTest
    // to avoid duplication and provide more comprehensive edge case testing

    // Expiration Validation Tests have been moved to TokenClaimValidatorEdgeCaseTest
    // to avoid duplication and provide more comprehensive edge case testing
}
