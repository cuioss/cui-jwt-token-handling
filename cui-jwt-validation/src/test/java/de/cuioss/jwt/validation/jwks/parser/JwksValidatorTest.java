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
package de.cuioss.jwt.validation.jwks.parser;

import de.cuioss.jwt.validation.security.JwkAlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(warn = JwksValidator.class)
@DisplayName("Tests JwksValidator functionality")
class JwksValidatorTest {

    private JwksValidator validator;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        securityEventCounter = new SecurityEventCounter();
        JwkAlgorithmPreferences preferences = new JwkAlgorithmPreferences();
        validator = new JwksValidator(preferences, securityEventCounter);
    }

    @Nested
    @DisplayName("JWKS Structure Validation")
    class JwksStructureValidationTests {

        @Test
        @DisplayName("Should accept valid JWKS with keys array")
        void shouldAcceptValidJwksWithKeysArray() {
            // Given a valid JWKS structure
            JsonObjectBuilder jwksBuilder = Json.createObjectBuilder()
                    .add("keys", Json.createArrayBuilder()
                            .add(Json.createObjectBuilder()
                                    .add("kty", "RSA")
                                    .add("kid", "test-key")));
            JsonObject jwks = jwksBuilder.build();

            // When validating
            boolean result = validator.validateJwksStructure(jwks);

            // Then should accept
            assertTrue(result, "Should accept valid JWKS structure");
        }

        @Test
        @DisplayName("Should accept valid single key object")
        void shouldAcceptValidSingleKey() {
            // Given a single key object
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "RSA")
                    .add("kid", "test-key")
                    .build();

            // When validating
            boolean result = validator.validateJwksStructure(jwk);

            // Then should accept
            assertTrue(result, "Should accept valid single key structure");
        }

        @Test
        @DisplayName("Should reject null JWKS")
        void shouldRejectNullJwks() {
            // When validating null
            boolean result = validator.validateJwksStructure(null);

            // Then should reject
            assertFalse(result, "Should reject null JWKS");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "JWKS object is null");
        }

        @Test
        @DisplayName("Should reject JWKS with too many properties")
        void shouldRejectJwksWithTooManyProperties() {
            // Given JWKS with excessive properties
            JsonObjectBuilder builder = Json.createObjectBuilder();
            for (int i = 0; i < 15; i++) {
                builder.add("prop" + i, "value" + i);
            }
            JsonObject jwks = builder.build();

            // When validating
            boolean result = validator.validateJwksStructure(jwks);

            // Then should reject
            assertFalse(result, "Should reject JWKS with too many properties");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "excessive number of properties");
        }

        @Test
        @DisplayName("Should reject JWKS with too many keys")
        void shouldRejectJwksWithTooManyKeys() {
            // Given JWKS with too many keys
            JsonArrayBuilder keysBuilder = Json.createArrayBuilder();
            for (int i = 0; i < 60; i++) {
                keysBuilder.add(Json.createObjectBuilder()
                        .add("kty", "RSA")
                        .add("kid", "key" + i));
            }
            JsonObject jwks = Json.createObjectBuilder()
                    .add("keys", keysBuilder)
                    .build();

            // When validating
            boolean result = validator.validateJwksStructure(jwks);

            // Then should reject
            assertFalse(result, "Should reject JWKS with too many keys");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "exceeds maximum size");
        }

        @Test
        @DisplayName("Should reject JWKS with empty keys array")
        void shouldRejectJwksWithEmptyKeysArray() {
            // Given JWKS with empty keys array
            JsonObject jwks = Json.createObjectBuilder()
                    .add("keys", Json.createArrayBuilder())
                    .build();

            // When validating
            boolean result = validator.validateJwksStructure(jwks);

            // Then should reject
            assertFalse(result, "Should reject JWKS with empty keys array");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "keys array is empty");
        }
    }

    @Nested
    @DisplayName("Key Parameters Validation")
    class KeyParametersValidationTests {

        @Test
        @DisplayName("Should accept valid RSA key")
        void shouldAcceptValidRsaKey() {
            // Given a valid RSA key
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "RSA")
                    .add("kid", "test-key")
                    .add("alg", "RS256")
                    .add("use", "sig")
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should accept
            assertTrue(result, "Should accept valid RSA key");
        }

        @Test
        @DisplayName("Should accept valid EC key")
        void shouldAcceptValidEcKey() {
            // Given a valid EC key
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "EC")
                    .add("kid", "test-key")
                    .add("alg", "ES256")
                    .add("use", "sig")
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should accept
            assertTrue(result, "Should accept valid EC key");
        }

        @Test
        @DisplayName("Should reject key without kty")
        void shouldRejectKeyWithoutKty() {
            // Given a key without key type
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kid", "test-key")
                    .add("alg", "RS256")
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should reject
            assertFalse(result, "Should reject key without kty");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "missing required 'kty' parameter");
        }

        @Test
        @DisplayName("Should reject unsupported key type")
        void shouldRejectUnsupportedKeyType() {
            // Given a key with unsupported type
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "oct")
                    .add("kid", "test-key")
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should reject
            assertFalse(result, "Should reject unsupported key type");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unsupported key type");
        }

        @Test
        @DisplayName("Should reject key with oversized ID")
        void shouldRejectKeyWithOversizedId() {
            // Given a key with very long ID
            String longKeyId = "x".repeat(150);
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "RSA")
                    .add("kid", longKeyId)
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should reject
            assertFalse(result, "Should reject key with oversized ID");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "exceeds maximum length");
        }

        @Test
        @DisplayName("Should reject key with unsupported algorithm")
        void shouldRejectKeyWithUnsupportedAlgorithm() {
            // Given a key with unsupported algorithm
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "RSA")
                    .add("kid", "test-key")
                    .add("alg", "HS256") // HMAC algorithm should be rejected
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should reject
            assertFalse(result, "Should reject key with unsupported algorithm");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Invalid or unsupported algorithm");
        }

        @Test
        @DisplayName("Should accept key without optional parameters")
        void shouldAcceptKeyWithoutOptionalParameters() {
            // Given a minimal valid key
            JsonObject jwk = Json.createObjectBuilder()
                    .add("kty", "RSA")
                    .build();

            // When validating
            boolean result = validator.validateKeyParameters(jwk);

            // Then should accept
            assertTrue(result, "Should accept key with only required parameters");
        }
    }

    @Nested
    @DisplayName("Security Event Tracking")
    class SecurityEventTrackingTests {

        @Test
        @DisplayName("Should track validation failures")
        void shouldTrackValidationFailures() {
            // Given invalid key
            JsonObject invalidJwk = Json.createObjectBuilder()
                    .add("invalid", "key")
                    .build();

            // When validating
            validator.validateKeyParameters(invalidJwk);

            // Then should track security event
            assertTrue(securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED) > 0,
                    "Should track validation failures");
        }
    }
}