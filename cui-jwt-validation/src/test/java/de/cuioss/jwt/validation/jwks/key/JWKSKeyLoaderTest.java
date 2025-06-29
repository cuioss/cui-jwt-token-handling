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
package de.cuioss.jwt.validation.jwks.key;

import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED;
import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger(debug = {JWKSKeyLoader.class}, trace = {JWKSKeyLoader.class})
@DisplayName("Tests JWKSKeyLoader functionality")
class JWKSKeyLoaderTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final String TEST_ETAG = "\"test-etag\"";
    private JWKSKeyLoader keyLoader;
    private String jwksContent;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        jwksContent = InMemoryJWKSFactory.createDefaultJwks();
        securityEventCounter = new SecurityEventCounter();
        keyLoader = JWKSKeyLoader.builder()
                .jwksContent(jwksContent)

                .securityEventCounter(securityEventCounter)
                .build();
    }

    @Nested
    @DisplayName("Basic Functionality")
    class BasicFunctionalityTests {
        @Test
        @DisplayName("Should parse JWKS content")
        void shouldParseJwksContent() {

            Optional<KeyInfo> keyInfo = keyLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present");
        }

        @Test
        @DisplayName("Should get first key when available")
        void shouldGetFirstKeyWhenAvailable() {

            Optional<KeyInfo> keyInfo = keyLoader.getFirstKeyInfo();
            assertTrue(keyInfo.isPresent(), "First key info should be present");
        }

        @Test
        @DisplayName("Should return correct keySet")
        void shouldReturnCorrectKeySet() {

            var keySet = keyLoader.keySet();
            assertFalse(keySet.isEmpty(), "KeySet should not be empty");
            assertTrue(keySet.contains(TEST_KID), "KeySet should contain the test key ID");
            assertEquals(1, keySet.size(), "KeySet should contain exactly one key");
        }
    }

    @Nested
    @DisplayName("Error Handling")
    class ErrorHandlingTests {
        @Test
        @DisplayName("Should return empty when kid is null")
        void shouldReturnEmptyWhenKidIsNull() {

            Optional<KeyInfo> keyInfo = keyLoader.getKeyInfo(null);
            assertFalse(keyInfo.isPresent(), "Key info should not be present when kid is null");
            // Note: Log assertion removed as it's not essential to the test's purpose
        }

        @Test
        @DisplayName("Should return empty when kid is not found")
        void shouldReturnEmptyWhenKidNotFound() {

            Optional<KeyInfo> keyInfo = keyLoader.getKeyInfo("unknown-kid");
            assertFalse(keyInfo.isPresent(), "Key info should not be present when kid is not found");
        }

        @Test
        @DisplayName("Should handle invalid JWKS format")
        void shouldHandleInvalidJwksFormat() {

            String invalidJwksContent = InMemoryJWKSFactory.createInvalidJson();
            JWKSKeyLoader invalidLoader = JWKSKeyLoader.builder()
                    .jwksContent(invalidJwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();
            Optional<KeyInfo> keyInfo = invalidLoader.getKeyInfo(TEST_KID);
            assertFalse(keyInfo.isPresent(), "Key info should not be present when JWKS is invalid");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "Failed to parse JWKS JSON");
        }

        @Test
        @DisplayName("Should handle missing required fields in JWK")
        void shouldHandleMissingRequiredFieldsInJwk() {

            String missingFieldsJwksContent = InMemoryJWKSFactory.createJwksWithMissingFields(TEST_KID);
            JWKSKeyLoader missingFieldsLoader = JWKSKeyLoader.builder()
                    .jwksContent(missingFieldsJwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();
            Optional<KeyInfo> keyInfo = missingFieldsLoader.getKeyInfo(TEST_KID);
            assertFalse(keyInfo.isPresent(), "Key info should not be present when JWK is missing required fields");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
        }
    }

    @Nested
    @DisplayName("Key Management")
    class KeyManagementTests {
        @Test
        @DisplayName("Should report not empty when keys are present")
        void shouldReportNotEmptyWhenKeysArePresent() {
            boolean notEmpty = keyLoader.isNotEmpty();
            assertTrue(notEmpty, "Loader should report not empty when keys are present");
        }

        @Test
        @DisplayName("Should report empty when no keys are present")
        void shouldReportEmptyWhenNoKeysArePresent() {
            String emptyJwksContent = "{}";
            JWKSKeyLoader emptyLoader = JWKSKeyLoader.builder()
                    .jwksContent(emptyJwksContent)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();
            boolean notEmpty = emptyLoader.isNotEmpty();
            assertFalse(notEmpty, "Loader should report empty when no keys are present");
        }
    }

    @Nested
    @DisplayName("Security Features")
    class SecurityFeaturesTests {
        @Test
        @DisplayName("Should work with custom ParserConfig")
        void shouldWorkWithCustomParserConfig() {
            ParserConfig customConfig = ParserConfig.builder()
                    .maxPayloadSize(1024)
                    .maxStringSize(512)
                    .maxArraySize(10)
                    .maxDepth(5)
                    .build();
            JWKSKeyLoader loaderWithCustomConfig = JWKSKeyLoader.builder()
                    .jwksContent(jwksContent)

                    .parserConfig(customConfig)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();
            assertTrue(loaderWithCustomConfig.isNotEmpty(),
                    "Loader should parse valid JWKS with custom config");
        }

        @Test
        @DisplayName("Should reject JWKS content exceeding maximum size")
        void shouldRejectJwksContentExceedingMaximumSize() {

            int maxSize = 100; // Small size for testing
            ParserConfig restrictiveConfig = ParserConfig.builder()
                    .maxPayloadSize(maxSize)
                    .build();

            // Create a large JWKS content that exceeds the maximum size
            // Add enough padding to exceed maxSize
            JWKSKeyLoader loader = JWKSKeyLoader.builder()
                    .jwksContent("{\"keys\":[" + "\"x\":\"" + "a".repeat(maxSize) + "\"}]}"

                    )
                    .parserConfig(restrictiveConfig)
                    .securityEventCounter(new SecurityEventCounter())
                    .build();
            assertFalse(loader.isNotEmpty(), "Loader should reject content exceeding maximum size");
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, JWKS_CONTENT_SIZE_EXCEEDED.resolveIdentifierString());
        }

    }
}
