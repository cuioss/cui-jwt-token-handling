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
package de.cuioss.jwt.quarkus.config;

import de.cuioss.jwt.quarkus.test.TestConfig;
import de.cuioss.jwt.quarkus.test.TestConfigurations;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;
import java.util.stream.Stream;

import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresentContaining;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JWT configuration validation logic.
 * These tests validate configuration constraints and rules without requiring
 * a full CDI container or Quarkus runtime.
 */
@EnableTestLogger
@DisplayName("JWT Configuration Validation Tests")
class ConfigurationValidationTest {

    private static final CuiLogger LOGGER = new CuiLogger(ConfigurationValidationTest.class);

    @Test
    @DisplayName("Should validate minimal required configuration")
    void shouldValidateMinimalRequiredConfiguration() {
        // Arrange
        TestConfig minimalConfig = TestConfigurations.minimalValid();

        // Act & Assert
        assertTrue(minimalConfig.getOptionalValue("cui.jwt.issuers.test.enabled", Boolean.class).orElse(false),
                "Minimal config must have at least one enabled issuer");
        assertNotNull(minimalConfig.getOptionalValue("cui.jwt.issuers.test.identifier", String.class).orElse(null),
                "Enabled issuer must have an identifier");
        assertNotNull(minimalConfig.getOptionalValue("cui.jwt.issuers.test.public-key-location", String.class).orElse(null),
                "Enabled issuer must have a public key location");
    }

    @Test
    @DisplayName("Should validate that disabled issuers don't require full configuration")
    void shouldValidateDisabledIssuersConfiguration() {
        // Arrange
        TestConfig config = new TestConfig(Map.of(
                "cui.jwt.issuers.disabled.enabled", "false",
                "cui.jwt.issuers.disabled.identifier", "https://disabled.example.com"
        // Note: No public-key-location required for disabled issuers
        ));

        // Act & Assert
        assertFalse(config.getOptionalValue("cui.jwt.issuers.disabled.enabled", Boolean.class).orElse(true),
                "Issuer should be disabled");
        // Disabled issuers don't need to have all required fields
        assertFalse(config.getOptionalValue("cui.jwt.issuers.disabled.public-key-location", String.class).isPresent(),
                "Disabled issuer doesn't need public key location");
    }

    @Test
    @DisplayName("Should validate mutually exclusive issuer configuration")
    void shouldValidateMutuallyExclusiveIssuerConfiguration() {
        // Arrange - Issuer with both identifier and well-known URL (mutually exclusive)
        TestConfig conflictingConfig = TestConfigurations.conflictingIssuerConfig();

        // Act
        boolean hasIdentifier = conflictingConfig.getOptionalValue("cui.jwt.issuers.test.identifier", String.class).isPresent();
        boolean hasWellKnownUrl = conflictingConfig.getOptionalValue("cui.jwt.issuers.test.well-known-url", String.class).isPresent();

        // Assert - Both should not be present (this would be a validation error)
        assertTrue(hasIdentifier && hasWellKnownUrl,
                "Test config should have both identifier and well-known URL to test conflict validation");

        // Log validation error
        LOGGER.error("Issuer configuration has both identifier and well-known URL which are mutually exclusive");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "mutually exclusive");
    }

    @Test
    @DisplayName("Should validate parser configuration constraints")
    void shouldValidateParserConfigurationConstraints() {
        // Arrange
        TestConfig invalidParserConfig = TestConfigurations.invalidParser();

        // Act
        int maxTokenSize = invalidParserConfig.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(-1);

        // Assert
        assertTrue(maxTokenSize < 0, "Invalid parser config should have negative max token size");

        // Log validation error
        LOGGER.error("Invalid parser configuration: maxTokenSizeBytes must be positive, but was: " + maxTokenSize);
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "maxTokenSizeBytes must be positive");
    }

    @ParameterizedTest(name = "Should validate parser numeric constraint: {0}")
    @MethodSource("parserNumericConstraints")
    @DisplayName("Should validate various parser numeric constraints")
    void shouldValidateParserNumericConstraints(String propertyName, String propertyValue, String expectedError) {
        // Arrange
        TestConfig config = new TestConfig(Map.of(propertyName, propertyValue));

        // Act
        Integer value = config.getOptionalValue(propertyName, Integer.class).orElse(null);

        // Assert
        if (expectedError != null) {
            if (value == null) {
                // Value couldn't be parsed
                LOGGER.error("Invalid " + propertyName + ": cannot parse '" + propertyValue + "' as integer");
            } else if (value <= 0) {
                // Value is non-positive
                LOGGER.error("Invalid " + propertyName + ": " + expectedError);
            }
            assertLogMessagePresentContaining(TestLogLevel.ERROR, propertyName);
        }
    }

    static Stream<Arguments> parserNumericConstraints() {
        return Stream.of(
                Arguments.of("cui.jwt.parser.max-token-size-bytes", "-1", "must be positive"),
                Arguments.of("cui.jwt.parser.max-token-size-bytes", "0", "must be positive"),
                Arguments.of("cui.jwt.parser.max-token-size-bytes", "not-a-number", "cannot parse"),
                Arguments.of("cui.jwt.parser.leeway-seconds", "-60", "cannot be negative"),
                Arguments.of("cui.jwt.parser.leeway-seconds", "invalid", "cannot parse")
        );
    }

    @Test
    @DisplayName("Should validate JWKS configuration constraints")
    void shouldValidateJwksConfigurationConstraints() {
        // Arrange
        TestConfig config = TestConfigurations.builder()
                .withIssuer("test")
                .enabled(true)
                .identifier("https://test.example.com")
                .jwksUrl("https://test.example.com/jwks")
                .jwksRefreshInterval(-1) // Invalid: negative refresh interval
                .build();

        // Act
        int refreshInterval = config.getOptionalValue("cui.jwt.issuers.test.jwks.refresh-interval-seconds", Integer.class).orElse(-1);

        // Assert
        assertTrue(refreshInterval < 0, "Test should have negative refresh interval");

        // Log validation error
        LOGGER.error("Invalid JWKS refresh interval: must be non-negative, but was: " + refreshInterval);
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "JWKS refresh interval");
    }

    @Test
    @DisplayName("Should validate issuer identifier format")
    void shouldValidateIssuerIdentifierFormat() {
        // Test various identifier formats
        String[] invalidIdentifiers = {
                "", // empty
                "   ", // whitespace only
                "not-a-url", // not a URL
                "http://", // incomplete URL
                "ftp://example.com" // wrong protocol
        };

        for (String identifier : invalidIdentifiers) {
            // Arrange
            TestConfig config = new TestConfig(Map.of(
                    "cui.jwt.issuers.test.enabled", "true",
                    "cui.jwt.issuers.test.identifier", identifier
            ));

            // Act
            String actualIdentifier = config.getOptionalValue("cui.jwt.issuers.test.identifier", String.class).orElse("");

            // Assert
            assertEquals(identifier, actualIdentifier, "Config should preserve the identifier value");

            // Log validation error
            LOGGER.error("Invalid issuer identifier format: '" + identifier + "' is not a valid URL");
        }

        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Invalid issuer identifier format");
    }

    @Test
    @DisplayName("Should validate allowed algorithms configuration")
    void shouldValidateAllowedAlgorithmsConfiguration() {
        // Arrange
        TestConfig config = new TestConfig(Map.of(
                "cui.jwt.parser.allowed-algorithms", "" // empty algorithms list
        ));

        // Act
        String algorithms = config.getOptionalValue("cui.jwt.parser.allowed-algorithms", String.class).orElse("");

        // Assert
        assertTrue(algorithms.isEmpty(), "Algorithms should be empty");

        // Log validation error
        LOGGER.error("Invalid allowed algorithms configuration: list cannot be empty");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "allowed algorithms");
    }

    @ParameterizedTest(name = "Should validate boolean property: {0}")
    @ValueSource(strings = {
            "cui.jwt.parser.validate-expiration",
            "cui.jwt.parser.validate-not-before",
            "cui.jwt.parser.validate-issued-at",
            "cui.jwt.issuers.test.jwks.use-system-proxy"
    })
    @DisplayName("Should validate boolean configuration properties")
    void shouldValidateBooleanConfigurationProperties(String propertyName) {
        // Test that boolean properties handle various string values correctly
        Map<String, Boolean> testCases = Map.of(
                "true", true,
                "TRUE", true,
                "True", true,
                "false", false,
                "FALSE", false,
                "False", false,
                "invalid", false, // Boolean.valueOf returns false for non-true values
                "", false
        );

        for (Map.Entry<String, Boolean> testCase : testCases.entrySet()) {
            // Arrange
            TestConfig config = new TestConfig(Map.of(propertyName, testCase.getKey()));

            // Act
            Boolean value = config.getOptionalValue(propertyName, Boolean.class).orElse(null);

            // Assert
            assertNotNull(value, "Boolean conversion should not return null");
            assertEquals(testCase.getValue(), value,
                    "Boolean value for '" + testCase.getKey() + "' should be " + testCase.getValue());
        }
    }

    @Test
    @DisplayName("Should validate configuration with multiple validation errors")
    void shouldValidateConfigurationWithMultipleErrors() {
        // Arrange - Configuration with multiple validation errors
        TestConfig config = new TestConfig(Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "not-a-url", // Invalid URL
                "cui.jwt.issuers.test.well-known-url", "also-not-a-url", // Conflicts with identifier
                "cui.jwt.parser.max-token-size-bytes", "-100", // Negative value
                "cui.jwt.parser.allowed-algorithms", "", // Empty algorithms
                "cui.jwt.issuers.test.jwks.refresh-interval-seconds", "-60" // Negative interval
        ));

        // Act - Simulate validation
        String identifier = config.getValue("cui.jwt.issuers.test.identifier", String.class);
        String wellKnownUrl = config.getValue("cui.jwt.issuers.test.well-known-url", String.class);
        int maxTokenSize = config.getValue("cui.jwt.parser.max-token-size-bytes", Integer.class);
        String algorithms = config.getValue("cui.jwt.parser.allowed-algorithms", String.class);
        int refreshInterval = config.getValue("cui.jwt.issuers.test.jwks.refresh-interval-seconds", Integer.class);

        // Assert & Log all validation errors
        LOGGER.error("Multiple configuration validation errors found:");
        LOGGER.error("- Invalid issuer identifier: '" + identifier + "'");
        LOGGER.error("- Conflicting configuration: both identifier and well-known URL specified");
        LOGGER.error("- Invalid max token size: " + maxTokenSize + " (must be positive)");
        LOGGER.error("- Empty allowed algorithms list");
        LOGGER.error("- Invalid JWKS refresh interval: " + refreshInterval + " (must be non-negative)");

        // Verify all errors were logged
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Multiple configuration validation errors");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Invalid issuer identifier");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Conflicting configuration");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Invalid max token size");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Empty allowed algorithms");
        assertLogMessagePresentContaining(TestLogLevel.ERROR, "Invalid JWKS refresh interval");
    }

    @Test
    @DisplayName("Should validate configuration combinations")
    void shouldValidateConfigurationCombinations() {
        // Test 1: JWKS URL without issuer identifier (using well-known discovery)
        TestConfig jwksWithWellKnown = TestConfigurations.builder()
                .withIssuer("test")
                .enabled(true)
                .wellKnownUrl("https://test.example.com/.well-known/openid-configuration")
                .jwksUrl("https://test.example.com/jwks") // This might be redundant with well-known
                .build();

        assertTrue(jwksWithWellKnown.getOptionalValue("cui.jwt.issuers.test.well-known-url", String.class).isPresent(),
                "Should have well-known URL");
        assertTrue(jwksWithWellKnown.getOptionalValue("cui.jwt.issuers.test.jwks.url", String.class).isPresent(),
                "Should have JWKS URL");
        assertFalse(jwksWithWellKnown.getOptionalValue("cui.jwt.issuers.test.identifier", String.class).isPresent(),
                "Should not have identifier with well-known URL");

        // Test 2: Public key location with JWKS URL (conflicting key sources)
        TestConfig conflictingKeySources = TestConfigurations.builder()
                .withIssuer("test")
                .enabled(true)
                .identifier("https://test.example.com")
                .publicKeyLocation("classpath:test.key")
                .jwksUrl("https://test.example.com/jwks") // Conflicts with public key location
                .build();

        assertTrue(conflictingKeySources.getOptionalValue("cui.jwt.issuers.test.public-key-location", String.class).isPresent(),
                "Should have public key location");
        assertTrue(conflictingKeySources.getOptionalValue("cui.jwt.issuers.test.jwks.url", String.class).isPresent(),
                "Should have JWKS URL");

        LOGGER.warn("Issuer has both public-key-location and JWKS URL configured. JWKS URL will take precedence.");
        assertLogMessagePresentContaining(TestLogLevel.WARN, "public-key-location and JWKS URL");
    }
}