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
package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.test.TestConfig;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link TokenValidatorProducer} focusing on edge cases and error conditions.
 * These tests use a simple implementation of Config for testing purposes.
 */
@EnableTestLogger
class TokenValidatorProducerUnitTest {


    @Test
    @DisplayName("Should fail with negative maxTokenSizeBytes")
    void shouldFailWithNegativeMaxTokenSizeBytes() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.parser.max-token-size-bytes", "-1",
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        assertTrue(exception.getMessage().contains("maxTokenSizeBytes must be positive"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "maxTokenSizeBytes must be positive, but was: -1");
    }

    @Test
    @DisplayName("Should fail with zero maxTokenSizeBytes")
    void shouldFailWithZeroMaxTokenSizeBytes() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.parser.max-token-size-bytes", "0",
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        assertTrue(exception.getMessage().contains("maxTokenSizeBytes must be positive"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "maxTokenSizeBytes must be positive, but was: 0");
    }

    @Test
    @DisplayName("Should fail when no enabled issuers found")
    void shouldFailWhenNoEnabledIssuersFound() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "false",
                "cui.jwt.issuers.test.identifier", "https://test.example.com"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        assertEquals("No enabled issuers found in configuration", exception.getMessage());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "No enabled issuers found in configuration");
    }

    @Test
    @DisplayName("Should fail when issuer has both identifier and well-known URL")
    void shouldFailWhenIssuerHasBothIdentifierAndWellKnownUrl() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com",
                "cui.jwt.issuers.test.well-known-url", "https://test.example.com/.well-known/openid_configuration"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        assertTrue(exception.getMessage().contains("has both explicit identifier and well-known-url configured"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "has both explicit identifier and well-known-url configured");
    }

    @Test
    @DisplayName("Should fail when issuer has conflicting configuration")
    void shouldFailWhenIssuerHasConflictingConfiguration() {
        // Arrange - This configuration has multiple conflicts:
        // 1. identifier vs well-known-url (caught first)
        // 2. jwks.url vs well-known-url (would be caught if #1 wasn't there)
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com",
                "cui.jwt.issuers.test.jwks.url", "https://test.example.com/jwks",
                "cui.jwt.issuers.test.well-known-url", "https://test.example.com/.well-known/openid_configuration"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        // Should fail due to configuration conflicts - either identifier vs well-known or jwks vs well-known
        assertTrue(exception.getMessage().contains("has both") && exception.getMessage().contains("configured"),
                "Expected message about configuration conflict, but got: " + exception.getMessage());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "has both");
    }

    @Test
    @DisplayName("Should warn when enabled issuer has no identifier configuration")
    void shouldWarnWhenEnabledIssuerHasNoIdentifierConfiguration() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.valid.enabled", "true",
                "cui.jwt.issuers.valid.identifier", "https://valid.example.com",
                "cui.jwt.issuers.valid.public-key-location", "classpath:jwt-test.key"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert - Should succeed but warn about missing identifier
        assertDoesNotThrow(producer::produceTokenValidator);
        assertNotNull(producer.getTokenValidator());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Issuer 'test' is enabled but missing issuer identifier configuration");
    }

    @Test
    @DisplayName("Should fail when well-known endpoint is unreachable")
    void shouldFailWhenWellKnownEndpointIsUnreachable() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.well-known-url", "https://nonexistent.example.com/.well-known/openid_configuration"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        assertTrue(exception.getMessage().contains("Failed to discover issuer identifier from well-known URL"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "Failed to discover issuer identifier from well-known URL");
    }

    @Test
    @DisplayName("Should fail when well-known URL is malformed")
    void shouldFailWhenWellKnownUrlIsMalformed() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.well-known-url", "not-a-valid-url"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                producer::produceTokenValidator);
        assertTrue(exception.getMessage().contains("Failed to discover issuer identifier from well-known URL"));
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "Failed to discover issuer identifier from well-known URL");
    }

    @Test
    @DisplayName("Should handle missing property values with defaults")
    void shouldHandleMissingPropertyValuesWithDefaults() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com",
                "cui.jwt.issuers.test.jwks.url", "https://test.example.com/jwks"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act & Assert - Should use default configuration values
        assertDoesNotThrow(producer::produceTokenValidator);
        assertNotNull(producer.getTokenValidator());
    }

    @Test
    @DisplayName("Should return same instance on multiple calls")
    void shouldReturnSameInstanceOnMultipleCalls() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com",
                "cui.jwt.issuers.test.public-key-location", "classpath:jwt-test.key"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act
        var validator1 = producer.produceTokenValidator();
        var validator2 = producer.produceTokenValidator();

        // Assert
        assertSame(validator1, validator2);
    }

    @Test
    @DisplayName("Should handle mixed valid and invalid issuer configurations")
    void shouldHandleMixedValidAndInvalidIssuerConfigurations() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.valid.enabled", "true",
                "cui.jwt.issuers.valid.identifier", "https://valid.example.com",
                "cui.jwt.issuers.valid.public-key-location", "classpath:jwt-test.key",
                "cui.jwt.issuers.invalid.enabled", "true",
                "cui.jwt.issuers.disabled.enabled", "false",
                "cui.jwt.issuers.disabled.identifier", "https://disabled.example.com"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act
        producer.produceTokenValidator();

        // Assert
        assertNotNull(producer.getTokenValidator());
        assertEquals(1, producer.getIssuerConfigs().size());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Issuer 'invalid' is enabled but missing issuer identifier configuration");
    }

    @Test
    @DisplayName("Should discover issuer names from property scanning")
    void shouldDiscoverIssuerNamesFromPropertyScanning() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.issuers.keycloak-prod.enabled", "true",
                "cui.jwt.issuers.keycloak-prod.identifier", "https://keycloak-prod.example.com",
                "cui.jwt.issuers.keycloak-prod.public-key-location", "classpath:jwt-test.key",
                "cui.jwt.issuers.azure-ad.enabled", "true",
                "cui.jwt.issuers.azure-ad.identifier", "https://azure-ad.example.com",
                "cui.jwt.issuers.azure-ad.public-key-location", "classpath:jwt-test.key",
                "cui.jwt.issuers.local-dev.enabled", "false",
                "cui.jwt.issuers.local-dev.identifier", "https://local-dev.example.com"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act
        producer.produceTokenValidator();

        // Assert
        assertNotNull(producer.getTokenValidator());
        assertEquals(2, producer.getIssuerConfigs().size());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Discovered issuer names:");
    }

    @Test
    @DisplayName("Should validate configuration before creating TokenValidator")
    void shouldValidateConfigurationBeforeCreatingTokenValidator() {
        // Arrange
        Map<String, String> props = Map.of(
                "cui.jwt.parser.max-token-size-bytes", "4096",
                "cui.jwt.issuers.test.enabled", "true",
                "cui.jwt.issuers.test.identifier", "https://test.example.com",
                "cui.jwt.issuers.test.public-key-location", "classpath:jwt-test.key"
        );
        Config testConfig = new TestConfig(props);
        TokenValidatorProducer producer = new TokenValidatorProducer(testConfig);

        // Act
        producer.produceTokenValidator();

        // Assert
        assertNotNull(producer.getTokenValidator());
        assertNotNull(producer.getIssuerConfigs());
        assertFalse(producer.getIssuerConfigs().isEmpty());
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.INFO, "Validating JWT configuration");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Configuration validation successful");
    }
}