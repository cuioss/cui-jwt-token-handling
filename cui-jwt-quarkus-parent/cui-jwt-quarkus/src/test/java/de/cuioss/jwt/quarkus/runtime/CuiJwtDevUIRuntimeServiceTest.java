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
package de.cuioss.jwt.quarkus.runtime;

import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.jwt.quarkus.test.TestConfig;
import de.cuioss.jwt.quarkus.test.TestConfigurations;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for {@link CuiJwtDevUIRuntimeService}.
 * <p>
 * This test class provides comprehensive coverage of the runtime service functionality,
 * including validation status, JWKS status, configuration, token validation, and health
 * information. Tests use the Quarkus test framework with real dependencies.
 * </p>
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
@DisplayName("CuiJwtDevUIRuntimeService Tests")
class CuiJwtDevUIRuntimeServiceTest {

    @Inject
    CuiJwtDevUIRuntimeService service;

    @Inject
    Instance<TokenValidator> tokenValidatorInstance;

    @Inject
    Config config;

    @Test
    @DisplayName("Should inject service successfully")
    void shouldInjectServiceSuccessfully() {
        assertNotNull(service, "Service should be injected successfully");
        assertNotNull(config, "Config should be injected successfully");
        assertNotNull(tokenValidatorInstance, "TokenValidator instance should be injected successfully");
    }

    @Nested
    @DisplayName("Validation Status Tests")
    class ValidationStatusTests {

        @Test
        @DisplayName("Should return validation status with current configuration")
        void shouldReturnValidationStatusWithCurrentConfiguration() {
            // Act
            Map<String, Object> result = service.getValidationStatus();

            // Assert
            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("enabled"), "Enabled status should be present");
            assertNotNull(result.get("validatorPresent"), "Validator present status should be present");
            assertEquals("RUNTIME", result.get("status"), "Status should be RUNTIME");
            assertNotNull(result.get("statusMessage"), "Status message should be present");

            // The actual values depend on the test configuration
            boolean enabled = (Boolean) result.get("enabled");
            String statusMessage = (String) result.get("statusMessage");

            if (enabled) {
                assertEquals("JWT validation is active and ready", statusMessage,
                        "Status message should indicate active validation when enabled");
            } else {
                assertEquals("JWT validation is disabled", statusMessage,
                        "Status message should indicate disabled validation when disabled");
            }
        }
    }

    @Nested
    @DisplayName("JWKS Status Tests")
    class JwksStatusTests {

        @Test
        @DisplayName("Should return JWKS status with current configuration")
        void shouldReturnJwksStatusWithCurrentConfiguration() {
            // Act
            Map<String, Object> result = service.getJwksStatus();

            // Assert
            assertNotNull(result, "Result should not be null");
            assertEquals("RUNTIME", result.get("status"), "Status should be RUNTIME");
            assertNotNull(result.get("message"), "Message should be present");
            assertNotNull(result.get("issuersConfigured"), "Issuers configured count should be present");

            // Verify the issuer count matches the configuration
            int issuersConfigured = (Integer) result.get("issuersConfigured");
            assertTrue(issuersConfigured >= 0, "Issuers configured should be non-negative");
        }
    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should return configuration information")
        void shouldReturnConfigurationInformation() {
            // Act
            Map<String, Object> result = service.getConfiguration();

            // Assert
            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("enabled"), "Enabled status should be present");
            assertEquals(true, result.get("healthEnabled"), "Health should always be enabled");
            assertEquals(false, result.get("buildTime"), "Should not be build time");
            assertEquals(true, result.get("metricsEnabled"), "Metrics should always be enabled");
            assertNotNull(result.get("message"), "Message should be present");
            assertNotNull(result.get("issuersCount"), "Issuers count should be present");

            int issuersCount = (Integer) result.get("issuersCount");
            assertTrue(issuersCount >= 0, "Issuers count should be non-negative");
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should return error for null token")
        void shouldReturnErrorForNullToken() {
            // Act
            Map<String, Object> result = service.validateToken(null);

            // Assert
            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"), "Should have correct error message");
        }

        @Test
        @DisplayName("Should return error for empty token")
        void shouldReturnErrorForEmptyToken() {
            // Act
            Map<String, Object> result = service.validateToken("   ");

            // Assert
            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"), "Should have correct error message");
        }

        @Test
        @DisplayName("Should handle token validation attempts")
        void shouldHandleTokenValidationAttempts() {
            // Test with a token that might be processed as different token types
            // Act
            Map<String, Object> result = service.validateToken("not.a.valid.jwt");

            // Assert
            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");

            // The service tries access token, ID token, and refresh token validation
            // Depending on the token format, it might succeed as one of these types
            boolean isValid = (Boolean) result.get("valid");

            if (isValid) {
                // If validation succeeded, check that we have the expected fields
                assertNotNull(result.get("tokenType"), "Token type should be present for valid tokens");
                String tokenType = (String) result.get("tokenType");
                assertTrue("ACCESS_TOKEN".equals(tokenType) || "ID_TOKEN".equals(tokenType) || "REFRESH_TOKEN".equals(tokenType),
                        "Token type should be one of the expected types");
            } else {
                // If validation failed, check that we have an error message
                assertNotNull(result.get("error"), "Should have error message for invalid tokens");
                String error = (String) result.get("error");
                assertFalse(error.isEmpty(), "Error message should not be empty");
            }
        }
    }

    @Nested
    @DisplayName("Health Info Tests")
    class HealthInfoTests {

        @Test
        @DisplayName("Should return health information")
        void shouldReturnHealthInformation() {
            // Act
            Map<String, Object> result = service.getHealthInfo();

            // Assert
            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("configurationValid"), "Configuration valid status should be present");
            assertNotNull(result.get("tokenValidatorAvailable"), "Token validator available status should be present");
            assertEquals(true, result.get("securityCounterAvailable"), "Security counter should always be available");
            assertEquals("RUNTIME", result.get("overallStatus"), "Overall status should be RUNTIME");
            assertNotNull(result.get("message"), "Message should be present");
            assertNotNull(result.get("healthStatus"), "Health status should be present");

            String healthStatus = (String) result.get("healthStatus");
            assertTrue("UP".equals(healthStatus) || "DOWN".equals(healthStatus),
                    "Health status should be either UP or DOWN");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create service with null dependencies")
        void shouldCreateServiceWithNullDependencies() {
            // This tests the constructor's robustness
            assertDoesNotThrow(() -> new CuiJwtDevUIRuntimeService(null, null),
                    "Constructor should not throw exception with null dependencies");
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle validateToken with whitespace-only token")
        void shouldHandleWhitespaceOnlyToken() {
            // Act
            Map<String, Object> result = service.validateToken("   \t\n   ");

            // Assert
            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"),
                    "Should have correct error message for whitespace-only token");
        }

        @Test
        @DisplayName("Should handle validateToken with very long token")
        void shouldHandleVeryLongToken() {
            // Given - Create a very long token string

            // Act
            Map<String, Object> result = service.validateToken("a".repeat(10000)
            // Act
            );

            // Assert
            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");
            // The result can be either valid or invalid depending on the actual validation logic
        }

        @Test
        @DisplayName("Should handle validateToken with special characters")
        void shouldHandleTokenWithSpecialCharacters() {
            // Act
            Map<String, Object> result = service.validateToken("!@#$%^&*()_+-=[]{}|;':\",./<>?");

            // Assert
            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");
            // The result can be either valid or invalid depending on the actual validation logic
        }

        @Test
        @DisplayName("Should handle multiple consecutive calls to same method")
        void shouldHandleMultipleConsecutiveCalls() {
            // Act - Call the same method multiple times
            Map<String, Object> result1 = service.getValidationStatus();
            Map<String, Object> result2 = service.getValidationStatus();
            Map<String, Object> result3 = service.getValidationStatus();

            // Assert - All results should be consistent
            assertNotNull(result1, "First result should not be null");
            assertNotNull(result2, "Second result should not be null");
            assertNotNull(result3, "Third result should not be null");

            assertEquals(result1.get("enabled"), result2.get("enabled"),
                    "Enabled status should be consistent");
            assertEquals(result2.get("enabled"), result3.get("enabled"),
                    "Enabled status should be consistent");
            assertEquals(result1.get("status"), result2.get("status"),
                    "Status should be consistent");
        }

        @Test
        @DisplayName("Should handle getConfiguration method edge cases")
        void shouldHandleGetConfigurationEdgeCases() {
            // Act
            Map<String, Object> result = service.getConfiguration();

            // Assert - Test specific edge case values
            assertNotNull(result, "Result should not be null");
            assertEquals(true, result.get("healthEnabled"),
                    "Health should always be enabled in runtime");
            assertEquals(false, result.get("buildTime"),
                    "Should not be build time in runtime");
            assertEquals(true, result.get("metricsEnabled"),
                    "Metrics should always be enabled in runtime");

            // Test that issuersCount is always non-negative
            Object issuersCount = result.get("issuersCount");
            assertNotNull(issuersCount, "Issuers count should not be null");
            assertInstanceOf(Integer.class, issuersCount, "Issuers count should be Integer");
            assertTrue((Integer) issuersCount >= 0, "Issuers count should be non-negative");
        }

        @Test
        @DisplayName("Should handle getHealthInfo method consistency")
        void shouldHandleGetHealthInfoConsistency() {
            // Act - Call multiple times
            Map<String, Object> result1 = service.getHealthInfo();
            Map<String, Object> result2 = service.getHealthInfo();

            // Assert - Results should be consistent
            assertNotNull(result1, "First result should not be null");
            assertNotNull(result2, "Second result should not be null");

            assertEquals(result1.get("overallStatus"), result2.get("overallStatus"),
                    "Overall status should be consistent");
            assertEquals("RUNTIME", result1.get("overallStatus"),
                    "Overall status should be RUNTIME");
            assertEquals(true, result1.get("securityCounterAvailable"),
                    "Security counter should always be available");

            // Health status should be UP or DOWN
            String healthStatus1 = (String) result1.get("healthStatus");
            String healthStatus2 = (String) result2.get("healthStatus");
            assertTrue("UP".equals(healthStatus1) || "DOWN".equals(healthStatus1),
                    "Health status should be UP or DOWN");
            assertEquals(healthStatus1, healthStatus2, "Health status should be consistent");
        }

        @Test
        @DisplayName("Should handle getJwksStatus method edge cases")
        void shouldHandleGetJwksStatusEdgeCases() {
            // Act
            Map<String, Object> result = service.getJwksStatus();

            // Assert
            assertNotNull(result, "Result should not be null");
            assertEquals("RUNTIME", result.get("status"), "Status should be RUNTIME");
            assertNotNull(result.get("message"), "Message should not be null");
            assertNotNull(result.get("issuersConfigured"), "Issuers configured should not be null");

            // Test that issuersConfigured is always non-negative
            Object issuersConfigured = result.get("issuersConfigured");
            assertInstanceOf(Integer.class, issuersConfigured, "Issuers configured should be Integer");
            assertTrue((Integer) issuersConfigured >= 0, "Issuers configured should be non-negative");
        }
    }

    @Nested
    @DisplayName("TestConfig Integration Tests")
    @EnableTestLogger
    class TestConfigIntegrationTests {

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for empty configurations")
        void shouldDemonstrateTestConfigUsageForEmptyConfigurations() {
            // Arrange
            Config emptyConfig = TestConfigurations.empty();

            // Act & Assert - Test that TestConfig works properly for missing properties
            assertFalse(emptyConfig.getOptionalValue("cui.jwt.issuers.test.enabled", Boolean.class).isPresent(),
                    "Empty config should not have any issuer properties");
            assertFalse(emptyConfig.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).isPresent(),
                    "Empty config should not have any parser properties");

            // Test that getValue throws for missing properties
            assertThrows(NoSuchElementException.class,
                    () -> emptyConfig.getValue("cui.jwt.issuers.test.enabled", Boolean.class),
                    "getValue should throw for missing properties");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for disabled issuers")
        void shouldDemonstrateTestConfigUsageForDisabledIssuers() {
            // Arrange
            Config configWithDisabledIssuers = TestConfigurations.noEnabledIssuers();

            // Act & Assert - Test that TestConfig provides disabled issuer config
            assertEquals(false, configWithDisabledIssuers.getOptionalValue("cui.jwt.issuers.test.enabled", Boolean.class).orElse(true),
                    "Should have disabled issuer configuration");
            assertTrue(configWithDisabledIssuers.getOptionalValue("cui.jwt.issuers.test.identifier", String.class).isPresent(),
                    "Should have issuer identifier even when disabled");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for minimal valid setup")
        void shouldDemonstrateTestConfigUsageForMinimalValidSetup() {
            // Arrange
            Config minimalConfig = TestConfigurations.minimalValid();

            // Act & Assert - Test that TestConfig provides minimal valid configuration
            assertEquals(true, minimalConfig.getOptionalValue("cui.jwt.issuers.test.enabled", Boolean.class).orElse(false),
                    "Should have enabled issuer");
            assertEquals("https://test.example.com", minimalConfig.getOptionalValue("cui.jwt.issuers.test.identifier", String.class).orElse(null),
                    "Should have correct issuer identifier");
            assertEquals("classpath:jwt-test.key", minimalConfig.getOptionalValue("cui.jwt.issuers.test.public-key-location", String.class).orElse(null),
                    "Should have public key location");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for multiple issuers")
        void shouldDemonstrateTestConfigUsageForMultipleIssuers() {
            // Arrange
            Config multipleIssuersConfig = TestConfigurations.multipleIssuers();

            // Act & Assert - Test that TestConfig provides multiple issuer configuration
            assertEquals(true, multipleIssuersConfig.getOptionalValue("cui.jwt.issuers.primary.enabled", Boolean.class).orElse(false),
                    "Primary issuer should be enabled");
            assertEquals(true, multipleIssuersConfig.getOptionalValue("cui.jwt.issuers.secondary.enabled", Boolean.class).orElse(false),
                    "Secondary issuer should be enabled");
            assertEquals(false, multipleIssuersConfig.getOptionalValue("cui.jwt.issuers.disabled.enabled", Boolean.class).orElse(true),
                    "Disabled issuer should be disabled");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage with builder pattern")
        void shouldDemonstrateTestConfigUsageWithBuilderPattern() {
            // Arrange & Act
            Config customConfig = TestConfigurations.builder()
                    .withIssuer("custom")
                    .enabled(true)
                    .identifier("https://custom.example.com")
                    .publicKeyLocation("classpath:custom.key")
                    .jwksRefreshInterval(300)
                    .and()
                    .withParser()
                    .maxTokenSizeBytes(4096)
                    .leewaySeconds(60)
                    .validateExpiration(true)
                    .allowedAlgorithms("RS256,ES256")
                    .build();

            // Assert - Test that builder pattern creates proper configuration
            assertEquals(true, customConfig.getOptionalValue("cui.jwt.issuers.custom.enabled", Boolean.class).orElse(false),
                    "Custom issuer should be enabled");
            assertEquals("https://custom.example.com", customConfig.getOptionalValue("cui.jwt.issuers.custom.identifier", String.class).orElse(null),
                    "Should have custom issuer identifier");
            assertEquals(300, customConfig.getOptionalValue("cui.jwt.issuers.custom.jwks.refresh-interval-seconds", Integer.class).orElse(0),
                    "Should have custom JWKS refresh interval");
            assertEquals(4096, customConfig.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(0),
                    "Should have custom parser max token size");
            assertEquals("RS256,ES256", customConfig.getOptionalValue("cui.jwt.parser.allowed-algorithms", String.class).orElse(null),
                    "Should have custom allowed algorithms");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for malformed properties")
        void shouldDemonstrateTestConfigUsageForMalformedProperties() {
            // Arrange - Create config with malformed properties
            Config malformedConfig = new TestConfig(Map.of(
                    "cui.jwt.issuers.test.enabled", "not-a-boolean",
                    "cui.jwt.parser.max-token-size-bytes", "invalid-number",
                    "cui.jwt.parser.leeway-seconds", "",
                    "valid.property", "test-value"
            ));

            // Act & Assert - Test that TestConfig handles malformed values gracefully
            assertEquals(false, malformedConfig.getOptionalValue("cui.jwt.issuers.test.enabled", Boolean.class).orElse(true),
                    "Should return false for non-'true' boolean strings (Boolean.valueOf behavior)");
            assertFalse(malformedConfig.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).isPresent(),
                    "Should return empty Optional for invalid integer");
            assertFalse(malformedConfig.getOptionalValue("cui.jwt.parser.leeway-seconds", Integer.class).isPresent(),
                    "Should return empty Optional for empty integer");
            assertEquals("test-value", malformedConfig.getOptionalValue("valid.property", String.class).orElse(null),
                    "Should handle valid string properties correctly");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig predefined configurations")
        void shouldDemonstrateTestConfigPredefinedConfigurations() {
            // Test invalid parser configuration
            Config invalidParserConfig = TestConfigurations.invalidParser();
            assertEquals(-1, invalidParserConfig.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(0),
                    "Invalid parser config should have negative max token size");

            // Test JWKS URL configuration
            Config jwksConfig = TestConfigurations.withJwksUrl();
            assertEquals("https://test.example.com/jwks", jwksConfig.getOptionalValue("cui.jwt.issuers.test.jwks.url", String.class).orElse(null),
                    "JWKS config should have JWKS URL");

            // Test well-known URL configuration
            Config wellKnownConfig = TestConfigurations.withWellKnownUrl();
            assertEquals("https://test.example.com/.well-known/openid_configuration",
                    wellKnownConfig.getOptionalValue("cui.jwt.issuers.test.well-known-url", String.class).orElse(null),
                    "Well-known config should have well-known URL");

            // Test custom parser configuration
            Config customParserConfig = TestConfigurations.customParser();
            assertEquals(16384, customParserConfig.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(0),
                    "Custom parser config should have custom max token size");
            assertEquals("RS256,ES256", customParserConfig.getOptionalValue("cui.jwt.parser.allowed-algorithms", String.class).orElse(null),
                    "Custom parser config should have custom allowed algorithms");
        }
    }
}
