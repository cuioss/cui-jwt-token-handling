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

import de.cuioss.jwt.quarkus.config.IssuerConfigResolver;
import de.cuioss.jwt.quarkus.config.JwtPropertyKeys;
import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.jwt.quarkus.test.TestConfig;
import de.cuioss.jwt.quarkus.test.TestConfigurations;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.stream.Stream;


import jakarta.enterprise.inject.Instance;
import jakarta.enterprise.util.TypeLiteral;

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

    /**
     * Helper method to create a mock Instance<List<IssuerConfig>> for testing.
     * This resolves issuer configurations from the given TestConfig.
     */
    private Instance<List<IssuerConfig>> createMockIssuerConfigsInstance(TestConfig testConfig) {
        List<IssuerConfig> issuerConfigs;
        try {
            IssuerConfigResolver resolver = new IssuerConfigResolver(testConfig);
            issuerConfigs = resolver.resolveIssuerConfigs();
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Return empty list if configuration resolution fails
            issuerConfigs = List.of();
        }

        final List<IssuerConfig> finalIssuerConfigs = issuerConfigs;

        return new Instance<List<IssuerConfig>>() {
            @Override
            public List<IssuerConfig> get() {
                return finalIssuerConfigs;
            }

            @Override
            public boolean isResolvable() {
                return true;
            }

            // Minimal implementation - only implement required methods
            @Override
            public boolean isAmbiguous() {
                return false;
            }

            @Override
            public boolean isUnsatisfied() {
                return false;
            }

            @Override
            public Instance<List<IssuerConfig>> select(Annotation... qualifiers) {
                return this;
            }

            @Override
            public <U extends List<IssuerConfig>> Instance<U> select(Class<U> subtype, Annotation... qualifiers) {
                return (Instance<U>) this;
            }

            @Override
            public <U extends List<IssuerConfig>> Instance<U> select(TypeLiteral<U> subtype, Annotation... qualifiers) {
                return (Instance<U>) this;
            }

            @Override
            public Iterator<List<IssuerConfig>> iterator() {
                return List.of(get()).iterator();
            }

            @Override
            public void destroy(List<IssuerConfig> instance) {
            }

            @Override
            public Stream<List<IssuerConfig>> stream() {
                return Stream.of(get());
            }

            @Override
            public Iterable<Instance.Handle<List<IssuerConfig>>> handles() {
                return List.of();
            }

            @Override
            public Instance.Handle<List<IssuerConfig>> getHandle() {
                return null;
            }
        };
    }

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
            Map<String, Object> result = service.getValidationStatus();

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("enabled"), "Enabled status should be present");
            assertNotNull(result.get("validatorPresent"), "Validator present status should be present");
            assertEquals("RUNTIME", result.get("status"), "Status should be RUNTIME");
            assertNotNull(result.get("statusMessage"), "Status message should be present");

            boolean enabled = (Boolean) result.get("enabled");
            String statusMessage = (String) result.get("statusMessage");

            // Based on the current test configuration (JwtTestProfile), validation is enabled
            assertTrue(enabled, "JWT validation should be enabled with current test configuration");
            assertEquals("JWT validation is active and ready", statusMessage,
                    "Status message should indicate active validation when enabled");
        }

        @Test
        @DisplayName("Should correctly determine JWT enabled status based on issuer configuration")
        void shouldCorrectlyDetermineJwtEnabledStatusBasedOnIssuerConfiguration() {
            Map<String, Object> result = service.getValidationStatus();

            assertNotNull(result, "Result should not be null");

            // Test the actual configuration state - JWT is enabled in current test profile
            boolean enabled = (Boolean) result.get("enabled");
            assertTrue(enabled, "JWT should be enabled with current test configuration");

            String statusMessage = (String) result.get("statusMessage");
            assertEquals("JWT validation is active and ready", statusMessage,
                    "Status message should indicate active validation when enabled");

            // Verify validator presence is correctly reported
            boolean validatorPresent = (Boolean) result.get("validatorPresent");
            assertNotNull(validatorPresent, "Validator present status should be reported");
        }

        @Test
        @DisplayName("Should attempt token validation when JWT is enabled")
        void shouldAttemptTokenValidationWhenJwtIsEnabled() {
            // Test that token validation is attempted when JWT is enabled (current test configuration)
            String invalidJwtFormat = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.invalid-signature";

            Map<String, Object> result = service.validateToken(invalidJwtFormat);

            assertNotNull(result, "Result should not be null");

            // The validation was attempted (not disabled), check the actual result
            Boolean valid = (Boolean) result.get("valid");
            assertNotNull(valid, "Valid status should be present");

            if (valid) {
                // Token was successfully validated (possibly as refresh token)
                assertNotNull(result.get("tokenType"), "Token type should be present for valid tokens");
            } else {
                // Token validation failed, but validation was attempted
                String error = (String) result.get("error");
                assertNotNull(error, "Should have error message");
                assertNotEquals("JWT validation is disabled", error, "Error should not be 'disabled' message when JWT is enabled");

                // Verify no token type or claims are returned for invalid tokens
                assertNull(result.get("tokenType"), "Token type should not be present for invalid tokens");
                assertNull(result.get("claims"), "Claims should not be present for invalid tokens");
            }
        }
    }

    @Nested
    @DisplayName("JWKS Status Tests")
    class JwksStatusTests {

        @Test
        @DisplayName("Should return JWKS status with current configuration")
        void shouldReturnJwksStatusWithCurrentConfiguration() {
            Map<String, Object> result = service.getJwksStatus();

            assertNotNull(result, "Result should not be null");
            assertEquals("RUNTIME", result.get("status"), "Status should be RUNTIME");
            assertNotNull(result.get("message"), "Message should be present");
            assertNotNull(result.get("issuersConfigured"), "Issuers configured count should be present");

            int issuersConfigured = (Integer) result.get("issuersConfigured");
            assertTrue(issuersConfigured >= 0, "Issuers configured should be non-negative");
        }

        @Test
        @DisplayName("Should correctly count configured issuers including disabled ones")
        void shouldCorrectlyCountConfiguredIssuersIncludingDisabledOnes() {
            Map<String, Object> result = service.getJwksStatus();

            assertNotNull(result, "Result should not be null");

            // Based on JwtTestProfile: "default" issuer is enabled, "test-issuer" is disabled
            // The JWKS status should count all configured issuers, not just enabled ones
            int issuersConfigured = (Integer) result.get("issuersConfigured");
            assertTrue(issuersConfigured >= 1, "Should have at least one configured issuer");

            String message = (String) result.get("message");
            assertNotNull(message, "Message should be present");

            // Verify the message reflects the actual configuration state
            if (issuersConfigured > 0) {
                assertTrue(message.contains("issuer") || message.contains("configured"),
                        "Message should mention issuers or configuration");
            }
        }

        @Test
        @DisplayName("Should return consistent JWKS status on multiple calls")
        void shouldReturnConsistentJwksStatusOnMultipleCalls() {
            Map<String, Object> result1 = service.getJwksStatus();
            Map<String, Object> result2 = service.getJwksStatus();

            assertNotNull(result1, "First result should not be null");
            assertNotNull(result2, "Second result should not be null");

            assertEquals(result1.get("status"), result2.get("status"), "Status should be consistent");
            assertEquals(result1.get("issuersConfigured"), result2.get("issuersConfigured"),
                    "Issuers configured count should be consistent");
            assertNotNull(result1.get("message"), "First message should not be null");
            assertNotNull(result2.get("message"), "Second message should not be null");
        }
    }

    @Nested
    @DisplayName("Configuration Tests")
    class ConfigurationTests {

        @Test
        @DisplayName("Should return configuration information")
        void shouldReturnConfigurationInformation() {
            Map<String, Object> result = service.getConfiguration();

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

        @Test
        @DisplayName("Should have consistent configuration structure")
        void shouldHaveConsistentConfigurationStructure() {
            Map<String, Object> result = service.getConfiguration();

            assertNotNull(result, "Result should not be null");
            assertTrue(result.containsKey("enabled"), "Should contain enabled key");
            assertTrue(result.containsKey("healthEnabled"), "Should contain healthEnabled key");
            assertTrue(result.containsKey("buildTime"), "Should contain buildTime key");
            assertTrue(result.containsKey("metricsEnabled"), "Should contain metricsEnabled key");
            assertTrue(result.containsKey("message"), "Should contain message key");
            assertTrue(result.containsKey("issuersCount"), "Should contain issuersCount key");

            // Verify data types
            assertInstanceOf(Boolean.class, result.get("enabled"), "Enabled should be Boolean");
            assertInstanceOf(Boolean.class, result.get("healthEnabled"), "HealthEnabled should be Boolean");
            assertInstanceOf(Boolean.class, result.get("buildTime"), "BuildTime should be Boolean");
            assertInstanceOf(Boolean.class, result.get("metricsEnabled"), "MetricsEnabled should be Boolean");
            assertInstanceOf(String.class, result.get("message"), "Message should be String");
            assertInstanceOf(Integer.class, result.get("issuersCount"), "IssuersCount should be Integer");
        }

        @Test
        @DisplayName("Should return consistent configuration on multiple calls")
        void shouldReturnConsistentConfigurationOnMultipleCalls() {
            Map<String, Object> result1 = service.getConfiguration();
            Map<String, Object> result2 = service.getConfiguration();

            assertNotNull(result1, "First result should not be null");
            assertNotNull(result2, "Second result should not be null");

            assertEquals(result1.get("enabled"), result2.get("enabled"), "Enabled should be consistent");
            assertEquals(result1.get("healthEnabled"), result2.get("healthEnabled"), "HealthEnabled should be consistent");
            assertEquals(result1.get("buildTime"), result2.get("buildTime"), "BuildTime should be consistent");
            assertEquals(result1.get("metricsEnabled"), result2.get("metricsEnabled"), "MetricsEnabled should be consistent");
            assertEquals(result1.get("issuersCount"), result2.get("issuersCount"), "IssuersCount should be consistent");
            assertNotNull(result1.get("message"), "First message should not be null");
            assertNotNull(result2.get("message"), "Second message should not be null");
        }
    }

    @Nested
    @DisplayName("Token Validation Tests")
    class TokenValidationTests {

        @Test
        @DisplayName("Should return error for null token")
        void shouldReturnErrorForNullToken() {
            Map<String, Object> result = service.validateToken(null);

            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"), "Should have correct error message");
        }

        @Test
        @DisplayName("Should return error for empty token")
        void shouldReturnErrorForEmptyToken() {
            Map<String, Object> result = service.validateToken("   ");

            assertNotNull(result, "Result should not be null");
            assertEquals(false, result.get("valid"), "Should be invalid");
            assertEquals("Token is empty or null", result.get("error"), "Should have correct error message");
        }

        @Test
        @DisplayName("Should attempt access token validation when JWT is enabled")
        void shouldAttemptAccessTokenValidationWhenJwtIsEnabled() {
            // Create a service with enabled JWT configuration to test the validation logic
            TestConfig enabledConfig = TestConfigurations.withJwksUrl();
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> issuerConfigs = createMockIssuerConfigsInstance(enabledConfig).get();
            CuiJwtDevUIRuntimeService enabledService = new CuiJwtDevUIRuntimeService(validator, issuerConfigs);

            // Test with an invalid access token to see the validation attempt behavior
            // This tests that validation is attempted (not just disabled)
            String testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid-payload.invalid-signature";
            Map<String, Object> result = enabledService.validateToken(testToken);

            assertNotNull(result, "Result should not be null");

            // The main test is that validation was attempted (not just disabled)
            // If JWT is enabled, validation should be attempted regardless of the result
            String error = (String) result.get("error");
            if (error != null) {
                assertNotEquals("JWT validation is disabled", error, "Error should not be 'disabled' message when JWT is enabled");
            }

            // Since we only validate access tokens now, invalid tokens should be rejected
            Boolean isValid = (Boolean) result.get("valid");
            if (isValid) {
                // If valid, should have ACCESS_TOKEN type and claims
                assertEquals("ACCESS_TOKEN", result.get("tokenType"), "Valid token should be ACCESS_TOKEN type");
                assertNotNull(result.get("claims"), "Valid access token should have claims");
                assertNotNull(result.get("issuer"), "Valid access token should have issuer");
            } else {
                // If invalid, should have error message but not token type
                assertNotNull(error, "Invalid token should have error message");
                assertNull(result.get("tokenType"), "Invalid token should not have token type");
                assertNull(result.get("claims"), "Invalid token should not have claims");
            }
        }
    }

    @Nested
    @DisplayName("Health Info Tests")
    class HealthInfoTests {

        @Test
        @DisplayName("Should return health information")
        void shouldReturnHealthInformation() {
            Map<String, Object> result = service.getHealthInfo();

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

        @Test
        @DisplayName("Should determine health status based on configuration and validator availability")
        void shouldDetermineHealthStatusBasedOnConfigurationAndValidatorAvailability() {
            Map<String, Object> result = service.getHealthInfo();

            assertNotNull(result, "Result should not be null");

            boolean configValid = (Boolean) result.get("configurationValid");
            boolean validatorAvailable = (Boolean) result.get("tokenValidatorAvailable");
            String healthStatus = (String) result.get("healthStatus");
            String message = (String) result.get("message");

            // Test the health determination logic
            if (configValid && validatorAvailable) {
                assertEquals("UP", healthStatus, "Health should be UP when config is valid and validator is available");
                assertTrue(message.contains("healthy") || message.contains("operational"),
                        "Message should indicate healthy state");
            } else if (configValid) {
                assertEquals("DOWN", healthStatus, "Health should be DOWN when config is valid but validator unavailable");
                assertTrue(message.contains("validator") && message.contains("not available"),
                        "Message should indicate validator unavailability");
            } else {
                assertEquals("DOWN", healthStatus, "Health should be DOWN when config is invalid");
                assertTrue(message.contains("disabled") || message.contains("misconfigured"),
                        "Message should indicate configuration issues");
            }

            // Security counter should always be available in runtime
            assertEquals(true, result.get("securityCounterAvailable"),
                    "Security counter should always be available in runtime");
        }

        @Test
        @DisplayName("Should return consistent health info on multiple calls")
        void shouldReturnConsistentHealthInfoOnMultipleCalls() {
            Map<String, Object> result1 = service.getHealthInfo();
            Map<String, Object> result2 = service.getHealthInfo();

            assertNotNull(result1, "First result should not be null");
            assertNotNull(result2, "Second result should not be null");

            assertEquals(result1.get("configurationValid"), result2.get("configurationValid"),
                    "ConfigurationValid should be consistent");
            assertEquals(result1.get("tokenValidatorAvailable"), result2.get("tokenValidatorAvailable"),
                    "TokenValidatorAvailable should be consistent");
            assertEquals(result1.get("securityCounterAvailable"), result2.get("securityCounterAvailable"),
                    "SecurityCounterAvailable should be consistent");
            assertEquals(result1.get("overallStatus"), result2.get("overallStatus"),
                    "OverallStatus should be consistent");
            assertEquals(result1.get("healthStatus"), result2.get("healthStatus"),
                    "HealthStatus should be consistent");
            assertNotNull(result1.get("message"), "First message should not be null");
            assertNotNull(result2.get("message"), "Second message should not be null");
        }
    }

    @Nested
    @DisplayName("Configuration Scenarios Tests")
    class ConfigurationScenariosTests {

        @Test
        @DisplayName("Should handle service with enabled issuer configuration")
        void shouldHandleServiceWithEnabledIssuerConfiguration() {
            // Create a service with enabled issuer configuration
            TestConfig enabledConfig = TestConfigurations.withJwksUrl();
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> issuerConfigs = createMockIssuerConfigsInstance(enabledConfig).get();
            CuiJwtDevUIRuntimeService testService = new CuiJwtDevUIRuntimeService(validator, issuerConfigs);

            Map<String, Object> validationStatus = testService.getValidationStatus();
            Map<String, Object> configuration = testService.getConfiguration();

            // With enabled issuer, JWT should be enabled
            assertTrue((Boolean) validationStatus.get("enabled"), "JWT should be enabled with valid issuer configuration");
            assertTrue((Integer) configuration.get("issuersCount") > 0, "Should have at least one enabled issuer");
        }

        @Test
        @DisplayName("Should handle service with no enabled issuers")
        void shouldHandleServiceWithNoEnabledIssuers() {
            // Create a service with no enabled issuers
            TestConfig noIssuersConfig = TestConfigurations.noEnabledIssuers();
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> issuerConfigs = createMockIssuerConfigsInstance(noIssuersConfig).get();
            CuiJwtDevUIRuntimeService testService = new CuiJwtDevUIRuntimeService(validator, issuerConfigs);

            Map<String, Object> validationStatus = testService.getValidationStatus();
            Map<String, Object> configuration = testService.getConfiguration();

            // With no enabled issuers, JWT should be disabled
            assertFalse((Boolean) validationStatus.get("enabled"), "JWT should be disabled with no enabled issuers");
            assertEquals(0, (Integer) configuration.get("issuersCount"), "Should have zero enabled issuers");
            assertEquals("JWT validation is disabled", validationStatus.get("statusMessage"));
        }

        @Test
        @DisplayName("Should handle service with multiple issuers")
        void shouldHandleServiceWithMultipleIssuers() {
            // Create a service with multiple issuers
            TestConfig multipleIssuersConfig = TestConfigurations.multipleIssuers();
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> issuerConfigs = createMockIssuerConfigsInstance(multipleIssuersConfig).get();
            CuiJwtDevUIRuntimeService testService = new CuiJwtDevUIRuntimeService(validator, issuerConfigs);

            Map<String, Object> configuration = testService.getConfiguration();
            Map<String, Object> jwksStatus = testService.getJwksStatus();

            // Should count multiple issuers
            int issuersCount = (Integer) configuration.get("issuersCount");
            int issuersConfigured = (Integer) jwksStatus.get("issuersConfigured");

            assertTrue(issuersCount >= 2, "Should have multiple enabled issuers");
            assertTrue(issuersConfigured >= 2, "Should have multiple configured issuers");
        }

        @Test
        @DisplayName("Should validate token rejection with disabled JWT")
        void shouldValidateTokenRejectionWithDisabledJwt() {
            // Create a service with no enabled issuers
            TestConfig disabledConfig = TestConfigurations.noEnabledIssuers();
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> issuerConfigs = createMockIssuerConfigsInstance(disabledConfig).get();
            CuiJwtDevUIRuntimeService testService = new CuiJwtDevUIRuntimeService(validator, issuerConfigs);

            // Try to validate a token
            String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature";
            Map<String, Object> result = testService.validateToken(token);

            // Should be rejected due to disabled JWT
            assertFalse((Boolean) result.get("valid"), "Token should be invalid when JWT is disabled");
            assertEquals("JWT validation is disabled", result.get("error"));
        }

        @Test
        @DisplayName("Should determine health based on different configurations")
        void shouldDetermineHealthBasedOnDifferentConfigurations() {
            // Test with enabled configuration
            TestConfig enabledConfig = TestConfigurations.withJwksUrl();
            TokenValidator enabledValidator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> enabledIssuerConfigs = createMockIssuerConfigsInstance(enabledConfig).get();
            CuiJwtDevUIRuntimeService enabledService = new CuiJwtDevUIRuntimeService(enabledValidator, enabledIssuerConfigs);

            Map<String, Object> enabledHealth = enabledService.getHealthInfo();
            assertTrue((Boolean) enabledHealth.get("configurationValid"), "Configuration should be valid with enabled issuer");

            // Test with disabled configuration
            TestConfig disabledConfig = TestConfigurations.noEnabledIssuers();
            TokenValidator disabledValidator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            List<IssuerConfig> disabledIssuerConfigs = createMockIssuerConfigsInstance(disabledConfig).get();
            CuiJwtDevUIRuntimeService disabledService = new CuiJwtDevUIRuntimeService(disabledValidator, disabledIssuerConfigs);

            Map<String, Object> disabledHealth = disabledService.getHealthInfo();
            assertFalse((Boolean) disabledHealth.get("configurationValid"), "Configuration should be invalid with no enabled issuers");
            assertEquals("DOWN", disabledHealth.get("healthStatus"), "Health should be DOWN with invalid configuration");
        }
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create service with minimal dependencies")
        void shouldCreateServiceWithMinimalDependencies() {
            // This tests the constructor's robustness with empty issuer configs
            assertDoesNotThrow(() -> new CuiJwtDevUIRuntimeService(null, List.of()),
                    "Constructor should not throw exception with null tokenValidator and empty issuerConfigs");
        }

        @Test
        @DisplayName("Should create service with valid dependencies")
        void shouldCreateServiceWithValidDependencies() {
            // Test constructor with actual dependencies
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            CuiJwtDevUIRuntimeService testService = new CuiJwtDevUIRuntimeService(validator, List.of());
            assertNotNull(testService, "Service should be created successfully with valid dependencies");

            // Verify the service can perform basic operations
            assertDoesNotThrow(() -> testService.getValidationStatus(),
                    "Service should be able to get validation status");
            assertDoesNotThrow(() -> testService.getConfiguration(),
                    "Service should be able to get configuration");
        }

        @Test
        @DisplayName("Should handle mixed null and valid dependencies")
        void shouldHandleMixedNullAndValidDependencies() {
            // Test with null tokenValidator but valid issuerConfigs
            assertDoesNotThrow(() -> new CuiJwtDevUIRuntimeService(null, List.of()),
                    "Constructor should handle null tokenValidator with empty issuerConfigs");

            // Test with valid tokenValidator and empty issuerConfigs
            TokenValidator validator = tokenValidatorInstance.isResolvable() ? tokenValidatorInstance.get() : null;
            assertDoesNotThrow(() -> new CuiJwtDevUIRuntimeService(validator, List.of()),
                    "Constructor should handle valid tokenValidator with empty issuerConfigs");

            // Verify services can be created in both scenarios
            CuiJwtDevUIRuntimeService service1 = new CuiJwtDevUIRuntimeService(null, List.of());
            CuiJwtDevUIRuntimeService service2 = new CuiJwtDevUIRuntimeService(validator, List.of());

            assertNotNull(service1, "Service should be created with null tokenValidator");
            assertNotNull(service2, "Service should be created with valid tokenValidator");
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
            Map<String, Object> result = service.validateToken("a".repeat(10000));

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");
        }

        @Test
        @DisplayName("Should handle validateToken with special characters")
        void shouldHandleTokenWithSpecialCharacters() {
            Map<String, Object> result = service.validateToken("!@#$%^&*()_+-=[]{}|;':\",./<>?");

            assertNotNull(result, "Result should not be null");
            assertNotNull(result.get("valid"), "Valid status should be present");
        }

        @Test
        @DisplayName("Should handle multiple consecutive calls to same method")
        void shouldHandleMultipleConsecutiveCalls() {
            Map<String, Object> result1 = service.getValidationStatus();
            Map<String, Object> result2 = service.getValidationStatus();
            Map<String, Object> result3 = service.getValidationStatus();

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
            Map<String, Object> result = service.getConfiguration();

            assertNotNull(result, "Result should not be null");
            assertEquals(true, result.get("healthEnabled"),
                    "Health should always be enabled in runtime");
            assertEquals(false, result.get("buildTime"),
                    "Should not be build time in runtime");
            assertEquals(true, result.get("metricsEnabled"),
                    "Metrics should always be enabled in runtime");

            Object issuersCount = result.get("issuersCount");
            assertNotNull(issuersCount, "Issuers count should not be null");
            assertInstanceOf(Integer.class, issuersCount, "Issuers count should be Integer");
            assertTrue((Integer) issuersCount >= 0, "Issuers count should be non-negative");
        }

        @Test
        @DisplayName("Should handle getHealthInfo method consistency")
        void shouldHandleGetHealthInfoConsistency() {
            Map<String, Object> result1 = service.getHealthInfo();
            Map<String, Object> result2 = service.getHealthInfo();

            assertNotNull(result1, "First result should not be null");
            assertNotNull(result2, "Second result should not be null");

            assertEquals(result1.get("overallStatus"), result2.get("overallStatus"),
                    "Overall status should be consistent");
            assertEquals("RUNTIME", result1.get("overallStatus"),
                    "Overall status should be RUNTIME");
            assertEquals(true, result1.get("securityCounterAvailable"),
                    "Security counter should always be available");

            String healthStatus1 = (String) result1.get("healthStatus");
            String healthStatus2 = (String) result2.get("healthStatus");
            assertTrue("UP".equals(healthStatus1) || "DOWN".equals(healthStatus1),
                    "Health status should be UP or DOWN");
            assertEquals(healthStatus1, healthStatus2, "Health status should be consistent");
        }

        @Test
        @DisplayName("Should handle getJwksStatus method edge cases")
        void shouldHandleGetJwksStatusEdgeCases() {
            Map<String, Object> result = service.getJwksStatus();

            assertNotNull(result, "Result should not be null");
            assertEquals("RUNTIME", result.get("status"), "Status should be RUNTIME");
            assertNotNull(result.get("message"), "Message should not be null");
            assertNotNull(result.get("issuersConfigured"), "Issuers configured should not be null");

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
            Config emptyConfig = TestConfigurations.empty();
            assertFalse(emptyConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).isPresent(),
                    "Empty config should not have any issuer properties");
            assertFalse(emptyConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).isPresent(),
                    "Empty config should not have any parser properties");

            // Test that getValue throws for missing properties
            assertThrows(NoSuchElementException.class,
                    () -> emptyConfig.getValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class),
                    "getValue should throw for missing properties");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for disabled issuers")
        void shouldDemonstrateTestConfigUsageForDisabledIssuers() {
            Config configWithDisabledIssuers = TestConfigurations.noEnabledIssuers();
            assertEquals(false, configWithDisabledIssuers.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).orElse(true),
                    "Should have disabled issuer configuration");
            assertTrue(configWithDisabledIssuers.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), String.class).isPresent(),
                    "Should have issuer identifier even when disabled");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for minimal valid setup")
        void shouldDemonstrateTestConfigUsageForMinimalValidSetup() {
            Config minimalConfig = TestConfigurations.minimalValid();
            assertEquals(true, minimalConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).orElse(false),
                    "Should have enabled issuer");
            assertEquals("https://test.example.com", minimalConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("test"), String.class).orElse(null),
                    "Should have correct issuer identifier");
            assertEquals("classpath:keys/test_public_key.jwks", minimalConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.JWKS_FILE_PATH.formatted("test"), String.class).orElse(null),
                    "Should have public key location");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for multiple issuers")
        void shouldDemonstrateTestConfigUsageForMultipleIssuers() {
            Config multipleIssuersConfig = TestConfigurations.multipleIssuers();
            assertEquals(true, multipleIssuersConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("primary"), Boolean.class).orElse(false),
                    "Primary issuer should be enabled");
            assertEquals(true, multipleIssuersConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("secondary"), Boolean.class).orElse(false),
                    "Secondary issuer should be enabled");
            assertEquals(false, multipleIssuersConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("disabled"), Boolean.class).orElse(true),
                    "Disabled issuer should be disabled");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage with builder pattern")
        void shouldDemonstrateTestConfigUsageWithBuilderPattern() {
            Config customConfig = TestConfigurations.builder()
                    .withIssuer("custom")
                    .enabled(true)
                    .identifier("https://custom.example.com")
                    .publicKeyLocation("classpath:custom.key")
                    .jwksRefreshInterval(300)
                    .and()
                    .withParser()
                    .maxTokenSize(4096)
                    .maxPayloadSize(4096)
                    .maxStringSize(2048)
                    .maxArraySize(64)
                    .maxDepth(10)
                    .build();

            assertEquals(true, customConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("custom"), Boolean.class).orElse(false),
                    "Custom issuer should be enabled");
            assertEquals("https://custom.example.com", customConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ISSUER_IDENTIFIER.formatted("custom"), String.class).orElse(null),
                    "Should have custom issuer identifier");
            assertEquals(300, customConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.REFRESH_INTERVAL_SECONDS.formatted("custom"), Integer.class).orElse(0),
                    "Should have custom JWKS refresh interval");
            assertEquals(4096, customConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).orElse(0),
                    "Should have custom parser max token size");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig utility usage for malformed properties")
        void shouldDemonstrateTestConfigUsageForMalformedProperties() {
            Config malformedConfig = new TestConfig(Map.of(
                    JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), "not-a-boolean",
                    JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, "invalid-number",
                    JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, "",
                    "valid.property", "test-value"
            ));

            assertEquals(false, malformedConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.ENABLED.formatted("test"), Boolean.class).orElse(true),
                    "Should return false for non-'true' boolean strings (Boolean.valueOf behavior)");
            assertFalse(malformedConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).isPresent(),
                    "Should return empty Optional for invalid integer");
            assertFalse(malformedConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_PAYLOAD_SIZE, Integer.class).isPresent(),
                    "Should return empty Optional for empty integer");
            assertEquals("test-value", malformedConfig.getOptionalValue("valid.property", String.class).orElse(null),
                    "Should handle valid string properties correctly");
        }

        @Test
        @DisplayName("Should demonstrate TestConfig predefined configurations")
        void shouldDemonstrateTestConfigPredefinedConfigurations() {
            // Test invalid parser configuration
            Config invalidParserConfig = TestConfigurations.invalidParser();
            assertEquals(-1, invalidParserConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).orElse(0),
                    "Invalid parser config should have negative max token size");

            // Test JWKS URL configuration
            Config jwksConfig = TestConfigurations.withJwksUrl();
            assertEquals("https://test.example.com/jwks", jwksConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.JWKS_URL.formatted("test"), String.class).orElse(null),
                    "JWKS config should have JWKS URL");

            // Test well-known URL configuration
            Config wellKnownConfig = TestConfigurations.withWellKnownUrl();
            assertEquals("https://test.example.com/.well-known/openid_configuration",
                    wellKnownConfig.getOptionalValue(JwtPropertyKeys.ISSUERS.WELL_KNOWN_URL.formatted("test"), String.class).orElse(null),
                    "Well-known config should have well-known URL");

            // Test custom parser configuration
            Config customParserConfig = TestConfigurations.customParser();
            assertEquals(16384, customParserConfig.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE, Integer.class).orElse(0),
                    "Custom parser config should have custom max token size");
        }
    }
}
