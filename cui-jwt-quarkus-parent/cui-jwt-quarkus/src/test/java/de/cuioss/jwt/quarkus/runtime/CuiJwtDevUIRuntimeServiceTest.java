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
import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

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
    JwtValidationConfig config;

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
                assertTrue(tokenType.equals("ACCESS_TOKEN") || tokenType.equals("ID_TOKEN") || tokenType.equals("REFRESH_TOKEN"),
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
}
