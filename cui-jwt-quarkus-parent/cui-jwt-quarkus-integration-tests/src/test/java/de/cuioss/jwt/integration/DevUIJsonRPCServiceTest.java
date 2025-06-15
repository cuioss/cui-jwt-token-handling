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
package de.cuioss.jwt.integration;

import de.cuioss.jwt.quarkus.runtime.CuiJwtDevUIRuntimeService;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jakarta.inject.Inject;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for the Dev UI JsonRPC runtime service.
 * <p>
 * This test focuses on verifying the backend service that powers the Dev UI components.
 * It tests the service directly in runtime mode to ensure proper wiring and basic functionality.
 * </p>
 */
@QuarkusTest
class DevUIJsonRPCServiceTest {

    @Inject
    CuiJwtDevUIRuntimeService devUIService;

    @Test
    @DisplayName("Should inject Dev UI service correctly")
    void shouldInjectDevUIService() {
        assertNotNull(devUIService, "Dev UI service should be injected");
    }

    @Test
    @DisplayName("Should provide JWT validation status")
    void shouldProvideValidationStatus() {
        // When
        Map<String, Object> response = devUIService.getValidationStatus();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("enabled"), "Response should contain 'enabled' field");
        assertTrue(response.containsKey("validatorPresent"), "Response should contain 'validatorPresent' field");
        assertTrue(response.containsKey("status"), "Response should contain 'status' field");
        assertTrue(response.containsKey("statusMessage"), "Response should contain 'statusMessage' field");
        
        // In runtime mode with configuration, validation should be enabled
        assertTrue((Boolean) response.get("enabled"), "JWT validation should be enabled in runtime");
        assertTrue((Boolean) response.get("validatorPresent"), "Validator should be present in runtime");
        assertEquals("RUNTIME", response.get("status"), "Status should be RUNTIME");
        assertNotNull(response.get("statusMessage"), "Status message should be present");
    }

    @Test
    @DisplayName("Should provide JWKS status")
    void shouldProvideJwksStatus() {
        // When
        Map<String, Object> response = devUIService.getJwksStatus();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("status"), "Response should contain 'status' field");
        assertTrue(response.containsKey("message"), "Response should contain 'message' field");
        assertTrue(response.containsKey("issuersConfigured"), "Response should contain 'issuersConfigured' field");
        
        // JWKS status should be available in runtime
        assertEquals("RUNTIME", response.get("status"), "JWKS status should be RUNTIME");
        assertNotNull(response.get("message"), "Message should be present");
        assertTrue((Integer) response.get("issuersConfigured") > 0, "Should have configured issuers");
    }

    @Test
    @DisplayName("Should provide configuration information")
    void shouldProvideConfiguration() {
        // When
        Map<String, Object> response = devUIService.getConfiguration();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("enabled"), "Response should contain 'enabled' field");
        assertTrue(response.containsKey("healthEnabled"), "Response should contain 'healthEnabled' field");
        assertTrue(response.containsKey("buildTime"), "Response should contain 'buildTime' field");
        assertTrue(response.containsKey("message"), "Response should contain 'message' field");
        
        // Configuration should reflect runtime values
        assertTrue((Boolean) response.get("enabled"), "JWT should be enabled");
        assertTrue((Boolean) response.get("healthEnabled"), "Health should be enabled");
        assertFalse((Boolean) response.get("buildTime"), "Should not be build time in runtime");
        assertNotNull(response.get("message"), "Message should be present");
    }

    @Test
    @DisplayName("Should handle empty token validation")
    void shouldHandleEmptyTokenValidation() {
        // Given - empty token
        String emptyToken = "";

        // When
        Map<String, Object> response = devUIService.validateToken(emptyToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("valid"), "Response should contain 'valid' field");
        assertTrue(response.containsKey("error"), "Response should contain 'error' field");
        
        assertFalse((Boolean) response.get("valid"), "Empty token should be invalid");
        assertEquals("Token is empty or null", response.get("error"), 
                "Should provide appropriate error message for empty token");
    }

    @Test
    @DisplayName("Should handle null token validation")
    void shouldHandleNullTokenValidation() {
        // Given - null token
        String nullToken = null;

        // When
        Map<String, Object> response = devUIService.validateToken(nullToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("valid"), "Response should contain 'valid' field");
        assertTrue(response.containsKey("error"), "Response should contain 'error' field");
        
        assertFalse((Boolean) response.get("valid"), "Null token should be invalid");
        assertEquals("Token is empty or null", response.get("error"), 
                "Should provide appropriate error message for null token");
    }

    @Test
    @DisplayName("Should handle malformed token validation")
    void shouldHandleMalformedTokenValidation() {
        // Given - malformed token
        String malformedToken = "not.a.valid.jwt";

        // When
        Map<String, Object> response = devUIService.validateToken(malformedToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("valid"), "Response should contain 'valid' field");
        
        assertFalse((Boolean) response.get("valid"), "Malformed token should be invalid");
        
        if (response.containsKey("error")) {
            assertNotNull(response.get("error"), "Should provide error message for malformed token");
            assertFalse(response.get("error").toString().isEmpty(), "Error message should not be empty");
        }
    }

    @Test
    @DisplayName("Should handle well-formed but invalid JWT token")
    void shouldHandleWellFormedInvalidToken() {
        // Given - well-formed but invalid JWT token (sample from JWT.io)
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // When
        Map<String, Object> response = devUIService.validateToken(invalidToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("valid"), "Response should contain 'valid' field");
        
        // Token should be invalid (wrong signature/algorithm/issuer)
        assertFalse((Boolean) response.get("valid"), "Sample JWT should be invalid");
        
        if (response.containsKey("error")) {
            assertNotNull(response.get("error"), "Error message should be present if validation fails");
        }
    }

    @Test
    @DisplayName("Should provide health information")
    void shouldProvideHealthInfo() {
        // When
        Map<String, Object> response = devUIService.getHealthInfo();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("configurationValid"), "Response should contain 'configurationValid' field");
        assertTrue(response.containsKey("tokenValidatorAvailable"), "Response should contain 'tokenValidatorAvailable' field");
        assertTrue(response.containsKey("overallStatus"), "Response should contain 'overallStatus' field");
        assertTrue(response.containsKey("message"), "Response should contain 'message' field");
        assertTrue(response.containsKey("healthStatus"), "Response should contain 'healthStatus' field");
        
        // Health information should reflect runtime state
        assertTrue((Boolean) response.get("configurationValid"), "Configuration should be valid");
        assertTrue((Boolean) response.get("tokenValidatorAvailable"), "Token validator should be available");
        assertEquals("RUNTIME", response.get("overallStatus"), "Overall status should be RUNTIME");
        assertNotNull(response.get("message"), "Message should be present");
        assertEquals("UP", response.get("healthStatus"), "Health status should be UP");
    }

    @Test
    @DisplayName("Should provide consistent data across multiple calls")
    void shouldProvideConsistentDataAcrossMultipleCalls() {
        // When - making multiple independent calls
        Map<String, Object> statusResponse1 = devUIService.getValidationStatus();
        Map<String, Object> statusResponse2 = devUIService.getValidationStatus();
        Map<String, Object> configResponse = devUIService.getConfiguration();

        // Then - all calls should provide consistent data
        assertNotNull(statusResponse1, "First status response should not be null");
        assertNotNull(statusResponse2, "Second status response should not be null");
        assertNotNull(configResponse, "Config response should not be null");
        
        // Values should be consistent across calls (since they're in the same runtime)
        assertEquals(statusResponse1.get("enabled"), statusResponse2.get("enabled"),
                "Enabled status should be consistent across calls");
        assertEquals(statusResponse1.get("enabled"), configResponse.get("enabled"),
                "Enabled status should be consistent between status and config");
    }

    @Test
    @DisplayName("Should handle service method invocations without errors")
    void shouldHandleServiceMethodInvocationsWithoutErrors() {
        // This test verifies that all service methods can be called without throwing exceptions
        // This tests the basic wiring and method invocation mechanism
        
        assertDoesNotThrow(() -> {
            devUIService.getValidationStatus();
        }, "getValidationStatus should not throw");
        
        assertDoesNotThrow(() -> {
            devUIService.getJwksStatus();
        }, "getJwksStatus should not throw");
        
        assertDoesNotThrow(() -> {
            devUIService.getConfiguration();
        }, "getConfiguration should not throw");
        
        assertDoesNotThrow(() -> {
            devUIService.getHealthInfo();
        }, "getHealthInfo should not throw");
        
        assertDoesNotThrow(() -> {
            devUIService.validateToken("test.token.string");
        }, "validateToken should not throw");
    }
}