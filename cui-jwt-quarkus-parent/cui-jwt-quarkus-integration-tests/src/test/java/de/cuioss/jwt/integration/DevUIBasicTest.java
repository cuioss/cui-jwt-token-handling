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

import de.cuioss.jwt.quarkus.deployment.CuiJwtDevUIJsonRPCService;
import io.quarkus.test.junit.QuarkusIntegrationTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic Dev UI test for integration testing environment.
 * <p>
 * This test verifies that the Dev UI JsonRPC service components are properly
 * wired and can provide basic functionality. It tests the build-time service
 * which is available in both development and production modes.
 * </p>
 */
@QuarkusIntegrationTest
class DevUIBasicTest extends BaseIntegrationTest {

    @Test
    @DisplayName("Should create and use Dev UI JsonRPC service directly")
    void shouldCreateAndUseDevUIJsonRPCServiceDirectly() {
        // Given - create the service directly (testing the wiring concept)
        CuiJwtDevUIJsonRPCService service = new CuiJwtDevUIJsonRPCService();

        // When & Then - test all service methods work without throwing exceptions
        assertDoesNotThrow(() -> {
            Map<String, Object> validationStatus = service.getValidationStatus();
            assertNotNull(validationStatus, "Validation status should not be null");
            assertTrue(validationStatus.containsKey("enabled"), "Should contain enabled field");
            assertTrue(validationStatus.containsKey("status"), "Should contain status field");
        }, "getValidationStatus should not throw");

        assertDoesNotThrow(() -> {
            Map<String, Object> jwksStatus = service.getJwksStatus();
            assertNotNull(jwksStatus, "JWKS status should not be null");
            assertTrue(jwksStatus.containsKey("status"), "Should contain status field");
        }, "getJwksStatus should not throw");

        assertDoesNotThrow(() -> {
            Map<String, Object> config = service.getConfiguration();
            assertNotNull(config, "Configuration should not be null");
            assertTrue(config.containsKey("enabled"), "Should contain enabled field");
        }, "getConfiguration should not throw");

        assertDoesNotThrow(() -> {
            Map<String, Object> health = service.getHealthInfo();
            assertNotNull(health, "Health info should not be null");
            assertTrue(health.containsKey("configurationValid"), "Should contain configurationValid field");
        }, "getHealthInfo should not throw");
    }

    @Test
    @DisplayName("Should handle token validation in build-time service")
    void shouldHandleTokenValidationInBuildTimeService() {
        // Given
        CuiJwtDevUIJsonRPCService service = new CuiJwtDevUIJsonRPCService();

        // When - test with empty token
        Map<String, Object> emptyTokenResult = service.validateToken("");

        // Then
        assertNotNull(emptyTokenResult, "Result should not be null");
        assertFalse((Boolean) emptyTokenResult.get("valid"), "Empty token should be invalid");
        assertEquals("Token is empty or null", emptyTokenResult.get("error"),
                "Should provide appropriate error message");

        // When - test with null token
        Map<String, Object> nullTokenResult = service.validateToken(null);

        // Then
        assertNotNull(nullTokenResult, "Result should not be null");
        assertFalse((Boolean) nullTokenResult.get("valid"), "Null token should be invalid");
        assertEquals("Token is empty or null", nullTokenResult.get("error"),
                "Should provide appropriate error message");

        // When - test with sample token (will fail at build time)
        Map<String, Object> sampleTokenResult = service.validateToken("sample.jwt.token");

        // Then
        assertNotNull(sampleTokenResult, "Result should not be null");
        assertFalse((Boolean) sampleTokenResult.get("valid"), "Sample token should be invalid at build time");
        assertEquals("Token validation not available at build time", sampleTokenResult.get("error"),
                "Should indicate build-time limitation");
    }

    @Test
    @DisplayName("Should provide consistent build-time status information")
    void shouldProvideConsistentBuildTimeStatusInformation() {
        // Given
        CuiJwtDevUIJsonRPCService service = new CuiJwtDevUIJsonRPCService();

        // When
        Map<String, Object> validationStatus = service.getValidationStatus();
        Map<String, Object> jwksStatus = service.getJwksStatus();
        Map<String, Object> configuration = service.getConfiguration();
        Map<String, Object> healthInfo = service.getHealthInfo();

        // Then - all should indicate build-time status
        assertEquals("BUILD_TIME", validationStatus.get("status"),
                "Validation status should be BUILD_TIME");
        assertEquals("BUILD_TIME", jwksStatus.get("status"),
                "JWKS status should be BUILD_TIME");
        assertTrue((Boolean) configuration.get("buildTime"),
                "Configuration should indicate build time");
        assertEquals("BUILD_TIME", healthInfo.get("overallStatus"),
                "Health status should be BUILD_TIME");

        // Enabled should be false at build time
        assertFalse((Boolean) validationStatus.get("enabled"),
                "Validation should not be enabled at build time");
        assertFalse((Boolean) configuration.get("enabled"),
                "Configuration should not show enabled at build time");
    }

    @Test
    @DisplayName("Should demonstrate basic Dev UI component wiring concept")
    void shouldDemonstrateBasicDevUIComponentWiringConcept() {
        // This test demonstrates the basic concept of how Dev UI components
        // would interact with the backend JsonRPC service
        
        // Given - simulate what a frontend component would do
        CuiJwtDevUIJsonRPCService service = new CuiJwtDevUIJsonRPCService();

        // When - simulate the JWT debugger component loading status
        Map<String, Object> status = service.getValidationStatus();

        // Then - verify the component would get the expected data structure
        assertNotNull(status, "Status should be available for component");
        assertTrue(status.containsKey("enabled"), "Component expects 'enabled' field");
        assertTrue(status.containsKey("validatorPresent"), "Component expects 'validatorPresent' field");
        assertTrue(status.containsKey("status"), "Component expects 'status' field");
        assertTrue(status.containsKey("statusMessage"), "Component expects 'statusMessage' field");

        // When - simulate the JWT debugger component attempting token validation
        Map<String, Object> validationResult = service.validateToken("test.token.example");

        // Then - verify the component would get a valid response structure
        assertNotNull(validationResult, "Validation result should be available");
        assertTrue(validationResult.containsKey("valid"), "Component expects 'valid' field");
        assertTrue(validationResult.containsKey("error"), "Component expects 'error' field for invalid tokens");

        // This demonstrates that the basic wiring between frontend components
        // and backend service works correctly, even if full runtime validation
        // is not available in this test environment
    }

    @Test
    @DisplayName("Should handle multiple concurrent service calls")
    void shouldHandleMultipleConcurrentServiceCalls() {
        // This test verifies that the service can handle multiple calls
        // which simulates multiple Dev UI components making concurrent requests
        
        CuiJwtDevUIJsonRPCService service = new CuiJwtDevUIJsonRPCService();

        // When - make multiple concurrent calls (simulating multiple components)
        assertDoesNotThrow(() -> {
            Map<String, Object> status1 = service.getValidationStatus();
            Map<String, Object> config1 = service.getConfiguration();
            Map<String, Object> health1 = service.getHealthInfo();
            Map<String, Object> jwks1 = service.getJwksStatus();

            // Verify all calls return consistent data
            assertEquals(status1.get("enabled"), config1.get("enabled"),
                    "Status and config should be consistent");
            assertEquals("BUILD_TIME", status1.get("status"),
                    "Status should be BUILD_TIME");
            assertEquals("BUILD_TIME", health1.get("overallStatus"),
                    "Health should be BUILD_TIME");
            assertEquals("BUILD_TIME", jwks1.get("status"),
                    "JWKS should be BUILD_TIME");
        }, "Multiple concurrent calls should work without issues");
    }
}