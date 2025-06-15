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
package de.cuioss.jwt.quarkus.deployment;

import de.cuioss.jwt.quarkus.runtime.CuiJwtDevUIRuntimeService;
import io.quarkus.test.QuarkusUnitTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import jakarta.inject.Inject;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Simple test for the Dev UI Runtime Service to verify basic wiring and functionality.
 * <p>
 * This test verifies that the runtime service can be instantiated and provides basic
 * functionality. It serves as a simpler test environment compared to the full
 * integration test setup.
 * </p>
 */
class CuiJwtDevUIRuntimeServiceSimpleTest {

    @RegisterExtension
    static final QuarkusUnitTest config = new QuarkusUnitTest()
            .withApplicationRoot(jar -> jar
                    .addClasses(CuiJwtDevUIRuntimeService.class))
            .overrideConfigKey("cui.jwt.issuers.default.url", "https://test-auth.example.com")
            .overrideConfigKey("cui.jwt.issuers.default.enabled", "true")
            .overrideConfigKey("cui.jwt.issuers.default.public-key-location", "classpath:test-public-key.pem");

    @Inject
    CuiJwtDevUIRuntimeService devUIService;

    @Test
    @DisplayName("Should inject Dev UI runtime service")
    void shouldInjectDevUIRuntimeService() {
        assertNotNull(devUIService, "Dev UI runtime service should be injected");
    }

    @Test
    @DisplayName("Should provide validation status")
    void shouldProvideValidationStatus() {
        // When
        Map<String, Object> response = devUIService.getValidationStatus();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("enabled"), "Response should contain 'enabled' field");
        assertTrue(response.containsKey("validatorPresent"), "Response should contain 'validatorPresent' field");
        assertTrue(response.containsKey("status"), "Response should contain 'status' field");
        assertEquals("RUNTIME", response.get("status"), "Status should be RUNTIME");
    }

    @Test
    @DisplayName("Should handle basic token validation")
    void shouldHandleBasicTokenValidation() {
        // Given - empty token (should be handled gracefully)
        String emptyToken = "";

        // When
        Map<String, Object> response = devUIService.validateToken(emptyToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("valid"), "Response should contain 'valid' field");
        assertFalse((Boolean) response.get("valid"), "Empty token should be invalid");
        assertEquals("Token is empty or null", response.get("error"), 
                "Should provide appropriate error message");
    }

    @Test
    @DisplayName("Should provide configuration information")
    void shouldProvideConfigurationInformation() {
        // When
        Map<String, Object> response = devUIService.getConfiguration();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("enabled"), "Response should contain 'enabled' field");
        assertTrue(response.containsKey("buildTime"), "Response should contain 'buildTime' field");
        assertFalse((Boolean) response.get("buildTime"), "Should not be build time in runtime service");
    }

    @Test
    @DisplayName("Should provide health information")
    void shouldProvideHealthInformation() {
        // When
        Map<String, Object> response = devUIService.getHealthInfo();

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.containsKey("configurationValid"), "Response should contain 'configurationValid' field");
        assertTrue(response.containsKey("overallStatus"), "Response should contain 'overallStatus' field");
        assertEquals("RUNTIME", response.get("overallStatus"), "Overall status should be RUNTIME");
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
        assertEquals("RUNTIME", response.get("status"), "Status should be RUNTIME");
    }

    @Test
    @DisplayName("Should handle all service methods without exceptions")
    void shouldHandleAllServiceMethodsWithoutExceptions() {
        // This test verifies that all service methods can be called without throwing exceptions
        // This is important for Dev UI wiring and basic functionality verification
        
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
            devUIService.validateToken("test.token.here");
        }, "validateToken should not throw");
        
        assertDoesNotThrow(() -> {
            devUIService.validateToken(null);
        }, "validateToken with null should not throw");
    }
}