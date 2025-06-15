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

import io.quarkus.test.QuarkusDevModeTest;
import io.quarkus.vertx.http.testutils.DevUIJsonRPCTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.fasterxml.jackson.databind.JsonNode;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for CUI JWT DevUI components.
 * <p>
 * Tests the DevUI JsonRPC backend service in development mode to verify
 * proper wiring and basic interactions. This focuses on the communication
 * layer between frontend components and backend services.
 * </p>
 */
class DevUIIntegrationTest extends DevUIJsonRPCTest {

    @RegisterExtension
    static final QuarkusDevModeTest config = new QuarkusDevModeTest()
            .withApplicationRoot(jar -> jar
                    .addAsResource("application.properties")
                    .addAsResource("test-public-key.pem", "keys/test_public_key.pem"))
            .setRuntimeProperties(java.util.Map.of(
                    "cui.jwt.enabled", "true",
                    "cui.jwt.issuers.default.enabled", "true",
                    "cui.jwt.issuers.default.url", "https://test-auth.example.com",
                    "cui.jwt.issuers.default.public-key-location", "classpath:keys/test_public_key.pem",
                    "cui.jwt.health.enabled", "true"));

    public DevUIIntegrationTest() {
        super("io.quarkus.cui-jwt");
    }

    @Test
    @DisplayName("Should provide JWT validation status via JsonRPC")
    void shouldProvideValidationStatus() throws Exception {
        // When
        JsonNode response = super.executeJsonRPCMethod("getValidationStatus");

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("enabled"), "Response should contain 'enabled' field");
        assertTrue(response.has("validatorPresent"), "Response should contain 'validatorPresent' field");
        assertTrue(response.has("status"), "Response should contain 'status' field");
        assertTrue(response.has("statusMessage"), "Response should contain 'statusMessage' field");
        
        // In runtime mode, validation should be enabled
        assertTrue(response.get("enabled").asBoolean(), "JWT validation should be enabled in runtime");
        assertTrue(response.get("validatorPresent").asBoolean(), "Validator should be present in runtime");
        assertEquals("RUNTIME", response.get("status").asText(), "Status should be RUNTIME");
    }

    @Test
    @DisplayName("Should provide JWKS status via JsonRPC")
    void shouldProvideJwksStatus() throws Exception {
        // When
        JsonNode response = super.executeJsonRPCMethod("getJwksStatus");

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("status"), "Response should contain 'status' field");
        assertTrue(response.has("message"), "Response should contain 'message' field");
        
        // JWKS status should be available in runtime
        assertEquals("RUNTIME", response.get("status").asText(), "JWKS status should be RUNTIME");
        assertNotNull(response.get("message").asText(), "Message should be present");
    }

    @Test
    @DisplayName("Should provide configuration via JsonRPC")
    void shouldProvideConfiguration() throws Exception {
        // When
        JsonNode response = super.executeJsonRPCMethod("getConfiguration");

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("enabled"), "Response should contain 'enabled' field");
        assertTrue(response.has("healthEnabled"), "Response should contain 'healthEnabled' field");
        assertTrue(response.has("buildTime"), "Response should contain 'buildTime' field");
        
        // Configuration should reflect runtime values
        assertTrue(response.get("enabled").asBoolean(), "JWT should be enabled");
        assertTrue(response.get("healthEnabled").asBoolean(), "Health should be enabled");
        assertFalse(response.get("buildTime").asBoolean(), "Should not be build time in dev mode");
    }

    @Test
    @DisplayName("Should handle token validation via JsonRPC")
    void shouldHandleTokenValidation() throws Exception {
        // Given - empty token (should fail gracefully)
        String emptyToken = "";

        // When
        JsonNode response = super.executeJsonRPCMethod("validateToken", emptyToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("valid"), "Response should contain 'valid' field");
        assertTrue(response.has("error"), "Response should contain 'error' field");
        
        assertFalse(response.get("valid").asBoolean(), "Empty token should be invalid");
        assertEquals("Token is empty or null", response.get("error").asText(), 
                "Should provide appropriate error message for empty token");
    }

    @Test
    @DisplayName("Should handle malformed token validation via JsonRPC")
    void shouldHandleMalformedTokenValidation() throws Exception {
        // Given - malformed token
        String malformedToken = "not.a.valid.jwt";

        // When
        JsonNode response = super.executeJsonRPCMethod("validateToken", malformedToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("valid"), "Response should contain 'valid' field");
        assertTrue(response.has("error"), "Response should contain 'error' field");
        
        assertFalse(response.get("valid").asBoolean(), "Malformed token should be invalid");
        assertNotNull(response.get("error").asText(), "Should provide error message for malformed token");
        assertFalse(response.get("error").asText().isEmpty(), "Error message should not be empty");
    }

    @Test
    @DisplayName("Should handle well-formed but invalid JWT token via JsonRPC")
    void shouldHandleWellFormedInvalidToken() throws Exception {
        // Given - well-formed but invalid JWT token (sample from JWT.io)
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
                "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        // When
        JsonNode response = super.executeJsonRPCMethod("validateToken", invalidToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("valid"), "Response should contain 'valid' field");
        
        // Token should be invalid (wrong signature/algorithm/issuer)
        assertFalse(response.get("valid").asBoolean(), "Sample JWT should be invalid");
        
        if (response.has("error")) {
            assertNotNull(response.get("error").asText(), "Error message should be present if validation fails");
        }
    }

    @Test
    @DisplayName("Should provide health information via JsonRPC")
    void shouldProvideHealthInfo() throws Exception {
        // When
        JsonNode response = super.executeJsonRPCMethod("getHealthInfo");

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("configurationValid"), "Response should contain 'configurationValid' field");
        assertTrue(response.has("tokenValidatorAvailable"), "Response should contain 'tokenValidatorAvailable' field");
        assertTrue(response.has("overallStatus"), "Response should contain 'overallStatus' field");
        
        // Health information should reflect runtime state
        assertTrue(response.get("configurationValid").asBoolean(), "Configuration should be valid");
        assertTrue(response.get("tokenValidatorAvailable").asBoolean(), "Token validator should be available");
        assertEquals("RUNTIME", response.get("overallStatus").asText(), "Overall status should be RUNTIME");
    }

    @Test
    @DisplayName("Should handle JsonRPC method with parameters correctly")
    void shouldHandleJsonRpcMethodWithParameters() throws Exception {
        // Given - testing parameter passing mechanism
        String testToken = "test.parameter.passing";

        // When
        JsonNode response = super.executeJsonRPCMethod("validateToken", testToken);

        // Then
        assertNotNull(response, "Response should not be null");
        assertTrue(response.has("valid"), "Response should contain validation result");
        
        // The key here is that the method was called and responded
        // This tests the JsonRPC parameter passing mechanism
        assertFalse(response.get("valid").asBoolean(), "Test token should be invalid");
    }

    @Test
    @DisplayName("Should handle multiple JsonRPC calls independently")
    void shouldHandleMultipleJsonRpcCalls() throws Exception {
        // When - making multiple independent calls
        JsonNode statusResponse = super.executeJsonRPCMethod("getValidationStatus");
        JsonNode configResponse = super.executeJsonRPCMethod("getConfiguration");
        JsonNode healthResponse = super.executeJsonRPCMethod("getHealthInfo");

        // Then - all calls should succeed independently
        assertNotNull(statusResponse, "Status response should not be null");
        assertNotNull(configResponse, "Config response should not be null");
        assertNotNull(healthResponse, "Health response should not be null");
        
        // Each response should have its expected structure
        assertTrue(statusResponse.has("enabled"), "Status should have enabled field");
        assertTrue(configResponse.has("enabled"), "Config should have enabled field");
        assertTrue(healthResponse.has("configurationValid"), "Health should have configurationValid field");
        
        // Values should be consistent across calls (since they're in the same session)
        assertEquals(statusResponse.get("enabled").asBoolean(), 
                configResponse.get("enabled").asBoolean(),
                "Enabled status should be consistent across calls");
    }
}