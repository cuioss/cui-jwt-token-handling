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
package de.cuioss.jwt.quarkus.health;

import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class TokenValidatorHealthCheckTest {

    @Inject
    @Liveness
    TokenValidatorHealthCheck healthCheck;

    @Test
    @DisplayName("Health check bean should be injected and available")
    void healthCheckBeanIsInjected() {
        assertNotNull(healthCheck, "TokenValidatorHealthCheck should be injected");
    }

    @Test
    @DisplayName("Health check should return valid response with status")
    void healthCheckBeanIsUpOrDown() {
        HealthCheckResponse response = healthCheck.call();
        assertNotNull(response, "HealthCheckResponse should not be null");
        assertNotNull(response.getStatus(), "Health check status should not be null");
        assertTrue(response.getStatus() == HealthCheckResponse.Status.UP ||
                response.getStatus() == HealthCheckResponse.Status.DOWN,
                "Health check status should be either UP or DOWN");
    }

    @Test
    @DisplayName("Health check should have correct name")
    void healthCheckName() {
        HealthCheckResponse response = healthCheck.call();
        assertEquals("jwt-validator", response.getName(),
                "Health check should have correct name");
    }

    /**
     * Parameterized test for health check status and data validation.
     * Tests both UP and DOWN status scenarios.
     *
     * @param status the health check status to test
     */
    @ParameterizedTest(name = "Health check should include correct data when status is {0}")
    @EnumSource(HealthCheckResponse.Status.class)
    @DisplayName("Health check should include correct data for different statuses")
    void healthCheckDataForStatus(HealthCheckResponse.Status status) {
        HealthCheckResponse response = healthCheck.call();

        // Skip if the current status doesn't match the test parameter
        if (response.getStatus() != status) {
            // Test is not applicable for this status
            return;
        }

        // Common assertions for all statuses
        assertTrue(response.getData().isPresent(),
                "Health check data should be present for status: " + status);

        Map<String, Object> data = response.getData().get();

        // Status-specific assertions
        if (status == HealthCheckResponse.Status.UP) {
            // UP status should have issuer count
            assertTrue(data.containsKey("issuerCount"),
                    "Health check data should contain issuerCount when UP");

            Object issuerCountValue = data.get("issuerCount");
            assertNotNull(issuerCountValue, "issuerCount should not be null");

            assertInstanceOf(Number.class, issuerCountValue,
                    "issuerCount should be a Number, but was: " + issuerCountValue.getClass().getSimpleName());

            int issuerCount = ((Number) issuerCountValue).intValue();
            assertTrue(issuerCount > 0,
                    "issuerCount should be greater than 0 when UP, but was: " + issuerCount);
        } else if (status == HealthCheckResponse.Status.DOWN) {
            // DOWN status should have error information
            assertTrue(data.containsKey("error"),
                    "Health check should contain error key when DOWN");

            Object errorValue = data.get("error");
            assertNotNull(errorValue, "error value should not be null");
            assertInstanceOf(String.class, errorValue,
                    "error should be a String, but was: " + errorValue.getClass().getSimpleName());

            String errorMessage = (String) errorValue;
            assertFalse(errorMessage.isEmpty(), "Error message should not be empty");
        }
    }

    @Test
    @DisplayName("Health check should handle edge cases gracefully")
    void healthCheckEdgeCases() {
        HealthCheckResponse response = healthCheck.call();

        // Response should be valid regardless of TokenValidator state
        assertNotNull(response, "Response should not be null");
        assertNotNull(response.getStatus(), "Health check status should not be null");
        assertTrue(response.getStatus() == HealthCheckResponse.Status.UP ||
                response.getStatus() == HealthCheckResponse.Status.DOWN,
                "Health check status should be either UP or DOWN");
        assertEquals("jwt-validator", response.getName(),
                "Health check should have correct name");

        if (response.getData().isPresent()) {
            Map<String, Object> data = response.getData().get();
            // Should contain issuer count or error information
            assertTrue(data.containsKey("issuerCount") || data.containsKey("error"),
                    "Should contain either issuer count or error information");
        }
    }

    @Test
    @DisplayName("Should handle null TokenValidator in constructor")
    void shouldHandleNullTokenValidatorInConstructor() {
        // Given/When - This tests the constructor with null parameter
        TokenValidatorHealthCheck healthCheckWithNull = new TokenValidatorHealthCheck(null);

        // Then - Constructor should not throw exception
        assertNotNull(healthCheckWithNull, "Health check should be created even with null TokenValidator");

        // When - Call the health check
        HealthCheckResponse response = healthCheckWithNull.call();

        // Then - Should handle null gracefully
        assertNotNull(response, "Response should not be null");
        assertEquals(HealthCheckResponse.Status.DOWN, response.getStatus(),
                "Status should be DOWN for null TokenValidator");
        assertEquals("jwt-validator", response.getName(),
                "Health check should have correct name");

        assertTrue(response.getData().isPresent(), "Data should be present");
        Map<String, Object> data = response.getData().get();
        assertTrue(data.containsKey("error"), "Should contain error key");
        assertEquals("TokenValidator not available", data.get("error"),
                "Should have correct error message");
    }

    @Test
    @DisplayName("Should test health check response structure consistency")
    void shouldTestHealthCheckResponseStructure() {
        // Given - Multiple calls to the health check
        HealthCheckResponse response1 = healthCheck.call();
        HealthCheckResponse response2 = healthCheck.call();

        // Then - Responses should have consistent structure
        assertEquals(response1.getName(), response2.getName(),
                "Health check name should be consistent");
        assertEquals("jwt-validator", response1.getName(),
                "Health check should have correct name");

        // Both responses should have data
        assertTrue(response1.getData().isPresent(), "First response should have data");
        assertTrue(response2.getData().isPresent(), "Second response should have data");

        // Status should be consistent (UP or DOWN)
        assertTrue(response1.getStatus() == HealthCheckResponse.Status.UP ||
                response1.getStatus() == HealthCheckResponse.Status.DOWN,
                "First response status should be UP or DOWN");
        assertTrue(response2.getStatus() == HealthCheckResponse.Status.UP ||
                response2.getStatus() == HealthCheckResponse.Status.DOWN,
                "Second response status should be UP or DOWN");
    }
}
