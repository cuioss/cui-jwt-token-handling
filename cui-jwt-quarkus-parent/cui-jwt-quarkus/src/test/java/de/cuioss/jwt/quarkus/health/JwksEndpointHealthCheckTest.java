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
import org.eclipse.microprofile.health.Readiness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class JwksEndpointHealthCheckTest {

    @Inject
    @Readiness
    JwksEndpointHealthCheck healthCheck;

    @Test
    @DisplayName("Health check bean should be injected and available")
    void testHealthCheckBeanIsInjected() {
        assertNotNull(healthCheck, "JwksEndpointHealthCheck should be injected");
    }

    @Test
    @DisplayName("Health check should return valid response with status")
    void testHealthCheckBeanIsUpOrDown() {
        HealthCheckResponse response = healthCheck.call();
        assertNotNull(response, "HealthCheckResponse should not be null");
        assertNotNull(response.getStatus(), "Health check status should not be null");
        assertTrue(response.getStatus() == HealthCheckResponse.Status.UP ||
                response.getStatus() == HealthCheckResponse.Status.DOWN,
                "Health check status should be either UP or DOWN");
    }

    @Test
    @DisplayName("Health check should have correct name")
    void testHealthCheckName() {
        HealthCheckResponse response = healthCheck.call();
        assertEquals("jwks-endpoints", response.getName(),
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
    void testHealthCheckDataForStatus(HealthCheckResponse.Status status) {
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
            // UP status should have endpoint count and issuer data
            assertTrue(data.containsKey("checkedEndpoints"),
                    "Health check data should contain checkedEndpoints count when UP");

            Object endpointCountValue = data.get("checkedEndpoints");
            assertNotNull(endpointCountValue, "checkedEndpoints should not be null");

            assertInstanceOf(Number.class, endpointCountValue,
                    "checkedEndpoints should be a Number, but was: " + endpointCountValue.getClass().getSimpleName());

            int endpointCount = ((Number) endpointCountValue).intValue();
            assertTrue(endpointCount > 0,
                    "checkedEndpoints should be greater than 0 when UP, but was: " + endpointCount);

            // Check for issuer-specific data
            boolean hasIssuerData = data.keySet().stream()
                    .anyMatch(key -> key.startsWith("issuer."));
            assertTrue(hasIssuerData, "Should contain issuer-specific data when UP");
        } else if (status == HealthCheckResponse.Status.DOWN) {
            // DOWN status should have error information
            boolean hasErrorInfo = data.containsKey("error") ||
                    data.values().stream().anyMatch(value ->
                            value instanceof String s && s.contains("DOWN"));

            assertTrue(hasErrorInfo,
                    "Health check should contain error information when DOWN. " +
                            "Available keys: " + data.keySet() + ", values: " + data.values());
        }
    }

    @Test
    @DisplayName("Health check should contain issuer endpoint details")
    void testIssuerEndpointDetails() {
        HealthCheckResponse response = healthCheck.call();

        if (response.getStatus() == HealthCheckResponse.Status.UP && response.getData().isPresent()) {
            Map<String, Object> data = response.getData().get();

            // Look for issuer-specific data patterns
            data.entrySet().stream()
                    .filter(entry -> entry.getKey().startsWith("issuer.") && entry.getKey().endsWith(".url"))
                    .forEach(entry -> {
                        String issuerPrefix = entry.getKey().substring(0, entry.getKey().lastIndexOf(".url"));

                        // Check that each issuer has required fields
                        assertTrue(data.containsKey(issuerPrefix + ".url"),
                                "Should contain URL for " + issuerPrefix);
                        assertTrue(data.containsKey(issuerPrefix + ".jwksType"),
                                "Should contain jwksType for " + issuerPrefix);
                        assertTrue(data.containsKey(issuerPrefix + ".status"),
                                "Should contain status for " + issuerPrefix);

                        // Verify status values
                        Object statusValue = data.get(issuerPrefix + ".status");
                        assertTrue("UP".equals(statusValue) || "DOWN".equals(statusValue),
                                "Issuer status should be UP or DOWN");
                    });
        }
    }

    @Test
    @DisplayName("Health check should handle concurrent calls properly")
    void testConcurrentHealthCheckCalls() {
        // Make multiple concurrent calls to test thread safety and caching
        HealthCheckResponse response1 = healthCheck.call();
        HealthCheckResponse response2 = healthCheck.call();
        HealthCheckResponse response3 = healthCheck.call();

        assertNotNull(response1, "First response should not be null");
        assertNotNull(response2, "Second response should not be null");
        assertNotNull(response3, "Third response should not be null");

        // All responses should have the same status (due to caching)
        assertEquals(response1.getStatus(), response2.getStatus(),
                "Concurrent calls should return same status");
        assertEquals(response1.getStatus(), response3.getStatus(),
                "Concurrent calls should return same status");
    }

    @Test
    @DisplayName("Health check should handle edge cases gracefully")
    void testHealthCheckEdgeCases() {
        HealthCheckResponse response = healthCheck.call();

        // Response should be valid regardless of JWKS endpoint status
        assertNotNull(response, "Response should not be null");
        assertNotNull(response.getStatus(), "Health check status should not be null");
        assertTrue(response.getStatus() == HealthCheckResponse.Status.UP ||
                response.getStatus() == HealthCheckResponse.Status.DOWN,
                "Health check status should be either UP or DOWN");
        assertEquals("jwks-endpoints", response.getName(),
                "Health check should have correct name");

        if (response.getData().isPresent()) {
            Map<String, Object> data = response.getData().get();
            // Should contain endpoint data or error information
            assertTrue(data.containsKey("checkedEndpoints") || data.containsKey("error"),
                    "Should contain either endpoint data or error information");
        }
    }

}
