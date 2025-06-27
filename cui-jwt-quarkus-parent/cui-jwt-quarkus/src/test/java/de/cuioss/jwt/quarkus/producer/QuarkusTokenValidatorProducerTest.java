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

import de.cuioss.jwt.quarkus.config.JwtTestProfile;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Basic tests for {@link TokenValidatorProducer} using Quarkus test framework.
 */
@QuarkusTest
@TestProfile(JwtTestProfile.class)
@EnableTestLogger
class QuarkusTokenValidatorProducerTest {

    @Inject
    TokenValidatorProducer producer;

    @Inject
    Config config;

    @Inject
    TokenValidator tokenValidator;

    /**
     * Test that the producer is properly injected.
     */
    @Test
    @DisplayName("Should inject the producer")
    void shouldInjectProducer() {
        // Assert
        assertNotNull(producer, "Producer should be injected");
        assertNotNull(config, "Config should be injected");
        assertNotNull(tokenValidator, "TokenValidator should be injected");
    }

    /**
     * Test that the TokenValidator is properly configured with the default issuer.
     */
    @Test
    @DisplayName("Should configure TokenValidator with default issuer")
    void shouldConfigureTokenValidatorWithDefaultIssuer() {
        // Assert
        assertNotNull(tokenValidator.getIssuerConfigMap(), "Issuer configs should not be null");
        assertTrue(tokenValidator.getIssuerConfigMap().containsKey("https://example.com/auth"),
                "TokenValidator should be configured with default issuer");

        // No direct way to check if issuer is enabled in TokenValidator
        // The fact that it's in the map means it's enabled and configured
        assertNotNull(tokenValidator.getIssuerConfigMap().get("https://example.com/auth"),
                "Default issuer should be present and enabled");
    }

    /**
     * Test that the TokenValidator has the correct security event counter.
     */
    @Test
    @DisplayName("Should have security event counter configured")
    void shouldHaveSecurityEventCounter() {
        // Assert
        assertNotNull(tokenValidator.getSecurityEventCounter(),
                "TokenValidator should have a security event counter");
    }

    /**
     * Test that the TokenValidator rejects invalid tokens.
     */
    @Test
    @DisplayName("Should reject invalid tokens")
    void shouldRejectInvalidTokens() {
        // Arrange
        String invalidToken = "invalid.token.format";

        // Act & Assert
        assertThrows(Exception.class, () -> tokenValidator.createAccessToken(invalidToken),
                "TokenValidator should reject invalid tokens");
    }

    /**
     * Test that the producer uses the configuration correctly.
     */
    @Test
    @DisplayName("Should use configuration correctly")
    void shouldUseConfigurationCorrectly() {
        // Assert
        assertNotNull(config, "Config should not be null");

        // Verify some key configuration properties exist
        assertTrue(config.getOptionalValue("cui.jwt.issuers.default.enabled", Boolean.class).isPresent(),
                "Default issuer configuration should exist");
        assertTrue(config.getOptionalValue("cui.jwt.parser.leeway-seconds", Integer.class).isPresent(),
                "Parser configuration should exist");

        // Verify the producer created the expected number of issuers from the test profile
        // Test profile defines: default, keycloak, wellknown, custom-auth-provider (all enabled)
        // Note: One issuer may fail to load due to missing well-known endpoint
        assertTrue(tokenValidator.getIssuerConfigMap().size() >= 3,
                "TokenValidator should have at least 3 issuers from test profile, but has: " + tokenValidator.getIssuerConfigMap().size());
    }

    /**
     * Test that arbitrary issuer names are supported.
     */
    @Test
    @DisplayName("Should support arbitrary issuer names")
    void shouldSupportArbitraryIssuerNames() {
        // Assert that our custom issuer name is properly configured
        assertTrue(tokenValidator.getIssuerConfigMap().containsKey("https://custom.example.com/auth"),
                "TokenValidator should support arbitrary issuer names like 'custom-auth-provider'");

        // Verify key issuers are present - don't check for well-known since it may fail during HTTP discovery
        assertTrue(tokenValidator.getIssuerConfigMap().containsKey("https://example.com/auth"),
                "Default issuer should be present");
        assertTrue(tokenValidator.getIssuerConfigMap().containsKey("https://keycloak.example.com/auth/realms/master"),
                "Keycloak issuer should be present");
        assertTrue(tokenValidator.getIssuerConfigMap().containsKey("https://custom.example.com/auth"),
                "Custom issuer should be present");

        // Check that the producer is dynamically discovering issuer names
        assertTrue(tokenValidator.getIssuerConfigMap().size() >= 3,
                "Should have at least 3 issuers configured");
    }
}
