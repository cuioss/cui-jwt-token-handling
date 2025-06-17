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
import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
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
    JwtValidationConfig config;

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
        assertNotNull(config.issuers(), "Issuers configuration should not be null");
        assertNotNull(config.parser(), "Parser configuration should not be null");

        // Verify the producer uses the configuration
        assertEquals(config.issuers().size(), tokenValidator.getIssuerConfigMap().size(),
                "TokenValidator should have the same number of issuers as the configuration");
    }
}
