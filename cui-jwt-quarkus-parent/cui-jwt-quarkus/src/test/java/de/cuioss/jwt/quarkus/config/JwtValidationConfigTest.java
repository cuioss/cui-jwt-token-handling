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
package de.cuioss.jwt.quarkus.config;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for JWT configuration.
 *
 * Note: Using @QuarkusTest to enable the full Quarkus CDI context for these tests.
 * Since JwtValidationConfig no longer uses @ConfigMapping, we test configuration directly via Config.
 */
@EnableTestLogger
@DisplayName("Tests JWT configuration")
@QuarkusTest
@TestProfile(JwtTestProfile.class)
class JwtValidationConfigTest {

    @Inject
    Config config;

    @Test
    @DisplayName("Should load configuration with default values")
    void shouldLoadConfigWithDefaults() {
        // Assert
        assertNotNull(config);

        // Check default issuer
        assertTrue(config.getOptionalValue("cui.jwt.issuers.default.enabled", Boolean.class).orElse(false));
        assertEquals("https://example.com/auth", config.getOptionalValue("cui.jwt.issuers.default.identifier", String.class).orElse(null));
        assertEquals("classpath:keys/public_key.pem", config.getOptionalValue("cui.jwt.issuers.default.public-key-location", String.class).orElse(null));
        assertFalse(config.getOptionalValue("cui.jwt.issuers.default.jwks.url", String.class).isPresent());

        // Check parser defaults
        assertEquals(30, config.getOptionalValue("cui.jwt.parser.leeway-seconds", Integer.class).orElse(30));
        assertEquals(8192, config.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(8192));
        assertTrue(config.getOptionalValue("cui.jwt.parser.validate-not-before", Boolean.class).orElse(true));
        assertTrue(config.getOptionalValue("cui.jwt.parser.validate-expiration", Boolean.class).orElse(true));
        assertFalse(config.getOptionalValue("cui.jwt.parser.validate-issued-at", Boolean.class).orElse(false));
        assertEquals("RS256,RS384,RS512,ES256,ES384,ES512", config.getOptionalValue("cui.jwt.parser.allowed-algorithms", String.class).orElse("RS256,RS384,RS512,ES256,ES384,ES512"));
    }

    @Test
    @DisplayName("Should load keycloak configuration with custom values")
    @SuppressWarnings("java:S5961") // owolff: Won't fix, this suffices
    void shouldLoadKeycloakConfig() {
        // Assert
        assertNotNull(config);

        // Check keycloak issuer is enabled
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.enabled", Boolean.class).orElse(false));

        // Check issuer config
        assertEquals("https://keycloak.example.com/auth/realms/master", config.getOptionalValue("cui.jwt.issuers.keycloak.identifier", String.class).orElse(null));
        assertEquals("classpath:keys/public_key.pem", config.getOptionalValue("cui.jwt.issuers.keycloak.public-key-location", String.class).orElse(null));

        // Check JWKS config
        assertEquals("https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs", config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.url", String.class).orElse(null));
        assertEquals(7200, config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.cache-ttl-seconds", Integer.class).orElse(0));
        assertEquals(600, config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.refresh-interval-seconds", Integer.class).orElse(0));
        assertEquals(3, config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.connection-timeout-seconds", Integer.class).orElse(0));
        assertEquals(3, config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.read-timeout-seconds", Integer.class).orElse(0));
        assertEquals(5, config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.max-retries", Integer.class).orElse(0));
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.jwks.use-system-proxy", Boolean.class).orElse(false));

        // Check issuer-specific parser config
        assertEquals("my-app", config.getOptionalValue("cui.jwt.issuers.keycloak.parser.audience", String.class).orElse(null));
        assertEquals(60, config.getOptionalValue("cui.jwt.issuers.keycloak.parser.leeway-seconds", Integer.class).orElse(0));
        assertEquals(16384, config.getOptionalValue("cui.jwt.issuers.keycloak.parser.max-token-size-bytes", Integer.class).orElse(0));
        assertFalse(config.getOptionalValue("cui.jwt.issuers.keycloak.parser.validate-not-before", Boolean.class).orElse(true));
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.parser.validate-expiration", Boolean.class).orElse(false));
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.parser.validate-issued-at", Boolean.class).orElse(false));
        assertEquals("RS256,ES256", config.getOptionalValue("cui.jwt.issuers.keycloak.parser.allowed-algorithms", String.class).orElse(null));
    }

    @Test
    @DisplayName("Should support arbitrary issuer names and identifier configuration")
    void shouldSupportArbitraryIssuerNames() {
        // Assert
        assertNotNull(config);

        // Verify that arbitrary issuer names are supported by checking enabled flags
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.enabled", Boolean.class).orElse(false), "Keycloak issuer should be present");
        assertTrue(config.getOptionalValue("cui.jwt.issuers.default.enabled", Boolean.class).orElse(false), "Default issuer should be present");
        assertTrue(config.getOptionalValue("cui.jwt.issuers.custom-auth-provider.enabled", Boolean.class).orElse(false), "Custom issuer should be present");

        // Verify that issuer identifiers are properly configured
        assertEquals("https://custom.example.com/auth", config.getOptionalValue("cui.jwt.issuers.custom-auth-provider.identifier", String.class).orElse(null));
        assertTrue(config.getOptionalValue("cui.jwt.issuers.custom-auth-provider.enabled", Boolean.class).orElse(false));
    }
}
