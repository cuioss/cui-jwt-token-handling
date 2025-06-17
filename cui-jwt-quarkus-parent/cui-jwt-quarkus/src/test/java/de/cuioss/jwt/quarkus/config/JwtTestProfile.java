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

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.HashMap;
import java.util.Map;

/**
 * Test profile for JWT tests, providing test configuration values.
 * <p>
 * This profile can be used with the {@link io.quarkus.test.junit.TestProfile} annotation
 * to override configuration for tests.
 * <p>
 * Example usage:
 * <pre>
 * {@code
 * @QuarkusTest
 * @TestProfile(JwtTestProfile.class)
 * public class MyTest {
 *     // test methods
 * }
 * }
 * </pre>
 */
public class JwtTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> config = new HashMap<>();

        // Default issuer configuration
        config.put("cui.jwt.issuers.default.url", "https://example.com/auth");
        config.put("cui.jwt.issuers.default.enabled", "true");
        config.put("cui.jwt.issuers.default.public-key-location", "classpath:keys/public_key.pem");

        // Keycloak issuer configuration
        config.put("cui.jwt.issuers.keycloak.url", "https://keycloak.example.com/auth/realms/master");
        config.put("cui.jwt.issuers.keycloak.enabled", "true");
        config.put("cui.jwt.issuers.keycloak.public-key-location", "classpath:keys/public_key.pem");
        config.put("cui.jwt.issuers.keycloak.jwks.url",
                "https://keycloak.example.com/auth/realms/master/protocol/openid-connect/certs");
        config.put("cui.jwt.issuers.keycloak.jwks.cache-ttl-seconds", "7200");
        config.put("cui.jwt.issuers.keycloak.jwks.refresh-interval-seconds", "600");
        config.put("cui.jwt.issuers.keycloak.jwks.connection-timeout-seconds", "3");
        config.put("cui.jwt.issuers.keycloak.jwks.read-timeout-seconds", "3");
        config.put("cui.jwt.issuers.keycloak.jwks.max-retries", "5");
        config.put("cui.jwt.issuers.keycloak.jwks.use-system-proxy", "true");
        config.put("cui.jwt.issuers.keycloak.parser.audience", "my-app");
        config.put("cui.jwt.issuers.keycloak.parser.leeway-seconds", "60");
        config.put("cui.jwt.issuers.keycloak.parser.max-token-size-bytes", "16384");
        config.put("cui.jwt.issuers.keycloak.parser.validate-not-before", "false");
        config.put("cui.jwt.issuers.keycloak.parser.validate-expiration", "true");
        config.put("cui.jwt.issuers.keycloak.parser.validate-issued-at", "true");
        config.put("cui.jwt.issuers.keycloak.parser.allowed-algorithms", "RS256,ES256");

        // Well-known issuer configuration (using OpenID Connect Discovery)
        config.put("cui.jwt.issuers.wellknown.url", "https://wellknown.example.com/auth/realms/master");
        config.put("cui.jwt.issuers.wellknown.enabled", "true");
        config.put("cui.jwt.issuers.wellknown.jwks.well-known-url",
                "https://wellknown.example.com/auth/realms/master/.well-known/openid-configuration");
        config.put("cui.jwt.issuers.wellknown.jwks.url",
                "https://wellknown.example.com/auth/realms/master/protocol/openid-connect/certs"); // Fallback direct URL
        config.put("cui.jwt.issuers.wellknown.jwks.cache-ttl-seconds", "3600");
        config.put("cui.jwt.issuers.wellknown.jwks.refresh-interval-seconds", "300");
        config.put("cui.jwt.issuers.wellknown.jwks.connection-timeout-seconds", "5");
        config.put("cui.jwt.issuers.wellknown.jwks.read-timeout-seconds", "5");
        config.put("cui.jwt.issuers.wellknown.jwks.max-retries", "3");
        config.put("cui.jwt.issuers.wellknown.jwks.use-system-proxy", "false");
        config.put("cui.jwt.issuers.wellknown.parser.audience", "well-known-app");
        config.put("cui.jwt.issuers.wellknown.parser.leeway-seconds", "30");

        // Global parser configuration
        config.put("cui.jwt.parser.leeway-seconds", "30");
        config.put("cui.jwt.parser.max-token-size-bytes", "8192");
        config.put("cui.jwt.parser.validate-not-before", "true");
        config.put("cui.jwt.parser.validate-expiration", "true");
        config.put("cui.jwt.parser.validate-issued-at", "false");
        config.put("cui.jwt.parser.allowed-algorithms", "RS256,RS384,RS512,ES256,ES384,ES512");

        // Health check configuration
        config.put("cui.jwt.health.enabled", "true");
        config.put("cui.jwt.health.jwks.cache-seconds", "30");
        config.put("cui.jwt.health.jwks.timeout-seconds", "5");

        return config;
    }
}
