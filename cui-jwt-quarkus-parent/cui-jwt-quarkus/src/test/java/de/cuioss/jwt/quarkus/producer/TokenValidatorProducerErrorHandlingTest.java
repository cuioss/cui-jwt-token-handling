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

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for error handling in {@link TokenValidatorProducer}.
 * <p>
 * This test class focuses on testing error handling paths that might not be
 * covered by the main test classes.
 */
@EnableTestLogger
@DisplayName("Tests TokenValidatorProducer Error Handling")
class TokenValidatorProducerErrorHandlingTest {

    private TokenValidatorProducer producer;

    /**
     * Base test implementation of JwtValidationConfig for testing purposes.
     */
    private static class TestJwtValidationConfig implements JwtValidationConfig {
        @Override
        public Map<String, IssuerConfig> issuers() {
            return Map.of("default", new TestIssuerConfig());
        }

        @Override
        public ParserConfig parser() {
            return new TestParserConfig();
        }

        @Override
        public HealthConfig health() {
            return new TestHealthConfig();
        }
    }

    /**
     * Test implementation of IssuerConfig with default values.
     */
    private static class TestIssuerConfig implements JwtValidationConfig.IssuerConfig {
        private boolean enabled = true;
        private Optional<String> publicKeyLocation = Optional.of("classpath:test-public-key.pem");
        private Optional<JwtValidationConfig.HttpJwksLoaderConfig> jwks = Optional.empty();

        @Override
        public String url() {
            return "https://example.com/auth";
        }

        @Override
        public Optional<String> publicKeyLocation() {
            return publicKeyLocation;
        }

        @Override
        public Optional<JwtValidationConfig.HttpJwksLoaderConfig> jwks() {
            return jwks;
        }

        @Override
        public Optional<JwtValidationConfig.ParserConfig> parser() {
            return Optional.empty();
        }

        @Override
        public boolean enabled() {
            return enabled;
        }

        // Setters for test configuration
        public TestIssuerConfig withEnabled(boolean enabled) {
            this.enabled = enabled;
            return this;
        }

        public TestIssuerConfig withPublicKeyLocation(Optional<String> publicKeyLocation) {
            this.publicKeyLocation = publicKeyLocation;
            return this;
        }

        public TestIssuerConfig withJwks(Optional<JwtValidationConfig.HttpJwksLoaderConfig> jwks) {
            this.jwks = jwks;
            return this;
        }
    }

    /**
     * Test implementation of ParserConfig with default values.
     */
    private static class TestParserConfig implements JwtValidationConfig.ParserConfig {
        private int maxTokenSizeBytes = 8192;
        private int leewaySeconds = 30;
        private String allowedAlgorithms = "RS256,RS384,RS512";

        @Override
        public Optional<String> audience() {
            return Optional.empty();
        }

        @Override
        public int leewaySeconds() {
            return leewaySeconds;
        }

        @Override
        public int maxTokenSizeBytes() {
            return maxTokenSizeBytes;
        }

        @Override
        public boolean validateNotBefore() {
            return true;
        }

        @Override
        public boolean validateExpiration() {
            return true;
        }

        @Override
        public boolean validateIssuedAt() {
            return false;
        }

        @Override
        public String allowedAlgorithms() {
            return allowedAlgorithms;
        }

        // Setters for test configuration
        public TestParserConfig withMaxTokenSizeBytes(int maxTokenSizeBytes) {
            this.maxTokenSizeBytes = maxTokenSizeBytes;
            return this;
        }

        public TestParserConfig withLeewaySeconds(int leewaySeconds) {
            this.leewaySeconds = leewaySeconds;
            return this;
        }

        public TestParserConfig withAllowedAlgorithms(String allowedAlgorithms) {
            this.allowedAlgorithms = allowedAlgorithms;
            return this;
        }
    }

    /**
     * Test implementation of HttpJwksLoaderConfig with default values.
     */
    private static class TestHttpJwksLoaderConfig implements JwtValidationConfig.HttpJwksLoaderConfig {
        @Override
        public Optional<String> url() {
            return Optional.of("https://example.com/jwks");
        }

        @Override
        public Optional<String> wellKnownUrl() {
            return Optional.empty();
        }

        @Override
        public int cacheTtlSeconds() {
            return 3600;
        }

        @Override
        public int refreshIntervalSeconds() {
            return 300;
        }

        @Override
        public int connectionTimeoutSeconds() {
            return 5;
        }

        @Override
        public int readTimeoutSeconds() {
            return 5;
        }

        @Override
        public int maxRetries() {
            return 3;
        }

        @Override
        public boolean useSystemProxy() {
            return false;
        }
    }

    /**
     * Test implementation of HealthConfig with default values.
     */
    private static class TestHealthConfig implements JwtValidationConfig.HealthConfig {
        @Override
        public boolean enabled() {
            return true;
        }

        @Override
        public JwtValidationConfig.JwksHealthConfig jwks() {
            return new TestJwksHealthConfig();
        }
    }

    /**
     * Test implementation of JwksHealthConfig with default values.
     */
    private static class TestJwksHealthConfig implements JwtValidationConfig.JwksHealthConfig {
        @Override
        public int cacheSeconds() {
            return 30;
        }

        @Override
        public int timeoutSeconds() {
            return 5;
        }
    }

    @Test
    @DisplayName("Should throw exception when configuration is null")
    void shouldThrowExceptionWhenConfigurationIsNull() {
        producer = new TokenValidatorProducer(null);

        assertThrows(IllegalStateException.class,
                () -> producer.initialize(),
                "Should throw exception when configuration is null");

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "JWT validation configuration is required");
    }

    @Test
    @DisplayName("Should throw exception when issuers are empty")
    void shouldThrowExceptionWhenIssuersAreEmpty() {
        JwtValidationConfig config = new EmptyIssuersTestConfig();
        producer = new TokenValidatorProducer(config);

        assertThrows(IllegalStateException.class,
                () -> producer.initialize(),
                "Should throw exception when issuers are empty");

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "At least one issuer configuration is required");
    }

    @Test
    @DisplayName("Should throw exception when no enabled issuers are found")
    void shouldThrowExceptionWhenNoEnabledIssuersAreFound() {
        JwtValidationConfig config = new DisabledIssuersTestConfig();
        producer = new TokenValidatorProducer(config);

        assertThrows(IllegalStateException.class,
                () -> producer.initialize(),
                "Should throw exception when no enabled issuers are found");

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "No enabled issuers found in configuration");
    }

    @Test
    @DisplayName("Should throw exception when maxTokenSizeBytes is invalid")
    void shouldThrowExceptionWhenMaxTokenSizeBytesIsInvalid() {
        JwtValidationConfig config = new InvalidMaxTokenSizeTestConfig();
        producer = new TokenValidatorProducer(config);

        assertThrows(IllegalStateException.class,
                () -> producer.initialize(),
                "Should throw exception when maxTokenSizeBytes is invalid");

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "maxTokenSizeBytes must be positive, but was: 0");
    }


    @Test
    @DisplayName("Should throw exception when parser config creation fails")
    void shouldThrowExceptionWhenParserConfigCreationFails() {
        JwtValidationConfig config = new ParserConfigExceptionTestConfig();
        producer = new TokenValidatorProducer(config);

        assertThrows(IllegalStateException.class,
                () -> producer.initialize(),
                "Should throw exception when parser config creation fails");

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "Failed to create TokenValidator");
    }

    private static class EmptyIssuersTestConfig extends TestJwtValidationConfig {
        @Override
        public Map<String, IssuerConfig> issuers() {
            return Collections.emptyMap();
        }
    }

    private static class DisabledIssuersTestConfig extends TestJwtValidationConfig {
        @Override
        public Map<String, IssuerConfig> issuers() {
            Map<String, IssuerConfig> issuers = new HashMap<>();
            issuers.put("default", new TestIssuerConfig().withEnabled(false));
            return issuers;
        }
    }

    private static class InvalidMaxTokenSizeTestConfig extends TestJwtValidationConfig {
        @Override
        public ParserConfig parser() {
            return new TestParserConfig().withMaxTokenSizeBytes(0);
        }
    }

    private static class ParserConfigExceptionTestConfig extends TestJwtValidationConfig {
        @Override
        public ParserConfig parser() {
            return new TestParserConfigWithException();
        }
    }

    private static class TestParserConfigWithException extends TestParserConfig {
        @Override
        public int maxTokenSizeBytes() {
            throw new RuntimeException("Test exception");
        }
    }
}
