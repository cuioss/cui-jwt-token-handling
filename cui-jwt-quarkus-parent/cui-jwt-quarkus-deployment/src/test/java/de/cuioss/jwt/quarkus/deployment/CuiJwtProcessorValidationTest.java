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

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for the validation methods in {@link CuiJwtProcessor}.
 * <p>
 * This test class focuses on testing the validation logic in CuiJwtProcessor
 * by providing invalid configurations and verifying that the appropriate
 * exceptions are thrown.
 */
@EnableTestLogger
@DisplayName("CuiJwtProcessor Validation Tests")
class CuiJwtProcessorValidationTest {

    private final CuiJwtProcessor processor = new CuiJwtProcessor();

    @Test
    @DisplayName("Should throw exception when config is null")
    void shouldThrowExceptionWhenConfigIsNull() {
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> processor.feature(null),
                "Should throw exception when config is null");

        assertTrue(exception.getMessage().contains("JWT validation configuration is missing"),
                "Exception message should mention missing configuration");
    }

    @Test
    @DisplayName("Should throw exception when parser config is null")
    void shouldThrowExceptionWhenParserConfigIsNull() {
        JwtValidationConfig config = new TestJwtValidationConfig() {
            @Override
            public ParserConfig parser() {
                return null;
            }
        };

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> processor.feature(config),
                "Should throw exception when parser config is null");

        assertTrue(exception.getMessage().contains("JWT parser configuration is missing"),
                "Exception message should mention missing parser configuration");
    }

    @Test
    @DisplayName("Should throw exception when issuers are null or empty")
    void shouldThrowExceptionWhenIssuersAreNullOrEmpty() {
        // Test with null issuers
        JwtValidationConfig configWithNullIssuers = new TestJwtValidationConfig() {
            @Override
            public Map<String, IssuerConfig> issuers() {
                return null;
            }
        };

        RuntimeException exceptionForNull = assertThrows(RuntimeException.class,
                () -> processor.feature(configWithNullIssuers),
                "Should throw exception when issuers are null");

        assertTrue(exceptionForNull.getMessage().contains("No JWT issuers configured"),
                "Exception message should mention no issuers configured");

        // Test with empty issuers
        JwtValidationConfig configWithEmptyIssuers = new TestJwtValidationConfig() {
            @Override
            public Map<String, IssuerConfig> issuers() {
                return new HashMap<>();
            }
        };

        RuntimeException exceptionForEmpty = assertThrows(RuntimeException.class,
                () -> processor.feature(configWithEmptyIssuers),
                "Should throw exception when issuers are empty");

        assertTrue(exceptionForEmpty.getMessage().contains("No JWT issuers configured"),
                "Exception message should mention no issuers configured");
    }

    @Test
    @DisplayName("Should throw exception when parser maxTokenSizeBytes is invalid")
    void shouldThrowExceptionWhenMaxTokenSizeBytesIsInvalid() {
        JwtValidationConfig config = new TestJwtValidationConfig() {
            @Override
            public ParserConfig parser() {
                return new TestParserConfig() {
                    @Override
                    public int maxTokenSizeBytes() {
                        return 0; // Invalid value
                    }
                };
            }
        };

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> processor.feature(config),
                "Should throw exception when maxTokenSizeBytes is invalid");

        assertTrue(exception.getMessage().contains("JWT parser maxTokenSizeBytes must be positive"),
                "Exception message should mention maxTokenSizeBytes must be positive");
    }

    @Test
    @DisplayName("Should throw exception when parser leewaySeconds is negative")
    void shouldThrowExceptionWhenLeewaySecondsIsNegative() {
        JwtValidationConfig config = new TestJwtValidationConfig() {
            @Override
            public ParserConfig parser() {
                return new TestParserConfig() {
                    @Override
                    public int leewaySeconds() {
                        return -1; // Invalid value
                    }
                };
            }
        };

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> processor.feature(config),
                "Should throw exception when leewaySeconds is negative");

        assertTrue(exception.getMessage().contains("JWT parser leewaySeconds must be non-negative"),
                "Exception message should mention leewaySeconds must be non-negative");
    }

    @Test
    @DisplayName("Should throw exception when parser allowedAlgorithms is empty")
    void shouldThrowExceptionWhenAllowedAlgorithmsIsEmpty() {
        JwtValidationConfig config = new TestJwtValidationConfig() {
            @Override
            public ParserConfig parser() {
                return new TestParserConfig() {
                    @Override
                    public String allowedAlgorithms() {
                        return ""; // Invalid value
                    }
                };
            }
        };

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> processor.feature(config),
                "Should throw exception when allowedAlgorithms is empty");

        assertTrue(exception.getMessage().contains("JWT parser allowedAlgorithms cannot be empty"),
                "Exception message should mention allowedAlgorithms cannot be empty");
    }

    @Test
    @DisplayName("Should throw exception when parser allowedAlgorithms contains 'none'")
    void shouldThrowExceptionWhenAllowedAlgorithmsContainsNone() {
        JwtValidationConfig config = new TestJwtValidationConfig() {
            @Override
            public ParserConfig parser() {
                return new TestParserConfig() {
                    @Override
                    public String allowedAlgorithms() {
                        return "RS256,none,RS512"; // Invalid value
                    }
                };
            }
        };

        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> processor.feature(config),
                "Should throw exception when allowedAlgorithms contains 'none'");

        assertTrue(exception.getMessage().contains("JWT parser allowedAlgorithms contains 'none' algorithm which is insecure"),
                "Exception message should mention 'none' algorithm is insecure");
    }

    /**
     * Test implementation of JwtValidationConfig for testing purposes.
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

    private static class TestIssuerConfig implements JwtValidationConfig.IssuerConfig {
        @Override
        public String url() {
            return "https://example.com/issuer";
        }

        @Override
        public Optional<String> publicKeyLocation() {
            return Optional.empty();
        }

        @Override
        public Optional<JwtValidationConfig.HttpJwksLoaderConfig> jwks() {
            return Optional.of(new TestHttpJwksLoaderConfig());
        }

        @Override
        public Optional<JwtValidationConfig.ParserConfig> parser() {
            return Optional.empty();
        }

        @Override
        public boolean enabled() {
            return true;
        }
    }

    private static class TestParserConfig implements JwtValidationConfig.ParserConfig {
        @Override
        public Optional<String> audience() {
            return Optional.empty();
        }

        @Override
        public int leewaySeconds() {
            return 30;
        }

        @Override
        public int maxTokenSizeBytes() {
            return 8192;
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
            return "RS256,RS384,RS512";
        }
    }

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
}