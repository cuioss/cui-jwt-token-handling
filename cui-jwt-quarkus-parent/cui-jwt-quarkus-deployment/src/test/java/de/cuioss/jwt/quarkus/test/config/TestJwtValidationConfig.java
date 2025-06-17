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
package de.cuioss.jwt.quarkus.test.config;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.HealthConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.HttpJwksLoaderConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.IssuerConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.JwksHealthConfig;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig.ParserConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Test implementation of {@link JwtValidationConfig} for deployment module unit tests.
 * This class provides a mock implementation with predefined values that match test expectations.
 */
@ApplicationScoped
public class TestJwtValidationConfig {

    /**
     * Produces a mock JwtValidationConfig for testing.
     *
     * @return A mock implementation of JwtValidationConfig
     */
    @Produces
    @ApplicationScoped
    public JwtValidationConfig createTestConfig() {
        return new JwtValidationConfig() {
            @Override
            public Map<String, IssuerConfig> issuers() {
                Map<String, IssuerConfig> issuers = new HashMap<>();
                issuers.put("default", createDefaultIssuerConfig());
                issuers.put("test", createTestIssuerConfig());
                return issuers;
            }

            @Override
            public ParserConfig parser() {
                return createGlobalParserConfig();
            }

            @Override
            public HealthConfig health() {
                return createHealthConfig();
            }
        };
    }

    private IssuerConfig createDefaultIssuerConfig() {
        return new IssuerConfig() {
            @Override
            public String url() {
                return "https://example.com/auth";
            }

            @Override
            public Optional<String> publicKeyLocation() {
                return Optional.empty();
            }

            @Override
            public Optional<HttpJwksLoaderConfig> jwks() {
                return Optional.empty();
            }

            @Override
            public Optional<ParserConfig> parser() {
                return Optional.empty();
            }

            @Override
            public boolean enabled() {
                return true;
            }
        };
    }

    private IssuerConfig createTestIssuerConfig() {
        return new IssuerConfig() {
            @Override
            public String url() {
                return "https://test-idp.example.com/auth/realms/test";
            }

            @Override
            public Optional<String> publicKeyLocation() {
                return Optional.of("classpath:keys/test_public_key.pem");
            }

            @Override
            public Optional<HttpJwksLoaderConfig> jwks() {
                return Optional.of(createTestJwksConfig());
            }

            @Override
            public Optional<ParserConfig> parser() {
                return Optional.of(createTestParserConfig());
            }

            @Override
            public boolean enabled() {
                return true;
            }
        };
    }

    private HttpJwksLoaderConfig createTestJwksConfig() {
        return new HttpJwksLoaderConfig() {
            @Override
            public Optional<String> url() {
                return Optional.of("https://test-idp.example.com/auth/realms/test/protocol/openid-connect/certs");
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
            public int connectionTimeoutMs() {
                return 2000;
            }

            @Override
            public int readTimeoutMs() {
                return 2000;
            }

            @Override
            public int maxRetries() {
                return 3;
            }

            @Override
            public boolean useSystemProxy() {
                return false;
            }
        };
    }

    private ParserConfig createTestParserConfig() {
        return new ParserConfig() {
            @Override
            public Optional<String> audience() {
                return Optional.of("test-app");
            }

            @Override
            public int leewaySeconds() {
                return 45;
            }

            @Override
            public int maxTokenSizeBytes() {
                return 4096;
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
                return "RS256,ES256";
            }
        };
    }

    private ParserConfig createGlobalParserConfig() {
        return new ParserConfig() {
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
                return "RS256,RS384,RS512,ES256,ES384,ES512";
            }
        };
    }

    private HealthConfig createHealthConfig() {
        return new HealthConfig() {
            @Override
            public boolean enabled() {
                return true;
            }

            @Override
            public JwksHealthConfig jwks() {
                return createJwksHealthConfig();
            }
        };
    }

    private JwksHealthConfig createJwksHealthConfig() {
        return new JwksHealthConfig() {
            @Override
            public int cacheSeconds() {
                return 30;
            }

            @Override
            public int timeoutSeconds() {
                return 5;
            }
        };
    }
}
