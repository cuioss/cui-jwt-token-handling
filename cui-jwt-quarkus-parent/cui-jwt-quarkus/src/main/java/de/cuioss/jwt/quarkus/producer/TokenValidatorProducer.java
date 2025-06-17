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
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import lombok.Getter;

import java.util.List;

/**
 * CDI producer for {@link TokenValidator} instances.
 * <p>
 * This producer creates a properly configured TokenValidator based on the
 * configuration provided by {@link JwtValidationConfig}.
 * </p>
 * <p>
 * The producer performs validation at startup to fail fast if the configuration
 * is invalid.
 * </p>
 */
@ApplicationScoped
public class TokenValidatorProducer {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorProducer.class);

    @Getter
    private TokenValidator tokenValidator;

    private final SecurityEventCounter securityEventCounter = new SecurityEventCounter();

    private final JwtValidationConfig jwtValidationConfig;

    @Getter
    private List<IssuerConfig> issuerConfigs;

    /**
     * Constructor for TokenValidatorProducer.
     *
     * @param jwtValidationConfig the JWT validation configuration
     */
    @Inject
    public TokenValidatorProducer(JwtValidationConfig jwtValidationConfig) {
        this.jwtValidationConfig = jwtValidationConfig;
    }

    /**
     * Initializes the TokenValidator at startup.
     * This method validates the configuration and fails fast if it's invalid.
     */
    @PostConstruct
    void initialize() {
        LOGGER.info("Initializing TokenValidator");

        // Create parser config
        ParserConfig parserConfig = createParserConfig(jwtValidationConfig.parser());

        // Create issuer configs using the factory
        issuerConfigs = IssuerConfigFactory.createIssuerConfigs(jwtValidationConfig.issuers());

        if (issuerConfigs.isEmpty()) {
            throw new IllegalStateException("No enabled issuers found in configuration");
        }

        // Initialize security event counter for each issuer config
        for (IssuerConfig issuerConfig : issuerConfigs) {
            issuerConfig.initSecurityEventCounter(securityEventCounter);
        }

        // Create TokenValidator
        tokenValidator = new TokenValidator(parserConfig, issuerConfigs.toArray(new IssuerConfig[0]));

        LOGGER.info("TokenValidator initialized with %s issuers", issuerConfigs.size());
    }

    /**
     * Produces a {@link TokenValidator} instance.
     *
     * @return the configured TokenValidator
     */
    @Produces
    @ApplicationScoped
    public TokenValidator produceTokenValidator() {
        return tokenValidator;
    }

    /**
     * Creates a ParserConfig from the configuration.
     *
     * @param parserConfig the parser configuration
     * @return a ParserConfig instance
     */
    private ParserConfig createParserConfig(JwtValidationConfig.ParserConfig parserConfig) {
        // Note: The ParserConfig class only supports maxTokenSize configuration
        // Other validation settings like expiration, issuedAt, notBefore, leeway, audience, and algorithms
        // are handled by the TokenValidator internally
        ParserConfig.ParserConfigBuilder builder = ParserConfig.builder()
                .maxTokenSize(parserConfig.maxTokenSizeBytes());

        // Log the configuration that will be applied by the TokenValidator
        LOGGER.info("Creating ParserConfig with maxTokenSize=%d bytes", parserConfig.maxTokenSizeBytes());
        LOGGER.info("TokenValidator will use validateExpiration=%s", parserConfig.validateExpiration());
        LOGGER.info("TokenValidator will use validateIssuedAt=%s", parserConfig.validateIssuedAt());
        LOGGER.info("TokenValidator will use validateNotBefore=%s", parserConfig.validateNotBefore());
        LOGGER.info("TokenValidator will use leeway=%d seconds", parserConfig.leewaySeconds());
        parserConfig.audience().ifPresent(audience ->
                LOGGER.info("TokenValidator will use expected audience=%s", audience));
        LOGGER.info("TokenValidator will use allowedAlgorithms=%s", parserConfig.allowedAlgorithms());

        return builder.build();
    }
}
