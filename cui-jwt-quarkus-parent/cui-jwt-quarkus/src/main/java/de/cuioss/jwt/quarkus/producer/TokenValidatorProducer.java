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
import org.eclipse.microprofile.config.Config;
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
 * The producer performs comprehensive validation at startup to fail fast if the configuration
 * is invalid. The initialization process is split into distinct phases:
 * </p>
 * <ul>
 *   <li>Configuration validation - validates all configuration parameters</li>
 *   <li>TokenValidator creation - creates and configures the validator instance</li>
 *   <li>Security event counter initialization - sets up monitoring for each issuer</li>
 * </ul>
 * <p>
 * Enhanced error handling provides detailed error messages for troubleshooting
 * configuration issues during application startup.
 * </p>
 */
@ApplicationScoped
public class TokenValidatorProducer {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorProducer.class);

    @Getter
    private TokenValidator tokenValidator;

    private final SecurityEventCounter securityEventCounter = new SecurityEventCounter();

    @Inject
    Config config;

    @Getter
    private List<IssuerConfig> issuerConfigs;

    /**
     * Initializes the TokenValidator at startup.
     * This method validates the configuration and fails fast if it's invalid.
     */
    @PostConstruct
    void initialize() {
        LOGGER.info("Initializing TokenValidator");

        validateConfiguration();
        tokenValidator = createTokenValidator();

        LOGGER.info("TokenValidator initialized with %s issuers", issuerConfigs.size());
    }

    /**
     * Validates the JWT validation configuration.
     * <p>
     * Uses direct Config.getConfigMapping() call instead of CDI injection to avoid
     * known issues with @ConfigMapping CDI injection in Quarkus extensions.
     * </p>
     * <p>
     * This approach is recommended for Quarkus extensions as documented in:
     * <ul>
     *   <li><a href="https://quarkus.io/guides/writing-extensions#configuration-mapping">Quarkus Extension Configuration Guide</a></li>
     *   <li><a href="https://github.com/quarkusio/quarkus/issues/29583">Quarkus Issue #29583: ConfigMapping CDI injection in extensions</a></li>
     * </ul>
     * </p>
     * Performs comprehensive validation and fails fast if configuration is invalid.
     *
     * @throws IllegalStateException if configuration is invalid
     */
    private void validateConfiguration() {
        // Direct ConfigMapping retrieval - recommended approach for Quarkus extensions
        // This avoids CDI injection issues with @ConfigMapping interfaces in extension contexts
        JwtValidationConfig jwtValidationConfig = getJwtValidationConfig();
        
        if (jwtValidationConfig == null) {
            LOGGER.error("JWT validation configuration is required");
            throw new IllegalStateException("JWT validation configuration is required");
        }

        if (jwtValidationConfig.issuers().isEmpty()) {
            LOGGER.error("At least one issuer configuration is required");
            throw new IllegalStateException("At least one issuer configuration is required");
        }

        // Create issuer configs using the factory and validate
        issuerConfigs = IssuerConfigFactory.createIssuerConfigs(jwtValidationConfig.issuers());

        if (issuerConfigs.isEmpty()) {
            LOGGER.error("No enabled issuers found in configuration");
            throw new IllegalStateException("No enabled issuers found in configuration");
        }

        // Validate parser configuration consistency
        try {
            int maxTokenSize = jwtValidationConfig.parser().maxTokenSizeBytes();
            if (maxTokenSize <= 0) {
                LOGGER.error("maxTokenSizeBytes must be positive, but was: " + maxTokenSize);
                throw new IllegalStateException("maxTokenSizeBytes must be positive, but was: " + maxTokenSize);
            }
        } catch (RuntimeException e) {
            LOGGER.error("Failed to create TokenValidator: " + e.getMessage(), e);
            throw new IllegalStateException("Failed to create TokenValidator: " + e.getMessage(), e);
        }

        LOGGER.debug("Configuration validation successful - found %d enabled issuers", issuerConfigs.size());
    }

    /**
     * Retrieves the JWT validation configuration using direct ConfigMapping approach.
     * <p>
     * This method uses the recommended pattern for accessing @ConfigMapping interfaces
     * in Quarkus extensions, avoiding CDI injection issues that can occur in extension contexts.
     * </p>
     * <p>
     * The approach follows the pattern documented in:
     * <ul>
     *   <li><a href="https://quarkus.io/guides/config-mappings#accessing-configmapping-from-application">Quarkus ConfigMapping Access Guide</a></li>
     *   <li><a href="https://smallrye.io/smallrye-config/Latest/config/mappings/">SmallRye Config Mappings Documentation</a></li>
     * </ul>
     * </p>
     * 
     * @return the JWT validation configuration instance
     * @throws IllegalStateException if configuration mapping cannot be created
     */
    private JwtValidationConfig getJwtValidationConfig() {
        try {
            // Use SmallRyeConfig.getConfigMapping() for direct access to @ConfigMapping interfaces
            // This is the recommended approach in Quarkus extensions to avoid CDI injection issues
            return config.unwrap(io.smallrye.config.SmallRyeConfig.class)
                    .getConfigMapping(JwtValidationConfig.class);
        } catch (Exception e) {
            String errorMessage = "Failed to retrieve JWT validation configuration: " + e.getMessage();
            LOGGER.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }

    /**
     * Creates and configures the TokenValidator instance.
     *
     * @return the configured TokenValidator
     * @throws IllegalStateException if TokenValidator creation fails
     */
    private TokenValidator createTokenValidator() {
        try {
            // Get configuration using direct ConfigMapping retrieval
            JwtValidationConfig jwtValidationConfig = getJwtValidationConfig();
            
            // Create parser config
            ParserConfig parserConfig = createParserConfig(jwtValidationConfig.parser());

            // Initialize security event counter for each issuer config
            initializeSecurityEventCounters();

            // Create TokenValidator
            TokenValidator validator = new TokenValidator(parserConfig, issuerConfigs.toArray(new IssuerConfig[0]));

            LOGGER.debug("TokenValidator created successfully");
            return validator;
        } catch (Exception e) {
            String errorMessage = "Failed to create TokenValidator: " + e.getMessage();
            LOGGER.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }

    /**
     * Initializes security event counters for all issuer configurations.
     */
    private void initializeSecurityEventCounters() {
        for (IssuerConfig issuerConfig : issuerConfigs) {
            try {
                issuerConfig.initSecurityEventCounter(securityEventCounter);
                LOGGER.debug("Security event counter initialized for issuer: %s", issuerConfig.getIssuer());
            } catch (Exception e) {
                String errorMessage = "Failed to initialize security event counter for issuer '%s': %s".formatted(
                        issuerConfig.getIssuer(), e.getMessage());
                LOGGER.error(errorMessage, e);
                throw new IllegalStateException(errorMessage, e);
            }
        }
    }

    /**
     * Produces a {@link TokenValidator} instance.
     * This method is called by CDI and handles initialization directly to ensure proper error handling.
     *
     * @return the configured TokenValidator
     */
    @Produces
    @ApplicationScoped
    public TokenValidator produceTokenValidator() {
        if (tokenValidator == null) {
            // Initialize on-demand if @PostConstruct failed or wasn't called
            LOGGER.info("TokenValidator not initialized, initializing on-demand");
            try {
                validateConfiguration();
                tokenValidator = createTokenValidator();
                LOGGER.info("TokenValidator initialized with %s issuers", issuerConfigs.size());
            } catch (Exception e) {
                LOGGER.error("Failed to initialize TokenValidator: %s", e.getMessage(), e);
                throw new IllegalStateException("Cannot produce TokenValidator: " + e.getMessage(), e);
            }
        }
        return tokenValidator;
    }

    /**
     * Creates a ParserConfig from the configuration.
     * Validates parser configuration parameters and provides comprehensive logging.
     *
     * @param parserConfig the parser configuration
     * @return a ParserConfig instance
     * @throws IllegalArgumentException if parser configuration is invalid
     */
    private ParserConfig createParserConfig(JwtValidationConfig.ParserConfig parserConfig) {
        try {
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

            ParserConfig result = builder.build();
            LOGGER.debug("ParserConfig created successfully");
            return result;
        } catch (Exception e) {
            String errorMessage = "Failed to create ParserConfig: " + e.getMessage();
            LOGGER.error(errorMessage, e);
            throw new IllegalArgumentException(errorMessage, e);
        }
    }
}
