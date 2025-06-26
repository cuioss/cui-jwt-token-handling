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

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import io.quarkus.runtime.Startup;
import org.eclipse.microprofile.config.Config;
import lombok.Getter;

import java.util.List;

/**
 * CDI producer for {@link TokenValidator} instances.
 * <p>
 * This producer creates a properly configured TokenValidator based on the
 * configuration properties.
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
@Singleton
@Startup
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
     * Initializes the TokenValidator lazily when first accessed.
     * This method validates the configuration and fails fast if it's invalid.
     */
    private synchronized void initializeIfNeeded() {
        if (tokenValidator == null) {
            LOGGER.info("Initializing TokenValidator");
            validateConfiguration();
            tokenValidator = createTokenValidator();
            LOGGER.info("TokenValidator initialized with %s issuers", issuerConfigs.size());
        }
    }

    /**
     * Validates the JWT validation configuration.
     * Performs comprehensive validation and fails fast if configuration is invalid.
     *
     * @throws IllegalStateException if configuration is invalid
     */
    private void validateConfiguration() {
        LOGGER.info("Validating JWT configuration");
        
        // Create issuer configs from properties
        issuerConfigs = createIssuerConfigsFromProperties();

        if (issuerConfigs.isEmpty()) {
            LOGGER.error("No enabled issuers found in configuration");
            throw new IllegalStateException("No enabled issuers found in configuration");
        }

        // Validate parser configuration using direct property access
        try {
            int maxTokenSize = config.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(8192);
            if (maxTokenSize <= 0) {
                LOGGER.error("maxTokenSizeBytes must be positive, but was: " + maxTokenSize);
                throw new IllegalStateException("maxTokenSizeBytes must be positive, but was: " + maxTokenSize);
            }
        } catch (RuntimeException e) {
            LOGGER.error("Failed to validate parser configuration: " + e.getMessage(), e);
            throw new IllegalStateException("Failed to validate parser configuration: " + e.getMessage(), e);
        }

        LOGGER.debug("Configuration validation successful - found %d enabled issuers", issuerConfigs.size());
    }
    
    /**
     * Creates issuer configurations from direct property access.
     */
    private List<IssuerConfig> createIssuerConfigsFromProperties() {
        List<IssuerConfig> issuers = new java.util.ArrayList<>();
        
        // Check for default issuer
        if (config.getOptionalValue("cui.jwt.issuers.default.enabled", Boolean.class).orElse(false)) {
            String url = config.getOptionalValue("cui.jwt.issuers.default.url", String.class).orElse(null);
            if (url != null) {
                IssuerConfig issuer = createIssuerConfig("default", url);
                if (issuer != null) {
                    issuers.add(issuer);
                    LOGGER.info("Added default issuer: " + url);
                }
            }
        }
        
        // Check for keycloak issuer
        if (config.getOptionalValue("cui.jwt.issuers.keycloak.enabled", Boolean.class).orElse(false)) {
            String url = config.getOptionalValue("cui.jwt.issuers.keycloak.url", String.class).orElse(null);
            if (url != null) {
                IssuerConfig issuer = createIssuerConfig("keycloak", url);
                if (issuer != null) {
                    issuers.add(issuer);
                    LOGGER.info("Added keycloak issuer: " + url);
                }
            }
        }
        
        // Check for wellknown issuer
        if (config.getOptionalValue("cui.jwt.issuers.wellknown.enabled", Boolean.class).orElse(false)) {
            String url = config.getOptionalValue("cui.jwt.issuers.wellknown.url", String.class).orElse(null);
            if (url != null) {
                IssuerConfig issuer = createIssuerConfig("wellknown", url);
                if (issuer != null) {
                    issuers.add(issuer);
                    LOGGER.info("Added wellknown issuer: " + url);
                }
            }
        }
        
        return issuers;
    }
    
    /**
     * Creates a single IssuerConfig from properties for a given issuer name.
     */
    private IssuerConfig createIssuerConfig(String issuerName, String issuerUrl) {
        try {
            IssuerConfig.IssuerConfigBuilder builder = IssuerConfig.builder().issuer(issuerUrl);
            
            // Check for public key location
            String publicKeyLocation = config.getOptionalValue("cui.jwt.issuers." + issuerName + ".public-key-location", String.class).orElse(null);
            if (publicKeyLocation != null) {
                builder.jwksFilePath(publicKeyLocation);
                LOGGER.debug("Set public key location for " + issuerName + ": " + publicKeyLocation);
            }
            
            // Check for JWKS URL
            String jwksUrl = config.getOptionalValue("cui.jwt.issuers." + issuerName + ".jwks.url", String.class).orElse(null);
            if (jwksUrl != null) {
                // Create simple JWKS config
                de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig jwksConfig = 
                    de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig.builder()
                        .url(jwksUrl)
                        .refreshIntervalSeconds(config.getOptionalValue("cui.jwt.issuers." + issuerName + ".jwks.refresh-interval-seconds", Integer.class).orElse(300))
                        .connectTimeoutSeconds(config.getOptionalValue("cui.jwt.issuers." + issuerName + ".jwks.connection-timeout-seconds", Integer.class).orElse(5))
                        .readTimeoutSeconds(config.getOptionalValue("cui.jwt.issuers." + issuerName + ".jwks.read-timeout-seconds", Integer.class).orElse(5))
                        .build();
                builder.httpJwksLoaderConfig(jwksConfig);
                LOGGER.debug("Set JWKS URL for " + issuerName + ": " + jwksUrl);
            }
            
            return builder.build();
        } catch (Exception e) {
            LOGGER.error("Failed to create issuer config for " + issuerName + ": " + e.getMessage(), e);
            return null;
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
            // Create parser config
            ParserConfig parserConfig = createParserConfigFromProperties();

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
     * This method initializes the TokenValidator lazily when first accessed.
     *
     * @return the configured TokenValidator
     */
    @Produces
    @Singleton
    public TokenValidator produceTokenValidator() {
        initializeIfNeeded();
        return tokenValidator;
    }

    /**
     * Creates a ParserConfig from direct property access.
     * Validates parser configuration parameters and provides comprehensive logging.
     *
     * @return a ParserConfig instance
     * @throws IllegalArgumentException if parser configuration is invalid
     */
    private ParserConfig createParserConfigFromProperties() {
        try {
            // Read parser configuration with defaults
            int maxTokenSizeBytes = config.getOptionalValue("cui.jwt.parser.max-token-size-bytes", Integer.class).orElse(8192);
            boolean validateExpiration = config.getOptionalValue("cui.jwt.parser.validate-expiration", Boolean.class).orElse(true);
            boolean validateIssuedAt = config.getOptionalValue("cui.jwt.parser.validate-issued-at", Boolean.class).orElse(false);
            boolean validateNotBefore = config.getOptionalValue("cui.jwt.parser.validate-not-before", Boolean.class).orElse(true);
            int leewaySeconds = config.getOptionalValue("cui.jwt.parser.leeway-seconds", Integer.class).orElse(30);
            String audience = config.getOptionalValue("cui.jwt.parser.audience", String.class).orElse(null);
            String allowedAlgorithms = config.getOptionalValue("cui.jwt.parser.allowed-algorithms", String.class).orElse("RS256,RS384,RS512,ES256,ES384,ES512");

            // Note: The ParserConfig class only supports maxTokenSize configuration
            // Other validation settings like expiration, issuedAt, notBefore, leeway, audience, and algorithms
            // are handled by the TokenValidator internally
            ParserConfig.ParserConfigBuilder builder = ParserConfig.builder()
                    .maxTokenSize(maxTokenSizeBytes);

            // Log the configuration that will be applied by the TokenValidator
            LOGGER.info("Creating ParserConfig with maxTokenSize=%d bytes", maxTokenSizeBytes);
            LOGGER.info("TokenValidator will use validateExpiration=%s", validateExpiration);
            LOGGER.info("TokenValidator will use validateIssuedAt=%s", validateIssuedAt);
            LOGGER.info("TokenValidator will use validateNotBefore=%s", validateNotBefore);
            LOGGER.info("TokenValidator will use leeway=%d seconds", leewaySeconds);
            if (audience != null) {
                LOGGER.info("TokenValidator will use expected audience=%s", audience);
            }
            LOGGER.info("TokenValidator will use allowedAlgorithms=%s", allowedAlgorithms);

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
