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

import de.cuioss.jwt.quarkus.config.JwtPropertyKeys;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.well_known.WellKnownHandler;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import lombok.Getter;
import org.eclipse.microprofile.config.Config;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
@ApplicationScoped
public class TokenValidatorProducer {

    private static final CuiLogger LOGGER = new CuiLogger(TokenValidatorProducer.class);

    @Getter
    private TokenValidator tokenValidator;

    private final SecurityEventCounter securityEventCounter = new SecurityEventCounter();

    private final Config config;

    @Getter
    private List<IssuerConfig> issuerConfigs;

    private final Map<String, WellKnownHandler> wellKnownHandlerCache = new HashMap<>();

    public TokenValidatorProducer(Config config) {
        this.config = config;
        this.issuerConfigs = new ArrayList<>();
    }


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
            int maxTokenSize = config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE_BYTES, Integer.class).orElse(8192);
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
     * Dynamically discovers all configured issuers by scanning properties starting with cui.jwt.issuers.*
     */
    private List<IssuerConfig> createIssuerConfigsFromProperties() {
        List<IssuerConfig> issuers = new ArrayList<>();
        Set<String> issuerNames = discoverIssuerNames();

        for (String issuerName : issuerNames) {
            boolean enabled = config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".enabled", Boolean.class).orElse(false);
            if (enabled) {
                String issuerIdentifier = resolveIssuerIdentifier(issuerName);
                if (issuerIdentifier != null) {
                    IssuerConfig issuer = createIssuerConfig(issuerName, issuerIdentifier);
                    if (issuer != null) {
                        issuers.add(issuer);
                        LOGGER.info("Added issuer '%s': %s", issuerName, issuerIdentifier);
                    }
                } else {
                    LOGGER.warn("Issuer '%s' is enabled but missing issuer identifier configuration", issuerName);
                }
            }
        }

        return issuers;
    }

    /**
     * Discovers all configured issuer names by scanning properties starting with cui.jwt.issuers.*
     */
    private Set<String> discoverIssuerNames() {
        Set<String> issuerNames = new HashSet<>();
        String prefix = JwtPropertyKeys.ISSUERS.BASE + ".";

        for (String propertyName : config.getPropertyNames()) {
            if (propertyName.startsWith(prefix)) {
                String remainder = propertyName.substring(prefix.length());
                int firstDot = remainder.indexOf('.');
                if (firstDot > 0) {
                    String issuerName = remainder.substring(0, firstDot);
                    issuerNames.add(issuerName);
                }
            }
        }

        LOGGER.debug("Discovered issuer names: %s", issuerNames);
        return issuerNames;
    }

    /**
     * Resolves the issuer identifier for a given issuer name.
     * Validates that only one source of issuer identifier is configured:
     * either explicit identifier or well-known discovery.
     */
    private String resolveIssuerIdentifier(String issuerName) {
        String explicitIdentifier = config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".identifier", String.class).orElse(null);
        String wellKnownUrl = config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".well-known-url", String.class).orElse(null);

        if (explicitIdentifier != null && wellKnownUrl != null) {
            String errorMessage = "Issuer '%s' has both explicit identifier and well-known-url configured. Only one can be specified.".formatted(issuerName);
            LOGGER.error(errorMessage);
            throw new IllegalStateException(errorMessage);
        }

        if (explicitIdentifier != null) {
            LOGGER.debug("Using explicit identifier for issuer '%s': %s", issuerName, explicitIdentifier);
            return explicitIdentifier;
        }

        if (wellKnownUrl != null) {
            try {
                WellKnownHandler wellKnownHandler = getOrCreateWellKnownHandler(issuerName, wellKnownUrl);
                String discoveredIssuer = wellKnownHandler.getIssuer().getUri().toString();
                LOGGER.debug("Discovered issuer identifier from well-known URL for issuer '%s': %s", issuerName, discoveredIssuer);
                return discoveredIssuer;
            } catch (Exception e) {
                LOGGER.error("Failed to discover issuer identifier from well-known URL for issuer '%s': %s", issuerName, e.getMessage());
                throw new IllegalStateException("Failed to discover issuer identifier from well-known URL for issuer '%s': %s".formatted(issuerName, e.getMessage()), e);
            }
        }

        LOGGER.warn("No issuer identifier configuration found for issuer '%s'", issuerName);
        return null;
    }

    /**
     * Gets or creates a cached WellKnownHandler for the given issuer to avoid redundant network calls.
     * 
     * @param issuerName the issuer name
     * @param wellKnownUrl the well-known URL
     * @return cached or newly created WellKnownHandler
     */
    private WellKnownHandler getOrCreateWellKnownHandler(String issuerName, String wellKnownUrl) {
        return wellKnownHandlerCache.computeIfAbsent(issuerName, key -> {
            LOGGER.debug("Creating WellKnownHandler for issuer '%s' with URL: %s", issuerName, wellKnownUrl);
            return WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .connectTimeoutSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".jwks.connection-timeout-seconds", Integer.class).orElse(5))
                    .readTimeoutSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".jwks.read-timeout-seconds", Integer.class).orElse(5))
                    .build();
        });
    }

    /**
     * Creates a single IssuerConfig from properties for a given issuer name.
     */
    private IssuerConfig createIssuerConfig(String issuerName, String issuerIdentifier) {
        try {
            IssuerConfig.IssuerConfigBuilder builder = IssuerConfig.builder().issuer(issuerIdentifier);

            // Check for public key location
            String publicKeyLocation = config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".public-key-location", String.class).orElse(null);
            if (publicKeyLocation != null) {
                builder.jwksFilePath(publicKeyLocation);
                LOGGER.debug("Set public key location for " + issuerName + ": " + publicKeyLocation);
            }

            // Check for JWKS URL and well-known URL - validate they're not both configured
            String jwksUrl = config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".jwks.url", String.class).orElse(null);
            String wellKnownUrl = config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + ".well-known-url", String.class).orElse(null);

            if (jwksUrl != null && wellKnownUrl != null) {
                String errorMessage = "Issuer '%s' has both jwks.url and well-known-url configured. Only one can be specified.".formatted(issuerName);
                LOGGER.error(errorMessage);
                throw new IllegalStateException(errorMessage);
            }

            if (jwksUrl != null) {
                // Create JWKS config with direct URL
                HttpJwksLoaderConfig jwksConfig =
                        HttpJwksLoaderConfig.builder()
                                .url(jwksUrl)
                                .refreshIntervalSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + JwtPropertyKeys.ISSUERS.JWKS.REFRESH_INTERVAL_SECONDS_PARTIAL, Integer.class).orElse(300))
                                .connectTimeoutSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + JwtPropertyKeys.ISSUERS.JWKS.CONNECTION_TIMEOUT_SECONDS_PARTIAL, Integer.class).orElse(5))
                                .readTimeoutSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + JwtPropertyKeys.ISSUERS.JWKS.READ_TIMEOUT_SECONDS_PARTIAL, Integer.class).orElse(5))
                                .build();
                builder.httpJwksLoaderConfig(jwksConfig);
                LOGGER.debug("Set JWKS URL for " + issuerName + ": " + jwksUrl);
            } else if (wellKnownUrl != null) {
                // Reuse cached WellKnownHandler to avoid redundant network calls
                WellKnownHandler wellKnownHandler = getOrCreateWellKnownHandler(issuerName, wellKnownUrl);

                // Create JWKS config with well-known discovery
                HttpJwksLoaderConfig jwksConfig =
                        HttpJwksLoaderConfig.builder()
                                .wellKnown(wellKnownHandler)
                                .refreshIntervalSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + JwtPropertyKeys.ISSUERS.JWKS.REFRESH_INTERVAL_SECONDS_PARTIAL, Integer.class).orElse(300))
                                .connectTimeoutSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + JwtPropertyKeys.ISSUERS.JWKS.CONNECTION_TIMEOUT_SECONDS_PARTIAL, Integer.class).orElse(5))
                                .readTimeoutSeconds(config.getOptionalValue(JwtPropertyKeys.ISSUERS.BASE + "." + issuerName + JwtPropertyKeys.ISSUERS.JWKS.READ_TIMEOUT_SECONDS_PARTIAL, Integer.class).orElse(5))
                                .build();
                builder.httpJwksLoaderConfig(jwksConfig);
                LOGGER.debug("Set well-known URL for " + issuerName + ": " + wellKnownUrl);
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
    @ApplicationScoped
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
            int maxTokenSizeBytes = config.getOptionalValue(JwtPropertyKeys.PARSER.MAX_TOKEN_SIZE_BYTES, Integer.class).orElse(8192);
            boolean validateExpiration = config.getOptionalValue(JwtPropertyKeys.PARSER.VALIDATE_EXPIRATION, Boolean.class).orElse(true);
            boolean validateIssuedAt = config.getOptionalValue(JwtPropertyKeys.PARSER.VALIDATE_ISSUED_AT, Boolean.class).orElse(false);
            boolean validateNotBefore = config.getOptionalValue(JwtPropertyKeys.PARSER.VALIDATE_NOT_BEFORE, Boolean.class).orElse(true);
            int leewaySeconds = config.getOptionalValue(JwtPropertyKeys.PARSER.LEEWAY_SECONDS, Integer.class).orElse(30);
            String audience = config.getOptionalValue(JwtPropertyKeys.PARSER.AUDIENCE, String.class).orElse(null);
            String allowedAlgorithms = config.getOptionalValue(JwtPropertyKeys.PARSER.ALLOWED_ALGORITHMS, String.class).orElse("RS256,RS384,RS512,ES256,ES384,ES512");

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
