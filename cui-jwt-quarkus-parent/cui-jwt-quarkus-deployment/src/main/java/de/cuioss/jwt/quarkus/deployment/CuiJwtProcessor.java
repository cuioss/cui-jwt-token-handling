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
import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.SystemPropertyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.devui.spi.page.Page;
import org.jboss.logging.Logger;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

/**
 * Processor for the CUI JWT Quarkus extension.
 * <p>
 * This class handles the build-time processing for the extension, including
 * registering the feature, setting up reflection configuration, and providing
 * build-time configuration validation with enhanced error reporting.
 * </p>
 * <p>
 * Enhanced features include:
 * </p>
 * <ul>
 *   <li>Build-time configuration validation with detailed error messages</li>
 *   <li>Compile-time security checks for configuration consistency</li>
 *   <li>Enhanced reflection registration for native image support</li>
 *   <li>Development-time DevUI integration with runtime status monitoring</li>
 * </ul>
 */
public class CuiJwtProcessor {

    /**
     * The feature name for the CUI JWT extension.
     */
    private static final String FEATURE = "cui-jwt";

    /**
     * Logger for build-time configuration validation and error reporting.
     */
    private static final Logger LOGGER = Logger.getLogger(CuiJwtProcessor.class);

    /**
     * Register the CUI JWT feature with build-time configuration validation.
     *
     * @param config the JWT validation configuration
     * @return A {@link FeatureBuildItem} for the CUI JWT feature
     */
    @BuildStep
    public FeatureBuildItem feature(JwtValidationConfig config) {
        validateBuildTimeConfiguration(config);
        LOGGER.infof("CUI JWT feature registered with %d configured issuers",
            config.issuers().size());
        return new FeatureBuildItem(FEATURE);
    }


    /**
     * Register the JWT validation configuration for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the JWT validation configuration
     */
    @BuildStep
    public ReflectiveClassBuildItem registerConfigForReflection() {
        return ReflectiveClassBuildItem.builder("de.cuioss.jwt.quarkus.config.JwtValidationConfig")
                .methods(true)
                .fields(true)
                .build();
    }

    /**
     * Register nested configuration classes for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the nested configuration classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerNestedConfigForReflection() {
        return ReflectiveClassBuildItem.builder(
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$IssuerConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$ParserConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$HttpJwksLoaderConfig")
                .methods(true)
                .fields(true)
                .build();
    }

    /**
     * Register JWT validation classes for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the JWT validation classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerJwtValidationClassesForReflection() {
        return ReflectiveClassBuildItem.builder(
                "de.cuioss.jwt.validation.TokenValidator",
                "de.cuioss.jwt.validation.IssuerConfig",
                "de.cuioss.jwt.validation.ParserConfig",
                "de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig",
                "de.cuioss.jwt.validation.security.SecurityEventCounter")
                .methods(true)
                .fields(true)
                .constructors(true)
                .build();
    }

    /**
     * Register classes that need to be initialized at runtime.
     *
     * @return A {@link RuntimeInitializedClassBuildItem} for classes that need runtime initialization
     */
    @BuildStep
    public RuntimeInitializedClassBuildItem runtimeInitializedClasses() {
        return new RuntimeInitializedClassBuildItem("de.cuioss.jwt.validation.jwks.http.HttpJwksLoader");
    }

    /**
     * Create DevUI card page for JWT validation monitoring and debugging.
     *
     * @return A {@link CardPageBuildItem} for the JWT DevUI card
     */
    @BuildStep(onlyIf = IsDevelopment.class)
    public CardPageBuildItem createJwtDevUICard() {
        CardPageBuildItem cardPageBuildItem = new CardPageBuildItem();

        // JWT Validation Status page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:shield-check")
                .title("JWT Validation Status")
                .componentLink("components/qwc-jwt-validation-status.js")
                .staticLabel("View Status"));

        // JWKS Endpoint Monitoring page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:key")
                .title("JWKS Endpoints")
                .componentLink("components/qwc-jwks-endpoints.js")
                .dynamicLabelJsonRPCMethodName("getJwksStatus"));

        // Token Debugging Tools page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:bug")
                .title("Token Debugger")
                .componentLink("components/qwc-jwt-debugger.js")
                .staticLabel("Debug Tokens"));

        // Configuration Overview page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:cog")
                .title("Configuration")
                .componentLink("components/qwc-jwt-config.js")
                .staticLabel("View Config"));

        return cardPageBuildItem;
    }

    /**
     * Register JSON-RPC providers for DevUI runtime data access.
     *
     * @return A {@link JsonRPCProvidersBuildItem} for JWT DevUI JSON-RPC methods
     */
    @BuildStep(onlyIf = IsDevelopment.class)
    public JsonRPCProvidersBuildItem createJwtDevUIJsonRPCService() {
        return new JsonRPCProvidersBuildItem("CuiJwtDevUI", CuiJwtDevUIJsonRPCService.class);
    }

    /**
     * Add build-time system properties for JWT validation optimization.
     *
     * @param systemProperties producer for system property build items
     */
    @BuildStep
    public void addSystemProperties(BuildProducer<SystemPropertyBuildItem> systemProperties) {
        // Optimize JWT parsing for build-time configuration
        systemProperties.produce(new SystemPropertyBuildItem("de.cuioss.jwt.validation.build.optimize", "true"));

        // Set reasonable defaults for build-time validation
        systemProperties.produce(new SystemPropertyBuildItem("de.cuioss.jwt.validation.build.timeout", "30000"));
    }

    /**
     * Validates the JWT configuration at build time and provides detailed error messages
     * for developers to quickly identify and fix configuration issues.
     *
     * @param config the JWT validation configuration to validate
     * @throws JwtConfigurationException if configuration is invalid with detailed error message
     */
    private void validateBuildTimeConfiguration(JwtValidationConfig config) {
        if (config == null) {
            throw new JwtConfigurationException("JWT validation configuration is missing. " +
                    "Please ensure que.cui.jwt.* properties are properly configured in application.properties");
        }

        validateParserConfig(config.parser());

        // Validate issuer configurations
        if (config.issuers().isEmpty()) {
            throw new JwtConfigurationException("No JWT issuers configured. " +
                    "Please configure at least one issuer using que.cui.jwt.issuers.* properties in application.properties");
        }

        validateIssuerConfigs(config);

        LOGGER.infof("Build-time JWT configuration validation successful: %d issuers, parser config valid",
                config.issuers().size());
    }

    /**
     * Validates parser configuration parameters at build time.
     *
     * @param parser the parser configuration to validate
     * @throws JwtConfigurationException if parser configuration is invalid
     */
    private void validateParserConfig(JwtValidationConfig.ParserConfig parser) {
        validateTokenSize(parser);
        validateLeewaySeconds(parser);
        validateAllowedAlgorithms(parser);
    }

    private void validateTokenSize(JwtValidationConfig.ParserConfig parser) {
        if (parser.maxTokenSizeBytes() <= 0) {
            throw new JwtConfigurationException("JWT parser maxTokenSizeBytes must be positive, but was: " +
                    parser.maxTokenSizeBytes() +
                    ". Please set que.cui.jwt.parser.max-token-size-bytes to a positive value");
        }

        if (parser.maxTokenSizeBytes() < 1024) {
            LOGGER.warnf("JWT parser maxTokenSizeBytes is very small (%d bytes). " +
                    "Consider increasing que.cui.jwt.parser.max-token-size-bytes for production use",
                    parser.maxTokenSizeBytes());
        }
    }

    private void validateLeewaySeconds(JwtValidationConfig.ParserConfig parser) {
        if (parser.leewaySeconds() < 0) {
            throw new JwtConfigurationException("JWT parser leewaySeconds must be non-negative, but was: " +
                    parser.leewaySeconds() +
                    ". Please set que.cui.jwt.parser.leeway-seconds to a non-negative value");
        }

        if (parser.leewaySeconds() > 300) {
            LOGGER.warnf("JWT parser leewaySeconds is very large (%d seconds). " +
                    "Consider reducing que.cui.jwt.parser.leeway-seconds for better security",
                    parser.leewaySeconds());
        }
    }

    private void validateAllowedAlgorithms(JwtValidationConfig.ParserConfig parser) {
        if (parser.allowedAlgorithms() == null || parser.allowedAlgorithms().trim().isEmpty()) {
            throw new JwtConfigurationException("JWT parser allowedAlgorithms cannot be empty. " +
                    "Please configure que.cui.jwt.parser.allowed-algorithms with at least one algorithm");
        }

        // Check for insecure algorithms
        if (parser.allowedAlgorithms().contains("none")) {
            throw new JwtConfigurationException("JWT parser allowedAlgorithms contains 'none' algorithm which is insecure. " +
                    "Please remove 'none' from que.cui.jwt.parser.allowed-algorithms");
        }
    }

    /**
     * Validates issuer configurations at build time.
     *
     * @param config the JWT validation configuration containing issuer configs
     * @throws JwtConfigurationException if any issuer configuration is invalid
     */
    private void validateIssuerConfigs(JwtValidationConfig config) {
        for (var issuerEntry : config.issuers().entrySet()) {
            String issuerName = issuerEntry.getKey();
            var issuerConfig = issuerEntry.getValue();
            validateSingleIssuerConfig(issuerName, issuerConfig);
        }
    }

    private void validateSingleIssuerConfig(String issuerName, JwtValidationConfig.IssuerConfig issuerConfig) {
        if (issuerConfig.url().trim().isEmpty()) {
            throw new JwtConfigurationException(("Issuer '%s' has empty issuer URL. " +
                    "Please configure que.cui.jwt.issuers.%s.url with a valid URL")
                            .formatted(issuerName, issuerName));
        }

        Optional<JwtValidationConfig.HttpJwksLoaderConfig> jwksConfig = issuerConfig.jwks();
        if (jwksConfig.isPresent()) {
            validateJwksConfig(issuerName, jwksConfig.get());
        } else if (issuerConfig.publicKeyLocation().isEmpty()) {
            throw new JwtConfigurationException(("Issuer '%s' has neither JWKS configuration nor public key location. " +
                    "Please configure either que.cui.jwt.issuers.%s.jwks.* or " +
                    "que.cui.jwt.issuers.%s.public-key-location")
                            .formatted(issuerName, issuerName, issuerName));
        }
    }

    private void validateJwksConfig(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig jwksConfig) {
        // Check if either JWKS URL or well-known URL is configured
        if (jwksConfig.url().isEmpty() && jwksConfig.wellKnownUrl().isEmpty()) {
            throw new JwtConfigurationException(("Issuer '%s' has JWKS config but no URL specified. " +
                    "Please configure either que.cui.jwt.issuers.%s.jwks.url or " +
                    "que.cui.jwt.issuers.%s.jwks.well-known-url")
                            .formatted(issuerName, issuerName, issuerName));
        }

        validateJwksUrl(issuerName, jwksConfig.url());
        validateWellKnownUrl(issuerName, jwksConfig.wellKnownUrl());
        validateHttpJwksLoaderConfig(issuerName, jwksConfig);
    }

    private void validateJwksUrl(String issuerName, Optional<String> url) {
        if (url.isPresent()) {
            String urlValue = url.get();
            try {
                new URI(urlValue);
            } catch (URISyntaxException e) {
                throw new JwtConfigurationException(("Issuer '%s' has invalid JWKS URL format: %s. " +
                        "Please check que.cui.jwt.issuers.%s.jwks.url configuration")
                                .formatted(issuerName, urlValue, issuerName), e);
            }

            // Warn about HTTP URLs in production
            if (urlValue.startsWith("http://")) {
                LOGGER.warnf("Issuer '%s' uses HTTP for JWKS URL which is insecure for production. " +
                        "Consider using HTTPS for que.cui.jwt.issuers.%s.jwks.url",
                        issuerName, issuerName);
            }
        }
    }

    private void validateWellKnownUrl(String issuerName, Optional<String> wellKnownUrl) {
        if (wellKnownUrl.isPresent()) {
            String urlValue = wellKnownUrl.get();
            try {
                new URI(urlValue);
            } catch (URISyntaxException e) {
                throw new JwtConfigurationException(("Issuer '%s' has invalid well-known URL format: %s. " +
                        "Please check que.cui.jwt.issuers.%s.jwks.well-known-url configuration")
                                .formatted(issuerName, urlValue, issuerName), e);
            }

            // Warn about HTTP URLs in production
            if (urlValue.startsWith("http://")) {
                LOGGER.warnf("Issuer '%s' uses HTTP for well-known URL which is insecure for production. " +
                        "Consider using HTTPS for que.cui.jwt.issuers.%s.jwks.well-known-url",
                        issuerName, issuerName);
            }
        }
    }

    /**
     * Validates HTTP JWKS loader configuration at build time.
     *
     * @param issuerName the name of the issuer
     * @param httpConfig the HTTP JWKS loader configuration
     * @throws JwtConfigurationException if HTTP JWKS loader configuration is invalid
     */
    private void validateHttpJwksLoaderConfig(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig httpConfig) {
        validateTimeouts(issuerName, httpConfig);
        validateCacheSettings(issuerName, httpConfig);
        validateRetrySettings(issuerName, httpConfig);
    }

    private void validateTimeouts(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig httpConfig) {
        if (httpConfig.connectionTimeoutSeconds() <= 0) {
            throw new JwtConfigurationException(("Issuer '%s' has invalid connectionTimeoutSeconds: %d. " +
                    "Please set que.cui.jwt.issuers.%s.jwks.connection-timeout-seconds to a positive value")
                            .formatted(issuerName, httpConfig.connectionTimeoutSeconds(), issuerName));
        }

        if (httpConfig.readTimeoutSeconds() <= 0) {
            throw new JwtConfigurationException(("Issuer '%s' has invalid readTimeoutSeconds: %d. " +
                    "Please set que.cui.jwt.issuers.%s.jwks.read-timeout-seconds to a positive value")
                            .formatted(issuerName, httpConfig.readTimeoutSeconds(), issuerName));
        }

        // Warn about very short timeouts
        if (httpConfig.connectionTimeoutSeconds() < 2) {
            LOGGER.warnf("Issuer '%s' has very short connection timeout (%d seconds). " +
                    "Consider increasing que.cui.jwt.issuers.%s.jwks.connection-timeout-seconds " +
                    "for better reliability",
                    issuerName, httpConfig.connectionTimeoutSeconds(), issuerName);
        }

        if (httpConfig.readTimeoutSeconds() < 2) {
            LOGGER.warnf("Issuer '%s' has very short read timeout (%d seconds). " +
                    "Consider increasing que.cui.jwt.issuers.%s.jwks.read-timeout-seconds " +
                    "for better reliability",
                    issuerName, httpConfig.readTimeoutSeconds(), issuerName);
        }
    }

    private void validateCacheSettings(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig httpConfig) {
        if (httpConfig.cacheTtlSeconds() <= 0) {
            throw new JwtConfigurationException(("Issuer '%s' has invalid cacheTtlSeconds: %d. " +
                    "Please set que.cui.jwt.issuers.%s.jwks.cache-ttl-seconds to a positive value")
                            .formatted(issuerName, httpConfig.cacheTtlSeconds(), issuerName));
        }

        if (httpConfig.refreshIntervalSeconds() <= 0) {
            throw new JwtConfigurationException(("Issuer '%s' has invalid refreshIntervalSeconds: %d. " +
                    "Please set que.cui.jwt.issuers.%s.jwks.refresh-interval-seconds to a positive value")
                            .formatted(issuerName, httpConfig.refreshIntervalSeconds(), issuerName));
        }

        // Warn about very short cache TTL
        if (httpConfig.cacheTtlSeconds() < 300) {
            LOGGER.warnf("Issuer '%s' has very short cache TTL (%d seconds). " +
                    "Consider increasing que.cui.jwt.issuers.%s.jwks.cache-ttl-seconds " +
                    "to reduce JWKS endpoint load",
                    issuerName, httpConfig.cacheTtlSeconds(), issuerName);
        }

        // Warn about very short refresh interval
        if (httpConfig.refreshIntervalSeconds() < 60) {
            LOGGER.warnf("Issuer '%s' has very short refresh interval (%d seconds). " +
                    "Consider increasing que.cui.jwt.issuers.%s.jwks.refresh-interval-seconds " +
                    "to reduce JWKS endpoint load",
                    issuerName, httpConfig.refreshIntervalSeconds(), issuerName);
        }
    }

    private void validateRetrySettings(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig httpConfig) {
        // Warn about large number of retries
        if (httpConfig.maxRetries() > 5) {
            LOGGER.warnf("Issuer '%s' has very high max retries (%d). " +
                    "Consider reducing que.cui.jwt.issuers.%s.jwks.max-retries " +
                    "to prevent long delays on failures",
                    issuerName, httpConfig.maxRetries(), issuerName);
        }
    }

    // Health checks are automatically discovered by Quarkus through their annotations
    // (@ApplicationScoped, @Readiness, @Liveness), so no explicit registration is needed
}
