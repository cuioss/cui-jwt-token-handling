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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksLoaderFactory;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.security.SignatureAlgorithmPreferences;
import de.cuioss.tools.base.Preconditions;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.Singular;
import lombok.ToString;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Configuration class for issuer settings.
 * It aggregates all information needed to validate a JWT token.
 * <p>
 * This class contains the issuer URL, expected audience, expected client ID,
 * configuration for JwksLoader and {@link SignatureAlgorithmPreferences}.
 * </p>
 * <p>
 * The JwksLoader is initialized through the {@link #initSecurityEventCounter(SecurityEventCounter)} method
 * and can be accessed through the {@link #jwksLoader} field.
 * </p>
 * <p>
 * This class is immutable after construction and thread-safe once the JwksLoader is initialized.
 * </p>
 * <p>
 * Usage example:
 * <pre>
 * // Create an issuer configuration with HTTP-based JWKS loading (well-known discovery)
 * IssuerConfig issuerConfig = IssuerConfig.builder()
 *     .expectedAudience("my-client")
 *     .httpJwksLoaderConfig(HttpJwksLoaderConfig.builder()
 *         .wellKnownUrl("https://example.com/.well-known/openid-configuration")
 *         .refreshIntervalSeconds(60)
 *         .build())
 *     .build(); // Validation happens automatically during build()
 *
 * // Initialize the security event counter -> This is usually done by TokenValidator
 * issuerConfig.initSecurityEventCounter(new SecurityEventCounter());
 *
 * // Issuer identifier is dynamically obtained from well-known discovery
 * Optional&lt;String&gt; issuer = issuerConfig.getIssuerIdentifier();
 * </pre>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-3">CUI-JWT-3: Multi-Issuer Support</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-4">CUI-JWT-4: Key Management</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-8.4">CUI-JWT-8.4: Claims Validation</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/technical-components.adoc#_issuerconfig_and_multi_issuer_support">Technical Components Specification - IssuerConfig and Multi-Issuer Support</a>
 *
 * @since 1.0
 */
@Builder
@Getter
@EqualsAndHashCode
@ToString
public class IssuerConfig implements HealthStatusProvider {

    /**
     * Whether this issuer configuration is enabled.
     * <p>
     * When set to {@code false}, this issuer configuration will be ignored during
     * token validation and will not attempt to use the underlying {@link JwksLoader}.
     * This allows for easy enabling/disabling of specific issuers without removing
     * their configuration.
     * <p>
     * Default value is {@code true}.
     */
    @Builder.Default
    boolean enabled = true;

    /**
     * The issuer identifier for token validation.
     * <p>
     * This field is required for all JWKS loading variants except well-known discovery.
     * For well-known discovery, the issuer identifier is automatically extracted from
     * the discovery document and this field is optional.
     * </p>
     * <p>
     * This identifier must match the "iss" claim in validated tokens.
     * </p>
     */
    String issuerIdentifier;

    /**
     * Set of expected audience values.
     * These values are matched against the "aud" claim in the token.
     * If the token's audience claim matches any of these values, it is considered valid.
     */
    @Singular("expectedAudience")
    Set<String> expectedAudience;

    /**
     * Set of expected client ID values.
     * These values are matched against the "azp" or "client_id" claim in the token.
     * If the token's client ID claim matches any of these values, it is considered valid.
     */
    @Singular("expectedClientId")
    Set<String> expectedClientId;

    /**
     * Configuration for HTTP JwksLoader.
     * Used when jwksLoader is null to initialize a new JwksLoader.
     */
    HttpJwksLoaderConfig httpJwksLoaderConfig;

    /**
     * File path for file-based JwksLoader.
     * Used when jwksLoader is null to initialize a new JwksLoader.
     */
    String jwksFilePath;

    /**
     * JWKS content for in-memory JwksLoader.
     * Used when jwksLoader is null to initialize a new JwksLoader.
     */
    String jwksContent;


    @Builder.Default
    SignatureAlgorithmPreferences algorithmPreferences = new SignatureAlgorithmPreferences();

    /**
     * Custom claim mappers that take precedence over the default ones.
     * The key is the claim name, and the value is the mapper to use for that claim.
     */
    @Singular("claimMapper")
    Map<String, ClaimMapper> claimMappers;

    /**
     * The JwksLoader instance used for loading JWKS keys.
     * This is initialized in the initSecurityEventCounter method.
     * Therefore, any configured JwksLoader will be overridden
     */
    JwksLoader jwksLoader;

    /**
     * Initializes the JwksLoader if it's not already initialized and the issuer is enabled.
     * <p>
     * This method should be called by TokenValidator before using the JwksLoader.
     * It will initialize the JwksLoader based on the first available configuration in the following order:
     * <ol>
     *   <li>HTTP JwksLoader (httpJwksLoaderConfig)</li>
     *   <li>File JwksLoader (jwksFilePath)</li>
     *   <li>In-memory JwksLoader (jwksContent)</li>
     * </ol>
     * <p>
     * If the issuer is disabled ({@link #enabled} is {@code false}), this method will not
     * initialize the JwksLoader and will leave it as {@code null}.
     * <p>
     * <strong>Important:</strong> This method assumes the configuration has already been validated
     * during construction via the {@link IssuerConfigBuilder#build()} method. It focuses solely on 
     * initializing the JwksLoader instances with the provided SecurityEventCounter.
     * <p>
     * This method is not thread-safe and should be called before the object is shared between threads.
     *
     * @param securityEventCounter the counter for security events, must not be null
     * @throws NullPointerException if securityEventCounter is null
     */
    public void initSecurityEventCounter(@NonNull SecurityEventCounter securityEventCounter) {
        // Skip initialization if the issuer is disabled
        if (!enabled) {
            return;
        }

        // Only initialize JwksLoader if one is not already set
        if (jwksLoader == null) {
            // Initialize JwksLoader based on the first available configuration
            if (httpJwksLoaderConfig != null) {
                jwksLoader = JwksLoaderFactory.createHttpLoader(httpJwksLoaderConfig, securityEventCounter);
            } else if (jwksFilePath != null) {
                jwksLoader = JwksLoaderFactory.createFileLoader(jwksFilePath, securityEventCounter);
            } else if (jwksContent != null) {
                jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
            }
        }
    }

    /**
     * Post-construction validation method called internally by constructor.
     * This ensures that all IssuerConfig instances are properly validated upon construction.
     */
    private void validateConfiguration() {
        // Skip validation if the issuer is disabled
        if (!enabled) {
            return;
        }

        // Validate that at least one JWKS loading method is configured
        if (httpJwksLoaderConfig == null && jwksFilePath == null &&
                jwksContent == null && jwksLoader == null) {
            throw new IllegalStateException("No JwksLoader configuration is present for enabled issuer. " +
                    "One of httpJwksLoaderConfig, jwksFilePath, jwksContent, or a custom jwksLoader must be provided.");
        }

        // Validate issuerIdentifier requirements based on JWKS loading method
        if (jwksLoader != null) {
            // For custom JwksLoaders, issuerIdentifier is required unless it's a well-known type
            if (issuerIdentifier == null && !jwksLoader.getJwksType().providesIssuerIdentifier()) {
                throw new IllegalStateException("issuerIdentifier is required for custom JwksLoader unless it provides its own issuer identifier");
            }
        } else {
            // For built-in JWKS loading methods, validate issuerIdentifier requirements
            if ((jwksFilePath != null || jwksContent != null) && issuerIdentifier == null) {
                throw new IllegalStateException("issuerIdentifier is required for file-based and in-memory JWKS loading");
            }
            // For HTTP well-known discovery, issuerIdentifier is optional (will be extracted from discovery)
        }
    }

    /**
     * Custom constructor with validation.
     * This is called by Lombok's generated constructor and ensures validation.
     */
    public IssuerConfig(boolean enabled, String issuerIdentifier, Set<String> expectedAudience,
            Set<String> expectedClientId, HttpJwksLoaderConfig httpJwksLoaderConfig,
            String jwksFilePath, String jwksContent, SignatureAlgorithmPreferences algorithmPreferences,
            Map<String, ClaimMapper> claimMappers, JwksLoader jwksLoader) {
        this.enabled = enabled;
        this.issuerIdentifier = issuerIdentifier;
        this.expectedAudience = expectedAudience;
        this.expectedClientId = expectedClientId;
        this.httpJwksLoaderConfig = httpJwksLoaderConfig;
        this.jwksFilePath = jwksFilePath;
        this.jwksContent = jwksContent;
        this.algorithmPreferences = algorithmPreferences;
        this.claimMappers = claimMappers;
        this.jwksLoader = jwksLoader;

        // Perform validation after all fields are set
        validateConfiguration();
    }

    /**
     * Gets the issuer identifier for token validation.
     * <p>
     * This method provides the issuer identifier that should be used for token validation.
     * The resolution logic prioritizes dynamic issuer identification (for well-known discovery)
     * over static configuration:
     * </p>
     * <p>
     * The resolution logic is:
     * <ol>
     *   <li>If the JwksLoader is initialized and healthy, delegate to its issuer identifier first</li>
     *   <li>If the JwksLoader returns empty (for non-well-known cases), use the configured issuerIdentifier</li>
     *   <li>If neither is available, return empty</li>
     * </ol>
     *
     * @return an Optional containing the issuer identifier if available, empty otherwise
     * @since 1.0
     */
    public Optional<String> getIssuerIdentifier() {
        // First try to get issuer identifier from JwksLoader (for well-known discovery)
        if (jwksLoader != null && jwksLoader.isHealthy() == LoaderStatus.OK) {
            Optional<String> jwksLoaderIssuer = jwksLoader.getIssuerIdentifier();
            if (jwksLoaderIssuer.isPresent()) {
                return jwksLoaderIssuer;
            }
        }

        // Fall back to configured issuer identifier (for file-based, in-memory, etc.)
        Preconditions.checkState(issuerIdentifier != null,
                "issuerIdentifier is null - this indicates a bug in validation logic. " +
                        "Non-well-known JWKS loaders should have been validated to require issuerIdentifier during initialization.");
        return Optional.of(issuerIdentifier);
    }

    /**
     * Checks the health status of this issuer configuration.
     * <p>
     * This method provides a unified view of both configuration state (enabled) and runtime state (healthy).
     * The health check process:
     * <ol>
     *   <li>Returns {@link LoaderStatus#UNDEFINED} immediately if the issuer is disabled</li>
     *   <li>Returns {@link LoaderStatus#UNDEFINED} if the JwksLoader is not initialized</li>
     *   <li>Delegates to the underlying {@link JwksLoader#isHealthy()} method</li>
     * </ol>
     * <p>
     * For HTTP-based loaders, this may trigger lazy loading of JWKS content if not already loaded.
     * The method is designed to be fail-fast and thread-safe.
     * <p>
     * The status reflects the combined state of configuration and runtime health:
     * <ul>
     *   <li>{@link LoaderStatus#UNDEFINED} - Issuer is disabled or JwksLoader not initialized</li>
     *   <li>{@link LoaderStatus#OK} - Issuer is enabled and JwksLoader is healthy</li>
     *   <li>{@link LoaderStatus#ERROR} - Issuer is enabled but JwksLoader has errors</li>
     * </ul>
     *
     * @return the current health status of this issuer configuration
     * @since 1.0
     */
    @Override
    public LoaderStatus isHealthy() {
        // Return UNDEFINED if the issuer is disabled
        if (!enabled) {
            return LoaderStatus.UNDEFINED;
        }

        // Return UNDEFINED if the JwksLoader is not initialized
        if (jwksLoader == null) {
            return LoaderStatus.UNDEFINED;
        }

        // Delegate to the underlying JwksLoader
        return jwksLoader.isHealthy();
    }

}
