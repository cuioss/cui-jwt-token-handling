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
 * // Create an issuer configuration with HTTP-based JWKS loading
 * IssuerConfig issuerConfig = IssuerConfig.builder()
 *     .expectedAudience("my-client")
 *     .httpJwksLoaderConfig(HttpJwksLoaderConfig.builder()
 *         .wellKnownUrl("https://example.com/.well-known/openid-configuration")
 *         .refreshIntervalSeconds(60)
 *         .build())
 *     .build();
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
     * This method is not thread-safe and should be called before the object is shared between threads.
     *
     * @param securityEventCounter the counter for security events, must not be null
     * @throws IllegalStateException if no JwksLoader configuration is present for an enabled issuer
     * @throws NullPointerException if securityEventCounter is null
     */
    public void initSecurityEventCounter(@NonNull SecurityEventCounter securityEventCounter) {
        // Skip initialization if the issuer is disabled
        if (!enabled) {
            return;
        }

        // Initialize JwksLoader based on the first available configuration
        if (httpJwksLoaderConfig != null) {
            jwksLoader = JwksLoaderFactory.createHttpLoader(httpJwksLoaderConfig, securityEventCounter);
        } else if (jwksFilePath != null) {
            jwksLoader = JwksLoaderFactory.createFileLoader(jwksFilePath, securityEventCounter);
        } else if (jwksContent != null) {
            jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
        } else {
            // Throw exception if no configuration is present for an enabled issuer
            throw new IllegalStateException("No JwksLoader configuration is present for enabled issuer. One of httpJwksLoaderConfig, jwksFilePath, or jwksContent must be provided. " + "httpJwksLoaderConfig: " + (httpJwksLoaderConfig != null) + ", jwksFilePath: " + (jwksFilePath != null) + ", jwksContent: " + (jwksContent != null));
        }

    }

    /**
     * Gets the issuer identifier for token validation.
     * <p>
     * This method provides the issuer identifier that should be used for token validation.
     * For well-known discovery configurations, this method only returns an actual issuer
     * identifier if the underlying {@link de.cuioss.jwt.validation.jwks.http.HttpJwksLoader#isHealthy()}
     * returns a non-error response, ensuring that the issuer identifier is only available
     * when the discovery process has completed successfully.
     * </p>
     * <p>
     * The resolution logic is:
     * <ol>
     *   <li>If the JwksLoader is initialized and healthy, delegate to its issuer identifier</li>
     *   <li>Otherwise, return empty to indicate no issuer identifier is available</li>
     * </ol>
     *
     * @return an Optional containing the issuer identifier if available, empty otherwise
     * @since 1.0
     */
    public Optional<String> getIssuerIdentifier() {
        // Only return issuer identifier if JwksLoader is initialized and healthy
        if (jwksLoader != null && jwksLoader.isHealthy() == LoaderStatus.OK) {
            return jwksLoader.getIssuerIdentifier();
        }

        // Return empty if JwksLoader is not healthy or not initialized
        return Optional.empty();
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
