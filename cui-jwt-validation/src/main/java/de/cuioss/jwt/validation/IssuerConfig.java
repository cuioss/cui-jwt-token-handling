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
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.security.AlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.Singular;
import lombok.ToString;

import java.util.Map;
import java.util.Set;

/**
 * Configuration class for issuer settings.
 * It aggregates all information needed to validate a JWT token.
 * <p>
 * This class contains the issuer URL, expected audience, expected client ID,
 * configuration for JwksLoader and {@link AlgorithmPreferences}.
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
 *     .issuer("https://example.com")
 *     .expectedAudience("my-client")
 *     .httpJwksLoaderConfig(HttpJwksLoaderConfig.builder()
 *         .url("https://example.com/.well-known/jwks.json")
 *         .refreshIntervalSeconds(60)
 *         .build())
 *     .build();
 *
 * // Initialize the security event counter -> This is usually done by TokenValidator
 * issuerConfig.initSecurityEventCounter(new SecurityEventCounter());
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
public class IssuerConfig {

    /**
     * The issuer URL that identifies the token issuer.
     * This value is matched against the "iss" claim in the token.
     */
    @NonNull
    String issuer;

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
    AlgorithmPreferences algorithmPreferences = new AlgorithmPreferences();

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
     * Initializes the JwksLoader if it's not already initialized.
     * This method should be called by TokenValidator before using the JwksLoader.
     * It will initialize the JwksLoader based on the first available configuration in the following order:
     * <ol>
     *   <li>HTTP JwksLoader (httpJwksLoaderConfig)</li>
     *   <li>File JwksLoader (jwksFilePath)</li>
     *   <li>In-memory JwksLoader (jwksContent)</li>
     * </ol>
     * <p>
     * This method is not thread-safe and should be called before the object is shared between threads.
     *
     * @param securityEventCounter the counter for security events, must not be null
     * @throws IllegalStateException if no JwksLoader configuration is present
     * @throws NullPointerException if securityEventCounter is null
     */
    public void initSecurityEventCounter(@NonNull SecurityEventCounter securityEventCounter) {


        // Initialize JwksLoader based on the first available configuration
        if (httpJwksLoaderConfig != null) {
            jwksLoader = JwksLoaderFactory.createHttpLoader(httpJwksLoaderConfig, securityEventCounter);
        } else if (jwksFilePath != null) {
            jwksLoader = JwksLoaderFactory.createFileLoader(jwksFilePath, securityEventCounter);
        } else if (jwksContent != null) {
            jwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
        } else {
            // Throw exception if no configuration is present
            throw new IllegalStateException("No JwksLoader configuration is present. One of httpJwksLoaderConfig, jwksFilePath, or jwksContent must be provided. " + "Issuer: " + issuer + ", httpJwksLoaderConfig: " + (httpJwksLoaderConfig != null) + ", jwksFilePath: " + (jwksFilePath != null) + ", jwksContent: " + (jwksContent != null));
        }

    }

}
