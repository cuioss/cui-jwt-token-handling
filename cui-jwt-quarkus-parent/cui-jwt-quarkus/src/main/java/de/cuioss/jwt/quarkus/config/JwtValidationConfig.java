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
package de.cuioss.jwt.quarkus.config;

import io.quarkus.arc.Unremovable;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.Map;
import java.util.Optional;

/**
 * Configuration properties for JWT validation in Quarkus applications.
 * <p>
 * This configuration supports the multi-issuer approach of the library,
 * allowing different validation settings for different token issuers.
 * </p>
 * <p>
 * All properties are prefixed with "cui.jwt".
 * </p>
 *
 * @since 1.0
 */
@ConfigMapping(prefix = "cui.jwt")
@Unremovable
public interface JwtValidationConfig {

    /**
     * Map of issuer configurations, where the key is the issuer identifier
     * and the value is the issuer-specific configuration.
     *
     * @return Map of issuer configurations
     */
    @NotNull
    @Valid
    Map<String, IssuerConfig> issuers();

    /**
     * Global parser configuration that applies to all issuers unless
     * overridden at the issuer level.
     *
     * @return Global parser configuration
     */
    @NotNull
    @Valid
    ParserConfig parser();

    /**
     * Configuration for a specific JWT issuer.
     */
    interface IssuerConfig {

        /**
         * The issuer URL/identifier that will be matched against the "iss" claim
         * in the JWT.
         *
         * @return The issuer URL/identifier
         */
        @NotNull
        @NotEmpty
        String url();

        /**
         * Location of the public key or certificate used to verify tokens from
         * this issuer. This can be a file path, URL, or classpath resource.
         *
         * @return Location of the public key or certificate
         */
        Optional<String> publicKeyLocation();

        /**
         * Configuration for the JWKS endpoint for this issuer.
         *
         * @return Configuration for the JWKS endpoint
         */
        @Valid
        Optional<HttpJwksLoaderConfig> jwks();

        /**
         * Parser configuration specific to this issuer. If not provided, the
         * global parser configuration will be used.
         *
         * @return Parser configuration specific to this issuer
         */
        @Valid
        Optional<ParserConfig> parser();

        /**
         * Whether this issuer configuration is enabled.
         *
         * @return true if this issuer configuration is enabled, false otherwise
         */
        @WithDefault("true")
        boolean enabled();
    }

    /**
     * Configuration for JWT parser settings.
     */
    interface ParserConfig {

        /**
         * The expected audience claim value. If specified, the JWT must contain
         * this value in its "aud" claim.
         *
         * @return The expected audience claim value
         */
        Optional<String> audience();

        /**
         * The leeway in seconds to allow for clock skew when validating
         * expiration and not-before claims.
         *
         * @return The leeway in seconds
         */
        @WithDefault("30")
        int leewaySeconds();

        /**
         * The maximum token size in bytes. Tokens larger than this will be
         * rejected.
         *
         * @return The maximum token size in bytes
         */
        @WithDefault("8192")
        int maxTokenSizeBytes();

        /**
         * Whether to validate the "nbf" (not before) claim.
         *
         * @return true if the "nbf" claim should be validated, false otherwise
         */
        @WithDefault("true")
        boolean validateNotBefore();

        /**
         * Whether to validate the "exp" (expiration) claim.
         *
         * @return true if the "exp" claim should be validated, false otherwise
         */
        @WithDefault("true")
        boolean validateExpiration();

        /**
         * Whether to validate the "iat" (issued at) claim.
         *
         * @return true if the "iat" claim should be validated, false otherwise
         */
        @WithDefault("false")
        boolean validateIssuedAt();

        /**
         * Comma-separated list of allowed signing algorithms.
         *
         * @return Comma-separated list of allowed signing algorithms
         */
        @WithDefault("RS256,RS384,RS512,ES256,ES384,ES512")
        String allowedAlgorithms();
    }

    /**
     * Configuration for HTTP JWKS (JSON Web Key Set) endpoint.
     */
    interface HttpJwksLoaderConfig {

        /**
         * The URL of the JWKS endpoint.
         * <p>
         * This property is mutually exclusive with {@link #wellKnownUrl()}.
         * If both are provided, the well-known approach takes precedence.
         * </p>
         *
         * @return The URL of the JWKS endpoint
         */
        Optional<String> url();

        /**
         * The URL of the OpenID Connect discovery document (well-known endpoint).
         * <p>
         * When provided, the JWKS URL will be automatically discovered from this endpoint.
         * This is the recommended approach for configuring JWKS as it follows the OpenID Connect
         * discovery standard.
         * </p>
         * <p>
         * This property is mutually exclusive with {@link #url()}. If both are provided,
         * the well-known approach takes precedence.
         * </p>
         * <p>
         * Example: https://your-idp.com/realms/my-realm/.well-known/openid-configuration
         * </p>
         *
         * @return The URL of the OpenID Connect discovery document
         */
        Optional<String> wellKnownUrl();

        /**
         * The cache time-to-live in seconds for the JWKS response.
         *
         * @return The cache time-to-live in seconds
         */
        @WithDefault("3600")
        int cacheTtlSeconds();

        /**
         * The refresh interval in seconds for the JWKS cache.
         *
         * @return The refresh interval in seconds
         */
        @WithDefault("300")
        int refreshIntervalSeconds();

        /**
         * The connection timeout in seconds for the JWKS endpoint.
         *
         * @return The connection timeout in seconds
         */
        @WithDefault("5")
        int connectionTimeoutSeconds();

        /**
         * The read timeout in seconds for the JWKS endpoint.
         *
         * @return The read timeout in seconds
         */
        @WithDefault("5")
        int readTimeoutSeconds();

        /**
         * The maximum number of retries for failed JWKS requests.
         *
         * @return The maximum number of retries
         */
        @WithDefault("3")
        int maxRetries();

        /**
         * Whether to use HTTP proxy settings from the system properties.
         *
         * @return true if system proxy settings should be used, false otherwise
         */
        @WithDefault("false")
        boolean useSystemProxy();
    }

    /**
     * Configuration for health checks.
     *
     * @return Health check configuration
     */
    @NotNull
    @Valid
    HealthConfig health();

    /**
     * Configuration for health checks.
     */
    interface HealthConfig {
        /**
         * Whether health checks are enabled.
         *
         * @return true if health checks are enabled, false otherwise
         */
        @WithDefault("true")
        boolean enabled();

        /**
         * Configuration for JWKS endpoint health checks.
         *
         * @return JWKS endpoint health check configuration
         */
        @Valid
        JwksHealthConfig jwks();
    }

    /**
     * Configuration for JWKS endpoint health checks.
     */
    interface JwksHealthConfig {
        /**
         * The cache time-to-live in seconds for health check results.
         * This helps to reduce the load on JWKS endpoints.
         *
         * @return The cache time-to-live in seconds
         */
        @WithDefault("30")
        int cacheSeconds();

        /**
         * The timeout in seconds for JWKS endpoint connectivity checks.
         *
         * @return The timeout in seconds
         */
        @WithDefault("5")
        int timeoutSeconds();
    }
}
