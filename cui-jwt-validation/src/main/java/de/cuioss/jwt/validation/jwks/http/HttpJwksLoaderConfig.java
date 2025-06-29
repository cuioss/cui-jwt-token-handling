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
package de.cuioss.jwt.validation.jwks.http;

import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.well_known.WellKnownResolver;
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

/**
 * Configuration parameters for {@link HttpJwksLoader}.
 * <p>
 * This class encapsulates configuration options for the HttpJwksLoader,
 * including JWKS endpoint URL, refresh interval, SSL context, and
 * background refresh parameters. The JWKS endpoint URL can be configured
 * directly or discovered via a {@link WellKnownResolver}.
 * <p>
 * Complex caching parameters (maxCacheSize, adaptiveWindowSize) have been 
 * removed for simplification while keeping essential refresh functionality.
 * <p>
 * For more detailed information about the HTTP-based JWKS loading, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/technical-components.adoc#_jwksloader">Technical Components Specification</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@ToString
@EqualsAndHashCode
public class HttpJwksLoaderConfig {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoaderConfig.class);

    /**
     * A Default of 10 minutes (600 seconds).
     */
    private static final int DEFAULT_REFRESH_INTERVAL_IN_SECONDS = 60 * 10;

    /**
     * The interval in seconds at which to refresh the keys.
     * If set to 0, no time-based caching will be used.
     * It defaults to 10 minutes (600 seconds).
     */
    @Getter
    private final int refreshIntervalSeconds;

    /**
     * The HttpHandler used for HTTP requests.
     */
    @NonNull
    @Getter
    @EqualsAndHashCode.Exclude
    private final HttpHandler httpHandler;

    /**
     * The ScheduledExecutorService used for background refresh operations.
     * Can be null if no background refresh is needed.
     */
    @Getter
    @EqualsAndHashCode.Exclude
    private final ScheduledExecutorService scheduledExecutorService;


    /**
     * Creates a new builder for HttpJwksLoaderConfig.
     * <p>
     * This method provides a convenient way to create a new instance of
     * HttpJwksLoaderConfigBuilder, allowing for fluent configuration of the
     * HttpJwksLoaderConfig parameters.
     *
     * @return a new HttpJwksLoaderConfigBuilder instance
     */
    public static HttpJwksLoaderConfigBuilder builder() {
        return new HttpJwksLoaderConfigBuilder();
    }

    /**
     * Builder for creating HttpJwksLoaderConfig instances with validation.
     */
    public static class HttpJwksLoaderConfigBuilder {
        private Integer refreshIntervalSeconds = DEFAULT_REFRESH_INTERVAL_IN_SECONDS;
        private final HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private ScheduledExecutorService scheduledExecutorService;

        /**
         * Constructor initializing the HttpHandlerBuilder.
         */
        public HttpJwksLoaderConfigBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder();
        }


        /**
         * Sets the JWKS URI directly.
         * <p>
         * Note: If this method is called, it will override any URI set by
         * {@link #url(String)} or {@link #wellKnown(WellKnownHandler)}.
         * The last call among these methods determines the final JWKS URI.
         * </p>
         *
         * @param jwksUri the URI of the JWKS endpoint. Must not be null.
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder uri(@NonNull URI jwksUri) {
            httpHandlerBuilder.uri(jwksUri);
            return this;
        }

        /**
         * Sets the JWKS URL as a string, which will be converted to a URI.
         * <p>
         * Note: If this method is called, it will override any URI set by
         * {@link #uri(URI)} or {@link #wellKnown(WellKnownHandler)}.
         * The last call among these methods determines the final JWKS URI.
         * </p>
         *
         * @param jwksUrl the URL string of the JWKS endpoint. Must not be null.
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder url(@NonNull String jwksUrl) {
            httpHandlerBuilder.url(jwksUrl);
            return this;
        }

        /**
         * Configures the JWKS URI by extracting it from a {@link WellKnownHandler}.
         * <p>
         * This method will retrieve the {@code jwks_uri} from the provided
         * {@code WellKnownHandler}. If the handler does not contain a {@code jwks_uri},
         * an {@link IllegalArgumentException} will be thrown.
         * </p>
         * <p>
         * Note: If this method is called, it will override any URI set by
         * {@link #uri(URI)} or {@link #url(String)}.
         * The last call among these methods determines the final JWKS URI.
         * </p>
         *
         * @param wellKnownResolver The {@link WellKnownResolver} instance from which to
         *                          extract the JWKS URI. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if {@code wellKnownResolver} is null
         */
        public HttpJwksLoaderConfigBuilder wellKnown(@NonNull WellKnownResolver wellKnownResolver) {
            HttpHandler extractedJwksHandler = wellKnownResolver.getJwksUri();
            httpHandlerBuilder.uri(extractedJwksHandler.getUri()).sslContext(extractedJwksHandler.getSslContext());
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider the TLS versions configuration to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            httpHandlerBuilder.tlsVersions(secureSSLContextProvider);
            return this;
        }

        /**
         * Sets the refresh interval in seconds.
         * <p>
         * If set to 0, no time-based caching will be used. It defaults to 10 minutes (600 seconds).
         * </p>
         *
         * @param refreshIntervalSeconds the refresh interval in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if a refresh interval is negative
         */
        public HttpJwksLoaderConfigBuilder refreshIntervalSeconds(int refreshIntervalSeconds) {
            Preconditions.checkArgument(refreshIntervalSeconds > -1, "refreshIntervalSeconds must be zero or positive");
            this.refreshIntervalSeconds = refreshIntervalSeconds;
            return this;
        }


        /**
         * Sets the SSL context to use for HTTPS connections.
         * <p>
         * If not set, a default secure SSL context will be created.
         * </p>
         *
         * @param sslContext The SSL context to use.
         * @return This builder instance.
         */
        public HttpJwksLoaderConfigBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            return this;
        }

        /**
         * Sets the connection timeout in seconds.
         *
         * @param connectTimeoutSeconds the connection timeout in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if connectTimeoutSeconds is not positive
         */
        public HttpJwksLoaderConfigBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            Preconditions.checkArgument(connectTimeoutSeconds > 0, "connectTimeoutSeconds must be > 0, but was %s", connectTimeoutSeconds);
            httpHandlerBuilder.connectionTimeoutSeconds(connectTimeoutSeconds);
            return this;
        }

        /**
         * Sets the read timeout in seconds.
         *
         * @param readTimeoutSeconds the read timeout in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if readTimeoutSeconds is not positive
         */
        public HttpJwksLoaderConfigBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            Preconditions.checkArgument(readTimeoutSeconds > 0, "readTimeoutSeconds must be > 0, but was %s", readTimeoutSeconds);
            httpHandlerBuilder.readTimeoutSeconds(readTimeoutSeconds);
            return this;
        }

        /**
         * Sets the ScheduledExecutorService for background refresh operations.
         *
         * @param scheduledExecutorService the executor service to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder scheduledExecutorService(ScheduledExecutorService scheduledExecutorService) {
            this.scheduledExecutorService = scheduledExecutorService;
            return this;
        }

        /**
         * Builds a new HttpJwksLoaderConfig instance with the configured parameters.
         * Validates all parameters and applies default values where appropriate.
         *
         * @return a new HttpJwksLoaderConfig instance
         * @throws IllegalArgumentException if any parameter is invalid
         */
        public HttpJwksLoaderConfig build() {
            // Build the HttpHandler for the well-known URL
            HttpHandler jwksHttpHandler;
            try {
                jwksHttpHandler = httpHandlerBuilder.build();
            } catch (IllegalArgumentException | IllegalStateException e) {
                LOGGER.warn(WARN.INVALID_JWKS_URI::format);
                throw new IllegalArgumentException("Invalid URL", e);
            }

            // Create default ScheduledExecutorService if not provided and refresh interval > 0
            ScheduledExecutorService executor = this.scheduledExecutorService;
            if (executor == null && refreshIntervalSeconds > 0) {
                executor = Executors.newScheduledThreadPool(1, r -> {
                    Thread t = new Thread(r, "jwks-refresh-" + jwksHttpHandler.getUri().getHost());
                    t.setDaemon(true);
                    return t;
                });
            }

            return new HttpJwksLoaderConfig(
                    refreshIntervalSeconds,
                    jwksHttpHandler,
                    executor);
        }
    }
}