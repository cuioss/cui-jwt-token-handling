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
import de.cuioss.jwt.validation.well_known.WellKnownHandler;
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
 * This class encapsulates all configuration options for the HttpJwksLoader,
 * including JWKS endpoint URL, refresh interval, SSL context, cache size,
 * and adaptive caching parameters. The JWKS endpoint URL can be configured
 * directly or discovered via a {@link WellKnownHandler}.
 * <p>
 * It provides validation for all parameters and default values where appropriate.
 * <p>
 * For more detailed information about the HTTP-based JWKS loading, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/technical-components.adoc#_jwksloader">Technical Components Specification</a>
 *
 * @author Oliver Wolff
 * @author Your Name (for well-known integration)
 * @since 1.0
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@ToString
@EqualsAndHashCode
public class HttpJwksLoaderConfig {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoaderConfig.class);
    private static final int DEFAULT_MAX_CACHE_SIZE = 100;
    private static final int DEFAULT_BACKGROUND_REFRESH_PERCENTAGE = 80;
    private static final int DEFAULT_ADAPTIVE_WINDOW_SIZE = 10;

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
     * The maximum number of entries in the cache.
     * This is useful in multi-issuer environments to prevent memory issues.
     */
    @Getter
    private final int maxCacheSize;

    /**
     * The number of accesses to consider for adaptive caching.
     * This controls how many accesses are considered when adjusting cache expiration.
     */
    @Getter
    private final int adaptiveWindowSize;

    /**
     * The percentage of the refresh interval at which to perform background refresh.
     * For example, if refreshIntervalSeconds is 60 and backgroundRefreshPercentage is 80,
     * background refresh will occur at 48 seconds (80% of 60).
     */
    @Getter
    private final int backgroundRefreshPercentage;

    /**
     * The ScheduledExecutorService for background refresh tasks.
     * If null, a new one will be created.
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
        private Integer maxCacheSize = DEFAULT_MAX_CACHE_SIZE;
        private Integer adaptiveWindowSize = DEFAULT_ADAPTIVE_WINDOW_SIZE;
        private Integer backgroundRefreshPercentage = DEFAULT_BACKGROUND_REFRESH_PERCENTAGE;
        private Integer refreshIntervalSeconds = DEFAULT_REFRESH_INTERVAL_IN_SECONDS;
        private ScheduledExecutorService scheduledExecutorService;
        private final HttpHandler.HttpHandlerBuilder httpHandlerBuilder;

        /**
         * Constructor initializing the HttpHandlerBuilder.
         */
        public HttpJwksLoaderConfigBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder();
        }

        /**
         * Sets the maximum cache size.
         * <p>
         * This is useful in multi-issuer environments to prevent memory issues.
         * </p>
         *
         * @param maxCacheSize the maximum number of entries in the cache
         * @return this builder instance
         * @throws IllegalArgumentException if maxCacheSize is negative
         */
        public HttpJwksLoaderConfigBuilder maxCacheSize(int maxCacheSize) {
            Preconditions.checkArgument(maxCacheSize > 0, "maxCacheSize must be positive");
            this.maxCacheSize = maxCacheSize;
            return this;
        }

        /**
         * The number of accesses to consider for adaptive caching.
         * This controls how many accesses are considered when adjusting cache expiration.
         *
         * @param adaptiveWindowSize the percentage of the refresh interval
         * @return this builder instance
         * @throws IllegalArgumentException if adaptiveWindowSize is not positive
         */
        public HttpJwksLoaderConfigBuilder adaptiveWindowSize(int adaptiveWindowSize) {
            Preconditions.checkArgument(adaptiveWindowSize > 0, "adaptiveWindowSize must be positive");
            this.adaptiveWindowSize = adaptiveWindowSize;
            return this;
        }

        /**
         * Sets the percentage of the refresh interval at which to perform background refresh.
         * <p>
         * For example, if refreshIntervalSeconds is 60 and backgroundRefreshPercentage is 80,
         * background refresh will occur at 48 seconds (80% of 60).
         * </p>
         *
         * @param backgroundRefreshPercentage the percentage of the refresh interval
         * @return this builder instance
         * @throws IllegalArgumentException if backgroundRefreshPercentage is not between 1 and 100
         */
        public HttpJwksLoaderConfigBuilder backgroundRefreshPercentage(int backgroundRefreshPercentage) {
            Preconditions.checkArgument(backgroundRefreshPercentage > 0 && backgroundRefreshPercentage <= 100,
                    "backgroundRefreshPercentage must be between 1 and 100");
            this.backgroundRefreshPercentage = backgroundRefreshPercentage;
            return this;
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
         * @param wellKnownHandler The {@link WellKnownHandler} instance from which to
         *                         extract the JWKS URI. Must not be null.
         * @return this builder instance
         * @throws IllegalArgumentException if {@code wellKnownHandler} is null
         */
        public HttpJwksLoaderConfigBuilder wellKnown(@NonNull WellKnownHandler wellKnownHandler) {
            HttpHandler extractedJwksHandler = wellKnownHandler.getJwksUri();
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
         * Sets the ScheduledExecutorService for background refresh tasks.
         *
         * @param scheduledExecutorService the ScheduledExecutorService to use
         * @return this builder instance
         */
        public HttpJwksLoaderConfigBuilder scheduledExecutorService(ScheduledExecutorService scheduledExecutorService) {
            this.scheduledExecutorService = scheduledExecutorService;
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
            if (scheduledExecutorService == null && refreshIntervalSeconds > 0) {
                scheduledExecutorService = Executors.newScheduledThreadPool(1);
            }

            return new HttpJwksLoaderConfig(
                    refreshIntervalSeconds,
                    jwksHttpHandler,
                    maxCacheSize,
                    adaptiveWindowSize,
                    backgroundRefreshPercentage,
                    scheduledExecutorService);
        }
    }
}
