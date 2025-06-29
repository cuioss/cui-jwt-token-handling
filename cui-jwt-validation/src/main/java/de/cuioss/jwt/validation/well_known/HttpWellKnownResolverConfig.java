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
package de.cuioss.jwt.validation.well_known;

import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.net.URL;
import java.time.Duration;

/**
 * Configuration for HttpWellKnownResolver instances.
 * <p>
 * This class provides a builder pattern for configuring HTTP well-known resolvers
 * with customizable timeouts, retry settings, and SSL configurations.
 * <p>
 * Example usage:
 * <pre>
 * HttpWellKnownResolverConfig config = HttpWellKnownResolverConfig.builder()
 *     .url("https://example.com/.well-known/openid-configuration")
 *     .connectTimeoutSeconds(5)
 *     .maxAttempts(3)
 *     .build();
 * 
 * HttpWellKnownResolver resolver = new HttpWellKnownResolver(config.getHttpHandler(), config.getParserConfig(),
 *     config.getMaxAttempts(), config.getRetryDelay());
 * </pre>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@Getter
@ToString
@EqualsAndHashCode
public class HttpWellKnownResolverConfig {

    private static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 2;
    private static final int DEFAULT_READ_TIMEOUT_SECONDS = 3;
    private static final int DEFAULT_MAX_ATTEMPTS = 3;
    private static final Duration DEFAULT_RETRY_DELAY = Duration.ofMillis(100);

    private final HttpHandler httpHandler;
    private final ParserConfig parserConfig;
    private final int maxAttempts;
    private final Duration retryDelay;

    private HttpWellKnownResolverConfig(HttpHandler httpHandler,
            ParserConfig parserConfig,
            int maxAttempts,
            Duration retryDelay) {
        this.httpHandler = httpHandler;
        this.parserConfig = parserConfig;
        this.maxAttempts = maxAttempts;
        this.retryDelay = retryDelay;
    }

    /**
     * Returns a new builder for creating HttpWellKnownResolverConfig instances.
     */
    public static HttpWellKnownResolverConfigBuilder builder() {
        return new HttpWellKnownResolverConfigBuilder();
    }

    /**
     * Builder for creating HttpWellKnownResolverConfig instances.
     */
    public static class HttpWellKnownResolverConfigBuilder {
        private ParserConfig parserConfig;
        private HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private HttpHandler preBuiltHttpHandler;
        private Integer connectTimeoutSeconds;
        private Integer readTimeoutSeconds;
        private Integer maxAttempts;
        private Duration retryDelay;

        public HttpWellKnownResolverConfigBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder();
        }

        public HttpWellKnownResolverConfigBuilder url(String wellKnownUrlString) {
            httpHandlerBuilder.url(wellKnownUrlString);
            return this;
        }

        public HttpWellKnownResolverConfigBuilder url(URL wellKnownUrl) {
            httpHandlerBuilder.url(wellKnownUrl);
            return this;
        }

        public HttpWellKnownResolverConfigBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            return this;
        }

        public HttpWellKnownResolverConfigBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            httpHandlerBuilder.tlsVersions(secureSSLContextProvider);
            return this;
        }

        public HttpWellKnownResolverConfigBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            this.connectTimeoutSeconds = connectTimeoutSeconds;
            return this;
        }

        public HttpWellKnownResolverConfigBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            this.readTimeoutSeconds = readTimeoutSeconds;
            return this;
        }

        public HttpWellKnownResolverConfigBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig;
            return this;
        }

        public HttpWellKnownResolverConfigBuilder httpHandler(HttpHandler httpHandler) {
            this.preBuiltHttpHandler = httpHandler;
            return this;
        }

        public HttpWellKnownResolverConfigBuilder maxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
            return this;
        }

        public HttpWellKnownResolverConfigBuilder retryDelay(Duration retryDelay) {
            this.retryDelay = retryDelay;
            return this;
        }

        public HttpWellKnownResolverConfig build() {
            HttpHandler wellKnownHttpHandler;

            if (preBuiltHttpHandler != null) {
                wellKnownHttpHandler = preBuiltHttpHandler;
            } else {
                // Determine timeouts
                int actualConnectTimeout = connectTimeoutSeconds != null ? connectTimeoutSeconds
                        : (parserConfig != null ? parserConfig.getWellKnownConnectTimeoutSeconds()
                        : DEFAULT_CONNECT_TIMEOUT_SECONDS);

                int actualReadTimeout = readTimeoutSeconds != null ? readTimeoutSeconds
                        : (parserConfig != null ? parserConfig.getWellKnownReadTimeoutSeconds()
                        : DEFAULT_READ_TIMEOUT_SECONDS);

                // Configure timeouts
                httpHandlerBuilder.connectionTimeoutSeconds(actualConnectTimeout);
                httpHandlerBuilder.readTimeoutSeconds(actualReadTimeout);

                try {
                    wellKnownHttpHandler = httpHandlerBuilder.build();
                } catch (IllegalArgumentException | IllegalStateException e) {
                    throw new IllegalArgumentException("Invalid .well-known URL configuration", e);
                }
            }

            int resolverMaxAttempts = maxAttempts != null ? maxAttempts : DEFAULT_MAX_ATTEMPTS;
            Duration resolverRetryDelay = retryDelay != null ? retryDelay : DEFAULT_RETRY_DELAY;

            return new HttpWellKnownResolverConfig(wellKnownHttpHandler, parserConfig,
                    resolverMaxAttempts, resolverRetryDelay);
        }
    }
}