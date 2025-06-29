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

import de.cuioss.jwt.validation.JWTValidationLogMessages.DEBUG;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.util.RetryException;
import de.cuioss.jwt.validation.util.RetryUtil;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import jakarta.json.JsonObject;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Lazy-loading implementation of WellKnownHandler that defers HTTP requests
 * until the first actual access to endpoint data.
 * <p>
 * This class implements the R3 requirement for lazy loading by:
 * <ul>
 *   <li>Deferring HTTP requests until first access</li>
 *   <li>Thread-safe lazy initialization</li>
 *   <li>Caching successfully loaded endpoints</li>
 *   <li>Retry logic for failed initial loads</li>
 *   <li>Integration with health check patterns</li>
 * </ul>
 * <p>
 * The build() method only validates configuration and does not access well-known URLs.
 * The actual HTTP request is triggered on the first call to any endpoint accessor
 * method or the isHealthy() method.
 * <p>
 * Usage example:
 * <pre>
 * LazyWellKnownHandler handler = LazyWellKnownHandler.builder()
 *     .url("https://example.com/.well-known/openid-configuration")
 *     .build();
 * 
 * // No HTTP request made yet
 * 
 * // This triggers the HTTP request
 * HttpHandler jwksUri = handler.getJwksUri();
 * </pre>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@ToString(exclude = {"lazyInitLock", "client", "parser", "mapper"})
@EqualsAndHashCode(exclude = {"lazyInitLock", "client", "parser", "mapper"})
public final class LazyWellKnownHandler {

    private static final CuiLogger LOGGER = new CuiLogger(LazyWellKnownHandler.class);

    private static final String ISSUER_KEY = "issuer";
    private static final String JWKS_URI_KEY = "jwks_uri";
    private static final String AUTHORIZATION_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo_endpoint";

    private static final int CONNECT_TIMEOUT_SECONDS = 2;
    private static final int READ_TIMEOUT_SECONDS = 3;

    @Getter
    private final URL wellKnownUrl;

    @Getter
    private final HttpHandler httpHandler;

    private final WellKnownClient client;
    private final WellKnownParser parser;
    private final WellKnownEndpointMapper mapper;

    private volatile Map<String, HttpHandler> endpoints;
    private volatile boolean initialized = false;
    private volatile Exception initializationError;

    private final ReentrantReadWriteLock lazyInitLock = new ReentrantReadWriteLock();

    /**
     * Creates a new LazyWellKnownHandler with the specified configuration.
     * This constructor is private to enforce use of the builder.
     */
    private LazyWellKnownHandler(URL wellKnownUrl,
            HttpHandler httpHandler,
            WellKnownClient client,
            WellKnownParser parser,
            WellKnownEndpointMapper mapper) {
        this.wellKnownUrl = wellKnownUrl;
        this.httpHandler = httpHandler;
        this.client = client;
        this.parser = parser;
        this.mapper = mapper;
    }

    /**
     * Returns a new builder for creating a {@link LazyWellKnownHandler} instance.
     *
     * @return A new builder instance.
     */
    public static LazyWellKnownHandlerBuilder builder() {
        return new LazyWellKnownHandlerBuilder();
    }

    /**
     * Builder for creating {@link LazyWellKnownHandler} instances.
     */
    public static class LazyWellKnownHandlerBuilder {
        private ParserConfig parserConfig;
        private HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private HttpHandler preBuiltHttpHandler;
        private Integer connectTimeoutSeconds;
        private Integer readTimeoutSeconds;

        /**
         * Constructor initializing the HttpHandlerBuilder.
         */
        public LazyWellKnownHandlerBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder();
        }

        /**
         * Sets the well-known URL as a string.
         *
         * @param wellKnownUrlString The string representation of the .well-known/openid-configuration URL.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder url(String wellKnownUrlString) {
            httpHandlerBuilder.url(wellKnownUrlString);
            return this;
        }

        /**
         * Sets the well-known URL directly.
         *
         * @param wellKnownUrl The URL of the .well-known/openid-configuration endpoint.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder url(URL wellKnownUrl) {
            httpHandlerBuilder.url(wellKnownUrl);
            return this;
        }

        /**
         * Sets the SSL context to use for HTTPS connections.
         *
         * @param sslContext The SSL context to use.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            return this;
        }

        /**
         * Sets the secure SSL context provider.
         *
         * @param secureSSLContextProvider The provider for creating secure SSL contexts.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            httpHandlerBuilder.tlsVersions(secureSSLContextProvider);
            return this;
        }

        /**
         * Sets the connection timeout in seconds.
         *
         * @param connectTimeoutSeconds The connection timeout in seconds.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            this.connectTimeoutSeconds = connectTimeoutSeconds;
            return this;
        }

        /**
         * Sets the read timeout in seconds.
         *
         * @param readTimeoutSeconds The read timeout in seconds.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            this.readTimeoutSeconds = readTimeoutSeconds;
            return this;
        }

        /**
         * Sets the parser configuration for JSON parsing and HTTP timeouts.
         *
         * @param parserConfig The parser configuration to use.
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig;
            return this;
        }

        /**
         * Sets a pre-built HttpHandler to use instead of building one.
         * <p>
         * This is useful when you want to wrap the HttpHandler with resilience
         * patterns or other decorators before using it.
         *
         * @param httpHandler the pre-built HttpHandler
         * @return This builder instance.
         */
        public LazyWellKnownHandlerBuilder httpHandler(HttpHandler httpHandler) {
            this.preBuiltHttpHandler = httpHandler;
            return this;
        }

        /**
         * Builds a new {@link LazyWellKnownHandler} instance with the configured parameters.
         * <p>
         * This method only validates configuration and creates the handler components.
         * No HTTP requests are made during the build process.
         *
         * @return A new {@link LazyWellKnownHandler} instance.
         * @throws IllegalArgumentException if the configuration is invalid
         */
        public LazyWellKnownHandler build() {
            HttpHandler wellKnownHttpHandler;

            if (preBuiltHttpHandler != null) {
                // Use the pre-built handler (e.g., wrapped with resilience)
                wellKnownHttpHandler = preBuiltHttpHandler;
                LOGGER.debug("Using pre-built HttpHandler for well-known discovery");
            } else {
                // Build a new handler with the configured parameters
                // Determine timeouts
                int actualConnectTimeout = connectTimeoutSeconds != null ? connectTimeoutSeconds
                        : (parserConfig != null ? parserConfig.getWellKnownConnectTimeoutSeconds()
                        : CONNECT_TIMEOUT_SECONDS);

                int actualReadTimeout = readTimeoutSeconds != null ? readTimeoutSeconds
                        : (parserConfig != null ? parserConfig.getWellKnownReadTimeoutSeconds()
                        : READ_TIMEOUT_SECONDS);

                // Configure timeouts
                httpHandlerBuilder.connectionTimeoutSeconds(actualConnectTimeout);
                httpHandlerBuilder.readTimeoutSeconds(actualReadTimeout);

                // Build the HttpHandler - this only validates configuration
                try {
                    wellKnownHttpHandler = httpHandlerBuilder.build();
                } catch (IllegalArgumentException | IllegalStateException e) {
                    throw new IllegalArgumentException("Invalid .well-known URL configuration", e);
                }
            }

            URL resolvedUrl = wellKnownHttpHandler.getUrl();

            // Create components but don't make HTTP requests
            WellKnownClient client = new WellKnownClient(wellKnownHttpHandler);
            WellKnownParser parser = new WellKnownParser(parserConfig);
            WellKnownEndpointMapper mapper = new WellKnownEndpointMapper(wellKnownHttpHandler);

            LOGGER.debug("Created LazyWellKnownHandler for URL: %s (not yet loaded)", resolvedUrl);

            return new LazyWellKnownHandler(resolvedUrl, wellKnownHttpHandler, client, parser, mapper);
        }
    }

    /**
     * Ensures the endpoints are initialized, making the HTTP request if necessary.
     * This method is thread-safe and will only make one HTTP request even if called
     * concurrently from multiple threads.
     *
     * @throws WellKnownDiscoveryException if discovery fails
     */
    private void ensureInitialized() {
        // Fast path - already initialized
        if (initialized) {
            if (initializationError != null) {
                throw new WellKnownDiscoveryException("Previous initialization failed", initializationError);
            }
            return;
        }

        // Slow path - need to initialize
        lazyInitLock.writeLock().lock();
        try {
            // Double-check after acquiring lock
            if (initialized) {
                if (initializationError != null) {
                    throw new WellKnownDiscoveryException("Previous initialization failed", initializationError);
                }
                return;
            }

            // Perform the actual discovery
            try {
                LOGGER.debug("Performing lazy initialization of well-known endpoints for: %s", wellKnownUrl);

                // Fetch and parse discovery document with retry
                String responseBody = RetryUtil.executeWithRetry(
                        () -> client.fetchDiscoveryDocument(),
                        "fetch well-known discovery document from " + wellKnownUrl
                );
                JsonObject discoveryDocument = parser.parseJsonResponse(responseBody, wellKnownUrl);

                LOGGER.trace(DEBUG.DISCOVERY_DOCUMENT_FETCHED.format(discoveryDocument));

                Map<String, HttpHandler> parsedEndpoints = new HashMap<>();

                // Parse all endpoints
                String issuerString = parser.getString(discoveryDocument, ISSUER_KEY)
                        .orElseThrow(() -> new WellKnownDiscoveryException(
                                "Required field 'issuer' not found in discovery document from " + wellKnownUrl));
                parser.validateIssuer(issuerString, wellKnownUrl);
                mapper.addHttpHandlerToMap(parsedEndpoints, ISSUER_KEY, issuerString, wellKnownUrl, true);

                // JWKS URI (Required)
                mapper.addHttpHandlerToMap(parsedEndpoints, JWKS_URI_KEY,
                        parser.getString(discoveryDocument, JWKS_URI_KEY).orElse(null), wellKnownUrl, true);

                // Required endpoints
                mapper.addHttpHandlerToMap(parsedEndpoints, AUTHORIZATION_ENDPOINT_KEY,
                        parser.getString(discoveryDocument, AUTHORIZATION_ENDPOINT_KEY).orElse(null), wellKnownUrl, true);
                mapper.addHttpHandlerToMap(parsedEndpoints, TOKEN_ENDPOINT_KEY,
                        parser.getString(discoveryDocument, TOKEN_ENDPOINT_KEY).orElse(null), wellKnownUrl, true);

                // Optional endpoints
                mapper.addHttpHandlerToMap(parsedEndpoints, USERINFO_ENDPOINT_KEY,
                        parser.getString(discoveryDocument, USERINFO_ENDPOINT_KEY).orElse(null), wellKnownUrl, false);

                // Accessibility check for jwks_uri
                mapper.performAccessibilityCheck(JWKS_URI_KEY, parsedEndpoints.get(JWKS_URI_KEY));

                // Success - save the endpoints
                this.endpoints = parsedEndpoints;
                this.initialized = true;

                LOGGER.info("Successfully loaded well-known endpoints from: %s", wellKnownUrl);

            } catch (WellKnownDiscoveryException e) {
                // Re-throw discovery exceptions as-is
                this.initializationError = e;
                this.initialized = true;
                throw e;
            } catch (RetryException e) {
                // Save the error for future attempts
                this.initializationError = e;
                this.initialized = true; // Mark as initialized even on error
                LOGGER.error(e, "Failed to load well-known endpoints from: %s after %d attempts", wellKnownUrl, e.getAttemptsMade());
                throw new WellKnownDiscoveryException("Failed to discover well-known endpoints after " + e.getAttemptsMade() + " attempts", e);
            }
        } finally {
            lazyInitLock.writeLock().unlock();
        }
    }

    /**
     * Checks if the well-known handler is healthy by attempting to load endpoints if needed.
     * This method triggers lazy loading if endpoints haven't been loaded yet.
     *
     * @return true if endpoints are successfully loaded, false otherwise
     */
    public boolean isHealthy() {
        try {
            ensureInitialized();
            return endpoints != null && !endpoints.isEmpty();
        } catch (WellKnownDiscoveryException e) {
            LOGGER.debug("Health check failed for well-known handler: %s", e.getMessage());
            return false;
        }
    }

    /**
     * @return The JWKS URI HttpHandler.
     * @throws WellKnownDiscoveryException if discovery fails
     */
    public HttpHandler getJwksUri() {
        ensureInitialized();
        return endpoints.get(JWKS_URI_KEY);
    }

    /**
     * @return The Authorization Endpoint HttpHandler.
     * @throws WellKnownDiscoveryException if discovery fails
     */
    public HttpHandler getAuthorizationEndpoint() {
        ensureInitialized();
        return endpoints.get(AUTHORIZATION_ENDPOINT_KEY);
    }

    /**
     * @return The Token Endpoint HttpHandler.
     * @throws WellKnownDiscoveryException if discovery fails
     */
    public HttpHandler getTokenEndpoint() {
        ensureInitialized();
        return endpoints.get(TOKEN_ENDPOINT_KEY);
    }

    /**
     * @return An {@link Optional} containing the UserInfo Endpoint HttpHandler, or empty if not present.
     * @throws WellKnownDiscoveryException if discovery fails
     */
    public Optional<HttpHandler> getUserinfoEndpoint() {
        ensureInitialized();
        return Optional.ofNullable(endpoints.get(USERINFO_ENDPOINT_KEY));
    }

    /**
     * @return The Issuer HttpHandler.
     * @throws WellKnownDiscoveryException if discovery fails
     */
    public HttpHandler getIssuer() {
        ensureInitialized();
        return endpoints.get(ISSUER_KEY);
    }
}