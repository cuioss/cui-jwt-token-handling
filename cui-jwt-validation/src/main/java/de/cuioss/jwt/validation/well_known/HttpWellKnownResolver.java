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
import de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.util.ETagAwareHttpHandler;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import jakarta.json.JsonObject;
import lombok.NonNull;

import javax.net.ssl.SSLContext;
import java.net.URL;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * HTTP-based implementation of WellKnownResolver that discovers OIDC endpoints.
 * <p>
 * This class provides lazy loading of well-known endpoints with built-in retry logic
 * and health checking capabilities. It follows the same pattern as HttpJwksLoader
 * with thread-safe operations and status reporting.
 * <p>
 * Features:
 * <ul>
 *   <li>Lazy loading - HTTP requests are deferred until first access</li>
 *   <li>Thread-safe initialization using double-checked locking</li>
 *   <li>Built-in retry logic for transient failures</li>
 *   <li>Health checking with status reporting</li>
 *   <li>Caching of successfully resolved endpoints</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public class HttpWellKnownResolver implements WellKnownResolver {

    private static final CuiLogger LOGGER = new CuiLogger(HttpWellKnownResolver.class);

    private static final String ISSUER_KEY = "issuer";
    private static final String JWKS_URI_KEY = "jwks_uri";
    private static final String AUTHORIZATION_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo_endpoint";

    private static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 2;
    private static final int DEFAULT_READ_TIMEOUT_SECONDS = 3;
    private static final int DEFAULT_MAX_ATTEMPTS = 3;
    private static final Duration DEFAULT_RETRY_DELAY = Duration.ofMillis(100);

    private final HttpHandler httpHandler;
    private final URL wellKnownUrl;
    private final ETagAwareHttpHandler etagHandler;
    private final WellKnownParser parser;
    private final WellKnownEndpointMapper mapper;
    private final int maxAttempts;
    private final Duration retryDelay;

    private final AtomicReference<Map<String, HttpHandler>> endpoints = new AtomicReference<>();
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;

    /**
     * Creates a new HTTP well-known resolver.
     *
     * @param httpHandler the HTTP handler for making requests
     * @param parserConfig the parser configuration
     * @param maxAttempts maximum retry attempts
     * @param retryDelay delay between retry attempts
     */
    public HttpWellKnownResolver(@NonNull HttpHandler httpHandler,
            ParserConfig parserConfig,
            int maxAttempts,
            Duration retryDelay) {
        this.httpHandler = httpHandler;
        this.wellKnownUrl = httpHandler.getUrl();
        this.etagHandler = new ETagAwareHttpHandler(httpHandler);
        this.parser = new WellKnownParser(parserConfig);
        this.mapper = new WellKnownEndpointMapper(httpHandler);
        this.maxAttempts = maxAttempts > 0 ? maxAttempts : DEFAULT_MAX_ATTEMPTS;
        this.retryDelay = retryDelay != null ? retryDelay : DEFAULT_RETRY_DELAY;
    }

    /**
     * Creates a new HTTP well-known resolver with default retry settings.
     */
    public HttpWellKnownResolver(@NonNull HttpHandler httpHandler, ParserConfig parserConfig) {
        this(httpHandler, parserConfig, DEFAULT_MAX_ATTEMPTS, DEFAULT_RETRY_DELAY);
    }

    /**
     * Returns a new builder for creating HttpWellKnownResolver instances.
     */
    public static HttpWellKnownResolverBuilder builder() {
        return new HttpWellKnownResolverBuilder();
    }

    /**
     * Builder for creating HttpWellKnownResolver instances.
     */
    public static class HttpWellKnownResolverBuilder {
        private ParserConfig parserConfig;
        private HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private HttpHandler preBuiltHttpHandler;
        private Integer connectTimeoutSeconds;
        private Integer readTimeoutSeconds;
        private Integer maxAttempts;
        private Duration retryDelay;

        public HttpWellKnownResolverBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder();
        }

        public HttpWellKnownResolverBuilder url(String wellKnownUrlString) {
            httpHandlerBuilder.url(wellKnownUrlString);
            return this;
        }

        public HttpWellKnownResolverBuilder url(URL wellKnownUrl) {
            httpHandlerBuilder.url(wellKnownUrl);
            return this;
        }

        public HttpWellKnownResolverBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            return this;
        }

        public HttpWellKnownResolverBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            httpHandlerBuilder.tlsVersions(secureSSLContextProvider);
            return this;
        }

        public HttpWellKnownResolverBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            this.connectTimeoutSeconds = connectTimeoutSeconds;
            return this;
        }

        public HttpWellKnownResolverBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            this.readTimeoutSeconds = readTimeoutSeconds;
            return this;
        }

        public HttpWellKnownResolverBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig;
            return this;
        }

        public HttpWellKnownResolverBuilder httpHandler(HttpHandler httpHandler) {
            this.preBuiltHttpHandler = httpHandler;
            return this;
        }

        public HttpWellKnownResolverBuilder maxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
            return this;
        }

        public HttpWellKnownResolverBuilder retryDelay(Duration retryDelay) {
            this.retryDelay = retryDelay;
            return this;
        }

        public HttpWellKnownResolver build() {
            HttpHandler wellKnownHttpHandler;

            if (preBuiltHttpHandler != null) {
                wellKnownHttpHandler = preBuiltHttpHandler;
                LOGGER.debug("Using pre-built HttpHandler for well-known discovery");
            } else {
                // Use configured timeouts or defaults
                int actualConnectTimeout = connectTimeoutSeconds != null ? connectTimeoutSeconds : DEFAULT_CONNECT_TIMEOUT_SECONDS;
                int actualReadTimeout = readTimeoutSeconds != null ? readTimeoutSeconds : DEFAULT_READ_TIMEOUT_SECONDS;

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

            LOGGER.debug("Created HttpWellKnownResolver for URL: %s (not yet loaded)", wellKnownHttpHandler.getUrl());

            return new HttpWellKnownResolver(wellKnownHttpHandler, parserConfig, resolverMaxAttempts, resolverRetryDelay);
        }
    }

    @Override
    public HttpHandler getJwksUri() {
        ensureLoaded();
        return getEndpoint(JWKS_URI_KEY);
    }

    @Override
    public HttpHandler getAuthorizationEndpoint() {
        ensureLoaded();
        return getEndpoint(AUTHORIZATION_ENDPOINT_KEY);
    }

    @Override
    public HttpHandler getTokenEndpoint() {
        ensureLoaded();
        return getEndpoint(TOKEN_ENDPOINT_KEY);
    }

    @Override
    public Optional<HttpHandler> getUserinfoEndpoint() {
        ensureLoaded();
        return Optional.ofNullable(endpoints.get().get(USERINFO_ENDPOINT_KEY));
    }

    @Override
    public HttpHandler getIssuer() {
        ensureLoaded();
        return getEndpoint(ISSUER_KEY);
    }

    @Override
    public boolean isHealthy() {
        if (endpoints.get() == null) {
            try {
                ensureLoaded();
            } catch (WellKnownDiscoveryException e) {
                LOGGER.debug("Health check failed during endpoint loading: %s", e.getMessage());
                return false;
            }
        }
        return status == LoaderStatus.OK;
    }

    @Override
    public LoaderStatus getStatus() {
        return status;
    }

    private HttpHandler getEndpoint(String key) {
        Map<String, HttpHandler> currentEndpoints = endpoints.get();
        if (currentEndpoints == null) {
            throw new WellKnownDiscoveryException("Endpoints not loaded");
        }
        HttpHandler handler = currentEndpoints.get(key);
        if (handler == null) {
            throw new WellKnownDiscoveryException("Endpoint not found: " + key);
        }
        return handler;
    }

    private void ensureLoaded() {
        if (endpoints.get() == null) {
            loadEndpointsIfNeeded();
        }
    }

    private void loadEndpointsIfNeeded() {
        // Double-checked locking pattern with AtomicReference
        if (endpoints.get() == null) {
            synchronized (this) {
                if (endpoints.get() == null) {
                    loadEndpoints();
                }
            }
        }
    }

    private void loadEndpoints() {
        Exception lastException = null;

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                LOGGER.debug("Loading well-known endpoints from %s (attempt %d/%d)", wellKnownUrl, attempt, maxAttempts);

                // Fetch and parse discovery document
                ETagAwareHttpHandler.LoadResult result = etagHandler.load();
                if (result.content() == null) {
                    throw new WellKnownDiscoveryException("Failed to fetch discovery document from " + wellKnownUrl);
                }
                JsonObject discoveryDocument = parser.parseJsonResponse(result.content(), wellKnownUrl);

                LOGGER.debug("Discovery document load state: %s", result.loadState());

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
                this.endpoints.set(parsedEndpoints);
                this.status = LoaderStatus.OK;

                if (attempt > 1) {
                    LOGGER.info("Successfully loaded well-known endpoints from %s on attempt %d", wellKnownUrl, attempt);
                } else {
                    LOGGER.info("Successfully loaded well-known endpoints from: %s", wellKnownUrl);
                }
                return;

            } catch (WellKnownDiscoveryException e) {
                lastException = e;
                if (attempt < maxAttempts) {
                    LOGGER.debug("Well-known discovery failed on attempt %d, retrying after %dms: %s",
                            attempt, retryDelay.toMillis(), e.getMessage());
                    try {
                        Thread.sleep(retryDelay.toMillis());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        this.status = LoaderStatus.ERROR;
                        throw new WellKnownDiscoveryException("Well-known discovery interrupted", ie);
                    }
                } else {
                    LOGGER.error(e, ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, attempt));
                }
            }
        }

        // All attempts failed
        this.status = LoaderStatus.ERROR;
        throw new WellKnownDiscoveryException("Failed to load well-known endpoints from " + wellKnownUrl +
                " after " + maxAttempts + " attempts", lastException);
    }
}