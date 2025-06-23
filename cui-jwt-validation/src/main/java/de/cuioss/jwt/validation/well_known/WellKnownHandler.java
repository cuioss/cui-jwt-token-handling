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
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import jakarta.json.JsonObject;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Handles the discovery of OpenID Connect (OIDC) Provider metadata from a
 * .well-known/openid-configuration endpoint.
 * <p>
 * This class orchestrates the fetching, parsing, and validation of OIDC discovery documents.
 * It provides access to the discovered endpoint URLs like {@code jwks_uri},
 * {@code authorization_endpoint}, etc.
 * <p>
 * The implementation uses composition with specialized components:
 * <ul>
 *   <li>{@link WellKnownClient} - for HTTP operations</li>
 *   <li>{@link WellKnownParser} - for JSON parsing and validation</li>
 *   <li>{@link WellKnownEndpointMapper} - for endpoint mapping</li>
 * </ul>
 * <p>
 * Issuer validation is performed to ensure the 'issuer' claim in the discovery
 * document is consistent with the .well-known URL from which it was fetched.
 * <p>
 * Use the builder to create instances of this class:
 * <pre>
 * WellKnownHandler handler = WellKnownHandler.builder()
 *     .url("https://example.com/.well-known/openid-configuration")
 *     .build();
 * </pre>
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@EqualsAndHashCode
@ToString
public final class WellKnownHandler {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownHandler.class);

    private static final String ISSUER_KEY = "issuer";
    private static final String JWKS_URI_KEY = "jwks_uri";
    private static final String AUTHORIZATION_ENDPOINT_KEY = "authorization_endpoint";
    private static final String TOKEN_ENDPOINT_KEY = "token_endpoint";
    private static final String USERINFO_ENDPOINT_KEY = "userinfo_endpoint";

    private static final int CONNECT_TIMEOUT_SECONDS = 2; // 2 seconds for connection
    private static final int READ_TIMEOUT_SECONDS = 3; // 3 seconds for reading
    public static final String WELL_KNOWN_OPENID_CONFIGURATION = "/.well-known/openid-configuration";

    private final Map<String, HttpHandler> endpoints;

    @Getter
    private final URL wellKnownUrl;

    /**
     * The HttpHandler used for HTTP requests.
     */
    @Getter
    private final HttpHandler httpHandler;

    /**
     * Returns a new builder for creating a {@link WellKnownHandler} instance.
     *
     * @return A new builder instance.
     */
    public static WellKnownHandlerBuilder builder() {
        return new WellKnownHandlerBuilder();
    }


    /**
     * Builder for creating {@link WellKnownHandler} instances.
     */
    public static class WellKnownHandlerBuilder {
        private ParserConfig parserConfig;
        private final HttpHandler.HttpHandlerBuilder httpHandlerBuilder;
        private Integer connectTimeoutSeconds;
        private Integer readTimeoutSeconds;

        /**
         * Constructor initializing the HttpHandlerBuilder.
         */
        public WellKnownHandlerBuilder() {
            this.httpHandlerBuilder = HttpHandler.builder();
        }

        /**
         * Sets the well-known URL as a string.
         *
         * @param wellKnownUrlString The string representation of the .well-known/openid-configuration URL.
         *                           Must not be null or empty.
         * @return This builder instance.
         * @throws IllegalArgumentException if the URL string is null, empty, or malformed (during build)
         */
        public WellKnownHandlerBuilder url(String wellKnownUrlString) {
            httpHandlerBuilder.url(wellKnownUrlString);
            return this;
        }

        /**
         * Sets the well-known URL directly.
         * <p>
         * Note: If both URL and string are set, the URL takes precedence.
         * </p>
         *
         * @param wellKnownUrl The URL of the .well-known/openid-configuration endpoint.
         *                     Must not be null.
         * @return This builder instance.
         * @throws IllegalArgumentException if the URL is null (during build)
         */
        public WellKnownHandlerBuilder url(URL wellKnownUrl) {
            httpHandlerBuilder.url(wellKnownUrl);
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
        public WellKnownHandlerBuilder sslContext(SSLContext sslContext) {
            httpHandlerBuilder.sslContext(sslContext);
            return this;
        }

        /**
         * Sets the TLS versions configuration.
         *
         * @param secureSSLContextProvider The TLS versions configuration to use.
         * @return This builder instance.
         */
        public WellKnownHandlerBuilder tlsVersions(SecureSSLContextProvider secureSSLContextProvider) {
            httpHandlerBuilder.tlsVersions(secureSSLContextProvider);
            return this;
        }

        /**
         * Sets the connection timeout in seconds.
         * <p>
         * If not set, the timeout will be taken from the ParserConfig if available,
         * otherwise the default value will be used.
         *
         * @param connectTimeoutSeconds the connection timeout in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if connectTimeoutSeconds is not positive
         */
        public WellKnownHandlerBuilder connectTimeoutSeconds(int connectTimeoutSeconds) {
            Preconditions.checkArgument(connectTimeoutSeconds > 0, "connectTimeoutSeconds must be > 0, but was %s", connectTimeoutSeconds);
            this.connectTimeoutSeconds = connectTimeoutSeconds;
            return this;
        }

        /**
         * Sets the read timeout in seconds.
         * <p>
         * If not set, the timeout will be taken from the ParserConfig if available,
         * otherwise the default value will be used.
         *
         * @param readTimeoutSeconds the read timeout in seconds
         * @return this builder instance
         * @throws IllegalArgumentException if readTimeoutSeconds is not positive
         */
        public WellKnownHandlerBuilder readTimeoutSeconds(int readTimeoutSeconds) {
            Preconditions.checkArgument(readTimeoutSeconds > 0, "readTimeoutSeconds must be > 0, but was %s", readTimeoutSeconds);
            this.readTimeoutSeconds = readTimeoutSeconds;
            return this;
        }

        /**
         * Sets the parser configuration for JSON parsing and HTTP timeouts.
         * <p>
         * If not set, a default secure parser configuration will be used.
         * The ParserConfig also provides default timeout values if explicit timeouts
         * are not set via {@link #connectTimeoutSeconds(int)} and {@link #readTimeoutSeconds(int)}.
         * </p>
         *
         * @param parserConfig The parser configuration to use.
         * @return This builder instance.
         */
        public WellKnownHandlerBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig;
            return this;
        }


        /**
         * Builds a new {@link WellKnownHandler} instance with the configured parameters.
         *
         * @return A new {@link WellKnownHandler} instance.
         * @throws WellKnownDiscoveryException If any error occurs during discovery,
         *                                     parsing, or validation (e.g., network issues,
         *                                     malformed JSON, invalid issuer).
         */
        @SuppressWarnings("try") // HttpClient implements AutoCloseable in Java 17 but doesn't need to be closed
        public WellKnownHandler build() {
            // Use ParserConfig timeout values if not explicitly set
            int actualConnectTimeout;
            if (connectTimeoutSeconds != null) {
                actualConnectTimeout = connectTimeoutSeconds;
            } else if (parserConfig != null) {
                actualConnectTimeout = parserConfig.getWellKnownConnectTimeoutSeconds();
            } else {
                actualConnectTimeout = CONNECT_TIMEOUT_SECONDS;
            }

            int actualReadTimeout;
            if (readTimeoutSeconds != null) {
                actualReadTimeout = readTimeoutSeconds;
            } else if (parserConfig != null) {
                actualReadTimeout = parserConfig.getWellKnownReadTimeoutSeconds();
            } else {
                actualReadTimeout = READ_TIMEOUT_SECONDS;
            }

            // Configure the HttpHandlerBuilder with the timeout
            httpHandlerBuilder.connectionTimeoutSeconds(actualConnectTimeout);
            httpHandlerBuilder.readTimeoutSeconds(actualReadTimeout);

            // Build the HttpHandler for the well-known URL
            HttpHandler wellKnownHttpHandler;
            try {
                wellKnownHttpHandler = httpHandlerBuilder.build();
            } catch (IllegalArgumentException | IllegalStateException e) {
                // If we get here, the URL is invalid
                throw new WellKnownDiscoveryException("Invalid .well-known URL", e);
            }

            // Get the URL from the HttpHandler
            URL resolvedUrl = wellKnownHttpHandler.getUrl();

            // Create composed components
            WellKnownClient client = new WellKnownClient(wellKnownHttpHandler);
            WellKnownParser parser = new WellKnownParser(parserConfig);
            WellKnownEndpointMapper mapper = new WellKnownEndpointMapper(wellKnownHttpHandler);

            // Fetch and parse discovery document
            String responseBody = client.fetchDiscoveryDocument();
            JsonObject discoveryDocument = parser.parseJsonResponse(responseBody, resolvedUrl);

            LOGGER.trace(DEBUG.DISCOVERY_DOCUMENT_FETCHED.format(discoveryDocument));

            Map<String, HttpHandler> parsedEndpoints = new HashMap<>();

            // Issuer (Required)
            String issuerString = parser.getString(discoveryDocument, ISSUER_KEY)
                    .orElseThrow(() -> new WellKnownDiscoveryException("Required field 'issuer' not found in discovery document from " + resolvedUrl));
            parser.validateIssuer(issuerString, resolvedUrl);
            mapper.addHttpHandlerToMap(parsedEndpoints, ISSUER_KEY, issuerString, resolvedUrl, true);

            // JWKS URI (Required)
            mapper.addHttpHandlerToMap(parsedEndpoints, JWKS_URI_KEY, parser.getString(discoveryDocument, JWKS_URI_KEY).orElse(null), resolvedUrl, true);

            // Required endpoints
            mapper.addHttpHandlerToMap(parsedEndpoints, AUTHORIZATION_ENDPOINT_KEY, parser.getString(discoveryDocument, AUTHORIZATION_ENDPOINT_KEY).orElse(null), resolvedUrl, true);
            mapper.addHttpHandlerToMap(parsedEndpoints, TOKEN_ENDPOINT_KEY, parser.getString(discoveryDocument, TOKEN_ENDPOINT_KEY).orElse(null), resolvedUrl, true);
            // Optional endpoints
            mapper.addHttpHandlerToMap(parsedEndpoints, USERINFO_ENDPOINT_KEY, parser.getString(discoveryDocument, USERINFO_ENDPOINT_KEY).orElse(null), resolvedUrl, false);

            // Accessibility check for jwks_uri (optional but recommended)
            mapper.performAccessibilityCheck(JWKS_URI_KEY, parsedEndpoints.get(JWKS_URI_KEY));

            return new WellKnownHandler(parsedEndpoints, resolvedUrl, wellKnownHttpHandler);
        }
    }

    /**
     * @return The JWKS URI HttpHandler.
     */
    public HttpHandler getJwksUri() {
        return endpoints.get(JWKS_URI_KEY);
    }

    /**
     * @return The Authorization Endpoint HttpHandler.
     */
    public HttpHandler getAuthorizationEndpoint() {
        return endpoints.get(AUTHORIZATION_ENDPOINT_KEY);
    }

    /**
     * @return The Token Endpoint HttpHandler.
     */
    public HttpHandler getTokenEndpoint() {
        return endpoints.get(TOKEN_ENDPOINT_KEY);
    }

    /**
     * @return An {@link Optional} containing the UserInfo Endpoint HttpHandler, or empty if not present.
     * According to the OpenID Connect Discovery 1.0 specification, this endpoint is RECOMMENDED but not REQUIRED.
     */
    public Optional<HttpHandler> getUserinfoEndpoint() {
        return Optional.ofNullable(endpoints.get(USERINFO_ENDPOINT_KEY));
    }

    /**
     * @return The Issuer HttpHandler.
     */
    public HttpHandler getIssuer() {
        return endpoints.get(ISSUER_KEY);
    }
}
