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
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.HttpStatusFamily;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Handles the discovery of OpenID Connect (OIDC) Provider metadata from a
 * .well-known/openid-configuration endpoint.
 * This class fetches, parses, and validates the OIDC discovery document.
 * It provides access to the discovered endpoint URLs like {@code jwks_uri},
 * {@code authorization_endpoint}, etc.
 * The implementation uses {@link java.net.http.HttpClient} for fetching the
 * discovery document and {@link jakarta.json.Json} for parsing the JSON response.
 * Issuer validation is performed to ensure the 'issuer' claim in the discovery
 * document is consistent with the .well-known URL from which it was fetched.
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

    private static final int TIMEOUT_SECONDS = 5; // 5 seconds
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
         * Sets the parser configuration for JSON parsing.
         * <p>
         * If not set, a default secure parser configuration will be used.
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
         * Parses a JSON response string into a JsonObject.
         *
         * @param responseBody The JSON response string to parse
         * @param wellKnownUrl The well-known URL (used for error messages)
         * @return The parsed JsonObject
         * @throws WellKnownDiscoveryException If parsing fails
         */
        private JsonObject parseJsonResponse(String responseBody, URL wellKnownUrl) {
            // Use the provided ParserConfig or create a default one
            ParserConfig config = parserConfig != null ? parserConfig : ParserConfig.builder().build();
            try (JsonReader jsonReader = config.getJsonReaderFactory().createReader(new StringReader(responseBody))) {
                return jsonReader.readObject();
            } catch (Exception e) {
                throw new WellKnownDiscoveryException("Failed to parse JSON from " + wellKnownUrl, e);
            }
        }

        /**
         * Extracts a string value from a JsonObject.
         *
         * @param jsonObject The JsonObject to extract from
         * @param key The key to extract
         * @return An Optional containing the string value, or empty if not found
         */
        private Optional<String> getString(JsonObject jsonObject, String key) {
            if (jsonObject.containsKey(key) && !jsonObject.isNull(key)) {
                JsonString jsonString = jsonObject.getJsonString(key);
                if (jsonString != null) {
                    return Optional.of(jsonString.getString());
                }
            }
            return Optional.empty();
        }

        /**
         * Adds an HttpHandler to the map of endpoints.
         *
         * @param map The map to add to
         * @param key The key for the HttpHandler
         * @param urlString The URL string to add
         * @param wellKnownUrl The well-known URL (used for error messages)
         * @param isRequired Whether this URL is required
         * @param baseHandler The base HttpHandler to use for configuration
         */
        private void addHttpHandlerToMap(Map<String, HttpHandler> map, String key, String urlString, URL wellKnownUrl, boolean isRequired, HttpHandler baseHandler) {
            if (urlString == null) {
                if (isRequired) {
                    throw new WellKnownDiscoveryException("Required URL field '" + key + "' is missing in discovery document from " + wellKnownUrl);
                }
                LOGGER.debug(DEBUG.OPTIONAL_URL_FIELD_MISSING.format(key, wellKnownUrl));
                return;
            }
            try {
                // Use asBuilder() to efficiently reuse the configuration from the base handler
                HttpHandler handler = baseHandler.asBuilder()
                        .uri(urlString)
                        .build();
                map.put(key, handler);
            } catch (IllegalArgumentException e) {
                throw new WellKnownDiscoveryException(
                        "Malformed URL for field '" + key + "': " + urlString + " from " + wellKnownUrl, e);
            }
        }

        /**
         * Validates that the issuer from the discovery document matches the well-known URL.
         *
         * @param issuerFromDocument The issuer from the discovery document
         * @param wellKnownUrl The well-known URL
         */
        private void validateIssuer(String issuerFromDocument, URL wellKnownUrl) {
            LOGGER.debug(DEBUG.VALIDATING_ISSUER.format(issuerFromDocument, wellKnownUrl));
            // The OpenID Connect Discovery 1.0 spec, section 4.3 states:
            // "The issuer value returned MUST be identical to the Issuer URL that was
            // used as the prefix to /.well-known/openid-configuration to retrieve the
            // configuration information."
            // A simple check is to see if the url starts with the issuer string,
            // and that the path component matches.
            // For example, if issuer is "https://example.com", url should be "https://example.com/.well-known/openid-configuration"
            // If issuer is "https://example.com/path", url should be "https://example.com/path/.well-known/openid-configuration"

            URL issuerAsUrl;
            try {
                issuerAsUrl = URI.create(issuerFromDocument).toURL();
            } catch (MalformedURLException | IllegalArgumentException e) {
                throw new WellKnownDiscoveryException("Issuer URL from discovery document is malformed: " + issuerFromDocument, e);
            }

            String expectedWellKnownPath = determineWellKnownPath(issuerAsUrl);


            boolean schemeMatch = issuerAsUrl.getProtocol().equals(wellKnownUrl.getProtocol());
            boolean hostMatch = issuerAsUrl.getHost().equalsIgnoreCase(wellKnownUrl.getHost());
            int issuerPort = issuerAsUrl.getPort() == -1 ? issuerAsUrl.getDefaultPort() : issuerAsUrl.getPort();
            int wellKnownPort = wellKnownUrl.getPort() == -1 ? wellKnownUrl.getDefaultPort() : wellKnownUrl.getPort();
            boolean portMatch = issuerPort == wellKnownPort;
            boolean pathMatch = wellKnownUrl.getPath().equals(expectedWellKnownPath);


            if (!(schemeMatch && hostMatch && portMatch && pathMatch)) {
                String errorMessage = ERROR.ISSUER_VALIDATION_FAILED.format(
                        issuerFromDocument, issuerAsUrl.getProtocol(), issuerAsUrl.getHost(),
                        (issuerAsUrl.getPort() != -1 ? ":" + issuerAsUrl.getPort() : ""),
                        (issuerAsUrl.getPath() == null ? "" : issuerAsUrl.getPath()),
                        wellKnownUrl.toString(),
                        expectedWellKnownPath,
                        schemeMatch, hostMatch, portMatch, issuerPort, wellKnownPort, pathMatch, wellKnownUrl.getPath());
                LOGGER.error(errorMessage);
                throw new WellKnownDiscoveryException(errorMessage);
            }
            LOGGER.debug(DEBUG.ISSUER_VALIDATION_SUCCESSFUL.format(issuerFromDocument));
        }

        private String determineWellKnownPath(URL issuerAsUrl) {
            String expectedWellKnownPath;
            if (issuerAsUrl.getPath() == null || issuerAsUrl.getPath().isEmpty() || "/".equals(issuerAsUrl.getPath())) {
                expectedWellKnownPath = WELL_KNOWN_OPENID_CONFIGURATION;
            } else {
                String issuerPath = issuerAsUrl.getPath();
                if (issuerPath.endsWith("/")) {
                    issuerPath = issuerPath.substring(0, issuerPath.length() - 1);
                }
                expectedWellKnownPath = issuerPath + WELL_KNOWN_OPENID_CONFIGURATION;
            }
            return expectedWellKnownPath;
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
            // Configure the HttpHandlerBuilder with the timeout
            // TODO: Update to new HttpHandler API
            // httpHandlerBuilder.requestTimeoutSeconds(TIMEOUT_SECONDS);

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
            LOGGER.debug(DEBUG.FETCHING_DISCOVERY_DOCUMENT.format(resolvedUrl));

            JsonObject discoveryDocument;
            try {
                // Create a request with Accept header for JSON
                HttpRequest request = wellKnownHttpHandler.requestBuilder()
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                // Send the request and get the response
                // Use the createHttpClient method from HttpHandler which already configures timeout and SSL context
                HttpClient httpClient = wellKnownHttpHandler.createHttpClient();
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                // Check the response status using HttpStatusFamily
                HttpStatusFamily statusFamily = HttpStatusFamily.fromStatusCode(response.statusCode());
                if (statusFamily != HttpStatusFamily.SUCCESS) {
                    throw new WellKnownDiscoveryException("Failed to fetch discovery document from " + resolvedUrl +
                            ". HTTP status: " + response.statusCode() + " (" + statusFamily + ")");
                }

                // Parse the response body
                discoveryDocument = parseJsonResponse(response.body(), resolvedUrl);
            } catch (IOException e) {
                throw new WellKnownDiscoveryException("IOException while fetching or reading from " + resolvedUrl, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new WellKnownDiscoveryException("Interrupted while fetching from " + resolvedUrl, e);
            } catch (Exception e) {
                throw new WellKnownDiscoveryException("Error while fetching from " + resolvedUrl, e);
            }

            LOGGER.trace(DEBUG.DISCOVERY_DOCUMENT_FETCHED.format(discoveryDocument));

            Map<String, HttpHandler> parsedEndpoints = new HashMap<>();

            // Issuer (Required)
            String issuerString = getString(discoveryDocument, ISSUER_KEY)
                    .orElseThrow(() -> new WellKnownDiscoveryException("Required field 'issuer' not found in discovery document from " + resolvedUrl));
            validateIssuer(issuerString, resolvedUrl);
            addHttpHandlerToMap(parsedEndpoints, ISSUER_KEY, issuerString, resolvedUrl, true, wellKnownHttpHandler);

            // JWKS URI (Required)
            addHttpHandlerToMap(parsedEndpoints, JWKS_URI_KEY, getString(discoveryDocument, JWKS_URI_KEY).orElse(null), resolvedUrl, true, wellKnownHttpHandler);

            // Required endpoints
            addHttpHandlerToMap(parsedEndpoints, AUTHORIZATION_ENDPOINT_KEY, getString(discoveryDocument, AUTHORIZATION_ENDPOINT_KEY).orElse(null), resolvedUrl, true, wellKnownHttpHandler);
            addHttpHandlerToMap(parsedEndpoints, TOKEN_ENDPOINT_KEY, getString(discoveryDocument, TOKEN_ENDPOINT_KEY).orElse(null), resolvedUrl, true, wellKnownHttpHandler);
            // Optional endpoints
            addHttpHandlerToMap(parsedEndpoints, USERINFO_ENDPOINT_KEY, getString(discoveryDocument, USERINFO_ENDPOINT_KEY).orElse(null), resolvedUrl, false, wellKnownHttpHandler);

            // Accessibility check for jwks_uri (optional but recommended)
            if (parsedEndpoints.get(JWKS_URI_KEY) != null) {
                HttpStatusFamily statusFamily = parsedEndpoints.get(JWKS_URI_KEY).pingHead();
                if (statusFamily != HttpStatusFamily.SUCCESS) {
                    LOGGER.warn(WARN.ACCESSIBILITY_CHECK_HTTP_ERROR.format(JWKS_URI_KEY, parsedEndpoints.get(JWKS_URI_KEY).getUrl(), statusFamily));
                } else {
                    LOGGER.debug(DEBUG.ACCESSIBILITY_CHECK_SUCCESSFUL.format(JWKS_URI_KEY, parsedEndpoints.get(JWKS_URI_KEY).getUrl(), statusFamily));
                }
            }

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
