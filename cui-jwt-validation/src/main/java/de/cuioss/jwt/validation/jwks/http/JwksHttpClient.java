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

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpStatusFamily;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

import static de.cuioss.jwt.validation.JWTValidationLogMessages.DEBUG;
import static de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;

/**
 * Handles HTTP operations for fetching JWKS content.
 * <p>
 * This class is responsible for:
 * <ul>
 *   <li>Creating and configuring the HTTP client</li>
 *   <li>Making requests to the JWKS endpoint</li>
 *   <li>Handling HTTP 304 "Not Modified" responses</li>
 *   <li>Managing ETag headers for conditional requests</li>
 * </ul>
 * <p>
 * This class implements {@link AutoCloseable} to properly close the {@link HttpClient}
 * when it's no longer needed.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@RequiredArgsConstructor
public class JwksHttpClient implements AutoCloseable {

    private static final CuiLogger LOGGER = new CuiLogger(JwksHttpClient.class);
    private static final String EMPTY_JWKS = "{}";

    @NonNull
    private final HttpJwksLoaderConfig config;

    @Getter
    private final HttpClient httpClient;

    /**
     * Response from a JWKS HTTP request.
     */
    public static class JwksHttpResponse {

        @Getter
        private final String content;
        private final String etag;
        @Getter
        private final boolean notModified;

        private JwksHttpResponse(String content, String etag, boolean notModified) {
            this.content = content;
            this.etag = etag;
            this.notModified = notModified;
        }

        /**
         * Creates a response for HTTP 304 Not Modified.
         *
         * @return a response indicating not modified
         */
        public static JwksHttpResponse notModified() {
            return new JwksHttpResponse(null, null, true);
        }

        /**
         * Creates a response with content and optional ETag.
         *
         * @param content the JWKS content
         * @param etag    the ETag header value, may be null
         * @return a response with content
         */
        public static JwksHttpResponse withContent(String content, String etag) {
            return new JwksHttpResponse(content, etag, false);
        }

        /**
         * Creates an empty JWKS response.
         *
         * @return a response with empty JWKS content
         */
        public static JwksHttpResponse empty() {
            return new JwksHttpResponse(EMPTY_JWKS, null, false);
        }

        /**
         * Gets the ETag header value.
         *
         * @return the ETag, or null if not present
         */
        public Optional<String> getEtag() {
            return Optional.ofNullable(etag);
        }

    }

    /**
     * Creates a new JwksHttpClient with the specified configuration.
     *
     * @param config the configuration
     * @return a new JwksHttpClient
     */
    @SuppressWarnings("try") // HttpClient implements AutoCloseable in Java 17 but doesn't need to be closed
    public static JwksHttpClient create(@NonNull HttpJwksLoaderConfig config) {
        HttpClient httpClient = config.getHttpHandler().createHttpClient();
        LOGGER.debug("Configuring JwksHttpClient for %s", config.getHttpHandler().getUrl().toString());
        return new JwksHttpClient(config, httpClient);
    }

    /**
     * Fetches JWKS content from the configured endpoint.
     *
     * @param previousEtag the ETag from a previous response may be null
     * @return the response containing JWKS content or not modified indication
     */
    @SuppressWarnings("try") // HttpClient implements AutoCloseable in Java 17 but doesn't need to be closed
    public JwksHttpResponse fetchJwksContent(String previousEtag) {
        // Get the HttpHandler from the config
        var httpHandler = config.getHttpHandler();

        // According to HttpHandler contract, URI is never null after build
        String uriString = httpHandler.getUri().toString();
        LOGGER.debug(DEBUG.RESOLVING_KEY_LOADER.format(uriString));

        // Build the request with conditional GET if we have an ETag
        HttpRequest.Builder requestBuilder = httpHandler.requestBuilder()
                .header("Accept", "application/json");

        if (previousEtag != null && !previousEtag.isEmpty()) {
            requestBuilder.header("If-None-Match", previousEtag);
        }

        HttpRequest request = requestBuilder.GET().build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Handle different response status codes
            int statusCode = response.statusCode();
            if (statusCode == 304) { // HTTP 304 Not Modified
                LOGGER.debug(DEBUG.RECEIVED_304_NOT_MODIFIED::format);
                return JwksHttpResponse.notModified();
            }

            // Check response status using HttpStatusFamily
            HttpStatusFamily statusFamily = HttpStatusFamily.fromStatusCode(statusCode);
            if (statusFamily != HttpStatusFamily.SUCCESS) {
                LOGGER.warn(WARN.JWKS_FETCH_FAILED.format(statusCode));
                return JwksHttpResponse.empty();
            }

            // Get content and ETag
            String jwksContent = response.body();
            String etag = response.headers().firstValue("ETag").orElse(null);

            LOGGER.debug(DEBUG.FETCHED_JWKS.format(uriString));
            return JwksHttpResponse.withContent(jwksContent, etag);

        } catch (IOException | InterruptedException e) {
            LOGGER.warn(e, WARN.FAILED_TO_FETCH_JWKS.format(uriString));
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return JwksHttpResponse.empty();
        }
    }

    /**
     * Closes this resource, relinquishing any underlying resources.
     * This method is invoked automatically on objects managed by the
     * try-with-resources statement.
     *
     * @throws Exception if this resource cannot be closed
     */
    @Override
    public void close() throws Exception {
        // HttpClient doesn't have a close method in Java 11, but we implement
        // AutoCloseable to allow for future versions that might require cleanup
        // or to support try-with-resources pattern
        LOGGER.debug("Closing JwksHttpClient");
    }
}
