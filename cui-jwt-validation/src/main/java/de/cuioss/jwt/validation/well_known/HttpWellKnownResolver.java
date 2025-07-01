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
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.util.ETagAwareHttpHandler;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import jakarta.json.JsonObject;
import lombok.NonNull;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

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

    private final URL wellKnownUrl;
    private final ETagAwareHttpHandler etagHandler;
    private final WellKnownParser parser;
    private final WellKnownEndpointMapper mapper;

    private final Map<String, HttpHandler> endpoints = new ConcurrentHashMap<>();
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;

    /**
     * Creates a new HTTP well-known resolver from WellKnownConfig.
     *
     * @param config the well-known configuration containing HTTP handler and parser settings
     */
    public HttpWellKnownResolver(@NonNull WellKnownConfig config) {
        HttpHandler httpHandler = config.getHttpHandler();
        this.wellKnownUrl = httpHandler.getUrl();
        this.etagHandler = new ETagAwareHttpHandler(httpHandler);
        this.parser = new WellKnownParser(config.getParserConfig());
        this.mapper = new WellKnownEndpointMapper(httpHandler);
        LOGGER.debug("Created HttpWellKnownResolver for URL: %s (not yet loaded)", wellKnownUrl);
    }

    @Override
    public WellKnownResult<HttpHandler> getJwksUri() {
        WellKnownResult<Void> loadResult = ensureLoaded();
        if (loadResult.isError()) {
            return WellKnownResult.error(loadResult.errorMessage());
        }
        return getEndpointResult(JWKS_URI_KEY);
    }

    @Override
    public WellKnownResult<HttpHandler> getAuthorizationEndpoint() {
        WellKnownResult<Void> loadResult = ensureLoaded();
        if (loadResult.isError()) {
            return WellKnownResult.error(loadResult.errorMessage());
        }
        return getEndpointResult(AUTHORIZATION_ENDPOINT_KEY);
    }

    @Override
    public WellKnownResult<HttpHandler> getTokenEndpoint() {
        WellKnownResult<Void> loadResult = ensureLoaded();
        if (loadResult.isError()) {
            return WellKnownResult.error(loadResult.errorMessage());
        }
        return getEndpointResult(TOKEN_ENDPOINT_KEY);
    }

    @Override
    public WellKnownResult<Optional<HttpHandler>> getUserinfoEndpoint() {
        WellKnownResult<Void> loadResult = ensureLoaded();
        if (loadResult.isError()) {
            return WellKnownResult.error(loadResult.errorMessage());
        }
        return WellKnownResult.success(Optional.ofNullable(endpoints.get(USERINFO_ENDPOINT_KEY)));
    }

    @Override
    public WellKnownResult<HttpHandler> getIssuer() {
        WellKnownResult<Void> loadResult = ensureLoaded();
        if (loadResult.isError()) {
            return WellKnownResult.error(loadResult.errorMessage());
        }
        return getEndpointResult(ISSUER_KEY);
    }

    @Override
    public LoaderStatus isHealthy() {
        if (endpoints.isEmpty()) {
            WellKnownResult<Void> loadResult = ensureLoaded();
            if (loadResult.isError()) {
                LOGGER.debug("Health check failed during endpoint loading: %s", loadResult.errorMessage());
                return LoaderStatus.ERROR;
            }
        }
        return status;
    }

    private WellKnownResult<HttpHandler> getEndpointResult(String key) {
        if (endpoints.isEmpty()) {
            return WellKnownResult.error("Endpoints not loaded");
        }
        HttpHandler handler = endpoints.get(key);
        if (handler == null) {
            return WellKnownResult.error("Endpoint not found: " + key);
        }
        return WellKnownResult.success(handler);
    }

    private WellKnownResult<Void> ensureLoaded() {
        if (endpoints.isEmpty()) {
            return loadEndpointsIfNeeded();
        }
        return WellKnownResult.success(null);
    }

    private WellKnownResult<Void> loadEndpointsIfNeeded() {
        // Double-checked locking pattern with ConcurrentHashMap
        if (endpoints.isEmpty()) {
            synchronized (this) {
                if (endpoints.isEmpty()) {
                    return loadEndpoints();
                }
            }
        }
        return WellKnownResult.success(null);
    }

    private WellKnownResult<Void> loadEndpoints() {
        LOGGER.debug("Loading well-known endpoints from %s", wellKnownUrl);

        // Fetch and parse discovery document
        ETagAwareHttpHandler.LoadResult result = etagHandler.load();
        if (result.content() == null) {
            this.status = LoaderStatus.ERROR;
            String errorMsg = "Failed to fetch discovery document from " + wellKnownUrl;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return WellKnownResult.error(errorMsg);
        }

        WellKnownResult<JsonObject> parseResult = parser.parseJsonResponse(result.content(), wellKnownUrl);
        if (parseResult.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return WellKnownResult.error(parseResult.errorMessage());
        }

        JsonObject discoveryDocument = parseResult.value();
        LOGGER.debug("Discovery document load state: %s", result.loadState());
        LOGGER.trace(DEBUG.DISCOVERY_DOCUMENT_FETCHED.format(discoveryDocument));

        Map<String, HttpHandler> parsedEndpoints = new HashMap<>();

        // Parse all endpoints
        String issuerString = parser.getString(discoveryDocument, ISSUER_KEY)
                .orElse(null);
        if (issuerString == null) {
            this.status = LoaderStatus.ERROR;
            String errorMsg = "Required field 'issuer' not found in discovery document from " + wellKnownUrl;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return WellKnownResult.error(errorMsg);
        }

        WellKnownResult<Void> issuerValidation = parser.validateIssuer(issuerString, wellKnownUrl);
        if (issuerValidation.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return issuerValidation;
        }

        WellKnownResult<Void> mapResult = mapper.addHttpHandlerToMap(parsedEndpoints, ISSUER_KEY, issuerString, wellKnownUrl, true);
        if (mapResult.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return mapResult;
        }

        // JWKS URI (Required)
        mapResult = mapper.addHttpHandlerToMap(parsedEndpoints, JWKS_URI_KEY,
                parser.getString(discoveryDocument, JWKS_URI_KEY).orElse(null), wellKnownUrl, true);
        if (mapResult.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return mapResult;
        }

        // Required endpoints
        mapResult = mapper.addHttpHandlerToMap(parsedEndpoints, AUTHORIZATION_ENDPOINT_KEY,
                parser.getString(discoveryDocument, AUTHORIZATION_ENDPOINT_KEY).orElse(null), wellKnownUrl, true);
        if (mapResult.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return mapResult;
        }

        mapResult = mapper.addHttpHandlerToMap(parsedEndpoints, TOKEN_ENDPOINT_KEY,
                parser.getString(discoveryDocument, TOKEN_ENDPOINT_KEY).orElse(null), wellKnownUrl, true);
        if (mapResult.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return mapResult;
        }

        // Optional endpoints
        mapResult = mapper.addHttpHandlerToMap(parsedEndpoints, USERINFO_ENDPOINT_KEY,
                parser.getString(discoveryDocument, USERINFO_ENDPOINT_KEY).orElse(null), wellKnownUrl, false);
        if (mapResult.isError()) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(ERROR.WELL_KNOWN_LOAD_FAILED.format(wellKnownUrl, 1));
            return mapResult;
        }

        // Accessibility check for jwks_uri
        mapper.performAccessibilityCheck(JWKS_URI_KEY, parsedEndpoints.get(JWKS_URI_KEY));

        // Success - save the endpoints
        this.endpoints.clear();
        this.endpoints.putAll(parsedEndpoints);
        this.status = LoaderStatus.OK;

        LOGGER.info("Successfully loaded well-known endpoints from: %s", wellKnownUrl);
        return WellKnownResult.success(null);
    }
}