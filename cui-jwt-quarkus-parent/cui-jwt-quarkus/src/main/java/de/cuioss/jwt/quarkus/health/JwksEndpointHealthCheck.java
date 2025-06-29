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
package de.cuioss.jwt.quarkus.health;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import de.cuioss.jwt.quarkus.config.JwtPropertyKeys;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Readiness;

import java.util.concurrent.TimeUnit;

/**
 * Health check for JWKS endpoint connectivity.
 * This class implements the SmallRye Health check interface to provide
 * readiness status for JWT validation JWKS endpoints.
 */
@ApplicationScoped
@Readiness // Marks this as a readiness check
public class JwksEndpointHealthCheck implements HealthCheck {

    private static final CuiLogger LOGGER = new CuiLogger(JwksEndpointHealthCheck.class);
    private static final String DEFAULT_CACHE_SECONDS = "30";
    private static final String HEALTHCHECK_NAME = "jwks-endpoints";
    private static final String ERROR_NO_ISSUER_CONFIGS = "No issuer configurations found";
    private static final String ERROR = "error";
    private static final String STATUS_UP = "UP";
    private static final String STATUS_DOWN = "DOWN";

    private final TokenValidator tokenValidator;
    private final ConcurrentHashMap<String, CachedResponse> healthCheckCache = new ConcurrentHashMap<>();
    private final long cacheTimeoutMillis;

    @Inject
    public JwksEndpointHealthCheck(TokenValidator tokenValidator,
            @ConfigProperty(name = JwtPropertyKeys.HEALTH.JWKS.CACHE_SECONDS, defaultValue = DEFAULT_CACHE_SECONDS) int cacheSeconds) {
        this.tokenValidator = tokenValidator;
        this.cacheTimeoutMillis = TimeUnit.SECONDS.toMillis(cacheSeconds);
    }

    @Override
    public HealthCheckResponse call() {
        // Use cache to prevent excessive network calls
        CachedResponse cached = healthCheckCache.get(HEALTHCHECK_NAME);
        if (cached != null && !cached.isExpired()) {
            return cached.response;
        }
        
        HealthCheckResponse response = performHealthCheck();
        healthCheckCache.put(HEALTHCHECK_NAME, new CachedResponse(response, System.currentTimeMillis() + cacheTimeoutMillis));
        return response;
    }

    /**
     * Performs the actual health check without caching.
     *
     * @return the health check response
     */
    private HealthCheckResponse performHealthCheck() {
        var issuerConfigMap = tokenValidator.getIssuerConfigMap();
        if (issuerConfigMap.isEmpty()) {
            return createErrorResponse(ERROR_NO_ISSUER_CONFIGS);
        }

        var responseBuilder = HealthCheckResponse.named(HEALTHCHECK_NAME).up();

        var results = issuerConfigMap.entrySet().stream()
                .map(entry -> EndpointResult.fromIssuerConfig(entry.getKey(), entry.getValue()))
                .toList();

        // Add all endpoint data to response
        for (int i = 0; i < results.size(); i++) {
            results.get(i).addToResponse(responseBuilder, "issuer." + i + ".");
        }

        // Set overall health status
        boolean allUp = results.stream().allMatch(EndpointResult::isHealthy);
        responseBuilder.withData("checkedEndpoints", results.size());

        if (!allUp) {
            responseBuilder.down();
        }

        return responseBuilder.build();
    }

    /**
     * Creates an error response with the given error message.
     *
     * @param errorMessage the error message
     * @return the health check response
     */
    private HealthCheckResponse createErrorResponse(String errorMessage) {
        return HealthCheckResponse.named(HEALTHCHECK_NAME)
                .down()
                .withData(ERROR, errorMessage)
                .build();
    }

    private record CachedResponse(HealthCheckResponse response, long expiryTime) {
        boolean isExpired() {
            return System.currentTimeMillis() > expiryTime;
        }
    }

    private record EndpointResult(String issuer, String jwksType, LoaderStatus status) {

        /**
         * Creates an EndpointResult from an issuer configuration.
         *
         * @param issuer the issuer name
         * @param issuerConfig the issuer configuration
         * @return the endpoint result
         */
        static EndpointResult fromIssuerConfig(String issuer, IssuerConfig issuerConfig) {
            try {
                JwksLoader jwksLoader = issuerConfig.getJwksLoader();

                if (jwksLoader == null) {
                    return new EndpointResult(issuer, JwksType.NONE.toString(), LoaderStatus.ERROR);
                }

                LoaderStatus status = jwksLoader.getStatus();
                LOGGER.debug("JWKS loader status for issuer %s: %s", issuer, status);

                return new EndpointResult(issuer, jwksLoader.getJwksType().toString(), status);
            } catch (Exception e) {
                LOGGER.warn(e, "Error checking JWKS loader for issuer %s: %s", issuer, e.getMessage());
                return new EndpointResult(issuer, JwksType.NONE.toString(), LoaderStatus.ERROR);
            }
        }

        /**
         * Adds this endpoint's data to the health check response builder.
         *
         * @param responseBuilder the response builder
         * @param prefix the prefix for the data keys
         */
        void addToResponse(HealthCheckResponseBuilder responseBuilder, String prefix) {
            boolean up = status == LoaderStatus.OK;
            responseBuilder.withData(prefix + "url", issuer);
            responseBuilder.withData(prefix + "jwksType", jwksType);
            responseBuilder.withData(prefix + "status", up ? STATUS_UP : STATUS_DOWN);
        }

        /**
         * Checks if this endpoint is healthy.
         *
         * @return true if the status is OK, false otherwise
         */
        boolean isHealthy() {
            return status == LoaderStatus.OK;
        }
    }
}
