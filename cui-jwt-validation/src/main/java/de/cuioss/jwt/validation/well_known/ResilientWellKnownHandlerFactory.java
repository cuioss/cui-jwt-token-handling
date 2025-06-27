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
import de.cuioss.jwt.validation.resilience.ResilientHttpHandler;
import de.cuioss.jwt.validation.resilience.ResilientHttpHandler.CircuitBreakerConfig;
import de.cuioss.jwt.validation.resilience.ResilientHttpHandler.RetryConfig;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

import javax.net.ssl.SSLContext;
import java.net.URL;
import java.time.Duration;

/**
 * Factory for creating resilient WellKnownHandler instances.
 * <p>
 * This factory integrates the resilient HttpHandler composition with WellKnownHandler
 * to provide comprehensive resilience patterns for well-known endpoint discovery.
 * <p>
 * Features:
 * <ul>
 *   <li>Automatic retry with exponential backoff for transient failures</li>
 *   <li>Circuit breaker to prevent cascading failures</li>
 *   <li>Lazy loading to defer discovery until needed</li>
 *   <li>Configurable timeout and retry parameters</li>
 *   <li>Native-image compatible implementation</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * // Create with default resilience configuration
 * LazyWellKnownHandler handler = ResilientWellKnownHandlerFactory.createResilient(
 *     "https://example.com/.well-known/openid-configuration"
 * );
 * 
 * // Create with custom configuration
 * LazyWellKnownHandler customHandler = ResilientWellKnownHandlerFactory.createResilient(
 *     "https://example.com/.well-known/openid-configuration",
 *     ParserConfig.builder()
 *         .wellKnownConnectTimeoutSeconds(5)
 *         .wellKnownReadTimeoutSeconds(10)
 *         .build(),
 *     RetryConfig.builder()
 *         .maxAttempts(5)
 *         .initialDelay(Duration.ofMillis(200))
 *         .build(),
 *     CircuitBreakerConfig.builder()
 *         .failureThreshold(3)
 *         .openTimeout(Duration.ofMinutes(1))
 *         .build()
 * );
 * </pre>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ResilientWellKnownHandlerFactory {

    private static final CuiLogger LOGGER = new CuiLogger(ResilientWellKnownHandlerFactory.class);

    /**
     * Default retry configuration for well-known discovery.
     * More aggressive than general HTTP calls due to critical nature.
     */
    private static final RetryConfig DEFAULT_WELLKNOWN_RETRY_CONFIG = RetryConfig.builder()
            .maxAttempts(3)
            .initialDelay(Duration.ofMillis(100))
            .maxDelay(Duration.ofSeconds(5))
            .multiplier(2.0)
            .jitterFactor(0.1)
            .build();

    /**
     * Default circuit breaker configuration for well-known discovery.
     * More tolerant than general HTTP calls to allow recovery attempts.
     */
    private static final CircuitBreakerConfig DEFAULT_WELLKNOWN_CIRCUIT_CONFIG = CircuitBreakerConfig.builder()
            .failureThreshold(5)
            .openTimeout(Duration.ofSeconds(60))
            .halfOpenMaxAttempts(3)
            .build();

    /**
     * Creates a resilient LazyWellKnownHandler with default configuration.
     *
     * @param wellKnownUrl the well-known discovery URL
     * @return a new LazyWellKnownHandler with resilience patterns applied
     */
    public static LazyWellKnownHandler createResilient(@NonNull String wellKnownUrl) {
        return createResilient(wellKnownUrl, null, null, null, null);
    }

    /**
     * Creates a resilient LazyWellKnownHandler with custom parser configuration.
     *
     * @param wellKnownUrl the well-known discovery URL
     * @param parserConfig the parser configuration (may be null for defaults)
     * @return a new LazyWellKnownHandler with resilience patterns applied
     */
    public static LazyWellKnownHandler createResilient(@NonNull String wellKnownUrl,
                                                      ParserConfig parserConfig) {
        return createResilient(wellKnownUrl, parserConfig, null, null, null);
    }

    /**
     * Creates a resilient LazyWellKnownHandler with custom resilience configuration.
     *
     * @param wellKnownUrl the well-known discovery URL
     * @param parserConfig the parser configuration (may be null for defaults)
     * @param retryConfig the retry configuration (may be null for defaults)
     * @param circuitBreakerConfig the circuit breaker configuration (may be null for defaults)
     * @return a new LazyWellKnownHandler with resilience patterns applied
     */
    public static LazyWellKnownHandler createResilient(@NonNull String wellKnownUrl,
                                                      ParserConfig parserConfig,
                                                      RetryConfig retryConfig,
                                                      CircuitBreakerConfig circuitBreakerConfig) {
        return createResilient(wellKnownUrl, parserConfig, retryConfig, circuitBreakerConfig, null);
    }

    /**
     * Creates a resilient LazyWellKnownHandler with full custom configuration.
     *
     * @param wellKnownUrl the well-known discovery URL
     * @param parserConfig the parser configuration (may be null for defaults)
     * @param retryConfig the retry configuration (may be null for defaults)
     * @param circuitBreakerConfig the circuit breaker configuration (may be null for defaults)
     * @param sslContext the SSL context (may be null for default secure context)
     * @return a new LazyWellKnownHandler with resilience patterns applied
     */
    public static LazyWellKnownHandler createResilient(@NonNull String wellKnownUrl,
                                                      ParserConfig parserConfig,
                                                      RetryConfig retryConfig,
                                                      CircuitBreakerConfig circuitBreakerConfig,
                                                      SSLContext sslContext) {
        LOGGER.debug("Creating resilient WellKnownHandler for URL: %s", wellKnownUrl);

        // Use defaults if not provided
        RetryConfig effectiveRetryConfig = retryConfig != null ? retryConfig : DEFAULT_WELLKNOWN_RETRY_CONFIG;
        CircuitBreakerConfig effectiveCircuitConfig = circuitBreakerConfig != null ? 
                circuitBreakerConfig : DEFAULT_WELLKNOWN_CIRCUIT_CONFIG;

        // First create a basic HttpHandler for the URL
        HttpHandler.HttpHandlerBuilder httpBuilder = HttpHandler.builder()
                .url(wellKnownUrl);

        if (sslContext != null) {
            httpBuilder.sslContext(sslContext);
        }

        // Apply timeout configuration from ParserConfig if available
        if (parserConfig != null) {
            httpBuilder.connectionTimeoutSeconds(parserConfig.getWellKnownConnectTimeoutSeconds());
            httpBuilder.readTimeoutSeconds(parserConfig.getWellKnownReadTimeoutSeconds());
        }

        HttpHandler baseHandler = httpBuilder.build();

        // Wrap with resilience patterns
        ResilientHttpHandler resilientHandler = ResilientHttpHandler.wrap(
                baseHandler,
                effectiveRetryConfig,
                effectiveCircuitConfig
        );

        // Build the LazyWellKnownHandler with the resilient handler
        LazyWellKnownHandler.LazyWellKnownHandlerBuilder builder = LazyWellKnownHandler.builder()
                .httpHandler(resilientHandler);

        if (parserConfig != null) {
            builder.parserConfig(parserConfig);
        }

        LazyWellKnownHandler handler = builder.build();

        LOGGER.info("Created resilient WellKnownHandler for URL: %s with retry=%d, circuitBreaker=%d failures",
                wellKnownUrl, effectiveRetryConfig.getMaxAttempts(), effectiveCircuitConfig.getFailureThreshold());

        return handler;
    }

    /**
     * Creates a resilient LazyWellKnownHandler from an existing URL object.
     *
     * @param wellKnownUrl the well-known discovery URL
     * @return a new LazyWellKnownHandler with resilience patterns applied
     */
    public static LazyWellKnownHandler createResilient(@NonNull URL wellKnownUrl) {
        return createResilient(wellKnownUrl.toString());
    }

    /**
     * Wraps an existing HttpHandler with resilience patterns suitable for well-known discovery.
     * <p>
     * This method is useful when you need to apply resilience patterns to an existing
     * HttpHandler before using it for well-known discovery.
     *
     * @param httpHandler the HttpHandler to wrap
     * @return a ResilientHttpHandler with well-known optimized configuration
     */
    public static ResilientHttpHandler wrapWithResilience(@NonNull HttpHandler httpHandler) {
        return wrapWithResilience(httpHandler, null, null);
    }

    /**
     * Wraps an existing HttpHandler with custom resilience patterns.
     *
     * @param httpHandler the HttpHandler to wrap
     * @param retryConfig the retry configuration (may be null for defaults)
     * @param circuitBreakerConfig the circuit breaker configuration (may be null for defaults)
     * @return a ResilientHttpHandler with the specified configuration
     */
    public static ResilientHttpHandler wrapWithResilience(@NonNull HttpHandler httpHandler,
                                                         RetryConfig retryConfig,
                                                         CircuitBreakerConfig circuitBreakerConfig) {
        RetryConfig effectiveRetryConfig = retryConfig != null ? retryConfig : DEFAULT_WELLKNOWN_RETRY_CONFIG;
        CircuitBreakerConfig effectiveCircuitConfig = circuitBreakerConfig != null ? 
                circuitBreakerConfig : DEFAULT_WELLKNOWN_CIRCUIT_CONFIG;

        LOGGER.debug("Wrapping HttpHandler with resilience patterns for URL: %s", httpHandler.getUrl());

        return ResilientHttpHandler.wrap(httpHandler, effectiveRetryConfig, effectiveCircuitConfig);
    }
}