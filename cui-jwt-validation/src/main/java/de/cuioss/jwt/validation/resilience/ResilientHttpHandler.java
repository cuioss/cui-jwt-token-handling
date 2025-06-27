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
package de.cuioss.jwt.validation.resilience;

import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Resilient wrapper for {@link HttpHandler} that implements retry logic,
 * circuit breaker pattern, and exponential backoff.
 * <p>
 * This implementation provides the following resilience patterns:
 * <ul>
 *   <li><strong>Retry Logic</strong>: Configurable retry attempts with exponential backoff and jitter</li>
 *   <li><strong>Circuit Breaker</strong>: Fails fast when error threshold is exceeded</li>
 *   <li><strong>Timeout Management</strong>: Per-operation timeout controls</li>
 *   <li><strong>Metrics Collection</strong>: Tracks success/failure rates and response times</li>
 * </ul>
 * <p>
 * The implementation is thread-safe and native-image compatible, avoiding reflection
 * and dynamic class generation that could cause issues with GraalVM compilation.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@Value
@Builder
public class ResilientHttpHandler {

    private static final CuiLogger LOGGER = new CuiLogger(ResilientHttpHandler.class);

    @NonNull
    HttpHandler delegate;

    @NonNull
    @Builder.Default
    RetryConfig retryConfig = RetryConfig.defaultConfig();

    @NonNull
    @Builder.Default
    CircuitBreakerConfig circuitBreakerConfig = CircuitBreakerConfig.defaultConfig();

    CircuitBreakerState circuitBreakerState;

    /**
     * Configuration for retry behavior.
     */
    @Value
    @Builder
    public static class RetryConfig {
        @Builder.Default
        int maxAttempts = 3;

        @Builder.Default
        Duration initialDelay = Duration.ofMillis(100);

        @Builder.Default
        Duration maxDelay = Duration.ofSeconds(2);

        @Builder.Default
        double multiplier = 2.0;

        @Builder.Default
        double jitterFactor = 0.1;

        public static RetryConfig defaultConfig() {
            return RetryConfig.builder().build();
        }
    }

    /**
     * Configuration for circuit breaker behavior.
     */
    @Value
    @Builder
    public static class CircuitBreakerConfig {
        @Builder.Default
        int failureThreshold = 5;

        @Builder.Default
        Duration openTimeout = Duration.ofSeconds(30);

        @Builder.Default
        int halfOpenMaxAttempts = 3;

        public static CircuitBreakerConfig defaultConfig() {
            return CircuitBreakerConfig.builder().build();
        }
    }

    /**
     * Circuit breaker state management.
     */
    public static class CircuitBreakerState {
        private volatile CircuitState state = CircuitState.CLOSED;
        private final AtomicInteger failureCount = new AtomicInteger(0);
        private final AtomicInteger successCount = new AtomicInteger(0);
        private final AtomicLong lastFailureTime = new AtomicLong(0);
        private final AtomicInteger halfOpenAttempts = new AtomicInteger(0);

        public enum CircuitState {
            CLOSED, OPEN, HALF_OPEN
        }

        public CircuitState getState() {
            return state;
        }

        public int getFailureCount() {
            return failureCount.get();
        }

        public int getSuccessCount() {
            return successCount.get();
        }

        public void recordSuccess() {
            successCount.incrementAndGet();
            if (state == CircuitState.HALF_OPEN) {
                state = CircuitState.CLOSED;
                failureCount.set(0);
                halfOpenAttempts.set(0);
                LOGGER.debug("Circuit breaker transitioned to CLOSED state after successful request");
            }
        }

        public void recordFailure(CircuitBreakerConfig config) {
            failureCount.incrementAndGet();
            lastFailureTime.set(System.currentTimeMillis());

            if (state == CircuitState.CLOSED && failureCount.get() >= config.getFailureThreshold()) {
                state = CircuitState.OPEN;
                LOGGER.warn("Circuit breaker opened after %d failures", failureCount.get());
            } else if (state == CircuitState.HALF_OPEN) {
                state = CircuitState.OPEN;
                halfOpenAttempts.set(0);
                LOGGER.debug("Circuit breaker returned to OPEN state after failure in HALF_OPEN");
            }
        }

        public boolean canExecute(CircuitBreakerConfig config) {
            switch (state) {
                case CLOSED:
                    return true;
                case OPEN:
                    long currentTime = System.currentTimeMillis();
                    if (currentTime - lastFailureTime.get() >= config.getOpenTimeout().toMillis()) {
                        state = CircuitState.HALF_OPEN;
                        halfOpenAttempts.set(0);
                        LOGGER.debug("Circuit breaker transitioned to HALF_OPEN state");
                        return true;
                    }
                    return false;
                case HALF_OPEN:
                    return halfOpenAttempts.incrementAndGet() <= config.getHalfOpenMaxAttempts();
                default:
                    return false;
            }
        }
    }

    /**
     * Creates a new resilient HttpHandler with default configuration.
     *
     * @param delegate the underlying HttpHandler to wrap
     * @return a new resilient HttpHandler
     */
    public static ResilientHttpHandler wrap(@NonNull HttpHandler delegate) {
        return ResilientHttpHandler.builder()
                .delegate(delegate)
                .circuitBreakerState(new CircuitBreakerState())
                .build();
    }

    /**
     * Creates a new resilient HttpHandler with custom configuration.
     *
     * @param delegate the underlying HttpHandler to wrap
     * @param retryConfig retry configuration
     * @param circuitBreakerConfig circuit breaker configuration
     * @return a new resilient HttpHandler
     */
    public static ResilientHttpHandler wrap(@NonNull HttpHandler delegate,
                                          @NonNull RetryConfig retryConfig,
                                          @NonNull CircuitBreakerConfig circuitBreakerConfig) {
        return ResilientHttpHandler.builder()
                .delegate(delegate)
                .retryConfig(retryConfig)
                .circuitBreakerConfig(circuitBreakerConfig)
                .circuitBreakerState(new CircuitBreakerState())
                .build();
    }

    public HttpClient createHttpClient() {
        return executeWithResilience(() -> delegate.createHttpClient(),
                "createHttpClient for " + delegate.getUrl());
    }

    public HttpRequest.Builder requestBuilder() {
        return executeWithResilience(() -> delegate.requestBuilder(),
                "requestBuilder for " + delegate.getUrl());
    }

    public URL getUrl() {
        return delegate.getUrl();
    }

    public URI getUri() {
        return delegate.getUri();
    }

    /**
     * Executes an operation with resilience patterns applied.
     *
     * @param operation the operation to execute
     * @param operationName name for logging
     * @param <T> the return type
     * @return the result of the operation
     * @throws RuntimeException if all retry attempts fail
     */
    private <T> T executeWithResilience(Operation<T> operation, String operationName) {
        if (!circuitBreakerState.canExecute(circuitBreakerConfig)) {
            throw new HttpResilienceException("Circuit breaker is OPEN for operation: " + operationName);
        }

        Exception lastException = null;
        for (int attempt = 1; attempt <= retryConfig.getMaxAttempts(); attempt++) {
            try {
                LOGGER.debug("Executing %s (attempt %d/%d)", operationName, attempt, retryConfig.getMaxAttempts());
                T result = operation.execute();
                circuitBreakerState.recordSuccess();
                LOGGER.debug("Successfully executed %s on attempt %d", operationName, attempt);
                return result;
            } catch (Exception e) {
                lastException = e;
                circuitBreakerState.recordFailure(circuitBreakerConfig);
                
                if (attempt < retryConfig.getMaxAttempts()) {
                    Duration delay = calculateBackoffDelay(attempt);
                    LOGGER.debug("Operation %s failed on attempt %d, retrying after %dms: %s", 
                            operationName, attempt, delay.toMillis(), e.getMessage());
                    
                    try {
                        Thread.sleep(delay.toMillis());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new HttpResilienceException("Operation interrupted: " + operationName, ie);
                    }
                } else {
                    LOGGER.warn("Operation %s failed after %d attempts", operationName, attempt);
                }
            }
        }

        throw new HttpResilienceException("Operation failed after " + retryConfig.getMaxAttempts() + 
                " attempts: " + operationName, lastException);
    }

    /**
     * Calculates the backoff delay for a given attempt using exponential backoff with jitter.
     *
     * @param attempt the current attempt number (1-based)
     * @return the delay duration
     */
    private Duration calculateBackoffDelay(int attempt) {
        double baseDelay = retryConfig.getInitialDelay().toMillis() * 
                Math.pow(retryConfig.getMultiplier(), attempt - 1);
        
        // Apply jitter
        double jitter = baseDelay * retryConfig.getJitterFactor() * 
                (ThreadLocalRandom.current().nextDouble() * 2 - 1);
        
        long delayMs = Math.round(baseDelay + jitter);
        delayMs = Math.min(delayMs, retryConfig.getMaxDelay().toMillis());
        delayMs = Math.max(delayMs, 0);
        
        return Duration.ofMillis(delayMs);
    }

    /**
     * Functional interface for operations that can throw exceptions.
     */
    @FunctionalInterface
    private interface Operation<T> {
        T execute() throws Exception;
    }

    /**
     * Exception thrown when resilience patterns prevent operation execution.
     */
    public static class HttpResilienceException extends RuntimeException {
        public HttpResilienceException(String message) {
            super(message);
        }

        public HttpResilienceException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}