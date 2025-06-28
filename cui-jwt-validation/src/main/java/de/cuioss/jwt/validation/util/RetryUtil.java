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
package de.cuioss.jwt.validation.util;

import de.cuioss.tools.logging.CuiLogger;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Simple retry utility for HTTP operations.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public final class RetryUtil {
    
    private static final CuiLogger LOGGER = new CuiLogger(RetryUtil.class);
    
    private RetryUtil() {
        // Utility class
    }
    
    /**
     * Executes the given operation with simple retry logic.
     * 
     * @param operation the operation to execute
     * @param maxAttempts maximum number of attempts (default: 3)
     * @param delay delay between retries (default: 100ms)
     * @param operationName name for logging
     * @param <T> return type
     * @return the result of the operation
     * @throws RuntimeException if all attempts fail
     */
    public static <T> T executeWithRetry(Supplier<T> operation, int maxAttempts, Duration delay, String operationName) {
        Exception lastException = null;
        
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                LOGGER.debug("Executing %s (attempt %d/%d)", operationName, attempt, maxAttempts);
                T result = operation.get();
                if (attempt > 1) {
                    LOGGER.info("Successfully executed %s on attempt %d", operationName, attempt);
                }
                return result;
            } catch (Exception e) {
                lastException = e;
                if (attempt < maxAttempts) {
                    LOGGER.debug("Operation %s failed on attempt %d, retrying after %dms: %s", 
                            operationName, attempt, delay.toMillis(), e.getMessage());
                    try {
                        Thread.sleep(delay.toMillis());
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Operation interrupted: " + operationName, ie);
                    }
                } else {
                    LOGGER.warn("Operation %s failed after %d attempts", operationName, attempt);
                }
            }
        }
        
        throw new RuntimeException("Operation failed after " + maxAttempts + " attempts: " + operationName, lastException);
    }
    
    /**
     * Executes with default retry settings (3 attempts, 100ms delay).
     */
    public static <T> T executeWithRetry(Supplier<T> operation, String operationName) {
        return executeWithRetry(operation, 3, Duration.ofMillis(100), operationName);
    }
}