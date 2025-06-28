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

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RetryUtilTest {

    @Test
    void testSuccessfulOperation() {
        String result = RetryUtil.executeWithRetry(() -> "success", "test operation");
        assertEquals("success", result);
    }

    @Test
    void testRetryOnFailure() {
        AtomicInteger attempts = new AtomicInteger(0);
        
        String result = RetryUtil.executeWithRetry(() -> {
            int attempt = attempts.incrementAndGet();
            if (attempt < 3) {
                throw new RuntimeException("Simulated failure " + attempt);
            }
            return "success on attempt " + attempt;
        }, 3, Duration.ofMillis(10), "test retry");
        
        assertEquals("success on attempt 3", result);
        assertEquals(3, attempts.get());
    }

    @Test
    void testRetryExhaustion() {
        AtomicInteger attempts = new AtomicInteger(0);
        
        RuntimeException exception = assertThrows(RuntimeException.class, () ->
            RetryUtil.executeWithRetry(() -> {
                attempts.incrementAndGet();
                throw new RuntimeException("Always fails");
            }, 2, Duration.ofMillis(1), "failing operation")
        );
        
        assertTrue(exception.getMessage().contains("Operation failed after 2 attempts"));
        assertEquals(2, attempts.get());
    }

    @Test
    void testDefaultRetrySettings() {
        AtomicInteger attempts = new AtomicInteger(0);
        
        String result = RetryUtil.executeWithRetry(() -> {
            int attempt = attempts.incrementAndGet();
            if (attempt < 2) {
                throw new RuntimeException("Fail once");
            }
            return "success";
        }, "default retry test");
        
        assertEquals("success", result);
        assertEquals(2, attempts.get());
    }
}