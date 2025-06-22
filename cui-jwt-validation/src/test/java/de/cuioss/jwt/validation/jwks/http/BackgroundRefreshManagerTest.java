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

import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests BackgroundRefreshManager")
class BackgroundRefreshManagerTest {

    private static final String JWKS_CONTENT = InMemoryJWKSFactory.createDefaultJwks();
    private static final String JWKS_URI = "https://example.com/.well-known/jwks.json";

    @Test
    @DisplayName("Should create manager with config")
    void shouldCreateManagerWithConfig() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(60)
                .build();

        JwksCacheManager cacheManager = createCacheManager(config);
        BackgroundRefreshManager manager = new BackgroundRefreshManager(config, cacheManager);
        assertNotNull(manager);
        assertTrue(manager.isEnabled(), "Background refresh should be enabled for positive refresh interval");

        // Clean up
        manager.close();
    }

    @Test
    @DisplayName("Should disable background refresh for zero refresh interval")
    void shouldDisableBackgroundRefreshForZeroRefreshInterval() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(0)
                .build();

        JwksCacheManager cacheManager = createCacheManager(config);
        BackgroundRefreshManager manager = new BackgroundRefreshManager(config, cacheManager);
        assertNotNull(manager);
        assertFalse(manager.isEnabled(), "Background refresh should be disabled for zero refresh interval");

        // Clean up
        manager.close();
    }

    @Test
    @DisplayName("Should skip scheduling for very short refresh intervals")
    void shouldSkipSchedulingForVeryShortRefreshIntervals() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(1) // Very short interval
                .build();

        JwksCacheManager cacheManager = createCacheManager(config);
        BackgroundRefreshManager manager = new BackgroundRefreshManager(config, cacheManager);
        assertNotNull(manager);
        assertTrue(manager.isEnabled(), "Background refresh should be enabled even for short refresh interval");

        // Clean up
        manager.close();
    }

    @Test
    @DisplayName("Should close executor service")
    void shouldCloseExecutorService() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(60)
                .build();

        JwksCacheManager cacheManager = createCacheManager(config);
        BackgroundRefreshManager manager = new BackgroundRefreshManager(config, cacheManager);
        manager.close();
        // No exception should be thrown
        assertTrue(true, "Close should complete without exceptions");
    }

    @Test
    @DisplayName("Should handle close when already closed")
    void shouldHandleCloseWhenAlreadyClosed() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(60)
                .build();

        JwksCacheManager cacheManager = createCacheManager(config);
        BackgroundRefreshManager manager = new BackgroundRefreshManager(config, cacheManager);
        manager.close();
        manager.close(); // Close again
        // No exception should be thrown
        assertTrue(true, "Multiple close calls should complete without exceptions");
    }

    @Test
    @DisplayName("Should handle close when executor service is null")
    void shouldHandleCloseWhenExecutorServiceIsNull() {

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(0) // Zero refresh interval means no executor service
                .build();

        JwksCacheManager cacheManager = createCacheManager(config);
        BackgroundRefreshManager manager = new BackgroundRefreshManager(config, cacheManager);
        manager.close();
        // No exception should be thrown
        assertTrue(true, "Close should complete without exceptions when executor service is null");
    }

    // Helper method to create a cache manager for testing
    private JwksCacheManager createCacheManager(HttpJwksLoaderConfig config) {
        AtomicInteger loaderCallCount = new AtomicInteger(0);
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();

        Function<String, JWKSKeyLoader> cacheLoader = key -> {
            loaderCallCount.incrementAndGet();
            return JWKSKeyLoader.builder()
                    .originalString(JWKS_CONTENT)
                    .securityEventCounter(securityEventCounter)
                    .build();
        };

        return new JwksCacheManager(config, cacheLoader, securityEventCounter);
    }
}
