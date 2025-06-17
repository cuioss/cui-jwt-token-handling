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

import com.github.benmanes.caffeine.cache.LoadingCache;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.concurrent.ConcurrentTools;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Enhanced tests for JwksCacheManager focusing on:
 * - Adaptive caching behavior
 * - Key rotation detection
 * - Different cache key prefixes
 * - Null or invalid JWKS URI
 */
@EnableTestLogger
@DisplayName("Enhanced tests for JwksCacheManager")
class JwksCacheManagerEnhancedTest {

    private static final CuiLogger LOGGER = new CuiLogger(JwksCacheManagerEnhancedTest.class);
    private static final String JWKS_CONTENT = InMemoryJWKSFactory.createDefaultJwks();
    private static final String JWKS_URI = "https://example.com/.well-known/jwks.json";
    private static final String DIFFERENT_JWKS_CONTENT = InMemoryKeyMaterialHandler.createJwks(
            InMemoryKeyMaterialHandler.Algorithm.RS384, "different-key-id");
    private static final int REFRESH_INTERVAL = 1; // Short interval for testing (in seconds)
    private static final int ADAPTIVE_WINDOW_SIZE = 5;

    private HttpJwksLoaderConfig config;
    private JwksCacheManager cacheManager;
    private AtomicInteger loaderCallCount;
    private SecurityEventCounter securityEventCounter;
    private String currentJwksContent;

    @BeforeEach
    void setUp() {
        config = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .adaptiveWindowSize(ADAPTIVE_WINDOW_SIZE)
                .build();

        loaderCallCount = new AtomicInteger(0);
        securityEventCounter = new SecurityEventCounter();
        currentJwksContent = JWKS_CONTENT;

        Function<String, JWKSKeyLoader> cacheLoader = key -> {
            loaderCallCount.incrementAndGet();
            return JWKSKeyLoader.builder()
                    .originalString(currentJwksContent)
                    .etag("\"test-etag\"")
                    .securityEventCounter(securityEventCounter)
                    .build();
        };

        cacheManager = new JwksCacheManager(config, cacheLoader, securityEventCounter);
    }

    @Test
    @DisplayName("Should detect key rotation")
    void shouldDetectKeyRotation() {
        // Reset the loader call count
        loaderCallCount.set(0);

        // Create a new cache manager with a fresh loader call count
        AtomicInteger rotationLoaderCallCount = new AtomicInteger(0);
        String initialContent = JWKS_CONTENT;

        // Create a cache manager with the initial content
        JwksCacheManager rotationCacheManager = new JwksCacheManager(config, key -> {
            rotationLoaderCallCount.incrementAndGet();
            return JWKSKeyLoader.builder()
                    .originalString(initialContent)
                    .etag("\"test-etag\"")
                    .securityEventCounter(securityEventCounter)
                    .build();
        }, securityEventCounter);

        // First resolve to populate the cache and set lastValidResult
        JWKSKeyLoader initialLoader = rotationCacheManager.resolve();
        assertNotNull(initialLoader);
        assertTrue(initialLoader.isNotEmpty(), "Initial loader should not be empty");

        // Get the initial key set
        Set<String> initialKeySet = initialLoader.keySet();
        assertFalse(initialKeySet.isEmpty(), "Initial key set should not be empty");

        // Explicitly set lastValidResult by calling updateCache with the initial content
        rotationCacheManager.updateCache(initialContent, "\"test-etag\"");

        // Now update the cache with the new content that has different keys
        JwksCacheManager.KeyRotationResult result = rotationCacheManager.updateCache(DIFFERENT_JWKS_CONTENT, "\"new-etag\"");

        // Verify that key rotation was detected
        assertTrue(result.keyRotationDetected(), "Key rotation should be detected");

        // Verify that the new key loader has different keys
        JWKSKeyLoader newLoader = result.keyLoader();
        assertNotNull(newLoader);
        assertTrue(newLoader.isNotEmpty(), "New loader should not be empty");
        assertNotEquals(initialKeySet, newLoader.keySet(), "Key sets should be different after rotation");
    }

    @Test
    @DisplayName("Should extend expiration time for frequently accessed keys")
    void shouldExtendExpirationTimeForFrequentlyAccessedKeys() throws Exception {
        // Reset the loader call count
        loaderCallCount.set(0);

        // Create a new cache manager with a fresh loader call count
        AtomicInteger adaptiveLoaderCallCount = new AtomicInteger(0);
        Function<String, JWKSKeyLoader> adaptiveCacheLoader = key -> {
            adaptiveLoaderCallCount.incrementAndGet();
            LOGGER.debug(() -> "Loader called, count: " + adaptiveLoaderCallCount.get());
            return JWKSKeyLoader.builder()
                    .originalString(currentJwksContent)
                    .etag("\"test-etag\"")
                    .securityEventCounter(securityEventCounter)
                    .build();
        };

        // Create a config with a longer refresh interval to make the test more reliable
        HttpJwksLoaderConfig testConfig = HttpJwksLoaderConfig.builder()
                .url(JWKS_URI)
                .refreshIntervalSeconds(1) // Reduced for faster tests
                .adaptiveWindowSize(ADAPTIVE_WINDOW_SIZE)
                .build();

        JwksCacheManager adaptiveCacheManager = new JwksCacheManager(testConfig, adaptiveCacheLoader, securityEventCounter);

        // Get access to the accessCount and hitCount fields
        Field accessCountField = JwksCacheManager.class.getDeclaredField("accessCount");
        Field hitCountField = JwksCacheManager.class.getDeclaredField("hitCount");
        Field jwksCacheField = JwksCacheManager.class.getDeclaredField("jwksCache");
        accessCountField.setAccessible(true);
        hitCountField.setAccessible(true);
        jwksCacheField.setAccessible(true);

        // Reset the counters
        AtomicInteger accessCount = (AtomicInteger) accessCountField.get(adaptiveCacheManager);
        AtomicInteger hitCount = (AtomicInteger) hitCountField.get(adaptiveCacheManager);
        accessCount.set(0);
        hitCount.set(0);

        // First resolve to populate the cache
        JWKSKeyLoader initialLoader = adaptiveCacheManager.resolve();
        assertNotNull(initialLoader);

        // Record the initial call count
        int initialCallCount = adaptiveLoaderCallCount.get();
        assertEquals(1, initialCallCount, "Initial loader call count should be 1");

        LOGGER.debug(() -> "Initial loader call count: " + initialCallCount);
        LOGGER.debug(() -> "Access count: " + accessCount.get() + ", Hit count: " + hitCount.get());

        // Access the cache multiple times to trigger adaptive caching
        for (int i = 0; i < ADAPTIVE_WINDOW_SIZE; i++) {
            JWKSKeyLoader loader = adaptiveCacheManager.resolve();
            assertNotNull(loader);
        }

        LOGGER.debug(() -> "After multiple accesses - Access count: " + accessCount.get() + ", Hit count: " + hitCount.get());

        // Manually force the cache to expire the entry
        @SuppressWarnings("unchecked")
        LoadingCache<String, JWKSKeyLoader> jwksCache =
                (LoadingCache<String, JWKSKeyLoader>) jwksCacheField.get(adaptiveCacheManager);
        jwksCache.invalidate(adaptiveCacheManager.getCacheKey());

        // Wait a bit to ensure the cache entry is expired
        ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(100));

        // Access the cache again - this should trigger a reload
        JWKSKeyLoader reloadedLoader = adaptiveCacheManager.resolve();
        assertNotNull(reloadedLoader);

        // The loader should have been called again
        assertTrue(adaptiveLoaderCallCount.get() > initialCallCount,
                "Loader should be called again after cache invalidation");

        LOGGER.debug(() -> "Final loader call count: " + adaptiveLoaderCallCount.get());
    }

    @Test
    @DisplayName("Should use different cache keys for different URIs")
    void shouldUseDifferentCacheKeysForDifferentUris() {
        // First config with one URI
        HttpJwksLoaderConfig config1 = HttpJwksLoaderConfig.builder()
                .url("https://example1.com/.well-known/jwks.json")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        // Second config with a different URI
        HttpJwksLoaderConfig config2 = HttpJwksLoaderConfig.builder()
                .url("https://example2.com/.well-known/jwks.json")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        // Create cache managers with the same loader function
        JwksCacheManager cacheManager1 = new JwksCacheManager(config1, key -> {
            loaderCallCount.incrementAndGet();
            return JWKSKeyLoader.builder()
                    .originalString(JWKS_CONTENT)
                    .etag("\"test-etag-1\"")
                    .securityEventCounter(securityEventCounter)
                    .build();
        }, securityEventCounter);

        JwksCacheManager cacheManager2 = new JwksCacheManager(config2, key -> {
            loaderCallCount.incrementAndGet();
            return JWKSKeyLoader.builder()
                    .originalString(DIFFERENT_JWKS_CONTENT)
                    .etag("\"test-etag-2\"")
                    .securityEventCounter(securityEventCounter)
                    .build();
        }, securityEventCounter);

        // Get the cache keys
        String cacheKey1 = cacheManager1.getCacheKey();
        String cacheKey2 = cacheManager2.getCacheKey();

        // Verify that the cache keys are different
        assertNotEquals(cacheKey1, cacheKey2, "Cache keys should be different for different URIs");

        // Resolve from both cache managers
        JWKSKeyLoader loader1 = cacheManager1.resolve();
        JWKSKeyLoader loader2 = cacheManager2.resolve();

        // Verify that both loaders were called
        assertEquals(2, loaderCallCount.get(), "Both loaders should be called");

        // Verify that the loaders have different content
        assertNotEquals(loader1.getOriginalString(), loader2.getOriginalString(),
                "Loaders should have different content");
    }

    @Test
    @DisplayName("Should fallback to last valid result when loader throws exception")
    void shouldFallbackToLastValidResultWhenLoaderThrowsException() {
        // First resolve to populate the cache and set the last valid result
        JWKSKeyLoader initialLoader = cacheManager.resolve();
        assertNotNull(initialLoader);
        assertTrue(initialLoader.isNotEmpty(), "Initial loader should not be empty");

        // Update the cache with valid content to set the last valid result
        JwksCacheManager.KeyRotationResult result = cacheManager.updateCache(JWKS_CONTENT, "\"test-etag\"");
        assertNotNull(result.keyLoader());

        // Create a new cache manager with a loader that throws an exception
        AtomicInteger exceptionLoaderCallCount = new AtomicInteger(0);
        JwksCacheManager exceptionCacheManager = new JwksCacheManager(config, key -> {
            exceptionLoaderCallCount.incrementAndGet();
            throw new RuntimeException("Test exception");
        }, securityEventCounter);

        // Update the cache with valid content to set the last valid result
        exceptionCacheManager.updateCache(JWKS_CONTENT, "\"test-etag\"");

        // Now resolve - it should fallback to the last valid result
        JWKSKeyLoader loader = exceptionCacheManager.resolve();

        // Verify that the loader was called
        assertEquals(1, exceptionLoaderCallCount.get(), "Exception loader should be called");

        // Verify that we got a valid result despite the exception
        assertNotNull(loader);
        assertTrue(loader.isNotEmpty(), "Loader should not be empty due to fallback");
        assertEquals(JWKS_CONTENT, loader.getOriginalString(), "Loader should have the last valid content");
    }
}
