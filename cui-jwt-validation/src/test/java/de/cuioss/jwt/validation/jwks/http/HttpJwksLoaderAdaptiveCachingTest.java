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
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the adaptive caching behavior of HttpJwksLoader.
 * <p>
 * This test class focuses on the adaptive caching mechanism that extends
 * expiration time for frequently accessed keys.
 */
@EnableTestLogger(debug = {HttpJwksLoader.class, JWKSKeyLoader.class, JwksCacheManager.class})
@DisplayName("Tests HttpJwksLoader adaptive caching")
@EnableMockWebServer
class HttpJwksLoaderAdaptiveCachingTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing (in seconds)
    private static final int ADAPTIVE_WINDOW_SIZE = 5; // Small window size for testing

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();
    private HttpJwksLoader httpJwksLoader;
    private JwksCacheManager cacheManager;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .adaptiveWindowSize(ADAPTIVE_WINDOW_SIZE)
                .build();

        httpJwksLoader = new HttpJwksLoader(config, securityEventCounter);

        // Get access to the cacheManager field for testing
        assertDoesNotThrow(() -> {
            Field cacheManagerField = HttpJwksLoader.class.getDeclaredField("cacheManager");
            cacheManagerField.setAccessible(true);
            cacheManager = (JwksCacheManager) cacheManagerField.get(httpJwksLoader);
        }, "Failed to access cacheManager field: ");
    }

    @Test
    @DisplayName("Should track access and hit counts for adaptive caching")
    void shouldTrackAccessAndHitCounts() throws Exception {
        // Get access to the accessCount and hitCount fields
        Field accessCountField = JwksCacheManager.class.getDeclaredField("accessCount");
        Field hitCountField = JwksCacheManager.class.getDeclaredField("hitCount");
        accessCountField.setAccessible(true);
        hitCountField.setAccessible(true);

        // Reset the counters manually since HttpJwksLoader constructor already accessed the cache
        AtomicInteger accessCount = (AtomicInteger) accessCountField.get(cacheManager);
        AtomicInteger hitCount = (AtomicInteger) hitCountField.get(cacheManager);
        accessCount.set(0);
        hitCount.set(0);

        // Verify counters are reset
        assertEquals(0, accessCount.get(), "Initial access count should be zero after reset");
        assertEquals(0, hitCount.get(), "Initial hit count should be zero after reset");

        // First access should increment both counts (since the key is already in cache)
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertEquals(1, accessCount.get(), "Access count should be incremented");
        assertEquals(1, hitCount.get(), "Hit count should be incremented for successful key retrieval");

        // Later accesses should increment both counts
        for (int i = 0; i < 3; i++) {
            keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present");
        }

        assertEquals(4, accessCount.get(), "Access count should be incremented for each access");
        assertEquals(4, hitCount.get(), "Hit count should be incremented for each successful access");

        // After reaching the adaptive window size, counts should be reset
        keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // Since ADAPTIVE_WINDOW_SIZE is 5, and we've made 5 accesses, the counters should be reset
        assertEquals(0, accessCount.get(), "Access count should be reset after reaching adaptive window size");
        assertEquals(0, hitCount.get(), "Hit count should be reset after reaching adaptive window size");
    }

    @Test
    @DisplayName("Should extend expiration time for frequently accessed keys")
    void shouldExtendExpirationTimeForFrequentlyAccessedKeys() throws Exception {
        // Get access to the jwksCache field to manually invalidate the cache
        Field jwksCacheField = JwksCacheManager.class.getDeclaredField("jwksCache");
        jwksCacheField.setAccessible(true);
        @SuppressWarnings("unchecked")
        LoadingCache<String, JWKSKeyLoader> jwksCache =
                (LoadingCache<String, JWKSKeyLoader>) jwksCacheField.get(cacheManager);

        // First access to populate the cache
        Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

        // Manually invalidate the cache to force a refresh
        jwksCache.invalidate(cacheManager.getCacheKey());

        // Reset the call counter to isolate the next server call
        moduleDispatcher.setCallCounter(0);

        // Access the key again - this should trigger a refresh
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // Verify that the server was called
        assertEquals(1, moduleDispatcher.getCallCounter(), "Server should be called after cache invalidation");

        // Reset the call counter again
        moduleDispatcher.setCallCounter(0);

        // Access the key again - it should be cached now
        keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // The server should not have been called again
        assertEquals(0, moduleDispatcher.getCallCounter(), "Server should not be called again due to caching");
    }

    @Test
    @DisplayName("Should reset counters after adaptive window size is reached")
    void shouldResetCountersAfterAdaptiveWindowSizeIsReached() throws Exception {
        // Get access to the accessCount and hitCount fields
        Field accessCountField = JwksCacheManager.class.getDeclaredField("accessCount");
        Field hitCountField = JwksCacheManager.class.getDeclaredField("hitCount");
        accessCountField.setAccessible(true);
        hitCountField.setAccessible(true);

        // Reset the counters manually since HttpJwksLoader constructor already accessed the cache
        AtomicInteger accessCount = (AtomicInteger) accessCountField.get(cacheManager);
        AtomicInteger hitCount = (AtomicInteger) hitCountField.get(cacheManager);
        accessCount.set(0);
        hitCount.set(0);

        // Access the key exactly ADAPTIVE_WINDOW_SIZE times
        for (int i = 0; i < ADAPTIVE_WINDOW_SIZE; i++) {
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present");
        }

        // Get the current counts again
        accessCount = (AtomicInteger) accessCountField.get(cacheManager);
        hitCount = (AtomicInteger) hitCountField.get(cacheManager);

        // Counts should be reset after reaching the adaptive window size
        assertEquals(0, accessCount.get(), "Access count should be reset after reaching adaptive window size");
        assertEquals(0, hitCount.get(), "Hit count should be reset after reaching adaptive window size");
    }
}
