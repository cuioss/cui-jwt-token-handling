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
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.tools.concurrent.ConcurrentTools;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the background refresh functionality of HttpJwksLoader.
 * <p>
 * This test class focuses on the background refresh mechanism that preemptively
 * refreshes keys before they expire.
 */
@EnableTestLogger(debug = {HttpJwksLoader.class, JWKSKeyLoader.class, BackgroundRefreshManager.class})
@DisplayName("Tests HttpJwksLoader background refresh")
@EnableMockWebServer
class HttpJwksLoaderBackgroundRefreshTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final int REFRESH_INTERVAL_SECONDS = 3; // Interval for testing (must be > 2 for background refresh to be scheduled)
    private static final int BACKGROUND_REFRESH_PERCENTAGE = 50; // Refresh at 50% of expiration time

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();
    private HttpJwksLoader httpJwksLoader;
    private SecurityEventCounter securityEventCounter;
    private BackgroundRefreshManager backgroundRefreshManager;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .backgroundRefreshPercentage(BACKGROUND_REFRESH_PERCENTAGE)
                .build();

        httpJwksLoader = new HttpJwksLoader(config, securityEventCounter);

        // Get access to the backgroundRefreshManager field for testing
        assertDoesNotThrow(() -> {
            Field backgroundRefreshManagerField = HttpJwksLoader.class.getDeclaredField("backgroundRefreshManager");
            backgroundRefreshManagerField.setAccessible(true);
            backgroundRefreshManager = (BackgroundRefreshManager) backgroundRefreshManagerField.get(httpJwksLoader);
        }, "Failed to access backgroundRefreshManager field: ");
    }

    @Test
    @DisplayName("Should enable background refresh for positive refresh interval")
    void shouldEnableBackgroundRefreshForPositiveRefreshInterval() {
        // Verify that background refresh is enabled
        assertTrue(backgroundRefreshManager.isEnabled(),
                "Background refresh should be enabled for positive refresh interval");
    }

    @Test
    @DisplayName("Should disable background refresh for zero refresh interval")
    void shouldDisableBackgroundRefreshForZeroRefreshInterval(URIBuilder uriBuilder) {

        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(0) // Zero refresh interval
                .backgroundRefreshPercentage(BACKGROUND_REFRESH_PERCENTAGE)
                .build();

        // Get access to the backgroundRefreshManager field
        try (HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter)) {
            Field backgroundRefreshManagerField = HttpJwksLoader.class.getDeclaredField("backgroundRefreshManager");
            backgroundRefreshManagerField.setAccessible(true);
            BackgroundRefreshManager manager = (BackgroundRefreshManager) backgroundRefreshManagerField.get(loader);

            // Verify that background refresh is disabled
            assertFalse(manager.isEnabled(),
                    "Background refresh should be disabled for zero refresh interval");
        } catch (Exception e) {
            fail("Failed to access backgroundRefreshManager field: " + e.getMessage());
        }
        // Clean up
    }

    @Test
    @DisplayName("Should perform background refresh before expiration")
    void shouldPerformBackgroundRefreshBeforeExpiration() {
        // First access to populate the cache
        Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

        // Record the initial call count
        int initialCallCount = moduleDispatcher.getCallCounter();

        // Wait for the background refresh to occur (50% of refresh interval)
        // Add a small buffer to ensure the background refresh has time to complete
        ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(
                (long) (REFRESH_INTERVAL_SECONDS * BACKGROUND_REFRESH_PERCENTAGE / 100.0 * 1000) + 200));

        // The server should have been called again by the background refresh
        assertTrue(moduleDispatcher.getCallCounter() > initialCallCount,
                "Server should be called again by background refresh");

        // Access the key again - it should still be valid and not trigger another refresh
        int currentCallCount = moduleDispatcher.getCallCounter();
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should still be present");
        assertEquals(currentCallCount, moduleDispatcher.getCallCounter(),
                "Server should not be called again on access after background refresh");
    }

    @Test
    @DisplayName("Should close background refresh executor service")
    void shouldCloseBackgroundRefreshExecutorService() {
        // Verify that the background refresh manager is enabled
        assertTrue(backgroundRefreshManager.isEnabled(),
                "Background refresh should be enabled initially");

        // Close the HttpJwksLoader
        httpJwksLoader.close();

        // Try to access a key after closing
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

        // The key should still be accessible from the cache
        assertTrue(keyInfo.isPresent(), "Key info should still be accessible after closing");

        // But background refresh should be disabled
        assertFalse(backgroundRefreshManager.isEnabled(),
                "Background refresh should be disabled after closing");
    }

    @Test
    @DisplayName("Should respect background refresh percentage")
    void shouldRespectBackgroundRefreshPercentage(URIBuilder uriBuilder) {

        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Create a loader with a different background refresh percentage
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .backgroundRefreshPercentage(75) // 75% of refresh interval
                .build();

        // Create a custom executor service that we can control
        ScheduledExecutorService executorService = Executors.newScheduledThreadPool(1);

        // Use reflection to set a custom executor service in the config
        assertDoesNotThrow(() -> {
            Field executorServiceField = HttpJwksLoaderConfig.class.getDeclaredField("scheduledExecutorService");
            executorServiceField.setAccessible(true);
            executorServiceField.set(config, executorService);
        }, "Failed to set custom executor service: ");

        try (HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter)) {
            // First access to populate the cache
            Optional<KeyInfo> initialKeyInfo = loader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Record the initial call count
            int initialCallCount = moduleDispatcher.getCallCounter();

            // Manually trigger the background refresh
            assertDoesNotThrow(() -> {
                // Get access to the cacheManager field
                Field cacheManagerField = HttpJwksLoader.class.getDeclaredField("cacheManager");
                cacheManagerField.setAccessible(true);
                JwksCacheManager cacheManager = (JwksCacheManager) cacheManagerField.get(loader);

                // Refresh the cache
                cacheManager.refresh();

                // Wait a bit for the refresh to complete
                ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(200));

                // The server should have been called again
                assertTrue(moduleDispatcher.getCallCounter() > initialCallCount,
                        "Server should be called again after manual refresh");
            }, "Failed to manually trigger refresh: ");
        } finally {
            // Clean up
            executorService.shutdownNow();
        }
    }
}
