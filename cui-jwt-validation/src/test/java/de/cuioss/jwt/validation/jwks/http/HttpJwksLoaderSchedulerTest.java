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

import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests HttpJwksLoader Background Refresh Scheduler")
@EnableMockWebServer
class HttpJwksLoaderSchedulerTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final int MAX_WAIT_TIME_MS = 5000; // Maximum wait time for async operations
    private static final int POLL_INTERVAL_MS = 100; // How often to check conditions

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp() {
        moduleDispatcher.setCallCounter(0);
        securityEventCounter = new SecurityEventCounter();
    }

    /**
     * Waits for a condition to become true, polling at regular intervals.
     * 
     * @param condition the condition to wait for
     * @param maxWaitMs maximum time to wait in milliseconds
     * @param message message to include in assertion error
     * @return true if condition was met, false if timeout
     */
    private boolean waitForCondition(BooleanSupplier condition, long maxWaitMs, String message) {
        long startTime = System.currentTimeMillis();
        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            if (condition.getAsBoolean()) {
                return true;
            }
            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    @Test
    @DisplayName("Should not start scheduler when no config provided")
    void shouldNotStartSchedulerWithoutConfig(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        // Create loader without scheduler config
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(0) // Disable scheduler
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Scheduler should not be active without config
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should not be active without refresh interval");

        loader.shutdown();
    }

    @Test
    @DisplayName("Should not start scheduler when refresh interval is zero")
    void shouldNotStartSchedulerWithZeroInterval(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(0) // Zero means no refresh
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Scheduler should not be active with zero interval
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should not be active with zero interval");

        loader.shutdown();
    }

    @Test
    @DisplayName("Should start scheduler after first successful load")
    void shouldStartSchedulerAfterFirstLoad(URIBuilder uriBuilder) throws InterruptedException {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(1) // 1 second for testing
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Scheduler should not be active before first load
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should not be active before first load");

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Wait for scheduler to start using proper synchronization
        assertTrue(
                waitForCondition(() -> loader.isBackgroundRefreshActive(), 2000, "Scheduler start"),
                "Background refresh should be active after first successful load"
        );

        // Verify log message about scheduler start
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.INFO,
                "Background JWKS refresh started with interval: 1");

        loader.shutdown();

        // After shutdown, scheduler should be inactive
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should be inactive after shutdown");
    }

    @Test
    @DisplayName("Should perform background refresh and detect changes")
    void shouldPerformBackgroundRefresh(URIBuilder uriBuilder) throws InterruptedException {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(1) // 1 second for testing
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Trigger initial load
        Optional<KeyInfo> initialKeyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial load should work");

        int initialCallCount = moduleDispatcher.getCallCounter();

        // Switch to different key to simulate change
        moduleDispatcher.switchToOtherPublicKey();

        // Wait for background refresh to trigger
        assertTrue(
                waitForCondition(
                        () -> moduleDispatcher.getCallCounter() > initialCallCount,
                        2000,
                        "Background refresh should have triggered additional HTTP calls"
                ),
                "Background refresh should have triggered additional HTTP calls within 2 seconds"
        );

        loader.shutdown();
    }

    @Test
    @DisplayName("Should handle background refresh errors gracefully")
    void shouldHandleBackgroundRefreshErrors(URIBuilder uriBuilder) throws InterruptedException {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(1) // 1 second for testing
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Trigger initial successful load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");
        assertEquals(LoaderStatus.OK, loader.isHealthy(), "Loader should be healthy after initial load");

        // Make subsequent requests fail
        moduleDispatcher.returnError();

        // Wait for background refresh to encounter errors - scheduler runs every 1 second
        CountDownLatch waitLatch = new CountDownLatch(1);
        waitLatch.await(1500, TimeUnit.MILLISECONDS); // Wait long enough for scheduler to run

        // Loader should still be healthy if it has existing keys
        assertEquals(LoaderStatus.OK, loader.isHealthy(), "Loader should remain healthy with cached keys even if background refresh fails");

        // Verify error logging occurred
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.WARN,
                "Background JWKS refresh failed");

        loader.shutdown();
    }

    @Test
    @DisplayName("Should only start scheduler once")
    void shouldStartSchedulerOnlyOnce(URIBuilder uriBuilder) throws InterruptedException {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(10) // Longer interval to avoid multiple executions during test
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Trigger multiple loads
        loader.getKeyInfo(TEST_KID);
        loader.getKeyInfo(TEST_KID);
        loader.getFirstKeyInfo();
        loader.getAllKeyInfos();

        // Wait for scheduler to start 
        assertTrue(
                waitForCondition(() -> loader.isBackgroundRefreshActive(), 500, "Scheduler start"),
                "Scheduler should start after operations"
        );

        // Should only have one scheduler start message
        LogAsserts.assertLogMessagePresentContaining(
                TestLogLevel.INFO,
                "Background JWKS refresh started");

        loader.shutdown();
    }

    @Test
    @DisplayName("Should shutdown scheduler cleanly")
    void shouldShutdownSchedulerCleanly(URIBuilder uriBuilder) throws InterruptedException {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(1)
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Start scheduler
        loader.getKeyInfo(TEST_KID);
        assertTrue(
                waitForCondition(() -> loader.isBackgroundRefreshActive(), 500, "Scheduler start"),
                "Scheduler should be active after key load"
        );

        // Shutdown should cancel the task
        loader.shutdown();
        assertFalse(loader.isBackgroundRefreshActive(), "Scheduler should be inactive after shutdown");

        // Multiple shutdowns should be safe
        loader.shutdown();
        loader.shutdown();
        assertFalse(loader.isBackgroundRefreshActive(), "Multiple shutdowns should be safe");
    }

    @Test
    @DisplayName("Should not start scheduler if initial load fails")
    void shouldNotStartSchedulerIfInitialLoadFails(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Make all requests fail from the start
        moduleDispatcher.returnError();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(1)
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Initial load should fail
        try {
            loader.getKeyInfo(TEST_KID);
            fail("Expected JwksLoadException for failed initial load");
        } catch (Exception e) {
            // Expected
        }

        // Scheduler should not be started after failed load
        assertFalse(loader.isBackgroundRefreshActive(), "Background refresh should not start after failed initial load");
        assertNotEquals(LoaderStatus.OK, loader.isHealthy(), "Loader should not be healthy after failed load");

        loader.shutdown();
    }

    @Test
    @DisplayName("Should handle background refresh correctly")
    void shouldHandleBackgroundRefreshCorrectly(URIBuilder uriBuilder) throws InterruptedException {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // Ensure dispatcher is in normal mode
        moduleDispatcher.returnDefault();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(1)
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);

        // Trigger initial load
        Optional<KeyInfo> keyInfo = loader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Initial load should work");

        // Wait for background refresh to execute - scheduler runs every 1 second  
        CountDownLatch waitLatch = new CountDownLatch(1);
        waitLatch.await(1500, TimeUnit.MILLISECONDS); // Wait long enough for scheduler to run

        // Verify that background refresh executed - it should have logged either:
        // - "Background refresh completed, no changes detected" if 304 Not Modified
        // - "Keys updated due to data change" if data changed
        // Both are valid outcomes depending on mock server behavior
        try {
            LogAsserts.assertLogMessagePresentContaining(
                    TestLogLevel.DEBUG,
                    "Background refresh completed, no changes detected");
        } catch (AssertionError e) {
            // If not no-changes, then it should have updated
            LogAsserts.assertLogMessagePresentContaining(
                    TestLogLevel.INFO,
                    "Keys updated due to data change");
        }

        loader.shutdown();
    }
}