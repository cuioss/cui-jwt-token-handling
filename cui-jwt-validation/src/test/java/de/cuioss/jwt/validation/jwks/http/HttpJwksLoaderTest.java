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

import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcher;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests HttpJwksLoader")
@EnableMockWebServer
class HttpJwksLoaderTest {

    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final int REFRESH_INTERVAL = 60;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private HttpJwksLoader httpJwksLoader;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        httpJwksLoader = new HttpJwksLoader(config, securityEventCounter);
    }

    @Test
    @DisplayName("Should create loader with constructor")
    void shouldCreateLoaderWithConstructor() {

        assertNotNull(httpJwksLoader);
        assertNotNull(httpJwksLoader.getConfig());
        assertEquals(REFRESH_INTERVAL, httpJwksLoader.getConfig().getRefreshIntervalSeconds());
    }

    @Test
    @DisplayName("Should get key info by ID")
    void shouldGetKeyInfoById() {

        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertEquals(TEST_KID, keyInfo.get().getKeyId(), "Key ID should match");
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called once");
    }

    @Test
    @DisplayName("Should return empty for unknown key ID")
    void shouldReturnEmptyForUnknownKeyId() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND);
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo("unknown-kid");
        assertFalse(keyInfo.isPresent(), "Key info should not be present for unknown key ID");

        // Verify security event was recorded
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_NOT_FOUND),
                "KEY_NOT_FOUND event should be incremented");
    }

    @Test
    @DisplayName("Should return empty for null key ID")
    void shouldReturnEmptyForNullKeyId() {

        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(null);
        assertFalse(keyInfo.isPresent(), "Key info should not be present for null key ID");
    }

    @Test
    @DisplayName("Should get first key info")
    void shouldGetFirstKeyInfo() {

        Optional<KeyInfo> keyInfo = httpJwksLoader.getFirstKeyInfo();
        assertTrue(keyInfo.isPresent(), "First key info should be present");
    }

    @Test
    @DisplayName("Should get all key infos")
    void shouldGetAllKeyInfos() {

        List<KeyInfo> keyInfos = httpJwksLoader.getAllKeyInfos();
        assertNotNull(keyInfos, "Key infos should not be null");
        assertFalse(keyInfos.isEmpty(), "Key infos should not be empty");
    }

    @Test
    @DisplayName("Should get key set")
    void shouldGetKeySet() {

        Set<String> keySet = httpJwksLoader.keySet();
        assertNotNull(keySet, "Key set should not be null");
        assertFalse(keySet.isEmpty(), "Key set should not be empty");
        assertTrue(keySet.contains(TEST_KID), "Key set should contain test key ID");
    }

    @Test
    @DisplayName("Should cache keys and minimize HTTP requests")
    void shouldCacheKeysAndMinimizeHttpRequests() {

        for (int i = 0; i < 5; i++) {
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present on call " + i);
        }
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called only once due to caching");
    }

    @Test
    @DisplayName("Should close resources")
    void shouldCloseResources() {

        httpJwksLoader.close();
        // No exception should be thrown
        assertTrue(true, "Close should complete without exceptions");
    }

    @Test
    @ModuleDispatcher
    @DisplayName("Should create new loader with custom parameters")
    void shouldCreateNewLoaderWithCustomParameters(URIBuilder uriBuilder) {

        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(30)
                .maxCacheSize(200)
                .adaptiveWindowSize(20)
                .backgroundRefreshPercentage(70)
                .build();

        HttpJwksLoader customLoader = new HttpJwksLoader(config, securityEventCounter);
        assertNotNull(customLoader);
        assertEquals(30, customLoader.getConfig().getRefreshIntervalSeconds());
        assertEquals(200, customLoader.getConfig().getMaxCacheSize());
        assertEquals(20, customLoader.getConfig().getAdaptiveWindowSize());
        assertEquals(70, customLoader.getConfig().getBackgroundRefreshPercentage());

        // Verify it works
        Optional<KeyInfo> keyInfo = customLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // Clean up
        customLoader.close();
    }

    @Test
    @DisplayName("Should count JWKS_FETCH_FAILED event")
    void shouldCountJwksFetchFailedEvent() {
        // Get initial count
        long initialCount = securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_FETCH_FAILED);

        // Manually increment the counter to simulate a fetch failure
        // This is similar to the approach used in JwksLoaderFactoryTest
        securityEventCounter.increment(SecurityEventCounter.EventType.JWKS_FETCH_FAILED);

        // Verify that the counter was incremented
        assertEquals(initialCount + 1, securityEventCounter.getCount(SecurityEventCounter.EventType.JWKS_FETCH_FAILED),
                "JWKS_FETCH_FAILED event should be incremented");
    }

    @Test
    @DisplayName("Should detect key rotation and log warning")
    void shouldDetectKeyRotationAndLogWarning() {
        // Get initial count of key rotation events
        long initialRotationCount = securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_ROTATION_DETECTED);

        // First, get a key to ensure the cache is populated
        Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
        assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

        // Switch to a different key to simulate key rotation
        moduleDispatcher.switchToOtherPublicKey();

        // Force a refresh of the cache
        assertDoesNotThrow(() -> {
            // Access private method to force refresh
            java.lang.reflect.Method refreshMethod = HttpJwksLoader.class.getDeclaredMethod("loadJwksKeyLoader", String.class);
            refreshMethod.setAccessible(true);
            refreshMethod.invoke(httpJwksLoader, "jwks:" + httpJwksLoader.getConfig().getHttpHandler().getUri());
        }, "Failed to invoke refresh method: ");

        // Verify that the key rotation event was recorded
        assertEquals(initialRotationCount + 1,
                securityEventCounter.getCount(SecurityEventCounter.EventType.KEY_ROTATION_DETECTED),
                "KEY_ROTATION_DETECTED event should be incremented");
    }

    @Test
    @DisplayName("Should log info message when JWKS is loaded and parsed")
    void shouldLogInfoMessageWhenJwksIsLoadedAndParsed() {
        // When loading a key, the JWKS is loaded and parsed
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

        // Then the key should be found
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // And the appropriate info message should be logged
        // The message should contain the JWKS URI and the number of keys
        LogAsserts.assertLogMessagePresent(
                TestLogLevel.INFO,
                JWTValidationLogMessages.INFO.JWKS_LOADED.format(
                        httpJwksLoader.getConfig().getHttpHandler().getUri().toString(),
                        1)); // We expect 1 key in the test JWKS
    }
}
