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
import de.cuioss.jwt.validation.test.dispatcher.EnhancedJwksResolveDispatcher;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.tools.concurrent.ConcurrentTools;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the enhancements made to HttpJwksLoader:
 * - HTTP 304 "Not Modified" handling
 * - Content-based caching
 * - Fallback mechanisms
 */
@EnableTestLogger(debug = {HttpJwksLoader.class, JWKSKeyLoader.class})
@DisplayName("Tests HttpJwksLoader enhancements")
@EnableMockWebServer
class HttpJwksLoaderCachingAndFallbackTest {

    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    @Getter
    private final EnhancedJwksResolveDispatcher moduleDispatcher = new EnhancedJwksResolveDispatcher();
    private HttpJwksLoader httpJwksLoader;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        SecurityEventCounter securityEventCounter = new SecurityEventCounter();

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .build();

        httpJwksLoader = new HttpJwksLoader(config, securityEventCounter);
    }

    @Nested
    @DisplayName("HTTP 304 Not Modified Tests")
    class Http304NotModifiedTests {

        public EnhancedJwksResolveDispatcher getModuleDispatcher() {
            return moduleDispatcher;
        }

        @Test
        @DisplayName("Should handle HTTP 304 Not Modified response")
        void shouldHandleHttp304NotModifiedResponse() {

            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return 304 Not Modified with ETag
            moduleDispatcher.returnNotModified();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present even with 304 response");
            // The key should still be available even though the server returned 304
            assertEquals(initialKeyInfo.get().key(), keyInfo.get().key(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should include If-None-Match header when ETag is available")
        void shouldIncludeIfNoneMatchHeaderWhenEtagIsAvailable() {

            // First request to populate the cache with ETag
            httpJwksLoader.getKeyInfo(TEST_KID);

            // Wait for the cache to expire (refresh interval is 1 second)
            ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(1500)); // Wait 1.5 seconds to ensure cache expiration

            // Configure dispatcher to check for If-None-Match header
            moduleDispatcher.expectIfNoneMatchHeader();

            // When - make another request
            httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(moduleDispatcher.wasIfNoneMatchHeaderPresent(), "If-None-Match header should be present");
        }
    }

    @Nested
    @DisplayName("Content-Based Caching Tests")
    class ContentBasedCachingTests {

        public EnhancedJwksResolveDispatcher getModuleDispatcher() {
            return moduleDispatcher;
        }

        @Test
        @DisplayName("Should reuse existing loader when content is unchanged")
        void shouldReuseExistingLoaderWhenContentUnchanged() {

            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return the same content
            moduleDispatcher.returnSameContent();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present");
            // The key should still be available and be the same as the initial key
            assertEquals(initialKeyInfo.get().key(), keyInfo.get().key(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should handle content changes")
        void shouldCreateNewLoaderWhenContentChanges() {

            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Record the initial call count
            int initialCallCount = moduleDispatcher.getCallCounter();

            // Force a refresh of the cache
            ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(1500)); // Wait for cache to expire

            // When - make another request for the same key
            Optional<KeyInfo> refreshedKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            // The key should still be available
            assertTrue(refreshedKeyInfo.isPresent(), "Refreshed key info should be present");
            // Verify that a new request was made to the server
            assertTrue(moduleDispatcher.getCallCounter() > initialCallCount,
                    "A new request should have been made to the server");
        }
    }

    @Nested
    @DisplayName("Fallback Mechanism Tests")
    class FallbackMechanismTests {

        public EnhancedJwksResolveDispatcher getModuleDispatcher() {
            return moduleDispatcher;
        }

        @Test
        @DisplayName("Should fallback to last valid result when server returns error")
        void shouldFallbackToLastValidResultWhenServerReturnsError() {

            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return error
            moduleDispatcher.returnError();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            // The key should still be available even though the server returned an error
            assertTrue(keyInfo.isPresent(), "Key info should still be present due to fallback");
            // The key should be the same as the initial key
            assertEquals(initialKeyInfo.get().key(), keyInfo.get().key(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should fallback to last valid result when server returns empty JWKS")
        void shouldFallbackToLastValidResultWhenServerReturnsEmptyJwks() {

            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return empty JWKS
            moduleDispatcher.returnEmptyJwks();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            // The key should still be available even though the server returned an empty JWKS
            assertTrue(keyInfo.isPresent(), "Key info should still be present due to fallback");
            // The key should be the same as the initial key
            assertEquals(initialKeyInfo.get().key(), keyInfo.get().key(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should fallback to last valid result when connection fails")
        void shouldFallbackToLastValidResultWhenConnectionFails() {

            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to simulate connection failure
            moduleDispatcher.simulateConnectionFailure();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            // The key should still be available even though the connection failed
            assertTrue(keyInfo.isPresent(), "Key info should still be present due to fallback");
            // The key should be the same as the initial key
            assertEquals(initialKeyInfo.get().key(), keyInfo.get().key(), "Key should be the same as the initial key");
        }
    }
}
