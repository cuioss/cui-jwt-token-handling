/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.jwks;

import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.dispatcher.EnhancedJwksResolveDispatcher;
import de.cuioss.jwt.token.test.dispatcher.JwksResolveDispatcher;
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

import static org.junit.jupiter.api.Assertions.*;

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
    private static final String TEST_KID = JWKSFactory.DEFAULT_KEY_ID;
    @Getter
    private final EnhancedJwksResolveDispatcher moduleDispatcher = new EnhancedJwksResolveDispatcher();
    private HttpJwksLoader httpJwksLoader;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);
        httpJwksLoader = HttpJwksLoader.builder()
                .withJwksUrl(jwksEndpoint)
                .withRefreshInterval(REFRESH_INTERVAL_SECONDS)
                .build();
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
            // Given
            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return 304 Not Modified with ETag
            moduleDispatcher.returnNotModified();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

            // Then
            assertTrue(keyInfo.isPresent(), "Key info should be present even with 304 response");
            // The key should still be available even though the server returned 304
            assertEquals(initialKeyInfo.get().getKey(), keyInfo.get().getKey(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should include If-None-Match header when ETag is available")
        void shouldIncludeIfNoneMatchHeaderWhenEtagIsAvailable() {
            // Given
            // First request to populate the cache with ETag
            httpJwksLoader.getKeyInfo(TEST_KID);

            // Wait for the cache to expire (refresh interval is 1 second)
            ConcurrentTools.sleepUninterruptedly(Duration.ofMillis(1500)); // Wait 1.5 seconds to ensure cache expiration

            // Configure dispatcher to check for If-None-Match header
            moduleDispatcher.expectIfNoneMatchHeader();

            // When - make another request
            httpJwksLoader.getKeyInfo(TEST_KID);

            // Then
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
            // Given
            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return the same content
            moduleDispatcher.returnSameContent();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

            // Then
            assertTrue(keyInfo.isPresent(), "Key info should be present");
            // The key should still be available and be the same as the initial key
            assertEquals(initialKeyInfo.get().getKey(), keyInfo.get().getKey(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should create new loader when content changes")
        void shouldCreateNewLoaderWhenContentChanges() {
            // Given
            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return different content with new key ID
            String newKeyId = "new-key-id";
            moduleDispatcher.returnDifferentContent(newKeyId);

            // When - make another request for the new key
            Optional<KeyInfo> newKeyInfo = httpJwksLoader.getKeyInfo(newKeyId);

            // Then
            // The new key should be available
            assertTrue(newKeyInfo.isPresent(), "New key info should be present");
            // Verify that the keys are different
            assertNotEquals(initialKeyInfo.get().getKey(), newKeyInfo.get().getKey(), "New key should be different from the initial key");
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
            // Given
            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return error
            moduleDispatcher.returnError();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

            // Then
            // The key should still be available even though the server returned an error
            assertTrue(keyInfo.isPresent(), "Key info should still be present due to fallback");
            // The key should be the same as the initial key
            assertEquals(initialKeyInfo.get().getKey(), keyInfo.get().getKey(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should fallback to last valid result when server returns empty JWKS")
        void shouldFallbackToLastValidResultWhenServerReturnsEmptyJwks() {
            // Given
            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to return empty JWKS
            moduleDispatcher.returnEmptyJwks();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

            // Then
            // The key should still be available even though the server returned an empty JWKS
            assertTrue(keyInfo.isPresent(), "Key info should still be present due to fallback");
            // The key should be the same as the initial key
            assertEquals(initialKeyInfo.get().getKey(), keyInfo.get().getKey(), "Key should be the same as the initial key");
        }

        @Test
        @DisplayName("Should fallback to last valid result when connection fails")
        void shouldFallbackToLastValidResultWhenConnectionFails() {
            // Given
            // First request to populate the cache
            Optional<KeyInfo> initialKeyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(initialKeyInfo.isPresent(), "Initial key info should be present");

            // Configure dispatcher to simulate connection failure
            moduleDispatcher.simulateConnectionFailure();

            // When - make another request
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

            // Then
            // The key should still be available even though the connection failed
            assertTrue(keyInfo.isPresent(), "Key info should still be present due to fallback");
            // The key should be the same as the initial key
            assertEquals(initialKeyInfo.get().getKey(), keyInfo.get().getKey(), "Key should be the same as the initial key");
        }
    }
}
