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
import de.cuioss.jwt.token.test.dispatcher.JwksResolveDispatcher;
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

import java.security.Key;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger(debug = {HttpJwksLoader.class, JWKSKeyLoader.class})
@DisplayName("Tests HttpJwksLoader functionality")
@EnableMockWebServer
class HttpJwksLoaderTest {

    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final String TEST_KID = JWKSFactory.DEFAULT_KEY_ID;
    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();
    private JwksLoader httpJwksLoader;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);
        httpJwksLoader = JwksLoaderFactory.createHttpLoader(jwksEndpoint, REFRESH_INTERVAL_SECONDS, null);
    }

    @Test
    @DisplayName("Should fetch and parse JWKS from remote endpoint")
    void shouldFetchAndParseJwks() {
        // When
        Optional<Key> key = httpJwksLoader.getKey(TEST_KID);

        // Then
        assertTrue(key.isPresent(), "Key should be present");
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called once");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Refreshing keys from JWKS endpoint");
    }

    @Test
    @DisplayName("Should cache keys and minimize HTTP requests")
    void shouldCacheKeys() {
        // When
        for (int i = 0; i < 5; i++) {
            Optional<Key> key = httpJwksLoader.getKey(TEST_KID);
            assertTrue(key.isPresent(), "Key should be present on call " + i);
        }

        // Then
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called only once due to caching");
    }

    @Test
    @DisplayName("Should refresh keys when kid not found")
    void shouldRefreshKeysWhenKidNotFound() {
        // Given
        httpJwksLoader.getKey(TEST_KID); // Initial fetch
        assertEquals(1, moduleDispatcher.getCallCounter());

        // When
        moduleDispatcher.returnEmptyJwks();
        Optional<Key> key = httpJwksLoader.getKey("unknown-kid");

        // Then
        assertFalse(key.isPresent(), "Key should not be present");
        assertEquals(2, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called again");
    }

    @Test
    @DisplayName("Should handle server errors")
    @ModuleDispatcher
    void shouldHandleServerErrors(URIBuilder uriBuilder) {
        // Given
        moduleDispatcher.returnError();

        // Create a new loader that will encounter server error
        String endpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoader errorLoader = new HttpJwksLoader(endpoint, REFRESH_INTERVAL_SECONDS, null);

        // When
        Optional<Key> key = errorLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when server returns error");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to fetch JWKS");
    }

    @Test
    @DisplayName("Should handle invalid JWKS format")
    @ModuleDispatcher
    void shouldHandleInvalidJwksFormat(URIBuilder uriBuilder) {
        // Given
        moduleDispatcher.returnInvalidJson();

        // Create a new loader with invalid JSON response
        String endpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoader invalidJsonLoader = new HttpJwksLoader(endpoint, REFRESH_INTERVAL_SECONDS, null);

        // When
        Optional<Key> key = invalidJsonLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when JWKS is invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse JWKS JSON");
    }

    @Test
    @DisplayName("Should refresh keys when creating a new instance")
    @ModuleDispatcher
    void shouldRefreshKeysWhenCreatingNewInstance(URIBuilder uriBuilder) {
        // Given
        httpJwksLoader.getKey(TEST_KID); // Initial fetch
        assertEquals(1, moduleDispatcher.getCallCounter());

        // When - create a new instance to force refresh
        String endpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoader newLoader = new HttpJwksLoader(endpoint, REFRESH_INTERVAL_SECONDS, null);
        newLoader.getKey(TEST_KID);

        // Then - verify keys were refreshed
        assertEquals(2, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called again with new instance");
    }

    @Test
    @DisplayName("Should return empty when kid is null")
    void shouldReturnEmptyWhenKidIsNull() {
        // When
        Optional<Key> key = httpJwksLoader.getKey(null);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when kid is null");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Key ID is null");
    }

    @Test
    @DisplayName("Should throw exception when refresh interval is invalid")
    @ModuleDispatcher
    void shouldThrowExceptionWhenRefreshIntervalIsInvalid(URIBuilder uriBuilder) {
        // Given
        String endpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> {
            JwksLoaderFactory.createHttpLoader(endpoint, 0, null);
        }, "Should throw exception when refresh interval is zero");

        assertThrows(IllegalArgumentException.class, () -> {
            JwksLoaderFactory.createHttpLoader(endpoint, -1, null);
        }, "Should throw exception when refresh interval is negative");
    }

    @Test
    @DisplayName("Should handle missing required fields in JWK")
    @ModuleDispatcher
    void shouldHandleMissingRequiredFieldsInJwk(URIBuilder uriBuilder) {
        // Given
        moduleDispatcher.returnMissingFieldsJwk();

        // Create a new loader with JWK missing required fields
        String endpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        HttpJwksLoader missingFieldsLoader = new HttpJwksLoader(endpoint, REFRESH_INTERVAL_SECONDS, null);

        // When
        Optional<Key> key = missingFieldsLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when JWK is missing required fields");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to parse RSA key");
    }

    @Test
    @DisplayName("Should get first key when available")
    void shouldGetFirstKeyWhenAvailable() {
        // When
        Optional<Key> key = httpJwksLoader.getFirstKey();

        // Then
        assertTrue(key.isPresent(), "First key should be present");
    }

    @Test
    @DisplayName("Should return correct keySet")
    void shouldReturnCorrectKeySet() {
        // Given
        // The loader is already initialized with a valid JWKS endpoint in setUp()

        // When
        var keySet = httpJwksLoader.keySet();

        // Then
        assertFalse(keySet.isEmpty(), "KeySet should not be empty");
        assertTrue(keySet.contains(TEST_KID), "KeySet should contain the test key ID");
        assertEquals(1, keySet.size(), "KeySet should contain exactly one key");
    }

    @Test
    @DisplayName("Should handle invalid URL")
    void shouldHandleInvalidUrl() {
        // Given
        HttpJwksLoader invalidUrlLoader = new HttpJwksLoader("invalid-url", REFRESH_INTERVAL_SECONDS, null);

        // When
        Optional<Key> key = invalidUrlLoader.getKey(TEST_KID);

        // Then
        assertFalse(key.isPresent(), "Key should not be present when URL is invalid");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Failed to fetch JWKS from URL: invalid-url");
    }

}