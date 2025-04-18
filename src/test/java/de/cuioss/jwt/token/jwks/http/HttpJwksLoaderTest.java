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
package de.cuioss.jwt.token.jwks.http;

import de.cuioss.jwt.token.jwks.key.KeyInfo;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.dispatcher.JwksResolveDispatcher;
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

    private static final String TEST_KID = JWKSFactory.DEFAULT_KEY_ID;
    private static final int REFRESH_INTERVAL = 60;

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private HttpJwksLoader httpJwksLoader;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        httpJwksLoader = new HttpJwksLoader(config);
    }

    @Test
    @DisplayName("Should create loader with constructor")
    void shouldCreateLoaderWithConstructor() {
        // Then
        assertNotNull(httpJwksLoader);
        assertNotNull(httpJwksLoader.getConfig());
        assertEquals(REFRESH_INTERVAL, httpJwksLoader.getConfig().getRefreshIntervalSeconds());
    }

    @Test
    @DisplayName("Should get key info by ID")
    void shouldGetKeyInfoById() {
        // When
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);

        // Then
        assertTrue(keyInfo.isPresent(), "Key info should be present");
        assertEquals(TEST_KID, keyInfo.get().getKeyId(), "Key ID should match");
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called once");
    }

    @Test
    @DisplayName("Should return empty for unknown key ID")
    void shouldReturnEmptyForUnknownKeyId() {
        // When
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo("unknown-kid");

        // Then
        assertFalse(keyInfo.isPresent(), "Key info should not be present for unknown key ID");
    }

    @Test
    @DisplayName("Should return empty for null key ID")
    void shouldReturnEmptyForNullKeyId() {
        // When
        Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(null);

        // Then
        assertFalse(keyInfo.isPresent(), "Key info should not be present for null key ID");
    }

    @Test
    @DisplayName("Should get first key info")
    void shouldGetFirstKeyInfo() {
        // When
        Optional<KeyInfo> keyInfo = httpJwksLoader.getFirstKeyInfo();

        // Then
        assertTrue(keyInfo.isPresent(), "First key info should be present");
    }

    @Test
    @DisplayName("Should get all key infos")
    void shouldGetAllKeyInfos() {
        // When
        List<KeyInfo> keyInfos = httpJwksLoader.getAllKeyInfos();

        // Then
        assertNotNull(keyInfos, "Key infos should not be null");
        assertFalse(keyInfos.isEmpty(), "Key infos should not be empty");
    }

    @Test
    @DisplayName("Should get key set")
    void shouldGetKeySet() {
        // When
        Set<String> keySet = httpJwksLoader.keySet();

        // Then
        assertNotNull(keySet, "Key set should not be null");
        assertFalse(keySet.isEmpty(), "Key set should not be empty");
        assertTrue(keySet.contains(TEST_KID), "Key set should contain test key ID");
    }

    @Test
    @DisplayName("Should cache keys and minimize HTTP requests")
    void shouldCacheKeysAndMinimizeHttpRequests() {
        // When
        for (int i = 0; i < 5; i++) {
            Optional<KeyInfo> keyInfo = httpJwksLoader.getKeyInfo(TEST_KID);
            assertTrue(keyInfo.isPresent(), "Key info should be present on call " + i);
        }

        // Then
        assertEquals(1, moduleDispatcher.getCallCounter(), "JWKS endpoint should be called only once due to caching");
    }

    @Test
    @DisplayName("Should handle invalid URL")
    void shouldHandleInvalidUrl() {
        // Given
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl("invalid url")
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        HttpJwksLoader invalidLoader = new HttpJwksLoader(config);

        // When
        Optional<KeyInfo> keyInfo = invalidLoader.getKeyInfo(TEST_KID);

        // Then
        assertFalse(keyInfo.isPresent(), "Key info should not be present for invalid URL");

        // Clean up
        invalidLoader.close();
    }

    @Test
    @DisplayName("Should close resources")
    void shouldCloseResources() {
        // When
        httpJwksLoader.close();

        // Then
        // No exception should be thrown
        assertTrue(true, "Close should complete without exceptions");
    }

    @Test
    @ModuleDispatcher
    @DisplayName("Should create new loader with custom parameters")
    void shouldCreateNewLoaderWithCustomParameters(URIBuilder uriBuilder) {
        // Given
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(jwksEndpoint)
                .refreshIntervalSeconds(30)
                .maxCacheSize(200)
                .adaptiveWindowSize(20)
                .requestTimeoutSeconds(15)
                .backgroundRefreshPercentage(70)
                .build();

        HttpJwksLoader customLoader = new HttpJwksLoader(config);

        // Then
        assertNotNull(customLoader);
        assertEquals(30, customLoader.getConfig().getRefreshIntervalSeconds());
        assertEquals(200, customLoader.getConfig().getMaxCacheSize());
        assertEquals(20, customLoader.getConfig().getAdaptiveWindowSize());
        assertEquals(15, customLoader.getConfig().getRequestTimeoutSeconds());
        assertEquals(70, customLoader.getConfig().getBackgroundRefreshPercentage());

        // Verify it works
        Optional<KeyInfo> keyInfo = customLoader.getKeyInfo(TEST_KID);
        assertTrue(keyInfo.isPresent(), "Key info should be present");

        // Clean up
        customLoader.close();
    }
}
