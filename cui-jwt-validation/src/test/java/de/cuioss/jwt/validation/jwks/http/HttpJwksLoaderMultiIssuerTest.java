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

import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.dispatcher.MultiIssuerJwksDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the multi-issuer support of HttpJwksLoader.
 * <p>
 * This test class focuses on the ability of HttpJwksLoader to handle
 * multiple JWKS URIs efficiently.
 */
@EnableTestLogger
@DisplayName("Tests HttpJwksLoader multi-issuer support")
@EnableMockWebServer
class HttpJwksLoaderMultiIssuerTest {

    private static final String ISSUER1_KID = "issuer1-kid";
    private static final String ISSUER2_KID = "issuer2-kid";
    private static final int REFRESH_INTERVAL_SECONDS = 1; // Short interval for testing
    private static final int MAX_CACHE_SIZE = 10;

    @Getter
    private final MultiIssuerJwksDispatcher moduleDispatcher = new MultiIssuerJwksDispatcher();
    private List<HttpJwksLoader> loaders;
    private SecurityEventCounter securityEventCounter;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        moduleDispatcher.setCallCounter(0);

        // Initialize the SecurityEventCounter
        securityEventCounter = new SecurityEventCounter();

        // Create a list to hold the loaders
        loaders = new ArrayList<>();
    }

    @Test
    @DisplayName("Should handle multiple issuers with different keys")
    void shouldHandleMultipleIssuersWithDifferentKeys(URIBuilder uriBuilder) {

        String issuer1Endpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER1_PATH).buildAsString();
        String issuer2Endpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER2_PATH).buildAsString();

        // Create loaders for each issuer
        HttpJwksLoaderConfig config1 = HttpJwksLoaderConfig.builder()
                .url(issuer1Endpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .maxCacheSize(MAX_CACHE_SIZE)
                .build();

        HttpJwksLoaderConfig config2 = HttpJwksLoaderConfig.builder()
                .url(issuer2Endpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .maxCacheSize(MAX_CACHE_SIZE)
                .build();

        HttpJwksLoader loader1 = new HttpJwksLoader(config1, securityEventCounter);
        HttpJwksLoader loader2 = new HttpJwksLoader(config2, securityEventCounter);

        // Add to list for cleanup
        loaders.add(loader1);
        loaders.add(loader2);
        Optional<KeyInfo> keyInfo1 = loader1.getKeyInfo(ISSUER1_KID);
        Optional<KeyInfo> keyInfo2 = loader2.getKeyInfo(ISSUER2_KID);
        assertTrue(keyInfo1.isPresent(), "Key info for issuer 1 should be present");
        assertTrue(keyInfo2.isPresent(), "Key info for issuer 2 should be present");

        // Verify that each loader got the correct key
        assertEquals(ISSUER1_KID, keyInfo1.get().keyId(), "Key ID for issuer 1 should match");
        assertEquals(ISSUER2_KID, keyInfo2.get().keyId(), "Key ID for issuer 2 should match");

        // Verify that the server was called for each issuer
        assertEquals(2, moduleDispatcher.getCallCounter(), "Server should be called once for each issuer");
    }

    @Test
    @DisplayName("Should respect max cache size with multiple issuers")
    void shouldRespectMaxCacheSizeWithMultipleIssuers(URIBuilder uriBuilder) {

        String issuer1Endpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER1_PATH).buildAsString();
        String issuer2Endpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER2_PATH).buildAsString();

        // Create a loader with a very small max cache size
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(issuer1Endpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .maxCacheSize(1) // Only cache one issuer
                .build();

        HttpJwksLoader loader = new HttpJwksLoader(config, securityEventCounter);
        loaders.add(loader);

        // When - first access issuer 1
        Optional<KeyInfo> keyInfo1 = loader.getKeyInfo(ISSUER1_KID);
        assertTrue(keyInfo1.isPresent(), "Key info for issuer 1 should be present");

        // Then - update the config to use issuer 2
        HttpJwksLoaderConfig newConfig = HttpJwksLoaderConfig.builder()
                .url(issuer2Endpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .maxCacheSize(1) // Only cache one issuer
                .build();

        // Create a new loader with the same security event counter
        HttpJwksLoader loader2 = new HttpJwksLoader(newConfig, securityEventCounter);
        loaders.add(loader2);

        // Access issuer 2
        Optional<KeyInfo> keyInfo2 = loader2.getKeyInfo(ISSUER2_KID);
        assertTrue(keyInfo2.isPresent(), "Key info for issuer 2 should be present");

        // Verify that the server was called for each issuer
        assertEquals(2, moduleDispatcher.getCallCounter(), "Server should be called once for each issuer");
    }

    @Test
    @DisplayName("Should handle multiple loaders with same URI but different refresh intervals")
    void shouldHandleMultipleLoadersWithSameUriButDifferentRefreshIntervals(URIBuilder uriBuilder) {

        String jwksEndpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER1_PATH).buildAsString();

        // Create loaders with different refresh intervals
        HttpJwksLoaderConfig config1 = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(30) // 30 seconds
                .build();

        HttpJwksLoaderConfig config2 = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(60) // 60 seconds
                .build();

        HttpJwksLoader loader1 = new HttpJwksLoader(config1, securityEventCounter);
        HttpJwksLoader loader2 = new HttpJwksLoader(config2, securityEventCounter);

        // Add to list for cleanup
        loaders.add(loader1);
        loaders.add(loader2);
        Optional<KeyInfo> keyInfo1 = loader1.getKeyInfo(ISSUER1_KID);

        // Reset the call counter after the first loader has loaded the keys
        moduleDispatcher.setCallCounter(0);

        Optional<KeyInfo> keyInfo2 = loader2.getKeyInfo(ISSUER1_KID);
        assertTrue(keyInfo1.isPresent(), "Key info from loader 1 should be present");
        assertTrue(keyInfo2.isPresent(), "Key info from loader 2 should be present");

        // Verify that the server was not called for the second loader
        // This is because the second loader is using the same URI as the first loader,
        // and the response is already cached by the mock server
        assertEquals(0, moduleDispatcher.getCallCounter(), "Server should not be called for the second loader");

        // Verify that both loaders got the same key
        assertEquals(ISSUER1_KID, keyInfo1.get().keyId(), "Key ID from loader 1 should match");
        assertEquals(ISSUER1_KID, keyInfo2.get().keyId(), "Key ID from loader 2 should match");
        assertEquals(keyInfo1.get().key(), keyInfo2.get().key(), "Keys from both loaders should be the same");
    }

    @Test
    @DisplayName("Should handle switching between issuers")
    void shouldHandleSwitchingBetweenIssuers(URIBuilder uriBuilder) {

        String issuer1Endpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER1_PATH).buildAsString();
        String issuer2Endpoint = uriBuilder.addPathSegment(MultiIssuerJwksDispatcher.ISSUER2_PATH).buildAsString();

        // Create configs for each issuer
        HttpJwksLoaderConfig config1 = HttpJwksLoaderConfig.builder()
                .url(issuer1Endpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .build();

        HttpJwksLoaderConfig config2 = HttpJwksLoaderConfig.builder()
                .url(issuer2Endpoint)
                .refreshIntervalSeconds(REFRESH_INTERVAL_SECONDS)
                .build();

        // Create a single loader that we'll reconfigure
        HttpJwksLoader loader = new HttpJwksLoader(config1, securityEventCounter);
        loaders.add(loader);

        // When - first access issuer 1
        Optional<KeyInfo> keyInfo1 = loader.getKeyInfo(ISSUER1_KID);
        assertTrue(keyInfo1.isPresent(), "Key info for issuer 1 should be present");

        // Create a new loader with issuer 2 config
        loader = new HttpJwksLoader(config2, securityEventCounter);
        loaders.add(loader);

        // Access issuer 2
        Optional<KeyInfo> keyInfo2 = loader.getKeyInfo(ISSUER2_KID);
        assertTrue(keyInfo2.isPresent(), "Key info for issuer 2 should be present");

        // Verify that the server was called for each issuer
        assertEquals(2, moduleDispatcher.getCallCounter(), "Server should be called once for each issuer");

        // Verify that we got different keys
        assertNotEquals(keyInfo1.get().key(), keyInfo2.get().key(), "Keys from different issuers should be different");
    }

    /**
     * Cleanup method to close all loaders.
     */
    @AfterEach
    void cleanup() {
        for (HttpJwksLoader loader : loaders) {
            loader.close();
        }
    }
}
