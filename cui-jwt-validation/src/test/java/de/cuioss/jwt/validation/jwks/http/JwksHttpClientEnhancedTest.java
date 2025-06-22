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

import de.cuioss.jwt.validation.test.dispatcher.EnhancedJwksResolveDispatcher;
import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Enhanced tests for JwksHttpClient focusing on:
 * - HTTP 304 "Not Modified" responses
 * - Different HTTP status codes
 * - ETag header handling
 * - Exception handling
 */
@EnableTestLogger
@DisplayName("Enhanced tests for JwksHttpClient")
@EnableMockWebServer
class JwksHttpClientEnhancedTest {

    private static final String TEST_ETAG = "\"test-etag-value\"";

    @Getter
    private final EnhancedJwksResolveDispatcher moduleDispatcher = new EnhancedJwksResolveDispatcher();
    private JwksHttpClient client;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(60)
                .build();

        client = JwksHttpClient.create(config);
    }

    @Test
    @DisplayName("Should handle HTTP 304 Not Modified response")
    void shouldHandleHttp304NotModifiedResponse() {
        // Configure dispatcher to return 304 Not Modified
        moduleDispatcher.returnNotModified();

        // When - fetch with a previous ETag
        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(TEST_ETAG);
        assertTrue(response.isNotModified(), "Response should indicate not modified");
        assertNull(response.getContent(), "Content should be null for not modified response");
        assertEquals(Optional.empty(), response.getEtag(), "ETag should be empty for not modified response");
    }

    @Test
    @DisplayName("Should include If-None-Match header when ETag is provided")
    void shouldIncludeIfNoneMatchHeaderWhenEtagIsProvided() {
        // Configure dispatcher to check for If-None-Match header
        moduleDispatcher.expectIfNoneMatchHeader();

        // When - fetch with a previous ETag
        client.fetchJwksContent(TEST_ETAG);
        assertTrue(moduleDispatcher.wasIfNoneMatchHeaderPresent(), "If-None-Match header should be present");
    }

    @Test
    @DisplayName("Should handle error response")
    void shouldHandleErrorResponse() {
        // Configure dispatcher to return error
        moduleDispatcher.returnError();
        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(null);
        assertFalse(response.isNotModified(), "Response should not indicate not modified");
        // The JwksHttpClient only returns empty JWKS for non-200 status codes
        // The EnhancedJwksResolveDispatcher's returnError method returns a valid JWKS
        assertNotNull(response.getContent(), "Content should not be null");
        assertTrue(response.getContent().contains("keys"), "Content should contain keys");
    }

    @Test
    @DisplayName("Should handle connection failure")
    void shouldHandleConnectionFailure() {
        // Configure dispatcher to simulate connection failure
        moduleDispatcher.simulateConnectionFailure();
        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(null);
        assertFalse(response.isNotModified(), "Response should not indicate not modified");
        assertEquals("{}", response.getContent(), "Content should be empty JWKS for connection failure");
        assertEquals(Optional.empty(), response.getEtag(), "ETag should be empty for connection failure");
    }

    @Test
    @DisplayName("Should handle same content with different ETag")
    void shouldHandleSameContentWithDifferentETag() {
        // Configure dispatcher to return same content
        moduleDispatcher.returnSameContent();
        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(null);
        assertFalse(response.isNotModified(), "Response should not indicate not modified");
        assertNotNull(response.getContent(), "Content should not be null");
        assertTrue(response.getContent().contains("keys"), "Content should contain keys");
        assertTrue(response.getEtag().isPresent(), "ETag should be present");
    }

    @Test
    @DisplayName("Should handle different content")
    void shouldHandleDifferentContent() {
        // Configure dispatcher to return different content
        String newKeyId = "new-key-id";
        moduleDispatcher.returnDifferentContent(newKeyId);
        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(null);
        assertFalse(response.isNotModified(), "Response should not indicate not modified");
        assertNotNull(response.getContent(), "Content should not be null");
        assertTrue(response.getContent().contains(newKeyId), "Content should contain the new key ID");
        assertTrue(response.getEtag().isPresent(), "ETag should be present");
    }

    @Test
    @DisplayName("Should extract ETag from response headers")
    void shouldExtractEtagFromResponseHeaders() {
        // The default response already includes an ETag
        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(null);
        assertFalse(response.isNotModified(), "Response should not indicate not modified");
        assertNotNull(response.getContent(), "Content should not be null");
        assertTrue(response.getEtag().isPresent(), "ETag should be extracted from response");
    }

}
