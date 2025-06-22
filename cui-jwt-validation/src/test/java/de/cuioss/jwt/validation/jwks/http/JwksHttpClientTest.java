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

import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
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

@EnableTestLogger
@DisplayName("Tests JwksHttpClient")
@EnableMockWebServer
class JwksHttpClientTest {

    private static final String JWKS_CONTENT = InMemoryJWKSFactory.createDefaultJwks();

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private HttpJwksLoaderConfig config;
    private JwksHttpClient client;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        config = HttpJwksLoaderConfig.builder()
                .url(jwksEndpoint)
                .refreshIntervalSeconds(60)
                .build();

        client = JwksHttpClient.create(config);
    }

    @Test
    @DisplayName("Should create client with config")
    void shouldCreateClientWithConfig() {

        assertNotNull(client);
        assertNotNull(client.getHttpClient());
    }

    @Test
    @DisplayName("Should handle 200 OK response")
    void shouldHandle200OkResponse() {

        JwksHttpClient.JwksHttpResponse response = client.fetchJwksContent(null);
        assertFalse(response.isNotModified());
        assertNotNull(response.getContent());
        assertTrue(response.getContent().contains("keys"));
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    @DisplayName("Should create empty response")
    void shouldCreateEmptyResponse() {

        JwksHttpClient.JwksHttpResponse response = JwksHttpClient.JwksHttpResponse.empty();
        assertFalse(response.isNotModified());
        assertEquals("{}", response.getContent());
        assertEquals(Optional.empty(), response.getEtag());
    }

    @Test
    @DisplayName("Should create not modified response")
    void shouldCreateNotModifiedResponse() {

        JwksHttpClient.JwksHttpResponse response = JwksHttpClient.JwksHttpResponse.notModified();
        assertTrue(response.isNotModified());
        assertNull(response.getContent());
        assertEquals(Optional.empty(), response.getEtag());
    }

    @Test
    @DisplayName("Should create response with content")
    void shouldCreateResponseWithContent() {

        String content = JWKS_CONTENT;
        String etag = "\"test-etag\"";
        JwksHttpClient.JwksHttpResponse response = JwksHttpClient.JwksHttpResponse.withContent(content, etag);
        assertFalse(response.isNotModified());
        assertEquals(content, response.getContent());
        assertEquals(Optional.of(etag), response.getEtag());
    }
}
