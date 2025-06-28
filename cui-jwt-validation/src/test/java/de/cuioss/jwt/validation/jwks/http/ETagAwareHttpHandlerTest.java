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

import de.cuioss.jwt.validation.test.dispatcher.JwksResolveDispatcher;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@EnableMockWebServer
class ETagAwareHttpHandlerTest {

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private ETagAwareHttpHandler cache;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        HttpHandler httpHandler = HttpHandler.builder()
                .url(jwksEndpoint)
                .build();

        cache = new ETagAwareHttpHandler(httpHandler);
    }

    @Test
    void testBasicLoad() {
        // Initially no cache - no way to verify directly (internal state hidden)

        // First load should fetch from HTTP
        ETagAwareHttpHandler.LoadResult result = cache.load();
        assertNotNull(result.content());
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, result.loadState());
        assertTrue(result.loadState().isDataChanged());
        assertNotNull(result.loadedAt());

        // Should have called endpoint once
        assertEquals(1, moduleDispatcher.getCallCounter());
    }

    @Test
    void testCachingBehaviorWithoutETag() {
        // First load
        ETagAwareHttpHandler.LoadResult result1 = cache.load();
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, result1.loadState());
        assertTrue(result1.loadState().isDataChanged());
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Second load - without ETag support from server, it will fetch again
        ETagAwareHttpHandler.LoadResult result2 = cache.load();
        assertEquals(result1.content(), result2.content());
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, result2.loadState());
        assertTrue(result2.loadState().isDataChanged());
        
        // Without ETag from server, each call fetches fresh content
        assertEquals(2, moduleDispatcher.getCallCounter());
    }

    @Test
    void testReloadBypassETag() {
        // Initial load
        cache.load();
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Reload with false should bypass ETag validation only
        ETagAwareHttpHandler.LoadResult reloadResult = cache.reload(false);
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, reloadResult.loadState());
        assertTrue(reloadResult.loadState().isDataChanged());
        assertEquals(2, moduleDispatcher.getCallCounter());
    }

    @Test
    void testReloadWithClearCache() {
        // Initial load
        ETagAwareHttpHandler.LoadResult result1 = cache.load();
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Reload with clear cache should completely clear all cached data
        ETagAwareHttpHandler.LoadResult reloadResult = cache.reload(true);
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, reloadResult.loadState());
        assertTrue(reloadResult.loadState().isDataChanged());
        assertEquals(2, moduleDispatcher.getCallCounter());

        // Content should be the same but completely fresh
        assertEquals(result1.content(), reloadResult.content());
    }


    @Test
    void testETagBasedCaching() {
        // This test demonstrates ETag-based caching behavior
        // Since the test dispatcher doesn't provide ETags, 
        // the cache will always fetch fresh content
        
        ETagAwareHttpHandler.LoadResult result1 = cache.load();
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, result1.loadState());
        assertTrue(result1.loadState().isDataChanged());
        
        // Without ETag support, subsequent calls fetch fresh content
        ETagAwareHttpHandler.LoadResult result2 = cache.load();
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, result2.loadState());
        assertTrue(result2.loadState().isDataChanged());
        
        // Content should be the same
        assertEquals(result1.content(), result2.content());
    }

    @Test
    void testLoadResultRecord() {
        ETagAwareHttpHandler.LoadResult result = cache.load();
        
        // Test record properties
        assertNotNull(result.content());
        assertNotNull(result.loadedAt());
        assertEquals(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, result.loadState());
        assertTrue(result.loadState().isDataChanged());

        // Test record equality
        ETagAwareHttpHandler.LoadResult sameResult = new ETagAwareHttpHandler.LoadResult(
                result.content(), result.loadState(), result.loadedAt());
        assertEquals(result, sameResult);
        assertEquals(result.hashCode(), sameResult.hashCode());
    }
    
    @Test
    void testLoadStateEnum() {
        // Test enum properties
        assertTrue(ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER.isDataChanged());
        assertFalse(ETagAwareHttpHandler.LoadState.CACHE_ETAG.isDataChanged());
        assertFalse(ETagAwareHttpHandler.LoadState.CACHE_CONTENT.isDataChanged());
        assertFalse(ETagAwareHttpHandler.LoadState.ERROR_WITH_CACHE.isDataChanged());
        assertTrue(ETagAwareHttpHandler.LoadState.ERROR_NO_CACHE.isDataChanged());
        
        // Test LoadResult with different states
        ETagAwareHttpHandler.LoadResult serverResult = new ETagAwareHttpHandler.LoadResult("content", 
                ETagAwareHttpHandler.LoadState.LOADED_FROM_SERVER, java.time.Instant.now());
        assertTrue(serverResult.loadState().isDataChanged());
        
        ETagAwareHttpHandler.LoadResult etagResult = new ETagAwareHttpHandler.LoadResult("content", 
                ETagAwareHttpHandler.LoadState.CACHE_ETAG, java.time.Instant.now());
        assertFalse(etagResult.loadState().isDataChanged());
        
        ETagAwareHttpHandler.LoadResult contentResult = new ETagAwareHttpHandler.LoadResult("content", 
                ETagAwareHttpHandler.LoadState.CACHE_CONTENT, java.time.Instant.now());
        assertFalse(contentResult.loadState().isDataChanged());
    }
}