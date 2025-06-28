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
class JwksHttpCacheTest {

    @Getter
    private final JwksResolveDispatcher moduleDispatcher = new JwksResolveDispatcher();

    private JwksHttpCache cache;

    @BeforeEach
    void setUp(URIBuilder uriBuilder) {
        String jwksEndpoint = uriBuilder.addPathSegment(JwksResolveDispatcher.LOCAL_PATH).buildAsString();
        moduleDispatcher.setCallCounter(0);

        HttpHandler httpHandler = HttpHandler.builder()
                .url(jwksEndpoint)
                .build();

        cache = new JwksHttpCache(httpHandler);
    }

    @Test
    void testBasicLoad() {
        // Initially no cache
        assertFalse(cache.hasCache());
        assertNull(cache.getCachedAt());
        assertNull(cache.getCachedETag());

        // First load should fetch from HTTP
        JwksHttpCache.LoadResult result = cache.load();
        assertNotNull(result.content());
        assertFalse(result.wasFromCache());
        assertNotNull(result.loadedAt());

        // Should have called endpoint once
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Cache should now contain content (but ETag may be null if server doesn't support it)
        assertEquals(result.loadedAt(), cache.getCachedAt());
        // Note: getCachedETag() may be null if server doesn't provide ETag header
    }

    @Test
    void testCachingBehaviorWithoutETag() {
        // First load
        JwksHttpCache.LoadResult result1 = cache.load();
        assertFalse(result1.wasFromCache());
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Second load - without ETag support from server, it will fetch again
        JwksHttpCache.LoadResult result2 = cache.load();
        assertEquals(result1.content(), result2.content());
        assertFalse(result2.wasFromCache()); // No cache because no ETag
        
        // Without ETag from server, each call fetches fresh content
        assertEquals(2, moduleDispatcher.getCallCounter());
    }

    @Test
    void testReload() {
        // Initial load
        cache.load();
        assertEquals(1, moduleDispatcher.getCallCounter());

        // Reload should bypass cache
        JwksHttpCache.LoadResult reloadResult = cache.reload();
        assertFalse(reloadResult.wasFromCache());
        assertEquals(2, moduleDispatcher.getCallCounter());
    }

    @Test
    void testClearCache() {
        // Load and verify cache
        cache.load();
        assertNotNull(cache.getCachedAt());

        // Clear cache
        cache.clearCache();
        assertNull(cache.getCachedAt());
        assertNull(cache.getCachedETag());

        // Next load should fetch fresh
        JwksHttpCache.LoadResult result = cache.load();
        assertFalse(result.wasFromCache());
        assertEquals(2, moduleDispatcher.getCallCounter());
    }

    @Test
    void testETagBasedCaching() {
        // This test demonstrates ETag-based caching behavior
        // Since the test dispatcher doesn't provide ETags, 
        // the cache will always fetch fresh content
        
        JwksHttpCache.LoadResult result1 = cache.load();
        assertFalse(result1.wasFromCache());
        
        // Without ETag support, subsequent calls fetch fresh content
        JwksHttpCache.LoadResult result2 = cache.load();
        assertFalse(result2.wasFromCache());
        
        // Content should be the same
        assertEquals(result1.content(), result2.content());
    }

    @Test
    void testLoadResultRecord() {
        JwksHttpCache.LoadResult result = cache.load();
        
        // Test record properties
        assertNotNull(result.content());
        assertNotNull(result.loadedAt());
        assertFalse(result.wasFromCache());

        // Test record equality
        JwksHttpCache.LoadResult sameResult = new JwksHttpCache.LoadResult(
                result.content(), result.wasFromCache(), result.loadedAt());
        assertEquals(result, sameResult);
        assertEquals(result.hashCode(), sameResult.hashCode());
    }
}