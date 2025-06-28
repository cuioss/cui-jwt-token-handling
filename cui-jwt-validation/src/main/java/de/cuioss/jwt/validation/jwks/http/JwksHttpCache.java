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

import de.cuioss.jwt.validation.util.RetryException;
import de.cuioss.jwt.validation.util.RetryUtil;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.NonNull;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;

/**
 * Simple stateful HTTP cache for JWKS content using ETags.
 * <p>
 * This component handles HTTP calls and provides HTTP-based caching using
 * ETags and "If-None-Match" headers. It tracks whether content was loaded 
 * from cache (304 Not Modified) or freshly fetched (200 OK).
 * <p>
 * Thread-safe implementation using volatile fields and synchronized methods.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public class JwksHttpCache {
    
    private static final CuiLogger LOGGER = new CuiLogger(JwksHttpCache.class);
    
    /**
     * Result of a load operation containing the payload and cache status.
     * 
     * @param content the JWKS content as string
     * @param wasFromCache true if content was loaded from cache (304), false if freshly fetched (200)
     * @param loadedAt the instant when content was loaded/cached
     */
    public record LoadResult(String content, boolean wasFromCache, Instant loadedAt) {}
    
    private final HttpHandler httpHandler;
    
    private volatile String cachedContent;
    private volatile String cachedETag;
    private volatile Instant cachedAt;
    
    /**
     * Creates a new HTTP cache using ETags for cache validation.
     * 
     * @param httpHandler the HTTP handler for making requests
     */
    public JwksHttpCache(@NonNull HttpHandler httpHandler) {
        this.httpHandler = httpHandler;
    }
    
    /**
     * Loads JWKS content, using ETag-based HTTP caching when supported.
     * 
     * @return LoadResult containing content and cache status
     * @throws JwksLoadException if loading fails after retries
     */
    public synchronized LoadResult load() {
        try {
            // If we have cached content and ETag, try conditional request
            if (cachedContent != null && cachedETag != null) {
                HttpCacheResult result = RetryUtil.executeWithRetry(
                    this::fetchJwksContentWithCache,
                    "fetch JWKS from " + httpHandler.getUrl()
                );
                
                if (result.notModified) {
                    // 304 Not Modified - use cached content
                    LOGGER.debug("JWKS content not modified (304), using cached version");
                    return new LoadResult(cachedContent, true, cachedAt);
                } else {
                    // 200 OK - fresh content received
                    Instant now = Instant.now();
                    this.cachedContent = result.content;
                    this.cachedETag = result.etag;
                    this.cachedAt = now;
                    
                    LOGGER.info("Loaded fresh JWKS content from %s", httpHandler.getUrl());
                    return new LoadResult(result.content, false, now);
                }
            } else {
                // No cache or no ETag - fetch fresh content
                HttpCacheResult result = RetryUtil.executeWithRetry(
                    this::fetchJwksContentWithCache,
                    "fetch JWKS from " + httpHandler.getUrl()
                );
                
                Instant now = Instant.now();
                this.cachedContent = result.content;
                this.cachedETag = result.etag; // May be null if server doesn't support ETags
                this.cachedAt = now;
                
                LOGGER.info("Loaded fresh JWKS content from %s", httpHandler.getUrl());
                return new LoadResult(result.content, false, now);
            }
        } catch (RetryException e) {
            // Unwrap JwksLoadException if wrapped by RetryUtil
            if (e.getCause() instanceof JwksLoadException) {
                throw (JwksLoadException) e.getCause();
            }
            // Wrap retry exceptions with context
            throw new JwksLoadException("Failed to load JWKS after " + e.getAttemptsMade() + " attempts from " + httpHandler.getUrl(), e);
        }
    }
    
    /**
     * Forces a reload of JWKS content, bypassing cache.
     * 
     * @return LoadResult with fresh content
     * @throws JwksLoadException if loading fails after retries
     */
    public synchronized LoadResult reload() {
        LOGGER.debug("Forcing reload of JWKS content from %s", httpHandler.getUrl());
        
        // Clear ETag to force fresh load
        this.cachedETag = null;
        
        return load();
    }
    
    /**
     * Checks if cache contains content.
     * 
     * @return true if cache contains content and ETag
     */
    public boolean hasCache() {
        return cachedContent != null && cachedETag != null;
    }
    
    /**
     * Clears the cache, forcing next load to fetch fresh content.
     */
    public synchronized void clearCache() {
        LOGGER.debug("Clearing JWKS cache for %s", httpHandler.getUrl());
        this.cachedContent = null;
        this.cachedETag = null;
        this.cachedAt = null;
    }
    
    /**
     * Gets the time when content was last cached.
     * 
     * @return cached timestamp or null if no content is cached
     */
    public Instant getCachedAt() {
        return cachedAt;
    }
    
    /**
     * Gets the current cached ETag.
     * 
     * @return cached ETag or null if no content is cached
     */
    public String getCachedETag() {
        return cachedETag;
    }
    
    /**
     * Internal result for HTTP cache operations.
     */
    private record HttpCacheResult(String content, String etag, boolean notModified) {}
    
    /**
     * Fetches JWKS content from the HTTP endpoint with ETag support.
     * 
     * @throws JwksLoadException if HTTP request fails
     */
    private HttpCacheResult fetchJwksContentWithCache() {
        try {
            HttpClient client = httpHandler.createHttpClient();
            
            // Build request with conditional headers
            HttpRequest.Builder requestBuilder = httpHandler.requestBuilder();
            
            // Add If-None-Match header if we have a cached ETag
            if (cachedETag != null) {
                requestBuilder.header("If-None-Match", cachedETag);
            }
            
            HttpRequest request = requestBuilder.build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() == 304) {
                // Not Modified - content hasn't changed
                LOGGER.debug("Received 304 Not Modified from %s", httpHandler.getUrl());
                return new HttpCacheResult(null, null, true);
            } else if (response.statusCode() == 200) {
                // OK - fresh content
                String content = response.body();
                String etag = response.headers().firstValue("ETag").orElse(null);
                
                LOGGER.debug("Received 200 OK from %s with ETag: %s", httpHandler.getUrl(), etag);
                return new HttpCacheResult(content, etag, false);
            } else {
                throw new JwksLoadException("HTTP " + response.statusCode() + " from " + httpHandler.getUrl());
            }
            
        } catch (IOException e) {
            throw new JwksLoadException("Failed to fetch JWKS from " + httpHandler.getUrl(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new JwksLoadException("Interrupted while fetching JWKS from " + httpHandler.getUrl(), e);
        }
    }
}