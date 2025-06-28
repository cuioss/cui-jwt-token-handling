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
 * Simple stateful HTTP cache for JWKS content.
 * <p>
 * This component handles HTTP calls and provides simple time-based caching
 * without scheduling. It tracks whether content was loaded from cache or
 * freshly fetched.
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
     * @param wasFromCache true if content was loaded from cache, false if freshly fetched
     * @param loadedAt the instant when content was loaded/cached
     */
    public record LoadResult(String content, boolean wasFromCache, Instant loadedAt) {}
    
    private final HttpHandler httpHandler;
    private final int cacheValiditySeconds;
    
    private volatile String cachedContent;
    private volatile Instant cachedAt;
    
    /**
     * Creates a new HTTP cache with the specified validity period.
     * 
     * @param httpHandler the HTTP handler for making requests
     * @param cacheValiditySeconds how long cached content remains valid (0 = no caching)
     */
    public JwksHttpCache(@NonNull HttpHandler httpHandler, int cacheValiditySeconds) {
        this.httpHandler = httpHandler;
        this.cacheValiditySeconds = Math.max(0, cacheValiditySeconds);
    }
    
    /**
     * Loads JWKS content, using cache if valid or fetching fresh content.
     * 
     * @return LoadResult containing content and cache status
     * @throws RuntimeException if loading fails after retries
     */
    public synchronized LoadResult load() {
        Instant now = Instant.now();
        
        // Check if we have valid cached content
        if (isCacheValid(now)) {
            LOGGER.debug("Returning cached JWKS content from %s", cachedAt);
            return new LoadResult(cachedContent, true, cachedAt);
        }
        
        // Fetch fresh content
        try {
            String freshContent = RetryUtil.executeWithRetry(
                this::fetchJwksContent,
                "fetch JWKS from " + httpHandler.getUrl()
            );
            
            // Update cache
            this.cachedContent = freshContent;
            this.cachedAt = now;
            
            LOGGER.info("Loaded fresh JWKS content from %s", httpHandler.getUrl());
            return new LoadResult(freshContent, false, now);
            
        } catch (Exception e) {
            LOGGER.error(e, "Failed to load JWKS from %s", httpHandler.getUrl());
            throw new RuntimeException("Failed to load JWKS", e);
        }
    }
    
    /**
     * Forces a reload of JWKS content, bypassing cache.
     * 
     * @return LoadResult with fresh content
     * @throws RuntimeException if loading fails after retries
     */
    public synchronized LoadResult reload() {
        LOGGER.debug("Forcing reload of JWKS content from %s", httpHandler.getUrl());
        
        // Clear cache to force fresh load
        this.cachedContent = null;
        this.cachedAt = null;
        
        return load();
    }
    
    /**
     * Checks if cache contains valid content.
     * 
     * @return true if cache is valid and contains content
     */
    public boolean isCacheValid() {
        return isCacheValid(Instant.now());
    }
    
    /**
     * Clears the cache, forcing next load to fetch fresh content.
     */
    public synchronized void clearCache() {
        LOGGER.debug("Clearing JWKS cache for %s", httpHandler.getUrl());
        this.cachedContent = null;
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
     * Checks if cached content is still valid at the given time.
     */
    private boolean isCacheValid(Instant now) {
        if (cacheValiditySeconds == 0) {
            return false; // No caching
        }
        
        if (cachedContent == null || cachedAt == null) {
            return false; // No cached content
        }
        
        return cachedAt.plusSeconds(cacheValiditySeconds).isAfter(now);
    }
    
    /**
     * Fetches JWKS content from the HTTP endpoint.
     */
    private String fetchJwksContent() {
        try {
            HttpClient client = httpHandler.createHttpClient();
            HttpRequest request = httpHandler.requestBuilder().build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode() + " from " + httpHandler.getUrl());
            }
            
            return response.body();
            
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new RuntimeException("Failed to fetch JWKS content", e);
        }
    }
}