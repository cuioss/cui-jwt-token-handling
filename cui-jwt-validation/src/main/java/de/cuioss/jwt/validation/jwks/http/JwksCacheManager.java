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

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import de.cuioss.jwt.validation.JWTValidationLogMessages.DEBUG;
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import lombok.NonNull;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Manages caching of JWKS content.
 * <p>
 * This class is responsible for:
 * <ul>
 *   <li>Configuring and managing the Caffeine cache</li>
 *   <li>Implementing adaptive caching logic</li>
 *   <li>Handling cache key generation</li>
 *   <li>Content-based caching to avoid unnecessary updates</li>
 *   <li>Fallback to last valid result when errors occur</li>
 * </ul>
 * <p>
 * For more details on caching and key management, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/technical-components.adoc#_jwksloader">Technical Components Specification</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
class JwksCacheManager {

    private static final CuiLogger LOGGER = new CuiLogger(JwksCacheManager.class);
    private static final String CACHE_KEY_PREFIX = "jwks:";
    private static final String EMPTY_JWKS = "{}";

    @NonNull
    private final HttpJwksLoaderConfig config;

    @NonNull
    private final SecurityEventCounter securityEventCounter;

    private final LoadingCache<String, JWKSKeyLoader> jwksCache;
    private JWKSKeyLoader lastValidResult;
    private final AtomicInteger accessCount;
    private final AtomicInteger hitCount;
    private String currentEtag;

    /**
     * Creates a new JwksCacheManager with the specified configuration.
     *
     * @param config      the configuration
     * @param cacheLoader function to load a JWKSKeyLoader when cache misses
     * @param securityEventCounter the counter for security events
     */
    JwksCacheManager(@NonNull HttpJwksLoaderConfig config,
            @NonNull Function<String, JWKSKeyLoader> cacheLoader,
            @NonNull SecurityEventCounter securityEventCounter) {
        this.config = config;
        this.securityEventCounter = securityEventCounter;
        this.lastValidResult = null;
        this.accessCount = new AtomicInteger(0);
        this.hitCount = new AtomicInteger(0);
        this.currentEtag = null;

        // Configure cache based on refresh interval and with size limit
        Caffeine<Object, Object> builder = Caffeine.newBuilder()
                .maximumSize(config.getMaxCacheSize());

        // If refreshIntervalSeconds is 0, don't set expiration or refresh policies
        if (config.getRefreshIntervalSeconds() > 0) {
            AdaptiveCacheExpiryPolicy expiryPolicy = new AdaptiveCacheExpiryPolicy(config, accessCount, hitCount);
            builder.expireAfter(expiryPolicy);
        }

        this.jwksCache = builder.build(cacheLoader::apply);
    }

    /**
     * Gets the cache key for the JWKS URI.
     * The key is based on the JWKS URI to support multiple issuers.
     * If the JWKS URI is null (invalid URL), a special key is returned.
     *
     * @return the cache key
     */
    String getCacheKey() {
        return CACHE_KEY_PREFIX + config.getHttpHandler().getUri();
    }

    /**
     * Gets the current ETag value.
     *
     * @return the current ETag, may be null
     */
    String getCurrentEtag() {
        return currentEtag;
    }

    /**
     * Sets the current ETag value.
     *
     * @param etag the new ETag value
     */
    void setCurrentEtag(String etag) {
        this.currentEtag = etag;
    }

    /**
     * Resolves a JWKSKeyLoader for the current JWKS content.
     * This method gets the current JWKSKeyLoader from the cache, which will trigger a refresh if needed.
     * It also tracks access patterns for adaptive caching.
     *
     * @return a JWKSKeyLoader instance with the current JWKS content
     */
    @SuppressWarnings("java:S2589")
    // owolff: Regarding the LoadingCache API, The API claims that the method may return null,
    // therefore the null check is not redundant
    JWKSKeyLoader resolve() {

        LOGGER.debug(DEBUG.RESOLVING_KEY_LOADER.format(config.getHttpHandler().getUri().toString()));

        try {
            // If refreshIntervalSeconds is 0, bypass the cache and load directly
            if (config.getRefreshIntervalSeconds() == 0) {
                return jwksCache.get(getCacheKey());
            }

            // Track access for adaptive caching
            int currentAccessCount = accessCount.incrementAndGet();

            // Get the current JWKSKeyLoader from cache, which will trigger a refresh if needed
            JWKSKeyLoader result = jwksCache.get(getCacheKey());

            // Track hit for adaptive caching if we got a valid result
            if (result != null && result.isNotEmpty()) {
                hitCount.incrementAndGet();
            }

            // Reset counters after adaptive window size is reached
            // This is also done in expireAfterRead, but we need to do it here as well
            // to ensure the counters are reset immediately after reaching the adaptive window size
            if (currentAccessCount >= config.getAdaptiveWindowSize()) {
                accessCount.set(0);
                hitCount.set(0);
            }

            return result;
        } catch (RuntimeException e) {
            LOGGER.warn(e, WARN.FALLBACK_TO_LAST_VALID_JWKS_EXCEPTION.format(e.getMessage()));
            if (lastValidResult != null && lastValidResult.isNotEmpty()) {
                return lastValidResult;
            }
            return JWKSKeyLoader.builder()
                    .originalString(EMPTY_JWKS)
                    .securityEventCounter(securityEventCounter)
                    .build();
        }
    }

    /**
     * Updates the cache with a new JWKSKeyLoader.
     * This method is called when new JWKS content is fetched.
     *
     * @param jwksContent the new JWKS content
     * @param etag        the ETag from the response, may be null
     * @return a pair containing the new JWKSKeyLoader and a boolean indicating if key rotation was detected
     */
    KeyRotationResult updateCache(String jwksContent, String etag) {
        // Content-based caching: if content hasn't changed and we have a valid previous result, return it
        if (lastValidResult != null &&
                lastValidResult.isNotEmpty() &&
                jwksContent.equals(lastValidResult.getOriginalString())) {
            LOGGER.debug(DEBUG.CONTENT_UNCHANGED::format);
            return new KeyRotationResult(lastValidResult, false);
        }

        // Create new JWKSKeyLoader with the content and etag
        JWKSKeyLoader newLoader = JWKSKeyLoader.builder()
                .originalString(jwksContent)
                .etag(etag)
                .securityEventCounter(securityEventCounter)
                .build();

        // Only update lastValidResult if the new loader has valid keys
        if (newLoader.isNotEmpty()) {
            boolean keyRotationDetected = lastValidResult != null && lastValidResult.isNotEmpty() &&
                    !newLoader.keySet().equals(lastValidResult.keySet());
            lastValidResult = newLoader;
            setCurrentEtag(etag);
            return new KeyRotationResult(newLoader, keyRotationDetected);
        } else if (lastValidResult != null && lastValidResult.isNotEmpty()) {
            // If new loader is empty, but we have a valid previous result, log warning and return previous
            LOGGER.warn(WARN.FALLBACK_TO_LAST_VALID_JWKS_EMPTY::format);
            return new KeyRotationResult(lastValidResult, false);
        }

        return new KeyRotationResult(newLoader, false);
    }

    /**
     * Simple class to hold the result of a cache update operation.
     */
    record KeyRotationResult(JWKSKeyLoader keyLoader, boolean keyRotationDetected) {
    }

    /**
     * Handles a 304 Not Modified response by returning the last valid result.
     *
     * @return the last valid JWKSKeyLoader
     */
    JWKSKeyLoader handleNotModified() {
        if (lastValidResult != null && lastValidResult.isNotEmpty()) {
            return lastValidResult;
        }
        return JWKSKeyLoader.builder()
                .originalString(EMPTY_JWKS)
                .securityEventCounter(securityEventCounter)
                .build();
    }

    /**
     * Refreshes the cache by invalidating the current entry.
     * Technically the underlying {@link LoadingCache} will asynchronously load the entry again
     * and return the previous value until the new entry is loaded.
     */
    void refresh() {
        jwksCache.refresh(getCacheKey());
    }

    /**
     * Gets the last valid JWKSKeyLoader.
     *
     * @return the last valid JWKSKeyLoader, or empty if none exists
     */
    Optional<JWKSKeyLoader> getLastValidResult() {
        return Optional.ofNullable(lastValidResult);
    }

    /**
     * Gets the current JWKSKeyLoader from cache if present, without triggering a load.
     * This is used to check the current state without causing side effects.
     *
     * @return the current JWKSKeyLoader if present in cache, null otherwise
     */
    JWKSKeyLoader getCurrentLoader() {
        return jwksCache.getIfPresent(getCacheKey());
    }
}
