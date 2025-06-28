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
package de.cuioss.jwt.validation.jwks.well_known;

import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.jwt.validation.jwks.http.JwksLoadException;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.well_known.LazyWellKnownHandler;
import de.cuioss.jwt.validation.well_known.WellKnownDiscoveryException;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.NonNull;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * JwksLoader implementation that uses delegation to handle the non-deterministic
 * behavior of well-known endpoint discovery.
 * <p>
 * This specialized {@link JwksLoader} implementation properly integrates
 * {@link LazyWellKnownHandler} with the JWT validation system by:
 * <ul>
 *   <li>Using delegation pattern to wrap WellKnownHandler functionality</li>
 *   <li>Implementing lazy initialization of well-known endpoints</li>
 *   <li>Handling discovery failures gracefully with proper fallback</li>
 *   <li>Caching discovered JWKS URI for subsequent requests</li>
 *   <li>Implementing isHealthy() that checks both discovery and JWKS availability</li>
 *   <li>Thread-safe implementation for concurrent access</li>
 * </ul>
 * <p>
 * The loader performs a two-phase initialization:
 * <ol>
 *   <li>Discovery phase: Fetch .well-known/openid-configuration to get JWKS URI</li>
 *   <li>JWKS loading phase: Create HttpJwksLoader with discovered URI</li>
 * </ol>
 * <p>
 * Usage example:
 * <pre>
 * LazyWellKnownHandler wellKnownHandler = LazyWellKnownHandler.builder()
 *     .url("https://example.com/.well-known/openid-configuration")
 *     .build();
 * 
 * WellKnownHandlerJWKSKeyloader loader = new WellKnownHandlerJWKSKeyloader(
 *     wellKnownHandler,
 *     HttpJwksLoaderConfig.builder()
 *         .refreshIntervalSeconds(300)
 *         .build(),
 *     securityEventCounter
 * );
 * 
 * // First isHealthy() call triggers discovery and JWKS loading
 * if (loader.isHealthy()) {
 *     Optional&lt;KeyInfo&gt; key = loader.getKeyInfo("key-id");
 * }
 * </pre>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public class WellKnownHandlerJWKSKeyloader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownHandlerJWKSKeyloader.class);

    private final LazyWellKnownHandler wellKnownHandler;
    private final SecurityEventCounter securityEventCounter;

    // Lazy-initialized delegate loader
    private volatile HttpJwksLoader delegateLoader;
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;
    private volatile Exception lastError;

    private final ReentrantReadWriteLock delegateLock = new ReentrantReadWriteLock();

    /**
     * Creates a new WellKnownHandlerJWKSKeyloader.
     *
     * @param wellKnownHandler the well-known handler for discovery
     * @param securityEventCounter the security event counter
     */
    public WellKnownHandlerJWKSKeyloader(@NonNull LazyWellKnownHandler wellKnownHandler,
                                        @NonNull SecurityEventCounter securityEventCounter) {
        this.wellKnownHandler = wellKnownHandler;
        this.securityEventCounter = securityEventCounter;
        
        LOGGER.debug("Created WellKnownHandlerJWKSKeyloader for well-known URL: %s", 
                    wellKnownHandler.getWellKnownUrl());
    }

    /**
     * Ensures the delegate HttpJwksLoader is initialized.
     * This method performs the two-phase initialization:
     * 1. Triggers well-known discovery to get JWKS URI
     * 2. Creates HttpJwksLoader with discovered URI
     *
     * @return true if initialization succeeded, false otherwise
     */
    private boolean ensureDelegateInitialized() {
        // Fast path - already initialized
        if (delegateLoader != null) {
            return true;
        }

        // Check if we've already failed
        if (status == LoaderStatus.ERROR && lastError != null) {
            LOGGER.debug("Skipping initialization due to previous error: %s", lastError.getMessage());
            return false;
        }

        // Slow path - need to initialize
        delegateLock.writeLock().lock();
        try {
            // Double-check after acquiring lock
            if (delegateLoader != null) {
                return true;
            }

            // Check again for previous failure
            if (status == LoaderStatus.ERROR && lastError != null) {
                return false;
            }

            try {
                LOGGER.debug("Initializing delegate JWKS loader via well-known discovery");

                // Phase 1: Trigger well-known discovery
                HttpHandler jwksUriHandler = wellKnownHandler.getJwksUri();
                if (jwksUriHandler == null) {
                    throw new WellKnownDiscoveryException("No JWKS URI found in discovery document");
                }

                // Phase 2: Create HttpJwksLoader with discovered URI
                LOGGER.debug("Discovered JWKS URI: %s", jwksUriHandler.getUri());

                delegateLoader = new HttpJwksLoader(jwksUriHandler, securityEventCounter);
                
                // Check if the delegate is healthy
                if (delegateLoader.isHealthy()) {
                    status = LoaderStatus.OK;
                    LOGGER.info("Successfully initialized JWKS loader via well-known discovery for: %s", 
                               wellKnownHandler.getWellKnownUrl());
                    return true;
                } else {
                    status = LoaderStatus.ERROR;
                    lastError = new WellKnownDiscoveryException("Delegate JWKS loader is not healthy");
                    LOGGER.warn("Delegate JWKS loader initialized but not healthy for: %s", 
                               wellKnownHandler.getWellKnownUrl());
                    return false;
                }

            } catch (WellKnownDiscoveryException | JwksLoadException e) {
                status = LoaderStatus.ERROR;
                lastError = e;
                LOGGER.error(e, "Failed to initialize JWKS loader via well-known discovery for: %s", 
                            wellKnownHandler.getWellKnownUrl());
                return false;
            }
        } finally {
            delegateLock.writeLock().unlock();
        }
    }

    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        if (!ensureDelegateInitialized()) {
            return Optional.empty();
        }
        return delegateLoader.getKeyInfo(kid);
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        if (!ensureDelegateInitialized()) {
            return Optional.empty();
        }
        return delegateLoader.getFirstKeyInfo();
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        if (!ensureDelegateInitialized()) {
            return List.of();
        }
        return delegateLoader.getAllKeyInfos();
    }

    @Override
    public Set<String> keySet() {
        if (!ensureDelegateInitialized()) {
            return Set.of();
        }
        return delegateLoader.keySet();
    }

    @Override
    public JwksType getJwksType() {
        // This loader is effectively an HTTP loader via well-known discovery
        return JwksType.HTTP;
    }

    @Override
    public LoaderStatus getStatus() {
        // Try to initialize if not already done
        if (status == LoaderStatus.UNDEFINED) {
            ensureDelegateInitialized();
        }
        
        // If we have a delegate, use its status
        if (delegateLoader != null) {
            LoaderStatus delegateStatus = delegateLoader.getStatus();
            // Update our status to match
            if (delegateStatus != LoaderStatus.UNDEFINED) {
                status = delegateStatus;
            }
        }
        
        return status;
    }

    @Override
    public boolean isHealthy() {
        // This triggers the full initialization chain if needed:
        // 1. Well-known discovery (lazy in LazyWellKnownHandler)
        // 2. JWKS URI extraction
        // 3. HttpJwksLoader creation
        // 4. JWKS loading (lazy in HttpJwksLoader)
        
        if (!ensureDelegateInitialized()) {
            return false;
        }
        
        // Check both well-known handler and delegate loader health
        boolean wellKnownHealthy = wellKnownHandler.isHealthy();
        boolean delegateHealthy = delegateLoader != null && delegateLoader.isHealthy();
        
        boolean healthy = wellKnownHealthy && delegateHealthy;
        
        LOGGER.debug("Health check for WellKnownHandlerJWKSKeyloader: wellKnown=%s, delegate=%s, overall=%s",
                    wellKnownHealthy, delegateHealthy, healthy);
        
        return healthy;
    }

    /**
     * Gets the last error that occurred during initialization.
     *
     * @return the last error, or null if no error occurred
     */
    public Exception getLastError() {
        return lastError;
    }

    /**
     * Gets the well-known URL being used for discovery.
     *
     * @return the well-known URL
     */
    public String getWellKnownUrl() {
        return wellKnownHandler.getWellKnownUrl().toString();
    }
}