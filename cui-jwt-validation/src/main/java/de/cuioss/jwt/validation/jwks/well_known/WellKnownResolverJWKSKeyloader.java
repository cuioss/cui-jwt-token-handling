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

import de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR;
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.jwt.validation.jwks.http.JwksLoadException;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.well_known.WellKnownDiscoveryException;
import de.cuioss.jwt.validation.well_known.WellKnownResolver;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.NonNull;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * JwksLoader implementation that uses delegation to handle the non-deterministic
 * behavior of well-known endpoint discovery.
 * <p>
 * This specialized {@link JwksLoader} implementation properly integrates
 * {@link WellKnownResolver} with the JWT validation system by:
 * <ul>
 *   <li>Using delegation pattern to wrap WellKnownResolver functionality</li>
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
 * WellKnownResolver resolver = HttpWellKnownResolver.builder()
 *     .url("https://example.com/.well-known/openid-configuration")
 *     .build();
 * 
 * WellKnownResolverJWKSKeyloader loader = new WellKnownResolverJWKSKeyloader(
 *     resolver,
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
public class WellKnownResolverJWKSKeyloader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownResolverJWKSKeyloader.class);

    private final WellKnownResolver wellKnownResolver;
    private final SecurityEventCounter securityEventCounter;

    // Lazy-initialized delegate loader
    private final AtomicReference<HttpJwksLoader> delegateLoader = new AtomicReference<>();
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;
    private volatile Exception lastError;

    /**
     * Creates a new WellKnownResolverJWKSKeyloader.
     *
     * @param wellKnownResolver the well-known resolver for discovery
     * @param securityEventCounter the security event counter
     */
    public WellKnownResolverJWKSKeyloader(@NonNull WellKnownResolver wellKnownResolver,
            @NonNull SecurityEventCounter securityEventCounter) {
        this.wellKnownResolver = wellKnownResolver;
        this.securityEventCounter = securityEventCounter;

        LOGGER.debug("Created WellKnownResolverJWKSKeyloader for well-known resolver");
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
        if (delegateLoader.get() != null) {
            return true;
        }

        // Check if we've already failed
        if (status == LoaderStatus.ERROR && lastError != null) {
            LOGGER.debug("Skipping initialization due to previous error: %s", lastError.getMessage());
            return false;
        }

        // Slow path - need to initialize
        synchronized (this) {
            // Double-check after acquiring lock
            if (delegateLoader.get() != null) {
                return true;
            }

            // Check again for previous failure
            if (status == LoaderStatus.ERROR && lastError != null) {
                return false;
            }

            try {
                LOGGER.debug("Initializing delegate JWKS loader via well-known discovery");

                // Phase 1: Trigger well-known discovery
                HttpHandler jwksUriHandler = wellKnownResolver.getJwksUri();
                if (jwksUriHandler == null) {
                    throw new WellKnownDiscoveryException("No JWKS URI found in discovery document");
                }

                // Phase 2: Create HttpJwksLoader with discovered URI
                LOGGER.debug("Discovered JWKS URI: %s", jwksUriHandler.getUri());

                HttpJwksLoader newDelegateLoader = new HttpJwksLoader(jwksUriHandler, securityEventCounter);

                // Check if the delegate is healthy
                if (newDelegateLoader.isHealthy()) {
                    delegateLoader.set(newDelegateLoader);
                    status = LoaderStatus.OK;
                    LOGGER.info("Successfully initialized JWKS loader via well-known discovery");
                    return true;
                } else {
                    status = LoaderStatus.ERROR;
                    lastError = new WellKnownDiscoveryException("Delegate JWKS loader is not healthy");
                    LOGGER.warn(WARN.JWKS_LOADER_NOT_HEALTHY.format(jwksUriHandler.getUri()));
                    return false;
                }

            } catch (WellKnownDiscoveryException | JwksLoadException e) {
                status = LoaderStatus.ERROR;
                lastError = e;
                LOGGER.error(e, ERROR.JWKS_LOADER_INIT_FAILED.format("well-known discovery"));
                return false;
            }
        }
    }

    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        if (!ensureDelegateInitialized()) {
            return Optional.empty();
        }
        return delegateLoader.get().getKeyInfo(kid);
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        if (!ensureDelegateInitialized()) {
            return Optional.empty();
        }
        return delegateLoader.get().getFirstKeyInfo();
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        if (!ensureDelegateInitialized()) {
            return List.of();
        }
        return delegateLoader.get().getAllKeyInfos();
    }

    @Override
    public Set<String> keySet() {
        if (!ensureDelegateInitialized()) {
            return Set.of();
        }
        return delegateLoader.get().keySet();
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
        HttpJwksLoader loader = delegateLoader.get();
        if (loader != null) {
            LoaderStatus delegateStatus = loader.getStatus();
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
        // 1. Well-known discovery (lazy in WellKnownResolver)
        // 2. JWKS URI extraction
        // 3. HttpJwksLoader creation
        // 4. JWKS loading (lazy in HttpJwksLoader)
        
        if (!ensureDelegateInitialized()) {
            return false;
        }

        // Check both well-known resolver and delegate loader health
        boolean wellKnownHealthy = wellKnownResolver.isHealthy();
        HttpJwksLoader loader = delegateLoader.get();
        boolean delegateHealthy = loader != null && loader.isHealthy();

        boolean healthy = wellKnownHealthy && delegateHealthy;

        LOGGER.debug("Health check for WellKnownResolverJWKSKeyloader: wellKnown=%s, delegate=%s, overall=%s",
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
}