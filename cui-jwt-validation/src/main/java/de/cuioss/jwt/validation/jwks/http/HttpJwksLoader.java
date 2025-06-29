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

import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.util.ETagAwareHttpHandler;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.NonNull;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import static de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR;
import static de.cuioss.jwt.validation.JWTValidationLogMessages.INFO;
import static de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;

/**
 * JWKS loader that loads from HTTP endpoint with caching support.
 * Uses ETagAwareHttpHandler for stateful HTTP caching without scheduling.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public class HttpJwksLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoader.class);

    private final ETagAwareHttpHandler httpCache;
    private final SecurityEventCounter securityEventCounter;
    private volatile JWKSKeyLoader keyLoader;
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;

    public HttpJwksLoader(@NonNull HttpHandler httpHandler,
            @NonNull SecurityEventCounter securityEventCounter) {
        this.httpCache = new ETagAwareHttpHandler(httpHandler);
        this.securityEventCounter = securityEventCounter;
    }

    /**
     * Constructor using HttpJwksLoaderConfig.
     * Uses the httpHandler directly from the config with all its settings.
     */
    public HttpJwksLoader(@NonNull HttpJwksLoaderConfig config,
            @NonNull SecurityEventCounter securityEventCounter) {
        this.httpCache = new ETagAwareHttpHandler(config.getHttpHandler());
        this.securityEventCounter = securityEventCounter;
    }

    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        ensureLoaded();
        return keyLoader != null ? keyLoader.getKeyInfo(kid) : Optional.empty();
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        ensureLoaded();
        return keyLoader != null ? keyLoader.getFirstKeyInfo() : Optional.empty();
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        ensureLoaded();
        return keyLoader != null ? keyLoader.getAllKeyInfos() : List.of();
    }

    @Override
    public Set<String> keySet() {
        ensureLoaded();
        return keyLoader != null ? keyLoader.keySet() : Set.of();
    }

    @Override
    public JwksType getJwksType() {
        return JwksType.HTTP;
    }

    @Override
    public LoaderStatus getStatus() {
        return status;
    }

    @Override
    public boolean isHealthy() {
        // For cached loader, we consider it healthy if we can load keys
        // This will trigger lazy loading on first health check
        if (keyLoader == null) {
            try {
                ensureLoaded();
            } catch (JwksLoadException e) {
                LOGGER.debug("Health check failed during key loading: %s", e.getMessage());
                return false;
            }
        }
        return status == LoaderStatus.OK;
    }

    /**
     * Forces a reload of JWKS content, optionally clearing cache completely.
     * 
     * @param clearCache if true, clears all cached content; if false, only bypasses ETag validation
     * @throws JwksLoadException if reloading fails
     */
    public void reload(boolean clearCache) {
        try {
            ETagAwareHttpHandler.LoadResult result = httpCache.reload(clearCache);
            updateKeyLoader(result);
            LOGGER.info(INFO.JWKS_RELOAD_COMPLETED.format(clearCache));
        } catch (JwksLoadException e) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(e, ERROR.JWKS_RELOAD_FAILED::format);
            throw e; // Re-throw specific exception
        }
    }

    private void ensureLoaded() {
        if (keyLoader == null) {
            loadKeys();
        }
    }

    private void loadKeys() {
        try {
            ETagAwareHttpHandler.LoadResult result = httpCache.load();

            // Handle error states appropriately
            if (result.loadState() == ETagAwareHttpHandler.LoadState.ERROR_NO_CACHE) {
                this.status = LoaderStatus.ERROR;
                throw new JwksLoadException("Failed to load JWKS and no cached content available");
            }

            // Only update key loader if data has changed and we have content
            if (result.content() != null && (result.loadState().isDataChanged() || keyLoader == null)) {
                updateKeyLoader(result);
                LOGGER.info(INFO.JWKS_KEYS_UPDATED.format(result.loadState()));
            }

            // Log appropriate message based on load state
            switch (result.loadState()) {
                case LOADED_FROM_SERVER:
                    LOGGER.info(INFO.JWKS_HTTP_LOADED::format);
                    break;
                case CACHE_ETAG:
                    LOGGER.debug("JWKS content validated via ETag (304 Not Modified)");
                    break;
                case CACHE_CONTENT:
                    LOGGER.debug("Using cached JWKS content");
                    break;
                case ERROR_WITH_CACHE:
                    LOGGER.warn(WARN.JWKS_LOAD_FAILED_CACHED_CONTENT::format);
                    break;
                case ERROR_NO_CACHE:
                    LOGGER.warn(WARN.JWKS_LOAD_FAILED_NO_CACHE::format);
                    break;
            }

        } catch (JwksLoadException e) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(e, ERROR.JWKS_LOAD_FAILED::format);
            throw e; // Re-throw specific exception
        }
    }

    private void updateKeyLoader(ETagAwareHttpHandler.LoadResult result) {
        this.keyLoader = JWKSKeyLoader.builder()
                .originalString(result.content())
                .securityEventCounter(securityEventCounter)
                .jwksType(JwksType.HTTP)
                .build();
        this.status = LoaderStatus.OK;
    }
}
