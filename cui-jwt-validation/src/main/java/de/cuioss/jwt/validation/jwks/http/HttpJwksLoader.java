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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR;
import static de.cuioss.jwt.validation.JWTValidationLogMessages.INFO;
import static de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;

/**
 * JWKS loader that loads from HTTP endpoint with caching and background refresh support.
 * Uses ETagAwareHttpHandler for stateful HTTP caching with optional scheduled background refresh.
 * Background refresh is automatically started after the first successful key load.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public class HttpJwksLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoader.class);

    private final ETagAwareHttpHandler httpCache;
    private final SecurityEventCounter securityEventCounter;
    private final HttpJwksLoaderConfig config;
    private final AtomicReference<JWKSKeyLoader> keyLoader = new AtomicReference<>();
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;
    private final AtomicReference<ScheduledFuture<?>> refreshTask = new AtomicReference<>();
    private final AtomicBoolean schedulerStarted = new AtomicBoolean(false);

    public HttpJwksLoader(@NonNull HttpHandler httpHandler,
            @NonNull SecurityEventCounter securityEventCounter) {
        this.httpCache = new ETagAwareHttpHandler(httpHandler);
        this.securityEventCounter = securityEventCounter;
        this.config = null; // No config, no background refresh
    }

    /**
     * Constructor using HttpJwksLoaderConfig.
     * Uses the httpHandler directly from the config with all its settings.
     * Enables background refresh if configured.
     */
    public HttpJwksLoader(@NonNull HttpJwksLoaderConfig config,
            @NonNull SecurityEventCounter securityEventCounter) {
        this.httpCache = new ETagAwareHttpHandler(config.getHttpHandler());
        this.securityEventCounter = securityEventCounter;
        this.config = config;
    }

    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        ensureLoaded();
        JWKSKeyLoader loader = keyLoader.get();
        return loader != null ? loader.getKeyInfo(kid) : Optional.empty();
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        ensureLoaded();
        JWKSKeyLoader loader = keyLoader.get();
        return loader != null ? loader.getFirstKeyInfo() : Optional.empty();
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        ensureLoaded();
        JWKSKeyLoader loader = keyLoader.get();
        return loader != null ? loader.getAllKeyInfos() : List.of();
    }

    @Override
    public Set<String> keySet() {
        ensureLoaded();
        JWKSKeyLoader loader = keyLoader.get();
        return loader != null ? loader.keySet() : Set.of();
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
        if (keyLoader.get() == null) {
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
     * Shuts down the background refresh scheduler if running.
     * Package-private for testing purposes only.
     */
    void shutdown() {
        ScheduledFuture<?> task = refreshTask.get();
        if (task != null && !task.isCancelled()) {
            task.cancel(false);
            LOGGER.debug("Background refresh task cancelled");
        }
    }

    /**
     * Checks if background refresh is enabled and running.
     * Package-private for testing purposes only.
     * 
     * @return true if background refresh is active, false otherwise
     */
    boolean isBackgroundRefreshActive() {
        ScheduledFuture<?> task = refreshTask.get();
        return task != null && !task.isCancelled() && !task.isDone();
    }

    private void ensureLoaded() {
        if (keyLoader.get() == null) {
            loadKeysIfNeeded();
        }
    }

    private void loadKeysIfNeeded() {
        // Double-checked locking pattern with AtomicReference
        if (keyLoader.get() == null) {
            synchronized (this) {
                if (keyLoader.get() == null) {
                    loadKeys();
                }
            }
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
            if (result.content() != null && (result.loadState().isDataChanged() || keyLoader.get() == null)) {
                updateKeyLoader(result);
                LOGGER.info(INFO.JWKS_KEYS_UPDATED.format(result.loadState()));

                // Start background refresh after first successful load
                startBackgroundRefreshIfNeeded();
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
        JWKSKeyLoader newLoader = JWKSKeyLoader.builder()
                .jwksContent(result.content())
                .securityEventCounter(securityEventCounter)
                .jwksType(JwksType.HTTP)
                .build();
        keyLoader.set(newLoader);
        this.status = LoaderStatus.OK;
    }

    private void startBackgroundRefreshIfNeeded() {
        if (config != null &&
                config.getScheduledExecutorService() != null &&
                config.getRefreshIntervalSeconds() > 0 &&
                schedulerStarted.compareAndSet(false, true)) {

            ScheduledExecutorService executor = config.getScheduledExecutorService();
            int intervalSeconds = config.getRefreshIntervalSeconds();

            ScheduledFuture<?> task = executor.scheduleAtFixedRate(
                    this::backgroundRefresh,
                    intervalSeconds,
                    intervalSeconds,
                    TimeUnit.SECONDS
            );
            refreshTask.set(task);

            LOGGER.info(INFO.JWKS_BACKGROUND_REFRESH_STARTED.format(intervalSeconds));
        }
    }

    private void backgroundRefresh() {
        LOGGER.debug("Starting background JWKS refresh");
        ETagAwareHttpHandler.LoadResult result = httpCache.load();

        // Only update keys if data has actually changed
        if (result.content() != null && result.loadState().isDataChanged()) {
            updateKeyLoader(result);
            LOGGER.info(INFO.JWKS_BACKGROUND_REFRESH_UPDATED.format(result.loadState()));
        } else {
            LOGGER.debug("Background refresh completed, no changes detected: %s", result.loadState());
        }
    }
}
