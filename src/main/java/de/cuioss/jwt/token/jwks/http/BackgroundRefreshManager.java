/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.jwks.http;

import de.cuioss.tools.logging.CuiLogger;
import lombok.NonNull;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static de.cuioss.jwt.token.JWTTokenLogMessages.DEBUG;
import static de.cuioss.jwt.token.JWTTokenLogMessages.WARN;

/**
 * Manages background refresh of JWKS content.
 * <p>
 * This class is responsible for:
 * <ul>
 *   <li>Scheduling background refresh tasks</li>
 *   <li>Preemptively refreshing keys before they expire</li>
 *   <li>Managing the executor service lifecycle</li>
 * </ul>
 *
 * @author Oliver Wolff
 */
class BackgroundRefreshManager implements AutoCloseable {

    private static final CuiLogger LOGGER = new CuiLogger(BackgroundRefreshManager.class);
    private static final int MINIMUM_REFRESH_SECONDS = 1;

    @NonNull
    private final HttpJwksLoaderConfig config;

    @NonNull
    private final JwksCacheManager cacheManager;

    private final ScheduledExecutorService executorService;

    /**
     * Creates a new BackgroundRefreshManager with the specified configuration.
     *
     * @param config       the configuration
     * @param cacheManager the cache manager to refresh
     */
    BackgroundRefreshManager(@NonNull HttpJwksLoaderConfig config, @NonNull JwksCacheManager cacheManager) {
        this.config = config;
        this.cacheManager = cacheManager;

        // Only create executor service if refresh interval is positive
        if (config.getRefreshIntervalSeconds() > 0) {
            this.executorService = config.getScheduledExecutorService();
            scheduleRefreshTask();
        } else {
            this.executorService = null;
        }
    }

    /**
     * Schedules the background refresh task.
     * The task will run at a percentage of the refresh interval to preemptively refresh keys.
     */
    private void scheduleRefreshTask() {
        // Skip scheduling for very short refresh intervals (likely test scenarios)
        if (config.getRefreshIntervalSeconds() <= 2) {
            LOGGER.debug("Skipping background refresh for short refresh interval: %d seconds",
                    config.getRefreshIntervalSeconds());
            return;
        }

        // Calculate refresh time as a percentage of the refresh interval
        long refreshTimeSeconds = Math.max(
                MINIMUM_REFRESH_SECONDS,
                config.getRefreshIntervalSeconds() * config.getBackgroundRefreshPercentage() / 100);

        LOGGER.debug("Scheduling background refresh task to run every %d seconds", refreshTimeSeconds);

        executorService.scheduleAtFixedRate(() -> {
            try {
                // Preemptively refresh the cache
                cacheManager.refresh();
                LOGGER.debug(DEBUG.REFRESHING_KEYS.format(config.getJwksUri().toString()));
            } catch (Exception e) {
                LOGGER.warn(e, WARN.JWKS_REFRESH_ERROR.format(e.getMessage()));
            }
        }, refreshTimeSeconds, refreshTimeSeconds, TimeUnit.SECONDS);
    }

    /**
     * Checks if background refresh is enabled.
     *
     * @return true if background refresh is enabled, false otherwise
     */
    boolean isEnabled() {
        return executorService != null;
    }

    /**
     * Shuts down the executor service.
     * This method should be called when the BackgroundRefreshManager is no longer needed.
     */
    @Override
    public void close() {
        if (executorService != null) {
            executorService.shutdown();
            try {
                if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                    executorService.shutdownNow();
                }
            } catch (InterruptedException e) {
                executorService.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}
